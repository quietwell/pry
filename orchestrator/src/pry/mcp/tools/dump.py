"""Dump tool registration for the pry MCP server.

``dump_manage`` wraps the pure-Python parser in ``pry.minidump``:
``parse`` answers {bugcheck, params[4], faulting_module, context,
stack_qwords} for a local/artifact/remote dump, ``latest`` pulls the
newest ``C:\\Windows\\Minidump\\*.dmp`` off the target and parses it in
one call. The module-level ``_latest_minidump`` / ``_parse_artifact``
helpers are shared with ``crash_state`` (target.py) and the boot
monitor so every path converges on the same pull+parse pipeline.

Registration mirrors files.py: ``*_ACTIONS`` list + ``_*_ACTION_HELP``
map + ``Annotated[..., json_schema_extra={"enum": ...}]`` wire enum +
``_guard`` funnel.
"""

from __future__ import annotations

import asyncio
import uuid

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .._artifacts import safe_basename
# Part 3 evidence envelope (detail=/retention); aliased to keep the
# closure namespace untouched.
from ..evidence.store import split_detail as _ev_split_detail
from ..evidence.store import with_evidence as _ev_with
from .._coverage import coverage as _coverage
from ...minidump import (
    dump_epoch_ms as _dump_epoch_ms,
    parse_dump as _parse_dump,
    read_triage_stack as _read_triage_stack,
    resolve_va as _resolve_va,
    sig_check as _sig_check,
)

DEFAULT_DUMP_DIR = r"C:\Windows\Minidump"
_PROBE_BYTES = 4096
_MAX_LATEST_CANDIDATES = 3
_MAX_LIVE_SYMBOLIZED_FRAMES = 64

DUMP_ACTIONS = ["parse", "latest", "stack", "process_snapshot",
                # live kernel dump via
                # NtSystemDebugControl(SysDbgGetLiveKernelDump). Umagent-
                # only (agent view surfaces kind='not_supported' with
                # hint='use name=user'). Gated by
                # security.allow_live_kernel_dump.
                "create_kernel_dump",
                "actions"]


def _dump_cov(partial: bool, limit: str = "driver_list_truncated") -> dict:
    """dump-threads coverage: complete when every thread/frame the dump
    carries was walked; partial + a machine-readable reason otherwise."""
    return _coverage("dump-threads",
                     "partial" if partial else "complete",
                     *([limit] if partial else []))

_DUMP_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "dump_manage(action='actions')"},
    "parse": {"one_liner": "parse a crash dump — bugcheck code+name, "
                           "params, context, stack qwords, watchdog "
                           "self-identification",
              "key_args": "path | sha256 | remote_path, name, resolve, "
                          "assume_fresh",
              "example": "dump_manage(action='parse', "
                         "remote_path='C:\\\\Windows\\\\Minidump\\\\"
                         "Mini100526-01.dmp')"},
    "latest": {"one_liner": "pull the newest .dmp from the target's "
                            "minidump dir and parse it",
               "key_args": "dir, name, resolve, assume_fresh",
               "example": "dump_manage(action='latest')"},
    "stack": {"one_liner": "walk a dump's saved stack — triage dumps "
                           "resolve offline via the embedded driver "
                           "list + KernBase (works on stale-boot "
                           "dumps); live map symbolizes when connected",
              "key_args": "path | sha256 | remote_path, count, name, "
                          "resolve, assume_fresh",
              "example": "dump_manage(action='stack', "
                         "remote_path='C:\\\\Windows\\\\Minidump\\\\"
                         "Mini100526-01.dmp')"},
    "process_snapshot": {"one_liner": "SI #14 — capture a live process "
                                       "minidump via PssCaptureSnapshot "
                                       "+ MiniDumpWriteDump with a "
                                       "stepped access-mask ladder "
                                       "(non-PP targets only; PP wait "
                                       "for feature #23, Wave 3)",
                          "key_args": "pid, dump_flags, output_path, "
                                      "use_snapshot, name",
                          "example": "dump_manage(action="
                                      "'process_snapshot', pid=1234, "
                                      "dump_flags=['WithFullMemory',"
                                      "'WithThreadInfo'])"},
    # live kernel dump.
    "create_kernel_dump": {"one_liner": "NtSystemDebugControl("
                                        "SysDbgGetLiveKernelDump) — "
                                        "live kernel dump written to "
                                        "the TARGET's disk; orchestrator "
                                        "sees {path,size,sha256} only. "
                                        "Umagent-only (agent view "
                                        "degrades to kind='not_supported'"
                                        ", hint='use name=user'). "
                                        "Default-off; set "
                                        "security.allow_live_kernel_dump"
                                        "=true to enable.",
                           "key_args": "output_path, dump_flags, "
                                       "compression, allow_cancel, name",
                           "example": "dump_manage(action="
                                      "'create_kernel_dump', "
                                      "output_path='C:\\\\dumps\\\\live"
                                      ".dmp', dump_flags=['stack_only',"
                                      "'compression'], name='user')"},
}


# SI #14 helpers (flag resolver, dispatch envelope) live in
# dump_snapshot.py so this module stays under the 700-line cap. Re-export
# the names tests use so the public import path from this module keeps
# working.
from .dump_snapshot import (  # noqa: F401 — public re-exports
    _DEFAULT_MINIDUMP_FLAGS,
    _LIVE_KERNEL_FLAG_MAP,
    _MINIDUMP_FLAG_MAP,
    _mem_live_kernel_dump,
    _mem_process_snapshot,
    _resolve_live_kernel_flags,
    _resolve_minidump_flags,
)


async def _list_dumps(c, dump_dir: str = DEFAULT_DUMP_DIR) -> list[dict]:
    """``.dmp`` rows in the remote minidump dir (newest mtime first)."""
    entries = await c.file_list_dir(dump_dir, recursive=False)
    cands = [e for e in (entries or [])
             if not e.get("dir")
             and str(e.get("name") or "").lower().endswith(".dmp")]
    cands.sort(key=lambda e: int(e.get("mtime_unix") or 0), reverse=True)
    return cands


async def _latest_minidump(ctx, c, dump_dir: str = DEFAULT_DUMP_DIR) -> dict | None:
    """Pull the newest parseable ``.dmp`` from ``dump_dir`` into
    ``artifacts/dumps/`` and describe it.

    Returns ``{remote_path, local_path, name, mtime_unix, size, dir,
    entries}`` or None when the dir holds no dumps / none pass the
    signature probe. The probe is a ranged 4 KiB download (per the WP1
    contract) so a bad candidate costs almost nothing before the full
    pull. ``entries`` carries the raw candidate list so the boot
    monitor's dir-watch can re-seed its seen-set without a second
    ListDir.
    """
    cands = await _list_dumps(c, dump_dir)
    if not cands:
        return None
    art = Path(ctx.cfg.artifacts_dir()) / "dumps"
    art.mkdir(parents=True, exist_ok=True)
    # Per-call probe name: two concurrent `latest` calls (chat + boot
    # monitor) used to share `.latest_probe.dmp` and read each other's
    # half-written probe.
    probe = art / f".latest_probe.{uuid.uuid4().hex[:12]}.tmp"
    try:
        for e in cands[:_MAX_LATEST_CANDIDATES]:
            remote_name = str(e["name"])
            remote = dump_dir.rstrip("\\/") + "\\" + remote_name
            try:
                await c.file_download(remote, str(probe), offset=0,
                                      length=_PROBE_BYTES)
                head = probe.read_bytes()[:8]
            except Exception:
                continue
            if not _sig_check(head):
                continue
            # The name comes from the TARGET's directory listing — reduce
            # it to one safe local component before it touches a path.
            local = art / safe_basename(remote_name, default="latest.dmp")
            if not await _download_atomic(c, remote, local):
                continue
            return {"remote_path": remote, "local_path": str(local),
                    "name": e["name"],
                    "mtime_unix": int(e.get("mtime_unix") or 0),
                    "size": int(e.get("size") or 0),
                    "dir": dump_dir, "entries": cands}
        return None
    finally:
        try:
            probe.unlink()
        except OSError:
            pass


async def _download_atomic(c, remote: str, local: Path) -> bool:
    """Download to a unique temp name next to ``local`` and rename it into
    place — a concurrent reader never sees a half-written dump, and two
    pulls of the same dump never interleave writes."""
    tmp = local.with_name(f".{local.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        await c.file_download(remote, str(tmp))
        if tmp.exists():
            os.replace(tmp, local)
        return True
    except Exception:
        return False
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


async def _boot_epoch_ms(c) -> int:
    """Live boot_epoch_ms for the freshness check; 0 when unknown."""
    if c is None:
        return 0
    try:
        st = await c.status()
    except Exception:
        return 0
    return int(st.get("boot_epoch_ms") or 0)


def _boot_freshness(res: dict, boot_epoch_ms: int,
                    assume_fresh: bool) -> tuple[bool, str]:
    """Is the dump's crash time inside the current boot lifetime?

    KASLR re-randomizes every boot, so module bases in the live map only
    line up with dump VAs when the dump was captured during THIS boot
    (manual/livedump) — a post-reboot crash dump is honestly stale.
    """
    if assume_fresh:
        return True, "assumed_fresh"
    if not boot_epoch_ms:
        return True, "unknown_boot"
    dump_ms = _dump_epoch_ms(res)
    if not dump_ms:
        return True, "unknown_dump_time"
    if dump_ms >= boot_epoch_ms:
        return True, "same_boot"
    return False, "stale_boot"


async def _parse_artifact(ctx, c, local_path: str, *, resolve: bool = True,
                          assume_fresh: bool = False,
                          boot_epoch_ms: int = 0) -> dict:
    """Parse ``local_path`` and, when the dump is same-boot-fresh,
    resolve params/faulting/stack pointers against the live module map.
    """
    # Pure-Python parse of a possibly multi-GB dump: keep it off the loop.
    res = await asyncio.to_thread(_parse_dump, local_path)
    if not res.get("ok"):
        return res
    if not resolve:
        res["resolution"] = "disabled"
        res["faulting_module"] = None
        return res
    if c is None:
        res["resolution"] = "no_target"
        res["faulting_module"] = None
        return res
    fresh, why = _boot_freshness(res, int(boot_epoch_ms or 0),
                                 bool(assume_fresh))
    res["resolution"] = why
    if not fresh:
        res["faulting_module"] = None
        return res
    resolved = []
    for p in res.get("params") or []:
        resolved.append(
            await _resolve_va(ctx, c, int(p)) if p else None)
    res["params_resolved"] = resolved
    fault_va = res.get("faulting_va") or (res.get("context") or {}).get("rip")
    fr = await _resolve_va(ctx, c, int(fault_va)) if fault_va else None
    if fr is not None:
        res["faulting"] = fr
        res["faulting_module"] = fr.get("module")
    else:
        res["faulting_module"] = None
    for q in res.get("stack_qwords") or []:
        r = await _resolve_va(ctx, c, int(q.get("value") or 0))
        if r is not None:
            q["text"] = r["text"]
    return res


def _hx(v) -> str:
    try:
        return f"0x{int(v):x}"
    except (TypeError, ValueError):
        return str(v)


def _mirror_hex(res: dict) -> dict:
    """Hex mirrors next to the decimal big integers (params, context
    registers, faulting VA/PC, watchdog params, stack qwords). Decimal
    keys stay untouched — callers compute from the ints, eyeball from
    the `*_hex` siblings, and no value_manage round-trip is needed."""
    out = dict(res)
    if isinstance(out.get("params"), list):
        out["params_hex"] = [_hx(p) for p in out["params"]]
    for k in ("faulting_va", "faulting_pc", "dtb", "kd_data_block"):
        if out.get(k):
            out[f"{k}_hex"] = _hx(out[k])
    if isinstance(out.get("context"), dict):
        out["context_hex"] = {k: _hx(v)
                              for k, v in out["context"].items()
                              if isinstance(v, int)}
    if isinstance(out.get("watchdog"), dict):
        out["watchdog_hex"] = {k: _hx(v)
                               for k, v in out["watchdog"].items()
                               if isinstance(v, int)}
    for q in out.get("stack_qwords") or []:
        if isinstance(q, dict):
            q["va_hex"] = _hx(q.get("va"))
            q["value_hex"] = _hx(q.get("value"))
    if out.get("kernbase"):
        out["kernbase_hex"] = _hx(out["kernbase"])
    for q in out.get("frames") or []:
        if isinstance(q, dict):
            q["va_hex"] = _hx(q.get("va"))
            q["value_hex"] = _hx(q.get("value"))
    return out


async def _symbolize_frames_live(ctx, c, res: dict, assume_fresh: bool
                                 ) -> None:
    """Best-effort live-map symbolization for stack frames — mutates
    ``res`` in place. Only when a target is connected AND the dump is
    same-boot fresh (KASLR): the offline driver-list attribution from
    ``read_triage_stack`` stays the base layer otherwise."""
    frames = res.get("frames") or []
    if not frames:
        return
    boot_epoch_ms = await _boot_epoch_ms(c)
    fresh, why = _boot_freshness(res, boot_epoch_ms, assume_fresh)
    res["resolution"] = why
    if not fresh:
        return
    try:
        mods = await c.mem_modules(0, True)
    except Exception:
        return
    if not mods:
        return
    parsed = [(-1, int(m.get("base") or 0), int(m.get("size") or 0),
               str(m.get("name") or "?"))
              for m in mods]
    sym_texts: dict[int, str] = {}
    sym_budget = _MAX_LIVE_SYMBOLIZED_FRAMES
    for q in frames:
        val = int(q.get("value") or 0)
        hit = None
        for i, (_idx, base, size, mname) in enumerate(parsed):
            if base and size and base <= val < base + size:
                hit = (i, base, size, mname)
                break
        if hit is None:
            continue
        _i, base, _size, mname = hit
        off = val - base
        q["live_module"] = mname
        q["live_offset"] = off
        if sym_budget > 0:
            sym_budget -= 1
            try:
                from ... import symbols as _sym
                from .symbols import _resolve_image
                img, _img_name = _resolve_image(ctx, mname, "")
                if img:
                    cfg = ctx.cfg
                    pdb_cache = (str(cfg.pdb_cache_dir())
                                 if hasattr(cfg, "pdb_cache_dir")
                                 else str(getattr(
                                     getattr(cfg, "artifacts", None),
                                     "pdb_cache", "") or ""))
                    symcfg = getattr(cfg, "symbols", None)
                    h = await asyncio.to_thread(
                        _sym.lookup_rva, img, off, pdb_cache,
                        getattr(symcfg, "allow_download", True),
                        getattr(symcfg, "servers", None) or None)
                    if isinstance(h, dict) and h.get("found"):
                        disp = int(h.get("displacement") or 0)
                        q["symbol"] = h["name"]
                        q["symbol_disp"] = disp
                        sym_texts[int(q.get("va") or 0)] = \
                            f"{mname}!{h['name']}+0x{disp:x}"
            except Exception:
                pass
    if sym_texts:
        res["lines"] = [
            sym_texts.get(int(q.get("va") or 0))
            or str(q.get("text") or f"0x{int(q.get('value') or 0):x}")
            for q in frames
        ]
        res["resolution"] = (res.get("resolution") or "") + \
            "+live_symbols"


async def _resolve_source(ctx, c, path: str, sha256: str,
                          remote_path: str) -> tuple[str | None, dict | None]:
    """``parse`` source selector -> ``(local_path, source_dict)`` or
    ``(None, error_dict)``."""
    if path:
        p = Path(path).expanduser()
        if not p.is_file():
            # Canonical store resolution: 'dumps/x.sys',
            # 'artifacts/dumps/x.sys', absolute-under-root all land on
            # the same file.
            from .._artifacts import resolve_artifact_path as _rap
            rp = _rap(ctx.cfg, path)
            if rp is not None and rp.is_file():
                p = rp
            else:
                alt = Path(ctx.cfg.artifacts_dir()) / path
                if alt.is_file():
                    p = alt
        if not p.is_file():
            return None, {"ok": False, "kind": "not_found",
                          "error": f"parse: {path!r} not found locally "
                                   "or under artifacts/"}
        return str(p), {"via": "path", "local_path": str(p)}
    if sha256:
        from .._artifacts import find_artifact_by_sha_async, valid_sha_prefix
        if valid_sha_prefix(sha256) is None:
            return None, {"ok": False, "kind": "bad_arg",
                          "error": f"parse: sha256 {sha256!r} is not a hex "
                                   "prefix (1-64 hex chars)"}
        hit = await find_artifact_by_sha_async(ctx.cfg, sha256,
                                               ledger=ctx.ledger)
        if hit is None:
            return None, {"ok": False, "kind": "not_found",
                          "error": f"parse: no artifact with sha256 "
                                   f"prefix {sha256!r}",
                          "hint": "file_manage(action='list_artifacts') "
                                  "to browse the store"}
        return hit[0], {"via": "artifact", "sha256": hit[1],
                        "local_path": hit[0]}
    if remote_path:
        if c is None:
            return None, {"ok": False, "kind": "no_target",
                          "error": "parse remote_path needs a connected "
                                   "view",
                          "hint": "target_manage(action='connect') first"}
        art = Path(ctx.cfg.artifacts_dir()) / "dumps"
        art.mkdir(parents=True, exist_ok=True)
        # `C:\x\..`, `c:evil.dmp`, `..` used to land outside dumps/ (or
        # drive-relative); one safe component only.
        local = art / safe_basename(remote_path, default="remote.dmp")
        tmp = local.with_name(f".{local.name}.{uuid.uuid4().hex[:8]}.tmp")
        try:
            r = await c.file_download(remote_path, str(tmp))
            if tmp.exists():
                os.replace(tmp, local)
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        return str(local), {"via": "remote", "remote_path": remote_path,
                            "local_path": str(local),
                            "downloaded_bytes": r.get("bytes"),
                            "sha256": r.get("sha256")}
    return None, {"ok": False, "kind": "bad_arg",
                  "error": "parse: one of path= | sha256= | remote_path= "
                           "is required"}


def register(mcp, ctx: Context) -> None:
    """Register the ``dump_manage`` tool on *mcp*, using *ctx* for state."""

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def dump_manage(action: Annotated[str, Field(json_schema_extra={"enum": DUMP_ACTIONS})],
                          path: str = "", sha256: str = "",
                          remote_path: str = "", dir: str = "",
                          name: str = "",
                          resolve: bool = True,
                          assume_fresh: bool = False,
                          count: int = 256,
                          detail: str = "complete",
                          # SI #14 process_snapshot kwargs
                          pid: int = 0,
                          dump_flags: list[str] | None = None,
                          output_path: str = "",
                          use_snapshot: bool = True,
                          # live-kernel-dump kwargs
                          compression: bool = False,
                          allow_cancel: bool = False) -> str:
        """Crash-dump triage: parse kernel dumps (DUMP_HEADER64) and
        usermode MDMP into bugcheck code+name, params, CONTEXT/EXCEPTION,
        stack qwords — pointers resolve to module!sym+off on same-boot
        dumps (pry watchdog fires self-identify). latest pulls the
        newest C:\\Windows\\Minidump .dmp. stack walks the dump's saved
        stack and attributes every frame — triage dumps resolve offline
        via the embedded driver list + KernBase, so stale-boot dumps
        work. Per-verb help: dump_manage(action='actions')."""
        args = {"action": action,
                "path": path or sha256 or remote_path, "name": name}
        # Part 3: detail="summary" swaps the inline payload for a counts
        # view; both modes retain the complete record under artifacts/
        # evidence/ (see mcp/evidence/). Retention is best-effort and
        # never alters a non-applicable result.
        _ev_detail, _ = _ev_split_detail(detail)

        async def run() -> str:
            # Discovery verb first — must answer with nothing connected.
            if action == "actions":
                return _actions_help("dump_manage", _DUMP_ACTION_HELP)
            if action == "parse":
                c = None
                try:
                    c = ctx.session.require_client(name)
                except Exception:
                    c = None
                local, src = await _resolve_source(
                    ctx, c, path, sha256, remote_path)
                if local is None:
                    return _j(src)
                res = await _parse_artifact(
                    ctx, c, local, resolve=resolve,
                    assume_fresh=assume_fresh,
                    boot_epoch_ms=await _boot_epoch_ms(c))
                res["source"] = src
                if res.get("ok") is not False:
                    # All streams the dump carries were walked; the
                    # parser's notes list carries honest truncation
                    # reasons (driver-list cutoff, missing callstack...).
                    notes = res.get("notes") or []
                    res["coverage"] = _dump_cov(bool(notes))
                return _j(_mirror_hex(res))
            if action == "latest":
                c = ctx.session.require_client(name)
                dump_dir = (dir or "").strip() or DEFAULT_DUMP_DIR
                got = await _latest_minidump(ctx, c, dump_dir)
                if got is None:
                    return _j({"ok": False, "kind": "not_found",
                               "error": f"no parseable .dmp files in "
                                        f"{dump_dir}",
                               "hint": "the target may not have "
                                       "bugchecked, or crash-dump "
                                       "collection is off (System "
                                       "Properties -> Startup and "
                                       "Recovery)"})
                entries = got.pop("entries", None)
                res = await _parse_artifact(
                    ctx, c, got["local_path"], resolve=resolve,
                    assume_fresh=assume_fresh,
                    boot_epoch_ms=await _boot_epoch_ms(c))
                res["source"] = {
                    k: got[k] for k in
                    ("remote_path", "local_path", "name",
                     "mtime_unix", "size", "dir")}
                res["source"]["dumps_seen"] = len(entries or [])
                return _j(_mirror_hex(res))
            if action == "stack":
                c = None
                try:
                    c = ctx.session.require_client(name)
                except Exception:
                    c = None
                local, src = await _resolve_source(
                    ctx, c, path, sha256, remote_path)
                if local is None:
                    return _j(src)
                res = await asyncio.to_thread(
                    _read_triage_stack, local, max(1, min(int(count), 4096)))
                if not res.get("ok"):
                    return _j(res)
                res["source"] = src
                # Layers: (1) offline driver-list attribution (always —
                # this is the stale-boot path), (2) live-map
                # symbolization when connected + same-boot fresh.
                if c is not None and resolve:
                    await _symbolize_frames_live(ctx, c, res, assume_fresh)
                elif not resolve:
                    res["resolution"] = "disabled"
                frames_total = int(res.get("frames_total")
                                   or len(res.get("frames") or []))
                capped = len(res.get("frames") or []) < frames_total
                res["coverage"] = _dump_cov(capped, "frame_cap_reached")
                return _j(_mirror_hex(res))
            if action == "process_snapshot":
                # SI #14 — PssCaptureSnapshot + MiniDumpWriteDump with
                # the stepped access-mask ladder. Non-PP only — PP
                # targets surface kind='pp_target_requires_feature_23'
                # until SI #23 (Wave 3) lands.
                c = ctx.session.require_client(name)
                res = await _mem_process_snapshot(
                    ctx, c, pid=pid, dump_flags=dump_flags,
                    output_path=output_path,
                    use_snapshot=use_snapshot, name=name)
                return _j(res)
            if action == "create_kernel_dump":
                # live kernel dump via
                # NtSystemDebugControl(SysDbgGetLiveKernelDump).
                # Config gate (allow_live_kernel_dump) + machine-trust
                # gate land in Session.assert_allowed +
                # _check_actuator_trust; by here they've been passed.
                # Umagent-only — the agent view answers with
                # kind='not_supported' hint='use name=user'.
                c = ctx.session.require_client(name)
                res = await _mem_live_kernel_dump(
                    ctx, c, output_path=output_path,
                    flags=dump_flags, compression=bool(compression),
                    allow_cancel=bool(allow_cancel), name=name)
                return _j(res)
            return _unknown_action("dump_manage", action, DUMP_ACTIONS,
                                   _DUMP_ACTION_HELP)

        return await _guard(ctx, "dump_manage", action, args,
                            _ev_with(ctx, "dump_manage", action, args, run,
                                     _ev_detail))
