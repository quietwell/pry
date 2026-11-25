"""Scan subsystem for ``memory_manage``.

Phase R4 lifts the whole scan surface — the synchronous ``pattern_scan``
dispatcher plus the long-running scan-job state machine
(``scan_start``/``scan_status``/``scan_result``/``scan_cancel``/
``scan_list``) and ``_section_spans`` — out of ``mem.py``'s
``register()`` closure into this module. The orchestrator-side scan
registry (``_SCANS`` + ``_SCAN_SEQ``) is now module-level: it still
survives the orchestrator lifetime the same way the closure variant
did, but is no longer rebuilt per ``register()`` call.

``mem.py``'s ``pattern_scan`` / ``scan_*`` dispatch branches collapse
to one-line delegations into the ``handle_*`` entry points below. Every
entry point takes whatever the branch had access to via closure
(``ctx``, the agent client ``c``, resolved addresses, every raw arg) as
explicit kwargs — zero behaviour change against the pre-R4 bodies.
"""

from __future__ import annotations

import logging
from typing import Any

from ....caller import current_client_id


def _owner_bucket(cid: str) -> str:
    """Collapse rotating per-connection anon ids into one stable bucket.

    Claude Desktop (and other streamable-HTTP clients that skip the
    ``Mcp-Session-Id`` handshake) land a fresh ``anon-<host>:<port>`` id
    on every tool call because each dispatch rides a new TCP endpoint.
    A scan created on one call would then look ``foreign_owned`` to its
    own follow-up next_scan / scan_list on the very next call.

    Mirrors ``mcp/tools/target/_plumbing.py``: any ``anon-*`` id becomes
    ``"anonymous"``. Authenticated callers (real ``Mcp-Session-Id``)
    keep their stable id and still get owner isolation.
    """
    if not cid or str(cid).startswith("anon-"):
        return "anonymous"
    return str(cid)

# ``mem.py`` star-imports ``.common`` to pull every ``_runtime/*`` helper
# into its closure. From inside the ``mem`` package we go through
# ``.._runtime`` directly — the symbols are the same objects either way.
from .._runtime.breadcrumbs import _pattern_scan_breadcrumb
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict, _j
from ._envelope import _scan_window_cov
from .region_filter import _any_region_flag_set, resolve_spans as _resolve_spans


log = logging.getLogger("pry.mcp.tools.mem")


# orchestrator-side registry of active scan jobs. Each entry is
#   {scan_id, owner, task, hits: list[int], progress: {...},
#    status: 'running'|'done'|'cancelled'|'error',
#    error?: str, args: {...for observability}, started_ts,
#    finished_ts?, cancel: asyncio.Event}
_SCANS: dict[str, dict[str, Any]] = {}
_SCAN_SEQ = [0]


# ------------------------------------------------- section-scoped scans ---

async def _section_spans(c, pid: int, space: str, sections: str,
                         module: str, base: int, kernel_lookup: bool):
    """Resolve ``sections='.text,PAGE'`` to ``[(va, size), ...]`` spans
    inside a live module image.

    ``module`` (image name) or ``base`` (image-start VA) selects the
    image; both may be given (module wins). Section names are
    case-insensitive, support ``*``/``?`` globs, and the meta-token
    ``!exec`` matches every executable (IMAGE_SCN_MEM_EXECUTE) section.

    Returns ``(spans, info, err)`` — ``err`` is a ready-to-return
    error dict on failure, else ``None``.
    """
    from fnmatch import fnmatch
    from ....analysis import pe as _pe
    from .._runtime.addrs import _addr_resolve

    want = [w.strip().lower() for w in sections.split(",") if w.strip()]
    if not want:
        return [], None, {
            "ok": False, "kind": "bad_arg",
            "error": "sections= was provided but empty",
            "hint": "sections='.text' | '.text,PAGE' | '!exec'"}
    img_base = base
    if module:
        try:
            img_base = await _addr_resolve(
                module + "+0x0", c, kernel=kernel_lookup, pid=pid,
                name="module")
        except Exception as exc:  # noqa: BLE001 - surfaced verbatim
            return [], None, {"ok": False, "kind": "no_module",
                              "error": f"sections: {exc}"}
    if not img_base:
        return [], None, {
            "ok": False, "kind": "bad_arg",
            "error": "sections= needs module=<image name> or a "
                     "base=/address= pointing at the image start",
            "hint": "memory_manage(action='modules', filter='ntoskrnl') "
                    "to find the base"}
    try:
        hdr = await c.mem_read(pid, img_base, 0x1000, space)
        if isinstance(hdr, tuple):
            hdr = hdr[0]
        need = _pe.header_extent(hdr)
        if need > len(hdr):
            hdr = await c.mem_read(pid, img_base,
                                   min(need, 0x100000), space)
            if isinstance(hdr, tuple):
                hdr = hdr[0]
        img = _pe.parse(bytes(hdr), layout="image")
    except Exception as exc:  # noqa: BLE001 - parse/read errors unify
        return [], None, {
            "ok": False, "kind": "pe_parse",
            "error": f"sections: PE header read/parse at "
                     f"{hex(img_base)} failed: {exc}"}

    spans: list[tuple[int, int]] = []
    matched: list[str] = []
    missed: list[str] = []
    exec_tokens = {"!exec", "!code", "exec"}
    for w in want:
        hit_w = False
        for s in img.sections:
            ok = s.exec if w in exec_tokens else fnmatch(s.name.lower(), w)
            if not ok:
                continue
            sz = s.vsize or s.raw_size
            if sz and (img_base + s.va, sz) not in spans:
                spans.append((img_base + s.va, sz))
                matched.append(s.name)
            hit_w = True
        if not hit_w:
            missed.append(w)
    if not spans:
        return [], None, {
            "ok": False, "kind": "no_sections",
            "error": f"sections: none of {want} matched; image has "
                     f"{[s.name for s in img.sections]}",
            "hint": "names are case-insensitive, '*'/'?' globs "
                    "allowed, '!exec' selects executable sections"}
    info: dict[str, Any] = {
        "module_base": img_base,
        "sections": matched,
        "spans": [{"va": s0, "size": sz} for s0, sz in spans],
        "size_of_image": img.size_of_image,
    }
    if missed:
        info["sections_unmatched"] = missed
    return spans, info, None


# ------------------------------------------------- scan-job state machine --

async def _scan_start(ctx, c, *, pid: int, addr: int,
                       base_i: int, size: int, space: str, kernel: bool,
                       pattern: str, pattern_hex: str, mask: str,
                       max_results: int, module: str = "",
                       sections: str = "",
                       writable: bool = False, executable: bool = False,
                       cow: bool = False, include_guarded: bool = False,
                       mem_types: list[str] | None = None,
                       scope: str = "") -> dict[str, Any]:
    """Kick off a background pattern_scan, return {scan_id, status}."""
    start = base_i or addr
    if kernel and space == "user":
        space_r = "kernel"
    elif space in ("user", "kernel", "physical"):
        space_r = space
    else:
        space_r = "user"
    if pattern:
        from ....sdk import parse_mask
        from ....sdk.reader import PryError as _ScanErr
        try:
            pat, mask_r = parse_mask(pattern)
        except _ScanErr as exc:
            return {"ok": False, "kind": "bad_arg",
                    "error": f"scan_start: {exc}"}
    else:
        pat = bytes.fromhex(pattern_hex) if pattern_hex else b""
        mask_r = mask
    if not pat:
        return {"ok": False, "kind": "bad_arg",
                "error": "scan_start: pattern or pattern_hex is required"}
    max_r = int(max_results or 64)
    # Region-filter / section-scoped mode: resolve the effective
    # (va, size) spans via ``resolve_spans``. This covers both the
    # legacy ``sections=`` path and the Wave-1 region filter
    # (writable / executable / cow / include_guarded / mem_types /
    # scope). resolve_spans delegates to ``_section_spans`` when
    # ``sections=`` is set with no region flags, so the pre-Wave-1
    # behaviour is bit-for-bit preserved.
    span_list: list[tuple[int, int]] | None = None
    span_info: dict[str, Any] = {}
    _any_region = _any_region_flag_set(
        writable=writable, executable=executable, cow=cow,
        include_guarded=include_guarded, mem_types=mem_types, scope=scope)
    if sections or _any_region:
        _kernel_lookup = kernel or space in ("kernel", "physical")
        span_list, span_info, serr = await _resolve_spans(
            c, pid=pid, space=space_r, kernel_lookup=_kernel_lookup,
            address=start, size=size, sections=sections, module=module,
            writable=writable, executable=executable, cow=cow,
            include_guarded=include_guarded, mem_types=mem_types,
            scope=scope)
        if serr:
            return serr
        if not span_list:
            return {"ok": False, "kind": "no_match",
                    "error": "scan_start: region filter resolved to zero spans",
                    "hint": "widen the filter or drop address+size"}
        start = span_list[0][0]
        size = sum(sz for _, sz in span_list)
    # Whole-space unary path can't be cancelled orchestrator-side without
    # the streaming proto RPC (agent-side stretch goal), so demand
    # start+size for the job surface. Small whole-space calls stay on
    # pattern_scan. Note: `address`/`base` may legitimately be 0 — the
    # check is on `size` alone (a 0x0 start scans the low VAs).
    if not size:
        return {"ok": False, "kind": "bad_arg",
                "error": "scan_start requires size>0 for the "
                         "cancellable client-side chunked path "
                         "(address/base may be 0)",
                "hint": "for a small whole-space sweep, use "
                        "memory_manage(action='pattern_scan') directly; "
                        "scan_start is for wide (multi-GiB) ranges where "
                        "you need scan_status/scan_cancel"}
    import asyncio as _asyncio
    import time as _t
    _SCAN_SEQ[0] += 1
    scan_id = f"s{_SCAN_SEQ[0]:04d}"
    cancel_evt = _asyncio.Event()
    owner = _owner_bucket(current_client_id())
    entry: dict[str, Any] = {
        "scan_id": scan_id, "owner": owner,
        "task": None,
        "hits": [], "progress": {
            "bytes_scanned": 0, "bytes_total": int(size),
            "chunks_read": 0, "chunks_skipped": 0,
            "hits_so_far": 0,
        },
        "status": "running",
        "args": {"pid": pid, "start": hex(start), "size": int(size),
                 "space": space_r, "pattern": pattern or pattern_hex,
                 "max_results": max_r,
                 **({"sections": sections,
                     "spans": span_info.get("spans", [])}
                    if sections else {}),
                 **({"region_filter": span_info.get("region_filter"),
                     "region_notes": span_info.get("notes", [])}
                    if _any_region else {})},
        "started_ts": _t.time(), "finished_ts": None,
        "cancel": cancel_evt,
    }
    _SCANS[scan_id] = entry

    async def _runner() -> None:
        from ....sdk import _scan_range_impl, pattern_scan as _match

        class _AdapterView:
            async def read(self, pid, ea, n, sp):
                return await c.mem_read(pid, ea, n, sp)

        try:
            view = _AdapterView()
            # spans -> [(start, end)] pairs. Single-span mode is the
            # historical [start, start+size) range.
            spans_end = [(s0, s0 + sz)
                         for s0, sz in (span_list or [(start, size)])]
            completed = 0  # bytes fully swept before the current span
            chunk = 0x100000
            overlap = max(0, len(pat) - 1)
            # coverage spans — same semantics as
            # sdk._scan_range_impl but tracked across the whole job.
            _cov_scanned: list[tuple[int, int]] = []
            _cov_skipped: list[tuple[int, int]] = []
            for (span_start, end) in spans_end:
                cursor = span_start
                while cursor < end and len(entry["hits"]) < max_r:
                    if cancel_evt.is_set():
                        entry["status"] = "cancelled"
                        break
                    n = min(chunk, end - cursor)
                    data: bytes | None = None
                    try:
                        data = await view.read(pid, cursor, n, space_r)
                    except Exception:
                        # Per-page salvage: identical to sdk._scan_range_impl.
                        prefix = bytearray()
                        page = cursor
                        page_end = cursor + n
                        while page < page_end:
                            if cancel_evt.is_set():
                                entry["status"] = "cancelled"
                                break
                            take = min(0x1000 - (page & 0xFFF), page_end - page)
                            try:
                                p = await view.read(pid, page, take, space_r)
                            except Exception:
                                break
                            if not p:
                                break
                            prefix += p
                            page += len(p)
                            if len(p) < take:
                                break
                        if entry["status"] == "cancelled":
                            break
                        if prefix:
                            data = bytes(prefix)
                        else:
                            adv = 0x1000
                            entry["progress"]["chunks_skipped"] += 1
                            _cov_skipped.append(
                                (cursor, min(cursor + adv, end)))
                            cursor += adv
                            entry["progress"]["bytes_scanned"] = min(
                                completed + (cursor - span_start), size)
                            continue
                    if not data:
                        break
                    entry["progress"]["chunks_read"] += 1
                    _cov_scanned.append(
                        (cursor, min(cursor + len(data), end)))
                    entry["progress"]["bytes_scanned"] = min(
                        completed + (cursor - span_start) + len(data),
                        size)
                    for off in _match(data, pat, mask_r):
                        entry["hits"].append(cursor + off)
                        entry["progress"]["hits_so_far"] = len(entry["hits"])
                        if len(entry["hits"]) >= max_r:
                            break
                    got = len(data)
                    if cursor + got >= end:
                        break
                    cursor = (cursor + got - overlap
                              if got > overlap else cursor + got)
                completed += end - span_start
                if (entry["status"] == "cancelled"
                        or len(entry["hits"]) >= max_r):
                    break
            if entry["status"] == "running":
                entry["status"] = "done"
            # publish the coverage map — for a single
            # span, unscanned is the complement inside [start, end);
            # multi-span (sections=) merges without it.
            try:
                from ....sdk.scan import (_coverage_map, _coalesce,
                                          _COVERAGE_CAP)
                if len(spans_end) == 1:
                    s0, e0 = spans_end[0]
                    entry["coverage"] = _coverage_map(
                        _cov_scanned, _cov_skipped, s0, e0)
                else:
                    # Disjoint spans — 'unscanned' between them is
                    # out of scope, so merge the raw lists directly.
                    def _fmt(rs):
                        return [{"start": hex(s), "end": hex(e)}
                                for s, e in rs[:_COVERAGE_CAP]]
                    sc = _coalesce(_cov_scanned)
                    sk = _coalesce(_cov_skipped)
                    entry["coverage"] = {
                        "scanned": _fmt(sc), "skipped": _fmt(sk),
                        "scanned_ranges": len(sc),
                        "skipped_ranges": len(sk),
                        "truncated": max(len(sc), len(sk))
                                     > _COVERAGE_CAP,
                        "merged_spans": len(spans_end)}
            except Exception:
                pass  # coverage is best-effort, never fails the job
        except Exception as exc:  # noqa: BLE001
            entry["status"] = "error"
            entry["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            entry["finished_ts"] = _t.time()

    entry["task"] = _asyncio.create_task(_runner(), name=f"pry-scan-{scan_id}")
    return {"ok": True, "scan_id": scan_id, "status": "running",
            "owner": owner, "hint": "poll memory_manage(action='scan_status', "
                                   f"scan_id={scan_id!r})"}


def _scan_status(scan_id: str) -> dict[str, Any]:
    entry = _SCANS.get(scan_id)
    if entry is None:
        return {"ok": False, "kind": "unknown_scan",
                "error": f"scan_id {scan_id!r} not found",
                "hint": "memory_manage(action='scan_list') to see active scans"}
    current = current_client_id()
    # Value scans track hits in packed arrays, not entry["hits"]. The
    # legacy pattern path reads entry["hits"] directly; here we pick
    # the right source based on scan_kind.
    is_value = entry.get("scan_kind") == "value"
    hits_so_far = (len(entry.get("snapshot_vas") or ())
                   if is_value else len(entry.get("hits") or ()))
    out: dict[str, Any] = {"ok": True,
            "scan_id": scan_id,
            "scan_kind": entry.get("scan_kind", "pattern"),
            "status": entry["status"],
            "progress": dict(entry["progress"]),
            "hits_so_far": hits_so_far,
            "started_ts": entry["started_ts"],
            "finished_ts": entry.get("finished_ts"),
            "owner": entry["owner"],
            "foreign": entry["owner"] != _owner_bucket(current),
            "error": entry.get("error")}
    if is_value:
        out["value_type"] = entry.get("value_type")
        out["generation"] = int(entry.get("generation", 0))
        out["agent_abi"] = entry.get("agent_abi", "v15")
    return out


def _scan_result(scan_id: str, *, limit: int, offset: int,
                 global_cap: int) -> dict[str, Any]:
    entry = _SCANS.get(scan_id)
    if entry is None:
        return {"ok": False, "kind": "unknown_scan",
                "error": f"scan_id {scan_id!r} not found"}
    if entry["status"] == "running":
        return {"ok": False, "kind": "not_ready",
                "error": f"scan {scan_id!r} is still running",
                "status": "running",
                "progress": dict(entry["progress"]),
                "hint": "memory_manage(action='scan_status') to poll, or "
                        "memory_manage(action='scan_cancel') to stop"}

    # v16 Memory scanner wave 1: value scans keep hits in packed arrays
    # (snapshot_vas + snapshot_raw). scan_result must serve those as
    # ``{va, value}`` rows rather than the pattern-scan bare address
    # list — otherwise every value scan surfaces zero hits (review
    # M2 + L5).
    if entry.get("scan_kind") == "value":
        from . import value_scan as _mem_vscan
        return _mem_vscan._value_scan_response(
            entry, limit=limit, offset=offset, global_cap=global_cap)

    addresses = [hex(a) for a in entry["hits"]]
    return _hexify_dict(_list_envelope(
        addresses, tool="memory_manage", action="scan_result",
        limit=limit or 0, offset=offset,
        fields=(),
        filter="",
        summary=False,
        global_cap=global_cap,
        extras={"scan_id": scan_id,
                "scan_kind": entry.get("scan_kind", "pattern"),
                "status": entry["status"],
                "progress": dict(entry["progress"]),
                "coverage": entry.get("coverage"),
                "started_ts": entry["started_ts"],
                "finished_ts": entry.get("finished_ts"),
                "owner": entry["owner"],
                "args": entry["args"]},
    ), add_int_mirror=True)  # already returns a JSON string envelope


async def _scan_cancel(scan_id: str, c=None) -> dict[str, Any]:
    entry = _SCANS.get(scan_id)
    if entry is None:
        return {"ok": False, "kind": "unknown_scan",
                "error": f"scan_id {scan_id!r} not found"}
    current = _owner_bucket(current_client_id())
    if entry["owner"] != current:
        return {"ok": False, "kind": "foreign_owned",
                "error": f"scan {scan_id!r} owned by {entry['owner']!r}",
                "hint": "pass force=true to override (not implemented "
                        "yet on scan_cancel — ask the peer to cancel)"}
    entry["cancel"].set()
    # v16 (Memory scanner wave 1): propagate cancel to the agent when the
    # scan lives on-target. Local event only is meaningless there
    # (review H6). Best-effort — a failing RPC leaves the local
    # cancel flag set so a subsequent scan_status still reflects
    # cancellation intent.
    if entry.get("agent_abi") == "v16" and c is not None \
            and getattr(c, "scan_service", None) is not None:
        try:
            await c.scan_cancel(scan_id)
        except Exception as exc:  # noqa: BLE001
            entry.setdefault("notes", []).append(
                f"agent_cancel_failed:{type(exc).__name__}")
    return {"ok": True, "scan_id": scan_id,
            "status": entry["status"],
            "hint": "poll scan_status until status == 'cancelled'"}


def _scan_list(current: str) -> dict[str, Any]:
    rows = []
    for sid, entry in _SCANS.items():
        # Value scans track hits in snapshot_vas; pattern scans in
        # entry["hits"]. Reading the wrong one gives a misleading
        # zero (review L5).
        is_value = entry.get("scan_kind") == "value"
        hits_so_far = (len(entry.get("snapshot_vas") or ())
                       if is_value else len(entry.get("hits") or ()))
        row: dict[str, Any] = {
            "scan_id": sid,
            "scan_kind": entry.get("scan_kind", "pattern"),
            "status": entry["status"],
            "hits_so_far": hits_so_far,
            "progress": dict(entry["progress"]),
            "started_ts": entry["started_ts"],
            "owner": entry["owner"],
            "foreign": entry["owner"] != _owner_bucket(current),
            "args": entry["args"],
        }
        if is_value:
            row["value_type"] = entry.get("value_type")
            row["generation"] = int(entry.get("generation", 0))
            row["agent_abi"] = entry.get("agent_abi", "v15")
        rows.append(row)
    rows.sort(key=lambda r: -r["started_ts"])
    return {"ok": True, "count": len(rows), "scans": rows}


# ---- pattern_scan dispatch (sync, ranged + whole-space + sections=) ------

async def handle_pattern_scan(ctx, c, *, pid: int, addr: int, base_i: int,
                              size: int, space: str, kernel: bool,
                              pattern: str, pattern_hex: str, mask: str,
                              max_results: int, module: str,
                              sections: str, kernel_lookup: bool,
                              limit: int, offset: int,
                              fields: list[str] | None, filter: Any,
                              summary: bool,
                              writable: bool = False,
                              executable: bool = False,
                              cow: bool = False,
                              include_guarded: bool = False,
                              mem_types: list[str] | None = None,
                              scope: str = "") -> str:
    """``action='pattern_scan'`` body lifted verbatim from mem.py.

    Returns the fully-serialised JSON envelope string, matching the
    pre-R4 dispatcher's return convention.
    """
    # base is the canonical param; accept address as an alias.
    # kernel=true is honored when space wasn't explicitly set.
    start = base_i or addr
    if kernel and space == "user":
        space_r = "kernel"
    elif space in ("user", "kernel", "physical"):
        space_r = space
    else:
        space_r = "user"
    if pattern:
        from ....sdk import parse_mask
        from ....sdk.reader import PryError as _ScanErr
        try:
            pat, mask_r = parse_mask(pattern)
        except _ScanErr as exc:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": f"pattern_scan: {exc}"})
    else:
        pat = bytes.fromhex(pattern_hex)
        mask_r = mask
    eff_limit = limit or max_results
    # Region-filter / section-scoped scan. Wave 1 Phase A unifies the
    # legacy ``sections=`` path and the new region filter
    # (writable/executable/cow/include_guarded/mem_types/scope) under
    # one span-resolver. ``resolve_spans`` delegates to
    # ``_section_spans`` when ``sections=`` is set alone, so the pre-
    # Wave-1 behaviour is bit-for-bit preserved.
    _any_region = _any_region_flag_set(
        writable=writable, executable=executable, cow=cow,
        include_guarded=include_guarded, mem_types=mem_types, scope=scope)
    if sections or _any_region:
        from ....sdk import scan_range_with_stats
        spans, sinfo, serr = await _resolve_spans(
            c, pid=pid, space=space_r, kernel_lookup=kernel_lookup,
            address=start, size=size, sections=sections, module=module,
            writable=writable, executable=executable, cow=cow,
            include_guarded=include_guarded, mem_types=mem_types,
            scope=scope)
        if serr:
            return _j(serr)
        if not spans:
            return _j({
                "ok": False, "kind": "no_match",
                "error": "pattern_scan: region filter resolved to zero spans",
                "hint": "widen the filter or drop address+size"})
        _mod_base = int(sinfo.get("module_base") or spans[0][0])
        _total_sz = int(sinfo.get("size_of_image")
                        or sum(sz for _, sz in spans))
        hits: list[int] = []
        telem: dict[str, Any] = {
            "start": hex(_mod_base),
            "end": hex(spans[-1][0] + spans[-1][1]),
            "chunk_size": 0x100000,
            "chunks_read": 0, "chunks_skipped": 0,
            "bytes_scanned": 0, "bytes_skipped": 0,
            "partial_chunks": 0, "partial_bytes": 0,
            "truncated": False,
        }
        span_covs: list[dict] = []
        for s0, sz in spans:
            if len(hits) >= max_results:
                telem["truncated"] = True
                break
            h, t = await scan_range_with_stats(
                c, pid, s0, sz, pat, mask_r, space_r,
                max_results=max_results - len(hits))
            hits += h
            for k in ("chunks_read", "chunks_skipped",
                      "bytes_scanned", "bytes_skipped",
                      "partial_chunks", "partial_bytes"):
                telem[k] += t.get(k, 0)
            if isinstance(t.get("coverage"), dict):
                span_covs.append(t["coverage"])
            telem["truncated"] = bool(
                telem["truncated"] or t.get("truncated"))
        # merge per-span coverage; 'unscanned'
        # is meaningless across disjoint section spans so the
        # merged map drops it.
        if span_covs:
            from ....sdk.scan import merge_coverage
            telem["coverage"] = merge_coverage(span_covs)
        addresses = [hex(a) for a in hits]
        extras = {"space": space_r}
        extras.update(telem)
        extras.update(sinfo)
        try:
            _pattern_scan_breadcrumb(
                ctx, pattern=pattern or pattern_hex,
                space=space_r,
                address=_mod_base,
                size=_total_sz,
            )
        except Exception as _bc_exc:  # pragma: no cover
            log.debug("pattern_scan breadcrumb dropped: %s",
                      _bc_exc)
        env = _list_envelope(
            addresses, tool="memory_manage", action="pattern_scan",
            limit=eff_limit, offset=offset,
            fields=fields or (),
            filter=filter,
            summary=summary,
            global_cap=ctx.cfg.mcp_max_items(),
            extras=extras,
        )
        env["coverage"] = _scan_window_cov(telem, ranged=True)
        return _hexify_dict(env, add_int_mirror=True)
    # If the caller gave a range (start or size), run the
    # client-side chunked scan so we can report telemetry
    # (bytes scanned, chunks skipped). Otherwise fall back to
    # the agent-side scan which enumerates the space for us.
    if start or size:
        from ....sdk import scan_range_with_stats
        scan_size = size or 0
        if not scan_size:
            return _j({"ok": False,
                       "error": "pattern_scan with `address`/`base` "
                                "requires `size` too; leave both 0 to "
                                "sweep the whole space."})
        hits, telem = await scan_range_with_stats(
            c, pid, start, scan_size, pat, mask_r,
            space_r, max_results=max_results,
        )
        addresses = [hex(a) for a in hits]
        extras = {"space": space_r}
        extras.update(telem)
        try:
            _pattern_scan_breadcrumb(
                ctx, pattern=pattern or pattern_hex, space=space_r,
                address=start, size=scan_size,
            )
        except Exception as _bc_exc:  # pragma: no cover
            log.debug("pattern_scan breadcrumb dropped: %s", _bc_exc)
        env = _list_envelope(
            addresses, tool="memory_manage", action="pattern_scan",
            limit=eff_limit, offset=offset,
            fields=fields or (),
            filter=filter,
            summary=summary,
            global_cap=ctx.cfg.mcp_max_items(),
            extras=extras,
        )
        env["coverage"] = _scan_window_cov(telem, ranged=True)
        return _hexify_dict(env, add_int_mirror=True)
    # Whole-space: agent-side scan. 'H'/'L' nibble mask
    # positions (pattern tokens '6?'/'?F') are byte-granular
    # on the wire, so sdk.scan downgrades them to '?' and
    # post-verifies each candidate via mem_read.
    from ....sdk.scan import agent_pattern_scan
    hits = await agent_pattern_scan(
        c, pid, pat, mask_r, 0, 0, max_results, space_r)
    addresses = [hex(a) for a in hits]
    try:
        _pattern_scan_breadcrumb(
            ctx, pattern=pattern or pattern_hex, space=space_r,
            address=0, size=0,
        )
    except Exception as _bc_exc:  # pragma: no cover
        log.debug("pattern_scan breadcrumb dropped: %s", _bc_exc)
    env = _list_envelope(
        addresses, tool="memory_manage", action="pattern_scan",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={"space": space_r, "start": None, "end": None,
                "note": "whole-space scan; pass address+size for telemetry"},
    )
    env["coverage"] = _scan_window_cov(None, ranged=False)
    return _hexify_dict(env, add_int_mirror=True)


# ---- scan-job action entry points ---------------------------------------

async def handle_scan_start(ctx, c, *, pid: int, addr: int, base_i: int,
                            size: int, space: str, kernel: bool,
                            pattern: str, pattern_hex: str, mask: str,
                            max_results: int, module: str,
                            sections: str,
                            writable: bool = False,
                            executable: bool = False,
                            cow: bool = False,
                            include_guarded: bool = False,
                            mem_types: list[str] | None = None,
                            scope: str = "") -> str:
    return _j(await _scan_start(
        ctx, c, pid=pid, addr=addr, base_i=base_i,
        size=size, space=space, kernel=kernel,
        pattern=pattern, pattern_hex=pattern_hex,
        mask=mask, max_results=max_results,
        module=module, sections=sections,
        writable=writable, executable=executable, cow=cow,
        include_guarded=include_guarded, mem_types=mem_types,
        scope=scope,
    ))


async def handle_scan_status(scan_id: str, c=None) -> str:
    """Return scan status. For v16 value scans, pulls live progress +
    hit_count from the agent (review H5). v15 scans and pattern scans
    just render the local entry."""
    entry = _SCANS.get(scan_id)
    if (entry is not None
            and entry.get("agent_abi") == "v16"
            and c is not None
            and getattr(c, "scan_service", None) is not None):
        try:
            agent = await c.scan_status(scan_id)
            if agent.get("ok"):
                # Merge agent-side fields into the local view.
                entry["status"] = agent.get("status") or entry.get("status")
                ap = agent.get("progress") or {}
                for k in ("bytes_scanned", "bytes_total", "chunks_read",
                          "chunks_skipped", "hits_so_far", "reads_failed"):
                    if k in ap:
                        entry["progress"][k] = int(ap[k] or 0)
                if agent.get("generation") is not None:
                    entry["generation"] = int(agent["generation"])
        except Exception as exc:  # noqa: BLE001 — surface as a note
            entry.setdefault("notes", []).append(
                f"agent_status_failed:{type(exc).__name__}")
    return _j(_scan_status(scan_id))


async def handle_scan_result(ctx, scan_id: str, *, limit: int,
                             offset: int, c=None) -> str:
    """Return the hits for a completed scan.

    v15 value scans + pattern scans: read directly from the local
    entry — ``snapshot_vas`` / ``snapshot_raw`` for value, ``hits`` for
    pattern.

    v16 value scans: the snapshot lives on the agent, so refresh the
    status + progress from the agent (so a scan that has already
    completed on-target is no longer reported as ``running`` locally),
    then pull the hits once via ``ScanService.Fetch`` and cache into
    the local ``snapshot_vas`` / ``snapshot_raw`` arrays keyed by
    generation. Subsequent calls at the same generation serve from
    the local cache. Pattern scans never took the v16 path."""
    import array as _array
    entry = _SCANS.get(scan_id)
    if (entry is not None
            and entry.get("agent_abi") == "v16"
            and entry.get("scan_kind") == "value"
            and c is not None
            and getattr(c, "scan_service", None) is not None):
        # Refresh status so a done-on-agent scan doesn't stay stuck
        # as ``running`` locally (the Create reply returned immediately
        # with status="running" and the orchestrator never polled).
        try:
            agent = await c.scan_status(scan_id)
            if agent.get("ok"):
                entry["status"] = agent.get("status") or entry.get("status")
                ap = agent.get("progress") or {}
                for k in ("bytes_scanned", "bytes_total", "chunks_read",
                          "chunks_skipped", "hits_so_far", "reads_failed"):
                    if k in ap:
                        entry["progress"][k] = int(ap[k] or 0)
                if agent.get("generation") is not None:
                    entry["generation"] = int(agent["generation"])
        except Exception as exc:  # noqa: BLE001
            entry.setdefault("notes", []).append(
                f"agent_status_failed:{type(exc).__name__}")
        cached_gen = entry.get("_fetch_cached_generation", -1)
        cur_gen = int(entry.get("generation", 0))
        if cached_gen != cur_gen:
            vas: _array.array = _array.array("Q")
            raw = bytearray()
            width = int(entry.get("width") or 0) or 4
            try:
                async for chunk in c.scan_fetch(
                        scan_id=scan_id, generation=cur_gen,
                        limit=0, offset=0):
                    if not chunk.get("ok", False):
                        entry.setdefault("notes", []).append(
                            f"agent_fetch_failed:{chunk.get('error','')}")
                        break
                    for row in chunk.get("rows", []):
                        vas.append(int(row["va"]))
                        rb = bytes(row["raw"])
                        if len(rb) < width:
                            rb = rb + b"\x00" * (width - len(rb))
                        raw += rb[:width]
                    if chunk.get("eof"):
                        break
            except Exception as exc:  # noqa: BLE001
                entry.setdefault("notes", []).append(
                    f"agent_fetch_failed:{type(exc).__name__}")
            else:
                entry["snapshot_vas"] = vas
                entry["snapshot_raw"] = raw
                entry["_fetch_cached_generation"] = cur_gen
    out = _scan_result(scan_id, limit=limit, offset=offset,
                       global_cap=ctx.cfg.mcp_max_items())
    return out if isinstance(out, str) else _j(out)


async def handle_scan_cancel(scan_id: str, c=None) -> str:
    return _j(await _scan_cancel(scan_id, c=c))


def handle_scan_list() -> str:
    return _j(_scan_list(current_client_id()))
