"""Memory scanner wave 3 §6.4 — ``InvariantFieldFinder``.

Two layers, strict priority:

1. **Baked JSON** (``artifacts/invariants/eprocess/<build>.json``) is
   authoritative. On use we read the DISPATCHER_HEADER type byte on
   the candidate base VA and assert it matches
   ``assertion.dispatcher_header_type_value``. A mismatch (build in
   the table but the layout drifted) hands the caller back to the
   scanner.
2. **Invariant scan** is the last resort — only engaged when the
   caller opts in with ``lookup_by.allow_invariant=true``. The anchor
   stack is DISPATCHER_HEADER type + the three-hop
   ``ActiveProcessLinks`` ring closure + a backward scan for
   ``UniqueProcessId`` + a forward scan for ``ImageFileName``. Much
   stronger than r1's "look for the PID as a u64".

Scope: Wave 3 ships ``_EPROCESS`` only. Wave 4 will widen to
``_ETHREAD`` / ``_DRIVER_OBJECT`` / ``_KPCR``.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Awaitable, Callable

log = logging.getLogger("pry.mcp.tools.kernel.invariants")


# ---------------------------------------------------------- baked table ----

def _baked_dir() -> Path:
    """Repo location of the shipped JSON tables.

    ``src/pry/mcp/tools/kernel/_invariants.py`` sits five levels
    under the repo root (``orchestrator/src/pry/mcp/tools/
    kernel/``). The baked directory lives at the repo root in
    ``artifacts/invariants/eprocess/``.
    """
    here = Path(__file__).resolve()
    # <repo>/orchestrator/src/pry/mcp/tools/kernel/_invariants.py
    #        parents[0]=kernel parents[1]=tools parents[2]=mcp
    #        parents[3]=pry parents[4]=src parents[5]=orchestrator
    #        parents[6]=<repo>
    repo_root = here.parents[6]
    return repo_root / "artifacts" / "invariants" / "eprocess"


def _candidates_for_build(build_major: int) -> list[str]:
    """Which filenames to probe for a given build. The repo ships
    files like ``win10_19041.json`` / ``win11_26100.json``; map the
    build number to the matching stem(s).
    """
    if build_major <= 0:
        return []
    out: list[str] = []
    # Win10: 19041 (20H2), 19042 (20H2), 19043 (21H1), 19044 (21H2),
    # 19045 (22H2). Win11: 22000 (21H2), 22621/22631 (22H2/23H2),
    # 26100 (24H2). Match exact build first, then nearest family
    # peer (shared PDB types between minor updates).
    if build_major < 22000:
        # Win10 family — 19041 is the shared starting point
        if build_major >= 19045:
            out.append("win10_19045.json")
        if build_major >= 19041:
            out.append("win10_19041.json")
    elif build_major < 26000:
        # Win11 22H2/23H2 — 22631 is the newer; 22631 and 22621 share
        if build_major >= 22631:
            out.append("win11_22631.json")
        else:
            out.append("win11_22631.json")
    else:
        # Win11 24H2
        out.append("win11_26100.json")
    return out


def load_baked(build_major: int, *,
               baked_dir: Path | None = None) -> dict[str, Any] | None:
    """Load the matching baked offset table, or ``None`` when none
    ship for this build."""
    root = baked_dir or _baked_dir()
    if not root.is_dir():
        return None
    for name in _candidates_for_build(build_major):
        p = root / name
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to parse baked table %s: %s", p, exc)
            continue
        if not isinstance(data, dict):
            continue
        return data
    return None


# The build key is the target's full_build_string ("26200.9186"). It
# comes from the target, so only a plain filename-safe key maps to a
# cache path: anything with a separator or ".." is never read or written.
_BUILD_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _discovered_path(build: str, artifacts_dir: Path | str) -> Path | None:
    if not build or ".." in build or not _BUILD_KEY.fullmatch(build):
        return None
    return (Path(artifacts_dir) / "invariants" / "eprocess"
            / f"{build}.discovered.json")


def cache_discovered(build: str, offsets: dict[str, Any],
                     artifacts_dir: Path | str) -> None:
    """Persist walker-discovered offsets to ``<artifacts>/invariants/
    eprocess/<build>.discovered.json`` so the next call on the same
    build re-uses them without rescanning (see :func:`load_discovered`).
    """
    out = _discovered_path(build, artifacts_dir)
    if out is None:
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    body = {"build": build, "arch": "x64",
            "eprocess": offsets or {},
            "note": "walker-discovered — assertion-gated reuse only"}
    out.write_text(json.dumps(body, indent=2), encoding="utf-8")


def load_discovered(build: str,
                    artifacts_dir: Path | str) -> dict[str, Any] | None:
    """The ``eprocess`` offsets :func:`cache_discovered` wrote for this
    build, or ``None``. Callers must gate reuse with
    :func:`discovered_layout_holds` before trusting them."""
    p = _discovered_path(build, artifacts_dir)
    if p is None or not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        log.warning("failed to parse discovered cache %s: %s", p, exc)
        return None
    eprocess = data.get("eprocess") if isinstance(data, dict) else None
    return eprocess if isinstance(eprocess, dict) and eprocess else None


async def discovered_layout_holds(read: "ReadFn", base: int,
                                  layout: dict[str, dict[str, Any]],
                                  hint_pid: int | None) -> bool:
    """Gate for reusing cached walker offsets on ``base``: the
    DISPATCHER_HEADER must still say ProcessObject and, when the caller
    names a PID, ``UniqueProcessId`` at the cached offset must equal it.
    A miss sends the caller back to a fresh scan, which rewrites the
    cache."""
    if not await InvariantFieldFinder()._dispatcher_hdr_ok(read, base):
        return False
    upid = layout.get("UniqueProcessId")
    if hint_pid is None or not upid:
        return True
    try:
        raw = await read(base + int(upid["offset"]), 8)
    except Exception:  # noqa: BLE001
        return False
    return len(raw) == 8 and int.from_bytes(raw, "little") == int(hint_pid)


# ---------------------------------------------------------- the walker ----

ReadFn = Callable[[int, int], Awaitable[bytes]]


class InvariantFieldFinder:
    """§6.4 strengthened scanner.

    The orchestrator-side walker; ``_read(va, size)`` is a plain async
    reader (the kernel view's ``mem_read`` wrapper, or a bytes-backed
    stub in the unit tests).
    """

    # Scan window for ActiveProcessLinks: §6.4 pins this to
    # [0x100, 0x400) on 8-byte boundaries. Wide enough to cover every
    # x64 build we have seen without inviting false positives.
    _FLINK_LO = 0x100
    _FLINK_HI = 0x400
    _FLINK_STEP = 8

    # Ring-closure depth. §6.4 asks for 20+ iterations without
    # cycling — that's enough to reject a two-node fake ring made by
    # two colliding pointers.
    _RING_HOPS = 20

    _DISPATCH_TYPE = 0x03         # KOBJECTS::ProcessObject
    _DISPATCH_TIMER = 0x00        # expected TimerType byte on EPROCESS

    def __init__(self) -> None:
        pass

    async def _dispatcher_hdr_ok(self, read: ReadFn, base: int) -> bool:
        try:
            hdr = await read(base, 2)
        except Exception:  # noqa: BLE001
            return False
        if not hdr or len(hdr) < 2:
            return False
        return hdr[0] == self._DISPATCH_TYPE \
            and hdr[1] == self._DISPATCH_TIMER

    async def _find_active_process_links(self, read: ReadFn,
                                         base: int) -> int | None:
        """Scan [0x100, 0x400) for an ``ActiveProcessLinks`` LIST_ENTRY.

        A valid slot has ``Flink - off`` pointing to another block
        whose dispatcher header passes, and the three-hop ring must
        close within :attr:`_RING_HOPS` iterations.
        """
        try:
            window = await read(base + self._FLINK_LO,
                                self._FLINK_HI - self._FLINK_LO)
        except Exception:  # noqa: BLE001
            return None
        if not window or len(window) < 16:
            return None
        import struct as _s
        for off_rel in range(0, len(window) - 16, self._FLINK_STEP):
            flink, blink = _s.unpack_from("<QQ", window, off_rel)
            if not flink or not blink:
                continue
            off_abs = self._FLINK_LO + off_rel
            # Walk the ring: each hop's EPROCESS base is `node - off`.
            seen: set[int] = {base}
            cur = flink
            closed = False
            for _ in range(self._RING_HOPS):
                neighbor = cur - off_abs
                if neighbor in seen:
                    closed = True
                    break
                seen.add(neighbor)
                if not await self._dispatcher_hdr_ok(read, neighbor):
                    closed = False
                    break
                try:
                    nxt = await read(cur, 8)
                except Exception:  # noqa: BLE001
                    closed = False
                    break
                if len(nxt) < 8:
                    closed = False
                    break
                cur = _s.unpack_from("<Q", nxt, 0)[0]
                if not cur:
                    closed = False
                    break
            if closed and len(seen) >= 2:
                return off_abs
        return None

    async def _find_unique_process_id(self, read: ReadFn, base: int,
                                      apl_off: int,
                                      hint_pid: int | None
                                      ) -> tuple[int, int] | None:
        """Scan backward from ``apl_off`` for the ``UniqueProcessId``
        slot. ``hint_pid`` (when supplied) gates the match; otherwise
        we accept any plausible small positive value.
        """
        lo = max(0, apl_off - 0x80)
        size = apl_off - lo
        if size < 8:
            return None
        try:
            buf = await read(base + lo, size)
        except Exception:  # noqa: BLE001
            return None
        if len(buf) < size:
            return None
        import struct as _s
        # UniqueProcessId is a HANDLE (u64) — all historical builds
        # keep it on an 8-byte boundary. Walk latest -> earliest so
        # the field *nearest* ActiveProcessLinks wins the race when
        # ties exist.
        for rel in range(size - 8, -1, -8):
            v = _s.unpack_from("<Q", buf, rel)[0]
            if v == 0 or v > 0x00FF_FFFF:  # PIDs cap ~16M in practice
                continue
            if hint_pid is not None and int(v) != int(hint_pid):
                continue
            return lo + rel, int(v)
        return None

    async def _find_image_filename(self, read: ReadFn, base: int,
                                   apl_off: int) -> tuple[int, int] | None:
        """Scan forward from ``apl_off`` for a 15-byte ASCII run with
        a trailing NUL — the ImageFileName field.
        """
        lo = apl_off
        hi = apl_off + 0x600
        try:
            buf = await read(base + lo, hi - lo)
        except Exception:  # noqa: BLE001
            return None
        if not buf:
            return None
        n = len(buf)
        for rel in range(0, n - 16, 8):
            window = buf[rel:rel + 16]
            # 1..14 printable ASCII bytes then NUL, no embedded NUL
            run = 0
            for b in window[:15]:
                if 0x20 <= b <= 0x7E:
                    run += 1
                    continue
                break
            if 1 <= run <= 14 and window[run] == 0x00:
                return lo + rel, 15
        return None

    async def scan(self, read: ReadFn, candidate_base: int, *,
                   hint_pid: int | None = None) -> dict[str, Any]:
        """Run the full scan on ``candidate_base``. Returns one of:

        * ``{"ok": True, "layout": {...}, "eprocess": {...}, "evidence": {...}}``
          — enough to feed :func:`_struct_read.decode_fields`.
        * ``{"ok": False, "kind": ..., "error": ...}`` — the step that
          failed; useful for reporting under ``candidate_offsets``.
        """
        if not await self._dispatcher_hdr_ok(read, candidate_base):
            return {"ok": False, "kind": "eprocess_anchor_failed",
                    "error": "DISPATCHER_HEADER does not look like an "
                             "EPROCESS at the candidate base"}
        apl_off = await self._find_active_process_links(read,
                                                       candidate_base)
        if apl_off is None:
            return {"ok": False, "kind": "eprocess_anchor_failed",
                    "error": "no ActiveProcessLinks LIST_ENTRY with a "
                             "closed three-hop ring in [0x100, 0x400)"}
        upid_hit = await self._find_unique_process_id(
            read, candidate_base, apl_off, hint_pid)
        img_hit = await self._find_image_filename(
            read, candidate_base, apl_off)
        eprocess: dict[str, dict[str, Any]] = {
            "ActiveProcessLinks": {"offset": apl_off, "size": 16,
                                   "kind": "ptr"},
        }
        if upid_hit is not None:
            eprocess["UniqueProcessId"] = {
                "offset": upid_hit[0], "size": 8, "kind": "scalar"}
        if img_hit is not None:
            eprocess["ImageFileName"] = {
                "offset": img_hit[0], "size": img_hit[1],
                "kind": "string_ansi"}
        layout: dict[str, dict[str, Any]] = {}
        for name, spec in eprocess.items():
            layout[name] = {"offset": spec["offset"],
                            "size": spec["size"],
                            "kind": spec["kind"]}
        if "UniqueProcessId" not in eprocess and "ImageFileName" \
                not in eprocess:
            return {"ok": False, "kind": "eprocess_offsets_unknown",
                    "error": "found ActiveProcessLinks but neither "
                             "UniqueProcessId nor ImageFileName",
                    "offsets": eprocess}
        return {"ok": True,
                "layout": layout,
                "eprocess": eprocess,
                "evidence": {
                    "active_process_links_offset": apl_off,
                    "unique_process_id_matched": bool(upid_hit),
                    "image_filename_matched": bool(img_hit),
                }}


__all__ = [
    "InvariantFieldFinder",
    "cache_discovered",
    "discovered_layout_holds",
    "load_baked",
    "load_discovered",
]
