"""Memory scanner wave 1: typed value_scan + next_scan + scan_undo
(orchestrator-RAM path, with v16 agent-routing hook).

This is the Wave 1 primary surface. Two paths share one `_SCANS`
registry (in :mod:`mem.scan`), one envelope shape, and one scan_id
prefix (``v####``):

* **v15 fallback** — orchestrator-RAM snapshot. ``resolve_spans`` to
  pick spans, ``scan_range_with_stats`` to read, typed probe at each
  aligned offset. Snapshot stored as packed ``array('Q')`` VAs +
  ``bytearray`` raw values (plan §2.6). Capped at
  ``SCAN_SNAPSHOT_MAX_BYTES = 128 MiB``. Works against the current
  live agent (no rebuild required).

* **v16 on-target** — delegates Create / Refine / Undo / Fetch /
  Destroy to ``AgentClient.scan_*`` wrappers (``ScanMixin``). Snapshot
  lives on the agent under ``<agent_dir>\\scans\\``. Kicks in once
  the agent advertises ``scan_service_version >= 1``; until then,
  this code path is dormant and v15 handles every call.

Routing is frozen at scan creation. A scan started on v15 stays on
v15 even if the agent is later upgraded (its snapshot lives in
orchestrator RAM; moving it mid-flight is Wave 2).

See ``an internal plan`` for the full
contract (API surface §3, caps §2.7, error-kind tables §3.1–§3.4).
"""
from __future__ import annotations

import array
import asyncio
import struct
import time
from typing import Any, Callable

from ....caller import current_client_id
from .._runtime.breadcrumbs import _pattern_scan_breadcrumb
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict, _j
from .region_filter import _any_region_flag_set, resolve_spans as _resolve_spans
from . import scan as _mem_scan
from .scan import _owner_bucket


# ======================================================================
# Config constants — see plan §2.7
# ======================================================================

SCAN_SNAPSHOT_MAX_BYTES = 128 * 1024 * 1024   # v15 fallback cap
SCAN_UNDO_DEPTH = 4
SCAN_UNDO_BYTES_TOTAL = 256 * 1024 * 1024
BATCH_READ_BYTES = 0x40000  # 256 KiB (next_scan coalesce window)
SYNC_SPAN_MAX_BYTES = 64 * 1024 * 1024  # above => too_wide, use scan_start

_FLOAT_DEFAULT_TOL = 1e-4
_DOUBLE_DEFAULT_TOL = 1e-7


# ======================================================================
# Value-type registry
# ======================================================================

# (python struct fmt without endian, width in bytes, is_float, is_signed)
_INT_TYPES: dict[str, tuple[str, int, bool, bool]] = {
    "int8":  ("b", 1, False, True),
    "uint8": ("B", 1, False, False),
    "int16":  ("h", 2, False, True),
    "uint16": ("H", 2, False, False),
    "int32":  ("i", 4, False, True),
    "uint32": ("I", 4, False, False),
    "int64":  ("q", 8, False, True),
    "uint64": ("Q", 8, False, False),
    "float":  ("f", 4, True, True),
    "double": ("d", 8, True, True),
}


_VALID_FIRST_OPS = {"eq", "lt", "gt", "between", "unknown"}
_VALID_NEXT_OPS = {
    "eq", "lt", "gt", "between",
    "changed", "unchanged", "increased", "decreased",
    "increased_by", "decreased_by",
}


def _is_string_type(value_type: str) -> bool:
    return value_type in ("string", "utf16")


def _default_tolerance(value_type: str) -> float:
    if value_type == "float":
        return _FLOAT_DEFAULT_TOL
    if value_type == "double":
        return _DOUBLE_DEFAULT_TOL
    return 0.0


def _struct_fmt(value_type: str, endian: str) -> str:
    """Return a ``struct`` format string for int/float value_type.

    Endian prefix: ``'<'`` LE, ``'>'`` BE. Strings do not pass through.
    """
    base, _w, _is_float, _is_signed = _INT_TYPES[value_type]
    return ("<" if endian == "le" else ">") + base


def _width_of(value_type: str, encoding: str, value: Any) -> int:
    if value_type in _INT_TYPES:
        return _INT_TYPES[value_type][1]
    if _is_string_type(value_type):
        s = str(value or "")
        enc = encoding or ("utf16le" if value_type == "utf16" else "utf8")
        return len(_encode_string(s, value_type, enc))
    raise ValueError(f"unknown value_type {value_type!r}")


def _encode_string(s: str, value_type: str, encoding: str) -> bytes:
    """Encode ``s`` for byte-wise comparison. Fixed-length; no NUL.

    * ``value_type='string'`` honours ``encoding in {ascii,utf8}``.
    * ``value_type='utf16'`` ignores ``encoding``.
    * Returns raw bytes exactly as they'd lie in memory.
    """
    enc = encoding or ("utf16le" if value_type == "utf16" else "utf8")
    if value_type == "utf16":
        # Accept the explicit utf16le / utf16be strings; default LE.
        if enc not in ("utf16le", "utf16be"):
            enc = "utf16le"
        return s.encode(enc.replace("utf16", "utf-16-"))
    # value_type == 'string'
    if enc == "utf16le":
        return s.encode("utf-16-le")
    if enc == "utf16be":
        return s.encode("utf-16-be")
    if enc not in ("ascii", "utf8"):
        enc = "utf8"
    return s.encode("utf-8" if enc == "utf8" else "ascii")


# ======================================================================
# Probe — closes over value_type/op/value and returns (buf, off) -> bool
# ======================================================================


def _coerce_number(v: Any, value_type: str) -> int | float:
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        s = v.strip()
        if value_type in ("float", "double"):
            return float(s)
        # Hex / decimal / octal via int(s, 0)
        return int(s, 0)
    raise ValueError(f"cannot coerce {v!r} to {value_type}")


def pack_probe(*, value_type: str, op: str, value: Any,
               value_hi: Any = None, delta: Any = None,
               endian: str = "le", encoding: str = "",
               tolerance: float = 0.0,
               ) -> Callable[[bytes, int], bool]:
    """Build the inner-loop predicate.

    Returns a callable ``(buf: bytes, off: int) -> bool``. No
    allocation per call; width is captured.
    """
    width = _width_of(value_type, encoding, value)
    _, _, is_float, _is_signed = _INT_TYPES.get(
        value_type, ("", width, False, False))

    # --- String types: exact byte match --------------------------------
    if _is_string_type(value_type):
        needle = _encode_string(str(value or ""), value_type, encoding)
        nlen = len(needle)
        if op == "eq":
            def pred(buf: bytes, off: int) -> bool:
                return (off + nlen <= len(buf)
                        and buf[off:off + nlen] == needle)
            return pred
        raise ValueError(
            f"strings only support op='eq'; got op={op!r} — "
            "use pattern_scan for substring")

    # --- Numeric types -------------------------------------------------
    fmt = _struct_fmt(value_type, endian)
    unpack = struct.Struct(fmt).unpack_from

    if op == "unknown":
        # Match every aligned slot: predicate is constant True.
        def pred(buf: bytes, off: int) -> bool:
            return off + width <= len(buf)
        return pred

    v = _coerce_number(value, value_type)

    if op == "eq":
        if is_float:
            tol = float(tolerance) if tolerance else _default_tolerance(value_type)
            def pred(buf: bytes, off: int) -> bool:
                if off + width > len(buf):
                    return False
                (cur,) = unpack(buf, off)
                return abs(cur - v) <= tol
            return pred
        def pred(buf: bytes, off: int) -> bool:
            if off + width > len(buf):
                return False
            (cur,) = unpack(buf, off)
            return cur == v
        return pred

    if op == "lt":
        def pred(buf: bytes, off: int) -> bool:
            if off + width > len(buf):
                return False
            (cur,) = unpack(buf, off)
            return cur < v
        return pred

    if op == "gt":
        def pred(buf: bytes, off: int) -> bool:
            if off + width > len(buf):
                return False
            (cur,) = unpack(buf, off)
            return cur > v
        return pred

    if op == "between":
        if value_hi is None:
            raise ValueError("op='between' requires value_hi")
        v2 = _coerce_number(value_hi, value_type)
        lo, hi = min(v, v2), max(v, v2)
        def pred(buf: bytes, off: int) -> bool:
            if off + width > len(buf):
                return False
            (cur,) = unpack(buf, off)
            return lo <= cur <= hi
        return pred

    raise ValueError(f"unsupported first-scan op={op!r}")


# ======================================================================
# Snapshot storage helpers
# ======================================================================


def _snapshot_bytes_total(entry: dict[str, Any]) -> int:
    v = entry.get("snapshot_vas")
    r = entry.get("snapshot_raw")
    return (len(v) * 8 if v is not None else 0) + (len(r) if r is not None else 0)


def _undo_bytes_total(entry: dict[str, Any]) -> int:
    return sum(len(vs) + len(rs) for vs, rs in entry.get("undo_stack", []))


def _push_undo(entry: dict[str, Any]) -> None:
    """Snapshot current gen onto undo stack; enforce §2.6 caps."""
    v = entry["snapshot_vas"]
    r = entry["snapshot_raw"]
    frame = (bytes(v), bytes(r))
    stack: list[tuple[bytes, bytes]] = entry.setdefault("undo_stack", [])
    stack.append(frame)
    dropped = 0
    while len(stack) > SCAN_UNDO_DEPTH:
        stack.pop(0)
        dropped += 1
    while stack and _undo_bytes_total(entry) > SCAN_UNDO_BYTES_TOTAL:
        stack.pop(0)
        dropped += 1
    if dropped:
        entry.setdefault("notes", []).append(f"undo_frames_dropped:{dropped}")


def _pop_undo(entry: dict[str, Any]) -> tuple[bytes, bytes] | None:
    stack: list[tuple[bytes, bytes]] = entry.get("undo_stack") or []
    if not stack:
        return None
    return stack.pop()


def _decode_from_raw(raw: bytes, off: int, width: int,
                     value_type: str, endian: str,
                     encoding: str) -> Any:
    chunk = raw[off:off + width]
    if _is_string_type(value_type):
        enc = encoding or ("utf16le" if value_type == "utf16" else "utf8")
        try:
            if value_type == "utf16":
                py_enc = "utf-16-le" if enc != "utf16be" else "utf-16-be"
            elif enc == "utf16le":
                py_enc = "utf-16-le"
            elif enc == "utf16be":
                py_enc = "utf-16-be"
            else:
                py_enc = "utf-8" if enc != "ascii" else "ascii"
            return chunk.decode(py_enc, errors="replace")
        except Exception:  # noqa: BLE001
            return chunk.hex()
    fmt = _struct_fmt(value_type, endian)
    try:
        (val,) = struct.unpack(fmt, chunk)
        return val
    except struct.error:
        return chunk.hex()


# ======================================================================
# First-scan pre-flight (shared between v15 and v16 paths)
# ======================================================================


def _validate_create_args(*, value_type: str, op: str, endian: str,
                          encoding: str, tolerance: float,
                          value: Any, value_hi: Any,
                          align: int) -> dict[str, Any] | None:
    if value_type not in _INT_TYPES and not _is_string_type(value_type):
        return {"ok": False, "kind": "bad_arg",
                "error": f"value_scan: unknown value_type={value_type!r}",
                "hint": "int8..int64, uint8..uint64, float, double, "
                        "string, utf16"}
    if op not in _VALID_FIRST_OPS:
        return {"ok": False, "kind": "bad_arg",
                "error": f"value_scan: unknown op={op!r}",
                "hint": "eq | lt | gt | between | unknown"}
    if endian not in ("le", "be"):
        return {"ok": False, "kind": "bad_arg",
                "error": f"value_scan: endian must be 'le' or 'be', got {endian!r}"}
    if _is_string_type(value_type) and endian != "le":
        # endian is ignored for strings; being strict surfaces caller
        # confusion early.
        return {"ok": False, "kind": "bad_arg",
                "error": "value_scan: endian= is ignored for string/utf16; "
                         "drop it or use the encoding= kwarg"}
    if tolerance and value_type not in ("float", "double"):
        return {"ok": False, "kind": "bad_arg",
                "error": "value_scan: tolerance= is only valid for "
                         "float / double"}
    if op == "between" and (value_hi is None or value_hi == ""):
        return {"ok": False, "kind": "bad_arg",
                "error": "value_scan: op='between' requires value_hi"}
    if op == "unknown" and (value not in (None, "", 0) or value_hi not in (None, "", 0)):
        # value=0 is ambiguous with unset; we treat 0 as unset to be
        # friendly, but non-zero value= with op='unknown' is still an
        # error.
        if value not in (None, "", 0):
            return {"ok": False, "kind": "bad_arg",
                    "error": "value_scan: op='unknown' must not carry a "
                             "value= argument"}
    if align not in (1, 2, 4, 8):
        return {"ok": False, "kind": "bad_arg",
                "error": f"value_scan: align must be 1/2/4/8, got {align!r}"}
    return None


# ======================================================================
# v15 fallback: orchestrator-RAM first scan
# ======================================================================


async def _run_first_scan_v15(entry: dict[str, Any], c, *,
                               pid: int, space_r: str,
                               spans: list[tuple[int, int]],
                               probe: Callable[[bytes, int], bool],
                               align: int, width: int,
                               max_results: int) -> None:
    """Fill ``entry`` (vas + raw + progress) by chunked span iteration.

    Mutates ``entry`` in place; honours ``entry['cancel']`` and
    ``SCAN_SNAPSHOT_MAX_BYTES``.
    """
    from ....sdk import scan_range_with_stats  # noqa: E402  (local; sdk is heavy)

    vas: array.array = entry["snapshot_vas"]
    raw: bytearray = entry["snapshot_raw"]
    progress = entry["progress"]
    cancel = entry["cancel"]

    chunk_size = 0x100000  # 1 MiB
    overlap = max(0, width - 1)
    total_bytes = sum(sz for _, sz in spans)
    progress["bytes_total"] = int(total_bytes)
    completed = 0

    for span_start, span_size in spans:
        if cancel.is_set() or len(vas) >= max_results:
            if cancel.is_set():
                entry["coverage_status"] = "partial"
                entry.setdefault("notes", []).append("cancelled")
            break
        cursor = span_start
        end = span_start + span_size
        # Align cursor relative to span start (plan §2.12).
        align_off = (cursor - span_start) % align
        if align_off:
            cursor += (align - align_off)
        while cursor < end and len(vas) < max_results:
            if cancel.is_set():
                entry["status"] = "cancelled"
                entry["coverage_status"] = "partial"
                entry.setdefault("notes", []).append("cancelled")
                return
            n = min(chunk_size, end - cursor)
            try:
                data = await c.mem_read(pid, cursor, n, space_r,
                                        partial=(space_r != "user"))
                if isinstance(data, tuple):
                    data = data[0]
            except Exception:  # noqa: BLE001
                progress["chunks_skipped"] = int(progress.get("chunks_skipped", 0)) + 1
                entry["coverage_status"] = "partial"
                reason = f"reads_failed:{progress['chunks_skipped']}"
                notes = entry.setdefault("notes", [])
                # Replace the last reads_failed:* note to avoid an N-long
                # list of near-duplicates.
                if notes and str(notes[-1]).startswith("reads_failed:"):
                    notes[-1] = reason
                else:
                    notes.append(reason)
                adv = max(0x1000, align)
                cursor += adv
                continue
            if not data:
                break
            progress["chunks_read"] = int(progress.get("chunks_read", 0)) + 1
            progress["bytes_scanned"] = min(
                completed + (cursor - span_start) + len(data), total_bytes)
            # Iterate aligned offsets inside the chunk.
            rel_start = (cursor - span_start) % align
            if rel_start:
                off = align - rel_start
            else:
                off = 0
            data_len = len(data)
            while off + width <= data_len:
                if probe(data, off):
                    hit_va = cursor + off
                    vas.append(hit_va)
                    raw += data[off:off + width]
                    if _snapshot_bytes_total(entry) > SCAN_SNAPSHOT_MAX_BYTES:
                        entry["status"] = "capped"
                        entry.setdefault("notes", []).append(
                            "snapshot_cap_hit")
                        return
                    if len(vas) >= max_results:
                        break
                off += align
            progress["hits_so_far"] = len(vas)
            got = data_len
            if cursor + got >= end:
                break
            cursor = (cursor + got - overlap) if got > overlap else (cursor + got)
            # Re-align after overlap.
            rel = (cursor - span_start) % align
            if rel:
                cursor += (align - rel)
        completed += span_size


# ======================================================================
# v15 fallback: next_scan refine loop
# ======================================================================


async def _run_refine_v15(entry: dict[str, Any], c, *,
                           op: str, value: Any, value_hi: Any,
                           delta: Any, tolerance: float) -> dict[str, Any]:
    """Re-read every stored VA, apply ``op`` against prev + curr,
    rewrite snapshot. Mutates entry; returns per-call notes."""
    width = entry["width"]
    value_type = entry["value_type"]
    endian = entry["endian"]
    encoding = entry.get("encoding", "")
    pid = entry["args"]["pid"]
    space_r = entry["args"]["space"]
    vas_old: array.array = entry["snapshot_vas"]
    raw_old: bytearray = entry["snapshot_raw"]

    if op not in _VALID_NEXT_OPS:
        return {"err": {"ok": False, "kind": "bad_arg",
                        "error": f"next_scan: unknown op={op!r}",
                        "hint": " | ".join(sorted(_VALID_NEXT_OPS))}}

    # Delta / value coercion
    want_value = False
    want_hi = False
    want_delta = False
    if op in ("eq", "lt", "gt", "between"):
        want_value = True
    if op == "between":
        want_hi = True
    if op in ("increased_by", "decreased_by"):
        want_delta = True

    if _is_string_type(value_type) and op not in ("eq", "changed", "unchanged"):
        return {"err": {"ok": False, "kind": "bad_arg",
                        "error": "next_scan on string type only supports "
                                 "op='eq' or op='changed'/'unchanged' "
                                 "(byte-compare)"}}
    v_num: int | float | None = None
    if want_value and not _is_string_type(value_type):
        try:
            v_num = _coerce_number(value, value_type)
        except Exception as exc:  # noqa: BLE001
            return {"err": {"ok": False, "kind": "bad_arg",
                            "error": f"next_scan: bad value: {exc}"}}
    v_hi_num: int | float | None = None
    if want_hi and not _is_string_type(value_type):
        if value_hi is None or value_hi == "":
            return {"err": {"ok": False, "kind": "bad_arg",
                            "error": "next_scan: op='between' requires value_hi"}}
        v_hi_num = _coerce_number(value_hi, value_type)
    v_delta_num: int | float | None = None
    if want_delta:
        if delta is None or delta == "":
            return {"err": {"ok": False, "kind": "bad_arg",
                            "error": f"next_scan: op={op!r} requires delta"}}
        v_delta_num = _coerce_number(delta, value_type)

    is_float = value_type in ("float", "double")
    tol = float(tolerance) if tolerance else _default_tolerance(value_type)

    # Batch VAs into coalesced read windows (§2.15).
    hits: list[tuple[int, bytes, int]] = []  # (va, prev_raw, idx_in_old)
    order = sorted(range(len(vas_old)), key=lambda i: vas_old[i])

    # Plan window reads
    read_windows: list[tuple[int, int, list[int]]] = []  # (start, size, indices)
    for i in order:
        va = int(vas_old[i])
        if (read_windows and
                va - read_windows[-1][0] < BATCH_READ_BYTES - width):
            s, sz, ind = read_windows[-1]
            new_end = max(s + sz, va + width)
            read_windows[-1] = (s, new_end - s, ind + [i])
        else:
            read_windows.append((va, width, [i]))

    reads_failed = 0
    unpack = (None if _is_string_type(value_type)
              else struct.Struct(_struct_fmt(value_type, endian)).unpack_from)

    def keep(prev_raw: bytes, curr_raw: bytes) -> bool:
        if _is_string_type(value_type):
            if op == "eq":
                needle = _encode_string(str(value), value_type, encoding)
                return curr_raw[:len(needle)] == needle
            if op == "changed":
                return curr_raw != prev_raw
            if op == "unchanged":
                return curr_raw == prev_raw
            return False
        # numeric
        (prev_v,) = unpack(prev_raw, 0)
        if len(curr_raw) < width:
            return False
        (curr_v,) = unpack(curr_raw, 0)
        if op == "eq":
            return (abs(curr_v - v_num) <= tol) if is_float else (curr_v == v_num)
        if op == "lt":
            return curr_v < v_num
        if op == "gt":
            return curr_v > v_num
        if op == "between":
            lo, hi = sorted([v_num, v_hi_num])
            return lo <= curr_v <= hi
        if op == "changed":
            return ((abs(curr_v - prev_v) > tol) if is_float
                    else (curr_v != prev_v))
        if op == "unchanged":
            return ((abs(curr_v - prev_v) <= tol) if is_float
                    else (curr_v == prev_v))
        if op == "increased":
            return curr_v > prev_v
        if op == "decreased":
            return curr_v < prev_v
        if op == "increased_by":
            diff = curr_v - prev_v
            return (abs(diff - v_delta_num) <= tol) if is_float else (diff == v_delta_num)
        if op == "decreased_by":
            diff = prev_v - curr_v
            return (abs(diff - v_delta_num) <= tol) if is_float else (diff == v_delta_num)
        return False

    survivors_vas: list[int] = []
    survivors_raw = bytearray()
    rows_preview: list[dict[str, Any]] = []

    for (win_start, win_size, idxs) in read_windows:
        if entry["cancel"].is_set():
            return {"err": {"ok": False, "kind": "cancelled",
                            "error": "next_scan: cancelled"}}
        try:
            data = await c.mem_read(pid, win_start, win_size, space_r,
                                    partial=True)
            if isinstance(data, tuple):
                data = data[0]
        except Exception:  # noqa: BLE001
            reads_failed += len(idxs)
            continue
        if not data:
            reads_failed += len(idxs)
            continue
        for idx in idxs:
            va = int(vas_old[idx])
            prev_raw = bytes(raw_old[idx * width:(idx + 1) * width])
            inner = va - win_start
            curr_raw = bytes(data[inner:inner + width])
            if len(curr_raw) < width:
                reads_failed += 1
                continue
            if keep(prev_raw, curr_raw):
                survivors_vas.append(va)
                survivors_raw += curr_raw
                if len(rows_preview) < 32:
                    rows_preview.append({
                        "va": hex(va),
                        "prev_value": _decode_from_raw(
                            prev_raw, 0, width, value_type, endian, encoding),
                        "curr_value": _decode_from_raw(
                            curr_raw, 0, width, value_type, endian, encoding),
                    })

    # Commit new snapshot
    new_vas = array.array("Q", survivors_vas)
    entry["snapshot_vas"] = new_vas
    entry["snapshot_raw"] = survivors_raw
    entry["generation"] = int(entry.get("generation", 0)) + 1
    return {"reads_failed": reads_failed,
            "dropped": len(vas_old) - len(new_vas),
            "rows_preview": rows_preview,
            "kept": len(new_vas)}


# ======================================================================
# Public verb handlers
# ======================================================================


import os as _os
import time as _time

# Session-unique scan id prefix. The agent-side ``ScanRegistry`` keyes by
# the exact scan_id string; a bare ``v0001`` collides with any orphan
# scan the agent still holds from a previous orchestrator run, forcing
# the v15 fallback path. Include the orchestrator's pid + boot time so
# every restart hands out a fresh namespace.
_SCAN_NONCE = f"{_os.getpid():x}{int(_time.time()) & 0xFFFF:04x}"


def _new_scan_id() -> str:
    _mem_scan._SCAN_SEQ[0] += 1
    return f"v{_SCAN_NONCE}_{_mem_scan._SCAN_SEQ[0]:04d}"


def _value_scan_response(entry: dict[str, Any], *,
                          limit: int, offset: int,
                          global_cap: int) -> str:
    """Serialise a done/running value scan into the standard envelope."""
    vas: array.array = entry["snapshot_vas"]
    raw: bytearray = entry["snapshot_raw"]
    width = entry["width"]
    value_type = entry["value_type"]
    endian = entry["endian"]
    encoding = entry.get("encoding", "")

    # Hand the FULL hit set to _list_envelope and let it apply
    # limit/offset once. Slicing here first and then passing the same
    # offset through would double-paginate (review: scan_result offset
    # past the pre-slice returned empty items).
    n = len(vas)
    rows: list[dict[str, Any]] = []
    for i in range(n):
        va = int(vas[i])
        val = _decode_from_raw(bytes(raw[i * width:(i + 1) * width]),
                               0, width, value_type, endian, encoding)
        rows.append({"va": hex(va), "value": val})
    env = _list_envelope(
        rows, tool="memory_manage", action="value_scan",
        limit=int(limit or 0), offset=int(offset or 0),
        fields=(),
        filter="",
        summary=False,
        global_cap=global_cap,
        extras={
            "scan_id": entry["scan_id"],
            "scan_kind": "value",
            "value_type": value_type,
            "endian": endian,
            "align": entry["align"],
            "width": width,
            "op": entry["op"],
            "value": entry["args"].get("value"),
            "hit_count": n,
            "generation": int(entry.get("generation", 0)),
            "coverage": {"status": entry.get("coverage_status", "complete"),
                         "reasons": list(entry.get("notes", []))},
            "space": entry["args"]["space"],
            "pid": entry["args"]["pid"],
            "status": entry.get("status", "done"),
            "owner": entry["owner"],
            "agent_abi": entry.get("agent_abi", "v15"),
            "fallback": entry.get("agent_abi", "v15") == "v15",
        },
    )
    return _j(_hexify_dict(env, add_int_mirror=True))


def _agent_abi_from_session(ctx, name: str) -> str:
    """Decide v16 vs v15 routing from the session's cached machine_info.

    Looks up the exact view key first; if ``name`` is a bare machine
    label (``"lab2"`` rather than ``"lab2.kernel"``), probes every
    view on that machine for ``scan_service_version`` and returns
    v16 when any one advertises it. Falls back to v15 on any lookup
    failure.
    """
    try:
        sess = ctx.session
        info_map = (sess._machine_info or {})
        view = name or ""
        if not view:
            view = sess.focus_view() if hasattr(sess, "focus_view") else ""
        # Exact-view path.
        info = info_map.get(view)
        if info:
            svv = int(info.get("scan_service_version") or 0)
            return "v16" if svv >= 1 else "v15"
        # Bare-machine-name path — scan every view on that machine.
        machine = name
        if hasattr(sess, "machine_of") and machine:
            machine = sess.machine_of(name)
        if machine:
            for key, v in info_map.items():
                key_machine = (sess.machine_of(key)
                               if hasattr(sess, "machine_of") else key)
                if key_machine == machine:
                    svv = int((v or {}).get("scan_service_version") or 0)
                    if svv >= 1:
                        return "v16"
        return "v15"
    except Exception:  # noqa: BLE001 — be forgiving
        return "v15"


async def handle_value_scan(ctx, c, *, pid: int, address: int,
                            size: int, space: str, kernel_lookup: bool,
                            value_type: str, op: str,
                            value: Any, value_hi: Any,
                            tolerance: float, endian: str,
                            encoding: str, align: int | str,
                            sections: str, module: str,
                            writable: bool, executable: bool,
                            cow: bool, include_guarded: bool,
                            mem_types: list[str] | None,
                            scope: str,
                            max_results: int,
                            confirm_full_space: bool,
                            name: str,
                            limit: int, offset: int,
                            ) -> str:
    # 1) Normalise + validate
    value_type = str(value_type or "").strip().lower()
    op = str(op or "").strip().lower()
    endian = str(endian or "le").strip().lower()
    encoding = str(encoding or "").strip().lower()
    if align in ("auto", "", 0, None):
        align = (_INT_TYPES.get(value_type, ("", 1, False, False))[1]
                 if not _is_string_type(value_type) else 1)
    try:
        align = int(align)
    except Exception:  # noqa: BLE001
        align = 1

    err = _validate_create_args(
        value_type=value_type, op=op, endian=endian, encoding=encoding,
        tolerance=tolerance, value=value, value_hi=value_hi, align=align)
    if err:
        return _j(err)

    # 2) Resolve spans (sections + region filter). value_scan defaults
    # writable=True per plan §2.13, but only when NO explicit base
    # range was given — otherwise respect the caller's window.
    eff_writable = writable
    if (not sections and not size and not _any_region_flag_set(
            writable=writable, executable=executable, cow=cow,
            include_guarded=include_guarded, mem_types=mem_types,
            scope=scope)):
        if not confirm_full_space:
            return _j({"ok": False, "kind": "would_exceed",
                       "error": "value_scan: whole-space sweep refused — "
                                "pass confirm_full_space=True or narrow "
                                "with address+size / sections / scope / "
                                "writable=True",
                       "hint": "typical: scope='heap', writable=True"})
        eff_writable = True  # at least narrow to writable VADs

    spans: list[tuple[int, int]]
    sinfo: dict[str, Any]
    needs_region = (sections or _any_region_flag_set(
        writable=eff_writable, executable=executable, cow=cow,
        include_guarded=include_guarded, mem_types=mem_types, scope=scope))
    if needs_region:
        spans, sinfo, serr = await _resolve_spans(
            c, pid=pid, space=space, kernel_lookup=kernel_lookup,
            address=int(address or 0), size=int(size or 0),
            sections=sections, module=module,
            writable=eff_writable, executable=executable, cow=cow,
            include_guarded=include_guarded, mem_types=mem_types,
            scope=scope)
        if serr:
            return _j(serr)
    else:
        spans = [(int(address or 0), int(size or 0))]
        sinfo = {}
    if not spans:
        return _j({"ok": False, "kind": "no_match",
                   "error": "value_scan: no spans to scan after filter",
                   "hint": "widen the filter"})

    total_bytes = sum(sz for _, sz in spans)
    if total_bytes > SYNC_SPAN_MAX_BYTES:
        return _j({"ok": False, "kind": "too_wide",
                   "error": (f"value_scan: span total {total_bytes} B "
                             f"exceeds sync cap {SYNC_SPAN_MAX_BYTES} B"),
                   "hint": "narrow with sections=/scope=, or use "
                           "memory_manage(action='scan_start', "
                           f"value_type={value_type!r}, ...) for the "
                           "async path"})

    # 3) Pre-flight snapshot cap
    width = _width_of(value_type, encoding, value if op != "unknown" else "x" * 1)
    est_hits = min(int(max_results or 4096), total_bytes // max(1, align))
    est_bytes = est_hits * (8 + width)
    if est_bytes > SCAN_SNAPSHOT_MAX_BYTES:
        return _j({"ok": False, "kind": "would_exceed",
                   "error": (f"value_scan: pre-flight snapshot "
                             f"{est_bytes} B exceeds {SCAN_SNAPSHOT_MAX_BYTES} B "
                             f"cap (orchestrator-RAM path)"),
                   "hint": "narrow max_results= or the span range"})

    # 4) Build probe
    try:
        probe = pack_probe(
            value_type=value_type, op=op, value=value,
            value_hi=value_hi, endian=endian,
            encoding=encoding, tolerance=tolerance)
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"value_scan: probe build failed: {exc}"})

    # 5) Routing decision: v16 agent if available, else v15 RAM path
    agent_abi = _agent_abi_from_session(ctx, name)
    scan_id = _new_scan_id()
    owner = _owner_bucket(current_client_id())

    # Allocate entry in shared _SCANS registry
    entry: dict[str, Any] = {
        "scan_id": scan_id, "scan_kind": "value",
        "owner": owner, "machine": name or "",
        "agent_abi": agent_abi,
        "value_type": value_type, "endian": endian,
        "encoding": encoding, "align": align, "width": width,
        "op": op,
        "snapshot_vas": array.array("Q"),
        "snapshot_raw": bytearray(),
        "undo_stack": [],
        "generation": 0,
        "hits": [],  # legacy field for pattern_scan paths
        "status": "running",
        "progress": {
            "bytes_scanned": 0, "bytes_total": int(total_bytes),
            "chunks_read": 0, "chunks_skipped": 0,
            "hits_so_far": 0,
        },
        "args": {"pid": int(pid), "start": hex(spans[0][0]),
                 "size": int(total_bytes), "space": space,
                 "value": value, "value_hi": value_hi,
                 "tolerance": tolerance,
                 "spans": [{"va": s0, "size": sz} for s0, sz in spans],
                 "sinfo": sinfo,
                 "max_results": int(max_results or 4096)},
        "started_ts": time.time(), "finished_ts": None,
        "cancel": asyncio.Event(),
        "notes": [],
    }
    _mem_scan._SCANS[scan_id] = entry

    # 5a) v16 path — delegate to agent (dormant until agent rebuild)
    if agent_abi == "v16":
        agent_resp: dict[str, Any]
        try:
            agent_resp = await c.scan_create(
                scan_id=scan_id, pid=pid, space=space,
                value_type=value_type, endian=endian, encoding=encoding,
                align=align, op=op,
                value_le=_le_bytes(value, value_type, endian, encoding, width),
                value_hi_le=_le_bytes(value_hi, value_type, endian,
                                      encoding, width) if value_hi not in (None, "") else b"",
                tolerance_bits=_float_tol_bits(tolerance, value_type),
                spans=spans, max_results=int(max_results or 4096),
                owner_client_id=owner, disk_spill_mode="auto")
        except Exception as exc:  # noqa: BLE001
            entry["status"] = "error"
            entry["notes"].append(f"agent_create_failed:{type(exc).__name__}")
            agent_resp = {"ok": False}
        if agent_resp.get("ok"):
            entry["status"] = agent_resp.get("status") or "running"
            return _j({
                "ok": True, "tool": "memory_manage", "action": "value_scan",
                "scan_id": scan_id, "scan_kind": "value",
                "agent_abi": "v16", "fallback": False,
                "status": entry["status"],
                "hint": "poll memory_manage(action='scan_status', "
                        f"scan_id={scan_id!r})",
            })
        # v16 call failed or returned not-ok — fall through to the v15
        # inline path. Reset the entry's agent_abi so follow-up
        # next_scan / scan_undo / scan_destroy stay orchestrator-side
        # and don't blindly RPC an agent that has no record of the
        # scan (review C3).
        entry["agent_abi"] = "v15"
        entry.setdefault("notes", []).append(
            "v16_create_declined_falling_back_to_v15")

    # 5b) v15 path — run orchestrator-RAM match loop inline
    try:
        await _run_first_scan_v15(
            entry, c, pid=int(pid), space_r=space,
            spans=spans, probe=probe, align=align, width=width,
            max_results=int(max_results or 4096))
    except Exception as exc:  # noqa: BLE001
        entry["status"] = "error"
        entry["notes"].append(f"scan_failed:{type(exc).__name__}")
    else:
        if entry.get("status") not in ("cancelled", "capped"):
            entry["status"] = "done"
    entry["finished_ts"] = time.time()

    try:
        _pattern_scan_breadcrumb(
            ctx, pattern=f"value_scan[{value_type}][{op}]",
            space=space, address=spans[0][0], size=int(total_bytes),
            module=module)
    except Exception:  # noqa: BLE001  pragma: no cover
        pass

    return _value_scan_response(
        entry, limit=limit, offset=offset,
        global_cap=ctx.cfg.mcp_max_items())


def _le_bytes(value: Any, value_type: str, endian: str,
              encoding: str, width: int) -> bytes:
    """Build the proto value_le bytes for agent delegation."""
    if value in (None, ""):
        return b""
    if _is_string_type(value_type):
        return _encode_string(str(value), value_type, encoding)[:32]
    try:
        v = _coerce_number(value, value_type)
        return struct.pack(_struct_fmt(value_type, "le"), v)[:32]
    except Exception:  # noqa: BLE001
        return b""


def _float_tol_bits(tolerance: float, value_type: str) -> int:
    if not tolerance or value_type not in ("float", "double"):
        return 0
    if value_type == "float":
        return int.from_bytes(struct.pack("<f", float(tolerance)), "little")
    return int.from_bytes(struct.pack("<d", float(tolerance)), "little")


async def handle_next_scan(ctx, c, *, scan_id: str, op: str,
                            value: Any, value_hi: Any, delta: Any,
                            tolerance: float,
                            limit: int, offset: int) -> str:
    entry = _mem_scan._SCANS.get(scan_id)
    if entry is None:
        return _j({"ok": False, "kind": "unknown_scan",
                   "error": f"next_scan: scan_id {scan_id!r} not found",
                   "hint": "memory_manage(action='scan_list')"})
    if entry.get("scan_kind") != "value":
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "next_scan: scan_id is a pattern scan; "
                            "pattern scans have no snapshot to refine"})
    current = _owner_bucket(current_client_id())
    if entry["owner"] != current:
        return _j({"ok": False, "kind": "foreign_owned",
                   "error": f"next_scan: scan {scan_id!r} owned by "
                            f"{entry['owner']!r}"})
    if entry.get("status") == "running":
        return _j({"ok": False, "kind": "not_ready",
                   "error": f"next_scan: scan {scan_id!r} still running",
                   "hint": "poll scan_status"})

    op = str(op or "").strip().lower()

    # Pre-validate op + required args before pushing anything onto the
    # undo stack. A bad-arg refine on a 128 MiB snapshot would
    # otherwise copy ~256 MiB of transient state just to roll it back
    # one line later (review M7).
    if op not in _VALID_NEXT_OPS:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"next_scan: unknown op={op!r}",
                   "hint": " | ".join(sorted(_VALID_NEXT_OPS))})
    if op in ("eq", "lt", "gt") and value in (None, ""):
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"next_scan: op={op!r} requires value"})
    if op == "between" and (value in (None, "") or value_hi in (None, "")):
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "next_scan: op='between' requires value + value_hi"})
    if op in ("increased_by", "decreased_by") and delta in (None, ""):
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"next_scan: op={op!r} requires delta"})
    if tolerance and entry.get("value_type") not in ("float", "double"):
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "next_scan: tolerance= is only valid for "
                            "float / double"})
    if _is_string_type(entry.get("value_type", "")) and op not in (
            "eq", "changed", "unchanged"):
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "next_scan on string type only supports "
                            "op='eq' or op='changed'/'unchanged'"})

    if entry.get("agent_abi") == "v16":
        try:
            r = await c.scan_refine(
                scan_id=scan_id, op=op,
                value_le=_le_bytes(value, entry["value_type"],
                                   entry["endian"], entry["encoding"],
                                   entry["width"]),
                value_hi_le=_le_bytes(value_hi, entry["value_type"],
                                      entry["endian"], entry["encoding"],
                                      entry["width"]) if value_hi not in (None, "") else b"",
                delta_le=_le_bytes(delta, entry["value_type"],
                                   entry["endian"], entry["encoding"],
                                   entry["width"]) if delta not in (None, "") else b"",
                tolerance_bits=_float_tol_bits(tolerance, entry["value_type"]),
            )
        except Exception as exc:  # noqa: BLE001
            return _j({"ok": False, "kind": "agent_rpc_failed",
                       "error": f"next_scan: {exc}"})
        # Mirror agent-side generation + op into the local entry so the
        # next scan_result re-fetches from the agent instead of serving
        # a stale cache.
        if r.get("generation") is not None:
            entry["generation"] = int(r["generation"])
        entry["op"] = op
        entry["args"]["value"] = value
        entry["args"]["value_hi"] = value_hi
        entry["_fetch_cached_generation"] = -1
        return _j({**r, "action": "next_scan"})

    # v15 RAM path: push undo, run refine, write back
    _push_undo(entry)
    out = await _run_refine_v15(
        entry, c, op=op, value=value, value_hi=value_hi,
        delta=delta, tolerance=tolerance)
    if "err" in out:
        # roll back the undo push
        if entry["undo_stack"]:
            vas_b, raw_b = entry["undo_stack"].pop()
            entry["snapshot_vas"] = array.array("Q")
            entry["snapshot_vas"].frombytes(vas_b)
            entry["snapshot_raw"] = bytearray(raw_b)
        return _j(out["err"])
    cov_status = "complete" if not out["reads_failed"] else "partial"
    cov_reasons: list[str] = (
        [f"reads_failed:{out['reads_failed']}"] if out["reads_failed"] else [])
    return _j({
        "ok": True, "tool": "memory_manage", "action": "next_scan",
        "scan_id": scan_id, "generation": int(entry["generation"]),
        "op": op,
        "hit_count": out["kept"],
        "dropped": out["dropped"],
        "hits": out["rows_preview"],
        "coverage": {"status": cov_status, "reasons": cov_reasons},
        "owner": entry["owner"],
        "agent_abi": "v15", "fallback": True,
    })


async def handle_scan_undo(ctx, c, *, scan_id: str) -> str:
    entry = _mem_scan._SCANS.get(scan_id)
    if entry is None:
        return _j({"ok": False, "kind": "unknown_scan",
                   "error": f"scan_undo: scan_id {scan_id!r} not found"})
    if entry.get("scan_kind") != "value":
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "scan_undo: pattern scans have no undo stack"})
    current = _owner_bucket(current_client_id())
    if entry["owner"] != current:
        return _j({"ok": False, "kind": "foreign_owned",
                   "error": f"scan_undo: scan {scan_id!r} owned by "
                            f"{entry['owner']!r}"})

    if entry.get("agent_abi") == "v16":
        try:
            r = await c.scan_undo(scan_id)
        except Exception as exc:  # noqa: BLE001
            return _j({"ok": False, "kind": "agent_rpc_failed",
                       "error": f"scan_undo: {exc}"})
        return _j({**r, "action": "scan_undo"})

    frame = _pop_undo(entry)
    if frame is None:
        return _j({"ok": False, "kind": "no_undo",
                   "error": f"scan_undo: undo stack empty for "
                            f"{scan_id!r}"})
    vas_b, raw_b = frame
    entry["snapshot_vas"] = array.array("Q")
    entry["snapshot_vas"].frombytes(vas_b)
    entry["snapshot_raw"] = bytearray(raw_b)
    entry["generation"] = max(0, int(entry.get("generation", 0)) - 1)
    return _j({
        "ok": True, "tool": "memory_manage", "action": "scan_undo",
        "scan_id": scan_id, "generation": entry["generation"],
        "hit_count": len(entry["snapshot_vas"]),
        "coverage": {"status": "complete"},
        "agent_abi": "v15", "fallback": True,
    })


async def handle_scan_destroy(ctx, c, *, scan_id: str) -> str:
    entry = _mem_scan._SCANS.get(scan_id)
    if entry is None:
        return _j({"ok": False, "kind": "unknown_scan",
                   "error": f"scan_destroy: scan_id {scan_id!r} not found"})
    current = _owner_bucket(current_client_id())
    if entry["owner"] != current:
        return _j({"ok": False, "kind": "foreign_owned",
                   "error": f"scan_destroy: scan {scan_id!r} owned by "
                            f"{entry['owner']!r}"})
    if entry.get("status") == "running":
        return _j({"ok": False, "kind": "busy",
                   "error": "scan_destroy: scan is still running; "
                            "scan_cancel first"})

    ram_bytes = _snapshot_bytes_total(entry) + _undo_bytes_total(entry)
    disk_bytes = 0
    if entry.get("agent_abi") == "v16":
        try:
            r = await c.scan_destroy(scan_id)
        except Exception as exc:  # noqa: BLE001
            # Transport error — keep the local entry so a retry can
            # still see it; surface the failure.
            entry.setdefault("notes", []).append(
                f"agent_destroy_failed:{type(exc).__name__}")
            return _j({"ok": False, "kind": "agent_rpc_failed",
                       "error": f"scan_destroy: {exc}",
                       "scan_id": scan_id,
                       "hint": "local entry kept; retry scan_destroy"})
        # Review M4: if the agent refuses (busy, or unknown-on-its-end
        # for a rehomed scan), do NOT drop the local entry — otherwise
        # the on-target scan orphans with no way to reach it.
        if not r.get("ok"):
            return _j({"ok": False, "kind": r.get("kind") or "busy",
                       "error": (r.get("error")
                                 or f"scan_destroy: agent refused {scan_id!r}"),
                       "scan_id": scan_id,
                       "hint": "call scan_cancel first, then retry "
                               "scan_destroy"})
        disk_bytes = int(r.get("disk_bytes_freed") or 0)
        ram_bytes = int(r.get("ram_bytes_freed") or ram_bytes)

    _mem_scan._SCANS.pop(scan_id, None)
    return _j({
        "ok": True, "tool": "memory_manage", "action": "scan_destroy",
        "scan_id": scan_id,
        "disk_bytes_freed": disk_bytes,
        "ram_bytes_freed": ram_bytes,
    })
