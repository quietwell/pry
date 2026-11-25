"""Triage stack + driver-list extraction (``dump_manage action='stack'``).

One call answers "what's on the stack and which module owns each
return address" for a triage minidump — including stale-boot dumps
where the live module map is useless. Everything comes from the dump
file itself: the embedded callstack bytes, KernBase out of the
debugger-data block, and the triage driver list (name/base/size).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .bugcheck import dump_type_name
from .context import _decode_context64
from .header import _u32, _u64
from .offsets import (
    HEADER_SIZE_64,
    PAGE_SIG,
    VALID_64,
    _KD_DEBUGGER_KERNBASE,
    _MAX_DRV_NAME_CHARS,
    _OFF_CONTEXT,
    _OFF_DTB,
    _OFF_DUMP_TYPE,
    _OFF_SYSTEM_TIME,
    _TRI_CALLSTACK_OFFSET,
    _TRI_CALLSTACK_SIZE,
    _TRI_DEBUGGER_DATA_OFFSET,
    _TRI_DEBUGGER_DATA_SIZE,
    _TRI_DRIVER_COUNT,
    _TRI_DRIVER_ENTRY_SIZE,
    _TRI_DRIVER_LIST_OFFSET,
    _TRI_DRV_BASE,
    _TRI_DRV_CHECKSUM,
    _TRI_DRV_NAME_OFFSET,
    _TRI_DRV_SIZE,
    _TRI_DRV_TIMESTAMP,
    _TRI_TOP_OF_STACK,
)
from .phys import _phys_reader_from_header, _vtop


def _read_pool_string(fh, file_offset: int, file_size: int) -> str:
    """Decode a u32-length-prefixed UTF-16 pool string at an absolute
    dump file offset (u32 char count, then count UTF-16-LE chars — a
    NUL terminator follows but is not counted). Empty string on any
    malformed input."""
    if not (0 <= file_offset < file_size - 4):
        return ""
    fh.seek(file_offset)
    raw = fh.read(4)
    if len(raw) < 4:
        return ""
    n = _u32(raw, 0)
    if n <= 0 or n > _MAX_DRV_NAME_CHARS:
        return ""
    if file_offset + 4 + n * 2 > file_size:
        return ""
    return fh.read(n * 2).decode("utf-16-le", "replace")


def _triage_driver_list(fh, size: int, dl_off: int, driver_count: int
                        ) -> tuple[list[dict[str, Any]], list[str]]:
    """Walk the embedded DUMP_DRIVER_ENTRY records. Returns
    ``(drivers, notes)`` — drivers carry name/base/size/timestamp/
    checksum; notes carry honest truncation reasons. Stops at the first
    entry whose base is not a kernel VA (stride drift guard)."""
    drivers: list[dict[str, Any]] = []
    notes: list[str] = []
    want = driver_count * _TRI_DRIVER_ENTRY_SIZE
    if dl_off <= 0 or dl_off + _TRI_DRIVER_ENTRY_SIZE > size:
        notes.append(f"driver list offset 0x{dl_off:x} outside file")
        return drivers, notes
    fh.seek(dl_off)
    blob = fh.read(min(want, size - dl_off))
    n_entries = len(blob) // _TRI_DRIVER_ENTRY_SIZE
    if n_entries < driver_count:
        notes.append(
            f"driver list truncated: {n_entries} of {driver_count} "
            "entries inside file")
    for i in range(min(driver_count, n_entries)):
        e = blob[i * _TRI_DRIVER_ENTRY_SIZE:(i + 1) * _TRI_DRIVER_ENTRY_SIZE]
        name_off = _u64(e, _TRI_DRV_NAME_OFFSET)
        base = _u64(e, _TRI_DRV_BASE)
        drv_size = _u64(e, _TRI_DRV_SIZE)
        if not base or base < 0xFFFF800000000000:
            notes.append(
                f"driver entry {i}: base 0x{base:x} is not a kernel VA "
                "— list walk stopped (format drift?)")
            break
        row: dict[str, Any] = {
            "name": _read_pool_string(fh, name_off, size),
            "base": base,
            "size": drv_size,
        }
        if i == 0 and not row["name"]:
            notes.append("driver entry 0 name undecodable — string pool "
                         "layout may have drifted")
        ts = e[_TRI_DRV_TIMESTAMP:_TRI_DRV_TIMESTAMP + 4]
        cs = e[_TRI_DRV_CHECKSUM:_TRI_DRV_CHECKSUM + 4]
        if len(ts) == 4 and len(cs) == 4:
            row["timestamp"] = _u32(ts, 0)
            row["checksum"] = _u32(cs, 0)
        drivers.append(row)
    return drivers, notes


def read_triage_stack(path: str | Path, max_frames: int = 256
                      ) -> dict[str, Any]:
    """Walk a kernel dump's saved stack and attribute every qword.

    Triage dumps (the ``C:\\Windows\\Minidump`` shape): walks the
    embedded callstack bytes end to end, pulls KernBase from the
    debugger-data block, parses the embedded driver list, and
    attributes each frame to its module — all offline, so stale-boot
    dumps still resolve. Full/bitmap dumps: walks up to ``max_frames``
    qwords from Rsp via the page tables stored in the dump; no driver
    list exists in those bodies (the live map or ``memory_manage modules``
    is the attribution path there).

    Never raises; ``{ok: False, kind: ...}`` on bad input.
    """
    p = Path(path)
    try:
        fsize = p.stat().st_size
    except OSError as exc:
        return {"ok": False, "kind": "not_found",
                "error": f"{path}: {exc}", "path": str(p)}
    try:
        fh = open(p, "rb")
    except OSError as exc:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: {exc}", "path": str(p)}
    with fh:
        fh.seek(0)
        magic = fh.read(8)
        if magic[:4] != PAGE_SIG:
            return {"ok": False, "kind": "bad_dump",
                    "error": f"{path}: not a kernel crash dump",
                    "path": str(p)}
        is_triage = magic[4:8] == VALID_64  # refined below via DumpType
        fh.seek(0)
        hdr = fh.read(HEADER_SIZE_64)
        if len(hdr) < HEADER_SIZE_64:
            return {"ok": False, "kind": "bad_dump",
                    "error": f"{path}: truncated DUMP_HEADER64",
                    "path": str(p)}
        dump_type = _u32(hdr, _OFF_DUMP_TYPE)
        is_triage = dump_type == 4
        context = _decode_context64(hdr[_OFF_CONTEXT:_OFF_CONTEXT + 3000])
        rsp = (context or {}).get("rsp") or 0
        dtb = _u64(hdr, _OFF_DTB)

        out: dict[str, Any] = {
            "ok": True,
            "path": str(p),
            "dump_type": {"code": dump_type,
                          "name": dump_type_name(dump_type)},
            "rsp": rsp,
            "system_time_filetime": _u64(hdr, _OFF_SYSTEM_TIME),
            "notes": [],
        }
        frames: list[dict[str, Any]] = []
        drivers: list[dict[str, Any]] = []
        kernbase = None

        if is_triage:
            if fsize < HEADER_SIZE_64 + 0x80:
                out["notes"].append("file too small for a triage body")
            else:
                fh.seek(HEADER_SIZE_64)
                tri = fh.read(0x80)
                cs_off = _u32(tri, _TRI_CALLSTACK_OFFSET)
                cs_size = _u32(tri, _TRI_CALLSTACK_SIZE)
                top = _u64(tri, _TRI_TOP_OF_STACK)
                out["top_of_stack"] = top
                out["callstack"] = {"file_offset": cs_off, "size": cs_size}
                dd_off = _u32(tri, _TRI_DEBUGGER_DATA_OFFSET)
                dd_size = _u32(tri, _TRI_DEBUGGER_DATA_SIZE)
                if (dd_off and dd_size > _KD_DEBUGGER_KERNBASE + 8
                        and dd_off + dd_size <= fsize):
                    fh.seek(dd_off)
                    dd = fh.read(_KD_DEBUGGER_KERNBASE + 8)
                    if len(dd) == _KD_DEBUGGER_KERNBASE + 8:
                        kb = _u64(dd, _KD_DEBUGGER_KERNBASE)
                        if kb >= 0xFFFF800000000000:
                            kernbase = kb
                            out["kernbase_source"] = "debugger_data+0x18"
                drivers, dnotes = _triage_driver_list(
                    fh, fsize, _u32(tri, _TRI_DRIVER_LIST_OFFSET),
                    _u32(tri, _TRI_DRIVER_COUNT))
                out["notes"].extend(dnotes)
                if not cs_size:
                    out["notes"].append("no callstack bytes saved")
                elif not (0 < cs_off and cs_off + cs_size <= fsize):
                    out["notes"].append(
                        f"callstack region 0x{cs_off:x}+0x{cs_size:x} "
                        "outside file")
                else:
                    fh.seek(cs_off)
                    blob = fh.read(cs_size)
                    va = top
                    for off in range(0, len(blob) - 7, 8):
                        frames.append({"va": va, "value": _u64(blob, off)})
                        va += 8
        else:
            phys = _phys_reader_from_header(fh, hdr, dump_type)
            if phys is None:
                out["notes"].append(
                    "dump body has no page data this parser can read")
            elif not rsp:
                out["notes"].append("context has no Rsp")
            else:
                def read_va(v: int, n: int) -> bytes | None:
                    pa = _vtop(phys, dtb, v)
                    return phys.read(pa, n) if pa is not None else None
                va = rsp
                for _ in range(max(0, max_frames)):
                    data = read_va(va, 8)
                    if data is None:
                        break
                    frames.append({"va": va, "value": _u64(data, 0)})
                    va += 8

        # Offline attribution against the embedded driver list first —
        # this is what makes stale-boot triage dumps usable.
        for q in frames:
            val = q["value"]
            if not (0xFFFF800000000000 <= val < 0xFFFFF90000000000):
                q["text"] = f"0x{val:016x}"
                q["attribution"] = "data"
                continue
            hit = None
            for d in drivers:
                b = int(d.get("base") or 0)
                s = int(d.get("size") or 0)
                if b and s and b <= val < b + s:
                    hit = (d, b, s)
                    break
            if kernbase and hit is None and kernbase <= val < kernbase + 0x10000000:
                q["module"] = "nt"
                q["offset"] = val - kernbase
                q["text"] = f"nt+0x{val - kernbase:x}"
                q["attribution"] = "kernbase_range"
                continue
            if hit is not None:
                d, b, _s = hit
                name = str(d.get("name") or "?")
                name = name.replace("/", "\\").split("\\")[-1]
                q["module"] = name
                q["offset"] = val - b
                q["text"] = f"{name}+0x{val - b:x}"
                q["attribution"] = "driver_list"
            else:
                q["text"] = f"0x{val:016x}"
                q["attribution"] = "unresolved"

        out["kernbase"] = kernbase
        out["frames_total"] = len(frames)
        out["frames"] = frames[:max(0, max_frames)]
        out["drivers"] = drivers
        out["driver_count"] = len(drivers)
        return out
