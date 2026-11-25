"""MDMP (usermode minidump) parser — minimal: header + ExceptionStream +
the memory-list streams for stack reads.
"""

from __future__ import annotations

import struct
from typing import Any

from .bugcheck import NTSTATUS_NAMES
from .context import _decode_context64, _mdmp_exception
from .header import _u32, _u64
from .phys import _stack_qwords

_MDMP_EXCEPTION_STREAM = 6
_MDMP_MEMORY_LIST_STREAM = 4
_MDMP_MEMORY64_LIST_STREAM = 9


def _parse_mdmp(fh, size: int, path: str) -> dict[str, Any]:
    fh.seek(0)
    hdr = fh.read(32)
    if len(hdr) < 32:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: truncated MINIDUMP_HEADER"}
    _sig, _ver, nstreams, dir_rva, _cksum, _tstamp, _flags = \
        struct.unpack("<IIIIIIQ", hdr)
    if nstreams > 4096 or dir_rva >= size:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: implausible stream directory "
                         f"(nstreams={nstreams}, rva=0x{dir_rva:x})"}
    fh.seek(dir_rva)
    streams: dict[int, tuple[int, int]] = {}
    for _ in range(nstreams):
        entry = fh.read(12)
        if len(entry) < 12:
            break
        stype, dsize, rva = struct.unpack("<III", entry)
        if rva + dsize <= size:
            streams.setdefault(stype, (rva, dsize))

    exc = None
    context = None
    if _MDMP_EXCEPTION_STREAM in streams:
        rva, dsize = streams[_MDMP_EXCEPTION_STREAM]
        fh.seek(rva)
        exc = _mdmp_exception(fh.read(dsize))
        if exc is not None:
            ctx_rva = exc.pop("context_rva", 0)
            ctx_size = exc.pop("context_size", 0)
            if ctx_rva and ctx_size and ctx_rva + ctx_size <= size:
                fh.seek(ctx_rva)
                context = _decode_context64(fh.read(ctx_size))

    # VA -> file ranges from the memory-list streams (for stack reads).
    ranges: list[tuple[int, int, int]] = []  # (va, size, file_off)
    if _MDMP_MEMORY_LIST_STREAM in streams:
        rva, dsize = streams[_MDMP_MEMORY_LIST_STREAM]
        fh.seek(rva)
        blob = fh.read(dsize)
        if len(blob) >= 4:
            count = _u32(blob, 0)
            off = 4
            for _i in range(count):
                if off + 16 > len(blob):
                    break
                va = _u64(blob, off)
                dsz = _u32(blob, off + 8)
                drva = _u32(blob, off + 12)
                ranges.append((va, dsz, drva))
                off += 16
    if _MDMP_MEMORY64_LIST_STREAM in streams:
        rva, dsize = streams[_MDMP_MEMORY64_LIST_STREAM]
        fh.seek(rva)
        blob = fh.read(dsize)
        if len(blob) >= 16:
            count = _u64(blob, 0)
            base_rva = _u64(blob, 8)
            off = 16
            cur = base_rva
            for _i in range(count):
                if off + 16 > len(blob):
                    break
                va = _u64(blob, off)
                dsz = _u64(blob, off + 8)
                ranges.append((va, dsz, cur))
                cur += dsz
                off += 16

    def read_va(va: int, n: int) -> bytes | None:
        for base, rsz, roff in ranges:
            if base <= va and va + n <= base + rsz:
                fh.seek(roff + (va - base))
                data = fh.read(n)
                return data if len(data) == n else None
        return None

    stack = _stack_qwords(read_va, (context or {}).get("rsp") or 0)

    code = (exc or {}).get("code") or 0
    params = ((exc or {}).get("parameters") or [])[:4]
    params += [0] * (4 - len(params))
    out: dict[str, Any] = {
        "ok": True,
        "format": "mdmp",
        "bugcheck": {"code": code,
                     "name": NTSTATUS_NAMES.get(code, "0x%08x" % code)},
        "params": params,
        "context": context,
        "exception": exc,
        "dtb": None,
        "kd_data_block": None,
        "faulting_va": (exc or {}).get("address"),
        "stack_qwords": stack,
        "note": "usermode minidump: exception record stands in for "
                "the bugcheck fields",
    }
    return out
