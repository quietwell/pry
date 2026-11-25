"""Kernel crash-dump decoders — ``DUMP_HEADER64`` + 32-bit fallback.

``_parse_kernel_dump`` walks the x64 DUMP_HEADER, decodes the embedded
CONTEXT and EXCEPTION record, extracts triage sub-header + saved
callstack bytes (when present), and resolves the stack qwords either
from the triage callstack region or by VA->PA through the dump's stored
page tables. ``_parse_kernel_dump32`` handles the x86 DUMP_HEADER
minimally so the caller gets bugcheck/params instead of a bad_dump
rejection.
"""

from __future__ import annotations

from typing import Any

from .bugcheck import (
    _FAULT_PARAM_MAP,
    _PRY_WATCHDOG_CODE,
    bugcheck_name,
    dump_type_name,
)
from .context import _decode_context64, _decode_exception64
from .header import _filetime_to_iso, _u32, _u64
from .offsets import (
    HEADER_SIZE_64,
    _KD_DEBUGGER_KERNBASE,
    _OFF_BUGCHECK,
    _OFF_COMMENT,
    _OFF_CONTEXT,
    _OFF_DTB,
    _OFF_DUMP_TYPE,
    _OFF_EXCEPTION,
    _OFF_KD_BLOCK,
    _OFF_MACHINE,
    _OFF_NUMPROC,
    _OFF_PARAMS,
    _OFF_PSAPH,
    _OFF_PSLML,
    _OFF_REQUIRED_SPACE,
    _OFF_SYSTEM_TIME,
    _OFF_SYSTEM_UPTIME,
    _OFF_VERSION_USER,
    _TRI_BROKEN_DRIVER_OFFSET,
    _TRI_CALLSTACK_OFFSET,
    _TRI_CALLSTACK_SIZE,
    _TRI_DATA_BLOCKS_COUNT,
    _TRI_DATA_BLOCKS_OFFSET,
    _TRI_DATA_PAGE_ADDRESS,
    _TRI_DATA_PAGE_OFFSET,
    _TRI_DATA_PAGE_SIZE,
    _TRI_DEBUGGER_DATA_OFFSET,
    _TRI_DEBUGGER_DATA_SIZE,
    _TRI_DRIVER_COUNT,
    _TRI_DRIVER_LIST_OFFSET,
    _TRI_SIZE_OF_DUMP,
    _TRI_SP_BUILD,
    _TRI_STRING_POOL_OFFSET,
    _TRI_STRING_POOL_SIZE,
    _TRI_TOP_OF_STACK,
)
from .phys import _phys_reader_from_header, _stack_qwords, _vtop


def _parse_kernel_dump(fh, size: int, path: str) -> dict[str, Any]:
    fh.seek(0)
    hdr = fh.read(HEADER_SIZE_64)
    if len(hdr) < HEADER_SIZE_64:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: truncated DUMP_HEADER64 "
                         f"({len(hdr)} of {HEADER_SIZE_64} bytes)"}
    params = [_u64(hdr, _OFF_PARAMS + i * 8) for i in range(4)]
    code = _u32(hdr, _OFF_BUGCHECK)
    context = _decode_context64(hdr[_OFF_CONTEXT:_OFF_CONTEXT + 3000])
    exception = _decode_exception64(hdr[_OFF_EXCEPTION:_OFF_EXCEPTION + 152])
    dtb = _u64(hdr, _OFF_DTB)
    dump_type = _u32(hdr, _OFF_DUMP_TYPE)
    system_time = _u64(hdr, _OFF_SYSTEM_TIME)

    out: dict[str, Any] = {
        "ok": True,
        "format": "kernel_dump",
        "bugcheck": {"code": code, "name": bugcheck_name(code)},
        "params": params,
        "context": context,
        "exception": exception,
        "dtb": dtb,
        "kd_data_block": _u64(hdr, _OFF_KD_BLOCK) or None,
        "machine_image_type": _u32(hdr, _OFF_MACHINE),
        "num_processors": _u32(hdr, _OFF_NUMPROC),
        "ps_loaded_module_list": _u64(hdr, _OFF_PSLML) or None,
        "ps_active_process_head": _u64(hdr, _OFF_PSAPH) or None,
        "version_user": hdr[_OFF_VERSION_USER:_OFF_VERSION_USER + 32]
                        .split(b"\0", 1)[0].decode("utf-8", "replace"),
        "os_version": {"major": _u32(hdr, 0x08), "minor": _u32(hdr, 0x0C)},
        "dump_type": {"code": dump_type, "name": dump_type_name(dump_type)},
        "system_time_filetime": system_time,
        "system_time_iso": _filetime_to_iso(system_time),
        "comment": hdr[_OFF_COMMENT:_OFF_COMMENT + 128]
                   .split(b"\0", 1)[0].decode("utf-8", "replace"),
        "required_dump_space": _u64(hdr, _OFF_REQUIRED_SPACE),
        "system_uptime_100ns": _u64(hdr, _OFF_SYSTEM_UPTIME),
    }

    # faulting_va heuristic — class-specific param first, then the
    # exception record's faulting address, then rip.
    spec = _FAULT_PARAM_MAP.get(code, {})
    faulting_va = None
    if "faulting_va" in spec:
        faulting_va = params[spec["faulting_va"]]
    if not faulting_va and exception:
        faulting_va = exception.get("address") or None
    if not faulting_va and context:
        faulting_va = context.get("rip")
    out["faulting_va"] = faulting_va
    if "faulting_pc" in spec:
        out["faulting_pc"] = params[spec["faulting_pc"]]
    elif context:
        out["faulting_pc"] = context.get("rip")

    # pry watchdog self-identification: the driver's DPC watchdog
    # bugchecks 0xE2 with params {id, deadline_us, last_kick_us, cookie}
    # (see driver/Watchdog.c). A user-initiated crash leaves them 0.
    if code == _PRY_WATCHDOG_CODE and any(params):
        out["watchdog"] = {
            "id": params[0],
            "deadline_us": params[1],
            "last_kick_us": params[2],
            "cookie": params[3],
        }
        out["fired_by"] = "pry_watchdog"

    # Stack qwords — how they're read depends on the body layout.
    stack: list[dict[str, int]] = []
    rsp = (context or {}).get("rsp") or 0
    if dump_type == 4 and size >= HEADER_SIZE_64 + 0x80:
        fh.seek(HEADER_SIZE_64)
        tri = fh.read(0x80)
        if len(tri) == 0x80:
            cs_off = _u32(tri, _TRI_CALLSTACK_OFFSET)
            cs_size = _u32(tri, _TRI_CALLSTACK_SIZE)
            top = _u64(tri, _TRI_TOP_OF_STACK)
            dp_addr = _u64(tri, _TRI_DATA_PAGE_ADDRESS)
            dp_off = _u32(tri, _TRI_DATA_PAGE_OFFSET)
            dp_size = _u32(tri, _TRI_DATA_PAGE_SIZE)
            out["triage"] = {
                "service_pack_build": _u32(tri, _TRI_SP_BUILD),
                "size_of_dump": _u32(tri, _TRI_SIZE_OF_DUMP),
                "callstack_offset": cs_off,
                "callstack_size": cs_size,
                "top_of_stack": top,
                "driver_list_offset": _u32(tri, _TRI_DRIVER_LIST_OFFSET),
                "driver_count": _u32(tri, _TRI_DRIVER_COUNT),
                "broken_driver_offset": _u32(tri, _TRI_BROKEN_DRIVER_OFFSET),
                "string_pool_offset": _u32(tri, _TRI_STRING_POOL_OFFSET),
                "string_pool_size": _u32(tri, _TRI_STRING_POOL_SIZE),
                "debugger_data_offset": _u32(tri, _TRI_DEBUGGER_DATA_OFFSET),
                "debugger_data_size": _u32(tri, _TRI_DEBUGGER_DATA_SIZE),
                "data_blocks_offset": _u32(tri, _TRI_DATA_BLOCKS_OFFSET),
                "data_blocks_count": _u32(tri, _TRI_DATA_BLOCKS_COUNT),
            }
            # KernBase from the embedded debugger-data block — the anchor
            # for offline nt-relative attribution when no live map exists.
            dd_off = _u32(tri, _TRI_DEBUGGER_DATA_OFFSET)
            dd_size = _u32(tri, _TRI_DEBUGGER_DATA_SIZE)
            if (dd_off and dd_size > _KD_DEBUGGER_KERNBASE + 8
                    and dd_off + dd_size <= size):
                fh.seek(dd_off)
                dd = fh.read(_KD_DEBUGGER_KERNBASE + 8)
                if len(dd) == _KD_DEBUGGER_KERNBASE + 8:
                    kb = _u64(dd, _KD_DEBUGGER_KERNBASE)
                    if kb >= 0xFFFF800000000000:
                        out["triage"]["kernbase"] = kb

            def read_va(va: int, n: int) -> bytes | None:
                # The saved callstack bytes cover VAs [TopOfStack,
                # TopOfStack + SizeOfCallStack): TopOfStack is the
                # capturing thread's Rsp (the stack grows down, so rsp is
                # the top of the in-use stack and the save runs upward
                # through the older frames). Pinned against real
                # minidumps: TopOfStack == context.rsp and stack[rsp]
                # decodes to a return address. An earlier reading of the
                # field as the region END (base = top - size) matched
                # nothing — that bug emptied stack_qwords for every
                # real triage dump.
                if cs_size and top <= va and va + n <= top + cs_size:
                    fh.seek(cs_off + (va - top))
                    data = fh.read(n)
                    return data if len(data) == n else None
                if dp_size and dp_addr <= va and va + n <= dp_addr + dp_size:
                    fh.seek(dp_off + (va - dp_addr))
                    data = fh.read(n)
                    return data if len(data) == n else None
                return None

            if rsp:
                stack = _stack_qwords(read_va, rsp)
            if not stack and top:
                # rsp below/outside the saved region — still walk what
                # was saved rather than returning nothing.
                stack = _stack_qwords(read_va, top)
    else:
        phys = _phys_reader_from_header(fh, hdr, dump_type)
        if phys is not None and rsp:
            def read_va(va: int, n: int) -> bytes | None:
                pa = _vtop(phys, dtb, va)
                return phys.read(pa, n) if pa is not None else None

            stack = _stack_qwords(read_va, rsp)
    out["stack_qwords"] = stack
    return out


def _parse_kernel_dump32(fh, size: int, path: str) -> dict[str, Any]:
    """Minimal 32-bit DUMP_HEADER parse — bugcheck + params only.

    The x86 header predates this codebase's scope (the lab is x64); the
    fixed early fields still decode so the caller gets the answer that
    matters instead of a bad_dump rejection.
    """
    fh.seek(0)
    hdr = fh.read(0x40)
    if len(hdr) < 0x3C:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: truncated 32-bit DUMP_HEADER"}
    params = [_u32(hdr, 0x2C + i * 4) for i in range(4)]
    code = _u32(hdr, 0x28)
    out: dict[str, Any] = {
        "ok": True,
        "format": "kernel_dump32",
        "bugcheck": {"code": code, "name": bugcheck_name(code)},
        "params": params,
        "context": None,
        "exception": None,
        "dtb": _u32(hdr, 0x10),
        "kd_data_block": None,
        "stack_qwords": [],
        "note": "32-bit header: context/exception/stack not decoded",
    }
    spec = _FAULT_PARAM_MAP.get(code, {})
    out["faulting_va"] = (params[spec["faulting_va"]]
                          if "faulting_va" in spec else None)
    if code == _PRY_WATCHDOG_CODE and any(params):
        out["watchdog"] = {
            "id": params[0], "deadline_us": params[1],
            "last_kick_us": params[2], "cookie": params[3],
        }
        out["fired_by"] = "pry_watchdog"
    return out
