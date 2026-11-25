"""CONTEXT_AMD64 + EXCEPTION_RECORD64 decoders, including the MDMP flavour.

Shared by both kernel and MDMP decoders — kernel reads the 3000-byte
ContextRecord buffer out of the DUMP_HEADER64, MDMP reads it out of a
stream RVA.
"""

from __future__ import annotations

from typing import Any

from .header import _u16, _u32, _u64
from .offsets import (
    _CONTEXT_AMD64,
    _CTX_DR0,
    _CTX_EFLAGS,
    _CTX_FLAGS,
    _CTX_MXCSR,
    _CTX_RAX,
    _CTX_RIP,
    _CTX_SEGCS,
    _EXC_ADDRESS,
    _EXC_CODE,
    _EXC_FLAGS,
    _EXC_INFO,
    _EXC_NUMPARAMS,
    _EXC_RECORD,
)


def _decode_context64(buf: bytes) -> dict[str, Any] | None:
    """Decode an x64 CONTEXT out of the 3000-byte ContextRecord buffer.

    Returns None when the buffer is absent/filler — post-Vista dumps pad
    unused header space with the "PAGE" loop and pre-SP1 fields can be
    zeros, so the CONTEXT_AMD64 flag bit is the only honest check.
    """
    if len(buf) < _CTX_RIP + 8:
        return None
    flags = _u32(buf, _CTX_FLAGS)
    if not (flags & _CONTEXT_AMD64):
        return None
    gprs = {}
    for i, name in enumerate(("rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                            "rsi", "rdi", "r8", "r9", "r10", "r11",
                            "r12", "r13", "r14", "r15")):
        gprs[name] = _u64(buf, _CTX_RAX + i * 8)
    ctx: dict[str, Any] = {
        "arch": "x64",
        "context_flags": flags,
        "mxcsr": _u32(buf, _CTX_MXCSR),
        "eflags": _u32(buf, _CTX_EFLAGS),
        "seg_cs": _u16(buf, _CTX_SEGCS),
        "seg_ds": _u16(buf, _CTX_SEGCS + 2),
        "seg_es": _u16(buf, _CTX_SEGCS + 4),
        "seg_fs": _u16(buf, _CTX_SEGCS + 6),
        "seg_gs": _u16(buf, _CTX_SEGCS + 8),
        "seg_ss": _u16(buf, _CTX_SEGCS + 10),
        "dr0": _u64(buf, _CTX_DR0),
        "dr1": _u64(buf, _CTX_DR0 + 8),
        "dr2": _u64(buf, _CTX_DR0 + 0x10),
        "dr3": _u64(buf, _CTX_DR0 + 0x18),
        "dr6": _u64(buf, _CTX_DR0 + 0x20),
        "dr7": _u64(buf, _CTX_DR0 + 0x28),
        "rip": _u64(buf, _CTX_RIP),
    }
    ctx.update(gprs)
    return ctx


def _decode_exception64(buf: bytes) -> dict[str, Any] | None:
    """Decode the embedded EXCEPTION_RECORD64. Returns None for an empty
    record (code 0 and address 0 means "not populated", not a real
    exception)."""
    if len(buf) < _EXC_INFO:
        return None
    code = _u32(buf, _EXC_CODE)
    addr = _u64(buf, _EXC_ADDRESS)
    if not code and not addr:
        return None
    n = min(_u32(buf, _EXC_NUMPARAMS), 15)
    return {
        "code": code,
        "flags": _u32(buf, _EXC_FLAGS),
        "record": _u64(buf, _EXC_RECORD),
        "address": addr,
        "num_parameters": _u32(buf, _EXC_NUMPARAMS),
        "parameters": [_u64(buf, _EXC_INFO + i * 8) for i in range(n)],
    }


def _mdmp_exception(buf: bytes) -> dict[str, Any] | None:
    if len(buf) < 4 + 4 + 152 + 8:
        return None
    exc_off = 8  # past ThreadId + alignment
    code = _u32(buf, exc_off)
    n = min(_u32(buf, exc_off + 0x18), 15)
    loc_off = exc_off + 152
    return {
        "thread_id": _u32(buf, 0),
        "code": code,
        "flags": _u32(buf, exc_off + 0x04),
        "record": _u64(buf, exc_off + 0x08),
        "address": _u64(buf, exc_off + 0x10),
        "num_parameters": _u32(buf, exc_off + 0x18),
        "parameters": [_u64(buf, exc_off + 0x20 + i * 8) for i in range(n)],
        "context_rva": _u32(buf, loc_off + 4),
        "context_size": _u32(buf, loc_off),
    }
