"""``disasm`` / ``assemble`` verb bodies (facade over ``codegen_glue``).

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

import json
from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.codegen_glue import _mem_assemble, _mem_disasm
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict


async def handle_disasm(ctx, c, *, name: str, pid: int, space: str,
                        addr: int, bytes_hex: str, arch: str, syntax: str,
                        count: int, size: int, detail: Any,
                        resolve_symbols: bool, allow_fault: bool,
                        timeout_s: float, filter: Any, summary: bool,
                        fields: list[str] | None, limit: int,
                        offset: int, max_results: int) -> str:
    raw = await _mem_disasm(
        ctx, name=name, pid=pid, space=space,
        address=addr, bytes_hex=bytes_hex,
        arch=arch, syntax=syntax, count=count, size=size,
        detail=detail, resolve_symbols=resolve_symbols,
        allow_fault=allow_fault, timeout_s=timeout_s,
    )
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return raw
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return parsed
    instructions = parsed.get("instructions", []) or []
    extras = {k: parsed[k] for k in
              ("arch", "start", "bytes_used",
               "truncated", "source", "first_bad_offset")
              if k in parsed}
    eff_limit = limit or count or max_results
    if parsed.get("first_bad_offset") is not None:
        cov = _coverage("mem-read", "partial",
                        "read_failed_mid_buffer")
    elif parsed.get("truncated"):
        cov = _coverage("mem-read", "partial", "decode_truncated")
    else:
        cov = _coverage("mem-read", "complete")
    env = _list_envelope(
        instructions, tool="memory_manage", action="disasm",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras=extras,
    )
    env["coverage"] = cov
    return _hexify_dict(env, add_int_mirror=True)


async def handle_assemble(ctx, c, *, name: str, pid: int, space: str,
                          code: str, arch: str, addr: int,
                          write_to: int | str, dry_run: bool,
                          allow_map_write: bool) -> str:
    return await _mem_assemble(
        ctx, name=name, pid=pid, space=space,
        code=code, arch=arch, address=addr,
        write_to=write_to, dry_run=dry_run,
        allow_map_write=allow_map_write,
    )
