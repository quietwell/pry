"""``probe_va`` / ``va_translate`` / ``imports`` / ``exports`` /
``heaps`` / ``phys_ranges`` verb bodies.

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.addrs import _enrich_win32
from .._runtime.driver_gate import _require_driver
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict, _j


async def handle_probe_va(ctx, c, *, pid: int, addr: int,
                          space: str) -> str:
    # 1-byte read with allow_fault forced OFF. `readable`
    # tells you whether the address currently backs valid
    # memory without the risk of the driver's soft-fault
    # fallback bugchecking the target — the exact primitive
    # for walking unknown kernel pools.
    try:
        await c.mem_read(pid, addr, 1, space, allow_fault=False)
        return _j({"ok": True, "readable": True,
                   "address": hex(addr), "space": space})
    except Exception as exc:  # noqa: BLE001 - probe never raises
        return _j({"ok": True, "readable": False,
                   "address": hex(addr), "space": space,
                   "reason": _enrich_win32(str(exc))})


async def handle_va_translate(ctx, c, *, pid: int, addr: int,
                              space: str) -> str:
    if not hasattr(c, "mem_va_translate"):
        return _j({"ok": False,
                   "error": "va_translate: agent < v7 (Memory.VaTranslate missing)",
                   "hint": "rebuild agent + comm + driver with ABI v7"})
    r = await c.mem_va_translate(addr, space=space, pid=pid)
    r.update({"ok": True, "va": hex(addr), "space": space, "pid": pid,
              "pa_hex": hex(r["pa"])})
    return _j(r)


async def handle_imports(ctx, c, *, pid: int, module: str, name: str,
                         kernel_lookup: bool, filter: Any, summary: bool,
                         fields: list[str] | None, limit: int, offset: int,
                         max_results: int) -> str:
    if not module:
        return _j({"ok": False, "error": "imports requires 'module'"})
    if kernel_lookup:
        guard = await _require_driver(ctx, "memory_manage", "imports", name)
        if guard: return _j(guard)
    ents = await c.mem_imports(pid, module, kernel_lookup)
    hooked = sum(1 for e in ents if e.get("hooked"))
    eff_limit = limit or max_results
    env = _list_envelope(
        ents, tool="memory_manage", action="imports",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={"module": module, "hooked": hooked},
    )
    env["coverage"] = _coverage("enumeration", "complete")
    return _hexify_dict(env, add_int_mirror=True)


async def handle_exports(ctx, c, *, pid: int, module: str, name: str,
                         kernel_lookup: bool, filter: Any, summary: bool,
                         fields: list[str] | None, limit: int, offset: int,
                         max_results: int) -> str:
    if not module:
        return _j({"ok": False, "error": "exports requires 'module'"})
    if kernel_lookup:
        guard = await _require_driver(ctx, "memory_manage", "exports", name)
        if guard: return _j(guard)
    ents = await c.mem_exports(pid, module, kernel_lookup)
    eff_limit = limit or max_results
    env = _list_envelope(
        ents, tool="memory_manage", action="exports",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={"module": module},
    )
    env["coverage"] = _coverage("enumeration", "complete")
    return _hexify_dict(env, add_int_mirror=True)


async def handle_heaps(ctx, c, *, pid: int, want_blocks: bool,
                       max_blocks: int) -> str:
    heaps = await c.mem_heaps(pid, want_blocks, max_blocks)
    return _j({"count": len(heaps), "heaps": heaps,
               "coverage": _coverage("enumeration", "complete")})


async def handle_phys_ranges(ctx, c) -> str:
    # Enumerate MmGetPhysicalMemoryRanges (re-queried per call).
    # Returned Base/Size come back as hex strings for LLM clients.
    ranges = await c.phys_ranges()
    total = sum(r["size"] for r in ranges)
    return _j({"count": len(ranges),
               "total_ram_bytes": total,
               "total_ram_gib": round(total / (1 << 30), 3),
               "coverage": _coverage("enumeration", "complete"),
               "ranges": [{"base": hex(r["base"]),
                           "size": hex(r["size"]),
                           "kind": r["kind"]} for r in ranges]})
