"""``alloc`` / ``free`` / ``protect`` verb bodies.

Phase R5 move — the three VirtualAlloc(Ex)-family dispatches lifted
verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

from .._runtime.response import _j


async def handle_alloc(ctx, c, *, pid: int, size: int, protect: int,
                       kernel: bool) -> str:
    a2 = await c.mem_alloc(pid, size or 0x1000, protect or 4, kernel)
    return _j({"ok": True, "address": hex(a2)})


async def handle_free(ctx, c, *, pid: int, addr: int, kernel: bool) -> str:
    return _j(await c.mem_free(pid, addr, kernel))


async def handle_protect(ctx, c, *, pid: int, addr: int, size: int,
                         protect: int) -> str:
    return _j(await c.mem_protect(pid, addr, size or 0x1000, protect))
