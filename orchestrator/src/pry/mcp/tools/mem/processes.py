"""``process_list`` verb body.

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict


async def handle_process_list(ctx, c, *, with_cmdline: bool,
                              filter: Any, fields: list[str] | None,
                              summary: bool, limit: int, offset: int,
                              max_results: int) -> str:
    res = await c.mem_processes(with_cmdline=with_cmdline, full=True)
    procs = (res.get("processes") if isinstance(res, dict)
             else res) or []
    eff_limit = limit or max_results
    env = _list_envelope(
        procs, tool="memory_manage", action="process_list",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={"source": res.get("source")
                if isinstance(res, dict) else "agent"},
    )
    env["coverage"] = _coverage("enumeration", "complete")
    return _hexify_dict(env, add_int_mirror=True)
