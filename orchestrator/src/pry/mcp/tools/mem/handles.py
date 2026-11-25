"""``handles`` verb body (paged enumeration).

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from ..._envelope.opts import resolve_limit as _res_lim
from .._runtime.envelope import _list_envelope
from .._runtime.response import _decode_list, _hexify_dict


async def handle_handles(ctx, c, *, pid: int, want_names: bool,
                         filter: Any, summary: bool,
                         fields: list[str] | None, limit: int, offset: int,
                         max_results: int) -> str:
    # pull the table in bounded pages instead of one
    # shot. The proto's limit/offset are post-fill (the agent
    # still enumerates the full table per call), so paging
    # costs one enumeration per page — but it caps each wire
    # response, which is what killed the single mega-message
    # under load on pid=4. A short page ends the table; when
    # the caller asked for a bounded window we early-out once
    # it is filled.
    _PAGE = 2000
    eff_limit = limit or max_results
    # Early-out only when no filter/summary needs the full
    # table — filtering happens post-fetch in _list_envelope.
    # `need` mirrors resolve_limit so a default call pulls
    # just the 128-row window, not the whole table.
    need = 0
    if not filter and not summary:
        resolved = _res_lim("memory_manage", "handles", eff_limit,
                            global_cap=ctx.cfg.mcp_max_items())
        need = offset + resolved
    raw: list[dict[str, Any]] = []
    off = 0
    pages = 0
    while True:
        want = _PAGE if not need else min(_PAGE, need - off)
        if want <= 0:
            break
        page = await c.handle_list(pid, want_names,
                                   limit=want, offset=off)
        pages += 1
        if not page:
            break
        raw.extend(page)
        off += len(page)
        if len(page) < want:  # short page = end of table
            break
    # Early-out can't see past the window — the true table
    # size is unknown. Probe one row past the end so
    # truncated/next_cursor in the envelope stay honest.
    has_more = False
    if need and raw and len(raw) >= need:
        probe = await c.handle_list(pid, False,
                                    limit=1, offset=need)
        pages += 1
        has_more = bool(probe)
    handles = [{"handle": int(h.get("handle", 0)),
                 "type_name": h.get("type_name", ""),
                 "object": int(h.get("object", 0)),
                 "granted_access": int(h.get("granted_access", 0)),
                 "name": h.get("name", "")} for h in raw]
    handles = _decode_list(handles, "handle")
    env = _list_envelope(
        handles, tool="memory_manage", action="handles",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={"pages_fetched": pages,
                "table_total_unknown": has_more},
    )
    if has_more:
        # The envelope computed truncated/next_cursor against
        # the fetched rows, not the (unknown) table — patch so
        # callers see the real paging contract.
        summ = env.get("summary")
        if isinstance(summ, dict):
            summ["truncated"] = True
            summ["item_total"] = None
            summ["next_cursor"] = (
                f"offset:{offset + summ.get('item_count', 0)}")
    # Coverage is about the requested window, not table size:
    # the loop provably ran to a short page (end of table) or
    # filled the window, so the enumeration itself is complete.
    # `has_more` stays a paging concern (summary.truncated).
    env["coverage"] = _coverage("enumeration", "complete")
    return _hexify_dict(env, add_int_mirror=True)
