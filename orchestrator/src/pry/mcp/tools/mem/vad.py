"""``vad`` verb body.

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.envelope import _envelope_ok, _list_envelope
from .._runtime.response import _decode_list, _hexify_dict
from .._runtime.row_filters import _apply_vad_filter, _vad_summary


async def handle_vad(ctx, c, *, pid: int, filter: Any, summary: bool,
                     fields: list[str] | None, limit: int, offset: int,
                     max_results: int) -> str:
    vads = await c.vad_list(pid)
    # Normalize before filter so protect/vad_type are comparable.
    vads = [{"start": int(e.get("start", 0)) if not isinstance(e.get("start"), str)
                        else int(e.get("start", "0"), 0),
              "end":   int(e.get("end", 0)) if not isinstance(e.get("end"), str)
                        else int(e.get("end", "0"), 0),
              "protect": int(e.get("protect", 0)),
              "vad_type": int(e.get("vad_type", 0)),
              "commit_charge": int(e.get("commit_charge", 0))}
             for e in vads]
    # Dict-shaped filter uses VAD-specific semantics (protect flags,
    # range overlap); apply it here so str filters still route
    # through apply_page_opts below.
    if isinstance(filter, dict) and filter:
        vads = _apply_vad_filter(vads, filter)
    if summary:
        env = _envelope_ok(
            {"summary": _vad_summary(vads)},
            kind="vad", tool="memory_manage", action="vad",
            item_count=0, item_total=len(vads),
            coverage=_coverage("enumeration", "complete"),
        )
        return _hexify_dict(env, add_int_mirror=True)
    # attach _decoded siblings for protect + vad_type
    vads = _decode_list(vads, "vad")
    eff_limit = limit or max_results
    pass_filter = "" if isinstance(filter, dict) else filter
    env = _list_envelope(
        vads, tool="memory_manage", action="vad",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=pass_filter,
        summary=False,
        global_cap=ctx.cfg.mcp_max_items(),
    )
    env["coverage"] = _coverage("enumeration", "complete")
    return _hexify_dict(env, add_int_mirror=True)
