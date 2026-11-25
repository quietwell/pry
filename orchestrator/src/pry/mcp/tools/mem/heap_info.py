"""``heap_info`` verb body (slice 03 Feature 7).

Segment-heap decode wrapper over ``Memory.HeapInfo``. Agent view uses
the pry driver as its ``UserReadFn`` so PPL targets still decode;
umagent view relies on ReadProcessMemory and fails ``access_denied``
on PP/PPL (slice doc §Feature 7 PPL asymmetry).

While Wave 3 dyn-data lands the signed segment-heap offset table, the
walker degrades to ``coverage='partial'`` + ``hint='dyn_data_wave_3_pending'``.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.envelope import _list_envelope
from .._runtime.response import _j, _j_hex


async def handle_heap_info(ctx, c, *, pid: int, heap_filter: int,
                            include_segments: bool, include_lfh_buckets: bool,
                            space: str, filter: Any,
                            summary: bool, fields: list[str] | None,
                            limit: int, offset: int,
                            max_results: int) -> str:
    """Decode segment heaps in ``pid`` through the agent/umagent view.

    ``space='user'`` is the only accepted selector — kernel/physical
    heaps don't exist; a non-user space surfaces ``kind='bad_arg'`` so
    the caller sees why.
    """
    if space not in ("", "user"):
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "heap_info: space='user' only "
                            "(segment heaps live in process memory)"})
    if int(pid or 0) <= 0:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "heap_info: pid > 0 is required "
                            "(segment-heap decode is per-process)"})
    try:
        res = await c.mem_heap_info(
            pid=int(pid), heap_filter=int(heap_filter or 0),
            include_segments=bool(include_segments),
            include_lfh_buckets=bool(include_lfh_buckets))
    except Exception as exc:
        text = str(exc)
        if "ACCESS_DENIED" in text.upper() or "access_denied" in text:
            # PPL asymmetry: umagent dies here; agent view decodes.
            return _j({"ok": False, "kind": "access_denied",
                       "error": f"heap_info: {text}",
                       "hint": "umagent fails on PPL; use name=''"
                               " (agent/driver view) for PPL targets"})
        return _j({"ok": False, "kind": "heap_info_failed",
                   "error": text})
    if not res.get("ok"):
        kind = res.get("kind") or "heap_info_failed"
        env: dict = {"ok": False, "kind": kind,
                     "error": res.get("error") or "heap_info failed"}
        if kind == "agent_version":
            env["hint"] = ("rebuild + redeploy the agent "
                           "(scripts/update_target.py --component "
                           "agent) — Memory.HeapInfo is missing from this agent")
        return _j(env)

    rows = list(res.get("heaps") or [])
    cov_status = str(res.get("coverage") or "complete").lower()
    hint = str(res.get("hint") or "")
    limits: list[str] = []
    if hint:
        limits.append(hint)
    env = _list_envelope(
        rows, tool="memory_manage", action="heap_info",
        limit=limit or max_results, offset=offset,
        fields=fields or (),
        filter=filter if isinstance(filter, str) else "",
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={
            "pid": int(pid),
            "heap_filter": int(heap_filter or 0),
            "include_segments": bool(include_segments),
            "include_lfh_buckets": bool(include_lfh_buckets),
            # Operator-facing note (also surfaced in the help blurb):
            # umagent view fails on PPL; agent view decodes via the
            # driver read path.
            "ppl_note": ("umagent fails on PPL; agent view decodes via "
                         "driver read"),
        },
    )
    env["coverage"] = _coverage(
        "heap-info",
        "partial" if cov_status != "complete" else "complete",
        *limits)
    if hint:
        env["hint"] = hint
    return _j_hex(env)
