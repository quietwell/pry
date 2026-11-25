"""``obj_enum`` verb body (kernel object-directory enumeration).

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
The slice doc names this module ``obj_browse.py`` because SI Wave 1
will also fold the ``obj_browse`` enrichment verb in here.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.envelope import _list_envelope
from .._runtime.response import _j


async def handle_obj_enum(ctx, c, *, path: str, depth: int,
                          max_results: int, filter: Any, summary: bool,
                          fields: list[str] | None, limit: int,
                          offset: int) -> str:
    if not path:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": ("obj_enum: path= is required "
                             "(e.g. path='\\\\Device')"),
                   "hint": ("memory_manage(action='obj_enum', "
                            "path='\\\\Device', depth=1) — "
                            "feeds device_manage ioctl sends")})
    try:
        res = await c.obj_enum(path, depth=depth,
                               max_entries=max_results or 4096)
    except Exception as exc:
        msg = str(exc)
        if "UNIMPLEMENTED" in msg:
            return _j({"ok": False, "kind": "agent_version",
                       "error": ("obj_enum: agent < v11 "
                                 "(Memory.ObjEnum missing)"),
                       "hint": ("rebuild + redeploy the agent "
                                "(scripts/update_target.py "
                                "--component agent)")})
        return _j({"ok": False, "kind": "obj_enum_failed",
                   "error": msg})
    if not res.get("ok"):
        return _j({"ok": False, "kind": "obj_enum_failed",
                   "error": res.get("error", "obj enum failed")})
    env = _list_envelope(
        res.get("entries", []), tool="memory_manage", action="obj_enum",
        limit=limit or max_results, offset=offset,
        fields=fields or (),
        filter=filter if isinstance(filter, str) else "",
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={"path": path, "depth": depth,
                "truncated": res.get("truncated", False),
                "note": ("device names here feed "
                         "device_manage(action='ioctl') "
                         "directly")},
    )
    env["coverage"] = _coverage(
        "enumeration",
        "partial" if res.get("truncated") else "complete",
        *(["provider_truncated"] if res.get("truncated") else []))
    return _j(env)
