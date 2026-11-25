"""``object_manage`` — canonical handle / object-namespace tool.

Taxonomy brief §5.5. Actions: ``handles``, ``handle_dup``,
``handle_close``, ``handle_compare``, ``enum``, ``find``,
``find_status``, ``find_result``, ``find_cancel``, ``find_list``,
``actions``.

Handlers moved from ``mem/handles.py``, ``mem/handle_ops.py``,
``mem/obj_browse.py`` and ``mem/global_find.py``. ``enum`` is the old
``obj_enum`` (object-directory walker). ``find`` is the old
``global_find`` + its ``g####`` lifecycle (``find_status`` / ``_result``
/ ``_cancel`` / ``_list``).
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .mem import global_find as _mem_global_find
from .mem import handle_ops as _mem_handle_ops
from .mem import handles as _mem_handles
from .mem import obj_browse as _mem_obj_browse


OBJECT_ACTIONS = [
    "handles", "handle_dup", "handle_close", "handle_compare",
    "enum",
    "find", "find_status", "find_result", "find_cancel", "find_list",
    "actions",
]


_OBJECT_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "object_manage(action='actions')"},
    "handles": {"one_liner": "handle table enumeration",
                "key_args": "pid, want_names, filter, fields, summary, "
                            "limit, offset",
                "example": "object_manage(action='handles', pid=4812)"},
    "handle_dup": {"one_liner": "duplicate a handle from src_pid into "
                                "the caller (SI #6)",
                   "key_args": "src_pid, src_handle, desired_access, "
                               "options, privilege_cookie",
                   "example": "object_manage(action='handle_dup', "
                              "src_pid=4812, src_handle='0x1234')"},
    "handle_close": {"one_liner": "close a remote handle (SI #6)",
                     "key_args": "target_pid, target_handle, privilege_cookie",
                     "example": "object_manage(action='handle_close', "
                                "target_pid=4812, target_handle='0x1234')"},
    "handle_compare": {"one_liner": "compare two handles for pointer "
                                    "identity (SI #6)",
                       "key_args": "pid_a, handle_a, pid_b, handle_b",
                       "example": "object_manage(action='handle_compare', "
                                  "pid_a=4812, handle_a='0x1234', "
                                  "pid_b=5000, handle_b='0x5678')"},
    "enum": {"one_liner": "object namespace / directory walk",
             "key_args": "path, depth, max_results",
             "example": "object_manage(action='enum', path='\\\\Device')"},
    "find": {"one_liner": "background find job over modules / handles "
                          "/ objects; returns scan_id and next calls",
             "key_args": "pattern, kinds, regex, want_object_names, concurrency",
             "example": "object_manage(action='find', pattern='nvme', "
                        "kinds=['module','handle'])"},
    "find_status": {"one_liner": "poll a find job's progress",
                    "key_args": "scan_id",
                    "example": "object_manage(action='find_status', "
                               "scan_id='g0001')"},
    "find_result": {"one_liner": "read a find job's matches",
                    "key_args": "scan_id, limit, offset",
                    "example": "object_manage(action='find_result', "
                               "scan_id='g0001')"},
    "find_cancel": {"one_liner": "cancel a running find job",
                    "key_args": "scan_id",
                    "example": "object_manage(action='find_cancel', "
                               "scan_id='g0001')"},
    "find_list": {"one_liner": "list live find jobs",
                  "key_args": "none",
                  "example": "object_manage(action='find_list')"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``object_manage`` tool on *mcp*."""

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def object_manage(
        action: Annotated[str, Field(json_schema_extra={"enum": OBJECT_ACTIONS})],
        pid: int = 0,
        want_names: bool = False,
        src_pid: int = 0,
        src_handle: int | str = 0,
        target_pid: int = 0,
        target_handle: int | str = 0,
        pid_a: int = 0,
        handle_a: int | str = 0,
        pid_b: int = 0,
        handle_b: int | str = 0,
        desired_access: int = 0,
        options: int = 0,
        privilege_cookie: int = 0,
        path: str = "",
        depth: int = 1,
        pattern: str = "",
        pattern_hex: str = "",
        kinds: list[str] | None = None,
        regex: bool = False,
        want_object_names: bool = True,
        concurrency: int = 8,
        scan_id: str = "",
        max_results: int = 64,
        filter: Any = "",
        fields: list[str] | None = None,
        summary: bool = False,
        verbosity: str = "normal",
        limit: int = 0,
        offset: int = 0,
        name: str = "",
    ) -> str:
        """Handle tables (list / dup / close / compare), the object
        namespace walk (enum) and the background name find job (find +
        find_status / find_result / find_cancel / find_list). Per-verb
        help: object_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "pid": pid, "name": name,
                "verbosity": verbosity, "fields": fields or [],
                "filter": filter}

        def _coerce_handle(h: int | str) -> int:
            if isinstance(h, int):
                return h
            if not h:
                return 0
            try:
                return int(h, 0)
            except (TypeError, ValueError):
                return 0

        async def run() -> Any:
            if action == "actions":
                return _actions_help("object_manage", _OBJECT_ACTION_HELP)
            if action not in OBJECT_ACTIONS:
                return _unknown_action("object_manage", action,
                                       OBJECT_ACTIONS, _OBJECT_ACTION_HELP)
            c = ctx.session.require_client(name)
            if action == "handles":
                return await _mem_handles.handle_handles(
                    ctx, c, pid=pid, want_names=want_names, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "handle_dup":
                return await _mem_handle_ops.handle_handle_dup(
                    ctx, c, src_pid=int(src_pid),
                    src_handle=_coerce_handle(src_handle),
                    desired_access=int(desired_access),
                    options=int(options),
                    privilege_cookie=int(privilege_cookie),
                    name=name,
                )
            if action == "handle_close":
                return await _mem_handle_ops.handle_handle_close(
                    ctx, c, target_pid=int(target_pid),
                    target_handle=_coerce_handle(target_handle),
                    privilege_cookie=int(privilege_cookie),
                    name=name,
                )
            if action == "handle_compare":
                return await _mem_handle_ops.handle_handle_compare(
                    ctx, c, pid_a=int(pid_a),
                    handle_a=_coerce_handle(handle_a),
                    pid_b=int(pid_b),
                    handle_b=_coerce_handle(handle_b),
                    privilege_cookie=int(privilege_cookie),
                    name=name,
                )
            if action == "enum":
                return await _mem_obj_browse.handle_obj_enum(
                    ctx, c, path=path, depth=depth,
                    max_results=max_results, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset,
                )
            if action == "find":
                return await _mem_global_find.handle_global_find(
                    ctx, c,
                    pattern=pattern or pattern_hex,
                    kinds=kinds, regex=regex,
                    want_object_names=want_object_names,
                    max_results=max_results,
                    concurrency=concurrency,
                    scan_id="",
                    limit=limit, offset=offset,
                    cancel=False, list_jobs=False,
                )
            if action == "find_status":
                return await _mem_global_find.handle_global_find(
                    ctx, c, pattern="", kinds=None, regex=False,
                    want_object_names=False, max_results=0, concurrency=0,
                    scan_id=scan_id, limit=0, offset=0,
                    cancel=False, list_jobs=False,
                )
            if action == "find_result":
                return await _mem_global_find.handle_global_find(
                    ctx, c, pattern="", kinds=None, regex=False,
                    want_object_names=False, max_results=0, concurrency=0,
                    scan_id=scan_id, limit=limit, offset=offset,
                    cancel=False, list_jobs=False,
                )
            if action == "find_cancel":
                return await _mem_global_find.handle_global_find(
                    ctx, c, pattern="", kinds=None, regex=False,
                    want_object_names=False, max_results=0, concurrency=0,
                    scan_id=scan_id, limit=0, offset=0,
                    cancel=True, list_jobs=False,
                )
            if action == "find_list":
                return await _mem_global_find.handle_global_find(
                    ctx, c, pattern="", kinds=None, regex=False,
                    want_object_names=False, max_results=0, concurrency=0,
                    scan_id="", limit=0, offset=0,
                    cancel=False, list_jobs=True,
                )
            return _unknown_action("object_manage", action,
                                   OBJECT_ACTIONS, _OBJECT_ACTION_HELP)

        return await _guard(ctx, "object_manage", action, args, run)
