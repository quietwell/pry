"""``kernel_manage`` - canonical kernel-structures tool.

Actions:

- ``pool_scan`` - synchronous pool-tag / content scan of the kernel pool.
- ``idt`` - per-CPU IDT dump.
- ``struct_read`` - live-read a named kernel struct (layout + fields).
- ``actions``.

The ``scan_status`` / ``scan_result`` / ``scan_cancel`` / ``scan_list``
verbs used to be duplicated here; they only ever served
``memory_manage(action='scan_start')`` jobs (pool_scan is synchronous)
and now answer with a ``moved`` pointer to ``memory_manage``.
"""

from __future__ import annotations

from ..common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from ..context import Context
from ..mem import forensics as _mem_forensics
from ..mem import pool as _mem_pool

from . import _struct_read


KERNEL_ACTIONS = [
    "pool_scan",
    "idt",
    # Memory scanner wave 3 §6 — live-read struct field view.
    "struct_read",
    "actions",
]


# Retired duplicates -> their canonical home (memory_manage owns scan jobs).
_KERNEL_MOVED: dict[str, tuple[str, str]] = {
    "scan_status": ("memory_manage", "scan_status"),
    "scan_result": ("memory_manage", "scan_result"),
    "scan_cancel": ("memory_manage", "scan_cancel"),
    "scan_list": ("memory_manage", "scan_list"),
}


_KERNEL_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "kernel_manage(action='actions')"},
    "pool_scan": {"one_liner": ("synchronous kernel-pool scan: filter by "
                                "pool tag and/or a byte pattern inside "
                                "each allocation (non-paged pool)"),
                  "key_args": ("tag (4-char or int), pattern (IDA-style "
                               "hex), size (content window, required with "
                               "pattern), content_offset, max_results, "
                               "enrich_tags"),
                  "example": "kernel_manage(action='pool_scan', "
                             "tag='Proc', max_results=32)"},
    "idt": {"one_liner": "per-CPU IDT dump (off-allowlist handlers "
                         "flagged suspicious)",
            "key_args": "all_cpus, path, compact, filter, summary",
            "example": "kernel_manage(action='idt')"},
    "struct_read": {"one_liner": "live-read a named kernel struct in "
                                 "one call (layout + decoded fields). "
                                 "Wave 3 scope: _EPROCESS. Baked "
                                 "offset tables cover PDB-less hosts.",
                    "key_args": "module, type_name, va | lookup_by, "
                                "fields, max_depth, name",
                    "example": "kernel_manage(action='struct_read', "
                               "type_name='_EPROCESS', "
                               "va='0xffffe000...', "
                               "fields=['ImageFileName',"
                               "'UniqueProcessId'])"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``kernel_manage`` tool on *mcp*."""

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def kernel_manage(
        action: Annotated[str, Field(json_schema_extra={"enum": KERNEL_ACTIONS})],
        pid: int = 0,
        size: int = 0,
        space: str = "kernel",
        pattern: str = "",
        pattern_hex: str = "",
        mask: str = "",
        protect: int = 0,
        enrich_tags: bool = True,
        module: str = "",
        scan_id: str = "",
        all_cpus: bool = False,
        path: str = "",
        compact: bool = False,
        filter: Any = "",
        fields: list[str] | None = None,
        summary: bool = False,
        verbosity: str = "normal",
        limit: int = 0,
        offset: int = 0,
        max_results: int = 64,
        name: str = "",
        # Memory scanner wave 3 §6 — struct_read inputs.
        type_name: str = "",
        va: int | str = 0,
        lookup_by: dict[str, Any] | None = None,
        max_depth: int = 1,
    ) -> str:
        """Semantic kernel structures: pool_scan (pool tag / content
        scan), idt (per-CPU IDT), struct_read (named struct, decoded).
        ``memory_manage(action='read', space='kernel', ...)`` is the
        raw-byte path. Per-verb help:
        kernel_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "pid": pid, "name": name,
                "verbosity": verbosity, "fields": fields or [],
                "filter": filter}

        async def run() -> Any:
            if action == "actions":
                return _actions_help("kernel_manage", _KERNEL_ACTION_HELP)
            if action in _KERNEL_MOVED:
                new_tool, new_action = _KERNEL_MOVED[action]
                return _moved_verb("kernel_manage", action, new_tool,
                                   new_action, "scan jobs live there")
            if action not in KERNEL_ACTIONS:
                return _unknown_action("kernel_manage", action,
                                       KERNEL_ACTIONS, _KERNEL_ACTION_HELP)
            # Space narrowing: pool_scan runs in kernel pool; idt is
            # per-CPU kernel data.
            if space not in ("", "kernel", "physical"):
                return _j({"ok": False, "kind": "bad_arg",
                           "error": f"kernel_manage.{action}: space must be "
                                    "'kernel' (or omitted); user is on "
                                    "memory_manage",
                           "hint": "pass space='kernel' or drop the kwarg"})
            c = ctx.session.require_client(name)
            if action == "pool_scan":
                return await _mem_pool.handle_pool_scan(
                    ctx, c, pid=pid, size=size, space="kernel", kernel=True,
                    pattern=pattern, pattern_hex=pattern_hex, mask=mask,
                    max_results=max_results, module=module,
                    protect=protect, filter=filter, summary=summary,
                    fields=fields, limit=limit, offset=offset,
                    enrich_tags=bool(enrich_tags),
                )
            if action == "idt":
                return await _mem_forensics.handle_idt(
                    ctx, c, pid=pid, all_cpus=all_cpus, path=path,
                    compact=compact, verbosity=verbosity, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "struct_read":
                return await _struct_read.handle_struct_read(
                    ctx, c,
                    name=name,
                    module=module,
                    type_name=type_name or "",
                    va=va,
                    lookup_by=lookup_by,
                    fields=list(fields) if fields else None,
                    max_depth=int(max_depth or 1),
                )
            return _unknown_action("kernel_manage", action,
                                   KERNEL_ACTIONS, _KERNEL_ACTION_HELP)

        return await _guard(ctx, "kernel_manage", action, args, run)
