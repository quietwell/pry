"""``module_manage`` — canonical module-inventory tool.

Taxonomy brief §5.4: ``list``, ``get``, ``imports``, ``exports``,
``coherency``, ``actions``.

Handlers moved from ``mem/modules.py``, ``mem/coherency.py``, and the
``mem/probes.py`` import/export walkers. **No mitigation data on module
rows** — mitigations live on ``process_manage`` (taxonomy §5.4 explicit
rule).
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .mem import coherency as _mem_coherency
from .mem import modules as _mem_modules
from .mem import probes as _mem_probes


MODULE_ACTIONS = ["list", "get", "imports", "exports", "coherency", "actions"]


_MODULE_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "module_manage(action='actions')"},
    "list": {"one_liner": "user / kernel loaded modules + signature "
                          "enrichment",
             "key_args": "pid, kernel, filter, name_regex, name_glob, "
                         "path_contains, verify_signatures, force_recheck",
             "example": "module_manage(action='list', pid=4812)"},
    "get": {"one_liner": "single-module detail",
            "key_args": "pid, module",
            "example": "module_manage(action='get', pid=4812, "
                       "module='ntdll.dll')"},
    "imports": {"one_liner": "PE import table walk",
                "key_args": "pid, module",
                "example": "module_manage(action='imports', pid=4812, "
                           "module='kernel32.dll')"},
    "exports": {"one_liner": "PE export table walk",
                "key_args": "pid, module",
                "example": "module_manage(action='exports', pid=4812, "
                           "module='ntdll.dll')"},
    "coherency": {"one_liner": "image coherency scorer: in-memory "
                                "image vs on-disk file",
                  "key_args": "pid, module, base, mode, "
                              "max_mismatch_ranges, include_mismatch_hex",
                  "example": "module_manage(action='coherency', pid=4812, "
                             "module='ntdll.dll')"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``module_manage`` tool on *mcp*."""

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def module_manage(
        action: Annotated[str, Field(json_schema_extra={"enum": MODULE_ACTIONS})],
        pid: int = 0,
        module: str = "",
        base: int | str = 0,
        kernel: bool = False,
        name_regex: str = "",
        name_glob: str = "",
        path_contains: str = "",
        compact: bool = False,
        verify_signatures: bool = False,
        force_recheck: bool = False,
        mode: str = "normal",
        max_mismatch_ranges: int = 0,
        include_mismatch_hex: bool = False,
        filter: Any = "",
        fields: list[str] | None = None,
        summary: bool = False,
        verbosity: str = "normal",
        limit: int = 0,
        offset: int = 0,
        max_results: int = 64,
        name: str = "",
    ) -> str:
        """Module inventory (user or kernel), single-module detail,
        imports/exports walks and image-coherency scoring (in-memory image
        vs on-disk file). kernel=true or pid=0 selects kernel modules.
        Mitigations live on process_manage, not on module rows. Per-verb
        help: module_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "pid": pid, "module": module, "name": name,
                "verbosity": verbosity, "fields": fields or [],
                "filter": filter}

        async def run() -> Any:
            if action == "actions":
                return _actions_help("module_manage", _MODULE_ACTION_HELP)
            if action not in MODULE_ACTIONS:
                return _unknown_action("module_manage", action,
                                       MODULE_ACTIONS, _MODULE_ACTION_HELP)
            # `name` is the target-view selector (PRIMARY_TARGET /
            # 'user' / 'kernel' / '<machine>.<kind>'), never a row
            # filter. Someone passing name='tcpip' meant filter='tcpip'
            # or name_regex='^tcpip\.sys$'; route them with a named
            # error before require_client churns on a bogus view.
            if name not in (PRIMARY_TARGET, "user", "kernel", "") \
                    and ctx.session._match_machine(
                        name.rsplit(".", 1)[0]) is None:
                return _j({"ok": False,
                           "kind": "kwarg_collision",
                           "error": ("'name' selects a target view ('kernel'|"
                                     "'user'), not a row filter. Use 'filter' "
                                     "or 'name_regex' to select rows."),
                           "hint": "filter='tcpip' or name_regex='^tcpip\\\\.sys$' "
                                   "for a modules row filter; name='kernel'/"
                                   "'user' picks the view"})
            c = ctx.session.require_client(name)
            # kernel-lookup follows the pre-rename contract: 'list' with
            # kernel=True drives the system module path; the per-module
            # verbs route by the pid supplied.
            _kernel_lookup = bool(kernel) or (not pid)
            if action == "list":
                return await _mem_modules.handle_modules(
                    ctx, c, pid=pid, space=("kernel" if kernel else "user"),
                    kernel=kernel, name=name,
                    name_regex=name_regex, name_glob=name_glob,
                    path_contains=path_contains, compact=compact,
                    summary=summary, filter=filter, fields=fields,
                    limit=limit, offset=offset, max_results=max_results,
                    verify_signatures=verify_signatures,
                    force_recheck=force_recheck,
                )
            if action == "get":
                if not module:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "module_manage.get: module= is required"})
                return await _mem_modules.handle_modules(
                    ctx, c, pid=pid, space=("kernel" if kernel else "user"),
                    kernel=kernel, name=name,
                    name_regex="", name_glob="", path_contains="",
                    compact=False, summary=False,
                    filter={"name": module}, fields=fields,
                    limit=0, offset=0, max_results=1,
                    verify_signatures=verify_signatures,
                    force_recheck=force_recheck,
                )
            if action == "imports":
                return await _mem_probes.handle_imports(
                    ctx, c, pid=pid, module=module, name=name,
                    kernel_lookup=_kernel_lookup, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "exports":
                return await _mem_probes.handle_exports(
                    ctx, c, pid=pid, module=module, name=name,
                    kernel_lookup=_kernel_lookup, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "coherency":
                _mode = str(mode or "normal").lower() or "normal"
                try:
                    _base = int(base, 0) if isinstance(base, str) and base else int(base or 0)
                except (TypeError, ValueError):
                    _base = 0
                return await _mem_coherency.handle_coherency(
                    ctx, c, pid=pid, module=module,
                    module_base=_base, mode=_mode, name=name,
                    max_mismatch_ranges=max_mismatch_ranges or max_results,
                    include_mismatch_hex=bool(include_mismatch_hex),
                    fields=fields, filter=filter, summary=summary,
                    limit=limit, offset=offset,
                )
            return _unknown_action("module_manage", action,
                                   MODULE_ACTIONS, _MODULE_ACTION_HELP)

        return await _guard(ctx, "module_manage", action, args, run)
