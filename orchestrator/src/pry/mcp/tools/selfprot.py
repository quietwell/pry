"""``selfprot_manage`` — SI #21 driver self-protection toggle (install/
refresh/disable the ObRegisterCallbacks handle-rights stripper) and
its read-only status counters. Split out of ``target_manage`` for
taxonomy cleanup; the underlying handlers still live under the
``target`` package and are reused unchanged.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)
from .context import Context
from .target import driver as _tgt_driver


SELFPROT_ACTIONS = ["config", "status", "actions"]


_SELFPROT_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "selfprot_manage(action='actions')"},
    "config": {"one_liner": "SI #21 — install/refresh/disable the "
                            "driver's ObRegisterCallbacks handle-rights "
                            "stripper for a PID list; enable=0/1/2",
               "key_args": "name, enable, flags, process_access_keep, "
                           "thread_access_keep, protected_pids, "
                           "disable_token",
               "example": "selfprot_manage(action='config', enable=1, "
                          "protected_pids=[1234])"},
    "status": {"one_liner": "SI #21 — read-only counters + whether the "
                            "altitude install took",
               "key_args": "name",
               "example": "selfprot_manage(action='status')"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``selfprot_manage`` tool on *mcp*, using *ctx* for state."""

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def selfprot_manage(action: Annotated[str, Field(
                                  json_schema_extra={"enum": SELFPROT_ACTIONS})],
                              name: str = "",
                              enable: int = 0,
                              flags: int = 0,
                              process_access_keep: int = 0,
                              thread_access_keep: int = 0,
                              protected_pids: list[int] | None = None,
                              disable_token: int = 0) -> str:
        """Driver self-protection via ObRegisterCallbacks: ``config``
        installs / refreshes / disables (enable=0/1/2) the handle-rights
        stripper for a PID list; ``status`` reads back the counters and
        whether the altitude install took. Per-verb help:
        selfprot_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "name": name, "enable": enable}

        async def run() -> str:
            if action == "actions":
                return _actions_help("selfprot_manage", _SELFPROT_ACTION_HELP)
            if action == "config":
                return await _tgt_driver.do_selfprot_config(
                    ctx, name=name, enable=enable, flags=flags,
                    process_access_keep=process_access_keep,
                    thread_access_keep=thread_access_keep,
                    protected_pids=protected_pids,
                    disable_token=disable_token)
            if action == "status":
                return await _tgt_driver.do_selfprot_status(ctx, name=name)
            return _unknown_action("selfprot_manage", action,
                                   SELFPROT_ACTIONS, _SELFPROT_ACTION_HELP)

        return await _guard(ctx, "selfprot_manage", action, args, run)
