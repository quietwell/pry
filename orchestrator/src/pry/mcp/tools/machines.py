"""``machines_manage`` — machine registry CRUD (register/set/unregister/
list/prune). Split out of ``target_manage`` for taxonomy cleanup; the
underlying handlers still live under the ``target`` package and are
reused unchanged.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)
from .context import Context
from .target import machines as _tgt_machines


MACHINES_ACTIONS = ["register", "set", "unregister", "list",
                    "prune", "actions"]


_MACHINES_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "machines_manage(action='actions')"},
    "register": {"one_liner": "persist a machine (host/ports/token "
                              "+ purpose/note/trust/tags) in the "
                              "registry — usable immediately, no "
                              "restart",
                 "key_args": "machine, host, port, user_port, "
                             "token, trust, purpose, note, tags",
                 "example": "machines_manage(action='register', "
                            "machine='lab3', host='10.0.2.20', "
                            "port=50074, token='${LAB3_TOKEN}', "
                            "trust='lab', purpose='delta rig')"},
    "set": {"one_liner": "update machine metadata/endpoints in the "
                         "registry (YAML aliases: metadata only "
                         "unless force=true)",
            "key_args": "machine, purpose, note, trust, tags, "
                        "host, port, token, force",
            "example": "machines_manage(action='set', "
                       "machine='lab3', trust='lab', "
                       "note='testsigning on')"},
    "unregister": {"one_liner": "remove a machine from the registry",
                   "key_args": "machine, force",
                   "example": "machines_manage(action='unregister', "
                              "machine='lab3')"},
    "list": {"one_liner": "one call, when wanted: every machine with "
                          "trust/purpose/note/tags/endpoints + "
                          "connection state",
             "key_args": "none",
             "example": "machines_manage(action='list')"},
    "prune": {"one_liner": "drop alias-only registry shells "
                           "(no trust/host/purpose/note/tags/"
                           "operator/token, not currently "
                           "connected) that passive probes "
                           "left behind; YAML/shadow entries "
                           "are never touched",
              "key_args": "dry_run",
              "example": "machines_manage(action='prune', "
                         "dry_run=True)"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``machines_manage`` tool on *mcp*, using *ctx* for state."""

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def machines_manage(action: Annotated[str, Field(
                                  json_schema_extra={"enum": MACHINES_ACTIONS})],
                              machine: str = "",
                              host: str = "",
                              port: int = 0,
                              user_port: int = 0,
                              token: str = "",
                              trust: str = "",
                              purpose: str = "",
                              note: str = "",
                              operator: str = "",
                              tags: str = "",
                              computer_name: str = "",
                              alt_hosts: list[str] | None = None,
                              force: bool = False,
                              dry_run: bool = False,
                              name: str = "") -> str:
        """Machine registry CRUD: register / set / unregister / list the
        machines kept in artifacts/targets.json (hot-reloaded, no restart)
        and prune alias-only entries passive probes left behind. trust=
        gates actuator verbs via security.min_trust_actuator. Per-verb help:
        machines_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "machine": machine, "name": name,
                "host": host, "port": port}

        async def run() -> str:
            if action == "actions":
                return _actions_help("machines_manage", _MACHINES_ACTION_HELP)
            if action == "prune":
                return await _tgt_machines.do_machines_prune(
                    ctx, dry_run=dry_run)
            if action in ("register", "set", "unregister", "list"):
                # The underlying handler still dispatches on the legacy
                # ``target_manage`` action names: ``machines_<verb>`` for
                # the mutators, plain ``machines`` for the full listing
                # (``machines_list`` would fall through to the per-alias
                # path and demand machine=).
                legacy = "machines" if action == "list" else f"machines_{action}"
                return await _tgt_machines.do_machines_cmd(
                    ctx, action=legacy,
                    name=name, machine=machine,
                    host=host, port=port, user_port=user_port, token=token,
                    trust=trust, purpose=purpose, note=note,
                    operator=operator, tags=tags,
                    computer_name=computer_name,
                    alt_hosts=alt_hosts,
                    force=force)
            return _unknown_action("machines_manage", action,
                                   MACHINES_ACTIONS, _MACHINES_ACTION_HELP)

        return await _guard(ctx, "machines_manage", action, args, run,
                            kind="machines")
