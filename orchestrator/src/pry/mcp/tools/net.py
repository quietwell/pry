"""Network tool registration for the pry MCP server.

``net_manage`` — IPHLPAPI snapshot + reverse-DNS LRU + service-tag
resolver, plus a ``SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)`` kill verb.
Umagent-only: the SI netlist.c surface is a pure IPHLPAPI call, and
``SetTcpEntry`` is a user-mode API. The ``.kernel`` suffix on
``name=`` is rejected with ``kind='bad_arg'`` before any gRPC fires.

``kill`` is an ACTUATOR: double-gated by
``security.allow_kill_connection`` (default false) + the standard
``_check_actuator_trust`` path via the capability registry.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .._coverage import coverage as _coverage


NET_ACTIONS = ["list", "interfaces", "stats", "kill", "actions"]


_NET_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "net_manage(action='actions')"},
    "list": {
        "one_liner": ("TCP+UDP (v4+v6) snapshot — PID / process / "
                      "service-tag / owning-module decorated; umagent "
                      "view only"),
        "key_args": ("families, protos, states, pid, include_loopback, "
                     "resolve_hostnames, include_services, limit"),
        "example": ("net_manage(action='list', protos=['tcp'], "
                    "states=['ESTABLISHED'], limit=64)"),
    },
    "interfaces": {
        "one_liner": "GetAdaptersAddresses projection",
        "key_args": "include_down",
        "example": "net_manage(action='interfaces')",
    },
    "stats": {
        "one_liner": "netstat -s equivalent per-protocol counters",
        "key_args": "families, protos",
        "example": "net_manage(action='stats', protos=['tcp'])",
    },
    "kill": {
        "one_liner": ("SetTcpEntry(MIB_TCP_STATE_DELETE_TCB) — ACTUATOR, "
                      "gated by security.allow_kill_connection"),
        "key_args": "local, remote, state_hint",
        "example": ("net_manage(action='kill', "
                    "local='10.0.0.5:49231', remote='93.184.216.34:443')"),
    },
}


# States that _apply_rows uses for simple server-side filtering before
# the envelope's filter engine runs. Any TCP state the agent returns is
# a plain string; this is just a case-folded containment set.
_TCP_STATE_NAMES = {
    "CLOSED", "LISTENING", "LISTEN", "SYN_SENT", "SYN_RCVD",
    "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT",
    "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB",
}


def _is_kernel_name(name: str) -> bool:
    """``.kernel`` suffix on ``name=`` means "pin to the driver view".
    net_manage is umagent-only — reject explicit kernel pins with a
    clear hint."""
    n = (name or "").strip().lower()
    return n.endswith(".kernel") or n == "kernel"


def _list_row(r: dict, *, verbosity: str) -> dict:
    """Project one gRPC row into the per-verbosity shape.

    compact : proto, family, pid, process, state, local, remote,
              service_tag, remote_host
    normal  : + create_time_ms, owning_module_names, offload
    full    : + scope_id_local, scope_id_remote
    """
    base = {
        "proto": r.get("proto", ""),
        "family": r.get("family", ""),
        "pid": int(r.get("pid", 0) or 0),
        "process": r.get("process", ""),
        "state": r.get("state", ""),
        "local": r.get("local", ""),
        "remote": r.get("remote", ""),
        "service_tag": r.get("service_tag", ""),
        "remote_host": r.get("remote_host", ""),
    }
    if verbosity == "compact":
        return base
    base["create_time_ms"] = int(r.get("create_time_ms", 0) or 0)
    base["offload"] = r.get("offload", "")
    base["owning_module_names"] = list(r.get("owning_module_names") or [])
    if verbosity == "normal":
        return base
    # full
    base["scope_id_local"] = int(r.get("scope_id_local", 0) or 0)
    base["scope_id_remote"] = int(r.get("scope_id_remote", 0) or 0)
    return base


def register(mcp, ctx: Context) -> None:
    """Register the ``net_manage`` tool on *mcp*, using *ctx* for state."""

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def net_manage(action: Annotated[str, Field(
                              json_schema_extra={"enum": NET_ACTIONS})],
                         families: list[str] | None = None,
                         protos: list[str] | None = None,
                         states: list[str] | None = None,
                         pid: int = 0,
                         include_loopback: bool = False,
                         include_services: bool = True,
                         resolve_hostnames: bool = False,
                         module_resolve: bool = False,
                         local: str = "",
                         remote: str = "",
                         state_hint: str = "ESTABLISHED",
                         include_down: bool = False,
                         limit: int = 64,
                         offset: int = 0,
                         cursor: str = "",
                         fields: list[str] | None = None,
                         filter: str = "",
                         summary: bool = False,
                         verbosity: str = "normal",
                         name: str = "") -> str:
        """Network inventory + actuator. ``list`` returns TCP+UDP (v4+v6)
        snapshot rows with PID / process / service-tag / optional
        reverse-DNS decoration. ``kill`` tears down a TCP flow via
        SetTcpEntry — gated by security.allow_kill_connection. The whole
        tool is umagent-only; a ``.kernel`` ``name=`` suffix is rejected.
        Per-verb help: ``net_manage(action='actions')``."""
        args = {"action": action, "name": name, "pid": pid,
                "local": local, "remote": remote}

        async def run() -> Any:
            if action not in NET_ACTIONS:
                return _unknown_action("net_manage", action,
                                        NET_ACTIONS, _NET_ACTION_HELP)
            if action == "actions":
                return _actions_help("net_manage", _NET_ACTION_HELP)
            # .user-only enforcement. Explicit .kernel pin fails fast
            # with a clear hint; an empty name resolves to the focus
            # machine's default view below.
            if _is_kernel_name(name):
                return _j({
                    "ok": False, "kind": "bad_arg",
                    "error": ("net_manage is umagent-only — IPHLPAPI + "
                              "SetTcpEntry are user-mode APIs"),
                    "hint": ("drop the '.kernel' suffix on name= (or "
                             "pass name='<machine>.user'); "
                             "target_manage(action='connect', "
                             "name='<machine>.user') if the view is not "
                             "yet connected"),
                })
            # Resolve the view; if it still ends in .kernel after
            # focus resolution (defaulted machine with no .user), we
            # want the same error rather than a surprise agent call.
            try:
                resolved = ctx.session.resolve_view_name(name)
            except Exception:
                resolved = name
            if _is_kernel_name(resolved):
                return _j({
                    "ok": False, "kind": "no_target",
                    "error": ("net_manage: no .user view connected on "
                              f"machine {resolved!r} — this surface is "
                              "umagent-only"),
                    "hint": ("connect umagent via "
                             "target_manage(action='connect', "
                             f"name='{resolved.rsplit('.', 1)[0]}.user')"),
                })
            c = ctx.session.require_client(name)

            if action == "list":
                if limit == 0:
                    return _j({
                        "ok": False, "kind": "bad_arg",
                        "error": "list: limit=0 is refused — pass a "
                                 "positive cap or omit the arg to get "
                                 "the default 64",
                    })
                res = await c.net_list(
                    families=families, protos=protos, states=states,
                    pid=int(pid or 0),
                    include_loopback=bool(include_loopback),
                    module_resolve=bool(module_resolve),
                    include_services=bool(include_services),
                    resolve_hostnames=bool(resolve_hostnames),
                    limit=int(limit or 64),
                )
                if not res.get("ok"):
                    return _j(res)
                verb = verbosity if verbosity in ("compact", "normal", "full") \
                       else "normal"
                items = [_list_row(r, verbosity=verb)
                          for r in res.get("items", [])]
                env = _list_envelope(
                    items, tool="net_manage", action="list",
                    limit=limit, offset=offset, cursor=cursor,
                    fields=fields or (), filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={
                        "truncated_agent": bool(res.get("truncated")),
                        "dns_cache_hits": int(res.get("dns_cache_hits", 0)),
                        "dns_cache_misses": int(res.get("dns_cache_misses", 0)),
                        "dns_cache_size": int(res.get("dns_cache_size", 0)),
                    },
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return env

            if action == "interfaces":
                res = await c.net_interfaces(include_down=bool(include_down))
                if not res.get("ok"):
                    return _j(res)
                env = _list_envelope(
                    res.get("items", []),
                    tool="net_manage", action="interfaces",
                    limit=limit, offset=offset, cursor=cursor,
                    fields=fields or (), filter=filter, summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return env

            if action == "stats":
                res = await c.net_stats(families=families, protos=protos)
                if not res.get("ok"):
                    return _j(res)
                env = _list_envelope(
                    res.get("counters", []),
                    tool="net_manage", action="stats",
                    limit=0, offset=0, cursor="",
                    fields=fields or (), filter=filter, summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return env

            if action == "kill":
                # Orchestrator-side primary gate. _check_actuator_trust
                # (fired by _guard before run() resolves) covers the
                # machine-trust leg; this flag is the "do you even want
                # this surface" switch.
                if not getattr(ctx.cfg.security, "allow_kill_connection",
                                False):
                    return _j({
                        "ok": False, "kind": "not_allowed",
                        "error": ("kill: disabled by "
                                  "security.allow_kill_connection"),
                        "hint": ("enable the flag only after confirming "
                                 "the target VM is one you may disrupt; "
                                 "SetTcpEntry(DELETE_TCB) is irreversible"),
                    })
                if not local or not remote:
                    return _j({
                        "ok": False, "kind": "bad_arg",
                        "error": ("kill: local= and remote= are required "
                                  "('ip:port' each)"),
                        "hint": ("net_manage(action='kill', "
                                 "local='10.0.0.5:49231', "
                                 "remote='93.184.216.34:443')"),
                    })
                res = await c.net_kill(local=local, remote=remote,
                                        state_hint=state_hint)
                return _j({
                    "ok": bool(res.get("ok")),
                    "kind": ("kill_failed" if not res.get("ok") else None),
                    "error": res.get("error", "") or "",
                    "killed": bool(res.get("killed", False)),
                    "local": local, "remote": remote,
                })

            return _unknown_action("net_manage", action,
                                    NET_ACTIONS, _NET_ACTION_HELP)

        return await _guard(ctx, "net_manage", action, args, run)
