"""Target tool registration — dispatcher for ``target_manage``.

R6 split the 2,700-line ``tools/target.py`` into this package. The
module shape here is unchanged from the historical ``target.py``
module (every ``from pry.mcp.tools.target import ...`` keeps
resolving): the dispatcher owns ``TARGET_ACTIONS``, the per-verb help
table, ``TargetArgs``, the ``AgentClient`` factory shim, and the
``register(mcp, ctx)`` entry FastMCP registers against.

Verb bodies moved verbatim into sibling modules
(``connect.py``/``status.py``/``driver.py``/``reboot.py``/``recover.py``/
``timeline.py``/``machines.py``/``peers.py``). The pre-register helpers
live in ``_runtime.py`` (boot-monitor + watchdog auto-arm hooks) and
``_plumbing.py`` (pure utilities, re-exported from here so tests that
import ``_resolve_port``/``_expand_cidr``/``_compact_connect_status``/
``_attach_machine_info`` from this module keep working).
"""

from __future__ import annotations

from ..common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from ....session import VIEW_KINDS
from ..context import Context
from ..follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)

from ._plumbing import (  # noqa: F401 — re-exported for tests
    _attach_machine_info,
    _auto_prepare,
    _compact_connect_status,
    _dedupe_watchdog_unconfigured,
    _expand_cidr,
    _resolve_port,
)
from ._runtime import (  # noqa: F401 — re-exported for compatibility
    _auto_arm_after_load,
    _auto_arm_cfg_status,
    _maybe_start_boot_monitor,
    _monitor_poll_s,
    _monitor_pull_minidump,
    _monitor_scan_idle_s,
    _park_minidump_notice,
)

from . import connect as _connect
from . import driver as _driver
from . import machines as _machines
from . import peers as _peers
from . import power as _power
from . import reboot as _reboot
from . import recover as _recover
from . import status as _status
from . import timeline as _timeline


# Late-bound AgentClient factory: tests monkey-patch
# ``pry.mcp.tools.AgentClient`` and expect that patch to reach the
# ``probe_client = AgentClient(...)`` inside ``wait_connectable`` below.
# The star-import above snapshotted ``AgentClient`` into this module's
# globals, so a direct bare reference would bypass the patch. Rebind
# ``AgentClient`` to a factory that resolves the class through the
# package namespace at call time.
def AgentClient(*args, **kwargs):  # noqa: N802 — deliberately shadows the class name
    import pry.mcp.tools as _pkg
    return _pkg.AgentClient(*args, **kwargs)


TARGET_ACTIONS = ["connect", "disconnect", "reconnect", "use",
                  "status", "targets",
                  "parity", "driver_load", "driver_unload",
                  "sysinfo", "host_info", "recent_ops",
                  "recent_ops_agent", "crash_state",
                  "wait_connectable", "wait_boot_change",
                  "whoami", "list_peers", "release_peer",
                  "subscribe_peers",
                  # discoverability
                  "actions", "tool_index",
                  # post-reboot choreography
                  "boot_recover",
                  # merged timeline view
                  # (boot identity + agent restarts + watchdog events +
                  #  recent ops + crash state + new minidumps)
                  "timeline",
                  # rediscover a machine's endpoint via
                  # parallel probe of configured/observed/alt_hosts +
                  # hostname resolution; swaps the live view on match.
                  "rediscover",
                  # PR#2 T1.1c: cold-start endpoint discovery that needs
                  # no connected session (phone-in before connect).
                  "wait_agent",
                  # reliable InitiateShutdownW reboot + wait-back.
                  # Each mode gets its own alias dispatching through the
                  # same handler so the gated verb surface reads as the
                  # mode name (``shutdown`` / ``poweroff`` / ``logoff``
                  # / ``reboot_abort``) without a mode= kwarg detour.
                  "reboot", "shutdown", "poweroff", "logoff",
                  "reboot_abort"]

_TARGET_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "target_manage(action='actions')"},
    "tool_index": {"one_liner": "global surface map — every registered "
                                "MCP tool + one-liner + verb count "
                                "(verbose=true adds verb lists)",
                   "key_args": "verbose",
                   "example": "target_manage(action='tool_index')"},
    "connect": {"one_liner": "connect a target view — machine= connects "
                             "lab2.kernel (views='both' adds .user). Follows "
                             "a machine across DHCP moves (fresh agent "
                             "beacons, then its hostname, then remembered "
                             "addresses) and refuses a host that answers as "
                             "a different computer; a failed connect lists "
                             "where each machine was last seen",
                "key_args": "machine|name ('<machine>.<kind>'), host, "
                            "port, token, views, force",
                "example": "target_manage(action='connect', "
                           "machine='lab2', views='both')"},
    "use": {"one_liner": "set this chat's current machine (focus) — "
                         "bare name= calls route there",
            "key_args": "machine ('lab2'|'lab2.user'|'none')",
            "example": "target_manage(action='use', machine='lab2')"},
    "disconnect": {"one_liner": "drop a view's client (refcount-aware)",
                   "key_args": "name",
                   "example": "target_manage(action='disconnect', "
                              "name='kernel')"},
    "reconnect": {"one_liner": "swap a wedged client for a fresh channel, "
                               "keeping co-owner refs (a view whose machine "
                               "moved to a new address is re-pointed "
                               "automatically — status() reports it as "
                               "endpoint_change)",
                  "key_args": "name",
                  "example": "target_manage(action='reconnect', "
                             "name='kernel')"},
    "status": {"one_liner": "session/client status for a view "
                              "(fast_fail=true: 1s TCP + 1s gRPC, "
                              "returns unreachable immediately — "
                              "wedge-vs-gone triage)",
               "key_args": "name, fast_fail",
               "example": "target_manage(action='status')"},
    "targets": {"one_liner": "list configured targets + live views",
                "key_args": "none",
                "example": "target_manage(action='targets')"},
    "parity": {"one_liner": "cross-check kernel vs user view byte-for-byte",
               "key_args": "pid, read_bytes, samples",
               "example": "target_manage(action='parity', pid=1234, "
                          "samples=16)"},
    "driver_load": {"one_liner": "load pry_driver.sys on the target "
                                 "(destructive, permission-gated)",
                    "key_args": "method",
                    "example": "target_manage(action='driver_load')"},
    "driver_unload": {"one_liner": "unload the driver (destructive, "
                                   "permission-gated)",
                      "key_args": "none",
                      "example": "target_manage(action='driver_unload')"},
    "sysinfo": {"one_liner": "OS/build/arch summary from the agent",
                "key_args": "name",
                "example": "target_manage(action='sysinfo')"},
    "host_info": {"one_liner": "host hardware/security-product inventory",
                  "key_args": "name, include_security_products, "
                              "include_hardware",
                  "example": "target_manage(action='host_info')"},
    "recent_ops": {"one_liner": "orchestrator op-log tail (audit trail)",
                   "key_args": "samples (row cap), persistent, "
                               "op_owner, since_iso",
                   "example": "target_manage(action='recent_ops')"},
    "recent_ops_agent": {"one_liner": "agent-side op log (post-crash "
                                      "forensics)",
                         "key_args": "name, samples (row cap)",
                         "example": "target_manage(action='recent_ops_agent')"},
    "crash_state": {"one_liner": "post-crash state snapshot — breadcrumb "
                                 "+ kernel log tail + newest minidump on "
                                 "new_boot",
                    "key_args": "name, include_dump",
                    "example": "target_manage(action='crash_state')"},
    "timeline": {"one_liner": "merged window: boot identity, agent "
                              "restarts, watchdog arms/fires, recent "
                              "ops tail, crash state, new minidumps",
                 "key_args": "name, since_iso, until_iso, "
                             "samples (row cap)",
                 "example": "target_manage(action='timeline', "
                            "since_iso='2026-10-23T00:00:00Z')"},
    "rediscover": {"one_liner": "re-probe a machine's endpoints "
                                "(configured + observed + alt_hosts + "
                                "hosts/cidr) in parallel; swaps the "
                                "live view on match",
                   "key_args": "machine, hosts, cidr, port, timeout_s",
                   "example": "target_manage(action='rediscover', "
                              "machine='lab2', cidr='10.0.0.0/24')"},
    "wait_agent": {"one_liner": "cold-start endpoint discovery — probes "
                                "hosts/cidr/mlabel candidates until one "
                                "answers Status; no connected view required",
                   "key_args": "hosts, cidr, mlabel, port, timeout_s, "
                               "interval_s, strict",
                   "example": "target_manage(action='wait_agent', "
                              "cidr='10.0.0.0/24', port=50074)"},
    "wait_connectable": {"one_liner": "block until a target answers gRPC "
                                      "(keep timeout_s <= 60 — the MCP "
                                      "host's own request deadline kills "
                                      "longer calls; loop instead)",
                         "key_args": "host, port, timeout_s",
                         "example": "target_manage(action='wait_connectable', "
                                    "host='10.0.0.5', timeout_s=60)"},
    "wait_boot_change": {"one_liner": "block until the view's boot identity "
                                      "changes (reboot / agent restart)",
                         "key_args": "name, timeout_s",
                         "example": "target_manage(action='wait_boot_change', "
                                    "timeout_s=120)"},
    "whoami": {"one_liner": "this client's id/owner record",
               "key_args": "none",
               "example": "target_manage(action='whoami')"},
    "list_peers": {"one_liner": "other agents/clients on this orchestrator",
                   "key_args": "none",
                   "example": "target_manage(action='list_peers')"},
    "boot_recover": {"one_liner": "post-reboot choreography in one call — "
                                  "verify/restore the view, sweep stale "
                                  "boot state, load the driver if it did "
                                  "not survive, re-arm watchdog.auto_arm, "
                                  "pull + parse the newest minidump",
                     "key_args": "name, load_driver, method, include_dump, "
                                 "host, port, token",
                     "example": "target_manage(action='boot_recover')"},
    "release_peer": {"one_liner": "release a stale peer's leases "
                                  "(destructive, gated)",
                     "key_args": "peer_id",
                     "example": "target_manage(action='release_peer', "
                                "peer_id='...')"},
    "subscribe_peers": {"one_liner": "peer join/leave feed snapshot",
                        "key_args": "none",
                        "example": "target_manage(action='subscribe_peers')"},
    "reboot": {"one_liner": "reliable Windows-API reboot via "
                            "InitiateShutdownW (gated by "
                            "security.allow_reboot); blocks until "
                            "the view's boot identity flips, then "
                            "runs boot_recover (reconnect + sweep + "
                            "driver_load + watchdog re-arm). Returns "
                            "a resume_token on MCP-deadline timeout",
               "key_args": "mode (reboot|shutdown|poweroff|logoff|"
                           "abort), delay_s, force, reason, wait, "
                           "recover, wait_timeout_s, resume_token",
               "example": "target_manage(action='reboot', force=true)"},
    "shutdown": {"one_liner": "like reboot but SHUTDOWN_NOREBOOT "
                              "(leaves power on)",
                 "key_args": "delay_s, force, reason, wait, recover, "
                             "wait_timeout_s, resume_token",
                 "example": "target_manage(action='shutdown', force=true)"},
    "poweroff": {"one_liner": "like reboot but SHUTDOWN_POWEROFF "
                              "(ACPI off)",
                 "key_args": "delay_s, force, reason, wait, recover, "
                             "wait_timeout_s, resume_token",
                 "example": "target_manage(action='poweroff', force=true)"},
    "logoff":   {"one_liner": "ExitWindowsEx(EWX_LOGOFF) — ends the "
                              "interactive user session",
                 "key_args": "force, reason",
                 "example": "target_manage(action='logoff', force=true)"},
    "reboot_abort": {"one_liner": "AbortSystemShutdownW — cancel a "
                                   "pending reboot/shutdown issued "
                                   "with delay_s>0",
                     "key_args": "none",
                     "example": "target_manage(action='reboot_abort')"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``target_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------ target_manage --

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def target_manage(action: Annotated[str, Field(json_schema_extra={"enum": TARGET_ACTIONS})],
                            name: str = "", machine: str = "",
                            views: str = "", host: str = "",
                            port: int = 0, token: str = "", method: str = "service",
                            pid: int = 0, samples: int = 16, read_bytes: int = 4096,
                            include_security_products: bool = False,
                            include_hardware: bool = True,
                            force: bool = False,
                            peer_id: str = "",
                            timeout_s: float = 15.0,
                            include_dump: bool = False,
                            load_driver: bool = True,
                            persistent: bool = False,
                            op_method: str = "",
                            op_owner: str = "",
                            since_iso: str = "",
                            until_iso: str = "",
                            focus: bool = True,
                            # T2.6 (PR#1): status fast-fail probe. True
                            # tightens TCP+gRPC deadlines to 1s each so a
                            # wedged view can be told apart from a gone
                            # one in sub-second. Default preserves the
                            # patient 3s probe + bounded backoff.
                            fast_fail: bool = False,
                            # PR#2 T1.1b/T1.1c: range-probe candidates.
                            # ``hosts`` is a plain host list, ``cidr`` an
                            # IPv4 range (capped at /20 = 4096 hosts).
                            # Used by rediscover / wait_connectable /
                            # reconnect / wait_agent.
                            hosts: list[str] | None = None,
                            cidr: str = "",
                            # PR#2 T1.1c: wait_agent-only — the machine
                            # alias to probe when the caller has no
                            # connected view yet.
                            mlabel: str = "",
                            # PR#2 T1.1c: wait_agent-only — require
                            # driver_state=='loaded' before resolving.
                            strict: bool = False,
                            # PR#2 T1.1c: wait_agent poll cadence.
                            interval_s: float = 1.0,
                            # PR#2 T2.1: compact-by-default connect
                            # response. verbose=True returns the exact
                            # pre-T2.1 dict byte-for-byte.
                            verbose: bool = False,
                            # PR#2 T2.7: one-call connect choreography —
                            # after a successful connect run use + a
                            # driver_load when the driver isn't up.
                            auto_prepare: bool = False,
                            # target_manage.reboot kwargs.
                            # mode: canonical mode (``action=`` carries
                            #       the alias for the mode-named verbs
                            #       so the default REBOOT survives).
                            # reason: free text mirrored into the event
                            #       log by the agent.
                            # wait: block until the view's boot identity
                            #       flips (default True).
                            # recover: on flip, also run the boot_recover
                            #       choreography (default True).
                            # wait_timeout_s: hard caller deadline for
                            #       the wait loop; the handler always
                            #       stays under the MCP host's 60s cap.
                            # resume_token: resume the wait loop after
                            #       an MCP-deadline timeout without a
                            #       fresh RPC.
                            mode: str = "",
                            delay_s: int = 0,
                            reason: str = "",
                            wait: bool = True,
                            recover: bool = True,
                            wait_timeout_s: float = 0.0,
                            resume_token: str = "") -> str:
        """All views are '<machine>.<view>'; 'use' sets your per-chat current machine.
        Connect/disconnect target views (kernel agent + usermode umagent), status,
        driver load/unload, and kernel-vs-usermode memory parity runs.
        boot_recover runs the whole post-reboot choreography (connect +
        sweep + driver_load + watchdog auto-arm + minidump pull) in one
        call. First use: target_manage(action='tool_index') maps every
        tool; wait_connectable keeps timeout_s <= 60 (MCP host deadline
        kills longer calls — loop instead)."""
        args = {"action": action, "name": name, "machine": machine,
                "host": host, "port": port, "method": method,
                # target_manage.reboot — forward to the actuator-
                # trust gate so a force=true override on an untrusted
                # machine reaches _check_actuator_trust. Legacy verbs
                # (driver_load, driver_unload, boot_recover,
                # release_peer) accept force too and the guard
                # already looked it up via (args or {}).get("force")
                # on earlier callers; promoting it to the stamped dict
                # makes the behavior explicit here.
                "force": bool(force)}

        async def run() -> str:
            # pure-compute discovery verbs — before any session or
            # client work so they answer even with nothing connected.
            if action == "actions":
                return await _status.do_actions(ctx)
            if action == "tool_index":
                return await _status.do_tool_index(ctx, mcp,
                                                   verbose=bool(verbose))
            if action == "use":
                return await _connect.do_use(ctx, machine=machine, name=name)
            if action == "connect":
                return await _connect.do_connect(
                    ctx, machine=machine, name=name, views=views,
                    host=host, port=port, token=token, method=method,
                    force=force, focus=focus, verbose=verbose,
                    auto_prepare=auto_prepare)
            if action == "disconnect":
                return await _connect.do_disconnect(ctx, name=name)
            if action == "reconnect":
                return await _connect.do_reconnect(
                    ctx, name=name, host=host, port=port, token=token,
                    hosts=hosts, cidr=cidr)
            if action == "targets":
                return await _status.do_targets(ctx)
            if action == "status":
                return await _status.do_status(
                    ctx, name=name, fast_fail=fast_fail, verbose=verbose)
            if action == "driver_load":
                return await _driver.do_driver_load(
                    ctx, name=name, method=method, verbose=verbose)
            if action == "driver_unload":
                return await _driver.do_driver_unload(
                    ctx, name=name, force=force)
            if action == "sysinfo":
                return await _status.do_sysinfo(ctx, name=name)
            if action == "host_info":
                return await _status.do_host_info(
                    ctx, name=name,
                    include_security_products=include_security_products,
                    include_hardware=include_hardware)
            if action == "parity":
                return await _status.do_parity(
                    ctx, name=name, pid=pid,
                    samples=samples, read_bytes=read_bytes)
            if action == "recent_ops":
                return await _timeline.do_recent_ops(
                    ctx, name=name, samples=samples,
                    persistent=persistent, op_method=op_method,
                    op_owner=op_owner, since_iso=since_iso,
                    until_iso=until_iso)
            if action == "recent_ops_agent":
                return await _timeline.do_recent_ops_agent(
                    ctx, name=name, samples=samples)
            if action == "crash_state":
                return await _recover.do_crash_state(
                    ctx, name=name, samples=samples,
                    read_bytes=read_bytes, include_dump=include_dump)
            if action == "timeline":
                return await _timeline.do_timeline(
                    ctx, name=name, since_iso=since_iso,
                    until_iso=until_iso, samples=samples)
            if action == "rediscover":
                return await _recover.do_rediscover(
                    ctx, machine=machine, name=name, port=port,
                    hosts=hosts, cidr=cidr, timeout_s=timeout_s)
            if action == "boot_recover":
                return await _recover.do_boot_recover(
                    ctx, name=name, host=host, port=port, token=token,
                    load_driver=load_driver, method=method,
                    include_dump=include_dump)
            if action == "wait_connectable":
                return await _reboot.do_wait_connectable(
                    ctx, name=name, host=host, port=port, token=token,
                    timeout_s=timeout_s, hosts=hosts, cidr=cidr)
            if action == "wait_agent":
                return await _reboot.do_wait_agent(
                    ctx, hosts=hosts, cidr=cidr, mlabel=mlabel,
                    machine=machine, port=port, token=token,
                    timeout_s=timeout_s, interval_s=interval_s,
                    strict=strict)
            if action == "wait_boot_change":
                return await _reboot.do_wait_boot_change(
                    ctx, name=name, timeout_s=timeout_s)
            if action == "whoami":
                return await _peers.do_whoami(ctx)
            if action == "list_peers":
                return await _peers.do_list_peers(ctx)
            if action == "release_peer":
                return await _peers.do_release_peer(
                    ctx, peer_id=peer_id, force=force)
            if action == "subscribe_peers":
                return await _peers.do_subscribe_peers(ctx)
            # one dispatcher body, five aliases. power.do_reboot
            # canonicalizes mode= from both the kwarg and the action name.
            if action in ("reboot", "shutdown", "poweroff", "logoff",
                           "reboot_abort"):
                return await _power.do_reboot(
                    ctx, action=action, name=name, mode=mode,
                    delay_s=delay_s, force=force, reason=reason,
                    wait=wait, recover=recover,
                    wait_timeout_s=wait_timeout_s,
                    resume_token=resume_token)
            return _unknown_action("target_manage", action, TARGET_ACTIONS, _TARGET_ACTION_HELP)

        return await _guard(ctx, "target_manage", action, args, run)
