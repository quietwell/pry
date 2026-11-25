"""Session constructor + plumbing — composes the per-concern mixins.

``Session`` is the orchestrator-side primary state for named target
clients grouped by machine. This module owns the constructor,
``check_target`` authorization bridge, the ToolCall audit sink, the
config-driven ``assert_allowed`` policy gate, and the observed-endpoint
hook. Everything else (connect/disconnect, machines, focus, boot
monitor, views) lives on the mixins in sibling modules and is composed
into ``Session`` the same way :class:`findings.ledger.FindingsLedger`
composes its concern mixins over ``LedgerCore``.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from ..agent_client import AgentClient
from ..allowlist import check_authorized, check_authorized_async
from ..audit import AuditWriter
from ..config import PRIMARY_TARGET, PryConfig
from ._models import DESTRUCTIVE_ACTIONS, ToolCall
from .boot_monitor import SessionBootMonitorMixin
from .connect import SessionConnectMixin
from .endpoint_heal import SessionEndpointHealMixin
from .focus import SessionFocusMixin
from .machines import SessionMachinesMixin
from .views import SessionViewsMixin


class Session(SessionConnectMixin, SessionBootMonitorMixin,
              SessionMachinesMixin, SessionFocusMixin,
              SessionViewsMixin, SessionEndpointHealMixin):
    """Session state: named target clients per session, grouped by machine.

    View keys are ``'<machine>.<kind>'`` — e.g. ``lab2.kernel`` or
    ``DESKTOP-ABC.user``. The machine label comes from (in priority order) the
    ``machine=`` connect arg, a config ``machines:`` alias matching the
    endpoint, the target's own ``computer_name`` (HostInfo), or the host
    address. ``computer_name`` is also stored per view and resolves as an
    alias, so a machine stays identifiable when its IP changes.

    Per-client ``focus`` (``target_manage(action='use', machine='lab2')``)
    fills in the ``name=`` selector when a tool call leaves it empty — each
    MCP client has its own focus, so concurrent chats can sit on different
    machines without fighting over a global default. With more than one
    machine connected, an unfocused empty selector raises
    :class:`.AmbiguousTargetError` instead of silently hitting whichever box
    happened to be primary.

    The primary client (the first connected machine's kernel view) keeps the
    historical single-target semantics: session.client / session.connected
    refer to it.
    """

    def __init__(self, cfg: PryConfig) -> None:
        self.cfg = cfg
        self.clients: dict[str, AgentClient] = {}
        # Per-name primary owner (first connector, or the caller that forced
        # a takeover) and per-name refcounts by owner id. A named entry is
        # torn down only when every owner has released it (refs empties).
        self.owners: dict[str, str] = {}
        self.refs: dict[str, dict[str, int]] = {}
        self.primary = PRIMARY_TARGET
        # view key -> {"machine", "computer_name", "endpoint"}. Written at
        # connect after the HostInfo round-trip; kept after disconnect so
        # `targets` can still name the boxes it lists as not_connected.
        self._machine_info: dict[str, dict[str, Any]] = {}
        # client_id -> {"machine", "kind"} set by target_manage(action='use').
        # Per-caller "current machine" — fills empty/bare `name=` selectors
        # so a chat's calls land on its own box, never a global default.
        self._focus: dict[str, dict[str, str]] = {}
        self.tool_log: list[ToolCall] = []
        # persistent audit sink. Deterministic per orchestrator
        # boot (PID + start epoch) so concurrent instances on the same host
        # don't clobber each other's roll files. The writer resolves the
        # base via `audit.default_base()` — which honors
        # `PRY_AUDIT_BASE_DIR` — so tests can point both write and query
        # paths at a tmp_path with a single env var.
        self._audit_session_id = f"orch-{os.getpid()}-{int(time.time())}"
        self._audit = AuditWriter(session_id=self._audit_session_id)
        # v14: last-seen boot identity per view — (boot_epoch_ms,
        # agent_instance_id) from the newest StatusResponse. A changed boot
        # epoch means the target rebooted (driver state, shells, follows,
        # watchdogs, detached handles all orphaned); a changed instance id
        # on the same boot means the agent process restarted.
        self._boot_ids: dict[str, dict[str, Any]] = {}
        # boot monitor. A per-view background task polls status()
        # and feeds every reply through note_boot_identity, making
        # reboot/agent-restart detection timely instead of lazy. The
        # change record the monitor produced is parked in
        # pending_boot_notices so the next status()/wait_boot_change call
        # still surfaces it to the caller (drain-and-clear).
        self.pending_boot_notices: dict[str, dict[str, Any]] = {}
        self._boot_monitors: dict[str, asyncio.Task] = {}
        # Minidump dir-watch seen-set per view — names already reported
        # (or seeded on first scan) so each new .dmp notifies once.
        self._dump_seen: dict[str, set[str]] = {}
        # last host that actually connected, per machine label —
        # retried first when the configured endpoint fails the pre-flight
        # probe (NIC lease flap, DHCP change).
        self._last_good_host: dict[str, str] = {}
        # optional callback that returns observed-endpoint
        # host strings for a machine label (newest-first), used to extend
        # the connect candidate list beyond the configured + last-good +
        # alt_hosts set. Context installs this with
        # ``set_observed_endpoint_source(lambda label: [...])``.
        self._observed_endpoint_source = None
        # DHCP self-heal (endpoint_heal.py). The registry provider is a
        # zero-arg callable (None until the lazy registry is loaded) that
        # feeds fresh phone-home beacons, learned identities and the
        # connect-failure overview. The heal hook runs after a view was
        # re-pointed to a new endpoint; the notices are drained by status().
        self._registry_provider = None
        self._link_heal_hook = None
        self._link_watchers: dict[str, asyncio.Task] = {}
        self.pending_endpoint_notices: dict[str, dict[str, Any]] = {}
        # view kind -> machine label learned by the last *bare* connect (no
        # machine=, no host=): when the legacy configured endpoint goes
        # stale, the next bare connect follows that machine's beacons.
        self._legacy_label: dict[str, str] = {}

    def set_observed_endpoint_source(self, fn) -> None:
        """Register a ``(machine_label) -> list[host|host:port]`` callable
        used by :meth:`connect` to probe registry-observed endpoints as
        additional candidates. ``fn=None`` clears the hook."""
        self._observed_endpoint_source = fn

    def _observed_hosts_for(self, label: str) -> list[str]:
        fn = self._observed_endpoint_source
        if fn is None:
            # No explicit hook (the Context installs one only once the lazy
            # registry has been touched): read straight from the registry
            # provider so a connect right after a restart still sees the
            # observed endpoints.
            reg = self._reg()
            if reg is not None:
                def fn(lbl, _reg=reg):  # noqa: E731 — local adapter
                    rows = _reg.observed_endpoints(lbl)
                    if not rows:
                        alias = _reg.find_alias_by_computer_name(lbl)
                        rows = _reg.observed_endpoints(alias) if alias else []
                    return [str(o.get("host")) for o in rows if o.get("host")]
        if fn is None or not label:
            return []
        try:
            vals = list(fn(label) or [])
        except Exception:  # noqa: BLE001 — observed-endpoint lookups are best-effort
            return []
        out: list[str] = []
        for v in vals:
            if not v:
                continue
            s = str(v)
            if ":" in s:
                s = s.rsplit(":", 1)[0]
            if s and s not in out:
                out.append(s)
        return out

    def audit_session_id(self) -> str:
        """The audit sink's session_id (used by target_manage
        recent_ops(persistent=True) so the query targets the current
        orchestrator's own JSONL tree)."""
        return self._audit_session_id

    @property
    def client(self) -> AgentClient | None:
        return self.clients.get(self.primary)

    @property
    def connected(self) -> bool:
        return bool(self.clients)

    def check_target(self, host: str | None = None) -> str:
        """Allowlist gate; returns the checked IP literal to dial. Blocks
        only for host NAMES (resolution) — async paths use
        :meth:`check_target_async`."""
        host = host or self.cfg.target.host
        return check_authorized(host, self.cfg.security.authorized_targets)

    async def check_target_async(self, host: str | None = None) -> str:
        """:meth:`check_target` with name resolution off the event loop."""
        host = host or self.cfg.target.host
        return await check_authorized_async(
            host, self.cfg.security.authorized_targets)

    def _apply_client_policy(self, client: Any) -> None:
        """Config-driven policy carried by every stored AgentClient:
        the driver soft-fault switch."""
        try:
            client.allow_softfault = bool(getattr(
                self.cfg.security, "allow_kernel_softfault", False))
        except Exception:  # noqa: BLE001 — duck-typed / slotted test clients
            pass

    def audit_event(self, record: dict[str, Any]) -> None:
        """Append a non-tool-call row (dashboard writes, in-flight markers)
        to the persistent audit sink. Never raises."""
        try:
            row = {"ts": time.time(), **record}
            self._audit.write(row)
        except Exception:  # noqa: BLE001 — audit must never mask the caller
            pass

    def record_tool_call(self, tool: str, action: str, args: dict[str, Any] | None = None,
                         ok: bool = True, error: str = "",
                         extra: dict[str, Any] | None = None) -> ToolCall:
        call = ToolCall(
            tool=tool,
            action=action,
            destructive=(tool, action) in DESTRUCTIVE_ACTIONS,
            args=args or {},
            ok=ok,
            error=error,
        )
        self.tool_log.append(call)
        if len(self.tool_log) > 2000:
            del self.tool_log[: len(self.tool_log) - 2000]
        # mirror to the persistent JSONL sink so the ring's
        # 2000-row cap + orchestrator-restart wipe doesn't lose forensic
        # history. The writer swallows I/O errors internally so a bad
        # disk never masks the tool call itself.
        try:
            self._audit.write({
                "ts": call.ts,
                "tool": tool,
                "action": action,
                "destructive": call.destructive,
                "args": call.args,
                "ok": ok,
                "error": error,
                # `_current_owner` is threaded in by tools that know their
                # client_id (bp_manage / exec_manage / watchdog_manage);
                # absent for older call sites, which show up as
                # `owner: null` on the audit query.
                "owner": (args or {}).get("_current_owner"),
                **(extra or {}),
            })
        except Exception:  # noqa: BLE001 — audit must never mask the call
            pass
        return call

    def assert_allowed(self, tool: str, action: str, args: dict[str, Any] | None = None) -> None:
        args = args or {}
        if tool == "target_manage" and action == "driver_load" and not self.cfg.security.allow_driver_load:
            raise PermissionError("driver_load disabled by config")
        if tool == "target_manage" and action == "driver_unload" and not self.cfg.security.allow_driver_unload:
            raise PermissionError("driver_unload disabled by config")
        if tool == "file_manage" and action == "delete":
            if self.cfg.security.allow_delete:
                return
            if not args.get("no_trash"):
                # trash-safe delete stays available with allow_delete=false
                return
            raise PermissionError(
                "allow_delete=false: hard delete (no_trash) refused; trash-safe delete still available"
            )
        # Part 3: evidence_prune is the only destructive knowledge_manage
        # action — gated behind the same allow_delete switch.
        if tool == "knowledge_manage" and action == "evidence_prune" \
                and not self.cfg.security.allow_delete:
            raise PermissionError(
                "allow_delete=false: evidence_prune refused; set "
                "security.allow_delete=true to enable evidence deletion"
            )
        # live kernel dump gated behind an
        # explicit opt-in because SysDbgGetLiveKernelDump can write
        # multi-GB files, pins the paged pool during the capture, and is
        # a real actuator against the kernel. Default-off matches
        # allow_delete / allow_driver_unload semantics.
        if tool == "dump_manage" and action == "create_kernel_dump" \
                and not getattr(self.cfg.security, "allow_live_kernel_dump", False):
            raise PermissionError(
                "allow_live_kernel_dump=false: dump_manage(action="
                "'create_kernel_dump') refused; set "
                "security.allow_live_kernel_dump=true to enable "
                "NtSystemDebugControl(SysDbgGetLiveKernelDump)"
            )
        # Reserved — P2 fills the handlers.
        if tool == "token_manage" and action in (
            "enable_privilege", "disable_privilege", "remove_privilege",
            "set_integrity_level", "set_virtualization", "impersonate",
            "modify_default_dacl",
        ) and not getattr(self.cfg.security, "allow_token_adjust", False):
            raise PermissionError(
                f"allow_token_adjust=false: token_manage(action={action!r})"
                " refused; set security.allow_token_adjust=true to enable"
                " token adjustments"
            )
        # Reserved — P3 fills the handler.
        if tool == "net_manage" and action == "kill" \
                and not getattr(self.cfg.security, "allow_kill_connection", False):
            raise PermissionError(
                "allow_kill_connection=false: net_manage(action='kill')"
                " refused; set security.allow_kill_connection=true to"
                " enable SetTcpEntry(DELETE_TCB)"
            )
        # Memory scanner wave 3 P4 (AccessTrace): the watchhw driver arms
        # the DR via the int1 hook (PatchGuard-sensitive). Refuse
        # access_trace_start with driver='watchhw' (or driver='auto'
        # when it would resolve to watchhw) until the operator opts
        # in explicitly. driver='dbgeng' is unaffected.
        if tool == "debug_manage" and action == "access_trace_start" \
                and not getattr(self.cfg.security, "allow_hw_bp_hook", False):
            req_driver = str((args or {}).get("driver") or "auto").lower()
            # auto resolves to watchhw ONLY when the flag is on, so when
            # it's off, auto defaults to dbgeng — no refusal needed for
            # auto. A caller who explicitly picks watchhw with the flag
            # off gets a clean refusal.
            if req_driver == "watchhw":
                raise PermissionError(
                    "allow_hw_bp_hook=false: access_trace_start with "
                    "driver='watchhw' refused; use driver='dbgeng' or "
                    "set security.allow_hw_bp_hook=true to enable the "
                    "int1-hook-backed HW watchpoint "
                    "(PatchGuard-sensitive, lab-only). "
                    "kind=hw_bp_hook_disabled"
                )
