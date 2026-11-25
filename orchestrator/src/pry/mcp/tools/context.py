"""``Context`` container shared by every ``@mcp.tool`` closure.

Bundles the config, session, findings ledger, IDA bridge, multi-agent
registries (clients / leases / ownership), and per-caller state
(``current_session_id`` map, follow / auto-kick tables, per-pid attach
leases). The class body is unchanged from the pre-split ``tools.py`` —
only its home has moved.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

_log = logging.getLogger(__name__)

from ...findings import FindingsLedger
from ...ghidra_bridge import GhidraBridge
from ...ida_bridge import IdaBridge
from ...leases import LeaseHandle
from ...session import Session

class Context:
    def __init__(self, cfg, session: Session, ledger: FindingsLedger, bridge: IdaBridge,
                 *, gbridge: "GhidraBridge | None" = None,
                 clients=None, leases=None, ownership=None) -> None:
        self.cfg = cfg
        self.session = session
        self.ledger = ledger
        self.bridge = bridge
        # Optional — present only when cfg.ghidra.enabled. tools/ghidra.py
        # raises a typed error when a caller hits ghidra_manage with no
        # bridge wired, mirroring the disabled-config path.
        self.gbridge = gbridge
        # per-caller registries. Keyword-only + optional so tests that
        # build a Context with just (cfg, session, ledger, bridge) still work.
        # - clients   : ClientRegistry — MCP client_id -> metadata / heartbeat.
        # - leases    : LeaseManager — exclusive-target locks (attach-pid, driver).
        # - ownership : OwnershipRegistry — creator (client_id) of long-lived ids
        #               (bp_id, shell session_id, IDA session, follow_id, ...).
        self.clients = clients
        self.leases = leases
        self.ownership = ownership
        # current ledger session-id is now per-caller. Old readers used
        # it as a bare str; every touch migrates to get_current_session_id() /
        # set_current_session_id(), both keyed by current_client_id().
        self.current_session_id: dict[str, str] = {}
        # one debug-event pump PER VIEW (it used to follow only the
        # primary view, so debug_manage(events) / bp hits on a second
        # machine never filled). Keyed by view name.
        self._event_pumps: dict[str, asyncio.Task] = {}
        # log-follow state — one entry per active file_manage(follow_start).
        # ids are globally unique so the map stays flat; each entry now carries
        # an 'owner' (client_id) field, and list-shaped responses filter by it.
        # {follow_id: {"path": str, "task": Task, "buffer": deque of chunks,
        #              "seq": int, "started_ts": float, "last_poll_ts": float,
        #              "eof": bool, "reason": str, "owner": str}}
        self._follows: dict[str, dict[str, Any]] = {}
        self._follow_next: int = 1
        # watchdog auto-kick state — one entry per file_manage(auto_kick).
        # Same shape rule: ids are globally unique, each entry gains 'owner'.
        # {wdg_id (as str): {"task": Task, "id": int, "deadline_ms": int,
        #                    "interval_ms": int, "started_ts": float, "kicks": int,
        #                    "last_kick_ts": float, "last_result": dict,
        #                    "last_error": str, "owner": str}}
        self._auto_kicks: dict[str, dict[str, Any]] = {}
        # per-pid debug attach leases. Keyed by (view, pid); the value
        # is the LeaseHandle returned by ctx.leases.acquire() at launch/attach
        # time. debug_manage(detach) releases every handle whose owner matches
        # the current client for the active view; a peer reap goes through
        # ctx.leases.release_by_owner(...) and never touches this dict — the
        # stale entry stays here until the owner calls detach or the process
        # restarts. Empty when the multi-agent lease layer is disabled
        # (ctx.leases is None) â€” every debug branch checks that first.
        self._attach_leases: dict[tuple[str, int], LeaseHandle] = {}
        # machine registry (artifacts/targets.json) — lazy so test
        # fixtures that build a Context with the bare 4-arg constructor
        # keep working; nothing touches it until machines_* / trust gate /
        # connect-banner code paths run.
        self._registry = None
        # machine_info banner dedup — {client_id: {machine labels
        # already introduced to that client}}. The trust/purpose block is
        # delivered once per machine per client (first connect), then only
        # on demand via target_manage(action='machines').
        self._machine_info_seen: dict[str, set[str]] = {}
        # PR#2 T2.7: dedupe the watchdog.auto_arm UNCONFIGURED hint —
        # the first driver_load on a machine shows it, subsequent loads
        # on the same machine omit unless verbose=True. Session-scoped
        # (orchestrator-process lifetime).
        self._watchdog_unconf_seen: set[str] = set()
        # DHCP self-heal (session/endpoint_heal.py). The session reads fresh
        # phone-home beacons / learned identities through a provider that
        # returns None until the lazy registry is loaded (so building a
        # Context never touches the registry file), and reports a view that
        # was re-pointed to a new address back through the heal hook.
        for _setter, _fn in (
                ("set_registry_provider", lambda: self._registry),
                ("set_link_heal_hook", self._on_link_healed)):
            _set = getattr(session, _setter, None)
            if callable(_set):
                try:
                    _set(_fn)
                except Exception:  # noqa: BLE001 — wiring is best-effort
                    pass

    @property
    def registry(self):
        """Lazy MachineRegistry (persists machine metadata + credentials
        in artifacts/targets.json; see pry.registry)."""
        if self._registry is None:
            from ...registry import MachineRegistry
            self._registry = MachineRegistry.load(self.cfg)
            # feed observed endpoints back into Session's
            # connect-candidate list so a boxed-up endpoint flap self-heals
            # (DHCP changed the IP; the registry remembered the IP the box
            # actually answered on, and connect probes that first).
            try:
                reg = self._registry
                # NOTE: hosts only — Session.connect pairs each entry with
                # the view's port itself. Earlier revisions emitted
                # "host:port" strings here, which connect() then probed as
                # literal hostnames: every observed endpoint was dead on
                # arrival and the DHCP self-heal never fired.
                self.session.set_observed_endpoint_source(
                    lambda label: [
                        str(o.get("host"))
                        for o in reg.observed_endpoints(label)
                        if o.get("host")])
            except Exception:  # noqa: BLE001 — hook install is best-effort
                pass
        return self._registry

    async def _on_link_healed(self, name: str, notice: dict[str, Any],
                              change: dict[str, Any] | None) -> None:
        """The session re-pointed view *name* to a new endpoint (DHCP move).

        Records the new address as an observed endpoint, and — when the
        machine also rebooted on the way (it usually did: every boot is a
        new lease) — does what the boot monitor would have: sweeps the
        orphaned shells/follows/watchdog arms, re-arms ``watchdog.auto_arm``
        after a new boot, and parks the newest crash dump for the next
        status() call. All best-effort; none of it may fail the heal.
        """
        from .target._runtime import (
            _auto_arm_after_load,
            _monitor_pull_minidump,
            _park_minidump_notice,
        )
        try:
            host, _, port_s = str(notice.get("to") or "").rpartition(":")
            if host and port_s.isdigit():
                self.registry.record_observed_endpoint(
                    self.session.machine_of(name), host=host,
                    port=int(port_s),
                    boot_epoch_ms=int((change or {}).get("boot_epoch_ms") or 0))
        except Exception:  # noqa: BLE001
            pass
        # The rebind closed the old channel under every stream consumer;
        # restart this view's debug-event pump on the new one.
        try:
            self.restart_event_pump(name)
        except Exception:  # noqa: BLE001
            pass
        if not change:
            return
        try:
            await self.sweep_view_state(name)
        except Exception:  # noqa: BLE001
            pass
        if change.get("kind") == "new_boot":
            await _auto_arm_after_load(
                self, self.session.clients.get(name), name)

        async def _pull() -> None:
            res = await _monitor_pull_minidump(
                self, name,
                boot_epoch_ms=int(change.get("boot_epoch_ms") or 0))
            if res is not None:
                _park_minidump_notice(self, name, res, source="link_watch")

        try:
            from ...caller import spawn_background
            spawn_background(_pull(), name=f"pry-dumppull-{name}",
                             owner="orchestrator:minidump")
        except Exception:  # noqa: BLE001
            pass

    def get_current_session_id(self, client_id: str) -> str:
        """Return the ledger session-id bound to ``client_id`` (``""`` if none).

        Never raises. Callers pass ``current_client_id()`` from
        :mod:`pry.caller`; unattributed transports land in the
        ``"anonymous"`` bucket, matching the ledger's own fallback.
        """
        return self.current_session_id.get(client_id, "")

    def set_current_session_id(self, client_id: str, sid: str) -> None:
        """Bind ``sid`` as the current ledger session-id for ``client_id``."""
        self.current_session_id[client_id] = sid

    async def sweep_view_state(self, view: str) -> dict[str, Any]:
        """Invalidate orchestrator-side state orphaned by a view's
        reboot/agent-restart: log follows streaming from the old lifetime,
        watchdog auto-kicks (watchdog state lives in the driver — gone on a
        new boot), debug attach leases, and view-scoped ownership tags.
        Agent-side artifacts (resX spill files) are reported by the caller,
        never deleted. Returns a summary dict."""
        swept: dict[str, Any] = {"view": view, "follows": [],
                                 "auto_kicks": [], "attach_leases": [],
                                 "ownership_tags": 0}
        # Follows stream from the primary client only — a secondary view
        # reboot leaves them untouched.
        if view == self.session.primary:
            for fid, st in list(self._follows.items()):
                task = st.get("task")
                if task is not None and not task.done():
                    task.cancel()
                st["eof"] = True
                st["reason"] = "invalidated: view rebooted/restarted"
                swept["follows"].append(fid)
            self._follows.clear()
        for key, st in list(self._auto_kicks.items()):
            if not str(key).startswith(f"{view}:"):
                continue
            task = st.get("task")
            if task is not None and not task.done():
                task.cancel()
            self._auto_kicks.pop(key, None)
            swept["auto_kicks"].append(str(key))
        for k in [k for k in self._attach_leases if k[0] == view]:
            self._attach_leases.pop(k, None)
            swept["attach_leases"].append(f"{k[0]}:{k[1]}")
        if self.ownership is not None:
            try:
                for cat in await self.ownership.categories():
                    if cat.endswith(f":{view}") or cat == view:
                        swept["ownership_tags"] += \
                            await self.ownership.release_category(cat)
            except Exception:  # noqa: BLE001 — sweep is best-effort
                pass
        return swept

    def _pump_view(self, view: str | None) -> str:
        return view or self.session.primary

    @property
    def _event_pump(self) -> asyncio.Task | None:
        """Back-compat: the primary view's pump task."""
        return self._event_pumps.get(self.session.primary)

    def start_event_pump(self, view: str | None = None) -> None:
        """Start (idempotently) the debug-event pump for *view* (default:
        the primary view). The pump drains ``Debug.StreamEvents`` into the
        view client's bus; it runs in a fresh context (not as the chat that
        triggered it) and exits with the stream — callers restart it."""
        name = self._pump_view(view)
        task = self._event_pumps.get(name)
        if task is not None and not task.done():
            return
        client = self.session.clients.get(name)
        if client is None or not hasattr(client, "debug_events"):
            return

        async def pump() -> None:
            try:
                async for _ev in client.debug_events():
                    pass  # debug_events() publishes into the bus itself
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # the stream ending is normal on disconnect/restart —
                # but a silent dead pump is how "debug events never
                # arrive" bugs hide; keep a breadcrumb.
                _log.info("event pump for %s ended: %r", name, exc)

        from ...caller import spawn_background
        try:
            self._event_pumps[name] = spawn_background(
                pump(), name=f"pry-eventpump-{name}",
                owner="orchestrator:event_pump")
        except RuntimeError:  # no running loop (sync test harness)
            return

    def restart_event_pump(self, view: str | None = None) -> None:
        """Cancel and restart *view*'s pump — after a link heal re-pointed
        the client, the old stream is bound to a closed channel."""
        name = self._pump_view(view)
        task = self._event_pumps.pop(name, None)
        if task is not None and not task.done():
            task.cancel()
        self.start_event_pump(name)

    def stop_event_pump(self, view: str | None = None) -> None:
        name = self._pump_view(view)
        task = self._event_pumps.pop(name, None)
        if task is not None and not task.done():
            task.cancel()

    def event_pump_alive(self, view: str | None = None) -> bool:
        task = self._event_pumps.get(self._pump_view(view))
        return task is not None and not task.done()
