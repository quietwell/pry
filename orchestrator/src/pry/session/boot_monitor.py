"""Boot-identity + boot-monitor mixin for :class:`.core.Session`.

Compares the ``(boot_epoch_ms, agent_instance_id)`` pair carried on
every StatusResponse against the per-view last-seen record so a
reboot or an agent-process restart surfaces as a change notice; the
per-view ``_boot_monitor_loop`` task polls the agent every few
seconds so detection is timely rather than lazy.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..agent_client import AgentClient


class SessionBootMonitorMixin:
    """Boot-identity classifier + per-view monitor task."""

    # T1.3 (PR#2): tolerance for FILETIME→unix-ms jitter when comparing
    # OS boot epochs. Below this delta we treat the boot as unchanged
    # (agent process restart on the same OS boot classifies as
    # agent_restart, not new_boot). See plan §T1.3.
    _BOOT_EPOCH_JITTER_MS: int = 2000

    # State owned by :class:`.core.Session.__init__`.
    clients: dict[str, AgentClient]
    _boot_ids: dict[str, dict[str, Any]]
    _boot_monitors: dict[str, asyncio.Task[None]]
    pending_boot_notices: dict[str, dict[str, Any]]

    def note_boot_identity(self, name: str, status: dict[str, Any]) -> dict[str, Any] | None:
        """Compare ``status``'s boot identity against the last seen for view
        ``name``. Returns a change record when the far end came back
        different (``kind`` = ``first_connect`` | ``new_boot`` |
        ``agent_restart``), else None (``unchanged``).

        T1.3 (PR#2): classification is tolerant of FILETIME→unix-ms
        jitter — a boot_epoch_ms delta <= 2000ms with a changed
        agent_instance_id classifies as ``agent_restart``, not
        ``new_boot``. SCM failure/restart of the agent service can
        produce a tiny BootTime jitter on some Windows builds; the
        2000ms window swallows it.

        The change record always carries ``kind``, ``delta_ms`` (how
        far boot_epoch_ms moved) and ``prev_instance_id`` so callers
        can diff the identity without re-reading state.

        Pre-v14 agents report neither field and are treated as
        indeterminate — recorded only when present, never flagged.
        """
        boot = int(status.get("boot_epoch_ms") or 0)
        inst = str(status.get("agent_instance_id") or "")
        if not boot and not inst:
            return None
        prev = self._boot_ids.get(name)
        self._boot_ids[name] = {"boot_epoch_ms": boot, "agent_instance_id": inst}
        if prev is None:
            # T1.3: surface "first time we've seen this view" explicitly
            # so callers can tell it apart from unchanged.
            return {"kind": "first_connect", "view": name,
                    "boot_epoch_ms": boot,
                    "agent_instance_id": inst,
                    "delta_ms": 0,
                    "prev_instance_id": None}
        prev_boot = int(prev.get("boot_epoch_ms") or 0)
        prev_inst = str(prev.get("agent_instance_id") or "")
        delta = abs(prev_boot - boot) if (boot and prev_boot) else 0
        if boot and prev_boot and delta > self._BOOT_EPOCH_JITTER_MS:
            return {"kind": "new_boot", "view": name,
                    "prev_boot_epoch_ms": prev_boot,
                    "boot_epoch_ms": boot,
                    "agent_instance_id": inst,
                    "delta_ms": delta,
                    "prev_instance_id": prev_inst or None}
        if inst and prev_inst and prev_inst != inst:
            return {"kind": "agent_restart", "view": name,
                    "boot_epoch_ms": boot,
                    "agent_instance_id": inst,
                    "delta_ms": delta,
                    "prev_instance_id": prev_inst}
        return None

    def boot_identity(self, name: str) -> dict[str, Any]:
        """Last boot identity recorded for view ``name`` by
        note_boot_identity — ``{}`` when the view has never answered a
        status carrying boot fields."""
        return dict(self._boot_ids.get(name) or {})

    def start_boot_monitor(self, name: str, interval_s: float = 5.0, *,
                           on_change=None, on_scan=None,
                           scan_idle_s: float = 60.0) -> bool:
        """Spawn (idempotently) the per-view boot-change poller.

        Every ``interval_s`` the loop calls ``client.status()`` for the
        named view and pushes the reply through
        :meth:`note_boot_identity` — the same detector ``status()`` uses,
        just timely rather than lazy. A change record is parked in
        ``pending_boot_notices`` (drained by the next status call) and
        ``on_change(name, change)`` runs for orchestrator-side followup
        (state sweep, auto minidump pull). While the view stays quiet
        for ``scan_idle_s`` straight, ``on_scan(name, boot_epoch_ms)``
        fires for lazy work that would be too expensive every tick (the
        minidump-dir watch).

        ``interval_s <= 0`` is the explicit disable; returns False and
        spawns nothing. Idempotent — a live monitor is never replaced.
        """
        if interval_s <= 0:
            return False
        existing = self._boot_monitors.get(name)
        if existing is not None and not existing.done():
            return False
        # a fresh contextvars context — the monitor (and the
        # sweep / auto-arm / minidump work its callbacks do) must not run
        # as the chat whose connect happened to start it.
        from ..caller import spawn_background
        self._boot_monitors[name] = spawn_background(
            self._boot_monitor_loop(
                name, float(interval_s), on_change=on_change,
                on_scan=on_scan, scan_idle_s=float(scan_idle_s)),
            name=f"pry-bootmon-{name}", owner="orchestrator:boot_monitor")
        return True

    def stop_boot_monitor(self, name: str | None = None) -> None:
        """Cancel monitor task(s); ``name=None`` stops every view's."""
        for n, task in list(self._boot_monitors.items()):
            if name is None or n == name:
                task.cancel()
                self._boot_monitors.pop(n, None)

    def boot_monitor_running(self, name: str) -> bool:
        task = self._boot_monitors.get(name)
        return task is not None and not task.done()

    async def _boot_monitor_loop(self, name: str, interval_s: float, *,
                                 on_change, on_scan,
                                 scan_idle_s: float) -> None:
        last_scan = time.monotonic()
        while True:
            await asyncio.sleep(interval_s)
            client = self.clients.get(name)
            if client is None:
                continue
            try:
                st = await client.status()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — transient poll failures are silent
                continue
            change = self.note_boot_identity(name, st)
            now = time.monotonic()
            # T1.3 (PR#2): first_connect is a classification, not a change —
            # park only actual boot/agent-restart notices.
            if change is not None and change.get("kind") in (
                    "new_boot", "agent_restart"):
                last_scan = now
                change.setdefault("source", "boot_monitor")
                self.pending_boot_notices[name] = change
                if on_change is not None:
                    try:
                        await on_change(name, change)
                    except asyncio.CancelledError:
                        raise
                    except Exception:  # noqa: BLE001 — monitor work is best-effort
                        pass
            elif on_scan is not None and (now - last_scan) >= scan_idle_s:
                last_scan = now
                try:
                    await on_scan(name, int(st.get("boot_epoch_ms") or 0))
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    pass
