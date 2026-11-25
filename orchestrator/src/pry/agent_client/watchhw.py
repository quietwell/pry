"""Thin WatchHw add/remove facade for AccessTrace (Wave 3 P4) and
``memory_manage(action='watch', mode='hw')``.

The agent serves a dedicated ``WatchHw`` gRPC service (proto
``service WatchHw { Add; Remove }``, agent ``services_bp.cpp`` —
``WatchHwSvc`` over ``Driver::BpHwSet``). :class:`AgentClient` binds it as
``self.watch_hw`` and exposes:

  * ``bp_hw_watch_add(...)``   — ``WatchHw.Add``: arm a DR0..3 slot in the
                                 kernel. With ``preempt_ok=False`` an active
                                 hw-bp holder is reported (busy slot) instead
                                 of silently preempted.
  * ``bp_hw_watch_remove(cookie)`` — ``WatchHw.Remove``: release the slot on
                                 job stop.

This wrapper keeps the AccessTrace driver decoupled from the
client: unit tests only have to patch ``WatchHwWrapper.add`` / ``.remove``,
and a duck-typed client lacking the methods yields a clean error dict.
"""

from __future__ import annotations

from typing import Any


class WatchHwWrapper:
    """Fat facade over the AgentClient instance.

    The wrapper is stateless — it reads attributes off the live agent
    client object (``c.bp_hw_watch_add`` / ``c.bp_hw_watch_remove`` if
    they exist, else surfaces a clean error dict). Keeps the driver
    composable in unit tests: the mocks only have to patch
    ``WatchHwWrapper.add`` / ``.remove``.
    """

    def __init__(self, client: Any) -> None:
        self._c = client

    async def add(self, *, pid: int, tid: int, address: int,
                   size: int, access: str, slot: int = 0xFF,
                   preempt_ok: bool = False, tag: str = "",
                   ) -> dict[str, Any]:
        """Arm a HW watchpoint. Returns a dict with ``ok``,
        ``watch_cookie`` (0 on failure), ``slot``, and ``error`` on
        failure. ``hvci_fallback=True`` means the DRs armed but the
        driver's int1 hook is refused by the hypervisor — hits never
        ring.
        """
        c = self._c
        if not hasattr(c, "bp_hw_watch_add"):
            return {
                "ok": False, "kind": "watchhw_unavailable",
                "error": ("WatchHw.Add: agent build lacks the hw-watch "
                          "shim (bp_hw_watch_add). Pass driver='dbgeng' "
                          "or rebuild the ABI v14 agent."),
                "watch_cookie": 0,
            }
        r = await c.bp_hw_watch_add(
            pid=int(pid), tid=int(tid), address=int(address),
            size=int(size), access=str(access), slot=int(slot),
            preempt_ok=bool(preempt_ok), tag=str(tag),
        )
        d = dict(r or {})
        d.setdefault("ok", True)
        d.setdefault("watch_cookie", int((r or {}).get("watch_cookie") or 0))
        return d

    async def remove(self, cookie: int) -> dict[str, Any]:
        """Release the DR slot. Mirrors ``BpRemove``'s already-removed
        breadcrumb — ``ok=True`` + ``already_removed=True`` when the
        slot was freed under us (thread-exit auto-prune)."""
        c = self._c
        if hasattr(c, "bp_hw_watch_remove"):
            r = await c.bp_hw_watch_remove(int(cookie))
            return dict(r or {})
        # Fall through to the generic bp_remove when the driver stuck
        # the cookie in the normal breakpoint id space (most agent
        # builds). Caller is expected to pass cookie = bp_id here.
        if hasattr(c, "bp_remove"):
            return dict(await c.bp_remove(int(cookie)))
        return {"ok": False, "kind": "watchhw_unavailable",
                "error": "no WatchHw.Remove / bp_remove on this agent"}
