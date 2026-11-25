"""Async-safe lease manager for pry.

Two resource families are leased in this system:

* ``debug:<view>:pid=<pid>`` — held from ``debug_manage`` launch/attach until
  detach (or peer reap by ``release_by_owner``).
* ``driver`` — held for the duration of ``driver_load`` / ``driver_unload``.
  A peer's kernel-view refcount is enforced *outside* this module and blocks
  ``driver_unload`` with ``in_use_by``; the lease here only serializes the
  load/unload critical section itself.

The manager is async-only. All mutations are serialized under one
:class:`asyncio.Condition`, so concurrent tasks observe a consistent view of
holders and waiters are woken deterministically when a slot frees.

Every ``acquire`` and ``release`` publishes an event dict of the shape

    {"type": "lease_acquire" | "lease_release",
     "resource": str, "owner": str, "since": float}

onto the injected ``publish_event`` callable.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Union

__all__ = ["LeaseManager", "LeaseHandle", "BusyInfo"]

_log = logging.getLogger(__name__)


PublishEvent = Callable[[dict[str, Any]], Any]


def _iso(ts: float) -> str:
    """Format an epoch-second timestamp as an ISO-8601 UTC string ending in ``Z``."""
    return (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass
class BusyInfo:
    """Returned by :meth:`LeaseManager.acquire` when the resource is held.

    ``waited_s`` reflects how long the caller actually blocked before giving
    up — ``0.0`` on the non-blocking path, and up to ``wait_s`` on the
    blocking path.
    """

    held_by: str
    since_iso: str
    waited_s: float
    kind: str = "busy"


@dataclass(eq=False)
class LeaseHandle:
    """A held lease. Acts as an async context manager:

        async with await mgr.acquire("driver", "kernel", 5.0) as lease:
            ...

    Callers may also release explicitly via :meth:`LeaseManager.release`.
    Both paths are idempotent — releasing twice, or exiting the ``async
    with`` after an explicit release, is a no-op.

    ``last_touched_at`` grows with :meth:`LeaseManager.touch` on
    each lease-holding call site; the periodic reaper releases a lease
    whose idle window exceeds ``cfg.leases.idle_ttl_s`` (default 10 min)
    or whose total hold exceeds ``cfg.leases.hard_max_s`` (default 1 hr).
    """

    resource: str
    owner: str
    since: float
    _mgr: "LeaseManager" = field(repr=False)
    _released: bool = field(default=False, repr=False)
    # idle TTL tracking. Initialised to ``since`` on acquire; the
    # reaper compares ``now - last_touched_at`` against ``idle_ttl_s``.
    last_touched_at: float = field(default=0.0)

    @property
    def since_iso(self) -> str:
        return _iso(self.since)

    async def __aenter__(self) -> "LeaseHandle":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._mgr.release(self)


# Convenience alias for the acquire() return type.
AcquireResult = Union[LeaseHandle, BusyInfo]


class LeaseManager:
    """Async-safe lease manager.

    A single :class:`asyncio.Condition` serializes state changes and is used
    to wake waiters when a resource is released. Construct one per running
    event loop — the internal condition binds to the loop it was created on.
    """

    def __init__(self, publish_event: PublishEvent) -> None:
        self._publish = publish_event
        self._cond = asyncio.Condition()
        self._holders: dict[str, LeaseHandle] = {}
        # background reaper handle; set by :meth:`start_reaper`.
        self._reaper_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------ core

    async def acquire(
        self,
        resource: str,
        owner: str,
        wait_s: float | None,
    ) -> AcquireResult:
        """Acquire ``resource`` for ``owner``.

        * ``wait_s`` of ``None`` or ``<= 0`` is non-blocking: returns
          :class:`BusyInfo` immediately if the resource is held.
        * ``wait_s > 0`` waits up to that many seconds (measured on the
          running loop's monotonic clock) before giving up with
          :class:`BusyInfo`.

        On success returns a :class:`LeaseHandle` and publishes a
        ``lease_acquire`` event.
        """
        loop = asyncio.get_running_loop()
        wait_start = loop.time()
        blocking = wait_s is not None and wait_s > 0
        deadline = wait_start + (wait_s if blocking else 0.0)

        async with self._cond:
            while resource in self._holders:
                if not blocking:
                    return self._busy(resource, waited_s=0.0)

                remaining = deadline - loop.time()
                if remaining <= 0:
                    return self._busy(
                        resource, waited_s=loop.time() - wait_start
                    )

                try:
                    await asyncio.wait_for(
                        self._cond.wait(), timeout=remaining
                    )
                except asyncio.TimeoutError:
                    # The slot may have freed at the very moment we timed
                    # out — give it one recheck before declaring busy.
                    if resource not in self._holders:
                        break
                    return self._busy(
                        resource, waited_s=loop.time() - wait_start
                    )

            now = time.time()
            handle = LeaseHandle(
                resource=resource,
                owner=owner,
                since=now,
                _mgr=self,
                last_touched_at=now,
            )
            self._holders[resource] = handle

        self._emit("lease_acquire", handle)
        return handle

    async def release(self, handle: LeaseHandle) -> None:
        """Release ``handle``. Idempotent.

        A no-op when the handle has already been released, or when the slot
        has since been taken by a different owner (defensive — a peer reap
        via :meth:`release_by_owner` marks the handle first, so the async
        context-manager exit that follows stays quiet).
        """
        async with self._cond:
            if handle._released:
                return
            current = self._holders.get(handle.resource)
            if current is not handle:
                handle._released = True
                return
            handle._released = True
            del self._holders[handle.resource]
            self._cond.notify_all()

        self._emit("lease_release", handle)

    async def release_by_owner(self, owner: str) -> list[str]:
        """Release every lease currently held by ``owner``.

        Used when a peer disappears (a debug view is reaped, an agent
        disconnects). Returns the resource names that were freed, in the
        order they were dropped from the holder table. Publishes one
        ``lease_release`` event per victim.
        """
        victims: list[LeaseHandle] = []
        async with self._cond:
            for h in list(self._holders.values()):
                if h.owner == owner and not h._released:
                    h._released = True
                    del self._holders[h.resource]
                    victims.append(h)
            if victims:
                self._cond.notify_all()

        for h in victims:
            self._emit("lease_release", h)
        return [h.resource for h in victims]

    # ------------------------------------------------- TTL + reap ----

    async def touch(self, handle: LeaseHandle) -> None:
        """Bump ``handle.last_touched_at`` to now so the reaper's idle TTL
        resets.

        Call-site wiring is intentionally sparse — the field
        is set on acquire and bumped only by code that explicitly calls
        this method. The reaper's job is to catch *abandoned* leases, not
        to arbitrate normal traffic; the hard_max cap bounds the long-tail
        worst case.
        """
        async with self._cond:
            if handle._released:
                return
            # Defensive: the holder slot may have changed owners if a peer
            # reap intervened; only touch our own handle.
            current = self._holders.get(handle.resource)
            if current is handle:
                handle.last_touched_at = time.time()

    async def reap_expired(self, idle_ttl_s: float,
                           hard_max_s: float) -> list[tuple[str, str]]:
        """Release every lease whose idle window or total-hold window
        exceeds the cap. Returns ``[(resource, reason), ...]``; reason is
        one of ``"idle_timeout"`` / ``"hard_max"``.

        Publishes one ``lease_release`` event per victim, extended with a
        ``"reason"`` key so observers can tell reaped leases from normal
        releases.
        """
        if idle_ttl_s <= 0 and hard_max_s <= 0:
            return []
        victims: list[tuple[LeaseHandle, str]] = []
        async with self._cond:
            now = time.time()
            for h in list(self._holders.values()):
                if h._released:
                    continue
                reason: str | None = None
                if hard_max_s > 0 and (now - h.since) > hard_max_s:
                    reason = "hard_max"
                elif idle_ttl_s > 0 and (now - h.last_touched_at) > idle_ttl_s:
                    reason = "idle_timeout"
                if reason is None:
                    continue
                h._released = True
                del self._holders[h.resource]
                victims.append((h, reason))
            if victims:
                self._cond.notify_all()
        for h, reason in victims:
            self._publish(
                {
                    "type": "lease_release",
                    "resource": h.resource,
                    "owner": h.owner,
                    "since": h.since,
                    "reason": reason,
                }
            )
            _log.info(
                "lease reaped resource=%s owner=%s reason=%s held_s=%.1f",
                h.resource, h.owner, reason, time.time() - h.since,
            )
        return [(h.resource, reason) for h, reason in victims]

    async def reap_once_sync(self, idle_ttl_s: float,
                             hard_max_s: float) -> list[tuple[str, str]]:
        """Public one-shot reap — intended to be ``await``ed from the
        orchestrator startup hook. Failures are swallowed by the caller
        so a stale lease table never blocks the server from booting.
        """
        return await self.reap_expired(idle_ttl_s, hard_max_s)

    async def start_reaper(self, interval_s: float, idle_ttl_s: float,
                           hard_max_s: float) -> asyncio.Task[None]:
        """Launch (or re-launch) the background reaper. Stores the task
        on ``self._reaper_task``; the caller is responsible for cancelling
        it on shutdown via :meth:`stop_reaper`.
        """
        if self._reaper_task is not None and not self._reaper_task.done():
            return self._reaper_task

        async def _loop() -> None:
            try:
                while True:
                    try:
                        await asyncio.sleep(interval_s)
                        await self.reap_expired(idle_ttl_s, hard_max_s)
                    except asyncio.CancelledError:
                        raise
                    except Exception:  # noqa: BLE001 - never die on a stray
                        _log.exception("lease reaper tick failed")
            except asyncio.CancelledError:
                pass

        self._reaper_task = asyncio.create_task(
            _loop(), name="lease-reaper"
        )
        return self._reaper_task

    async def stop_reaper(self) -> None:
        """Cancel the background reaper if it's running."""
        task = self._reaper_task
        self._reaper_task = None
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------ observers

    def who_holds(self, resource: str) -> str | None:
        """Return the current owner of ``resource``, or ``None`` if free.

        Lock-free by design so the dashboard can render snapshots without
        contending with an in-flight acquire.
        """
        h = self._holders.get(resource)
        return h.owner if h is not None else None

    def snapshot(self) -> dict[str, dict[str, str]]:
        """Return ``{resource: {"owner", "since_iso"}}`` for held leases.

        The returned dict is a fresh copy; callers may mutate it freely.
        """
        return {
            res: {"owner": h.owner, "since_iso": _iso(h.since)}
            for res, h in self._holders.items()
        }

    # -------------------------------------------------------------- helpers

    def _busy(self, resource: str, waited_s: float) -> BusyInfo:
        holder = self._holders[resource]
        return BusyInfo(
            held_by=holder.owner,
            since_iso=_iso(holder.since),
            waited_s=waited_s,
        )

    def _emit(self, kind: str, handle: LeaseHandle) -> None:
        self._publish(
            {
                "type": kind,
                "resource": handle.resource,
                "owner": handle.owner,
                "since": handle.since,
            }
        )
