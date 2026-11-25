"""Pure helpers for endpoint self-heal (DHCP moves).

The lab VM gets a new DHCP address on most boots, so "remember the old
address" cannot find it again. What *does* work:

* the agent's phone-home beacon (every ~30 s) — the registry knows the
  machine's current addresses within a heartbeat;
* OS name resolution (mDNS / LLMNR / DNS) of the machine's own name;
* verifying *who* answered, so a recycled lease can't attach the wrong box.

This module holds the dependency-free parts — freshness math, name
resolution, and the failure hint — so :mod:`pry.session` (candidate
ordering, link failover) and :mod:`pry.mcp._envelope` (failure
envelope) can share them without importing each other.
"""

from __future__ import annotations

import asyncio
import calendar
import ipaddress
import os
import socket
import time
from typing import Any, Iterable

#: An observation newer than this is the machine's *current* address. The
#: agent beacons every ~30 s, so four missed beats means it is gone.
BEACON_FRESH_S = 120.0

#: Cap for one OS name-resolution round (DNS + LLMNR + mDNS can stall for
#: seconds on a name that does not exist).
NAME_RESOLVE_TIMEOUT_S = 2.0

_FALSY = ("0", "false", "no", "off")


def _env_on(name: str, default: str = "1") -> bool:
    return os.environ.get(name, default).strip().lower() not in _FALSY


def name_resolution_enabled() -> bool:
    """``PRY_NAME_RESOLVE=0`` disables hostname-based endpoint discovery
    (the test-suite does, so unit tests never hit a real resolver)."""
    return _env_on("PRY_NAME_RESOLVE")


def link_heal_enabled() -> bool:
    """``PRY_LINK_HEAL=0`` disables the per-view endpoint failover
    watcher (the test-suite does, so fake clients are never polled)."""
    return _env_on("PRY_LINK_HEAL")


def looks_like_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(str(text).strip())
    except ValueError:
        return False
    return True


def usable_ipv4(addr: str) -> bool:
    """A routable-looking IPv4 — not loopback, link-local, unspecified or
    multicast (those are never a lab machine's address)."""
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except ValueError:
        return False
    return ip.version == 4 and not (
        ip.is_loopback or ip.is_link_local or ip.is_unspecified
        or ip.is_multicast)


def seen_epoch(ts: Any) -> float | None:
    """``'2026-11-23T17:04:50Z'`` -> epoch seconds (UTC), None if unparsable."""
    try:
        return float(calendar.timegm(
            time.strptime(str(ts), "%Y-%m-%dT%H:%M:%SZ")))
    except (ValueError, TypeError):
        return None


def age_s(ts: Any, now: float | None = None) -> float | None:
    """Seconds since *ts* (never negative), None if *ts* is unparsable."""
    ep = seen_epoch(ts)
    if ep is None:
        return None
    return max(0.0, (time.time() if now is None else now) - ep)


async def resolve_name_hosts(
        names: Iterable[str], *,
        timeout_s: float = NAME_RESOLVE_TIMEOUT_S) -> list[str]:
    """Resolve machine *names* through the OS resolver (DNS suffix search,
    LLMNR, mDNS) and return the usable IPv4 addresses, first-seen order.

    The OS answer is only a *candidate*: a router's DNS can hand back a
    stale lease, so callers must still TCP-probe and verify the identity of
    whatever answers. Each name gets its own *timeout_s*; a name that does
    not resolve in time is skipped (the executor thread may linger, that is
    harmless).
    """
    loop = asyncio.get_running_loop()

    async def _one(name: str) -> list[str]:
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(name, None, family=socket.AF_INET,
                                 type=socket.SOCK_STREAM),
                timeout=timeout_s)
        except Exception:  # noqa: BLE001 — NXDOMAIN, timeout, resolver down
            return []
        return [str(i[4][0]) for i in infos]

    wanted = [n for n in dict.fromkeys(
        str(n).strip() for n in names if str(n or "").strip())]
    out: list[str] = []
    for addrs in await asyncio.gather(*(_one(n) for n in wanted)):
        for a in addrs:
            if usable_ipv4(a) and a not in out:
                out.append(a)
    return out


def connect_failure_hint(info: dict[str, Any]) -> str:
    """Next-step text for a failed connect, built from the ``endpoint_info``
    the session attaches to the exception: the registry beacon overview
    (``beacons``) and the hostname-resolution result (``name_resolution``).

    The generic network hints tell an agent to "check the service on the
    target" — useless when the target is simply at another address. This
    names the machines that are beaconing *right now* and where.
    """
    beacons = [b for b in (info.get("beacons") or []) if isinstance(b, dict)]
    fresh = [b for b in beacons if b.get("fresh")]
    bits: list[str] = []
    if fresh:
        shown = "; ".join(
            f"{b.get('machine')} from {', '.join(b.get('hosts') or [])} "
            f"({int(b.get('age_s') or 0)}s ago)" for b in fresh[:3])
        bits.append(
            f"agents are beaconing right now: {shown}. Retry "
            "target_manage(action='connect', machine='<that alias>') "
            "(beacon addresses are tried first) or pass host=<ip>")
    else:
        if beacons:
            newest = beacons[0]
            bits.append(
                f"no agent has beaconed in the last {int(BEACON_FRESH_S)}s "
                f"(newest: {newest.get('machine')}, "
                f"{int(newest.get('age_s') or 0)}s ago) — the machine may "
                "be off, asleep or off the LAN")
        else:
            bits.append("no agent beacon is on record for any machine")
        bits.append(
            "`ping <hostname>` (mDNS usually returns the live address) or "
            "target_manage(action='wait_agent', cidr='<subnet>/24') can "
            "find it")
    nr = info.get("name_resolution") or {}
    if nr.get("resolved"):
        bits.append(
            "hostname resolution returned "
            f"{', '.join(nr['resolved'])} but nothing answered on the "
            "agent port")
    return "; ".join(bits)
