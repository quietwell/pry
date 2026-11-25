"""Target allowlist enforcement: connect is refused unless the target's
resolved address falls inside authorized_targets CIDRs. Runs before any
packet leaves the orchestrator.

Rules:

* A host name is resolved ONCE and **every** address it resolves to must be
  inside the allowlist — a split answer (one allowed, one not) is refused,
  because the OS/gRPC resolver may later pick the address we never checked.
  Callers then dial the checked IP literal returned here, never the name.
* Loopback is one thing: ``::1`` and ``127.0.0.0/8`` are interchangeable, so
  ``localhost`` (which Windows resolves to ``::1`` first) passes an
  allowlist that only lists ``127.0.0.0/8``.
* IPv4-mapped IPv6 (``::ffff:10.0.0.5``) is checked as the IPv4 address.
* :func:`check_authorized_async` resolves off the event loop; the sync
  :func:`check_authorized` never blocks for IP literals.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

_IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address
_LOOP4 = ipaddress.ip_address("127.0.0.1")
_LOOP6 = ipaddress.ip_address("::1")


class TargetNotAllowed(Exception):
    pass


def _literal(host: str) -> _IPAddr | None:
    s = str(host or "").strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _normalize(addr: _IPAddr) -> _IPAddr:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def resolve_all(host: str) -> list[str]:
    """Every address *host* resolves to (de-duplicated, IPv4 first, then
    the resolver's order). Blocking — call from a worker thread on the
    async paths (:func:`check_authorized_async` does).

    Raises TargetNotAllowed for unresolvable hosts.
    """
    lit = _literal(host)
    if lit is not None:
        return [str(_normalize(lit))]
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise TargetNotAllowed(f"cannot resolve target host {host!r}: {exc}") from exc
    seen: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        a = _literal(str(sockaddr[0]).split("%", 1)[0])
        if a is None:
            continue
        s = str(_normalize(a))
        if s not in seen:
            seen.append(s)
    if not seen:
        raise TargetNotAllowed(f"no addresses for {host!r}")
    v4 = [a for a in seen if ":" not in a]
    v6 = [a for a in seen if ":" in a]
    return v4 + v6


def resolve_host(host: str) -> str:
    """Resolve a host to its preferred address string (first IPv4, else the
    first IPv6). Raises TargetNotAllowed for unresolvable hosts."""
    return resolve_all(host)[0]


def _networks(authorized_cidrs: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for cidr in authorized_cidrs or []:
        try:
            nets.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
        except ValueError:
            continue  # a malformed entry authorizes nothing
    return nets


def address_allowed(addr: str, authorized_cidrs: list[str]) -> bool:
    """True when the IP literal *addr* is inside one of the CIDRs (with the
    loopback / IPv4-mapped equivalences described in the module doc)."""
    a = _literal(addr)
    if a is None:
        return False
    a = _normalize(a)
    nets = _networks(authorized_cidrs)
    for net in nets:
        if a.version == net.version and a in net:
            return True
    if a.is_loopback:
        # ::1 <-> 127.0.0.0/8: an allowlist that admits either loopback
        # flavour admits both.
        for net in nets:
            probe = _LOOP4 if net.version == 4 else _LOOP6
            if probe in net:
                return True
    return False


def check_addresses(host: str, addrs: list[str],
                    authorized_cidrs: list[str]) -> str:
    """Every entry of *addrs* (what *host* resolved to) must be allowed.
    Returns the preferred one (first IPv4, else first) — the literal the
    caller should dial."""
    if not addrs:
        raise TargetNotAllowed(f"no addresses for {host!r}")
    bad = [a for a in addrs if not address_allowed(a, authorized_cidrs)]
    if bad:
        shown = ", ".join(addrs)
        raise TargetNotAllowed(
            f"target {host} ({shown}) is not in authorized_targets "
            f"{authorized_cidrs}" + (
                f" — {', '.join(bad)} outside the allowlist"
                if len(addrs) > 1 else ""))
    v4 = [a for a in addrs if ":" not in a]
    return (v4 or addrs)[0]


def check_authorized(host: str, authorized_cidrs: list[str]) -> str:
    """Return the checked address to dial, or raise TargetNotAllowed.

    Blocking only for host *names* (resolution); prefer
    :func:`check_authorized_async` on the event loop."""
    return check_addresses(host, resolve_all(host), authorized_cidrs)


async def check_authorized_async(host: str, authorized_cidrs: list[str]) -> str:
    """:func:`check_authorized` with name resolution run in a worker thread
    so a slow resolver (mDNS/LLMNR stalls for seconds on a missing name)
    never blocks the event loop."""
    if _literal(host) is not None:
        return check_authorized(host, authorized_cidrs)
    addrs = await asyncio.to_thread(resolve_all, host)
    return check_addresses(host, addrs, authorized_cidrs)


def format_hostport(host: str, port: int) -> str:
    """``host:port`` with IPv6 literals bracketed (gRPC target syntax)."""
    h = str(host or "")
    if ":" in h and not h.startswith("["):
        return f"[{h}]:{int(port)}"
    return f"{h}:{int(port)}"
