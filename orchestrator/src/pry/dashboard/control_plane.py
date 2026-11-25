"""Control-plane guard for the orchestrator's HTTP listener.

The listener binds ``mcp.bind`` — ``0.0.0.0`` in lab configs, because lab
agents POST their phone-home beacon to ``/api/agent_report``. The same
socket also serves ``/mcp`` (exec, driver_load, every actuator),
``/api/*`` (registry writes: trust, tokens, prune), ``/ws`` and the
dashboard, so anything on the LAN — including the lab VMs that run the
samples under analysis — could drive the orchestrator, and any web page in
a local browser could do the same cross-site.

:class:`ControlPlaneGuard` is a pure-ASGI middleware (it never wraps the
response body, so the MCP SSE transport is untouched) enforcing, in order:

1. ``/api/agent_report`` is the ONE route open to non-loopback peers —
   ``POST`` with ``Content-Type: application/json`` only (the agent sends
   exactly that). Its payload is validated by the route itself.
2. Every other request must come from a loopback address or from a CIDR in
   ``mcp.remote_cidrs`` (default: none) — else ``403``.
3. ``Host`` must be an IP literal, ``localhost``, this machine's hostname
   or a name in ``mcp.allowed_hosts`` — a DNS-rebinding page
   (``evil.example`` resolving to 127.0.0.1) is refused.
4. ``Origin``, when present (browsers send it on POST and on every
   WebSocket handshake), must be same-origin with ``Host`` — cross-site
   fetches and cross-site WebSockets are refused.
5. When ``mcp.auth_token`` is set: ``Authorization: Bearer <token>`` (or
   the ``pry_token`` cookie the dashboard login sets) is required.
   ``GET /?token=<token>`` sets that cookie (HttpOnly, SameSite=Strict)
   and redirects, so the browser dashboard keeps working.
6. ``POST``/``PUT``/``PATCH`` must be ``application/json`` (a body-less
   POST is allowed only without an ``Origin``, i.e. from a non-browser
   client).
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import socket
from typing import Any, Iterable
from urllib.parse import parse_qs, urlencode, urlsplit

_log = logging.getLogger(__name__)

BEACON_PATH = "/api/agent_report"
TOKEN_COOKIE = "pry_token"


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    s = str(text or "").strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    try:
        a = ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        return a.ipv4_mapped
    return a


def is_loopback(addr: str) -> bool:
    a = _ip(addr)
    return bool(a is not None and a.is_loopback)


def _split_host(host_header: str) -> str:
    """``name:port`` / ``[v6]:port`` / ``name`` -> lowercase host part."""
    h = str(host_header or "").strip().lower()
    if h.startswith("["):
        end = h.find("]")
        return h[1:end] if end > 0 else h
    if h.count(":") == 1:
        return h.rsplit(":", 1)[0]
    return h


def _parse_nets(cidrs: Iterable[str]) -> list:
    nets = []
    for c in cidrs or []:
        try:
            nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            _log.warning("control plane: ignoring malformed mcp.remote_cidrs "
                         "entry %r", c)
    return nets


def _local_names() -> set[str]:
    names = {"localhost"}
    try:
        hn = socket.gethostname().strip().lower()
        if hn:
            names.update({hn, f"{hn}.local"})
    except OSError:
        pass
    return names


class ControlPlaneGuard:
    """See the module docstring. Construct with the FastAPI/Starlette app
    (``app.add_middleware(ControlPlaneGuard, cfg=cfg)``)."""

    def __init__(self, app, cfg: Any = None, *, remote_cidrs=None,
                 auth_token: str | None = None,
                 allowed_hosts: Iterable[str] | None = None) -> None:
        self.app = app
        mcp = getattr(cfg, "mcp", None)
        self.remote_nets = _parse_nets(
            remote_cidrs if remote_cidrs is not None
            else getattr(mcp, "remote_cidrs", []) or [])
        tok = auth_token if auth_token is not None \
            else str(getattr(mcp, "auth_token", "") or "")
        self.token = os.path.expandvars(tok).strip()
        if "${" in self.token or self.token.startswith("$"):
            # An unresolved ${VAR} stays the literal token rather than
            # silently disabling auth (loopback/CIDR gating still applies).
            _log.warning("control plane: mcp.auth_token references an unset "
                         "environment variable (%s) — requests must send "
                         "that literal value until it is set", tok)
        self.allowed_hosts = _local_names() | {
            str(h).strip().lower() for h in (
                allowed_hosts if allowed_hosts is not None
                else getattr(mcp, "allowed_hosts", []) or [])
            if str(h).strip()}

    # ------------------------------------------------------------ checks ----

    def peer_allowed(self, peer: str) -> bool:
        if is_loopback(peer):
            return True
        a = _ip(peer)
        if a is None:
            return False
        return any(a.version == n.version and a in n for n in self.remote_nets)

    def host_allowed(self, host_header: str | None) -> bool:
        if not host_header:
            return True            # HTTP/1.0 or a raw client; browsers always send Host
        h = _split_host(host_header)
        if _ip(h) is not None:
            return True            # an IP literal cannot be DNS-rebound
        return h in self.allowed_hosts or h.endswith(".localhost")

    @staticmethod
    def origin_allowed(origin: str, host_header: str | None) -> bool:
        if not origin or origin.strip().lower() == "null":
            return False
        parts = urlsplit(origin.strip())
        if parts.scheme not in ("http", "https", "ws", "wss") or not parts.netloc:
            return False
        return parts.netloc.lower() == str(host_header or "").strip().lower()

    def token_ok(self, headers: dict[str, str]) -> bool:
        if not self.token:
            return True
        auth = headers.get("authorization", "")
        if auth[:7].lower() == "bearer " and hmac.compare_digest(
                auth[7:].strip().encode(), self.token.encode()):
            return True
        cookie = _cookie(headers.get("cookie", ""), TOKEN_COOKIE)
        return bool(cookie) and hmac.compare_digest(
            cookie.encode(), self.token.encode())

    # -------------------------------------------------------------- ASGI ----

    async def __call__(self, scope, receive, send):
        kind = scope.get("type")
        if kind not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or ""
        headers = _headers(scope)
        method = str(scope.get("method") or "GET").upper()
        client = scope.get("client") or ("", 0)
        peer = str(client[0] if client else "")

        if path == BEACON_PATH:
            if kind != "http":
                return await _deny(scope, send, 403, "forbidden",
                                   "agent_report is HTTP POST only")
            if method != "POST":
                return await _deny(scope, send, 405, "method_not_allowed",
                                   "agent_report accepts POST only")
            if not _is_json(headers.get("content-type", "")):
                return await _deny(scope, send, 415, "unsupported_media_type",
                                   "agent_report requires Content-Type: "
                                   "application/json")
            await self.app(scope, receive, send)
            return

        if not self.peer_allowed(peer):
            return await _deny(
                scope, send, 403, "forbidden",
                f"the orchestrator control plane answers loopback clients "
                f"only (peer {peer or '?'}); add the network to "
                "mcp.remote_cidrs to allow it — only /api/agent_report is "
                "open to the LAN")
        host = headers.get("host")
        if not self.host_allowed(host):
            return await _deny(
                scope, send, 403, "forbidden_host",
                f"Host {host!r} is not an IP literal, localhost or a name "
                "in mcp.allowed_hosts (DNS-rebinding guard)")
        origin = headers.get("origin")
        if origin is not None and not self.origin_allowed(origin, host):
            return await _deny(
                scope, send, 403, "forbidden_origin",
                f"cross-origin request from {origin!r} refused")
        if self.token and not self.token_ok(headers):
            if kind == "http" and method == "GET":
                login = self._login_redirect(scope)
                if login is not None:
                    await _send_raw(send, *login)
                    return
            return await _deny(
                scope, send, 401, "unauthorized",
                "mcp.auth_token is set: send 'Authorization: Bearer <token>' "
                "(browsers: open /?token=<token> once)")
        if kind == "http" and method in ("POST", "PUT", "PATCH"):
            ctype = headers.get("content-type", "")
            if ctype and not _is_json(ctype):
                return await _deny(scope, send, 415, "unsupported_media_type",
                                   "control-plane writes require "
                                   "Content-Type: application/json")
            if not ctype and origin is not None:
                return await _deny(scope, send, 415, "unsupported_media_type",
                                   "browser POST without a JSON content "
                                   "type refused")
        await self.app(scope, receive, send)

    def _login_redirect(self, scope) -> tuple[int, list, bytes] | None:
        qs = parse_qs((scope.get("query_string") or b"").decode("latin-1"))
        got = (qs.get("token") or [""])[0]
        if not got or not hmac.compare_digest(got.encode(), self.token.encode()):
            return None
        rest = {k: v for k, v in qs.items() if k != "token"}
        loc = (scope.get("path") or "/") + (
            "?" + urlencode(rest, doseq=True) if rest else "")
        cookie = (f"{TOKEN_COOKIE}={self.token}; HttpOnly; SameSite=Strict; "
                  "Path=/")
        return 303, [(b"location", loc.encode("latin-1")),
                     (b"set-cookie", cookie.encode("latin-1")),
                     (b"cache-control", b"no-store")], b""


def _headers(scope) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in scope.get("headers") or []:
        name = k.decode("latin-1").lower()
        val = v.decode("latin-1")
        if name in out:
            sep = "; " if name == "cookie" else ", "
            out[name] = f"{out[name]}{sep}{val}"
        else:
            out[name] = val
    return out


def _cookie(header: str, name: str) -> str:
    for part in str(header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v.strip()
    return ""


def _is_json(ctype: str) -> bool:
    main = str(ctype or "").split(";", 1)[0].strip().lower()
    return main == "application/json" or (
        main.startswith("application/") and main.endswith("+json"))


async def _send_raw(send, status: int, headers: list, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status,
                "headers": headers + [(b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


async def _deny(scope, send, status: int, kind: str, error: str) -> None:
    _log.warning("control plane refused %s %s from %s: %s",
                 scope.get("method") or scope.get("type"), scope.get("path"),
                 (scope.get("client") or ("?",))[0], error)
    if scope.get("type") == "websocket":
        # Closing before accept rejects the handshake (HTTP 403).
        await send({"type": "websocket.close", "code": 1008})
        return
    body = json.dumps({"ok": False, "kind": kind, "error": error}).encode()
    await _send_raw(send, status, [(b"content-type", b"application/json")], body)


__all__ = ["BEACON_PATH", "ControlPlaneGuard", "TOKEN_COOKIE", "is_loopback"]
