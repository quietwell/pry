"""CallerAttributionMiddleware uses the TCP endpoint as fallback.

Previously, when the client did NOT send an ``Mcp-Session-Id`` header,
every tool call synthesised a fresh ``anon-<host>-<hex>-<ns>`` id. For a
client like Claude Code's MCP binding — which keeps the TCP connection
alive but neither sends nor echoes the session header — every call
looked like a NEW peer. Leases taken under one call's id were orphaned
the moment the call returned, because the next call's caller id was
already different, and ``release_peer(peer_id=<own>)`` could never
self-match.

The middleware now consults the client's ``(host, port)`` tuple
between the header check and the per-call synthesis fallback. The remote
TCP port is stable for the lifetime of a keep-alive HTTP socket, so every
tool call made on the same connection gets the same identity. Clients
that DO send ``Mcp-Session-Id`` (spec-compliant MCP SDKs) are unaffected
and still get their explicit id honored.

Live-verified on the lab against Claude Code's MCP binding — three
``whoami`` calls in a row returned the same ``anon-127.0.0.1:62740`` id.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from pry.caller import (
    CLIENT_ID,
    CallerAttributionMiddleware,
    _client_endpoint,
    _resolve_client_id,
)

from _multi_fakes import _FakeRequest


# --------------------------------------------------------------------------- #
# _resolve_client_id — unit-level
# --------------------------------------------------------------------------- #


def test_header_still_wins() -> None:
    """When the client DOES send an ``Mcp-Session-Id`` header, we still
    honor it ahead of the TCP-endpoint fallback. Header is the client's
    explicit, documented choice."""
    req = _FakeRequest({"Mcp-Session-Id": "peer-explicit"},
                       host="1.2.3.4", port=55555)
    assert _resolve_client_id(req, None) == "peer-explicit"


def test_no_header_uses_tcp_endpoint() -> None:
    """No header + TCP endpoint present → use ``anon-<host>:<port>``."""
    req = _FakeRequest({}, host="127.0.0.1", port=62740)
    assert _resolve_client_id(req, None) == "anon-127.0.0.1:62740"


def test_endpoint_stable_across_calls() -> None:
    """Two requests from the SAME ``(host, port)`` tuple — i.e. the same
    keep-alive TCP connection — produce the same client id. This is the
    core invariant the patch delivers."""
    req_a = _FakeRequest({}, host="10.0.0.5", port=54321)
    req_b = _FakeRequest({}, host="10.0.0.5", port=54321)
    assert _resolve_client_id(req_a, None) == _resolve_client_id(req_b, None)


def test_different_connections_different_ids() -> None:
    """Two requests from the same HOST but different ports — i.e. two
    separate TCP connections — are correctly treated as different
    peers. This is intentional: each connection is its own session.
    A client that pools connections would surface as multiple peers;
    that is the right modeling because the server has no cross-connection
    stickiness to lean on."""
    req_a = _FakeRequest({}, host="127.0.0.1", port=62740)
    req_b = _FakeRequest({}, host="127.0.0.1", port=62741)
    assert _resolve_client_id(req_a, None) != _resolve_client_id(req_b, None)


def test_no_endpoint_falls_back_to_synthesis() -> None:
    """No header AND no TCP endpoint (STDIO / in-memory transport) →
    fall back to per-call synthesis so we still stamp something."""
    cid = _resolve_client_id(_FakeRequest({}, host="10.0.0.5"), None)
    # host but no port → endpoint parser returns None → synthesis path.
    assert cid.startswith("anon-10.0.0.5-")
    parts = cid.split("-")
    assert len(parts) >= 4  # <host>-<hex>-<ns>


def test_no_request_at_all_falls_back_to_synthesis() -> None:
    """``register_client_id(None)`` → synthesis with ``local`` host."""
    cid = _resolve_client_id(None, None)
    assert cid.startswith("anon-local-")


def test_client_endpoint_parser_rejects_missing_port() -> None:
    req = _FakeRequest({}, host="127.0.0.1")  # no port
    assert _client_endpoint(req) is None


def test_client_endpoint_parser_returns_tuple() -> None:
    req = _FakeRequest({}, host="127.0.0.1", port=8080)
    assert _client_endpoint(req) == ("127.0.0.1", 8080)


# --------------------------------------------------------------------------- #
# Middleware-level integration (CLIENT_ID binding stability)
# --------------------------------------------------------------------------- #


async def _run_middleware_once(monkeypatch, request_obj) -> str:
    """Invoke the real middleware against a fake request (via
    monkeypatching ``get_http_request``) and return the ``CLIENT_ID``
    seen inside the call_next body."""
    import pry.caller as caller_mod
    monkeypatch.setattr(caller_mod, "get_http_request",
                         lambda: request_obj)

    mw = CallerAttributionMiddleware()
    seen: dict[str, str] = {}

    async def _fake_call_next(_: Any) -> str:
        seen["client_id"] = CLIENT_ID.get()
        return "ok"

    # context argument is ignored in the new resolver.
    result = await mw.on_call_tool(object(), _fake_call_next)  # type: ignore[arg-type]
    assert result == "ok"
    return seen["client_id"]


async def test_middleware_stable_id_across_calls(monkeypatch) -> None:
    """Two tool calls on the SAME keep-alive connection
    (same ``(host, port)``) see the SAME client id. The pre-patch
    behaviour returned a fresh id per call; a lease taken on
    call 1 could never be matched by self-id on call 2."""
    req = _FakeRequest({}, host="127.0.0.1", port=62740)
    cid1 = await _run_middleware_once(monkeypatch, req)
    cid2 = await _run_middleware_once(monkeypatch, req)
    assert cid1 == cid2
    assert cid1 == "anon-127.0.0.1:62740"


async def test_middleware_header_takes_precedence(monkeypatch) -> None:
    """Spec-compliant clients that DO send ``Mcp-Session-Id`` still
    get their explicit id, not the TCP endpoint."""
    req = _FakeRequest({"Mcp-Session-Id": "mcp-client-42"},
                       host="127.0.0.1", port=62740)
    cid = await _run_middleware_once(monkeypatch, req)
    assert cid == "mcp-client-42"


async def test_middleware_fresh_synthesis_without_endpoint(monkeypatch) -> None:
    """With neither header nor TCP endpoint, we still land on the
    per-call synthesis path. This covers STDIO / in-memory transports
    where the server simply has no stable identity to pin to."""
    # No port → no endpoint → synthesis fallback.
    req = _FakeRequest({}, host="127.0.0.1")
    cid1 = await _run_middleware_once(monkeypatch, req)
    cid2 = await _run_middleware_once(monkeypatch, req)
    assert cid1.startswith("anon-127.0.0.1-")
    assert cid2.startswith("anon-127.0.0.1-")
    # Different per-call suffixes.
    assert cid1 != cid2
