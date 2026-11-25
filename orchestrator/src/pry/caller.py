"""Per-tool-call caller attribution for the pry orchestrator.

Every MCP tool dispatch is stamped with a stable ``client_id`` string that
downstream code (the findings ledger, the audit log, rate limiters) can read
without threading it through every function signature. The id is exposed as
a ContextVar so it is safe under asyncio fan-out inside a single tool call.

Mechanism
---------
FastMCP 4.0.1 ships a first-class middleware chain
(``fastmcp.server.middleware.Middleware``); its ``on_call_tool`` hook fires
exactly once per JSON-RPC ``tools/call`` dispatch (see
``FastMCP._dispatch_component_middleware`` in
``.venv/Lib/site-packages/fastmcp/server/server.py``). Binding the ContextVar
in that hook — and resetting it in a ``finally`` — is the smallest scope
that survives async fan-out inside a single tool body without leaking across
pipelined messages on the same Streamable-HTTP connection.

We deliberately do NOT install this as a Starlette ``BaseHTTPMiddleware``:
FastMCP's own module docs (``server.py:54-68``) note that BaseHTTPMiddleware
interferes with SSE/streaming responses, and a per-HTTP-connection hook
cannot cleanly scope a ContextVar to a single tool call when clients
pipeline multiple JSON-RPC messages over one connection.

Public surface
--------------
* ``CLIENT_ID`` — the ContextVar itself (default ``"anonymous"``).
* ``current_client_id()`` — always-safe reader used by tool code.
* ``register_client_id(request)`` — pure extraction helper, unit-testable
  against a mock Starlette request.
* ``install_caller_middleware(app_or_server)`` — one-shot wiring called
  from ``pry.server.build_app`` before the MCP app is mounted.
* ``ConnectionTracker`` — pure-ASGI middleware that tells keep-alive TCP
  connections apart when a client sends no ``Mcp-Session-Id`` (see below).
* ``spawn_background(coro, ...)`` — start an orchestrator background task
  in a FRESH contextvars context (never as the chat that triggered it).

Identity without ``Mcp-Session-Id`` (trade-off)
--------------------------------------------------------
Spec-compliant clients echo the ``Mcp-Session-Id`` the server issued at
``initialize``; that id is per chat and always wins. A client that sends
none can only be identified by its TCP connection. The remote ``(host,
port)`` alone is NOT a safe key: uvicorn closes an idle keep-alive socket
after ``KEEPALIVE_S`` and the client OS may later reuse the same ephemeral
port for a *different* chat, which would then silently inherit the first
chat's focus machine and debug leases.

The fallback id is therefore ``anon-<host>:<port>`` for the first
connection seen on that endpoint and ``anon-<host>:<port>#<n>`` for each
later one: when a request arrives on an endpoint that has been idle (no
request in flight, last one finished) for longer than the server's
keep-alive window, the old socket is provably closed, so this is a new
connection and gets a new generation. Trade-off chosen: a session-less
client's focus/leases live exactly as long as one keep-alive connection
(a chat pausing > ``KEEPALIVE_S`` between calls becomes a new anonymous
peer and, with several machines connected, must pass ``name=`` again or
re-``use``) — fail-closed (``ambiguous_target``) instead of handing it
another chat's machine. Clients that want focus to persist must echo
``Mcp-Session-Id``.
"""

from __future__ import annotations

import asyncio
import contextvars
import os
import re
import time
from contextvars import ContextVar, Token
from typing import Any, Coroutine, Protocol

from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

__all__ = [
    "CLIENT_ID",
    "CallerAttributionMiddleware",
    "ConnectionTracker",
    "KEEPALIVE_S",
    "current_client_id",
    "install_caller_middleware",
    "is_anonymous_id",
    "register_client_id",
    "spawn_background",
]

#: uvicorn's keep-alive idle timeout (server.py passes it explicitly so the
#: two stay in sync). An endpoint idle longer than this + margin has had its
#: socket closed by the server.
KEEPALIVE_S = 5.0
_GEN_GAP_S = KEEPALIVE_S + 1.0


# --- Public ContextVar ------------------------------------------------------

# ``"anonymous"`` is a stable sentinel so downstream keys (ledger rows,
# audit-log lines) never see ``None`` and so unattributed transports land in
# ONE bucket rather than a rotating UUID per call. The middleware overwrites
# it for every real tool dispatch.
CLIENT_ID: ContextVar[str] = ContextVar("pry_client_id", default="anonymous")


def current_client_id() -> str:
    """Return the caller id bound to the active dispatch.

    Never raises. Falls back to ``"anonymous"`` when no middleware has run
    (e.g. a maintenance job invoked from a REPL or a unit test that bypasses
    the MCP transport).
    """
    return CLIENT_ID.get()


def is_anonymous_id(client_id: str | None) -> bool:
    """True for ids that do not come from an ``Mcp-Session-Id`` header
    (connection-scoped ``anon-…`` ids and the ``anonymous`` default)."""
    cid = str(client_id or "")
    return cid == "anonymous" or cid.startswith("anon-")


def spawn_background(coro: Coroutine[Any, Any, Any], *, name: str,
                     owner: str = "orchestrator",
                     loop: asyncio.AbstractEventLoop | None = None
                     ) -> asyncio.Task:
    """Create a long-lived orchestrator task in a FRESH contextvars context.

    ``asyncio.create_task`` copies the creator's context, so a boot monitor
    / link watcher / event pump started from a tool call used to run as
    that chat for its whole life: its RPCs were attributed to the chat in
    ``recent_ops`` and anything it claimed (ownership tags, watchdog
    kickers) belonged to the chat. Here the task starts from an empty
    context with :data:`CLIENT_ID` bound to *owner* (``orchestrator:…``).
    """
    ctx = contextvars.Context()
    ctx.run(CLIENT_ID.set, owner)
    lp = loop or asyncio.get_running_loop()
    return lp.create_task(coro, name=name, context=ctx)


class _EndpointState:
    __slots__ = ("gen", "inflight", "last_end")

    def __init__(self) -> None:
        self.gen = 0
        self.inflight = 0
        self.last_end = 0.0


#: (host, port) -> connection generation bookkeeping. Bounded by pruning
#: endpoints idle for an hour.
_ENDPOINTS: dict[tuple[str, int], _EndpointState] = {}
_PRUNE_AFTER_S = 3600.0
_last_prune = [0.0]


def _endpoint_begin(host: str, port: int, now: float | None = None) -> int:
    """Note a request starting on ``(host, port)``; returns its connection
    generation (1 = first connection seen on that endpoint)."""
    now = time.monotonic() if now is None else now
    key = (str(host), int(port))
    st = _ENDPOINTS.get(key)
    if st is None:
        st = _ENDPOINTS[key] = _EndpointState()
    if st.gen == 0 or (st.inflight == 0 and st.last_end
                       and now - st.last_end > _GEN_GAP_S):
        st.gen += 1
    st.inflight += 1
    if now - _last_prune[0] > 60.0:
        _last_prune[0] = now
        for k, v in list(_ENDPOINTS.items()):
            if v.inflight == 0 and v.last_end and now - v.last_end > _PRUNE_AFTER_S:
                _ENDPOINTS.pop(k, None)
    return st.gen


def _endpoint_end(host: str, port: int, now: float | None = None) -> None:
    st = _ENDPOINTS.get((str(host), int(port)))
    if st is None:
        return
    st.inflight = max(0, st.inflight - 1)
    st.last_end = time.monotonic() if now is None else now


def _endpoint_gen(host: str, port: int) -> int:
    st = _ENDPOINTS.get((str(host), int(port)))
    return st.gen if st is not None and st.gen else 1


class ConnectionTracker:
    """Pure-ASGI middleware feeding the connection-generation bookkeeping
    for every HTTP request (not just ``tools/call``), so idle gaps are
    measured exactly the way uvicorn's keep-alive timer measures them.
    The generation is stamped into ``scope['pry_conn_gen']``."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not scope.get("client"):
            await self.app(scope, receive, send)
            return
        host, port = scope["client"][0], scope["client"][1]
        scope["pry_conn_gen"] = _endpoint_begin(host, port)
        try:
            await self.app(scope, receive, send)
        finally:
            _endpoint_end(host, port)


# --- Extraction (pure, unit-testable) ---------------------------------------

class _RequestLike(Protocol):
    """The subset of ``starlette.requests.Request`` we actually touch.

    Declared as a Protocol so tests can pass a lightweight stand-in without
    constructing a full Starlette request/scope pair.
    """

    @property
    def headers(self) -> Any: ...  # supports .get(name, default)

    @property
    def client(self) -> Any: ...   # .host attribute or None


def _synthesise_client_id(request: _RequestLike | None) -> str:
    """Build a stable-per-connection id when no Mcp-Session-Id header exists.

    Composition:
        ``anon-<remote-host>-<random-hex>-<time-ns>``

    * ``remote-host`` groups anonymous calls from the same peer.
    * ``os.urandom(4).hex()`` prevents two peers behind the same NAT from
      colliding within the same nanosecond.
    * ``time.time_ns()`` keeps ids monotonic across process restarts so log
      readers can order them.
    """
    host = "local"
    if request is not None:
        client = getattr(request, "client", None)
        if client is not None:
            host = getattr(client, "host", None) or "local"
    entropy = os.urandom(4).hex()
    stamp = time.time_ns()
    return f"anon-{host}-{entropy}-{stamp}"


def register_client_id(request: _RequestLike | None) -> str:
    """Resolve the caller id from a Starlette request-like object.

    Preference order:
      1. The streamable-HTTP ``Mcp-Session-Id`` header (case-insensitive).
      2. A synthesised ``anon-<host>-<hex>-<ns>`` id.

    Kept side-effect-free (no ContextVar writes, no logging) so unit tests
    can exercise the extraction without a running MCP server.
    """
    if request is not None:
        headers = getattr(request, "headers", None)
        if headers is not None:
            # Starlette's Headers.get is case-insensitive; a plain dict in a
            # test also works as long as it uses the lower-case spelling.
            session_id = headers.get("mcp-session-id")
            if session_id:
                return str(session_id)
    return _synthesise_client_id(request)


# --- Middleware -------------------------------------------------------------

class CallerAttributionMiddleware(Middleware):
    """Bind :data:`CLIENT_ID` for the duration of every ``tools/call``.

    Registered by :func:`install_caller_middleware`. Reads the caller id
    BEFORE dispatch (via :func:`register_client_id`) and resets the
    ContextVar in ``finally`` so an exception in the tool body cannot leak
    the id into the next pipelined call on the same connection.

    When the client does not send an ``Mcp-Session-Id`` header
    (e.g. the Claude Code binding, pre-standardization MCP clients), we
    now reach into FastMCP's own connection-stable session id instead of
    synthesising a fresh ``anon-<host>-<hex>-<ns>`` per call. Without
    this, every tool call looked like a NEW peer, so the per-pid debug
    leases ``debug_manage(attach)`` takes were owned by an id that would
    never show up again — ``release_peer`` self-match never matched,
    the lease reaper's 10-minute idle TTL was the only cleanup path,
    and the user had to pass ``force=true`` to clean up their own leak.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        # If the caller pre-bound CLIENT_ID to something other than the
        # "anonymous" default, honor it. In production every request lands
        # in a fresh Task where the ContextVar is still at its default, so
        # this branch only ever fires from in-process tests and dashboard
        # SDK calls that want to attribute themselves explicitly.
        if CLIENT_ID.get() != "anonymous":
            return await call_next(context)
        try:
            request = get_http_request()
        except RuntimeError:
            # STDIO / in-memory transports have no Starlette request; fall
            # through to the synthesis path so we still stamp something.
            request = None
        tracked = None
        scope = getattr(request, "scope", None)
        if not (isinstance(scope, dict) and "pry_conn_gen" in scope):
            # No ConnectionTracker in front (tests, embedded use): track the
            # gaps between tool calls instead.
            ep = _client_endpoint(request)
            if ep is not None:
                _endpoint_begin(*ep)
                tracked = ep
        client_id = _resolve_client_id(request, context)
        token: Token[str] = CLIENT_ID.set(client_id)
        try:
            return await call_next(context)
        finally:
            CLIENT_ID.reset(token)
            if tracked is not None:
                _endpoint_end(*tracked)


def _resolve_client_id(request: _RequestLike | None, context: Any) -> str:
    """Pick the caller id in preference order.

    Preference order:
      1. The ``Mcp-Session-Id`` request header, when the client sent one
         (every spec-compliant MCP client should echo the handshake id).
      2. ``anon-<host>:<port>`` — the client's remote TCP endpoint.
         For a keep-alive HTTP connection the ``(host, port)`` tuple is
         stable for the lifetime of the socket, so every tool call made
         on it shares one identity. This is the path Claude Code's MCP
         binding takes: it sets ``Connection: keep-alive`` but neither
         sends nor echoes ``Mcp-Session-Id``, so without this fallback
         every tool call looked like a NEW peer and the per-pid debug
         leases ``debug_manage(attach)`` takes were owned by an id that
         would never show up again.
      3. A synthesised ``anon-<host>-<hex>-<ns>`` id — fresh per call;
         last-resort when none of the above apply (STDIO / in-memory /
         exotic transports with no remote endpoint).

    ``context`` is kept in the signature for forward-compat (a future
    FastMCP release may expose a connection id we can reach here) but
    is unused today — the FastMCP-level ``session_id`` falls back to a
    per-call UUID exactly when the client skips the header, so it
    buys us nothing here.
    """
    del context  # unused today, see docstring
    # Step 1 — explicit header still wins.
    if request is not None:
        headers = getattr(request, "headers", None)
        if headers is not None:
            header_id = headers.get("mcp-session-id")
            if header_id:
                return str(header_id)
    # Step 2 — client app identity: remote host + User-Agent product token.
    # Claude Code sends no Mcp-Session-Id and recycles its keep-alive
    # connections every few minutes, so a per-connection id turned every
    # breakpoint / detached job / lease it created "foreign" to its own
    # next call (seen live 2026-11-24). Keying on (host, user agent) keeps
    # one client app stable while still separating different apps; two
    # chats of the same session-less app share an identity, which is the
    # lesser evil. MCP_ANON_IDENTITY=connection restores the old scheme.
    endpoint = _client_endpoint(request)
    if endpoint is not None and os.environ.get(
            "MCP_ANON_IDENTITY", "client").strip().lower() != "connection":
        ua = ""
        headers = getattr(request, "headers", None)
        if headers is not None:
            ua = str(headers.get("user-agent") or "").strip()
        if ua:
            slug = re.sub(r"[^A-Za-z0-9._/-]+", "_", ua.split()[0])[:48]
            return f"anon-{endpoint[0]}-{slug}"
    # Step 2b — TCP endpoint + connection generation. Stable per
    # keep-alive connection; a later connection that reuses the same
    # ephemeral port gets a new generation, so it can never inherit the
    # previous connection's focus / leases.
    if endpoint is not None:
        host, port = endpoint
        scope = getattr(request, "scope", None)
        gen = (scope.get("pry_conn_gen")
               if isinstance(scope, dict) else None) or _endpoint_gen(host, port)
        return f"anon-{host}:{port}" if int(gen) <= 1 \
            else f"anon-{host}:{port}#{int(gen)}"
    # Step 3 — last-resort per-call synthesis.
    return _synthesise_client_id(request)


def _client_endpoint(request: _RequestLike | None) -> tuple[str, int] | None:
    """Return the client's ``(host, port)`` tuple when the request has
    one, else None. For ASGI/Streamable-HTTP transports the port is the
    remote TCP port — stable for the socket's lifetime — so repeated
    tool calls on a keep-alive connection share one identity."""
    if request is None:
        return None
    client = getattr(request, "client", None)
    if client is None:
        return None
    host = getattr(client, "host", None)
    port = getattr(client, "port", None)
    if not host or port is None:
        return None
    try:
        return str(host), int(port)
    except (TypeError, ValueError):
        return None


def _remote_host(request: _RequestLike | None) -> str:
    """Extract the remote host from a request-like, or ``"local"``."""
    if request is None:
        return "local"
    client = getattr(request, "client", None)
    if client is None:
        return "local"
    return getattr(client, "host", None) or "local"


# --- Installation -----------------------------------------------------------

def install_caller_middleware(app_or_server: Any) -> CallerAttributionMiddleware:
    """Attach :class:`CallerAttributionMiddleware` to a FastMCP server.

    ``app_or_server`` is expected to be the ``FastMCP`` instance returned by
    ``pry.mcp.tools.build_server``. For symmetry with future refactors we
    also accept anything else that exposes an ``add_middleware`` method
    taking a single positional argument (the middleware instance);
    ``FastMCP.add_middleware`` matches that shape
    (``fastmcp/server/server.py:598``).

    Returns the middleware instance so callers can hold a reference (useful
    in tests that want to assert it was installed).
    """
    middleware = CallerAttributionMiddleware()
    add = getattr(app_or_server, "add_middleware", None)
    if add is None:
        raise TypeError(
            "install_caller_middleware requires an object with "
            "add_middleware(...); got "
            f"{type(app_or_server).__name__}"
        )
    add(middleware)
    return middleware
