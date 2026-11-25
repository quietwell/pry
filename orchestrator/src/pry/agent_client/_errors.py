"""Kit-wide gRPC error normalization.

The per-tool wrappers in this package all route through :meth:`AgentClient._call`
to reach the agent. Without this layer, a dropped channel / timed-out RPC surfaced
in the MCP envelope as the raw :class:`grpc.aio.AioRpcError` ``str()`` form,
which contains the gRPC debug-string (noise the LLM has no use for and often
re-litigates). The debug surface got its own per-verb normalization
via ``_error_enrich.py``; this module ports the same shape kit-wide.

The decorator catches :class:`grpc.aio.AioRpcError` raised from ``_call`` and
re-raises an :class:`AgentRpcError` whose ``str()`` form is the clean
``"<MAPPED_KIND>: <details>"`` the orchestrator's existing
``enrich_error`` pattern matcher already understands, and whose ``.payload``
attribute carries the structured envelope the plan specifies
(``{"ok": False, "kind", "error", "hint"}``) so downstream code may lift it
directly.
"""

from __future__ import annotations

import functools
from typing import Any, Awaitable, Callable

import grpc


# ---------------------------------------------------------------------------
# Mapping tables — keep in sync with the plan's §4 Agent 5 bullet (E1).
# ---------------------------------------------------------------------------

_STATUS_KIND: dict[grpc.StatusCode, str] = {
    grpc.StatusCode.DEADLINE_EXCEEDED:  "deadline",
    grpc.StatusCode.CANCELLED:          "cancelled",
    grpc.StatusCode.UNAVAILABLE:        "unavailable",
    grpc.StatusCode.UNAUTHENTICATED:    "unauth",
    grpc.StatusCode.PERMISSION_DENIED:  "forbidden",
    grpc.StatusCode.INVALID_ARGUMENT:   "bad_arg",
    grpc.StatusCode.NOT_FOUND:          "not_found",
    grpc.StatusCode.FAILED_PRECONDITION: "precondition",
    grpc.StatusCode.ALREADY_EXISTS:     "exists",
    # the agent on this view serves no such RPC (old build, or the
    # umagent view lacking the service) — same slug the MCP enrich layer
    # uses for a bare UNIMPLEMENTED.
    grpc.StatusCode.UNIMPLEMENTED:      "not_supported",
}

_STATUS_HINT: dict[grpc.StatusCode, str] = {
    grpc.StatusCode.UNAVAILABLE:
        "agent connection lost — check target_manage(action='status') "
        "or reconnect",
    grpc.StatusCode.DEADLINE_EXCEEDED:
        "RPC exceeded its deadline — try again with a longer timeout",
    grpc.StatusCode.CANCELLED:
        "RPC was cancelled",
    grpc.StatusCode.UNAUTHENTICATED:
        "agent token mismatch — check config.toml agent.token",
    grpc.StatusCode.PERMISSION_DENIED:
        "agent refused: permission denied",
    grpc.StatusCode.UNIMPLEMENTED:
        "the agent on this view does not implement this RPC — use the "
        "'<machine>.kernel' view or redeploy a current agent build",
}

#: Detail used when a call raced a channel close (link heal / reconnect
#: re-pointing the client). Classified like UNAVAILABLE: retryable.
CHANNEL_CLOSED_DETAIL = ("channel closed (the view is being re-pointed or "
                         "was disconnected) — retry the call")


def _map_grpc_status(code: grpc.StatusCode | None) -> str:
    """Map a ``grpc.StatusCode`` to the stable kind slug used in envelopes."""
    if code is None:
        return "unknown"
    return _STATUS_KIND.get(code, "unknown")


def _hint_for(code: grpc.StatusCode | None) -> str:
    """One-line next-step hint for a status code, or ``""``."""
    if code is None:
        return ""
    return _STATUS_HINT.get(code, "")


# ---------------------------------------------------------------------------
# Typed exception carrying the clean envelope.
# ---------------------------------------------------------------------------


class AgentRpcError(RuntimeError):
    """Clean gRPC error raised in place of :class:`grpc.aio.AioRpcError`.

    ``str(exc)`` is the ``"<MAPPED_KIND>: <details>"`` form — stable enough
    for :func:`pry.mcp._error_enrich.enrich_error`'s existing pattern
    matcher to classify (e.g. "UNAVAILABLE: ..." already triggers
    ``channel_unavailable``). ``.payload`` carries the structured envelope
    for callers that want to skip the regex pass.
    """

    def __init__(
        self,
        kind: str,
        error: str,
        hint: str = "",
        *,
        code: grpc.StatusCode | None = None,
    ) -> None:
        self.kind = kind
        self.hint = hint
        self.error_text = error
        self.code = code
        # Build a classifier-friendly message:
        #   - prepend the gRPC code name so enrich_error's UNAVAILABLE /
        #     DEADLINE_EXCEEDED regex matches unchanged.
        #   - then the server's details() (quiet when empty).
        code_name = code.name if code is not None else kind.upper()
        pretty = f"{code_name}: {error}" if error else code_name
        super().__init__(pretty)

    @property
    def payload(self) -> dict[str, Any]:
        """The ``{ok, kind, error, hint}`` envelope the plan specifies."""
        env: dict[str, Any] = {
            "ok": False,
            "kind": self.kind,
            "error": self.error_text,
        }
        if self.hint:
            env["hint"] = self.hint
        return env


# ---------------------------------------------------------------------------
# Decorator applied at the _call call site.
# ---------------------------------------------------------------------------


def normalize_aio_errors(
    fn: Callable[..., Awaitable[Any]],
) -> Callable[..., Awaitable[Any]]:
    """Wrap ``fn`` so ``grpc.aio.AioRpcError`` becomes :class:`AgentRpcError`.

    Applied once at :meth:`AgentClient._call`; every per-tool wrapper that
    goes through ``_call`` inherits the normalized error path with no
    per-method changes. The success path is untouched — the wrapper's
    normal-path code (``msg.status.ok`` dereferences and proto-to-dict
    conversions) is completely unchanged.

    :class:`grpc.RpcError` (sync) subclasses are translated the same way so
    any lingering sync stub call also normalizes.
    """

    @functools.wraps(fn)
    async def _wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return await fn(*args, **kwargs)
        except (grpc.aio.AioRpcError, grpc.RpcError, grpc.aio.UsageError) as exc:
            raise to_agent_error(exc) from exc

    return _wrapped


def to_agent_error(exc: BaseException) -> "AgentRpcError | BaseException":
    """Translate a gRPC transport exception into :class:`AgentRpcError`.

    Shared by the unary ``_call`` decorator and the streaming helper, so
    both surfaces raise the same clean, classifiable error. A
    ``grpc.aio.UsageError`` ("Channel is closed" — a call that raced a
    link-heal rebind or a reconnect) becomes a retryable UNAVAILABLE
    instead of an opaque internal error. Anything else is returned as-is.
    """
    if isinstance(exc, AgentRpcError):
        return exc
    if isinstance(exc, grpc.aio.UsageError):
        code = grpc.StatusCode.UNAVAILABLE
        return AgentRpcError(kind=_map_grpc_status(code),
                             error=f"{CHANNEL_CLOSED_DETAIL} ({exc})",
                             hint=_hint_for(code), code=code)
    if isinstance(exc, grpc.aio.AioRpcError):
        code = exc.code()
        return AgentRpcError(kind=_map_grpc_status(code),
                             error=exc.details() or "",
                             hint=_hint_for(code), code=code)
    if isinstance(exc, grpc.RpcError):   # sync RpcError sibling
        code = None
        try:
            code = exc.code()
        except Exception:  # noqa: BLE001 — some sync errors lack .code()
            code = None
        try:
            details = exc.details() or ""
        except Exception:  # noqa: BLE001
            details = str(exc)
        return AgentRpcError(kind=_map_grpc_status(code), error=details,
                             hint=_hint_for(code), code=code)
    return exc


__all__ = [
    "AgentRpcError",
    "CHANNEL_CLOSED_DETAIL",
    "normalize_aio_errors",
    "to_agent_error",
    "_map_grpc_status",
    "_hint_for",
]
