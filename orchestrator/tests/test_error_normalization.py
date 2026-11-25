"""kit-wide ``AioRpcError`` normalization.

Agent 5's `@normalize_aio_errors` decorator wraps every `_call` in a
try/except that translates `grpc.aio.AioRpcError` to a dict shaped
`{ok:false, kind:<mapped>, hint:<mapped>, error:<str>}`. This test
pokes the decorator with a fake `AioRpcError` and asserts the
envelope shape — independent of a live gRPC channel.

Marked skip when the decorator has not yet landed in the branch
(fork-parallelism tolerance); the acceptance gate is "exists when the
integrator merges Agent 5's work".
"""
from __future__ import annotations

from typing import Any

import pytest


def _import_decorator():
    try:
        from pry.agent_client import _errors as _mod
    except ImportError:
        pytest.skip("agent_client._errors not yet landed (parallel "
                    "fork in progress)")
    dec = getattr(_mod, "normalize_aio_errors", None)
    if dec is None:
        pytest.skip("normalize_aio_errors not exported yet")
    return dec


async def test_normalize_aio_errors_translates_to_envelope():
    """The decorator must either RETURN the envelope dict or RAISE a typed
    carrier whose ``.payload`` is the same dict. The integrator picked the
    typed-exception shape (``AgentRpcError``) because the per-method
    wrappers read ``msg.status.ok`` off a proto response on the happy path
    — a dict return would break every call site. The MCP tool-dispatch
    ``_guard`` catches the exception and runs the classifier regex over
    ``str(exc)`` ("UNAVAILABLE: ...") so the end-to-end envelope shape
    the plan specifies still reaches the caller.

    This test accepts either delivery: a dict return or an
    ``AgentRpcError`` whose ``.payload`` has the same shape."""
    dec = _import_decorator()

    try:
        import grpc
    except ImportError:
        pytest.skip("grpc not importable in this env")

    from pry.agent_client import _errors as _mod
    _AgentRpcError = getattr(_mod, "AgentRpcError", None)

    class _FakeAioErr(grpc.aio.AioRpcError):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__(
                code=grpc.StatusCode.UNAVAILABLE,
                initial_metadata=None, trailing_metadata=None,
                details="channel closed")

    @dec
    async def _call(self, *args, **kwargs):
        raise _FakeAioErr()

    out: Any
    raised: BaseException | None = None
    try:
        out = await _call(object())
    except BaseException as exc:  # noqa: BLE001 — accept typed-carrier
        raised = exc
        out = None

    if raised is not None:
        assert _AgentRpcError is not None and isinstance(
            raised, _AgentRpcError
        ), f"raised unexpected exception: {type(raised).__name__}: {raised}"
        payload = raised.payload
        assert isinstance(payload, dict), payload
        assert payload.get("ok") is False
        assert payload.get("kind") in {"unavailable",
                                        "channel_unavailable",
                                        "unreachable"}, payload
        assert "hint" in payload
        assert "error" in payload
        # The str() form also must be classifier-friendly so `_guard` can
        # fall through to `enrich_error` on the generic `except Exception`.
        assert str(raised).startswith("UNAVAILABLE"), str(raised)
        return

    assert isinstance(out, dict), out
    assert out.get("ok") is False
    assert out.get("kind") in {"unavailable", "channel_unavailable",
                                 "unreachable"}, out
    assert "hint" in out
    assert "error" in out
