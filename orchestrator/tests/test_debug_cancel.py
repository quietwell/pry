"""debug_manage(action='cancel').

Envelope-shape loopback: the dispatcher routes `cancel` through the
mutation gate, calls `AgentClient.debug_cancel`, mirrors the
`state` echo, and releases the caller's lease on success.

The full agent-side `SetInterrupt` path is exercised by the lab
smoke matrix (`an internal plan` §6.1);
this test only proves the orchestrator plumbing.
"""
from __future__ import annotations

import json as _json
from typing import Any

import pytest

from test_debug_state_loop import (
    _FakeAgentClient,
    _call,
    _connect,
    _server,
)


class _CancelFakeClient(_FakeAgentClient):
    """Fake adds `debug_cancel` and makes the wait-family wrappers
    accept the ``include_context`` kwarg."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.cancel_calls: list[int] = []
        self.include_context_seen: dict[str, bool] = {}

    async def debug_cancel(self, pid: int = 0) -> dict[str, Any]:
        self.cancel_calls.append(int(pid))
        self._session.update(active=True, stopped=True,
                             stop_reason="pause")
        return {"ok": True, "state": self._state(reason="pause")}

    # Wait-family: accept and record the include_context flag.
    async def debug_status(self, *, include_context: bool = False):
        self.include_context_seen["status"] = bool(include_context)
        return await super().debug_status()

    async def debug_run(self, timeout_ms: int, *,
                        include_context: bool = False):
        self.include_context_seen["run"] = bool(include_context)
        return await super().debug_run(timeout_ms)

    async def debug_wait(self, timeout_ms: int, *,
                        include_context: bool = False):
        self.include_context_seen["wait"] = bool(include_context)
        return await super().debug_wait(timeout_ms)

    async def debug_run_to(self, address: int, timeout_ms: int, *,
                          include_context: bool = False):
        self.include_context_seen["run_to"] = bool(include_context)
        return await super().debug_run_to(address, timeout_ms)

    async def debug_pause(self, timeout_ms: int, *,
                          include_context: bool = False):
        self.include_context_seen["pause"] = bool(include_context)
        return await super().debug_pause(timeout_ms)

    async def debug_step_out(self, timeout_ms: int, *,
                             include_context: bool = False):
        self.include_context_seen["step_out"] = bool(include_context)
        return await super().debug_step_out(timeout_ms)

    async def debug_continue(self, *, include_context: bool = False):
        self.include_context_seen["continue"] = bool(include_context)
        return await super().debug_continue()

    async def debug_step(self, over: bool = False, count: int = 1, *,
                         include_context: bool = False):
        self.include_context_seen["step"] = bool(include_context)
        return await super().debug_step(over=over, count=count)


async def test_cancel_action_in_enum(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_CancelFakeClient)
    tools = {t.name: t for t in await server.list_tools()}
    enum = set(tools["debug_manage"].parameters["properties"]["action"]["enum"])
    assert "cancel" in enum


async def test_cancel_round_trips_state(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_CancelFakeClient)
    await _connect(server)

    launch = await _call(server, "debug_manage",
                         {"action": "launch",
                          "cmdline": r"C:\lab\victim.exe"})
    assert launch.get("ok") is not False, launch

    body = await _call(server, "debug_manage", {"action": "cancel"})
    assert body.get("ok") is not False, body
    state = body.get("state") or {}
    assert state.get("stop_reason") == "pause", state
    assert state.get("stopped") is True


async def test_include_context_threads_through(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_CancelFakeClient)
    await _connect(server)
    await _call(server, "debug_manage",
                {"action": "launch", "cmdline": r"C:\lab\victim.exe"})

    # Default: include_context=False threaded through to every
    # wait-family wrapper.
    await _call(server, "debug_manage", {"action": "status"})
    await _call(server, "debug_manage", {"action": "run", "timeout_s": 1})

    client = ctx.session.require_client("")
    assert client.include_context_seen.get("status") is False
    assert client.include_context_seen.get("run") is False

    # Opt-in on a single verb.
    await _call(server, "debug_manage",
                {"action": "run", "timeout_s": 1,
                 "include_context": True})
    assert client.include_context_seen.get("run") is True
