"""debug_manage(attach) lease release on raise + release_peer self-release.

Covers the three reliability patches landed on top of the envelope
diet:

- Patch 1 (orchestrator): `debug_manage(action='attach')` now releases the
  pid lease on EVERY failure path, including an exception from the agent RPC
  itself (gRPC DEADLINE_EXCEEDED / CANCELLED / transport error). Before the
  patch the lease leaked, pinning the (view,pid) tuple until the
  reaper caught up ~10 min later.

- Patch 2 (agent, C++): `DbgSession::Attach` calls `EndSession(DEBUG_SESSION_END)`
  on an `AttachProcess` HRESULT failure so a wedged engine substate doesn't
  poison the next attach. The C++ side is exercised by the lab smoke matrix;
  this file covers only the orchestrator-side plumbing.

- Patch 3 (orchestrator): `target_manage(action='release_peer', peer_id=<own
  id>)` no longer requires `force=true`. Releasing someone ELSE still does.

The fake agent client and `_server` / `_call` helpers come from
`test_debug_state_loop` — the same shape used by every other debug_manage test.
"""
from __future__ import annotations

import json as _json
from typing import Any

import grpc
import pytest

from pry.caller import CLIENT_ID

from test_debug_state_loop import (
    _FakeAgentClient,
    _call,
    _connect,
    _server,
)


# --------------------------------------------------------------------------- #
# Patch 1 — lease release on debug_attach raise
# --------------------------------------------------------------------------- #


class _RaisingAttachFake(_FakeAgentClient):
    """Fake whose `debug_attach` raises a gRPC-shaped timeout the first
    time it is called, then succeeds on the retry. Mirrors the
    client-side DEADLINE_EXCEEDED path the real agent took in the
    incident report."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.attach_calls: list[int] = []
        self.raise_on_next_attach = True

    async def debug_attach(self, pid: int,
                           monitor: bool = False) -> dict[str, Any]:
        self.attach_calls.append(int(pid))
        if self.raise_on_next_attach:
            self.raise_on_next_attach = False
            # Any BaseException would do — pick the one the orchestrator
            # actually sees in the field: a gRPC-level DEADLINE_EXCEEDED.
            raise grpc.RpcError("simulated DEADLINE_EXCEEDED from fake")
        return await super().debug_attach(pid, monitor=monitor)


async def test_attach_exception_releases_lease(tmp_path, monkeypatch):
    """Previously `debug_manage(action='attach')` acquired the per-pid
    lease, then let a gRPC transport exception from the agent bubble up
    through `_guard` into an error envelope — WITHOUT releasing the
    lease. The next attach saw kind='busy' pinned to the caller's own
    client id until the lease reaper caught up ~10 min later.

    The try/except in debug_manage.attach releases the lease
    before re-raising, so `_guard` still turns the exception into an
    error envelope, but the lease is free. The follow-up attach then
    acquires it cleanly."""
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_RaisingAttachFake)
    await _connect(server)

    # First attach — the fake raises gRPC DEADLINE_EXCEEDED. `_guard`
    # catches it and surfaces a generic error envelope (ok=False).
    body = await _call(server, "debug_manage",
                       {"action": "attach", "pid": 1728})
    assert body.get("ok") is False, body

    # Patch 1 invariant: the lease must NOT be held after the raise.
    view = ctx.session.resolve_view_name("")
    assert ctx.leases is not None
    assert ctx.leases.who_holds(f"debug:{view}:pid=1728") is None, \
        "attach lease leaked when debug_attach raised"

    # The follow-up attach must succeed without a busy envelope.
    body = await _call(server, "debug_manage",
                       {"action": "attach", "pid": 1728})
    assert body.get("ok") is not False, body
    assert body.get("kind") != "busy", body

    # Lease is held by the current caller on the successful path.
    holder = ctx.leases.who_holds(f"debug:{view}:pid=1728")
    assert holder == "peer-A", holder


async def test_attach_returned_error_still_releases_lease(tmp_path, monkeypatch):
    """Regression: the earlier behavior where `ok=False` from the
    agent releases the lease must stay intact after the try/except
    wrapper landed around the RPC."""

    class _OkFalseFake(_FakeAgentClient):
        async def debug_attach(self, pid: int,
                               monitor: bool = False) -> dict[str, Any]:
            return {"ok": False, "error": "AttachProcess failed"}

    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_OkFalseFake)
    await _connect(server)

    body = await _call(server, "debug_manage",
                       {"action": "attach", "pid": 4242})
    assert body.get("ok") is False, body

    view = ctx.session.resolve_view_name("")
    assert ctx.leases is not None
    assert ctx.leases.who_holds(f"debug:{view}:pid=4242") is None, \
        "ok=False agent reply leaked the attach lease"


# --------------------------------------------------------------------------- #
# Patch 3 — release_peer self-release without force
# --------------------------------------------------------------------------- #


async def test_release_peer_self_without_force(tmp_path, monkeypatch):
    """A caller releasing its OWN lease table no longer needs
    force=true. Mirrors the incident where a wedged `attach` leaked a
    lease on the caller's own client id — the only recovery was
    release_peer(force=true, peer_id=<own>), which read as a missing
    feature because the error text said force is for "another peer's"
    leases."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    await _call(server, "debug_manage",
                {"action": "launch", "cmdline": r"C:\lab\victim.exe"})

    # Sanity: launch took a lease under the caller id "peer-A".
    view = ctx.session.resolve_view_name("")
    assert ctx.leases.who_holds(f"debug:{view}:pid=4321") == "peer-A"

    body = await _call(server, "target_manage",
                       {"action": "release_peer", "peer_id": "peer-A"})
    assert body.get("ok") is not False, body
    # The lease is gone.
    assert ctx.leases.who_holds(f"debug:{view}:pid=4321") is None


async def test_release_peer_foreign_still_needs_force(tmp_path, monkeypatch):
    """Patch 3 relaxes the force gate ONLY for self-release. A caller
    releasing a DIFFERENT peer still gets kind='confirm_required' back
    unless force=true."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)

    body = await _call(server, "target_manage",
                       {"action": "release_peer",
                        "peer_id": "some-other-peer"})
    assert body.get("ok") is False, body
    assert body.get("kind") == "confirm_required", body

    # With force=true it should go through (nothing held under that id;
    # just proves the gate honors force on a foreign id).
    body = await _call(server, "target_manage",
                       {"action": "release_peer",
                        "peer_id": "some-other-peer",
                        "force": True})
    assert body.get("ok") is not False, body
