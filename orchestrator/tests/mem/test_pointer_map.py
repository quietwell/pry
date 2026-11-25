"""v17 (Memory scanner wave 2 Phase G): pointer-map routing + envelope shape.

Exercises the MCP tool handlers in
:mod:`pry.mcp.tools.mem.pointer_map` without a live agent. Uses a
stand-in client whose ``pointer_map_service`` is None so the mixin
returns ``kind='needs_v17'`` and we can confirm the routing gate.

The on-target engine (sweep, reverse BFS, diff) is exercised via live
tests (Phase H) and C++ build-verify (Phase B Checkpoint). These
tests pin the orchestrator-side routing + envelope contract.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.mem import pointer_map as pm  # noqa: E402


class _FakeSession:
    def __init__(self, pointer_map_version: int = 0,
                 view: str = "lab2.user"):
        self._machine_info = {
            view: {"pointer_map_version": pointer_map_version,
                    "scan_service_version": 1,
                    "machine": "lab2",
                    "computer_name": "LAB2"}
        }

    def focus_view(self) -> str:
        return ""

    def machine_of(self, view: str) -> str:
        return view.rsplit(".", 1)[0] if "." in view else view


class _FakeCtx:
    def __init__(self, sess: _FakeSession):
        self.session = sess


class _FakeClient:
    """Stand-in AgentClient for the routing tests. The pointer-map
    mixin's ``_needs_v17`` path short-circuits before any RPC, so we
    never actually dispatch."""

    def __init__(self, pointer_map_service=None, dissect_service=None):
        self.pointer_map_service = pointer_map_service
        self.dissect_service = dissect_service


# --------------------------------------------- _pointer_map_version gate --

def test_pointer_map_version_zero_refuses():
    sess = _FakeSession(pointer_map_version=0)
    ctx = _FakeCtx(sess)
    assert pm._pointer_map_version(ctx, "lab2.user") == 0


def test_pointer_map_version_one_accepts():
    sess = _FakeSession(pointer_map_version=1)
    ctx = _FakeCtx(sess)
    assert pm._pointer_map_version(ctx, "lab2.user") == 1


def test_pointer_map_version_bare_machine_name():
    # name='lab2' (no .user suffix) should still find pointer_map_version
    # via the sibling-view walk.
    sess = _FakeSession(pointer_map_version=1, view="lab2.user")
    ctx = _FakeCtx(sess)
    assert pm._pointer_map_version(ctx, "lab2") == 1


# ------------------------------------------------ needs_v17 envelope shape -

async def _run(h, *a, **kw):
    return await h(*a, **kw)


def _call(coro):
    return asyncio.get_event_loop().run_until_complete(coro) \
        if sys.platform == "win32" else asyncio.run(coro)


def test_pointer_map_create_refuses_on_pre_v17():
    sess = _FakeSession(pointer_map_version=0)
    ctx = _FakeCtx(sess)
    c = _FakeClient()
    env_json = asyncio.run(pm.handle_pointer_map_create(
        ctx, c, pid=1234, spans=[(0x1000, 0x100)],
        space="user", name="lab2.user"))
    env = json.loads(env_json)
    assert env["ok"] is False
    assert env["kind"] == "needs_v17"
    assert env["action"] == "pointer_map_create"
    assert "ABI v17 rebuild" in env["error"]
    assert "hint" in env


def test_pointer_scan_refuses_on_pre_v17():
    sess = _FakeSession(pointer_map_version=0)
    ctx = _FakeCtx(sess)
    c = _FakeClient()
    env = json.loads(asyncio.run(pm.handle_pointer_scan(
        ctx, c, name="lab2.user", map_id="pm1234_0001",
        target_va=0x7ff800001000, max_depth=3)))
    assert env["ok"] is False
    assert env["kind"] == "needs_v17"
    assert env["action"] == "pointer_scan"


def test_pointer_map_diff_refuses_on_pre_v17():
    sess = _FakeSession(pointer_map_version=0)
    ctx = _FakeCtx(sess)
    c = _FakeClient()
    env = json.loads(asyncio.run(pm.handle_pointer_map_diff(
        ctx, c, name="lab2.user", map_id_a="pm1234_0001",
        map_id_b="pm1234_0002")))
    assert env["ok"] is False
    assert env["kind"] == "needs_v17"


@pytest.mark.parametrize("verb,handler,extra_kwargs", [
    ("pointer_map_status",  "handle_pointer_map_status",
     {"map_id": "pm_x"}),
    ("pointer_map_list",    "handle_pointer_map_list", {}),
    ("pointer_map_cancel",  "handle_pointer_map_cancel",
     {"map_id": "pm_x"}),
    ("pointer_map_save",    "handle_pointer_map_save",
     {"map_id": "pm_x", "remote_path": "D:/tmp/pm"}),
    ("pointer_map_load",    "handle_pointer_map_load",
     {"remote_path": "D:/tmp/pm"}),
    ("pointer_map_destroy", "handle_pointer_map_destroy",
     {"map_id": "pm_x"}),
])
def test_every_verb_refuses_on_pre_v17(verb, handler, extra_kwargs):
    sess = _FakeSession(pointer_map_version=0)
    ctx = _FakeCtx(sess)
    c = _FakeClient()
    h = getattr(pm, handler)
    env = json.loads(asyncio.run(h(ctx, c, name="lab2.user",
                                    **extra_kwargs)))
    assert env["ok"] is False
    assert env["kind"] == "needs_v17"
    assert env["action"] == verb
