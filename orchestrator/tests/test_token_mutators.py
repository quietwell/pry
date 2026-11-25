"""token_manage mutator gate + lifecycle.

Covers:
- Every mutator refuses with ``kind='not_allowed'`` when
  ``security.allow_token_adjust=False`` (default).
- Flipping the config to True lets the mutator through to the stub.
- Impersonation returns an ``impersonation_id`` + tombstone budget
  (30s default, 300s with ``persist=True``) matching slice 01
  §Impersonation lifecycle.
- Simulated orchestrator crash: after a successful impersonate, a new
  stop_impersonate call with a stale id surfaces a labelled error
  (what the tombstone sweep would do in production).
- modify_default_dacl without ``aces`` is rejected as ``bad_arg``.
- Capability registry: every token_manage mutator carries
  ``gate='allow_token_adjust'``.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from pry.mcp.tools import token as _token_tool
from pry.mcp.tools._runtime.capabilities import canonical


# -----------------------------------------------------------------------
# Capability registry gating (static assertion)
# -----------------------------------------------------------------------


_MUTATOR_VERBS = ("enable_privilege", "disable_privilege",
                  "remove_privilege",
                  "set_integrity_level", "set_virtualization",
                  "impersonate", "modify_default_dacl")


def test_every_mutator_has_allow_token_adjust_gate() -> None:
    for a in _MUTATOR_VERBS:
        cap = canonical("token_manage", a)
        assert cap is not None, f"{a} not in capability registry"
        assert cap.mutating is True
        assert cap.gate == "allow_token_adjust", (
            f"{a} gate={cap.gate!r} (want allow_token_adjust)")


def test_stop_impersonate_is_ungated() -> None:
    cap = canonical("token_manage", "stop_impersonate")
    assert cap is not None
    # stop_impersonate is a mutator but ungated — explicit teardown of
    # a prior impersonate (slice 01).
    assert cap.gate is None


# -----------------------------------------------------------------------
# Config-flag refusal
# -----------------------------------------------------------------------


class _CfgSec:
    def __init__(self, allow: bool = False) -> None:
        self.allow_token_adjust = allow


class _Ctx:
    def __init__(self, allow: bool = False) -> None:
        class _Cfg:
            def mcp_max_items(self): return 1000
        self.cfg = _Cfg()
        self.cfg.security = _CfgSec(allow)


class _StubRpc:
    """Fake agent client — every mutator forwards here. ``token`` is a
    non-None sentinel; the tool-level config gate is tested with the
    orchestrator ``ctx``, not the stub."""

    def __init__(self) -> None:
        self.token_svc = object()
        self.calls: list[tuple[str, dict]] = []

    async def token_adjust_privilege(self, **kw):
        self.calls.append(("adjust", kw))
        return {"ok": True, "previous_state": "disabled",
                "new_state": "enabled",
                "luid_low": 20, "luid_high": 0}

    async def token_set_integrity(self, **kw):
        self.calls.append(("set_il", kw))
        return {"ok": True, "previous_rid": 0x3000, "new_rid": 0x2000}

    async def token_set_virtualization(self, **kw):
        self.calls.append(("set_virt", kw))
        return {"ok": True, "previous": False, "new": True}

    async def token_impersonate(self, **kw):
        self.calls.append(("impersonate", kw))
        return {"ok": True, "impersonation_id": "imp-abc",
                "agent_thread_id": 1234,
                "level_granted": kw.get("impersonation_level",
                                         "impersonation")}

    async def token_stop_impersonate(self, **kw):
        self.calls.append(("stop_impersonate", kw))
        if kw.get("impersonation_id") == "stale-id":
            return {"ok": False, "error": "impersonation_id not found"}
        return {"ok": True, "error": ""}

    async def token_modify_dacl(self, **kw):
        self.calls.append(("modify_dacl", kw))
        return {"ok": True, "ace_count_before": 2,
                "ace_count_after": len(kw.get("aces", []) or [])}


def _run(coro):
    return asyncio.run(coro)


# -----------------------------------------------------------------------
# Refusal on allow_token_adjust=False
# -----------------------------------------------------------------------


def _assert_refused(result: str) -> None:
    r = json.loads(result)
    assert r["ok"] is False, result
    assert r["kind"] == "not_allowed"
    assert "allow_token_adjust" in r["error"]


def test_enable_privilege_refused_by_default() -> None:
    _assert_refused(_run(_token_tool.handle_enable_privilege(
        ctx=_Ctx(allow=False), c=_StubRpc(), pid=1234, tid=0,
        privilege="SeDebugPrivilege",
        luid_low=0, luid_high=0)))


def test_disable_privilege_refused_by_default() -> None:
    _assert_refused(_run(_token_tool.handle_disable_privilege(
        ctx=_Ctx(allow=False), c=_StubRpc(), pid=1234, tid=0,
        privilege="SeShutdownPrivilege",
        luid_low=0, luid_high=0)))


def test_remove_privilege_refused_by_default() -> None:
    _assert_refused(_run(_token_tool.handle_remove_privilege(
        ctx=_Ctx(allow=False), c=_StubRpc(), pid=1234, tid=0,
        privilege="SeDebugPrivilege",
        luid_low=0, luid_high=0)))


def test_set_integrity_level_refused_by_default() -> None:
    _assert_refused(_run(_token_tool.handle_set_integrity_level(
        ctx=_Ctx(allow=False), c=_StubRpc(), pid=1234, tid=0,
        level="low")))


def test_set_virtualization_refused_by_default() -> None:
    _assert_refused(_run(_token_tool.handle_set_virtualization(
        ctx=_Ctx(allow=False), c=_StubRpc(), pid=1234, tid=0,
        enabled=True)))


def test_impersonate_refused_by_default() -> None:
    _assert_refused(_run(_token_tool.handle_impersonate(
        ctx=_Ctx(allow=False), c=_StubRpc(),
        source_pid=4, persist=False)))


def test_modify_default_dacl_refused_by_default() -> None:
    _assert_refused(_run(_token_tool.handle_modify_default_dacl(
        ctx=_Ctx(allow=False), c=_StubRpc(), pid=1234, tid=0,
        aces=[{"sid": "S-1-5-18", "access_mask": 0xf01ff,
               "type": "allow", "flags": 0}])))


# -----------------------------------------------------------------------
# allow_token_adjust=True passes through to stub
# -----------------------------------------------------------------------


def test_enable_privilege_passes_when_allowed() -> None:
    stub = _StubRpc()
    out = _run(_token_tool.handle_enable_privilege(
        ctx=_Ctx(allow=True), c=stub, pid=1234, tid=0,
        privilege="SeDebugPrivilege",
        luid_low=0, luid_high=0))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["new_state"] == "enabled"
    assert len(stub.calls) == 1
    assert stub.calls[0][0] == "adjust"
    assert stub.calls[0][1]["action"] == "enable"


def test_set_integrity_level_resolves_name() -> None:
    stub = _StubRpc()
    out = _run(_token_tool.handle_set_integrity_level(
        ctx=_Ctx(allow=True), c=stub, pid=1234, tid=0, level="low"))
    r = json.loads(out)
    assert r["ok"] is True
    assert stub.calls[0][1]["integrity_name"] == "low"


# -----------------------------------------------------------------------
# Impersonation lifecycle
# -----------------------------------------------------------------------


def test_impersonate_returns_tombstone_budget_default() -> None:
    out = _run(_token_tool.handle_impersonate(
        ctx=_Ctx(allow=True), c=_StubRpc(),
        source_pid=4, persist=False))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["tombstone_seconds"] == 30
    assert r["persist"] is False
    assert r["impersonation_id"] == "imp-abc"


def test_impersonate_persist_lifts_tombstone_to_300s() -> None:
    out = _run(_token_tool.handle_impersonate(
        ctx=_Ctx(allow=True), c=_StubRpc(),
        source_pid=4, persist=True))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["tombstone_seconds"] == 300
    assert r["persist"] is True


def test_stop_impersonate_ungated_but_still_requires_id() -> None:
    stub = _StubRpc()
    # Even with allow_token_adjust=False, stop_impersonate goes through.
    out = _run(_token_tool.handle_stop_impersonate(
        ctx=_Ctx(allow=False), c=stub,
        impersonation_id="imp-abc"))
    r = json.loads(out)
    assert r["ok"] is True


def test_stop_impersonate_stale_id_surfaces_labelled_error() -> None:
    """Simulates post-crash state: the agent tombstone fired on timeout
    (clearing the entry), then the caller sends stop_impersonate with
    the id they remembered. The agent surfaces 'not found' — the
    orchestrator passes the error through."""
    out = _run(_token_tool.handle_stop_impersonate(
        ctx=_Ctx(allow=True), c=_StubRpc(),
        impersonation_id="stale-id"))
    r = json.loads(out)
    assert r["ok"] is False
    assert "not found" in r["error"]


# -----------------------------------------------------------------------
# modify_default_dacl shape validation
# -----------------------------------------------------------------------


def test_modify_default_dacl_rejects_empty_aces() -> None:
    out = _run(_token_tool.handle_modify_default_dacl(
        ctx=_Ctx(allow=True), c=_StubRpc(), pid=1234, tid=0,
        aces=[]))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "bad_arg"


def test_modify_default_dacl_rejects_malformed_ace() -> None:
    out = _run(_token_tool.handle_modify_default_dacl(
        ctx=_Ctx(allow=True), c=_StubRpc(), pid=1234, tid=0,
        aces=[{"sid": "S-1-5-18"}]))  # missing access_mask
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "bad_arg"


def test_modify_default_dacl_happy_path() -> None:
    stub = _StubRpc()
    aces = [{"sid": "S-1-5-18", "access_mask": 0xf01ff,
             "type": "allow", "flags": 0}]
    out = _run(_token_tool.handle_modify_default_dacl(
        ctx=_Ctx(allow=True), c=stub, pid=1234, tid=0, aces=aces))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["ace_count_after"] == 1
    assert stub.calls[0][1]["aces"] == aces
