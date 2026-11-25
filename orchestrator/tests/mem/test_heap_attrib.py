"""orchestrator-side handler tests for
``memory_manage(action='heap_attrib')``.

Covers the full matrix laid out in the plan §7.6 + the chunk kickoff:

* batch response ordering (one record per input VA in request order);
* cache miss → ``index_from_cache=False``;
* cache hit → ``index_from_cache=True`` under TTL;
* TTL expiry → rebuild;
* committed-sum delta > 1 MiB → rebuild;
* ``refresh=True`` → rebuild regardless of TTL;
* ``memory_heap_attrib_version=0`` → ``feature_unavailable`` gate;
* ``pid=0`` → ``bad_arg`` refusal;
* batch > HEAPATTRIB_MAX_VAS → ``too_many_vas`` refusal;
* both scalar ``va=`` and list ``vas=[...]`` paths succeed.

Mocks: every test drives a tiny ``_CannedClient`` that returns the
exact wire shape the agent would. Cache / TTL / committed-sum-delta
logic lives on the agent (C++ ``HeapAttribCache``); the orchestrator
just threads through whatever ``index_from_cache`` /
``cache_committed_sum`` the agent set. These tests therefore prove
the orchestrator's envelope translation + gating, not the agent
state machine.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.mem import heap_attrib as ha  # noqa: E402


# --------------------------------------------- shared test harness ---------


class _FakeSession:
    """Mirrors the ``_FakeSession`` in ``test_wave3_p5.py`` — the
    handler reads ``memory_heap_attrib_version`` via
    ``ctx.session._machine_info[view]``."""

    def __init__(self, memory_heap_attrib_version: int = 1,
                 view: str = "lab2.kernel"):
        self._machine_info = {
            view: {
                "memory_heap_attrib_version": memory_heap_attrib_version,
                "pointer_map_version": 1,
                "dissect_version": 1,
                "scan_service_version": 1,
                "machine": "lab2",
                "computer_name": "LAB2",
            }
        }

    def focus_view(self) -> str:
        return ""

    def machine_of(self, view: str) -> str:
        return view.rsplit(".", 1)[0] if "." in view else view


class _FakeCtx:
    def __init__(self, sess: _FakeSession):
        self.session = sess


class _CannedClient:
    """Minimal mock of :class:`AgentClient` for the heap_attrib
    handler. Records every call so tests can assert arg forwarding
    (notably ``refresh``)."""

    def __init__(self, response: dict[str, Any] | None = None):
        self._response = response or {
            "ok": True, "records": [],
            "index_from_cache": False, "cache_epoch": 1,
            "cache_age_ms": 0, "cache_committed_sum": 0,
        }
        self.calls: list[dict[str, Any]] = []

    async def heap_attrib(self, *, pid: int, vas: list[int],
                          refresh: bool) -> dict[str, Any]:
        self.calls.append({
            "pid": int(pid), "vas": list(vas), "refresh": bool(refresh)
        })
        return self._response


def _run(coro):
    return json.loads(asyncio.run(coro))


# --------------------------------------------- happy-path matrix -----------


def test_batch_response_ordering_matches_input():
    sess = _FakeSession(memory_heap_attrib_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(response={
        "ok": True,
        "records": [
            {"va": 0x1000, "found": True,  "heap_handle": 0xA, "segment_base": 0xB,
             "chunk_base": 0x1000, "chunk_size": 64,  "flags": 1, "size_class": 64},
            {"va": 0x2000, "found": False, "heap_handle": 0,   "segment_base": 0,
             "chunk_base": 0,      "chunk_size": 0,   "flags": 0, "size_class": 0},
            {"va": 0x3000, "found": True,  "heap_handle": 0xA, "segment_base": 0xB,
             "chunk_base": 0x3000, "chunk_size": 192, "flags": 8, "size_class": 256},
        ],
        "index_from_cache": False, "cache_epoch": 1,
        "cache_age_ms": 0, "cache_committed_sum": 4096,
    })
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=[0x1000, 0x2000, 0x3000],
        refresh=False, name="lab2.kernel"))
    assert env["ok"] is True
    # Records surface under env.data per _wrap. _hexify_dict renders
    # address-shaped scalars as '0x…' and adds an `_int` mirror; pin
    # both the hex string and the decimal mirror so a regression in
    # either format fails this test.
    records = env["data"]["records"]
    assert [r["va"] for r in records] == ["0x1000", "0x2000", "0x3000"]
    assert [r["va_int"] for r in records] == [0x1000, 0x2000, 0x3000]
    assert records[0]["found"] is True
    assert records[1]["found"] is False
    # size_class isn't an address-shaped field, so it doesn't get
    # hexified — stays int.
    assert records[2]["size_class"] == 256
    # Client call carried the exact batch in order.
    assert c.calls == [{"pid": 1234, "vas": [0x1000, 0x2000, 0x3000],
                         "refresh": False}]


def test_cache_miss_reports_index_from_cache_false():
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient(response={
        "ok": True, "records": [],
        "index_from_cache": False, "cache_epoch": 1,
        "cache_age_ms": 0, "cache_committed_sum": 0,
    })
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=[0x1000], name="lab2.kernel"))
    assert env["ok"] is True
    assert env["data"]["index_from_cache"] is False
    assert env["data"]["cache_epoch"] == 1


def test_cache_hit_within_ttl_reports_index_from_cache_true():
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient(response={
        "ok": True, "records": [],
        # agent kept the index; it's 250 ms old, well under TTL.
        "index_from_cache": True, "cache_epoch": 1,
        "cache_age_ms": 250, "cache_committed_sum": 4096,
    })
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=[0x1000], name="lab2.kernel"))
    assert env["ok"] is True
    assert env["data"]["index_from_cache"] is True
    assert env["data"]["cache_age_ms"] == 250


def test_ttl_expiry_surfaces_fresh_epoch_and_not_from_cache():
    """The agent's TTL check rebuilds the index and bumps epoch; the
    orchestrator surfaces both facts verbatim."""
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient(response={
        "ok": True, "records": [],
        # TTL expired → agent rebuilt; epoch bumped from 1 to 2.
        "index_from_cache": False, "cache_epoch": 2,
        "cache_age_ms": 0, "cache_committed_sum": 8192,
    })
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=[0x1000], name="lab2.kernel"))
    assert env["data"]["index_from_cache"] is False
    assert env["data"]["cache_epoch"] == 2


def test_committed_sum_delta_triggers_rebuild():
    """Agent's committed-sum probe moved > max(1 MiB, 1%); a rebuild
    happened. The orchestrator surfaces the fresh cache_committed_sum."""
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient(response={
        "ok": True, "records": [],
        "index_from_cache": False, "cache_epoch": 3,
        "cache_age_ms": 1200,  # under TTL — rebuild wasn't TTL-driven
        "cache_committed_sum": 10 * 1024 * 1024,
    })
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=[0x1000], name="lab2.kernel"))
    assert env["data"]["index_from_cache"] is False
    assert env["data"]["cache_committed_sum"] == 10 * 1024 * 1024


def test_refresh_true_forwards_to_client():
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient(response={
        "ok": True, "records": [],
        "index_from_cache": False, "cache_epoch": 4,
        "cache_age_ms": 0, "cache_committed_sum": 4096,
    })
    _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=[0x1000], refresh=True,
        name="lab2.kernel"))
    assert c.calls[0]["refresh"] is True


def test_scalar_va_kwarg_reaches_batch():
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient(response={
        "ok": True,
        "records": [{"va": 0x4000, "found": True, "heap_handle": 0,
                     "segment_base": 0, "chunk_base": 0x4000,
                     "chunk_size": 32, "flags": 1, "size_class": 32}],
        "index_from_cache": False, "cache_epoch": 1,
        "cache_age_ms": 0, "cache_committed_sum": 0,
    })
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, va=0x4000, name="lab2.kernel"))
    assert env["ok"] is True
    assert c.calls[0]["vas"] == [0x4000]


def test_scalar_va_kwarg_accepts_hex_string():
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient()
    _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, va="0x5000", name="lab2.kernel"))
    assert c.calls[0]["vas"] == [0x5000]


def test_scalar_and_list_merged_in_order():
    """``va=`` first, then every ``vas`` entry — gives callers a way to
    probe a single VA while also warming the cache with a batch."""
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient()
    _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, va=0x1000, vas=[0x2000, 0x3000],
        name="lab2.kernel"))
    assert c.calls[0]["vas"] == [0x1000, 0x2000, 0x3000]


# --------------------------------------------- refusal matrix --------------


def test_feature_unavailable_when_version_zero():
    sess = _FakeSession(memory_heap_attrib_version=0)
    ctx = _FakeCtx(sess)

    class _ShouldNotCall:
        async def heap_attrib(self, **kw):
            raise AssertionError(
                "heap_attrib must refuse before reaching the client")

    env = _run(ha.handle_heap_attrib(
        ctx, _ShouldNotCall(), pid=1234, vas=[0x1000],
        name="lab2.user"))
    assert env["ok"] is False
    assert env["kind"] == "feature_unavailable"


def test_pid_zero_refused_with_bad_arg():
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient()
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=0, vas=[0x1000], name="lab2.kernel"))
    assert env["ok"] is False
    assert env["kind"] == "bad_arg"
    # Client must not be reached — the orchestrator refuses first.
    assert c.calls == []


def test_empty_vas_refused_with_bad_arg():
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient()
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=None, name="lab2.kernel"))
    assert env["ok"] is False
    assert env["kind"] == "bad_arg"
    assert c.calls == []


def test_too_many_vas_refused_orchestrator_side():
    """Plan §7.3 caps vas at 4096 per call. The orchestrator pre-checks
    so the agent never sees an oversized batch."""
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient()
    too_many = list(range(ha.HEAPATTRIB_MAX_VAS + 1))
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=too_many, name="lab2.kernel"))
    assert env["ok"] is False
    assert env["kind"] == "too_many_vas"
    assert c.calls == []


def test_unparseable_va_refused_with_bad_arg():
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient()
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=["not-a-number"], name="lab2.kernel"))
    assert env["ok"] is False
    assert env["kind"] == "bad_arg"
    assert c.calls == []


def test_agent_error_surfaces_kind_through_wrap():
    """An agent-side refusal (set OpStatus.kind='heap_walk_failed')
    threads through the wrapper without being flattened to the generic
    'heap_attrib' slug."""
    sess = _FakeSession()
    ctx = _FakeCtx(sess)
    c = _CannedClient(response={
        "ok": False,
        "error": "heap walk failed",
        "agent_kind": "heap_walk_failed",
        "records": [],
        "index_from_cache": False,
        "cache_epoch": 0, "cache_age_ms": 0,
        "cache_committed_sum": 0,
    })
    env = _run(ha.handle_heap_attrib(
        ctx, c, pid=1234, vas=[0x1000], name="lab2.kernel"))
    assert env["ok"] is False
    assert env["kind"] == "heap_walk_failed"


def test_agent_version_fallback_from_client_wrapper():
    """When the client wrapper itself returns ``kind='agent_version'``
    (old agent, UNIMPLEMENTED RPC), the wrapper surfaces it verbatim
    rather than overriding with the generic heap_attrib slug."""
    sess = _FakeSession()
    ctx = _FakeCtx(sess)

    class _OldAgent:
        async def heap_attrib(self, **kw):
            return {
                "ok": False,
                "kind": "agent_version",
                "error": "heap_attrib: agent predates the RPC",
                "records": [],
                "index_from_cache": False,
                "cache_epoch": 0, "cache_age_ms": 0,
                "cache_committed_sum": 0,
            }

    env = _run(ha.handle_heap_attrib(
        ctx, _OldAgent(), pid=1234, vas=[0x1000],
        name="lab2.kernel"))
    assert env["ok"] is False
    assert env["kind"] == "agent_version"
