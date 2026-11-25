"""Unit tests for the AccessTrace dbgeng driver (fallback path).

Mirrors ``test_access_trace_watchhw_unit.py``: mock the agent-client
surface, drive the driver end-to-end through the registry, assert:

  * No `allow_hw_bp_hook` requirement (dbgeng works regardless).
  * ``bp_manage.remove`` fires on stop.
  * DebugEvent filter rejects foreign ``bp_id`` events.
"""

from __future__ import annotations

import asyncio
import types

import pytest

pytest.importorskip(
    "capstone",
    reason="capstone install pending at integration",
)

from pry.mcp.tools.debug import access_trace as at  # noqa: E402


class _FakeDebugEventStream:
    """Async iterator yielding ``DebugEvent`` namespaces."""

    def __init__(self, events):
        self._events = list(events)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._events:
            raise StopAsyncIteration
        return self._events.pop(0)


def _debug_event(**over):
    base = dict(kind="BREAKPOINT_HW", bp_id=0, pid=100, tid=200,
                address=0x7ffe_0000, dropped=False, seq=0,
                dropped_count=0)
    base.update(over)
    return types.SimpleNamespace(**base)


class _DbgFakeClient:
    """Smallest surface the dbgeng driver reaches for."""

    def __init__(self, *, events, rip_bytes=b"\x48\x89\x07",
                 regs=None, bp_id=55, stack=None):
        self._events = events
        self._rip_bytes = rip_bytes
        self._regs = dict(regs or {"rdi": 0x7ffe_1000, "rax": 42})
        self._bp_id = bp_id
        self._stack = stack or {"kernel_frames": [],
                                 "user_frames": [{"rip": 0x7ffe_0000}]}
        self.attached = []
        self.bp_added = []
        self.bp_removed = []

    async def debug_attach(self, pid, **kw):
        self.attached.append({"pid": pid, **kw})
        return {"ok": True, "pid": pid, "monitor": bool(kw.get("monitor"))}

    async def bp_add(self, *, kind, address, size, access, pid, tid,
                      via_debugger=False):
        self.bp_added.append(dict(kind=kind, address=address, size=size,
                                    access=access, pid=pid, tid=tid,
                                    via_debugger=via_debugger))
        return {"bp_id": self._bp_id}

    async def bp_remove(self, bp_id):
        self.bp_removed.append(bp_id)
        return {"ok": True}

    def debug_stream_events(self, duration_ms=0):
        return _FakeDebugEventStream(self._events)

    async def debug_regs(self, tid=0):
        return dict(self._regs)

    async def mem_read(self, *, pid, address, size, space="user"):
        return self._rip_bytes[:size]

    async def stack_walk(self, *, tid, max_frames=8):
        return dict(self._stack)

    # No watchdog_* methods — the driver tolerates absence.


class _DbgFakeCfg:
    class security:
        allow_hw_bp_hook = False     # dbgeng works regardless


class _DbgFakeSession:
    def __init__(self, c):
        self._c = c

    def require_client(self, name):
        return self._c

    def resolve_view_name(self, name):
        return name or "lab.user"


class _DbgFakeCtx:
    def __init__(self, c):
        self.cfg = _DbgFakeCfg()
        self.session = _DbgFakeSession(c)


async def _wait_for_state(job_id, state, *, timeout=2.0, poll=0.01):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        job = at._get_job_for_tests(job_id)
        if job and job["state"] == state:
            return job
        await asyncio.sleep(poll)
    raise AssertionError(f"job {job_id!r} never reached state={state!r}")


@pytest.fixture(autouse=True)
def _reset_registry():
    at._reset_for_tests()
    yield
    at._reset_for_tests()


async def test_dbgeng_hit_records_and_bp_remove():
    bp_id = 77
    events = [
        _debug_event(bp_id=bp_id, address=0x7ffe_0000, tid=200, seq=1),
        _debug_event(bp_id=bp_id, address=0x7ffe_0010, tid=200, seq=2),
    ]
    c = _DbgFakeClient(events=events, bp_id=bp_id)
    ctx = _DbgFakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.user", owner="tests", name="lab.user",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="dbgeng", max_hits=4096,
        symbolize=False, disasm=False, stackwalk=False,
        timeout_s=1, redact_regs=True,
    )
    # No allow_hw_bp_hook requirement — ok=True immediately.
    assert r["ok"] is True
    assert r["driver_used"] == "dbgeng"
    assert r["bp_id"] == bp_id
    job = await _wait_for_state(r["job_id"], "ready")
    assert job["hits_so_far"] == 2
    assert c.bp_removed == [bp_id]
    assert c.attached and c.attached[0].get("monitor") is True
    assert c.bp_added and c.bp_added[0]["kind"] == "hw"


async def test_dbgeng_filters_foreign_bp_ids():
    our_bp = 77
    # Interleave events whose bp_id matches ours and ones that don't.
    events = [
        _debug_event(bp_id=12345, address=0x7ffe_00ff),  # noise
        _debug_event(bp_id=our_bp, address=0x7ffe_0000, seq=1),
        _debug_event(bp_id=12345, address=0x7ffe_00ff),  # noise
        _debug_event(bp_id=our_bp, address=0x7ffe_0010, seq=2),
    ]
    c = _DbgFakeClient(events=events, bp_id=our_bp)
    ctx = _DbgFakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.user", owner="tests", name="lab.user",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="dbgeng", max_hits=4096,
        symbolize=False, disasm=False, stackwalk=False,
        timeout_s=1, redact_regs=True,
    )
    job = await _wait_for_state(r["job_id"], "ready")
    assert job["hits_so_far"] == 2
    assert [h["seq"] for h in job["hits"]] == [1, 2]


async def test_dbgeng_filters_non_hw_bp_kinds():
    our_bp = 77
    events = [
        _debug_event(kind="EXCEPTION", bp_id=our_bp),       # dropped
        _debug_event(kind="BREAKPOINT_HW", bp_id=our_bp, seq=1),
        _debug_event(kind="PROCESS_EXIT", bp_id=our_bp),    # dropped
    ]
    c = _DbgFakeClient(events=events, bp_id=our_bp)
    ctx = _DbgFakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.user", owner="tests", name="lab.user",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="dbgeng", max_hits=4096,
        symbolize=False, disasm=False, stackwalk=False,
        timeout_s=1, redact_regs=True,
    )
    job = await _wait_for_state(r["job_id"], "ready")
    assert job["hits_so_far"] == 1


async def test_dbgeng_stop_calls_bp_remove():
    class _SlowStream:
        def __aiter__(self):
            return self

        async def __anext__(self):
            await asyncio.sleep(1.0)
            raise StopAsyncIteration

    c = _DbgFakeClient(events=[], bp_id=88)
    c.debug_stream_events = lambda duration_ms=0: _SlowStream()
    ctx = _DbgFakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.user", owner="tests", name="lab.user",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="dbgeng", max_hits=4096,
        symbolize=False, disasm=False, stackwalk=False,
        timeout_s=5, redact_regs=True,
    )
    await asyncio.sleep(0.05)
    stop = await at.at_cancel(ctx, c=c, job_id=r["job_id"])
    assert stop["state"] == "cancelled"
    assert c.bp_removed == [88]


async def test_dbgeng_hit_carries_bp_id():
    our_bp = 77
    events = [_debug_event(bp_id=our_bp, seq=1)]
    c = _DbgFakeClient(events=events, bp_id=our_bp)
    ctx = _DbgFakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.user", owner="tests", name="lab.user",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="dbgeng", max_hits=4096,
        symbolize=False, disasm=False, stackwalk=False,
        timeout_s=1, redact_regs=False,
    )
    await _wait_for_state(r["job_id"], "ready")
    status = at.at_status(job_id=r["job_id"], limit=0, offset=0,
                           verbosity="full", redact_regs=False)
    assert status["hits"][0]["bp_id"] == our_bp
