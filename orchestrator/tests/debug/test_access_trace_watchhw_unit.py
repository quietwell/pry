"""Unit tests for the AccessTrace watchhw driver.

Mocks the agent-client surface (``bp_hw_watch_add`` / ``events_stream``
/ ``debug_regs`` / ``mem_read`` / ``stack_walk``) and drives the
driver end-to-end through the registry. Capstone IS required (the
driver's hit decoration call-site dereferences the decoder). If the
venv lacks it the whole file skips with the plan's documented
reason.
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


# ----------------------------------------------------------------- fakes --


class _FakeStream:
    """Async iterator yielding synthetic ``EventsStream`` chunks.

    Each chunk has a ``.dropped`` scalar + an ``.events`` list; events
    carry seq/kind/pid/tid/address fields matching ``agent_client/
    device.py:_event_dict`` so the driver's attribute access lands
    on the right names.
    """

    def __init__(self, chunks):
        self._chunks = list(chunks)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._chunks:
            raise StopAsyncIteration
        return self._chunks.pop(0)


def _event(**over):
    # kind=6 is proto EventsKind.EVENTS_KIND_BP_HIT — what the agent
    # actually streams (1 << 6 is the subscription MASK bit).
    base = dict(seq=0, kind=6, pid=100, parent_pid=0, tid=200,
                image="", cmdline="", dropped=False, address=0x7ffe_0000,
                dr6=0, bp_id=0, slot=0, access=2, irql=0)
    base.update(over)
    return types.SimpleNamespace(**base)


def _chunk(events, dropped=0, done=False):
    return types.SimpleNamespace(events=events, dropped=dropped,
                                  done=done)


class _FakeClient:
    """Smallest surface the watchhw driver reaches for."""

    def __init__(self, *, chunks, rip_bytes=b"\x48\x89\x07",
                 regs=None, stack=None, code_base=None):
        self._chunks = chunks
        self._rip_bytes = rip_bytes
        # Backing code memory: with code_base set, mem_read serves the
        # slice at the requested address (the driver reads BEFORE rip
        # for data-watch traps).
        self._code_base = code_base
        self._regs = dict(regs or {"rdi": 0x7ffe_1000, "rax": 42})
        self._stack = stack or {"kernel_frames": [{"rip": 0xffff_f800_0000_0000}],
                                 "user_frames": [{"rip": 0x7ffe_0000}]}
        self.added = []
        self.removed = []

    async def bp_hw_watch_add(self, **kw):
        self.added.append(kw)
        return {"ok": True, "watch_cookie": 0x42, "slot": 2,
                "hvci_fallback": False}

    async def bp_hw_watch_remove(self, cookie):
        self.removed.append(cookie)
        return {"ok": True}

    async def bp_remove(self, cookie):
        self.removed.append(cookie)
        return {"ok": True}

    def events_stream(self, **kw):
        return _FakeStream(self._chunks)

    async def debug_regs(self, tid=0):
        return dict(self._regs)

    async def mem_read(self, *, pid, address, size, space="user"):
        if self._code_base is None:
            return self._rip_bytes[:size]
        off = address - self._code_base
        if off < 0:
            raise RuntimeError("unmapped")
        return self._rip_bytes[off:off + size]

    async def stack_walk(self, *, tid, max_frames=8):
        return dict(self._stack)

    # Watchdog kicker stubs — the wrapper tolerates missing methods but
    # the driver prefers to arm when present.
    async def watchdog_arm(self, *a, **kw):
        return {"ok": True}

    async def watchdog_kick(self, *a, **kw):
        return {"ok": True}

    async def watchdog_disarm(self, *a, **kw):
        return {"ok": True}


class _FakeSecurity:
    def __init__(self, allow_hw_bp_hook=True):
        self.allow_hw_bp_hook = allow_hw_bp_hook


class _FakeCfg:
    def __init__(self, allow_hw_bp_hook=True):
        self.security = _FakeSecurity(allow_hw_bp_hook)


class _FakeSession:
    def __init__(self, c):
        self._c = c

    def require_client(self, name):
        return self._c

    def resolve_view_name(self, name):
        return name or "lab.kernel"


class _FakeCtx:
    def __init__(self, c, *, allow_hw_bp_hook=True):
        self.cfg = _FakeCfg(allow_hw_bp_hook=allow_hw_bp_hook)
        self.session = _FakeSession(c)


# -------------------------------------------------------------- helpers --


async def _wait_for_state(job_id, state, *, timeout=2.0, poll=0.01):
    """Poll ``_ATJOBS[job_id].state`` until it matches."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        job = at._get_job_for_tests(job_id)
        if job is None:
            await asyncio.sleep(poll)
            continue
        if job["state"] == state:
            return job
        await asyncio.sleep(poll)
    raise AssertionError(f"job {job_id!r} never reached state={state!r}")


# ---------------------------------------------------------------- tests --


@pytest.fixture(autouse=True)
def _reset_registry():
    at._reset_for_tests()
    yield
    at._reset_for_tests()


async def test_watchhw_hit_ring_ordering_and_kernel_dropped():
    # Three hits across two chunks, chunk 2 reports dropped=5. The
    # final registry row should carry total_hits=3, kernel_dropped=5,
    # ring preserved in seq order.
    chunks = [
        _chunk([_event(seq=1, address=0x7ffe_0000, tid=200),
                 _event(seq=2, address=0x7ffe_0000, tid=200)],
                dropped=0),
        _chunk([_event(seq=3, address=0x7ffe_0000, tid=200)],
                dropped=5),
    ]
    c = _FakeClient(chunks=chunks)
    ctx = _FakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.kernel", owner="tests", name="lab.kernel",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="watchhw", max_hits=4096,
        symbolize=False, disasm=False, stackwalk=False,
        timeout_s=1, redact_regs=True,
    )
    assert r["ok"] is True, r
    assert r["driver_used"] == "watchhw"
    assert r["watch_cookie"] == 0x42
    job = await _wait_for_state(r["job_id"], "ready")
    assert job["hits_so_far"] == 3
    assert [h["seq"] for h in job["hits"]] == [1, 2, 3]
    assert job["kernel_dropped"] == 5
    # WatchHw.Remove must fire on job exit.
    assert c.removed == [0x42]


async def test_watchhw_refusal_when_hook_disabled():
    c = _FakeClient(chunks=[])
    ctx = _FakeCtx(c, allow_hw_bp_hook=False)
    r = await at.at_start(
        ctx, c=c, view="lab.kernel", owner="tests", name="lab.kernel",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="watchhw", max_hits=4096,
        symbolize=False, disasm=False, stackwalk=False,
        timeout_s=1, redact_regs=True,
    )
    assert r["ok"] is False
    assert r["kind"] == "hw_bp_hook_disabled"
    assert "allow_hw_bp_hook" in r["error"]


async def test_watchhw_auto_falls_back_to_dbgeng_when_hook_disabled():
    c = _FakeClient(chunks=[])
    ctx = _FakeCtx(c, allow_hw_bp_hook=False)
    driver = at._resolve_driver(ctx, 100, "auto", view="lab.kernel")
    assert driver == "dbgeng"


async def test_watchhw_redacts_regs_by_default():
    chunks = [_chunk([_event(seq=1, address=0x7ffe_0000, tid=200)])]
    c = _FakeClient(chunks=chunks)
    ctx = _FakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.kernel", owner="tests", name="lab.kernel",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="watchhw", max_hits=4096,
        symbolize=False, disasm=True, stackwalk=False,
        timeout_s=1, redact_regs=True,
    )
    await _wait_for_state(r["job_id"], "ready")
    status = at.at_status(job_id=r["job_id"], limit=0, offset=0,
                           verbosity="normal", redact_regs=True)
    assert status["returned"] == 1
    hit = status["hits"][0]
    # GPR values redacted; rip preserved; bytes_at_rip hex redacted.
    assert hit["regs"]["rdi"] == "<redacted>"
    assert hit["regs"]["rax"] == "<redacted>"
    assert hit["bytes_at_rip"]["hex"] == "<redacted>"


async def test_watchhw_full_verbosity_keeps_regs():
    chunks = [_chunk([_event(seq=1, address=0x7ffe_0000, tid=200)])]
    c = _FakeClient(chunks=chunks)
    ctx = _FakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.kernel", owner="tests", name="lab.kernel",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="watchhw", max_hits=4096,
        symbolize=False, disasm=True, stackwalk=False,
        timeout_s=1, redact_regs=False,
    )
    await _wait_for_state(r["job_id"], "ready")
    status = at.at_status(job_id=r["job_id"], limit=0, offset=0,
                           verbosity="full", redact_regs=False)
    hit = status["hits"][0]
    assert hit["regs"]["rdi"] == 0x7ffe_1000


async def test_watchhw_batched_symbolize_fires_on_batch_size():
    # Build a synthetic chunk that holds exactly _SYM_BATCH_SIZE events
    # so the batcher kicks mid-stream. The symbolize_batch mock
    # records every call for assertion.
    from pry.mcp.tools.debug import _watchhw_driver as wd
    size = wd._SYM_BATCH_SIZE
    ev = [_event(seq=i + 1, address=0x7ffe_0000 + (i * 0x10), tid=200)
          for i in range(size + 3)]
    chunks = [_chunk(ev)]
    c = _FakeClient(chunks=chunks)
    ctx = _FakeCtx(c)

    calls: list[list[int]] = []

    async def batcher(rips):
        calls.append(list(rips))
        return {int(r): {"module": "mod", "symbol": "sym",
                         "displacement": 0, "confidence": "high"}
                for r in rips}

    # Monkeypatch the symbolizer builder so we keep deterministic
    # behavior without loading tools/symbols.
    orig = at._symbolize_batcher
    at._symbolize_batcher = lambda ctx, view, pid: batcher
    try:
        r = await at.at_start(
            ctx, c=c, view="lab.kernel", owner="tests", name="lab.kernel",
            pid=100, address=0x7ffe_0000, size=8, access="rw",
            tid=0, driver="watchhw", max_hits=4096,
            symbolize=True, disasm=False, stackwalk=False,
            timeout_s=1, redact_regs=True,
        )
        await _wait_for_state(r["job_id"], "ready")
    finally:
        at._symbolize_batcher = orig

    # One or more batcher calls fired; the union covers every hit RIP.
    all_rips = set()
    for b in calls:
        all_rips.update(b)
    assert len(all_rips) >= size + 3
    assert calls, "symbolize_batch never fired"


async def test_watchhw_stop_disarms():
    # Drip events slowly so the job sits in ``running`` when we call
    # stop; stop should fire WatchHw.Remove and flip the state.
    class _SlowStream:
        def __aiter__(self):
            return self

        async def __anext__(self):
            await asyncio.sleep(1.0)
            raise StopAsyncIteration

    c = _FakeClient(chunks=[])
    c.events_stream = lambda **kw: _SlowStream()
    ctx = _FakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.kernel", owner="tests", name="lab.kernel",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="watchhw", max_hits=4096,
        symbolize=False, disasm=False, stackwalk=False,
        timeout_s=5, redact_regs=True,
    )
    await asyncio.sleep(0.05)
    stop = await at.at_cancel(ctx, c=c, job_id=r["job_id"])
    assert stop["state"] == "cancelled"
    # WatchHw.Remove fired exactly once (cookie=0x42 from the fake).
    assert c.removed == [0x42]


async def test_watchhw_hit_includes_memop_and_stack():
    chunks = [_chunk([_event(seq=1, address=0x7ffe_0000, tid=200)])]
    # MOV [rdi], rax ENDING at the reported RIP: a data breakpoint is a
    # trap, so RIP is the instruction after the access.
    code = b"\x90" * 13 + b"\x48\x89\x07" + b"\xc3" * 16
    c = _FakeClient(chunks=chunks, rip_bytes=code,
                    code_base=0x7ffe_0000 - 16)
    ctx = _FakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.kernel", owner="tests", name="lab.kernel",
        pid=100, address=0x7ffe_0000, size=8, access="rw",
        tid=0, driver="watchhw", max_hits=4096,
        symbolize=False, disasm=True, stackwalk=True,
        timeout_s=1, redact_regs=False,
    )
    await _wait_for_state(r["job_id"], "ready")
    status = at.at_status(job_id=r["job_id"], limit=0, offset=0,
                           verbosity="full", redact_regs=False)
    hit = status["hits"][0]
    assert hit["memop"]["mnemonic"] == "mov"
    assert hit["memop"]["base_reg"] == "rdi"
    assert hit["memop"]["access"] == "write"
    assert hit["memop"]["effective_address"] == 0x7ffe_1000
    assert hit["stack"]["user_frames"] == [0x7ffe_0000]


async def test_watchhw_real_kind_decimal_regs_and_trap_backscan():
    """Real agent hits (kind=6) are decoded; MessageToDict-style decimal
    register strings resolve; for a data watch the instruction ENDING at
    RIP (the trap reports the next one) is decoded, and its rip-relative
    EA uses the end of that instruction."""
    from pry.mcp.tools.debug import _watchhw_driver as wd
    assert wd._is_bp_hit(6) and wd._is_bp_hit("EVENTS_KIND_BP_HIT")
    assert wd._is_bp_hit(wd._CLASS_BP)       # dbgeng adapter marker
    assert not wd._is_bp_hit(1) and not wd._is_bp_hit(0)
    assert wd._reg_int("140737488359424") == 140737488359424
    assert wd._reg_int("0x10") == 16 and wd._reg_int("bogus") is None

    rip = 0x7ffe_0000
    # mov dword ptr [rip+0x10], 1 (10 bytes) ends at rip; the bytes AT
    # rip are a different store (mov [rbx], rcx) that must NOT be used.
    store_rip_rel = bytes.fromhex("c70510000000" "01000000")
    code = (b"\x90" * 6 + store_rip_rel + bytes.fromhex("48890b")
            + b"\xc3" * 13)
    watch = rip + 0x10
    chunks = [_chunk([_event(seq=1, address=rip, tid=200, access=1)])]
    c = _FakeClient(chunks=chunks, rip_bytes=code, code_base=rip - 16,
                    regs={"rbx": str(0x1234), "rcx": "5"})
    ctx = _FakeCtx(c)
    r = await at.at_start(
        ctx, c=c, view="lab.kernel", owner="tests", name="lab.kernel",
        pid=100, address=watch, size=4, access="write",
        tid=0, driver="watchhw", max_hits=4096,
        symbolize=False, disasm=True, stackwalk=False,
        timeout_s=1, redact_regs=False,
    )
    await _wait_for_state(r["job_id"], "ready")
    hit = at.at_status(job_id=r["job_id"], limit=0, offset=0,
                       verbosity="full", redact_regs=False)["hits"][0]
    m = hit["memop"]
    assert m["decode_basis"] == "trap_backscan"
    assert m["insn_va"] == rip - 10
    assert m["rip_relative"] is True
    assert m["effective_address"] == watch


async def test_watchhw_exec_watch_decodes_at_rip_with_real_length():
    """Exec watches fault AT rip: decode there, rip_next = rip + the
    decoded length (the old code used rip + 16)."""
    import time as _time

    from pry.mcp.tools.debug import _watchhw_driver as wd
    rip = 0x7ffe_0000
    # mov rax, [rip+0x20] (7 bytes) AT rip.
    code = bytes.fromhex("488b0520000000") + b"\xc3" * 16
    c = _FakeClient(chunks=[], rip_bytes=code, code_base=rip)
    stream = _FakeStream([_chunk([_event(seq=1, address=rip, tid=200,
                                         access=0)])])
    job_ctx = wd.WatchhwJobCtx(
        pid=100, tid=0, address=rip, size=1, access="exec", max_hits=8,
        disasm=True, stackwalk=False, symbolize=False, timeout_s=5,
        symbolize_batch=None)
    hits: list = []
    await wd._consume_events(
        stream=stream, job_ctx=job_ctx, client=c, on_hit=hits.append,
        drop_sink=lambda n: None, watch_cookie=1,
        deadline_ts=_time.monotonic() + 5)
    m = hits[0]["memop"]
    assert m["decode_basis"] == "fault_at_rip"
    assert m["insn_va"] == rip
    assert m["effective_address"] == rip + 7 + 0x20
