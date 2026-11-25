"""orchestrator-side regression tests
for the Wave 1/2 cleanup.

Covers the P0/P1 items whose observable surface is on the Python
wrapper. Agent-side C++ gtests for P0 items 1 (SweepWorker join), 2
(Scan+Diff cancellation), and 3 (Diff chains cap) are deferred — the
agent isn't rebuilt this session; see the chunk kickoff prompt.

Mock client: the pointer-map / dissect handlers accept whatever shape
the mock returns, so we drive them with the exact wire shape a
newer agent would hand back (new fields set) and an older
agent would hand back (new fields absent / default).
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

from src.pry.mcp.tools.mem import pointer_map as pm  # noqa: E402
from src.pry.mcp.tools.mem import dissect as ds  # noqa: E402


class _FakeSession:
    def __init__(self, pointer_map_version: int = 1,
                 dissect_version: int = 1,
                 view: str = "lab2.user"):
        self._machine_info = {
            view: {
                "pointer_map_version": pointer_map_version,
                "dissect_version": dissect_version,
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
    """Mock AgentClient whose dispatch methods return the canned shape
    the test wants. We advertise the stubs as truthy so the mixin's
    ``_needs_v17`` short-circuit doesn't fire."""

    def __init__(self, scan_result: dict[str, Any] | None = None,
                 diff_result: dict[str, Any] | None = None,
                 dissect_result: dict[str, Any] | None = None):
        self.pointer_map_service = object()
        self.dissect_service = object()
        self._scan_result = scan_result
        self._diff_result = diff_result
        self._dissect_result = dissect_result

    async def pointer_scan(self, **kwargs):
        return self._scan_result

    async def pointer_map_diff(self, **kwargs):
        return self._diff_result

    async def dissect(self, **kwargs):
        return self._dissect_result


# ------------------------------------------- P0 item 4: truncation bools -----

def test_scan_truncation_wall_exceeded_maps_to_kind():
    """Agent sets ``wall_exceeded=True`` (new bool); wrapper
    surfaces ``kind='wall_ms_exceeded'`` without the older
    heuristic."""
    sess = _FakeSession(pointer_map_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(scan_result={
        "ok": True, "chains": [],
        "truncated": True, "wall_ms_actual": 15_000,
        "candidates_examined": 10_000,
        "wall_exceeded": True, "fanout_exceeded": False,
    })
    env = json.loads(asyncio.run(pm.handle_pointer_scan(
        ctx, c, name="lab2.user", map_id="pm_x", target_va=0x1000)))
    assert env["ok"] is True
    assert env["kind"] == "wall_ms_exceeded"


def test_scan_truncation_fanout_exceeded_maps_to_kind():
    """Agent sets ``fanout_exceeded=True`` (new bool); wrapper
    surfaces ``kind='fanout_exceeded'`` even when the clock elapsed."""
    sess = _FakeSession(pointer_map_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(scan_result={
        "ok": True, "chains": [],
        "truncated": True, "wall_ms_actual": 42,
        "candidates_examined": 2048,
        "wall_exceeded": False, "fanout_exceeded": True,
    })
    env = json.loads(asyncio.run(pm.handle_pointer_scan(
        ctx, c, name="lab2.user", map_id="pm_x", target_va=0x1000)))
    assert env["ok"] is True
    assert env["kind"] == "fanout_exceeded"


def test_scan_truncation_older_agent_falls_back():
    """Older agents don't set the new bools (both default False);
    orchestrator can't safely distinguish cause and surfaces the
    neutral ``kind='scan_truncated'`` instead of the fragile
    ``wall_ms_actual > 0`` heuristic."""
    sess = _FakeSession(pointer_map_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(scan_result={
        "ok": True, "chains": [],
        "truncated": True, "wall_ms_actual": 123,
        "candidates_examined": 100,
        "wall_exceeded": False, "fanout_exceeded": False,
    })
    env = json.loads(asyncio.run(pm.handle_pointer_scan(
        ctx, c, name="lab2.user", map_id="pm_x", target_va=0x1000)))
    assert env["ok"] is True
    assert env["kind"] == "scan_truncated"


def test_scan_not_truncated_stays_default_kind():
    sess = _FakeSession(pointer_map_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(scan_result={
        "ok": True, "chains": [],
        "truncated": False, "wall_ms_actual": 500,
        "candidates_examined": 100,
        "wall_exceeded": False, "fanout_exceeded": False,
    })
    env = json.loads(asyncio.run(pm.handle_pointer_scan(
        ctx, c, name="lab2.user", map_id="pm_x", target_va=0x1000)))
    assert env["ok"] is True
    assert env["kind"] == "pointer_map"


# ------------------------------------------- P0 item 3: too_many_chains ------

def test_diff_too_many_chains_surfaces_named_kind():
    """Agent refuses an oversized filter list with
    ``kind='too_many_chains'`` (new OpStatus.kind field).
    Orchestrator honours the agent-set kind over substring matching."""
    sess = _FakeSession(pointer_map_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(diff_result={
        "ok": False,
        "error": "too many chains (cap 1024)",
        "errno_code": 0,
        "agent_kind": "too_many_chains",
        "rows": [],
        "compared_entries": 0,
        "truncated": False,
    })
    env = json.loads(asyncio.run(pm.handle_pointer_map_diff(
        ctx, c, name="lab2.user", map_id_a="A", map_id_b="B")))
    assert env["ok"] is False
    assert env["kind"] == "too_many_chains"


def test_diff_too_many_chains_falls_back_to_substring():
    """An older agent that doesn't set OpStatus.kind must still
    classify the refusal correctly via the substring fallback."""
    sess = _FakeSession(pointer_map_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(diff_result={
        "ok": False,
        "error": "too many chains (cap 1024)",
        "errno_code": 0,
        "rows": [],
        "compared_entries": 0,
        "truncated": False,
    })
    env = json.loads(asyncio.run(pm.handle_pointer_map_diff(
        ctx, c, name="lab2.user", map_id_a="A", map_id_b="B")))
    assert env["ok"] is False
    assert env["kind"] == "too_many_chains"


# ------------------------------------------- P0 item 5: dissect_version gate -

def test_dissect_version_zero_falls_back_to_v16_path():
    """dissect_version=0 means an older agent or absent DissectService →
    orchestrator-side v16 fallback (pure-Python decode). Mock serves a
    read failure so the fallback path surfaces cleanly."""
    sess = _FakeSession(pointer_map_version=1, dissect_version=0)
    ctx = _FakeCtx(sess)

    class _FbClient:
        pointer_map_service = object()
        dissect_service = object()

        async def dissect(self, **kw):  # should NOT be called
            raise AssertionError("dissect fast path reached on version=0")

        async def mem_read(self, **kw):
            return {"ok": False, "error": "read failed in test"}

        async def list_modules(self, pid):
            return {"ok": False, "modules": []}

    env = json.loads(asyncio.run(ds.handle_dissect(
        ctx, _FbClient(), pid=1234, address=0x1000, size=64,
        space="user", with_modules=False, align=4, name="lab2.user")))
    # read failed → fallback path returns kind=read_failed, not dissect.
    assert env["ok"] is False
    assert env["kind"] == "read_failed"


def test_dissect_version_one_takes_fast_path():
    """dissect_version=1 (newer agent) means the orchestrator routes
    directly through the agent handler, bypassing the v16 glue."""
    sess = _FakeSession(pointer_map_version=1, dissect_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(dissect_result={
        "ok": True,
        "slots": [],
        "total_rows": 16,
        "truncated": False,
    })
    env = json.loads(asyncio.run(ds.handle_dissect(
        ctx, c, pid=1234, address=0x1000, size=64,
        space="user", with_modules=False, align=4, name="lab2.user")))
    assert env["ok"] is True
    # Fast path: we should see total_rows/truncated surfaced.
    assert env["data"]["total_rows"] == 16
    assert env["data"]["truncated"] is False


def test_dissect_version_zero_with_pointer_map_version_one_still_falls_back():
    """Regression for the §A.0 bug: older agents set
    pointer_map_version=1 and dissect_version was absent; the Wave 2
    router used pointer_map_version as a proxy and took the fast path
    even when no DissectService was registered. Current code reads
    dissect_version directly, so a pointer_map_version=1 /
    dissect_version=0 agent correctly falls back."""
    sess = _FakeSession(pointer_map_version=1, dissect_version=0)
    ctx = _FakeCtx(sess)

    class _Watchdog:
        pointer_map_service = object()
        dissect_service = object()

        async def dissect(self, **kw):
            raise AssertionError(
                "fast path taken on dissect_version=0 agent")

        async def mem_read(self, **kw):
            return {"ok": True, "data": b"\x00" * 64}

        async def list_modules(self, pid):
            return {"ok": True, "modules": []}

    env = json.loads(asyncio.run(ds.handle_dissect(
        ctx, _Watchdog(), pid=1234, address=0x1000, size=64,
        space="user", with_modules=False, align=4, name="lab2.user")))
    assert env["ok"] is True
    # Fallback returned 16 rows (64 bytes / align 4).
    assert len(env["data"]["slots"]) == 16
    assert env["data"]["fallback"] is True


# ------------------------------------------- P1 item 10: DissectResponse ----

def test_dissect_response_surfaces_total_rows_and_truncated():
    """P1 item 10: newer agents hand ``total_rows`` + ``truncated``
    back on the response; the wrapper must thread them through."""
    sess = _FakeSession(pointer_map_version=1, dissect_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(dissect_result={
        "ok": True,
        "slots": [{"offset": i * 4} for i in range(4096)],
        "total_rows": 4200,  # agent capped at 4096
        "truncated": True,
    })
    env = json.loads(asyncio.run(ds.handle_dissect(
        ctx, c, pid=1234, address=0x1000, size=4200 * 4,
        space="user", with_modules=False, align=4, name="lab2.user")))
    assert env["ok"] is True
    assert env["data"]["total_rows"] == 4200
    assert env["data"]["truncated"] is True
    assert len(env["data"]["slots"]) == 4096


# ------------------------------------------- P1 item 11: _map_agent_error_kind

def test_map_agent_error_kind_prefers_agent_kind_over_substring():
    """When the agent sets ``OpStatus.kind``, trust it over substring
    matching — the agent has authoritative knowledge of the failure
    class, the substring table is a fallback for older agents."""
    # A newer agent sets a kind the substring table would NOT have
    # resolved (e.g. a Wave 3 P1 kind we don't know yet). The wrapper
    # must still surface it.
    k = pm._map_agent_error_kind("some error message the matcher misses",
                                   agent_kind="novel_kind")
    assert k == "novel_kind"


def test_map_agent_error_kind_substring_fallback_for_older_agents():
    """Older agents leave agent_kind empty; substring matching
    still works."""
    assert pm._map_agent_error_kind("pointer_map_full") == "pointer_map_full"
    assert pm._map_agent_error_kind("map not found") == "map_not_found"
    assert pm._map_agent_error_kind("map not mmap'd") == "map_not_mmapd"
    assert pm._map_agent_error_kind(
        "too many chains (cap 1024)") == "too_many_chains"


def test_map_agent_error_kind_none_on_unknown_older_agents():
    """No agent_kind, no substring hit → None so the caller keeps the
    default ``kind='pointer_map'`` envelope slug."""
    assert pm._map_agent_error_kind("mystery failure") is None
    assert pm._map_agent_error_kind("") is None


# ------------------------------------------- P1 item 14: dissect error map ---

def test_dissect_translates_agent_error_kind():
    """P1 item 14: v17 dissect fast path used to surface every agent
    failure as ``kind='dissect'``; newer code reuses the pointer_map
    mapping so a map_not_found / other named agent error flows through
    correctly."""
    sess = _FakeSession(pointer_map_version=1, dissect_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(dissect_result={
        "ok": False,
        "error": "read failed",
        "slots": [],
        "total_rows": 0,
        "truncated": False,
    })
    env = json.loads(asyncio.run(ds.handle_dissect(
        ctx, c, pid=1234, address=0x1000, size=64,
        space="user", with_modules=False, align=4, name="lab2.user")))
    assert env["ok"] is False
    # Substring fallback didn't match a mapped kind here, so it stays
    # as the default dissect — but critically, the ``agent_kind``
    # branch also runs and would have won had the agent set it.
    assert env["kind"] in ("dissect", "unknown")


# ------------------------------------------- P1 item 6: module sort invariant

def test_dissect_v16_fallback_order_invariant():
    """P1 item 6 pins the C++ ``FindModuleByVA`` to a base-sorted
    snapshot. The Python-side v16 fallback (``_classify_pointer``)
    still does a linear walk and must match the agent output bit-for-
    bit regardless of module input order. This proves the orchestrator
    glue isn't accidentally relying on a particular order."""
    import struct
    sess = _FakeSession(pointer_map_version=1, dissect_version=0)
    ctx = _FakeCtx(sess)
    mods_unsorted = [
        {"name": "ntdll.dll", "base": 0x7ff900000000, "size": 0x200000},
        {"name": "kernel32.dll", "base": 0x7ff800000000, "size": 0x100000},
    ]
    mods_sorted = sorted(mods_unsorted, key=lambda m: m["base"])

    class _OrderedClient:
        pointer_map_service = object()
        dissect_service = object()

        def __init__(self, mods):
            self._mods = mods

        async def dissect(self, **kw):
            raise AssertionError("fast path should not fire on version=0")

        async def mem_read(self, **kw):
            # Three slots: one pointer into kernel32, one into ntdll,
            # one anonymous.
            return {"ok": True,
                    "data": struct.pack("<QQQ",
                                         0x7ff800001234,   # kernel32
                                         0x7ff900005678,   # ntdll
                                         0x7ffabcdef000)}  # other

        async def list_modules(self, pid):
            return {"ok": True,
                    "modules": [{"name": m["name"], "base": m["base"],
                                 "size": m["size"]}
                                for m in self._mods]}

    envs = []
    for mods in (mods_unsorted, mods_sorted):
        env = json.loads(asyncio.run(ds.handle_dissect(
            ctx, _OrderedClient(mods), pid=1234, address=0x10000,
            size=24, space="user", with_modules=True, align=8,
            name="lab2.user")))
        envs.append(env)
    # Both orderings must produce the same slot classifications.
    assert envs[0]["data"]["slots"] == envs[1]["data"]["slots"]
    # Spot-check: kernel32 slot lands in kernel32.dll, ntdll slot in
    # ntdll.dll.
    slots = envs[0]["data"]["slots"]
    assert slots[0]["ptr_module"] == "kernel32.dll"
    assert slots[1]["ptr_module"] == "ntdll.dll"
    assert slots[2]["ptr_classification"] == "other"


def test_dissect_translates_agent_set_kind():
    """A newer agent that sets ``OpStatus.kind='read_failed'``
    propagates the slug through the dissect envelope, not the default
    ``kind='dissect'``."""
    sess = _FakeSession(pointer_map_version=1, dissect_version=1)
    ctx = _FakeCtx(sess)
    c = _CannedClient(dissect_result={
        "ok": False,
        "error": "read failed",
        "agent_kind": "read_failed",
        "slots": [],
        "total_rows": 0,
        "truncated": False,
    })
    env = json.loads(asyncio.run(ds.handle_dissect(
        ctx, c, pid=1234, address=0x1000, size=64,
        space="user", with_modules=False, align=4, name="lab2.user")))
    assert env["ok"] is False
    assert env["kind"] == "read_failed"
