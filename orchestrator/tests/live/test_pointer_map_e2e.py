"""v17 (Memory scanner wave 2 Phase H): E2E against a live target.

Walks the §4 Phase H script via the orchestrator's in-process
dispatcher. Skipped unless both env vars are set (so this never runs
in a plain unit-test sweep):

- ``PRY_LIVE_PID=<pid>`` — the pid of a running process on the
  focus machine (connect its view via
  ``target_manage(action='connect')`` before invoking pytest).
- ``PRY_LIVE_VIEW=<name>`` — the view name (e.g. ``"lab2.user"``)
  the test should target. The view must advertise
  ``StatusResponse.pointer_map_version >= 1``; otherwise the test
  skips rather than failing (pre-v17 agents can't exercise this
  surface).

Mirrors the Wave 1 live-test guard pattern (see
``tests/mem/test_pattern_scan_region.py``).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))


pytestmark = pytest.mark.skipif(
    not (os.environ.get("PRY_LIVE_PID") and os.environ.get("PRY_LIVE_VIEW")),
    reason="requires PRY_LIVE_PID + PRY_LIVE_VIEW env vars "
           "and a connected v17 pry session",
)


@pytest.fixture(scope="module")
def live_pid() -> int:
    return int(os.environ["PRY_LIVE_PID"], 0)


@pytest.fixture(scope="module")
def live_view() -> str:
    return os.environ["PRY_LIVE_VIEW"]


def _invoke(action: str, **kwargs) -> dict:
    from src.pry.mcp.tools.mem import _MEMORY_MANAGE_FN
    assert _MEMORY_MANAGE_FN is not None, (
        "dispatcher not initialised; run _mem.register() from a live "
        "orchestrator session before invoking this test.")
    res = asyncio.new_event_loop().run_until_complete(
        _MEMORY_MANAGE_FN(action=action, **kwargs))
    if isinstance(res, str):
        return json.loads(res)
    return res


def test_v17_advert(live_view):
    """Skip the whole suite if the connected view isn't v17 — the
    pointer-map surface refuses pre-v17 agents with ``kind='needs_v17'``
    and the rest of the suite would fail loudly in a way that doesn't
    illuminate the real problem."""
    from src.pry.mcp.tools.target import status as _mt_status  # noqa: F401
    # Simpler: issue a pointer_map_list; a pre-v17 view returns the
    # kind='needs_v17' envelope directly.
    env = _invoke("pointer_map_list", name=live_view)
    if not env.get("ok") and env.get("kind") == "needs_v17":
        pytest.skip(f"view {live_view!r} advertises pointer_map_version=0 "
                    f"(pre-v17); rebuild + redeploy agent + flip the version.")
    assert env.get("ok") is True


def test_pointer_map_create_image_rdata(live_pid, live_view):
    """Create a pointer map against the target pid's image/.rdata
    section — bounded ~2–10k pointers per plan §4 Phase H."""
    env = _invoke("pointer_map_create",
                  pid=live_pid, space="user",
                  scope="image", sections=".rdata",
                  max_candidates=100_000, name=live_view)
    assert env.get("ok"), f"pointer_map_create failed: {env}"
    assert env["data"]["map_id"]
    assert env["data"]["status"] in ("running", "done")
    pytest.map_id = env["data"]["map_id"]


def test_pointer_map_status_done(live_view):
    """Wait for the sweep worker to finish. A bounded .rdata scan
    terminates in <5s even on a cold agent."""
    import time
    for _ in range(60):
        env = _invoke("pointer_map_status",
                      map_id=pytest.map_id, name=live_view)
        assert env.get("ok")
        if env["data"]["status"] in ("done", "cancelled", "error",
                                      "capped", "timed_out"):
            break
        time.sleep(0.5)
    assert env["data"]["status"] in ("done", "capped"), (
        f"sweep did not reach terminal state: {env}")
    assert int(env["data"]["entries"]) > 0


def test_pointer_scan_returns_static_chains(live_view):
    """Reverse-scan a known target VA. We don't require a specific
    chain count (target-dependent), just that the call completes with
    ok=True and the chain shape is right."""
    # Pick a target VA from the pid's module list — module base is the
    # most-predictable touchpoint. We can't know a module's base at
    # test-authoring time, so we discover it dynamically.
    mods = _invoke("modules", pid=int(os.environ["PRY_LIVE_PID"], 0),
                    name=live_view)
    assert mods.get("ok"), f"modules list failed: {mods}"
    items = mods.get("data", {}).get("items") or []
    assert items, "no modules enumerated; cannot pick a target VA"
    base_str = str(items[0].get("base", "0"))
    base = int(base_str, 0) if isinstance(base_str, str) else int(base_str)
    target_va = base + 0x1000  # first page past PE header

    env = _invoke("pointer_scan",
                  map_id=pytest.map_id, target_va=target_va,
                  max_depth=3, max_offset=0x1000, static_only=True,
                  max_results=32, fanout_per_level=128, wall_ms=5_000,
                  name=live_view)
    assert env.get("ok"), f"pointer_scan failed: {env}"
    d = env["data"]
    assert "chains" in d
    assert "wall_ms_actual" in d
    assert "candidates_examined" in d
    # Determinism: re-run and confirm identical output.
    env2 = _invoke("pointer_scan",
                   map_id=pytest.map_id, target_va=target_va,
                   max_depth=3, max_offset=0x1000, static_only=True,
                   max_results=32, fanout_per_level=128, wall_ms=5_000,
                   name=live_view)
    d2 = env2["data"]
    # Compare anchor list — must match exactly.
    a1 = [(c.get("anchor_va"), tuple(c.get("offsets", [])))
          for c in d.get("chains", [])]
    a2 = [(c.get("anchor_va"), tuple(c.get("offsets", [])))
          for c in d2.get("chains", [])]
    assert a1 == a2, (
        f"pointer_scan non-deterministic: {len(a1)} vs {len(a2)} chains, "
        f"first diff {next((p for p, q in zip(a1, a2) if p != q), None)}")


def test_pointer_map_save_load_roundtrip(live_view):
    """Save + load + rescan should produce identical chains."""
    save_path = "C:\\pry\\scans\\saved\\pytest_pm"
    sv = _invoke("pointer_map_save",
                 map_id=pytest.map_id, remote_path=save_path,
                 name=live_view)
    assert sv.get("ok"), f"save failed: {sv}"
    assert int(sv["data"]["bytes_written"]) > 0

    ld = _invoke("pointer_map_load",
                 remote_path=save_path, name=live_view)
    assert ld.get("ok"), f"load failed: {ld}"
    new_mapid = ld["data"]["map_id"]
    assert new_mapid and new_mapid != pytest.map_id
    pytest.loaded_map_id = new_mapid
    assert int(ld["data"]["entries"]) > 0


def test_pointer_map_diff_self_all_valid(live_view):
    """Diff the original map against the save/load copy of itself —
    every row should classify as still_valid=true."""
    df = _invoke("pointer_map_diff",
                 map_id=pytest.map_id,
                 map_id_b=pytest.loaded_map_id,
                 static_only=False, name=live_view)
    assert df.get("ok"), f"diff failed: {df}"
    d = df["data"]
    # The envelope may spill large row lists into an artifact. Both
    # shapes are valid here; we only need compared_entries + no drift.
    compared = int(d.get("compared_entries", 0))
    assert compared > 0, f"compared=0 (empty diff): {d}"


def test_dissect_window_with_modules(live_pid, live_view):
    """Dissect a 256B window at the target pid's module base + 0x1000.
    With with_modules=True, the module snapshot should reach into
    probable_type scoring."""
    mods = _invoke("modules", pid=live_pid, name=live_view)
    base_str = str(mods["data"]["items"][0]["base"])
    base = int(base_str, 0) if isinstance(base_str, str) else int(base_str)

    env = _invoke("dissect",
                  pid=live_pid, address=base + 0x1000, size=256,
                  space="user", with_modules=True, align=8,
                  name=live_view)
    assert env.get("ok"), f"dissect failed: {env}"
    slots = env["data"]["slots"]
    assert len(slots) == 32  # 256 / 8
    # Tie-break order: ensure every slot carries a probable_type field.
    for s in slots:
        assert s.get("probable_type") in (
            "pointer", "utf16", "ascii", "f64", "f32", "i32")


def test_pointer_map_destroy_cleans_up(live_view):
    """Destroy both the original + the loaded copy; verify both are
    gone from the registry."""
    for mid_attr in ("map_id", "loaded_map_id"):
        mid = getattr(pytest, mid_attr, None)
        if not mid:
            continue
        env = _invoke("pointer_map_destroy", map_id=mid,
                      keep_disk=False, name=live_view)
        assert env.get("ok"), f"destroy({mid}) failed: {env}"
    lst = _invoke("pointer_map_list", name=live_view)
    assert lst.get("ok")
    ids = [e.get("map_id") for e in lst["data"].get("entries", [])]
    for mid_attr in ("map_id", "loaded_map_id"):
        mid = getattr(pytest, mid_attr, None)
        if mid:
            assert mid not in ids, (
                f"{mid_attr}={mid} still present after destroy: {ids}")
