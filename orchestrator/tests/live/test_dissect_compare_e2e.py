"""DissectCompare live E2E test.

Plan §3.5: pick 3-6 pointer-map entries sharing the same terminal
module, run ``dissect_compare`` at ``window=0x80``, and assert at least
one ``stable`` offset and one ``per_instance_*`` offset.

Deferred per the Memory scanner wave 3 kickoff: a rebuilt agent is required
to advertise ``dissect_version=2`` and register the Compare handler on
the running MCP binary. The orchestrator-side tests cover the gate +
preflight + taxonomy contract without live hardware.
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


pytestmark = pytest.mark.skip(
    reason="needs rebuilt agent; deferred per Memory scanner wave 3 kickoff")


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


def test_dissect_compare_live_smoke(live_pid, live_view):
    """E2E smoke: build a pointer map, pull a few chains pointing at the
    same anchor module, then run dissect_compare on the chain sources.
    Skipped by default; needs a rebuilt agent advertising
    ``dissect_version >= 2``."""
    # Step 1: build the pointer map (bounded scope).
    create = _invoke("pointer_map_create", name=live_view, pid=live_pid,
                     scope="image", sections=".rdata")
    assert create["ok"], create
    map_id = create["data"]["map_id"]

    # Step 2: reverse-scan for a module-interior target. In practice the
    # test harness picks a VA inside a known .rdata region; for the
    # scaffolding we accept any non-empty scan result.
    scan = _invoke("pointer_scan", name=live_view, map_id=map_id,
                   target_va=0, max_depth=3, max_results=6)
    assert scan["ok"], scan
    chains = scan["data"].get("chains") or []
    assert len(chains) >= 3, "need >= 3 chains for compare"

    # Step 3: compare the chain anchors at window=0x80.
    base_vas = [int(c["anchor_va"]) for c in chains[:6]]
    cmp_env = _invoke("dissect_compare", name=live_view, pid=live_pid,
                      base_vas=base_vas, window_size=0x80, align=8,
                      with_modules=True)
    assert cmp_env["ok"], cmp_env
    offsets = cmp_env["data"]["offsets"]
    classes = {o["classification"] for o in offsets}
    assert "stable" in classes, (
        f"expected at least one stable offset, got {classes}")
    assert any(c.startswith("per_instance_") for c in classes), (
        f"expected at least one per_instance_* offset, got {classes}")
