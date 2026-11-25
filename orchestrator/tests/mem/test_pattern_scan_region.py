"""E2E: ``pattern_scan`` + region filter against a live target.

Skipped unless both of these env vars are set (so this test never
runs in a plain unit-test sweep):

- ``PRY_LIVE_PID=<pid>`` — the pid of a running process on the
  focus machine (connect it via ``target_manage(action='connect')``
  before invoking pytest).
- ``PRY_LIVE_PATTERN`` — an AOB string (``"48 8B 05 ?? ?? ?? ??"``
  shape) known to exist in that pid's memory. The test does not
  write to the target; it only reads.

Intent: pattern a known AOB with ``scope='heap'`` and then re-pattern
with ``scope='image'`` — one call hits, the other misses. The exact
signatures depend on the target, so the harness lets the operator
supply them.

The orchestrator must already have an agent connection; the test
does not call ``target_manage(action='connect')`` itself. Run from
a terminal session that is NOT the one hosting the pry server
(the server's process space is shared with the Python
interpreter running pytest).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))


pytestmark = pytest.mark.skipif(
    not (os.environ.get("PRY_LIVE_PID")
         and os.environ.get("PRY_LIVE_PATTERN")),
    reason="requires PRY_LIVE_PID + PRY_LIVE_PATTERN env vars "
           "and a connected pry session",
)


@pytest.fixture(scope="module")
def live_pid() -> int:
    return int(os.environ["PRY_LIVE_PID"], 0)


@pytest.fixture(scope="module")
def live_pattern() -> str:
    return os.environ["PRY_LIVE_PATTERN"]


def _invoke_pattern_scan(pid: int, pattern: str, **region_kwargs):
    """Call ``memory_manage(action='pattern_scan', ...)`` through the
    orchestrator's in-process dispatcher. Returns the parsed envelope.

    We go through the internal ``_MEMORY_MANAGE_FN`` handle rather than
    the MCP tool wrapper so we don't need an RPC transport; the handler
    is the exact same code path the MCP tool invokes.
    """
    import asyncio
    import json

    from src.pry.mcp.tools.mem import _MEMORY_MANAGE_FN
    assert _MEMORY_MANAGE_FN is not None, \
        "dispatcher not initialised; run _mem.register() from a live " \
        "orchestrator session before invoking this test."

    res = asyncio.new_event_loop().run_until_complete(
        _MEMORY_MANAGE_FN(
            action="pattern_scan",
            pid=pid, pattern=pattern,
            max_results=16,
            **region_kwargs,
        )
    )
    # Dispatcher returns a JSON string or an MCP tool response.
    if isinstance(res, str):
        return json.loads(res)
    body = getattr(res, "structured_content", None) or {}
    return body


def test_region_filter_narrows_scan(live_pid, live_pattern):
    """``scope='heap'`` should match the operator-supplied AOB when
    the operator picks an AOB they know lives in the heap; the same
    AOB with ``scope='image'`` should either miss or return fewer
    hits (an operator-chosen AOB inside a module would obviously
    reverse this)."""
    heap_res = _invoke_pattern_scan(
        live_pid, live_pattern, scope="heap", writable=True)
    image_res = _invoke_pattern_scan(
        live_pid, live_pattern, scope="image", executable=True)

    assert heap_res.get("ok") is True
    assert image_res.get("ok") is True

    heap_hits = heap_res.get("items") or heap_res.get("addresses") or []
    image_hits = image_res.get("items") or image_res.get("addresses") or []

    # The two scopes must not return the same set of hits.
    assert sorted(heap_hits) != sorted(image_hits), (
        "pattern_scan returned the same hits for scope=heap and "
        "scope=image — either the pattern is not in heap-only memory "
        "or region filter is not narrowing. Hits: "
        f"heap={heap_hits!r} image={image_hits!r}")

    # region_filter should be echoed back in the extras for both.
    assert heap_res.get("region_filter", {}).get("scope") == "heap"
    assert image_res.get("region_filter", {}).get("scope") == "image"


def test_region_filter_writable_only_matches_rw_pages(live_pid,
                                                      live_pattern):
    """A writable-only scan should return a subset of the unfiltered
    hits (never a superset)."""
    all_res = _invoke_pattern_scan(live_pid, live_pattern)
    rw_res = _invoke_pattern_scan(
        live_pid, live_pattern, writable=True)
    assert all_res.get("ok") is True
    assert rw_res.get("ok") is True

    def _hits(resp):
        rows = resp.get("items") or resp.get("addresses") or []
        return {int(r, 0) if isinstance(r, str) else int(r) for r in rows}

    all_hits = _hits(all_res)
    rw_hits = _hits(rw_res)
    assert rw_hits.issubset(all_hits), (
        "writable=True returned hits not present in the unfiltered "
        "scan — region filter is not a strict subset. "
        f"extras_only={rw_hits - all_hits!r}")
