"""End-to-end AccessTrace smoke test (plan §4.7).

Drives a real agent (lab target) with:

  1. Bind a known read/write loop onto a page we control.
  2. ``access_trace_start`` against the page with
     driver='watchhw' + security.allow_hw_bp_hook=true.
  3. Drive the loop, poll ``access_trace_status`` until the ring has
     the expected hits.
  4. ``access_trace_stop`` and assert the DR slot released.

Deferred per the Memory scanner wave 3 kickoff — the agent still has to
ship the hw-watch shim (``bp_hw_watch_add``) before this test can
run live. The watchhw and dbgeng unit tests cover the orchestrator
side of the feature in the meantime.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(
    reason=(
        "needs rebuilt agent; deferred per Memory scanner wave 3 kickoff"
    )
)


def test_access_trace_end_to_end():
    # Placeholder — the real test will live here once the agent build
    # that exposes bp_hw_watch_add is deployed. See the module
    # docstring for the operational outline.
    assert False, "deferred"
