"""live end-to-end test for
``memory_manage(action='heap_attrib')``.

Per the chunk kickoff, live tests are DEFERRED while this chunk is
in flight — the C++ agent isn't rebuilt in this session, so no lab
target advertises ``memory_heap_attrib_version=1``. The whole file
is marked skip; a later run on a rebuilt agent flips the marker off.

Shape (for the eventual runner):

1. Pick a pid via ``PRY_LIVE_PID``.
2. Walk heaps (``memory_manage(action='heaps', want_blocks=true)``) to
   get a known-live chunk ``(base, size)``.
3. Call ``memory_manage(action='heap_attrib', pid, vas=[base,
   base+size/2, base+size-1])``.
4. Assert all three records come back ``found=true`` with
   ``chunk_base == base`` and ``chunk_size == size`` — the midpoint
   and last-byte lookups both resolve to the same chunk.
5. Assert ``index_from_cache == False`` on the first call.
6. Repeat the call; assert ``index_from_cache == True`` and the
   same cache_epoch.
7. Pass ``refresh=True``; assert ``index_from_cache == False`` and
   a fresh cache_epoch.

See an internal plan §7.6.
"""
from __future__ import annotations

import pytest

# All live tests in this module need the rebuilt agent that
# advertises memory_heap_attrib_version=1. Until that build ships,
# every case is unconditionally skipped.
pytestmark = pytest.mark.skip(
    reason="needs rebuilt agent; deferred per Memory scanner wave 3 kickoff")


def test_heap_attrib_live_e2e():
    """Placeholder for the live matrix above. Runs only once the agent
    is rebuilt (and the chunk-level skip marker is dropped)."""
    raise AssertionError(
        "live heap_attrib test not yet implemented — see module "
        "docstring for the planned shape.")
