"""Mem-local envelope / coverage shapers.

These wrappers are specific to ``memory_manage`` — they encode the scan-window
coverage rules (`partial` on hit/byte caps or unreadable chunks,
`unknown` for whole-space sweeps) and are consumed by both the ranged
``pattern_scan`` branch and ``pool_scan``. Kept out of
``_runtime/envelope.py`` so the broadly-reusable envelope helpers stay
pure.
"""

from __future__ import annotations

from ..._coverage import coverage as _coverage


__all__ = ["_scan_window_cov"]


def _scan_window_cov(telem: dict | None, ranged: bool) -> dict:
    """scan-window coverage for pattern_scan/pool_scan: hit/byte caps →
    partial, unreadable chunks → partial+range_unreadable, no range
    established (whole-space sweep) → unknown."""
    if not ranged:
        return _coverage("scan-window", "unknown")
    t = telem or {}
    if t.get("truncated"):
        return _coverage("scan-window", "partial", "scan_limit_reached")
    if t.get("chunks_skipped") or t.get("partial_chunks") \
            or t.get("partial_bytes"):
        return _coverage("scan-window", "partial", "range_unreadable")
    return _coverage("scan-window", "complete")
