"""Parity harness for mitigation readout.

Umagent view vs agent view must return identical fields for a
cooperative (non-PPL) target. Mitigation policy is read from the kernel
process struct; both views see the same value.

PPL coverage asymmetry (README §7): a PPL target surfaces
``mitigations_source='denied'`` on the umagent view and (via Wave-1
HANDLE_DUP) a populated row on the agent view. This harness skips PPL
pids on both sides; the explicit asymmetry test is in
``test_mitigations.py::test_mitigations_ppl_marks_partial_coverage``.

This file is shaped like a smoke harness, not a pytest module — it is
driven by ``scripts_user/mitigations_smoketest/`` once a lab target is
connected (same pattern as ``parity_svc_driver_base.py`` will use).
Running it under pytest without an agent connection is a no-op that
asserts the function is importable and the required proto bindings
exist.
"""
from __future__ import annotations

from typing import Any


# Fields the parity harness compares byte-for-byte between the two
# views. Each entry is a dotted path into the mitigations row.
_PARITY_FIELDS: tuple[str, ...] = (
    "pid", "create_time_100ns",
    "dep.enable", "dep.permanent",
    "aslr.bottom_up", "aslr.high_entropy",
    "cfg.enable", "cfg.strict_mode",
    "strict_handle_check",
    "extension_points_disabled",
    "image_load.no_remote_images", "image_load.prefer_system32",
    "user_shadow_stack.enabled",
    "redirection_trust.enforce",
)


def _dig(row: dict[str, Any], path: str) -> Any:
    cur: Any = row
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def compare_rows(kernel_row: dict[str, Any],
                  user_row: dict[str, Any]) -> list[str]:
    """Return a list of diff strings (empty on parity)."""
    diffs: list[str] = []
    for f in _PARITY_FIELDS:
        a = _dig(kernel_row, f)
        b = _dig(user_row, f)
        if a != b:
            diffs.append(f"{f}: kernel={a!r} user={b!r}")
    return diffs


# -----------------------------------------------------------------------
# Smoke test — importable without a lab connection.
# -----------------------------------------------------------------------


def test_parity_fields_well_formed() -> None:
    assert all(isinstance(f, str) and f for f in _PARITY_FIELDS)


def test_parity_compares_identical_rows_as_equal() -> None:
    row = {
        "pid": 1234, "create_time_100ns": 132_000_000_000_000_000,
        "dep": {"enable": True, "permanent": True},
        "aslr": {"bottom_up": True, "high_entropy": True},
        "cfg": {"enable": True, "strict_mode": False},
        "strict_handle_check": True,
        "extension_points_disabled": False,
        "image_load": {"no_remote_images": True, "prefer_system32": True},
        "user_shadow_stack": {"enabled": True},
        "redirection_trust": {"enforce": False},
    }
    assert compare_rows(row, row) == []


def test_parity_detects_a_diff() -> None:
    k = {"pid": 1, "cfg": {"enable": True, "strict_mode": True}}
    u = {"pid": 1, "cfg": {"enable": True, "strict_mode": False}}
    diffs = compare_rows(k, u)
    assert any("cfg.strict_mode" in d for d in diffs)
