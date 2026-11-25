"""Parity harness for token view.

Umagent view vs agent view must return byte-identical ``user_sid``,
``integrity_rid``, ``elevation_type``, ``session_id`` and ``logon_id``
pair for a cooperative non-PPL target. ``groups`` + ``privileges``
parity requires an LSA warmup so group-name resolution hits the agent-
side cache on both views; the harness warms up once before comparing.

Importable under pytest without an agent connection (the ``test_*``
functions below check shape of the comparator; the real lab-driven
parity run lives under ``scripts_user/token_smoketest/``).
"""
from __future__ import annotations

from typing import Any

# Core fields compared byte-for-byte.
_CORE_FIELDS: tuple[str, ...] = (
    "user_sid",
    "integrity_level_rid",
    "integrity_level_name",
    "elevation_type",
    "is_elevated",
    "session_id",
    "logon_session_id_low",
    "logon_session_id_high",
    "mandatory_policy",
    "is_app_container",
    "trust_label_sid",
    "token_source",
    "thread_impersonating",
)

# When include_privileges=True — compared by set of (name, state), not
# by exact ordering (the token itself defines order, but the agent
# might re-wrap identically; still, set-equality is enough for parity).
_PRIV_FIELDS: tuple[str, ...] = ("name", "state", "enabled_by_default")


def compare_cores(agent_row: dict[str, Any],
                   user_row: dict[str, Any]) -> list[str]:
    diffs: list[str] = []
    for f in _CORE_FIELDS:
        a = agent_row.get(f)
        b = user_row.get(f)
        if a != b:
            diffs.append(f"{f}: agent={a!r} user={b!r}")
    return diffs


def compare_privilege_sets(agent_row: dict[str, Any],
                            user_row: dict[str, Any]) -> list[str]:
    def _norm(privs):
        out = set()
        for p in (privs or []):
            out.add(tuple(p.get(k) for k in _PRIV_FIELDS))
        return out
    a = _norm(agent_row.get("privileges"))
    b = _norm(user_row.get("privileges"))
    only_a = a - b
    only_b = b - a
    diffs = []
    if only_a:
        diffs.append(f"privileges only in agent view: {sorted(only_a)}")
    if only_b:
        diffs.append(f"privileges only in user view: {sorted(only_b)}")
    return diffs


def test_parity_core_equal_rows() -> None:
    row = {f: ("S-1-5-18" if f == "user_sid"
                else "primary" if f == "token_source"
                else "system" if f == "integrity_level_name"
                else "default" if f == "elevation_type"
                else 0x4000 if f == "integrity_level_rid"
                else False if f == "thread_impersonating"
                else True if f == "is_elevated"
                else 0 if "session" in f or "mandatory_policy" in f
                else 0 if "logon" in f
                else False if f == "is_app_container"
                else "")
            for f in _CORE_FIELDS}
    assert compare_cores(row, row) == []


def test_parity_detects_logon_id_diff() -> None:
    a = {f: 0 for f in _CORE_FIELDS}
    a["logon_session_id_low"] = 0x3e7
    b = dict(a)
    b["logon_session_id_low"] = 0x3e8
    diffs = compare_cores(a, b)
    assert any("logon_session_id_low" in d for d in diffs)


def test_parity_priv_set_equality() -> None:
    row = {"privileges": [
        {"name": "SeDebugPrivilege", "state": "enabled",
         "enabled_by_default": True},
        {"name": "SeChangeNotifyPrivilege", "state": "enabled",
         "enabled_by_default": True},
    ]}
    assert compare_privilege_sets(row, row) == []


def test_parity_priv_set_detects_added_slot() -> None:
    a = {"privileges": [
        {"name": "SeDebugPrivilege", "state": "enabled",
         "enabled_by_default": True},
    ]}
    b = {"privileges": a["privileges"] + [
        {"name": "SeShutdownPrivilege", "state": "disabled",
         "enabled_by_default": False}]}
    diffs = compare_privilege_sets(a, b)
    assert any("only in user" in d for d in diffs)
