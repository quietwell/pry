"""token_manage view verbs.

Covers:
- ``view`` returns the dict shape slice 01 §Feature 1 documents, with
  include_* kwargs gating optional sub-blocks.
- ``lookup_sid`` short-circuits well-known SIDs locally (SYSTEM /
  Administrators) without touching the agent stub.
- ``well_known_sids`` dumps the vendored table.
- ``logon_sessions`` paginates via limit/offset.
- An older agent returns ``kind='agent_version'``.
- PPL coverage asymmetry documented in the help blurb (umagent fails,
  agent view routes via Wave-1 HANDLE_DUP for reads).
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from pry.mcp.tools import token as _token_tool
from pry.mcp.tools.token import TOKEN_ACTIONS, _TOKEN_ACTION_HELP


def _run(coro):
    return asyncio.run(coro)


# -----------------------------------------------------------------------
# Registration + help surface
# -----------------------------------------------------------------------


def test_token_actions_registered() -> None:
    for a in ("view", "lookup_sid", "well_known_sids", "logon_sessions",
              "enable_privilege", "disable_privilege", "remove_privilege",
              "set_integrity_level", "set_virtualization",
              "impersonate", "stop_impersonate", "modify_default_dacl",
              "actions"):
        assert a in TOKEN_ACTIONS


def test_token_help_mentions_ppl_asymmetry() -> None:
    """PPL coverage asymmetry (README §7) must appear in the view help
    blurb and the privilege-mutator help blurbs."""
    assert "PPL" in _TOKEN_ACTION_HELP["view"]["one_liner"]
    assert "PPL" in _TOKEN_ACTION_HELP["enable_privilege"]["one_liner"]


def test_token_help_mentions_dc_latency() -> None:
    assert "DC" in _TOKEN_ACTION_HELP["lookup_sid"]["one_liner"]


# -----------------------------------------------------------------------
# token_view — happy path
# -----------------------------------------------------------------------


class _StubToken:
    """Fake AgentClient — exercises every token_* wrapper the orchestrator
    uses. ``token`` is a non-None sentinel so missing-stub degrade is
    bypassed."""

    def __init__(self) -> None:
        self.token_svc = object()
        self.last_view_pid: int | None = None
        self.last_lookup: dict | None = None
        self.last_adjust: dict | None = None
        self.canned_view: dict[str, Any] | None = None

    async def token_view(self, **kw) -> dict[str, Any]:
        self.last_view_pid = kw.get("pid")
        if self.canned_view is not None:
            return self.canned_view
        base = {
            "ok": True, "pid": kw["pid"], "tid": kw.get("tid", 0),
            "token_source": "primary", "thread_impersonating": False,
            "user_sid": "S-1-5-18", "user_name": "SYSTEM",
            "user_domain": "NT AUTHORITY", "logon_sid": "",
            "integrity_level_rid": 0x4000,
            "integrity_level_name": "system",
            "elevation_type": "default",
            "is_elevated": True,
            "linked_token_present": False,
            "uac_virtualization_enabled": False,
            "uac_virtualization_allowed": False,
            "mandatory_policy": 1,
            "session_id": 0,
            "logon_session_id_low": 0x3e7,
            "logon_session_id_high": 0,
            "is_app_container": False,
            "app_container_sid": "", "app_container_name": "",
            "app_container_number": 0,
            "trust_label_sid": "", "trust_label_name": "",
        }
        if kw.get("include_groups"):
            base["groups"] = [
                {"sid": "S-1-5-32-544", "name": "Administrators",
                 "domain": "BUILTIN",
                 "flags": {"deny": False, "mandatory": True,
                            "integrity": False, "logon_id": False,
                            "enabled": True, "enabled_by_default": True,
                            "use_for_deny_only": False,
                            "owner": True, "resource": False},
                 "attributes": 0xE, "use": "Alias"},
            ]
        if kw.get("include_privileges"):
            base["privileges"] = [
                {"luid_low": 20, "luid_high": 0,
                 "name": "SeDebugPrivilege",
                 "display_name": "Debug programs",
                 "attributes": 2, "state": "enabled",
                 "enabled_by_default": True},
            ]
        if kw.get("include_logon_session"):
            base["logon_session"] = {
                "logon_id_low": 0x3e7, "logon_id_high": 0,
                "user_name": "SYSTEM",
                "auth_domain": "NT AUTHORITY",
                "logon_type": 0, "logon_type_name": "Unknown",
                "session_id": 0, "logon_time_100ns": 0,
                "logoff_time_100ns": 0, "logon_server": "",
                "dns_domain": "", "upn": "", "user_flags": 0,
            }
        return base

    async def token_lookup_sid(self, *, sids, names):
        self.last_lookup = {"sids": list(sids), "names": list(names)}
        rows = []
        for s in sids:
            rows.append({"input": s, "sid": s, "name": "ResolvedName",
                         "domain": "DC", "type": "User",
                         "well_known": False})
        for n in names:
            rows.append({"input": n, "sid": "S-1-5-1234-" + str(hash(n) & 0xFFFF),
                         "name": n, "domain": "", "type": "User",
                         "well_known": False})
        return {"ok": True, "rows": rows}

    async def token_logon_sessions(self, *, include_dns_names):
        return {"ok": True, "sessions": [
            {"logon_id_low": i, "logon_id_high": 0,
             "user_name": f"user{i}", "auth_domain": "NT AUTHORITY",
             "logon_type": 2, "logon_type_name": "Interactive",
             "session_id": 1, "logon_time_100ns": 0,
             "logoff_time_100ns": 0, "logon_server": "DC",
             "dns_domain": "", "upn": "", "user_flags": 0,
             "auth_package": ""}
            for i in range(5)]}

    async def token_adjust_privilege(self, **kw):
        self.last_adjust = dict(kw)
        return {"ok": True, "previous_state": "disabled",
                "new_state": "enabled",
                "luid_low": 20, "luid_high": 0}


class _StubNoToken:
    """Older agent: no `.token_svc` stub."""
    token_svc = None

    async def token_view(self, **kw):
        return {"ok": False, "kind": "agent_version",
                "error": ("token_view: older agent/umagent "
                          "(Token service missing)")}

    async def token_lookup_sid(self, **kw):
        return {"ok": False, "kind": "agent_version",
                "error": "Token service missing"}

    async def token_logon_sessions(self, **kw):
        return {"ok": False, "kind": "agent_version",
                "error": "Token service missing"}


def test_view_happy_path_minimal() -> None:
    stub = _StubToken()
    out = _run(_token_tool.handle_view(
        ctx=None, c=stub, pid=4,
        include_groups=False, include_privileges=False,
        include_security_attributes=False, include_logon_session=False))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["pid"] == 4
    assert r["user_sid"] == "S-1-5-18"
    assert r["integrity_level_name"] == "system"
    # minimal view: no optional sub-blocks
    assert "groups" not in r
    assert "privileges" not in r
    assert "logon_session" not in r
    assert r["coverage"]["status"] == "complete"


def test_view_includes_opt_sub_blocks() -> None:
    stub = _StubToken()
    out = _run(_token_tool.handle_view(
        ctx=None, c=stub, pid=4,
        include_groups=True, include_privileges=True,
        include_security_attributes=False, include_logon_session=True))
    r = json.loads(out)
    assert r["ok"] is True
    assert len(r["groups"]) == 1
    assert r["groups"][0]["name"] == "Administrators"
    assert len(r["privileges"]) == 1
    assert r["privileges"][0]["name"] == "SeDebugPrivilege"
    assert r["logon_session"]["user_name"] == "SYSTEM"


def test_view_older_agent_degrades() -> None:
    out = _run(_token_tool.handle_view(
        ctx=None, c=_StubNoToken(), pid=4,
        include_groups=False, include_privileges=False,
        include_security_attributes=False, include_logon_session=False))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "agent_version"


def test_view_rejects_zero_pid() -> None:
    out = _run(_token_tool.handle_view(
        ctx=None, c=_StubToken(), pid=0,
        include_groups=False, include_privileges=False,
        include_security_attributes=False, include_logon_session=False))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "bad_arg"


# -----------------------------------------------------------------------
# lookup_sid — well-known SIDs short-circuit; others pass to the stub
# -----------------------------------------------------------------------


def test_lookup_sid_short_circuits_well_known() -> None:
    stub = _StubToken()
    out = _run(_token_tool.handle_lookup_sid(
        ctx=None, c=stub,
        sids=["S-1-5-18", "S-1-5-32-544"], names=[]))
    r = json.loads(out)
    assert r["ok"] is True
    rows = r["rows"]
    assert any(row["sid"] == "S-1-5-18" and row["name"] == "SYSTEM"
               and row["well_known"] is True for row in rows)
    assert any(row["sid"] == "S-1-5-32-544" and row["name"] == "Administrators"
               and row["well_known"] is True for row in rows)
    # Short-circuited rows must not have touched the stub.
    assert stub.last_lookup is None


def test_lookup_sid_dispatches_unknown_to_agent() -> None:
    stub = _StubToken()
    out = _run(_token_tool.handle_lookup_sid(
        ctx=None, c=stub,
        sids=["S-1-5-21-9999-9999-9999-1001"], names=[]))
    r = json.loads(out)
    assert r["ok"] is True
    assert stub.last_lookup == {
        "sids": ["S-1-5-21-9999-9999-9999-1001"], "names": []}
    assert len(r["rows"]) == 1
    assert r["rows"][0]["sid"] == "S-1-5-21-9999-9999-9999-1001"


def test_lookup_sid_requires_input() -> None:
    out = _run(_token_tool.handle_lookup_sid(
        ctx=None, c=_StubToken(), sids=[], names=[]))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "bad_arg"


# -----------------------------------------------------------------------
# well_known_sids
# -----------------------------------------------------------------------


def test_well_known_sids_dumps_vendored_table() -> None:
    out = _run(_token_tool.handle_well_known_sids(ctx=None, c=_StubToken()))
    r = json.loads(out)
    assert r["ok"] is True
    sids = {row["sid"] for row in r["rows"]}
    assert "S-1-5-18" in sids
    assert "S-1-5-32-544" in sids
    assert "S-1-16-16384" in sids   # System Mandatory Level
    assert r["coverage"]["status"] == "complete"


# -----------------------------------------------------------------------
# logon_sessions pagination
# -----------------------------------------------------------------------


def test_logon_sessions_paginates() -> None:
    out = _run(_token_tool.handle_logon_sessions(
        ctx=None, c=_StubToken(), include_dns_names=False,
        limit=2, offset=1))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["total"] == 5
    assert len(r["sessions"]) == 2
    assert r["sessions"][0]["user_name"] == "user1"
    assert r["truncated"] is True
