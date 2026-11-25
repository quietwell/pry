"""``token_manage`` MCP tool.

Token / privilege / SID viewer + mutator. Modelled on ``tools/bp.py``.

Read verbs land in the first PR of this slice (view, lookup_sid,
well_known_sids, logon_sessions); mutators follow with the actuator
gate + tombstone timer wiring (slice 01 §Impersonation lifecycle).

All mutators sit behind the ``security.allow_token_adjust`` config
flag + the capability-registry actuator-trust gate. PPL coverage
asymmetry (slice 01 §Edge cases): umagent view fails on PPL;
agent view (driver + Wave-1 HANDLE_DUP) succeeds for reads, mutators
still await Wave 3 #23 (KernelMode OpenProcess).

Shared coordination (see 00-combined-plan.md §6):
- ``_runtime/capabilities.py`` lists every verb + its gate.
- ``_runtime/guard.py`` reads the gate from the registry.
"""

from __future__ import annotations

from typing import Any

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .._coverage import coverage as _coverage


TOKEN_ACTIONS = [
    "view", "lookup_sid", "well_known_sids", "logon_sessions",
    "enable_privilege", "disable_privilege", "remove_privilege",
    "set_integrity_level", "set_virtualization",
    "impersonate", "stop_impersonate", "modify_default_dacl",
    "actions",
]


_PPL_HINT = (
    "umagent view fails on PPL; agent view routes via Wave-1 HANDLE_DUP for "
    "reads. Mutators on PPL need Wave 3 #23 (KernelMode OpenProcess).")

_DC_LATENCY_HINT = (
    "LsaLookupSids2 against unreachable DCs can block up to 3s; the agent "
    "surfaces coverage.partial.lsa_timeout on cutoff and leaves SID populated.")


_TOKEN_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "token_manage(action='actions')"},
    "view": {
        "one_liner": ("read everything about a process or thread token "
                      "(user/SID/groups/privileges/integrity/elevation). "
                      "PPL coverage: " + _PPL_HINT),
        "key_args": ("pid, tid, include_groups, include_privileges, "
                     "include_security_attributes, include_logon_session"),
        "example": ("token_manage(action='view', pid=1234, "
                    "include_privileges=True)")},
    "lookup_sid": {
        "one_liner": ("LsaLookupSids2 + reverse LookupAccountNameW + "
                      "well-known-SID short circuit. " + _DC_LATENCY_HINT),
        "key_args": "sids, names",
        "example": ("token_manage(action='lookup_sid', "
                    "sids=['S-1-5-18','S-1-5-32-544'])")},
    "well_known_sids": {
        "one_liner": "dump the well-known SID table (no RPC on hit)",
        "key_args": "none",
        "example": "token_manage(action='well_known_sids')"},
    "logon_sessions": {
        "one_liner": ("LsaEnumerateLogonSessions + LsaGetLogonSessionData "
                      "walk. pages via limit/offset (default 64)"),
        "key_args": "include_dns_names, limit, offset",
        "example": "token_manage(action='logon_sessions')"},
    "enable_privilege": {
        "one_liner": ("AdjustTokenPrivileges(enable). Mutator — gated by "
                      "security.allow_token_adjust + actuator trust. "
                      "ERROR_NOT_ALL_ASSIGNED folds into ok=true with "
                      "previous='absent'/new='absent'. " + _PPL_HINT),
        "key_args": "pid, tid, privilege, luid_low, luid_high",
        "example": ("token_manage(action='enable_privilege', pid=self, "
                    "privilege='SeDebugPrivilege')")},
    "disable_privilege": {
        "one_liner": "AdjustTokenPrivileges(disable). Mutator — see enable.",
        "key_args": "pid, tid, privilege",
        "example": ("token_manage(action='disable_privilege', pid=1234, "
                    "privilege='SeShutdownPrivilege')")},
    "remove_privilege": {
        "one_liner": ("AdjustTokenPrivileges(SE_PRIVILEGE_REMOVED). "
                      "**Destructive** — the slot is gone until the token "
                      "is recreated. Mutator-gated."),
        "key_args": "pid, tid, privilege",
        "example": ("token_manage(action='remove_privilege', pid=1234, "
                    "privilege='SeDebugPrivilege')")},
    "set_integrity_level": {
        "one_liner": ("SetTokenInformation(TokenIntegrityLevel). Caller "
                      "token must be at or above the target IL. Mutator."),
        "key_args": "pid, tid, level (name or RID)",
        "example": ("token_manage(action='set_integrity_level', pid=1234, "
                    "level='low')")},
    "set_virtualization": {
        "one_liner": "SetTokenInformation(TokenVirtualizationEnabled). Mutator.",
        "key_args": "pid, tid, enabled",
        "example": ("token_manage(action='set_virtualization', pid=1234, "
                    "enabled=True)")},
    "impersonate": {
        "one_liner": ("DuplicateTokenEx + SetThreadToken on an agent worker "
                      "thread. Tombstone 30s (persist=False) / 300s "
                      "(persist=True). stop_impersonate clears early. "
                      "Mutator-gated."),
        "key_args": ("source_pid, source_tid, persist, "
                     "impersonation_level, target_tid"),
        "example": ("token_manage(action='impersonate', source_pid=4, "
                    "persist=False)")},
    "stop_impersonate": {
        "one_liner": ("clear the agent-side thread token "
                      "(SetThreadToken(NULL)). No gate — explicit teardown "
                      "of a prior impersonate."),
        "key_args": "impersonation_id",
        "example": ("token_manage(action='stop_impersonate', "
                    "impersonation_id='imp-7f3...')")},
    "modify_default_dacl": {
        "one_liner": ("SetTokenInformation(TokenDefaultDacl). Caller passes "
                      "an explicit SID+mask list; no 'everyone' sugar. "
                      "Mutator-gated."),
        "key_args": "pid, tid, aces, replace",
        "example": ("token_manage(action='modify_default_dacl', pid=1234, "
                    "aces=[{'sid':'S-1-5-18','access_mask':0xf01ff,"
                    "'type':'allow'}])")},
}


# Which verbs are mutators — mirrors the capability registry so the gate
# check works even if the registry is misconfigured.
_MUTATOR_ACTIONS = frozenset({
    "enable_privilege", "disable_privilege", "remove_privilege",
    "set_integrity_level", "set_virtualization",
    "impersonate", "modify_default_dacl",
    # stop_impersonate is a mutator but ungated — it clears a prior op.
})


# Vendored well-known SID table (short-circuit for the lookup_sid verb).
# One row per WELL_KNOWN_SID_TYPE that SI's prpgtok.c calls out. The
# ``well_known_sids`` verb emits this table verbatim; ``lookup_sid`` hits
# it before issuing any LSA call so a reachable-DC round trip is skipped.
_WELL_KNOWN_SIDS: list[dict[str, str]] = [
    {"sid": "S-1-0-0",       "name": "Null SID",       "type": "well_known_group"},
    {"sid": "S-1-1-0",       "name": "Everyone",       "type": "well_known_group"},
    {"sid": "S-1-2-0",       "name": "LOCAL",          "type": "well_known_group"},
    {"sid": "S-1-3-0",       "name": "CREATOR OWNER",  "type": "well_known_group"},
    {"sid": "S-1-3-1",       "name": "CREATOR GROUP",  "type": "well_known_group"},
    {"sid": "S-1-5-1",       "name": "DIALUP",         "type": "well_known_group"},
    {"sid": "S-1-5-2",       "name": "NETWORK",        "type": "well_known_group"},
    {"sid": "S-1-5-3",       "name": "BATCH",          "type": "well_known_group"},
    {"sid": "S-1-5-4",       "name": "INTERACTIVE",    "type": "well_known_group"},
    {"sid": "S-1-5-6",       "name": "SERVICE",        "type": "well_known_group"},
    {"sid": "S-1-5-7",       "name": "ANONYMOUS LOGON", "type": "well_known_group"},
    {"sid": "S-1-5-11",      "name": "Authenticated Users", "type": "well_known_group"},
    {"sid": "S-1-5-18",      "name": "SYSTEM",         "type": "user"},
    {"sid": "S-1-5-19",      "name": "LOCAL SERVICE",  "type": "user"},
    {"sid": "S-1-5-20",      "name": "NETWORK SERVICE", "type": "user"},
    {"sid": "S-1-5-32-544",  "name": "Administrators", "type": "alias"},
    {"sid": "S-1-5-32-545",  "name": "Users",          "type": "alias"},
    {"sid": "S-1-5-32-546",  "name": "Guests",         "type": "alias"},
    {"sid": "S-1-5-32-547",  "name": "Power Users",    "type": "alias"},
    {"sid": "S-1-5-32-551",  "name": "Backup Operators", "type": "alias"},
    {"sid": "S-1-5-32-555",  "name": "Remote Desktop Users", "type": "alias"},
    {"sid": "S-1-16-0",      "name": "Untrusted Mandatory Level", "type": "label"},
    {"sid": "S-1-16-4096",   "name": "Low Mandatory Level",       "type": "label"},
    {"sid": "S-1-16-8192",   "name": "Medium Mandatory Level",    "type": "label"},
    {"sid": "S-1-16-8448",   "name": "Medium Plus Mandatory Level", "type": "label"},
    {"sid": "S-1-16-12288",  "name": "High Mandatory Level",      "type": "label"},
    {"sid": "S-1-16-16384",  "name": "System Mandatory Level",    "type": "label"},
    {"sid": "S-1-16-20480",  "name": "Protected Process Mandatory Level", "type": "label"},
]


def _mutator_not_allowed(action: str) -> dict[str, Any]:
    return {
        "ok": False, "kind": "not_allowed",
        "error": (f"token_manage.{action}: security.allow_token_adjust=false "
                  "— the mutator is refused by config"),
        "hint": ("set security.allow_token_adjust=true in the orchestrator "
                 "config to permit token adjust/impersonate/modify_dacl"),
    }


def _check_mutator_gate(ctx, action: str) -> dict[str, Any] | None:
    """Return a ``not_allowed`` envelope when the config flag is off,
    else None. Used before every mutator call."""
    if action not in _MUTATOR_ACTIONS:
        return None
    if ctx is None:
        return None
    sec = getattr(ctx.cfg, "security", None)
    if sec is None or not getattr(sec, "allow_token_adjust", False):
        return _mutator_not_allowed(action)
    return None


# -----------------------------------------------------------------------
# Verb handlers (importable so tests + P1's shell dispatcher both reach
# the same functions).
# -----------------------------------------------------------------------


async def handle_view(ctx, c, *, pid: int, tid: int = 0,
                      include_groups: bool = False,
                      include_privileges: bool = False,
                      include_security_attributes: bool = False,
                      include_logon_session: bool = False) -> str:
    if not pid or int(pid) <= 0:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "view: pid must be a positive integer"})
    res = await c.token_view(
        pid=int(pid), tid=int(tid or 0),
        include_groups=bool(include_groups),
        include_privileges=bool(include_privileges),
        include_security_attributes=bool(include_security_attributes),
        include_logon_session=bool(include_logon_session))
    if not res.get("ok"):
        return _j(res)
    out = dict(res)
    status = "complete"
    sub = []
    err = str(out.get("error") or "")
    if "lsa_timeout" in err.lower():
        status, sub = "partial", ["lsa_timeout"]
    elif "token_class_failed" in err.lower() or "security_attributes" in err.lower():
        status, sub = "partial", ["token_class_failed"]
    out["coverage"] = _coverage("token-window", status, *sub)
    return _j(out)


async def handle_lookup_sid(ctx, c, *, sids: list[str] | None = None,
                            names: list[str] | None = None) -> str:
    sids = [str(s) for s in (sids or []) if s]
    names = [str(n) for n in (names or []) if n]
    if not sids and not names:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "lookup_sid: at least one of sids / names required"})
    # Short-circuit well-known SIDs locally so a disconnected DC never
    # stalls a classifier that only wants system SIDs.
    well_known_by_sid = {w["sid"]: w for w in _WELL_KNOWN_SIDS}
    short_circuited: list[dict[str, Any]] = []
    remaining_sids: list[str] = []
    for s in sids:
        wk = well_known_by_sid.get(s)
        if wk is not None:
            short_circuited.append({
                "input": s, "sid": s, "name": wk["name"],
                "domain": "", "type": wk["type"], "well_known": True,
            })
        else:
            remaining_sids.append(s)
    res = {"ok": True, "rows": []}
    if remaining_sids or names:
        res = await c.token_lookup_sid(sids=remaining_sids, names=names)
    rows = short_circuited + (res.get("rows") or [])
    coverage_status = "complete"
    err = str(res.get("error") or "")
    if "timeout" in err.lower() or "unavailable" in err.lower():
        coverage_status = "partial"
    out = {
        "ok": bool(res.get("ok", True) or short_circuited),
        "rows": rows,
        "coverage": _coverage("sid-lookup",
                              coverage_status,
                              *(["lsa_timeout"]
                                if coverage_status == "partial" else [])),
    }
    if not res.get("ok") and res.get("error"):
        out["error"] = res["error"]
    return _j(out)


async def handle_well_known_sids(ctx, c) -> str:
    return _j({
        "ok": True,
        "rows": [dict(w) for w in _WELL_KNOWN_SIDS],
        "coverage": _coverage("sid-table", "complete"),
    })


async def handle_logon_sessions(ctx, c, *, include_dns_names: bool = False,
                                limit: int = 64, offset: int = 0) -> str:
    res = await c.token_logon_sessions(include_dns_names=bool(include_dns_names))
    if not res.get("ok"):
        return _j(res)
    sessions = res.get("sessions") or []
    total = len(sessions)
    off = max(0, int(offset or 0))
    lim = max(1, int(limit or 64))
    page = sessions[off:off + lim]
    return _j({
        "ok": True,
        "sessions": page,
        "total": total,
        "truncated": (off + lim) < total,
        "coverage": _coverage("logon-sessions", "complete"),
    })


async def _handle_adjust_privilege(ctx, c, action_name: str,
                                   *, pid: int, tid: int,
                                   privilege: str = "",
                                   luid_low: int = 0, luid_high: int = 0
                                   ) -> str:
    denied = _check_mutator_gate(ctx, action_name)
    if denied is not None:
        return _j(denied)
    adjust_action = {"enable_privilege": "enable",
                     "disable_privilege": "disable",
                     "remove_privilege": "remove"}[action_name]
    res = await c.token_adjust_privilege(
        pid=int(pid), tid=int(tid or 0),
        privilege_name=str(privilege or ""),
        luid_low=int(luid_low or 0), luid_high=int(luid_high or 0),
        action=adjust_action,
    )
    return _j(res)


async def handle_enable_privilege(ctx, c, **kw) -> str:
    return await _handle_adjust_privilege(ctx, c, "enable_privilege", **kw)


async def handle_disable_privilege(ctx, c, **kw) -> str:
    return await _handle_adjust_privilege(ctx, c, "disable_privilege", **kw)


async def handle_remove_privilege(ctx, c, **kw) -> str:
    return await _handle_adjust_privilege(ctx, c, "remove_privilege", **kw)


async def handle_set_integrity_level(ctx, c, *, pid: int, tid: int = 0,
                                     level: str | int = "") -> str:
    denied = _check_mutator_gate(ctx, "set_integrity_level")
    if denied is not None:
        return _j(denied)
    rid = 0
    name = ""
    if isinstance(level, int):
        rid = int(level)
    elif isinstance(level, str) and level:
        if level.lower().startswith("0x") or level.isdigit():
            try:
                rid = int(level, 0)
            except ValueError:
                name = level
        else:
            name = level
    res = await c.token_set_integrity(
        pid=int(pid), tid=int(tid or 0),
        integrity_rid=rid, integrity_name=name)
    return _j(res)


async def handle_set_virtualization(ctx, c, *, pid: int, tid: int = 0,
                                    enabled: bool = False) -> str:
    denied = _check_mutator_gate(ctx, "set_virtualization")
    if denied is not None:
        return _j(denied)
    res = await c.token_set_virtualization(
        pid=int(pid), tid=int(tid or 0), enable=bool(enabled))
    return _j(res)


async def handle_impersonate(ctx, c, *, source_pid: int,
                             source_tid: int = 0,
                             persist: bool = False,
                             target_tid: int = 0,
                             impersonation_level: str = "impersonation"
                             ) -> str:
    denied = _check_mutator_gate(ctx, "impersonate")
    if denied is not None:
        return _j(denied)
    res = await c.token_impersonate(
        source_pid=int(source_pid), source_tid=int(source_tid or 0),
        persist=bool(persist), target_tid=int(target_tid or 0),
        impersonation_level=str(impersonation_level or "impersonation"))
    if res.get("ok"):
        # Surface the tombstone budget so a caller sees the window.
        res = dict(res)
        res["tombstone_seconds"] = 300 if persist else 30
        res["persist"] = bool(persist)
    return _j(res)


async def handle_stop_impersonate(ctx, c, *, impersonation_id: str) -> str:
    # ungated: explicit teardown of a prior impersonate
    res = await c.token_stop_impersonate(
        impersonation_id=str(impersonation_id or ""))
    return _j(res)


async def handle_modify_default_dacl(ctx, c, *, pid: int, tid: int = 0,
                                     aces: list[dict[str, Any]] | None = None,
                                     replace: bool = False) -> str:
    denied = _check_mutator_gate(ctx, "modify_default_dacl")
    if denied is not None:
        return _j(denied)
    if not aces:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "modify_default_dacl: aces must be a non-empty list"})
    for a in aces:
        if not isinstance(a, dict) or "sid" not in a or "access_mask" not in a:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": ("modify_default_dacl: every ace needs "
                                 "{sid, access_mask, type:'allow'|'deny', "
                                 "flags}")})
    res = await c.token_modify_dacl(
        pid=int(pid), tid=int(tid or 0),
        aces=aces, replace=bool(replace))
    return _j(res)


# -----------------------------------------------------------------------
# register() — minimal, delegated. P1 wires the full tool definition
# with the enum-annotated action argument. This file keeps register()
# as a no-op so build_server can call it unconditionally.
# -----------------------------------------------------------------------


def register(mcp, ctx: Context) -> None:
    """Register the ``token_manage`` tool.

    P2 provides a self-contained registration so Feature 1 is callable
    even before P1's taxonomy slice merges. When P1's shell lands at
    merge time, the merge picks the P2 definition (which carries real
    handlers) and the two slices stack cleanly.
    """
    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def token_manage(action: Annotated[str,
                               Field(json_schema_extra={"enum": TOKEN_ACTIONS})],
                           pid: int = 0, tid: int = 0,
                           source_pid: int = 0, source_tid: int = 0,
                           target_tid: int = 0,
                           privilege: str = "",
                           luid_low: int = 0, luid_high: int = 0,
                           level: str | int = "",
                           enabled: bool = False,
                           persist: bool = False,
                           impersonation_level: str = "impersonation",
                           impersonation_id: str = "",
                           aces: list[dict[str, Any]] | None = None,
                           replace: bool = False,
                           sids: list[str] | None = None,
                           names: list[str] | None = None,
                           include_groups: bool = False,
                           include_privileges: bool = False,
                           include_security_attributes: bool = False,
                           include_logon_session: bool = False,
                           include_dns_names: bool = False,
                           limit: int = 64, offset: int = 0,
                           name: str = "") -> str:
        """Token / privilege / SID viewer and mutator. Read verbs: view,
        lookup_sid, well_known_sids, logon_sessions. Mutators (gated by
        security.allow_token_adjust + actuator trust): enable_privilege,
        disable_privilege, remove_privilege, set_integrity_level,
        set_virtualization, impersonate, modify_default_dacl;
        stop_impersonate is ungated teardown. PPL targets: the user view
        fails on PPL, the kernel view reads via driver handle duplication.
        Per-verb help: token_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "pid": pid, "tid": tid,
                "source_pid": source_pid, "persist": persist,
                "name": name}

        async def run() -> str:
            if action not in TOKEN_ACTIONS:
                return _unknown_action("token_manage", action, TOKEN_ACTIONS,
                                       _TOKEN_ACTION_HELP)
            if action == "actions":
                return _actions_help("token_manage", _TOKEN_ACTION_HELP)
            view = ctx.session.resolve_view_name(name)
            c = ctx.session.require_client(view)
            if action == "view":
                return await handle_view(
                    ctx, c, pid=pid, tid=tid,
                    include_groups=include_groups,
                    include_privileges=include_privileges,
                    include_security_attributes=include_security_attributes,
                    include_logon_session=include_logon_session)
            if action == "lookup_sid":
                return await handle_lookup_sid(ctx, c,
                                                sids=sids, names=names)
            if action == "well_known_sids":
                return await handle_well_known_sids(ctx, c)
            if action == "logon_sessions":
                return await handle_logon_sessions(
                    ctx, c, include_dns_names=include_dns_names,
                    limit=limit, offset=offset)
            if action in ("enable_privilege", "disable_privilege",
                           "remove_privilege"):
                h = {"enable_privilege": handle_enable_privilege,
                     "disable_privilege": handle_disable_privilege,
                     "remove_privilege": handle_remove_privilege}[action]
                return await h(ctx, c, pid=pid, tid=tid,
                               privilege=privilege,
                               luid_low=luid_low, luid_high=luid_high)
            if action == "set_integrity_level":
                return await handle_set_integrity_level(
                    ctx, c, pid=pid, tid=tid, level=level)
            if action == "set_virtualization":
                return await handle_set_virtualization(
                    ctx, c, pid=pid, tid=tid, enabled=enabled)
            if action == "impersonate":
                return await handle_impersonate(
                    ctx, c, source_pid=source_pid, source_tid=source_tid,
                    persist=persist, target_tid=target_tid,
                    impersonation_level=impersonation_level)
            if action == "stop_impersonate":
                return await handle_stop_impersonate(
                    ctx, c, impersonation_id=impersonation_id)
            if action == "modify_default_dacl":
                return await handle_modify_default_dacl(
                    ctx, c, pid=pid, tid=tid, aces=aces, replace=replace)
            return _unknown_action("token_manage", action, TOKEN_ACTIONS,
                                   _TOKEN_ACTION_HELP)

        return await _guard(ctx, "token_manage", action, args, run)
