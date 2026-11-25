"""Token service mixin.

Thin wrappers around the agent/umagent ``pry.Token`` RPCs. Each
wrapper is a direct forward with proto-to-dict flattening; the
orchestrator ``token_manage`` tool composes these into verb handlers.

Older agents (no ``TokenStub``) surface a well-shaped
``{ok:false, kind:'agent_version'}`` envelope so callers degrade.

See ``an internal plan`` Feature 1.
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb


_INTEGRITY_NAME_BY_RID = {
    0x0000: "untrusted",
    0x1000: "low",
    0x2000: "medium",
    0x2100: "medium_plus",
    0x3000: "high",
    0x4000: "system",
    0x5000: "protected",
}

_INTEGRITY_RID_BY_NAME = {v: k for k, v in _INTEGRITY_NAME_BY_RID.items()}


def _resolve_integrity(rid: int, name: str) -> tuple[int, str]:
    """Normalise an integrity (rid, name) pair so callers can pass
    either representation. ``name`` wins when non-empty."""
    name = str(name or "").strip().lower()
    if name:
        if name in _INTEGRITY_RID_BY_NAME:
            return _INTEGRITY_RID_BY_NAME[name], name
        return int(rid or 0), name
    rid = int(rid or 0)
    return rid, _INTEGRITY_NAME_BY_RID.get(rid, "")


def _group_to_dict(g: Any) -> dict[str, Any]:
    return {
        "sid": g.sid, "name": g.name, "domain": g.domain,
        "attributes": int(g.attributes),
        "flags": {
            "deny": bool(g.is_deny),
            "mandatory": bool(g.is_mandatory),
            "integrity": bool(g.is_integrity),
            "logon_id": bool(g.is_logon_id),
            "enabled": bool(g.is_enabled),
            "enabled_by_default": bool(g.is_enabled_by_default),
            "use_for_deny_only": bool(g.is_use_for_deny_only),
            "owner": bool(g.is_owner),
            "resource": bool(g.is_resource),
        },
        "use": g.use or "",
    }


def _priv_to_dict(p: Any) -> dict[str, Any]:
    return {
        "luid_low": int(p.luid_low),
        "luid_high": int(p.luid_high),
        "name": p.name,
        "display_name": p.display_name,
        "attributes": int(p.attributes),
        "state": p.state or "default",
        "enabled_by_default": bool(p.enabled_by_default),
    }


def _logon_to_dict(ls: Any) -> dict[str, Any]:
    return {
        "logon_id_low": int(ls.logon_id_low),
        "logon_id_high": int(ls.logon_id_high),
        "user_name": ls.user_name,
        "auth_package": "",  # proto carries auth_domain only; name match for help blurb
        "auth_domain": ls.auth_domain,
        "logon_type": int(ls.logon_type),
        "logon_type_name": ls.logon_type_name,
        "session_id": int(ls.session_id),
        "logon_time_100ns": int(ls.logon_time_100ns),
        "logoff_time_100ns": int(ls.logoff_time_100ns),
        "logon_server": ls.logon_server,
        "dns_domain": ls.dns_domain_name,
        "upn": ls.upn,
        "user_flags": int(ls.user_flags),
    }


class TokenMixin:
    """``self.token`` is the ``TokenStub`` populated by ``client.connect()``;
    absent on older agents."""

    def _token_missing(self, action: str) -> dict[str, Any]:
        return {
            "ok": False, "kind": "agent_version",
            "error": (f"token_{action}: older agent/umagent "
                      "(Token service missing)"),
            "hint": ("rebuild + redeploy agent/umagent for the slice 01 "
                     "Feature 1 token surface"),
        }

    async def token_view(self, *, pid: int, tid: int = 0,
                         include_groups: bool = False,
                         include_privileges: bool = False,
                         include_security_attributes: bool = False,
                         include_logon_session: bool = False
                         ) -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("view")
        req = pb.TokenViewRequest(
            pid=int(pid), tid=int(tid or 0),
            include_groups=bool(include_groups),
            include_privileges=bool(include_privileges),
            include_security_attributes=bool(include_security_attributes),
            include_logon_session=bool(include_logon_session),
        )
        msg = await self._call(self.token_svc.View, req)
        if not msg.status.ok:
            kind = "error"
            err = msg.status.error or ""
            lower = err.lower()
            if "denied_ppl" in lower or "ppl" in lower:
                kind = "denied_ppl"
            elif "access" in lower and ("denied" in lower or "0x5" in lower):
                kind = "access_denied"
            elif "no_token" in lower or "no_impersonation" in lower:
                kind = "no_impersonation"
            return {"ok": False, "kind": kind, "error": err}
        core = msg.core
        out: dict[str, Any] = {
            "ok": True,
            "pid": int(pid),
            "tid": int(tid or 0),
            "token_source": msg.token_source or "primary",
            "thread_impersonating": bool(msg.thread_impersonating),
            "user_sid": core.user_sid,
            "user_name": core.user_name,
            "user_domain": core.user_domain,
            "logon_sid": core.logon_sid,
            "integrity_level_rid": int(core.integrity_rid),
            "integrity_level_name": core.integrity_name or
                _INTEGRITY_NAME_BY_RID.get(int(core.integrity_rid), ""),
            "elevation_type": core.elevation_type or "default",
            "is_elevated": bool(core.is_elevated),
            "linked_token_present": bool(core.linked_token_present),
            "uac_virtualization_enabled": bool(core.uac_virtualization_enabled),
            "uac_virtualization_allowed": bool(core.uac_virtualization_allowed),
            "mandatory_policy": int(core.mandatory_policy),
            "session_id": int(core.session_id),
            "logon_session_id_low": int(core.logon_id_low),
            "logon_session_id_high": int(core.logon_id_high),
            "is_app_container": bool(core.is_app_container),
            "app_container_sid": core.app_container_sid,
            "app_container_name": core.app_container_name,
            "app_container_number": int(core.app_container_number),
            "trust_label_sid": core.trust_label_sid,
            "trust_label_name": core.trust_label_name,
        }
        if include_groups:
            out["groups"] = [_group_to_dict(g) for g in msg.groups]
        if include_privileges:
            out["privileges"] = [_priv_to_dict(p) for p in msg.privileges]
        if msg.capabilities:
            out["capability_sids"] = [
                {"sid": c.sid, "name": c.name} for c in msg.capabilities]
        if include_security_attributes:
            out["security_attributes_raw"] = bytes(msg.security_attributes_raw)
        if include_logon_session:
            out["logon_session"] = _logon_to_dict(msg.logon_session)
        return out

    async def token_adjust_privilege(self, *, pid: int, tid: int,
                                     privilege_name: str = "",
                                     luid_low: int = 0, luid_high: int = 0,
                                     action: str = "enable") -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("adjust_privilege")
        req = pb.AdjustPrivilegeRequest(
            pid=int(pid), tid=int(tid or 0),
            privilege_name=str(privilege_name or ""),
            luid_low=int(luid_low or 0), luid_high=int(luid_high or 0),
            action=str(action or "enable"),
        )
        msg = await self._call(self.token_svc.AdjustPrivilege, req)
        if not msg.status.ok:
            err = msg.status.error or ""
            lower = err.lower()
            kind = "error"
            if "denied_ppl" in lower:
                kind = "denied_ppl"
            elif "access_denied" in lower or "0x5" in lower:
                kind = "access_denied"
            elif "not_assigned" in lower or "not all assigned" in lower:
                # ERROR_NOT_ALL_ASSIGNED is a soft error per slice 01
                return {"ok": True, "previous_state": "absent",
                        "new_state": "absent",
                        "luid_low": int(msg.luid_low),
                        "luid_high": int(msg.luid_high),
                        "note": err}
            return {"ok": False, "kind": kind, "error": err}
        return {"ok": True,
                "previous_state": msg.previous_state,
                "new_state": msg.new_state,
                "luid_low": int(msg.luid_low),
                "luid_high": int(msg.luid_high)}

    async def token_set_integrity(self, *, pid: int, tid: int,
                                  integrity_rid: int,
                                  integrity_name: str = "") -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("set_integrity")
        req = pb.SetIntegrityLevelRequest(
            pid=int(pid), tid=int(tid or 0),
            integrity_rid=int(integrity_rid or 0),
            integrity_name=str(integrity_name or ""),
        )
        msg = await self._call(self.token_svc.SetIntegrityLevel, req)
        if not msg.status.ok:
            err = msg.status.error or ""
            lower = err.lower()
            kind = "denied_ppl" if "ppl" in lower else "access_denied" if "denied" in lower else "error"
            return {"ok": False, "kind": kind, "error": err}
        return {"ok": True,
                "previous_rid": int(msg.previous_rid),
                "new_rid": int(msg.new_rid)}

    async def token_set_virtualization(self, *, pid: int, tid: int,
                                       enable: bool) -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("set_virtualization")
        req = pb.SetVirtualizationRequest(
            pid=int(pid), tid=int(tid or 0), enable=bool(enable),
        )
        msg = await self._call(self.token_svc.SetVirtualization, req)
        if not msg.status.ok:
            err = msg.status.error or ""
            kind = "denied_ppl" if "ppl" in err.lower() else "access_denied" if "denied" in err.lower() else "error"
            return {"ok": False, "kind": kind, "error": err}
        return {"ok": True,
                "previous": bool(msg.previous),
                "new": bool(msg.new_value)}

    async def token_impersonate(self, *, source_pid: int, source_tid: int = 0,
                                persist: bool = False, target_tid: int = 0,
                                impersonation_level: str = "impersonation"
                                ) -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("impersonate")
        req = pb.ImpersonateRequest(
            source_pid=int(source_pid), source_tid=int(source_tid or 0),
            persist=bool(persist), target_tid=int(target_tid or 0),
            impersonation_level=str(impersonation_level or "impersonation"),
        )
        msg = await self._call(self.token_svc.Impersonate, req)
        if not msg.status.ok:
            err = msg.status.error or ""
            kind = "denied_ppl" if "ppl" in err.lower() else "access_denied" if "denied" in err.lower() else "error"
            return {"ok": False, "kind": kind, "error": err}
        return {"ok": True,
                "impersonation_id": msg.impersonation_id,
                "agent_thread_id": int(msg.agent_thread_id),
                "level_granted": msg.level_granted}

    async def token_stop_impersonate(self, *, impersonation_id: str
                                     ) -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("stop_impersonate")
        req = pb.StopImpersonateRequest(
            impersonation_id=str(impersonation_id or ""),
        )
        st = await self._call(self.token_svc.StopImpersonate, req)
        return {"ok": bool(st.ok),
                "error": st.error if not st.ok else ""}

    async def token_modify_dacl(self, *, pid: int, tid: int,
                                aces: list[dict[str, Any]] | None,
                                replace: bool = False) -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("modify_dacl")
        req = pb.ModifyDefaultDaclRequest(
            pid=int(pid), tid=int(tid or 0), replace=bool(replace),
        )
        for ace in (aces or []):
            a = req.aces.add()
            a.sid = str(ace.get("sid", ""))
            a.access_mask = int(ace.get("access_mask", 0) or 0)
            a.type = str(ace.get("type", "allow"))
            a.flags = int(ace.get("flags", 0) or 0)
        msg = await self._call(self.token_svc.ModifyDefaultDacl, req)
        if not msg.status.ok:
            err = msg.status.error or ""
            kind = "denied_ppl" if "ppl" in err.lower() else "access_denied" if "denied" in err.lower() else "error"
            return {"ok": False, "kind": kind, "error": err}
        return {"ok": True,
                "ace_count_before": int(msg.ace_count_before),
                "ace_count_after": int(msg.ace_count_after)}

    async def token_lookup_sid(self, *, sids: list[str] | None = None,
                               names: list[str] | None = None
                               ) -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("lookup_sid")
        req = pb.LookupSidRequest(
            sids=[str(s) for s in (sids or []) if s],
            names=[str(n) for n in (names or []) if n],
        )
        msg = await self._call(self.token_svc.LookupSid, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "error",
                    "error": msg.status.error, "rows": []}
        rows = [{
            "input": r.input, "sid": r.sid, "name": r.name,
            "domain": r.domain, "type": r.use,
            "well_known": bool(r.well_known),
        } for r in msg.rows]
        return {"ok": True, "rows": rows}

    async def token_logon_sessions(self, *, include_dns_names: bool = False
                                   ) -> dict[str, Any]:
        if getattr(self, "token_svc", None) is None:
            return self._token_missing("logon_sessions")
        req = pb.LogonSessionsRequest(
            include_dns_names=bool(include_dns_names),
        )
        msg = await self._call(self.token_svc.LogonSessions, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "error",
                    "error": msg.status.error, "sessions": []}
        return {"ok": True,
                "sessions": [_logon_to_dict(s) for s in msg.sessions]}
