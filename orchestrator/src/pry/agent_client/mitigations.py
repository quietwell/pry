"""Mitigations.GetMitigationPolicy mixin.

Thin wrapper around the agent/umagent's ``Mitigations.GetMitigationPolicy``
RPC. The ``process_manage`` MCP tool uses this to fan out a batched
``GetProcessMitigationPolicy`` probe for the ``mitigations`` action and
the ``verify_mitigations=True`` kwarg on ``action='list'``.

Older agents (missing ``MitigationsStub``) return
``{ok:false, kind:'agent_version', ...}`` so callers can degrade.
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb


def _row_to_dict(row: Any) -> dict[str, Any]:
    """Flatten a ``MitigationRow`` proto into the nested-dict shape the
    orchestrator exposes. One-field-per-policy bool matches
    an internal plan §Feature 6."""
    def _struct(sub: Any, fields: tuple[str, ...]) -> dict[str, Any]:
        return {f: bool(getattr(sub, f)) for f in fields}
    out: dict[str, Any] = {
        "pid": int(row.pid),
        "create_time_100ns": int(row.create_time_100ns),
        "error": row.error or "",
        "cache_hit": bool(row.cache_hit),
        "mitigations_source": "cache" if row.cache_hit else ("live" if not row.error else "denied"),
        "mitigations_cache_hit": bool(row.cache_hit),
        "mitigations_error": row.error or "",
    }
    out["dep"] = _struct(row.dep, ("enable", "atl_thunk_emulation_disable", "permanent"))
    out["aslr"] = _struct(row.aslr, (
        "bottom_up", "force_relocate", "high_entropy",
        "disallow_stripped_images", "bottom_up_high_entropy",
        "high_address_space_override"))
    out["cfg"] = _struct(row.cfg, (
        "enable", "strict_mode", "suppress_exports",
        "export_dynamic_invalidation"))
    out["strict_handle_check"] = bool(row.strict_handle_check)
    out["system_call_disable"] = _struct(row.syscall, (
        "disable", "allow_win32k_system_calls"))
    out["extension_points_disabled"] = bool(row.extension_points_disabled)
    out["dynamic_code"] = _struct(row.dynamic_code, (
        "prohibit", "allow_thread_opt_out", "allow_remote_downgrade",
        "audit", "audit_allow_thread_opt_out",
        "audit_allow_remote_downgrade"))
    bs = row.binary_signature
    out["binary_signature"] = {
        "micro_signed_only": bool(bs.micro_signed_only),
        "store_signed_only": bool(bs.store_signed_only),
        "mitigation_opt_in": bool(bs.mitigation_opt_in),
        "mitigation_audit_mask": int(bs.mitigation_audit_mask),
        "oem_signed_loosened_to_wintcb": bool(bs.oem_signed_loosened_to_wintcb),
    }
    out["font_disable"] = _struct(row.font_disable, (
        "disable_non_system_fonts", "audit"))
    out["image_load"] = _struct(row.image_load, (
        "no_remote_images", "no_low_mandatory_label_images",
        "prefer_system32", "audit_no_remote_images",
        "audit_no_low_mandatory_label_images", "audit_prefer_system32"))
    out["user_shadow_stack"] = _struct(row.user_shadow_stack, (
        "enabled", "audit", "strict_mode", "set_context_ip_validation",
        "set_context_ip_validation_relaxed_mode", "block_non_cet_binaries",
        "block_non_cet_binaries_non_ehcont",
        "cet_dynamic_apis_out_of_proc_only",
        "audit_set_context_ip_validation", "audit_block_non_cet_binaries"))
    out["payload_restriction"] = _struct(row.payload_restriction, (
        "enable_export_address_filter", "enable_export_address_filter_plus",
        "audit_export_address_filter", "audit_export_address_filter_plus",
        "enable_import_address_filter", "audit_import_address_filter",
        "enable_rop_stack_pivot", "audit_rop_stack_pivot",
        "enable_rop_caller_check", "audit_rop_caller_check",
        "enable_rop_sim_exec", "audit_rop_sim_exec"))
    out["side_channel_isolation"] = _struct(row.side_channel, (
        "smt_branch_target_isolation", "isolate_security_domain",
        "disable_page_combine", "speculative_store_bypass_disable"))
    out["redirection_trust"] = _struct(row.redirection_trust, (
        "enforce", "audit"))
    return out


class MitigationsMixin:
    """``self.mitigations`` is the ``MitigationsStub`` populated by
    ``client.connect()``; absent on older agents."""

    def _mitigations_missing(self) -> dict[str, Any]:
        return {
            "ok": False, "kind": "agent_version",
            "error": ("verify_mitigations: older agent/umagent "
                      "(Mitigations service missing)"),
            "hint": ("rebuild + redeploy agent/umagent for the slice 01 "
                     "Feature 6 mitigations readout"),
            "rows": [], "cache_hits": 0, "probed": 0,
        }

    async def verify_mitigations(self, pids: list[int], *,
                                 force_recheck: bool = False
                                 ) -> dict[str, Any]:
        """Call the agent/umagent's Mitigations.GetMitigationPolicy RPC
        for the given pids. Returns ``{ok, rows, cache_hits, probed}``.

        Each row is the dict shape documented in slice 01 Feature 6:
        nested dep/aslr/cfg/… blocks plus ``mitigations_source`` and
        ``mitigations_cache_hit`` discriminators. Older agents
        return ``{ok:false, kind:'agent_version', ...}`` without raising.
        """
        if getattr(self, "mitigations", None) is None:
            return self._mitigations_missing()
        if not hasattr(pb, "GetMitigationPolicyRequest"):
            return self._mitigations_missing()
        req = pb.GetMitigationPolicyRequest(
            pids=[int(p) for p in (pids or []) if int(p or 0) > 0],
            force_recheck=bool(force_recheck),
        )
        msg = await self._call(self.mitigations.GetMitigationPolicy, req)
        if not msg.status.ok:
            return {"ok": False,
                    "kind": "verify_mitigations_failed",
                    "error": msg.status.error,
                    "rows": [], "cache_hits": 0, "probed": 0}
        rows = [_row_to_dict(r) for r in msg.rows]
        return {
            "ok": True,
            "rows": rows,
            "cache_hits": int(msg.cache_hits),
            "probed": int(msg.probed),
        }
