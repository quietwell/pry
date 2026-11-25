"""Coarse error classes for agents.

``error.kind`` is fine-grained (~200 slugs, see ``error_maps.KNOWN_KINDS``)
and is the right thing to log or quote. An agent deciding *what to do
next* needs something smaller, so every error envelope also carries:

* ``error.class`` - one of :data:`CLASSES`:

  ============== ===========================================================
  bad_arg        the call itself is wrong: fix the args/verb and call again
  not_found      the thing asked for doesn't exist (pid, module, symbol...)
  unavailable    a prerequisite is missing: driver, view, agent feature,
                 optional package. Fix the setup, then retry
  denied         refused by policy/permission/trust. Needs a human or
                 ``force=true`` where the hint says so
  transient      timeout/busy/stream hiccup - the same call may succeed
  needs_confirm  the call needs an explicit confirmation flag
  failed         the operation ran and failed on the target
  internal       orchestrator-side bug or unclassified error
  ============== ===========================================================

* ``error.retryable`` - true only for ``transient``.
"""

from __future__ import annotations

CLASSES = ("bad_arg", "not_found", "unavailable", "denied", "transient",
           "needs_confirm", "failed", "internal")

_EXACT: dict[str, str] = {
    # bad_arg
    "bad_arg": "bad_arg", "unknown_action": "bad_arg",
    "unknown_kwarg": "bad_arg", "kwarg_collision": "bad_arg",
    "invalid_parameter": "bad_arg", "invalid_address": "bad_arg",
    "ambiguous_target": "bad_arg", "moved": "bad_arg",
    "removed_action": "bad_arg", "cidr_too_broad": "bad_arg",
    "too_wide": "bad_arg", "too_many_vas": "bad_arg",
    "too_many_instances": "bad_arg", "would_exceed": "bad_arg",
    "input_too_large": "bad_arg", "offset_out_of_range": "bad_arg",
    "division_by_zero": "bad_arg", "expr_overflow": "bad_arg",
    "undefined_name": "bad_arg", "unsafe_default": "bad_arg",
    "view_mismatch": "bad_arg", "wrong_machine": "bad_arg",
    "create_process_e_invalidarg": "bad_arg", "self_pid": "bad_arg",
    # unavailable
    "driver_absent": "unavailable", "driver_absent_or_stale": "unavailable",
    "no_driver": "unavailable", "no_target": "unavailable",
    "not_connected": "unavailable", "channel_unavailable": "unavailable",
    "orchestrator_unreachable": "unavailable",
    "host_unreachable": "unavailable", "network_unreachable": "unavailable",
    "unreachable": "unavailable", "connect_refused": "unavailable",
    "agent_old": "unavailable", "agent_version": "unavailable",
    "agent_version_low": "unavailable", "needs_v17": "unavailable",
    "codegen_extra_missing": "unavailable", "feature_disabled": "unavailable",
    "feature_unavailable": "unavailable", "not_implemented": "unavailable",
    "not_supported": "unavailable", "wave_3_pending": "unavailable",
    "pdb_missing": "unavailable", "pdb_layout_missing": "unavailable",
    "udt_details_unavailable": "unavailable", "no_session": "unavailable",
    "ida_backend_dead": "unavailable", "pending_boot": "unavailable",
    "not_ready": "unavailable", "pid_lookup_unavailable": "unavailable",
    "hw_bp_hook_disabled": "unavailable", "endpoint_moved": "unavailable",
    "pp_target_requires_feature_23": "unavailable",
    "eprocess_offsets_unknown": "unavailable",
    "privilege_absent": "unavailable", "schema_mismatch": "unavailable",
    # denied
    "access_denied": "denied", "attach_denied": "denied",
    "not_allowed": "denied", "connect_blocked": "denied",
    "mmio_blocked": "denied", "phys_map_denied": "denied",
    "foreign_owned": "denied", "reboot_refused": "denied",
    "sharing_locked": "denied",
    # transient
    "busy": "transient", "connect_timeout": "transient",
    "deadline_exceeded": "transient", "evaluation_timeout": "transient",
    "wait_timeout": "transient", "wait_agent_timeout": "transient",
    "wct_timeout": "transient", "reboot_timeout": "transient",
    "agent_stream_closed": "transient", "handles_stream_closed": "transient",
    "dbgeng_session_stale": "transient", "stale_kaslr": "transient",
    "analysis_running": "transient", "watchdog_collision": "transient",
    # needs_confirm
    "confirm_required": "needs_confirm",
    # internal
    "internal_error": "internal", "unknown": "internal", "error": "internal",
}


def classify(kind: str) -> tuple[str, bool]:
    """``(class, retryable)`` for an ``error.kind`` slug."""
    k = str(kind or "").strip().lower()
    cls = _EXACT.get(k)
    if cls is None:
        if k.endswith("_not_found") or k.startswith("no_") or k in (
                "not_found", "no_match", "filter_no_match"):
            cls = "not_found"
        elif k.startswith("unknown_"):
            cls = "not_found"
        elif k.startswith(("bad_", "invalid_", "unsupported_")):
            cls = "bad_arg"
        elif k.endswith(("_timeout", "_stream_closed")):
            cls = "transient"
        elif k.endswith(("_denied", "_blocked", "_refused")):
            cls = "denied"
        elif k.endswith(("_failed", "_missing")) or k in (
                "short_read", "partial_read", "pte_absent", "decode_failed"):
            cls = "failed"
        else:
            cls = "failed"
    return cls, cls == "transient"


__all__ = ["CLASSES", "classify"]
