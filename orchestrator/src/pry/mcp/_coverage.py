"""Producer-declared coverage blocks for the response envelope.

A ``coverage`` block states how completely a producer looked at the scope
it was asked about, so "empty" (nothing there) is distinguishable from
"couldn't look" (coverage not established) and from "partially looked"
(some reads failed). Shape (top-level envelope key, ABSENT when not
applicable — never ``null``, never empty-dict-only):

    "coverage": {"scope": "mem-read",
                 "status": "complete" | "partial" | "unknown",
                 "limits": ["read_failed_mid_buffer", ...]}

Rules every producer honors:

* Never fabricate ``complete``. If completeness can't be proven, use
  ``unknown`` (or ``partial`` with a ``limits`` entry).
* Paging (``summary.truncated`` / ``next_cursor``) is independent of
  coverage: a fully covered enumeration that is merely paged is
  ``status="complete"`` with paging in ``summary``.
* Empty result + ``status="unknown"`` is the honest "couldn't look"
  answer; empty + ``complete`` means "looked, nothing there".

Every producer goes through :func:`coverage`, which validates the scope
against :data:`APPROVED_SCOPES` so drift fails loudly (a test asserts the
whitelist too).
"""
from __future__ import annotations

import json
from typing import Any

# The exact scope strings the adoption plan approves (test-asserted).
APPROVED_SCOPES: frozenset[str] = frozenset({
    "mem-read",        # memory_manage read/disasm/dt/dps byte windows
    "scan-window",     # memory_manage pattern_scan / pool_scan ranges
    "enumeration",     # memory_manage inventory listings (modules, handles, ...)
    "static-analysis", # bin_manage cfg/xrefs/gadgets/ioctl_surface
    "decompiler",      # ida_manage / ghidra_manage decompile + xref
    "dump-threads",    # dump_manage parse / stack thread walks
    "event-window",    # bp_manage event drain windows
    "pointer-chain",   # memory_manage follow_chain pointer walks
    "leak-kernel_pool",  # memory_manage leak_scan kernel pool coverage
    "leak-module_data",  # memory_manage leak_scan module .data/.rdata coverage
    "leak-per_process",  # memory_manage leak_scan per-process heap coverage
    # SI feature #1 (image coherency scoring): quick/normal cap the
    # bytes-compared window, so coverage is "partial" + sampling_cap
    # unless the caller asked for mode="full".
    "coherency-window",
    # SI feature #14 (process-snapshot minidump): the C++ side runs the
    # stepped access-mask ladder end-to-end; coverage flips to "partial"
    # with "unknown_flags" when the caller passed MINIDUMP_TYPE names
    # the orchestrator didn't recognise.
    "process-snapshot",
    # SI feature #2 (hidden-process detection): Wave 1 modes
    # (brute/registry/ETW) run usermode PID oracles against NtQSI.
    # Coverage is "complete" when every requested mode ran; "partial"
    # with "mode_unavailable:<name>" when a mode bailed, and
    # "partial" with "csrss_mode_wave2" when the caller asked for the
    # Wave-2-only CSRSS mode.
    "hidden-proc-window",
    # GetProcessMitigationPolicy readout.
    # "partial" + "denied_ppl" when a PPL target is probed from the
    # umagent view; "partial" + "mitigations_class_failed" when a
    # single policy class fell back.
    "mitigations",
    # token readout. "partial" +
    # "lsa_timeout" when the DC-side LSA lookup bailed; "partial" +
    # "token_class_failed" when one GetTokenInformation class failed.
    "token-window",
    # lookup_sid helper. "partial" +
    # "lsa_timeout" names the DC-latency failure.
    "sid-lookup",
    # well-known SID table dump (always
    # complete; a sanity scope so emitters don't have to case-split).
    "sid-table",
    # logon-session enumeration. The verb
    # pages via limit/offset; "complete" because the LSA snapshot
    # itself is atomic.
    "logon-sessions",
    # live kernel dump via
    # NtSystemDebugControl(SysDbgGetLiveKernelDump). Coverage flips to
    # "partial" with "unknown_flags" when the caller passed slice-doc
    # flag names the umagent didn't recognise.
    "live-kernel-dump",
    # segment-heap decode. Coverage is
    # "complete" on a known build / "partial" with "unknown_build" or
    # "pattern_fallback" when offsets drifted and the walker had to
    # pattern-scan for the segment-heap signature instead.
    "heap-info",
    # EnumPropsExW / EnumChildWindows walks.
    # Coverage flips to "partial" with "max_depth_reached" or
    # "session_1_worker_missing" per slice doc §Edge cases.
    "window-walk",
    # per-thread opt-in enrichment. Coverage
    # is "partial" with "wave_3_pending" (driver WAIT_INFO / IRP_LIST
    # degrade), "ppl_fallback", "wct_timeout", or
    # "mid_enrichment_exit" per slice doc §Edge cases.
    "thread-columns",
})

_VALID_STATUS: frozenset[str] = frozenset({"complete", "partial", "unknown"})


def coverage(scope: str, status: str, *limits: str) -> dict:
    """Build a validated coverage block. ``limits`` entries are short
    snake_case reasons (empty list when the status speaks for itself)."""
    if scope not in APPROVED_SCOPES:
        raise ValueError(f"coverage scope {scope!r} not in APPROVED_SCOPES")
    if status not in _VALID_STATUS:
        raise ValueError(f"coverage status {status!r} not in {_VALID_STATUS}")
    return {"scope": scope, "status": status,
            "limits": [str(x) for x in limits if x]}


def merge(*blocks: dict) -> dict:
    """Merge sibling coverage blocks (e.g. per-span scans): the weakest
    status wins (unknown > partial > complete), limits concatenate
    deduplicated. All scopes must agree."""
    if not blocks:
        raise ValueError("merge() needs at least one coverage block")
    scopes = {b.get("scope") for b in blocks}
    if len(scopes) > 1:
        raise ValueError(f"merge() scope mismatch: {sorted(scopes)}")
    order = {"unknown": 2, "partial": 1, "complete": 0}
    status = max((str(b.get("status", "unknown")) for b in blocks),
                 key=lambda s: order.get(s, 2))
    limits: list[str] = []
    for b in blocks:
        for x in b.get("limits") or []:
            if x not in limits:
                limits.append(x)
    return {"scope": next(iter(scopes)), "status": status, "limits": limits}


def attach(target: Any, block: dict) -> Any:
    """Attach ``block`` as the ``coverage`` member of a producer result.

    Accepts a dict (legacy tool-body result) or a JSON string (what most
    ``_j``-style call sites hold); returns the same type it was given.
    Already-envelope and already-covered payloads pass through
    untouched, and error envelopes (``ok: false``) never carry coverage —
    only provenance rides on errors.
    """
    if isinstance(target, str):
        try:
            parsed = json.loads(target)
        except (TypeError, ValueError):
            return target
        patched = attach(parsed, block)
        if patched is parsed:
            return target
        return json.dumps(patched, indent=2, default=str)
    if not isinstance(target, dict) or target.get("ok") is False:
        return target
    if "coverage" not in target:
        target["coverage"] = block
    return target
