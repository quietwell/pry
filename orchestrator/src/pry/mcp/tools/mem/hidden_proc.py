"""``hidden_proc`` verb body — SI feature #2 Wave 1 (hidden-process
detection).

Cross-references the NtQuerySystemInformation(SystemProcessInformation)
inventory (ground truth) against three alternative PID oracles that
land on the agent / umagent side:

* ``brute``    — ``OpenProcess`` across a stepped PID range; a PID that
                 opens, or that returns ``ERROR_ACCESS_DENIED`` (PPL /
                 protected), is a yes.
* ``registry`` — ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\*\\ImagePath``
                 image names, joined to ``EnumProcesses`` output.
* ``etw``      — ``EnumerateTraceGuidsEx(TraceGuidQueryInfo)`` returns
                 the pid list of every registered ETW provider.

CSRSS mode (handle-table deref via the driver) is Wave 2 and depends on
the slice-1 ``HANDLE_LIST`` enrichment. The verb accepts it in ``modes``
today and silently drops it so a pre-Wave-2 orchestrator can't crash
Wave-2-ready callers; the ``modes_run`` field in the response is
authoritative about what actually ran.

The verdict for each candidate PID is computed orchestrator-side:

    is_hidden = (any mode saw it) AND (NtQSI did NOT)

and a short-form ``verdict`` string labels why:

    "clean"               — present in NtQSI (never surfaces as hidden)
    "unlinked_from_pslist"— brute surfaced it, NtQSI did not
    "zombie"              — exit_time_100ns != 0 but still open-able
    "ghost_etw_owner"     — only etw saw it
    "stale_registry"      — only registry saw it

Driver-free: the three Wave 1 modes are pure usermode APIs, so the
umagent view answers them identically to the agent view. The
dispatcher adds ``hidden_proc`` to the ``_driver_free`` whitelist in
``mem/__init__.py``.

Slice doc: an internal plan
§Feature 2.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict, _j


# Modes we actively run in Wave 1. "csrss" is accepted (silently
# dropped) so a Wave-2-ready caller doesn't error on us.
_WAVE1_MODES = ("brute", "registry", "etw")
_KNOWN_MODES = _WAVE1_MODES + ("csrss",)


def _confidence(row: dict[str, Any], present_nqsi: bool) -> float:
    """Confidence that the row is actually hidden (0..1).

    * NQSI confirms it ⇒ 0.0 (never hidden).
    * Every mode agrees it exists but NtQSI does not ⇒ 1.0.
    * One mode alone ⇒ 0.33; two ⇒ 0.66.
    * Zombie row (exit_time_100ns set) adds 0.1 (a lingering handle).
    """
    if present_nqsi:
        return 0.0
    hits = (int(bool(row.get("present_brute")))
            + int(bool(row.get("present_registry")))
            + int(bool(row.get("present_etw"))))
    if hits == 0:
        return 0.0
    base = min(1.0, hits / float(len(_WAVE1_MODES)))
    if int(row.get("exit_time_100ns") or 0):
        base = min(1.0, base + 0.1)
    return round(base, 3)


def _verdict(row: dict[str, Any], present_nqsi: bool) -> str:
    """Short-form verdict label — see module docstring."""
    if present_nqsi:
        return "clean"
    if int(row.get("exit_time_100ns") or 0):
        return "zombie"
    brute = bool(row.get("present_brute"))
    reg = bool(row.get("present_registry"))
    etw = bool(row.get("present_etw"))
    if brute and not reg and not etw:
        return "unlinked_from_pslist"
    if etw and not brute and not reg:
        return "ghost_etw_owner"
    if reg and not brute and not etw:
        return "stale_registry"
    # Two-or-more modes agreeing (minus NtQSI) is still an
    # unlink-shaped signal, bucket it there.
    if brute:
        return "unlinked_from_pslist"
    if etw:
        return "ghost_etw_owner"
    return "stale_registry"


def _normalize_modes(modes: list[str] | None) -> tuple[list[str], list[str]]:
    """Return (modes_to_send, modes_dropped).

    Unknown modes are dropped with their name recorded in modes_dropped
    so the caller sees exactly what we discarded. Empty / None input
    means "run every Wave 1 mode".
    """
    if not modes:
        return list(_WAVE1_MODES), []
    cleaned: list[str] = []
    dropped: list[str] = []
    seen: set[str] = set()
    for m in modes:
        if not isinstance(m, str):
            continue
        norm = m.strip().lower()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        if norm in _WAVE1_MODES:
            cleaned.append(norm)
        elif norm == "csrss":
            dropped.append(norm)  # Wave 2 — ack but skip
        else:
            dropped.append(norm)
    if not cleaned:
        # Caller asked only for unknown / Wave-2 modes — fall back to
        # Wave 1 defaults so the response still carries something.
        cleaned = list(_WAVE1_MODES)
    return cleaned, dropped


async def handle_hidden_proc(ctx, c, *, modes: list[str] | None,
                             pid_max: int, step: int,
                             timeout_ms: int,
                             fields: list[str] | None,
                             filter: Any, summary: bool,
                             limit: int, offset: int,
                             max_results: int) -> str:
    """Dispatch ``memory_manage(action='hidden_proc')``.

    Fires the scanner RPC AND the baseline NtQSI process list in
    parallel-shaped flow (we await them one after the other but neither
    blocks the other on the agent side), then cross-joins to produce
    one row per candidate PID with ``is_hidden`` / ``verdict`` /
    ``confidence`` columns. ``modes_run`` reflects what actually ran on
    the agent; a mode in the response's ``modes_failed`` carries its
    present_<mode> as False and the verdict logic treats it as absent.
    """
    if getattr(c, "hidden_proc", None) is None:
        return _j({"ok": False, "kind": "agent_version",
                   "error": "hidden_proc: this agent/umagent is too old "
                            "(HiddenProcess service missing)",
                   "hint": "rebuild + redeploy agent/umagent "
                           "(scripts/update_target.py --component "
                           "agent --component umagent)"})

    modes_send, modes_dropped = _normalize_modes(modes)

    # NtQSI ground truth. mem_processes returns either a list or a dict
    # depending on `full=`; we only need the pid set, so the plain list
    # path is fine.
    try:
        nqsi = await c.mem_processes(full=True, with_cmdline=False)
    except Exception as exc:  # noqa: BLE001 — surface as named error
        return _j({"ok": False, "kind": "nqsi_failed",
                   "error": f"{type(exc).__name__}: {exc}"})
    nqsi_rows = (nqsi.get("processes") if isinstance(nqsi, dict)
                 else nqsi) or []
    nqsi_pids: dict[int, dict[str, Any]] = {}
    for row in nqsi_rows:
        pid = int(row.get("pid") or 0)
        if pid:
            nqsi_pids[pid] = row

    try:
        scan = await c.hidden_proc_scan(
            pid_max=pid_max, step=step, modes=modes_send,
            timeout_ms=timeout_ms,
        )
    except Exception as exc:  # noqa: BLE001 — surface as named error
        return _j({"ok": False, "kind": "hidden_proc_failed",
                   "error": f"{type(exc).__name__}: {exc}"})
    if not scan.get("ok"):
        return _j({"ok": False, "kind": "hidden_proc_failed",
                   "error": scan.get("error", "hidden_proc: scan failed"),
                   "modes_run": scan.get("modes_run") or [],
                   "modes_failed": scan.get("modes_failed") or []})

    oracle_rows = scan.get("rows") or []
    seen_oracle: set[int] = set()
    out_rows: list[dict[str, Any]] = []
    hidden_count = 0

    for row in oracle_rows:
        pid = int(row.get("pid") or 0)
        if not pid:
            continue
        seen_oracle.add(pid)
        nqsi_hit = pid in nqsi_pids
        verdict = _verdict(row, nqsi_hit)
        conf = _confidence(row, nqsi_hit)
        is_hidden = (not nqsi_hit) and (
            bool(row.get("present_brute"))
            or bool(row.get("present_registry"))
            or bool(row.get("present_etw"))
        )
        if is_hidden:
            hidden_count += 1
        image = row.get("image") or ""
        if not image and nqsi_hit:
            image = (nqsi_pids[pid].get("image")
                     or nqsi_pids[pid].get("image_name") or "")
        out_rows.append({
            "pid": pid,
            "image": image,
            "present_brute": bool(row.get("present_brute")),
            "present_registry": bool(row.get("present_registry")),
            "present_etw": bool(row.get("present_etw")),
            "present_nqsi": nqsi_hit,
            "exit_time_100ns": int(row.get("exit_time_100ns") or 0),
            "handle_count": int(row.get("handle_count") or 0),
            "sources": row.get("sources") or "",
            "is_hidden": is_hidden,
            "verdict": verdict,
            "confidence": conf,
        })

    # Coverage: a mode in modes_failed, or a Wave-2 mode we dropped,
    # downgrades to partial.
    modes_run = list(scan.get("modes_run") or [])
    modes_failed = list(scan.get("modes_failed") or [])
    status = ("partial" if (modes_failed
                             or any(m == "csrss" for m in modes_dropped))
              else "complete")
    limits: list[str] = []
    for m in modes_failed:
        limits.append(f"mode_unavailable:{m}")
    if any(m == "csrss" for m in modes_dropped):
        limits.append("csrss_mode_wave2")
    cov = _coverage("hidden-proc-window", status, *limits)

    source = "umagent" if ctx.session.view_kind_of(
        getattr(c, "_view_name", "") or "") == "user" else "agent"
    pid_sources = sorted({
        s.strip() for row in out_rows for s in (row["sources"] or "").split(",")
        if s.strip()
    })

    extras: dict[str, Any] = {
        # Named ``scan_summary`` to avoid colliding with ``_list_envelope``'s
        # own ``summary`` field. Tests + consumers look for this key.
        "scan_summary": {
            "modes_run": modes_run,
            "modes_failed": modes_failed,
            "modes_dropped": modes_dropped,
            "pid_sources": pid_sources,
            "oracle_pids": len(seen_oracle),
            "nqsi_pids": len(nqsi_pids),
            "hidden_candidates": hidden_count,
        },
        "pid_max_used": int(scan.get("pid_max_used") or 0),
        "step_used": int(scan.get("step_used") or 0),
        "source": source,
    }

    env = _list_envelope(
        out_rows, tool="memory_manage", action="hidden_proc",
        limit=limit or max_results or len(out_rows),
        offset=offset, fields=fields or (),
        filter=filter if isinstance(filter, str) else "",
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras=extras,
    )
    env["coverage"] = cov
    return _hexify_dict(env, add_int_mirror=True)


__all__ = ["handle_hidden_proc"]
