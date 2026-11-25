"""``target_manage`` status/discovery verbs — ``actions``, ``tool_index``,
``status``, ``targets``, ``sysinfo``, ``host_info``, ``parity``,
``whoami``.

``status`` carries the degraded-view warn banner (``PRY_DEGRADED_WARN_MS``)
and the pry-driver health probe. ``host_info`` wraps every security
pair in the confidence envelope shape (`{value, confidence, source}`)
callers already know from ``sysinfo``.
"""

from __future__ import annotations

from typing import Any

from ..common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)


# Imported late so this module stays importable even when `TARGET_ACTIONS`
# is being extended by a sibling.
async def do_actions(ctx) -> str:
    from . import _TARGET_ACTION_HELP
    return _actions_help("target_manage", _TARGET_ACTION_HELP)


async def do_tool_index(ctx, mcp, *, verbose: bool = False) -> str:
    """Global surface map: one row per registered tool with its
    one-liner and verb count.

    The per-tool verb lists already ride in ``tools/list`` (each tool's
    ``action`` enum) and ``<tool>(action='actions')``, so they are only
    repeated here with ``verbose=True``, together with the capability
    registry's per-domain grouping (``domains``).

    ida_manage / ghidra_manage forward any unlisted verb to their backend,
    so their verb list is reported as ``"<passthrough>"``.
    """
    _PASSTHROUGH_TOOLS = {"ida_manage", "ghidra_manage"}
    tools = await mcp.list_tools()
    rows = []
    for t in sorted(tools, key=lambda t: t.name or ""):
        props = (t.parameters or {}).get("properties", {})
        act = props.get("action") or {}
        enum = act.get("enum")
        if t.name in _PASSTHROUGH_TOOLS or not enum:
            actions: Any = "<passthrough>"
        else:
            actions = enum
        row: dict[str, Any] = {
            "tool": t.name,
            "one_liner": _one_line_desc(t.description or "", cap=160),
            "verbs": (len(actions) if isinstance(actions, list)
                      else "<passthrough>"),
        }
        if verbose:
            row["actions"] = actions
        rows.append(row)
    out: dict[str, Any] = {
        "ok": True,
        "count": len(rows),
        "tools": rows,
        "hint": ("<tool>(action='actions') lists a tool's verbs; "
                 "verb='<verb>' narrows to one; verbose=true adds the "
                 "verb lists + capability domains here"),
    }
    if verbose:
        from .._runtime.help import _tool_index_domains
        out["domains"] = _tool_index_domains()
    return _j(out)


async def do_targets(ctx) -> str:
    # Phase 0.2: configured endpoint + last_seen_ts per view so
    # reconnect after a wedge is deterministic. Backwards-compat:
    # `connected` list preserved for callers that only cared
    # about which names are up.
    machines = {
        m: {"computer_name": ctx.session.machine_label(
                keys[0]).get("computer_name", ""),
            "views": keys}
        for m, keys in ctx.session.machines().items()}
    return _j({"ok": True,
               "connected": sorted(ctx.session.clients),
               "primary": ctx.session.primary,
               "views": ctx.session.all_views(),
               "machines": machines,
               "focus": ctx.session.focus_of(
                   current_client_id())})


def _lean_status(s: dict) -> dict:
    """trim the status response to the fields the LLM reasons
    about on every poll. ``target_manage(..., verbose=True)`` skips this
    pass so a caller that genuinely wants the posture flags / adapter
    plumbing / internal driver_health block gets the unfiltered shape
    verbatim.

    Kept: ``ok``, ``driver_state`` + ``driver_present`` + ``driver_version``,
    ``agent_version``, ``os_version`` / ``os_build``, ``testsigning``
    (gatekeeps driver loads), ``secureboot``, ``machine`` / ``computer_name``,
    ``boot_epoch_ms`` + ``service_uptime_ms``, ``ipv4`` (up-only, lean),
    ``pry_driver_health`` (collapsed to ``{verdict}`` when healthy),
    plus any ``boot_change`` / ``warnings`` / ``minidump`` / ``swept``
    that `do_status` attached from a boot-identity change.

    Dropped on the lean path (restored by ``verbose=True``):
      * ``agent_uptime_ms``, ``pc_uptime_ms``, ``agent_instance_id`` —
        pick-one or opaque internals.
      * ``ipv4[]`` entries with ``up=False`` (APIPA linklayer addresses)
        and the ``.mac`` / ``.origin`` / ``.gateway`` / ``.prefix_len``
        sub-fields on every entry (MAC/gw/origin are once-at-triage
        values, not status-poll churn).
      * Security posture flags that don't pivot a tool decision mid-session
        — ``hvci`` / ``memory_integrity`` / ``driver_blocklist_on`` /
        ``kva_shadow`` / ``vbs_enabled`` / ``credential_guard`` /
        ``lsa_protected`` / ``kernel_debugger`` / ``patchguard_expected`` /
        ``patchguard_state``. All reachable via
        ``target_manage(action='host_info')``.
      * ``pry_driver_health``'s nested ``service`` / ``file`` /
        ``residual`` / ``hint`` / ``probe_errors`` sub-blocks when
        ``verdict == 'loaded'`` and ``probe_errors == []`` (they only
        add signal when the driver is NOT loaded).
    """
    if not isinstance(s, dict):
        return s
    # ipv4 adapter list — keep only up=true, keep only the essentials.
    ipv4 = s.get("ipv4")
    if isinstance(ipv4, list):
        s["ipv4"] = [
            {k: a[k] for k in ("adapter", "address") if k in a}
            for a in ipv4
            if isinstance(a, dict) and a.get("up")
        ]
    # Uptime quadruple → keep service_uptime_ms + boot_epoch_ms.
    for k in ("agent_uptime_ms", "pc_uptime_ms", "agent_instance_id"):
        s.pop(k, None)
    # The agent ships boot_epoch_ms as a string (proto int64 -> JSON)
    # while prev_boot_epoch_ms is an int; give agents one type.
    for k in ("boot_epoch_ms", "prev_boot_epoch_ms", "service_uptime_ms"):
        v = s.get(k)
        if isinstance(v, str) and v.strip().lstrip("-").isdigit():
            s[k] = int(v)
    # Collapse pry_driver_health when it's just "healthy, nothing to
    # see". Preserves the block whole when verdict != loaded or probes
    # tripped — that's when its contents are diagnostic.
    dh = s.get("pry_driver_health")
    if isinstance(dh, dict):
        verdict = str(dh.get("verdict", "")).lower()
        probe_errors = dh.get("probe_errors") or []
        if verdict == "loaded" and not probe_errors:
            s["pry_driver_health"] = {"verdict": "loaded"}
    # Security posture flags. The two kept (testsigning / secureboot)
    # are the only ones that pivot a decision inside a session (test-
    # signing gates driver loads; secureboot is the top-level yes/no
    # for policy-restricted lab work).
    for k in ("hvci", "memory_integrity", "driver_blocklist_on",
              "kva_shadow", "vbs_enabled", "credential_guard",
              "lsa_protected", "kernel_debugger",
              "patchguard_expected", "patchguard_state"):
        s.pop(k, None)
    return s


def _status_health_warnings(ctx, s: dict, driver_present: bool) -> list[str]:
    out: list[str] = []
    cw = list(getattr(ctx.cfg, "config_warnings", None) or [])
    if cw:
        shown = "; ".join(cw[:5]) + (f"; ... (+{len(cw) - 5} more)"
                                     if len(cw) > 5 else "")
        out.append(f"orchestrator config: {len(cw)} key(s) ignored at load "
                   f"— {shown}. Fix the YAML and restart.")
    reg = getattr(ctx, "_registry", None)
    reason = str(getattr(reg, "read_only_reason", "") or "")
    if reason:
        out.append(f"machine registry is READ-ONLY: {reason}")
    try:
        drv_abi = int(s.get("driver_abi_version") or 0)
        agent_abi = int(s.get("agent_abi_version") or 0)
    except (TypeError, ValueError):
        drv_abi = agent_abi = 0
    if driver_present and (drv_abi or agent_abi) \
            and s.get("driver_abi_ok") is False:
        out.append(
            f"driver ABI mismatch: loaded driver v{drv_abi}, agent expects "
            f"v{agent_abi} — driver-backed RPCs are refused (or misread on "
            "an older agent). Reload a matching driver build "
            "(scripts/update_target.py --component driver).")
    return out


async def do_status(ctx, *, name: str, fast_fail: bool,
                    verbose: bool = False) -> str:
    view = ctx.session.resolve_view_name(name)
    client = ctx.session.require_client(view)
    # T2.6 (PR#1): fast_fail=True — 1s TCP probe + 1s gRPC
    # deadline for wedge-vs-gone triage. Returns unreachable
    # immediately on either failure (elapsed_ms attached) so a
    # dashboard can distinguish "box gone" from "box slow".
    if fast_fail:
        import time as _time
        from ....session import _probe_tcp as _probe
        _t0 = _time.monotonic()
        _endpoint = getattr(client, "endpoint", "") or ""
        # Use locals prefixed with underscore so this branch
        # never shadows the outer `host`/`port` function
        # kwargs — Python scopes a function's locals by
        # assignment, and an unprefixed `host, ... = ...`
        # unpacking here would turn `host` into a local for
        # the entire run() closure (breaking connect's use).
        _host, _sep, _port_s = _endpoint.rpartition(":")
        try:
            _port_n = int(_port_s)
        except ValueError:
            _port_n = 0
        try:
            if _host and _port_n:
                await _probe(_host, _port_n, timeout_s=1.0)
            s = await asyncio.wait_for(client.status(),
                                        timeout=1.0)
        except (asyncio.TimeoutError, OSError, Exception) as exc:
            return _j({
                "ok": False, "kind": "unreachable",
                "view": view,
                "endpoint": _endpoint,
                "elapsed_ms": int((_time.monotonic() - _t0)
                                  * 1000),
                "error": str(exc),
                "hint": ("status fast_fail=true tightens the "
                         "probe to 1s TCP + 1s gRPC — the box "
                         "is wedged or gone. Drop fast_fail "
                         "for the patient path, or call "
                         "target_manage(action='reconnect') "
                         "if the endpoint moved")})
    else:
        s = await client.status()
    # v14: boot-epoch tracking. A changed boot_epoch_ms means the
    # target rebooted — driver state, shells, follows, watchdog
    # arms and detached handles from the last lifetime are all
    # orphaned; a changed agent_instance_id on the same boot is
    # an agent restart (same orphans minus the driver). Either
    # way the stale orchestrator-side state gets swept so stale
    # session_id / handle_id errors stop masquerading as live
    # resources.
    view_name = view
    change = ctx.session.note_boot_identity(view_name, s)
    # T1.3 (PR#2): first_connect is informational — attach to
    # the status reply but never sweep or warn.
    if change and change.get("kind") in ("new_boot",
                                          "agent_restart"):
        s["swept"] = await ctx.sweep_view_state(view_name)
        s["boot_change"] = change
        kind = change["kind"]
        s["warnings"] = [
            f"view {view_name!r}: {kind.replace('_', ' ')} "
            "detected — every shell, follow, watchdog arm and "
            "detached handle from the previous lifetime is dead; "
            "spilled resX artifacts predate this boot. "
            + ("Reload the driver before kernel ops."
               if kind == "new_boot" else
               "Reconnect debug sessions; driver state survived.")
        ]
    # drain notices parked by the boot monitor — a
    # reboot the monitor saw first surfaces here exactly as if
    # the lazy detector above had caught it (sweep already ran
    # inside the monitor); a standalone minidump notice attaches
    # its parsed dump under `minidump`.
    pending = ctx.session.pending_boot_notices.pop(view_name, None)
    if pending is not None:
        if change is None and pending.get("kind") in (
                "new_boot", "agent_restart"):
            s["boot_change"] = pending
            s["warnings"] = [
                f"view {view_name!r}: "
                f"{pending['kind'].replace('_', ' ')} detected "
                "by the boot monitor — stale shells/follows/"
                "watchdog arms/detached handles were swept at "
                "detection time; resX artifacts predate this "
                "boot."
                + (" Reload the driver before kernel ops."
                   if pending["kind"] == "new_boot" else "")]
        if pending.get("minidump") is not None:
            s["minidump"] = pending["minidump"]
    # DHCP self-heal: the link watcher re-pointed this view to the
    # machine's new address while nobody was looking — say so once.
    moved = ctx.session.pending_endpoint_notices.pop(view_name, None)
    if moved is not None:
        s["endpoint_change"] = moved
        warns = s.get("warnings")
        if not isinstance(warns, list):
            warns = []
        warns.append(
            f"view {view_name!r}: the machine moved from "
            f"{moved.get('from')} to {moved.get('to')} "
            f"(found via {moved.get('source')}); the channel was "
            "re-pointed automatically and the identity verified"
            + (f" — it also did a {str(moved.get('boot_change')).replace('_', ' ')}"
               if moved.get("boot_change") else ""))
        s["warnings"] = warns
    # Phase 0.1: honest driver-absent envelope on driver-sourced
    # fields so the LLM stops treating pre-load defaults as truth.
    driver_present = str(s.get("driver_state", "")).upper() in (
        "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED", "SERVICE", "MANUAL_MAPPED")
    s["driver_present"] = driver_present
    # orchestrator-side problems that change what is safe to do —
    # config keys that were ignored (a typo in a security knob fails
    # closed now, but say so), a read-only machine registry, and a
    # driver/agent ABI mismatch (StatusResponse.driver_abi_*).
    extra = _status_health_warnings(ctx, s, driver_present)
    if extra:
        warns = s.get("warnings")
        s["warnings"] = (warns if isinstance(warns, list) else []) + extra
    if not driver_present:
        for field_name in ("testsigning", "hvci", "secureboot",
                           "patchguard_expected", "driver_version"):
            if field_name in s and not isinstance(s[field_name], dict):
                s[field_name] = {
                    "value": s[field_name],
                    "confidence": "driver-absent-default",
                    "note": "value from agent bring-up path; "
                            "only trustworthy after a successful driver_load",
                }
    # promote key host_info fields into
    # the slim status response so a first `status` call shows
    # HVCI, MSFT-driver-blocklist, KVA shadow, PC uptime, and
    # the pry-driver health block. These require agent v8+
    # for the HostInfo RPC; fall back cleanly if unavailable.
    try:
        hi = await client.host_info(include_hardware=False)
    except Exception as exc:
        hi = {"ok": False, "error": str(exc)}
    if hi.get("ok"):
        sec = hi.get("security") or {}
        uptime = hi.get("uptime") or {}
        def _val(pair, default=None):
            return pair.get("value", default) if isinstance(pair, dict) else pair
        # HVCI: overwrite the driver-absent placeholder with the
        # host_info-verified value when we have one (registry /
        # api / driver — never the slim default).
        hvci_pair = sec.get("hvci")
        if isinstance(hvci_pair, dict) and hvci_pair.get("source") not in (
                None, "unknown", "driver-absent-default"):
            s["hvci"] = hvci_pair
        # Newly-surfaced fields:
        s["memory_integrity"] = hvci_pair       # alias — user-facing name
        s["driver_blocklist_on"] = sec.get("driver_blocklist_on")
        s["kva_shadow"] = sec.get("kva_shadow")  # populated when agent has the probe
        s["vbs_enabled"] = sec.get("vbs_enabled")
        s["credential_guard"] = sec.get("credential_guard")
        s["lsa_protected"] = sec.get("lsa_protected")
        s["kernel_debugger"] = sec.get("kernel_debugger")
        s["secureboot"] = sec.get("secureboot") if isinstance(sec.get("secureboot"), dict) \
                           else s.get("secureboot")
        s["pc_uptime_ms"] = uptime.get("pc_uptime_ms")
        s["service_uptime_ms"] = uptime.get("service_uptime_ms")
        s["patchguard_state"] = sec.get("patchguard_state")
        # Multi-machine: self-label the reply and refresh the
        # cached identity so machine-alias resolution stays
        # current when a box's address changes.
        s["machine"] = ctx.session.machine_of(view)
        s["computer_name"] = (
            (hi.get("identity") or {}).get("computer_name")
            or "")
        ctx.session.note_machine_identity(
            view, computer_name=s["computer_name"],
            endpoint=getattr(client, "endpoint", ""),
            scan_service_version=int(s.get("scan_service_version") or 0),
            pointer_map_version=int(s.get("pointer_map_version") or 0),
            dissect_version=int(s.get("dissect_version") or 0))
    else:
        s["host_info_hint"] = ("HostInfo RPC unavailable (agent < v8?) — "
                                "run target_manage(action='host_info') for the "
                                "richer view once the agent is rebuilt")
    # pry-driver-specific health.
    # Explains WHY driver_state might say DRIVER_ABSENT.
    if str(view).endswith(".user") or str(view) == "user":
        # The umagent has no Files / service-enum surface, so the probe
        # could only report UNIMPLEMENTED errors and a bogus
        # "absent_clean" verdict. The driver is the kernel view's concern.
        machine = str(view).rsplit(".", 1)[0] if "." in str(view) else ""
        s["pry_driver_health"] = {
            "verdict": "not_applicable",
            "hint": ("the user view (umagent) does not use the driver; "
                     "check target_manage(action='status', name="
                     f"'{machine + '.kernel' if machine else 'kernel'}')")}
    else:
        try:
            from ..._pry_driver_probe import probe_pry_driver
            s["pry_driver_health"] = await probe_pry_driver(
                client, driver_state=s.get("driver_state"))
        except Exception as exc:
            s["pry_driver_health"] = {"ok": False,
                                          "error": f"probe failed: {exc}"}
    # degraded-view warn banner. Sweep every
    # connected view and warn on any that has been silent
    # longer than PRY_DEGRADED_WARN_MS (default 5000 ms).
    # A stale channel doesn't necessarily mean anything is
    # broken — the caller may just not have used it — but
    # when it happens on the primary view during active
    # tool use it's a strong hint that a reconnect is due.
    try:
        warn_ms = int(os.environ.get(
            "PRY_DEGRADED_WARN_MS") or 5000)
    except (TypeError, ValueError):
        warn_ms = 5000
    degraded = []
    for v in ctx.session.all_views():
        if not v.get("connected"):
            continue
        idle_s = v.get("seconds_since_last_op") or 0
        if idle_s and idle_s > (warn_ms / 1000.0):
            degraded.append((v["name"], idle_s))
    # apply the lean pass unless verbose=True.
    if not verbose:
        s = _lean_status(s)
    if not degraded:
        return _j(s)
    # Build the envelope explicitly so we can attach warns
    # via _envelope.warn() — a raw dict returned by _j would
    # lose the warnings slot (envelope_from_result packs
    # extras under `data`).
    env = _envelope_ok(
        s,
        kind=_resolve_kind("target_manage", "status"),
        tool="target_manage",
        action="status",
    )
    from ..._envelope import warn as _envelope_warn
    for vname, idle_s in degraded:
        _envelope_warn(env,
            f"view {vname!r} has been silent for {idle_s}s — "
            f"consider target_manage(action='reconnect', "
            f"name={vname!r}) if calls to it are hanging.")
    return _j(env)


async def do_sysinfo(ctx, *, name: str) -> str:
    view = ctx.session.resolve_view_name(name)
    s = await ctx.session.require_client(view).status()
    driver_present = str(s.get("driver_state", "")).upper() in (
        "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED", "SERVICE", "MANUAL_MAPPED")
    def _honest(v):
        if driver_present:
            return v
        return {"value": v, "confidence": "driver-absent-default",
                "note": "load the driver before trusting this field"}
    return _j({
        "ok": True,
        "driver_present": driver_present,
        "os": s.get("os_version"),
        "build": s.get("os_build"),
        "testsigning": _honest(s.get("testsigning")),
        "hvci": _honest(s.get("hvci")),
        "driver_state": s.get("driver_state"),
        "patchguard_expected": _honest(s.get("patchguard_expected")),
        "agent_uptime_ms": s.get("agent_uptime_ms"),
    })


async def do_host_info(ctx, *, name: str,
                       include_security_products: bool,
                       include_hardware: bool) -> str:
    # v8: broad target-machine fingerprint. Grouped payload with
    # identity / os / security / hardware / uptime, and each
    # posture bit is a {value, source} pair — we lift that into
    # the confidence-envelope shape callers already know from
    # sysinfo. Older agents come back with a clean ok:false so
    # the LLM sees a real gap instead of a fabricated default.
    view = ctx.session.resolve_view_name(name)
    client = ctx.session.require_client(view)
    raw = await client.host_info(
        include_security_products=include_security_products,
        include_hardware=include_hardware,
    )
    if not raw.get("ok"):
        return _j(raw)
    sec = raw.get("security") or {}
    def _wrap(pair):
        if not isinstance(pair, dict):
            return pair
        src = pair.get("source") or "unknown"
        confidence = {
            "driver": "driver-verified",
            "registry": "usermode-registry",
            "api": "usermode-api",
            "unknown": "unknown",
        }.get(src, src)
        return {"value": pair.get("value"),
                "confidence": confidence,
                "source": src}
    wrapped_security = {k: (_wrap(v) if isinstance(v, dict) else v)
                        for k, v in sec.items()}
    raw["security"] = wrapped_security
    return _j(raw)


async def do_parity(ctx, *, name: str, pid: int, samples: int,
                     read_bytes: int) -> str:
    # The kernel/user pair always comes from ONE machine —
    # name= (or the caller's focus) picks which.
    view = ctx.session.resolve_view_name(name)
    p_machine = ctx.session.machine_of(view)
    kernel_client = ctx.session.require_client(
        ctx.session._view_for(p_machine, "kernel"))
    user_client = ctx.session.require_client(
        ctx.session._view_for(p_machine, "user"))
    report = await run_parity(kernel_client, user_client, pid,
                              samples=samples, read_bytes=read_bytes)
    severity, reason = verdict(report)
    cid = current_client_id()
    sid = ctx.get_current_session_id(cid) or ctx.ledger.start_session(
        ctx.session.cfg.target_endpoint)
    if not ctx.get_current_session_id(cid):
        ctx.set_current_session_id(cid, sid)
    fid = ctx.ledger.record(
        sid, severity,
        f"parity pid={pid}: kernel vs usermode",
        reason, refs="parity_check", agent_id=cid,
    )
    ctx.ledger.add_evidence(fid, "parity_report", _j(report))
    # breadcrumb: attribute the parity run itself
    try:
        ctx.ledger.event(
            "target_manage", "parity", agent_id=cid, session_id=sid,
            target=ctx.session.cfg.target_endpoint,
            summary=f"pid={pid} verdict={severity} finding={fid}",
        )
    except Exception:  # pragma: no cover
        pass
    return _j({"ok": True, "finding_id": fid, "severity": severity,
               "reason": reason, "summary": report["summary"],
               "checks": report["checks"][:8]})
