"""Bp tool registration for the pry MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from .common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)


# module-level so the lazy action-enum annotation resolves
# (from __future__ import annotations defers eval to module globals).
BP_ACTIONS = ["add", "remove", "list", "enable", "disable", "events",
              "actions"]


def _event_window_cov(hits: list, dropped: int, limit: int) -> dict:
    """event-window coverage for bp_manage events: a drain that reported
    exhaustion is complete; a cut-off window (drain cap hit) is partial +
    drain_limit_reached; lost events are partial + event_window_drained."""
    from .._coverage import coverage as _coverage
    if dropped:
        return _coverage("event-window", "partial", "event_window_drained")
    if limit and len(hits) >= limit:
        return _coverage("event-window", "partial", "drain_limit_reached")
    return _coverage("event-window", "complete")

# EventsKind bit for kernel HW-BP hits (driver int1 hook feed).
_BP_HIT_KIND_BIT = 1 << 6

# debug-port fallback state: when the kernel #DB trap can't install
# (hypervisor descriptor-table exiting + EPT-RO IDT — observed on the
# Hyper-V lab guest), user-space HW bp hits are still observable via the
# agent's dbgeng session in monitor mode. Module-level so the armed set
# and attach survive across calls; single-pid (dbgeng single-session).
_BP_BRIDGE = {"pid": 0, "attached": False, "armed": {}}

_USER_VA_MAX = 0x0000800000000000


async def _bp_events_debug_port(c, ctx, *, since_seq: int, limit: int) -> dict:
    """Observe armed user-space pry HW bps through the agent's dbgeng
    debug port instead of the (hypervisor-blocked) kernel int1 hook.

    Attaches to the bp's pid in monitor mode (hits auto-resume so the
    process never freezes), mirrors each armed user-space driver bp as a
    dbgeng `ba` data breakpoint, and maps BREAKPOINT_HW debug events
    (plus driver-DR7 hits arriving as single-step exceptions) back into
    the BP_HIT row shape. Note the semantics shift: the target process
    becomes *debugged* — visible to anti-debug checks, exclusive of other
    debuggers — and only pid-scoped user-space bps are covered; kernel
    and global bps still need the kernel hook."""
    bps = await c.bp_list()
    user_bps = [
        b for b in (bps or [])
        if int(b.get("bp_id", 0) or 0) >= 1000000
        and b.get("enabled")
        and int(b.get("pid", 0) or 0) != 0
        and int(b.get("address", 0) or 0) < _USER_VA_MAX
    ]
    # filter dead-pid bps before the multi-pid span check.
    # Driver bps outlive the owning pid when the process exits — the
    # per-thread DR state is cleared via PryOnThreadNotify but the
    # top-level BpRecord lingers until a successful BpHwClear. A test
    # loop that spawns short-lived targets fills the registry with
    # ghost bps, and the previous span check then errored
    # 'armed user bps span pids [...]' even when only ONE pid is still
    # alive. Ask the agent for the live process list and keep only bps
    # whose pid is in it.
    candidate_pids = {int(b["pid"]) for b in user_bps}
    live_pids: set[int] = set()
    if candidate_pids:
        try:
            procs = await c.mem_processes()
            live_pids = {int(p.get("pid", 0) or 0) for p in (procs or [])}
        except Exception:  # noqa: BLE001 — fall back to the raw set
            live_pids = candidate_pids
        user_bps = [b for b in user_bps if int(b["pid"]) in live_pids]
    if not user_bps:
        dead_pids = sorted(candidate_pids - live_pids) if live_pids else []
        hint = ("kernel int1 hook unavailable under this "
                "hypervisor and no armed pid-scoped user-space "
                "HW bps found for the debug-port fallback; "
                "kernel/global bps are not observable here")
        if dead_pids:
            hint = (f"all armed user HW bps belong to dead pids "
                    f"{dead_pids}; bp_manage(action='remove', bp_id=…) "
                    f"to prune the lingering registry entries "
                    f"(idempotent on dead-pid driver bps)")
        return {"ok": True, "hits": [], "count": 0,
                "delivery": "none",
                "hook_installed": False,
                "hint": hint}

    pids = sorted({int(b["pid"]) for b in user_bps})
    if len(pids) > 1:
        return {"ok": False, "kind": "bp_bridge_multi_pid",
                "error": (f"armed user bps span pids {pids}; the dbgeng "
                          "fallback is single-session"),
                "hint": ("disarm all but one pid's bps, or run the kernel "
                         "hook on a non-virtualized target")}

    pid = pids[0]
    if not (_BP_BRIDGE["attached"] and _BP_BRIDGE["pid"] == pid):
        att = await c.debug_attach(pid, monitor=True)
        if not att.get("ok"):
            err = str(att.get("error", ""))
            if "already" not in err:
                return {"ok": False, "kind": "bp_bridge_attach",
                        "error": f"debug-port attach pid={pid}: {err}",
                        "hint": ("the process may already be debugged or "
                                 "be PPL-protected; try kernel mode on a "
                                 "non-virtualized target")}
            if _BP_BRIDGE["pid"] != pid:
                return {"ok": False, "kind": "bp_bridge_attach",
                        "error": (f"dbgeng session already active and "
                                  f"not known to be on pid={pid}"),
                        "hint": ("debug_manage(action='detach') the current "
                                 "session first, then retry")}
        _BP_BRIDGE.update(pid=pid, attached=True)

    # mirror-arm each driver bp as a dbgeng data bp — dbgeng writes the
    # DRs through the debug port, so hits arrive as bp_hw events. Routed
    # through Breakpoints.Add(via_debugger) — AddBreakpoint2 works while
    # the target runs, so a monitor session never needs parking.
    armed = _BP_BRIDGE["armed"]
    for b in user_bps:
        addr = int(b["address"])
        if addr in armed:
            continue
        acc_str = str(b.get("access", "exec"))
        sz = 1 if acc_str == "exec" else int(b.get("size") or 4)
        try:
            out = await c.bp_add("hw", addr, size=sz, access=acc_str,
                                 via_debugger=True)
        except Exception as exc:
            return {"ok": False, "kind": "bp_bridge_arm",
                    "error": f"dbgeng bp_add 0x{addr:x}: {exc}"}
        armed[addr] = {"bp_id": int(b["bp_id"]),
                       "dbg_id": int(out.get("bp_id", 0) or 0),
                       "access": acc_str}

    # drain new debug events: breakpoint_hw hits + single-step exceptions
    # whose address matches an armed bp (driver-armed DR firing on a
    # thread dbgeng's mirror didn't cover surfaces as an exception).
    # The debug bus only fills while the stream pump is alive — restart it
    # if it died so a "no hits" answer stays honest.
    if not ctx.event_pump_alive():
        ctx.start_event_pump()
    hits = []
    last_seq = max(_BP_BRIDGE.get("last_seq", 0), int(since_seq))
    max_seq = _BP_BRIDGE.get("last_seq", 0)
    addr_map = armed
    for ev in c.bus.recent:
        if ev.kind != "debug":
            continue
        d = ev.data
        seq = int(d.get("seq", 0) or 0)
        if seq <= last_seq:
            continue
        kind = str(d.get("kind", ""))
        addr = int(d.get("address", 0) or 0)
        if kind == "BREAKPOINT_HW" and addr in addr_map:
            rec = addr_map[addr]
        elif (kind == "EXCEPTION"
              and int(d.get("exception_code", 0) or 0) & 0xFFFFFFFF
                  == 0x80000004
              and addr in addr_map):
            rec = addr_map[addr]
        else:
            continue
        hits.append({"seq": seq,
                     "ts_ms": int(d.get("timestamp_unix", 0) or 0) * 1000,
                     "pid": pid, "tid": int(d.get("tid", 0) or 0),
                     "rip": addr, "rip_hex": hex(addr),
                     "bp_id": rec["bp_id"],
                     "access": rec["access"],
                     "via": "debug_port"})
        if seq > max_seq:
            max_seq = seq
    if max_seq > last_seq:
        _BP_BRIDGE["last_seq"] = max_seq

    hits = hits[-int(limit):] if hits else []
    # safety net: if the session wasn't attached with monitor (e.g. a
    # prior non-monitor attach), hits still stop the target — resume.
    if hits:
        try:
            await c.debug_continue()
        except Exception:
            pass
    return {"ok": True, "hits": hits, "count": len(hits),
            "last_seq": max_seq,
            "delivery": "debug_port",
            "debug_pid": pid,
            "pump_alive": ctx.event_pump_alive(),
            "hook_installed": False,
            "hint": ("empty: no hits drained — dbgeng mirror bps are armed; "
                     "hits appear after a watched access" if not hits else "")}


# since_seq far past any real sequence: the poll installs the hook and
# subscribes without draining (or losing) a single queued hit.
_NO_DRAIN_SEQ = 1 << 62


async def _ensure_bp_hook(ctx, c, dangerous_ok: bool) -> dict | None:
    """Make sure the driver int1 hook is installed before a hw bp is armed.

    Returns an error dict when the hook can't be used, else ``None``. An
    armed debug register whose hit nobody consumes is delivered to the
    target thread as STATUS_SINGLE_STEP and terminates the process."""
    hint = ("hw breakpoint hits need the driver int1 hook to consume them; "
            "without it the first hit raises STATUS_SINGLE_STEP in the target "
            "and kills it. Pass dangerous_ok=true (lab only, installs the "
            "hook) and enable security.allow_event_stream.")
    if not dangerous_ok:
        return {"ok": False, "kind": "confirm_required",
                "error": "bp add kind='hw': refusing to arm without the int1 "
                         "hook (dangerous_ok=false)",
                "hint": hint}
    if not getattr(ctx.cfg.security, "allow_event_stream", False):
        return {"ok": False, "kind": "not_allowed",
                "error": "bp add kind='hw': security.allow_event_stream=false, "
                         "so no hook can consume the hits",
                "hint": hint}
    if getattr(c, "events", None) is None:
        return {"ok": False, "kind": "agent_version",
                "error": "bp add kind='hw': agent has no Events service",
                "hint": "rebuild + redeploy the agent"}
    try:
        resp = await c.events_poll(since_seq=_NO_DRAIN_SEQ, max_events=1,
                                   kinds_mask=_BP_HIT_KIND_BIT,
                                   dangerous_ok=True)
    except Exception as exc:  # noqa: BLE001 — surfaced to the caller
        return {"ok": False, "kind": "hook_failed",
                "error": f"bp add kind='hw': hook install failed: {exc}",
                "hint": hint}
    if not resp.get("ok") or not resp.get("bp_hook"):
        return {"ok": False, "kind": "hook_failed",
                "error": ("bp add kind='hw': the int1 hook is not installed "
                          f"({resp.get('error') or 'driver refused'})"),
                "hint": hint}
    return None


def register(mcp, ctx: Context) -> None:
    """Register the ``bp_manage`` tool on *mcp*, using *ctx* for state."""
    # --------------------------------------------------------------- bp_manage --

    # per-verb help for action='actions'. Every verb in BP_ACTIONS
    # gets a {one_liner, key_args, example} row; the 'actions' verb lists
    # itself so a caller sees the discovery primitive is real.
    _BP_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "bp_manage(action='actions')"},
        "add": {"one_liner": "arm a breakpoint; kind=sw (dbgeng int3) | "
                             "hw (DR0-3 via driver, always driver-backed). "
                             "address: int, '0x…', 'module+offset', "
                             "or 'module!export'. sw bps accept "
                             "condition / commands / hit_count / "
                             "one_shot; tid= is the sw match-tid filter; "
                             "global_=True arms a system-wide hw bp.",
                "key_args": "kind, address, slot, size, access, pid, tid, "
                            "global_, dangerous_ok, condition, commands, "
                            "hit_count, one_shot",
                "example": "bp_manage(action='add', kind='sw', "
                           "address='user32.dll!GetMessageW', pid=1234, "
                           "condition='@rcx == 0', one_shot=True)"},
        "remove": {"one_liner": "delete a breakpoint by bp_id",
                   "key_args": "bp_id, force",
                   "example": "bp_manage(action='remove', bp_id=3)"},
        "list": {"one_liner": "enumerate all breakpoints (owner/foreign "
                              "annotated)",
                 "key_args": "none",
                 "example": "bp_manage(action='list')"},
        "enable": {"one_liner": "re-enable a disabled breakpoint",
                   "key_args": "bp_id, force",
                   "example": "bp_manage(action='enable', bp_id=3)"},
        "disable": {"one_liner": "disable without removing",
                    "key_args": "bp_id, force",
                    "example": "bp_manage(action='disable', bp_id=3)"},
        "events": {"one_liner": "drain HW-BP hit events: driver int1 hook "
                                "feed (rip/dr6/slot/tid) when installable, "
                                "else debug-port fallback for user bps "
                                "(mode=auto). Needs dangerous_ok.",
                   "key_args": "dangerous_ok, since_seq, limit, mode",
                   "example": "bp_manage(action='events', dangerous_ok=True)"},
    }

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def bp_manage(action: Annotated[str, Field(json_schema_extra={"enum": BP_ACTIONS})],
                        kind: str = "sw", address: int | str = 0, slot: int = 0xFF,
                        size: int = 1, access: str = "exec", kernel_target: bool = False,
                        pid: int = 0, tid: int = 0, bp_id: int = 0,
                        global_: bool = False, dangerous_ok: bool = False,
                        force: bool = False,
                        since_seq: int = 0, limit: int = 256,
                        mode: str = "auto",
                        # sw-bp extensions
                        condition: str = "", commands: str = "",
                        hit_count: int = 0, one_shot: bool = False,
                        name: str = "") -> str:
        """Breakpoints: sw int3 (dbgeng) and hw DR0-3 (always driver-backed;
        kernel_target is a display hint). tid=0 arms every thread of pid;
        global_=true arms a system-wide hw bp (cap 2). sw bps take
        condition / commands / hit_count / one_shot, and tid= is their
        match-tid filter. events drains hw-BP hits - driver int1 hook
        (dangerous_ok, refused under a hypervisor) or the mode='auto'
        debug-port fallback (user pids only). force=true overrides a
        foreign-owner refusal. Per-verb help:
        bp_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "kind": kind, "address": address, "slot": slot}

        async def run() -> str:
            if action not in BP_ACTIONS:
                return _unknown_action("bp_manage", action, BP_ACTIONS, _BP_ACTION_HELP)
            if action == "actions":
                return _actions_help("bp_manage", _BP_ACTION_HELP)
            # name= resolves machine.view; the canonical key also
            # scopes the per-view ownership tags so bps on different
            # machines don't share a namespace.
            view = ctx.session.resolve_view_name(name)
            c = ctx.session.require_client(view)
            cat = f"bp:{view}"
            # kernel_target -> kernel module list; user bp -> the target pid.
            addr = await _addr_resolve(address, c, kernel=kernel_target,
                                       pid=pid, name="address")
            if action == "add":
                # HW breakpoints are ALWAYS driver-backed
                # (PryBpHwSet) — preflight so a missing driver surfaces
                # as `driver_absent` instead of a raw gRPC failure. SW
                # int3 bps go through dbgeng and work without the driver.
                if kind.lower() == "hw":
                    guard = await _require_driver(ctx, "bp_manage", "add",
                                                  name)
                    if guard:
                        return _j(guard)
                    # A hw bp hit nobody consumes is delivered to the
                    # target as STATUS_SINGLE_STEP and kills it (seen live:
                    # arming before the first `events` call installed the
                    # int1 hook). Install the hook first; without consent
                    # for the hook, refuse instead of arming a trap.
                    hook_err = await _ensure_bp_hook(ctx, c, dangerous_ok)
                    if hook_err:
                        return _j(hook_err)
                # forward sw-bp extensions (condition /
                # commands / hit_count -> pass_count / one_shot) and
                # treat `tid` as the engine match-tid filter on sw
                # bps. Pass only when non-default so an older
                # agent-client wrapper keeps working — mirrors the
                # existing `global_` / `dangerous_ok` plumbing.
                extra: dict[str, Any] = {}
                is_sw = kind.lower() == "sw"
                if condition:
                    extra["condition"] = condition
                if commands:
                    extra["commands"] = commands
                if hit_count:
                    extra["pass_count"] = int(hit_count)
                if one_shot:
                    extra["one_shot"] = True
                if is_sw and tid:
                    extra["match_tid"] = int(tid)
                resp = await c.bp_add(kind, addr, slot, size, access, kernel_target,
                                       pid, tid,
                                       global_=global_,
                                       dangerous_ok=dangerous_ok,
                                       **extra)
                if ctx.ownership is not None and isinstance(resp, dict):
                    new_id = resp.get("bp_id")
                    if isinstance(new_id, int) and new_id != 0:
                        await ctx.ownership.claim(cat, str(new_id),
                                                   current_client_id())
                return _j(resp)
            if action == "list":
                rows = await c.bp_list()
                if ctx.ownership is not None and rows:
                    # bp_list rows carry `bp_id` as int; ownership keys are
                    # strings. Coerce for the annotate pass then restore.
                    for r in rows:
                        rid = r.get("bp_id")
                        if isinstance(rid, int):
                            r["bp_id"] = str(rid)
                    await ctx.ownership.annotate(
                        cat, rows, id_field="bp_id",
                        current_owner=current_client_id())
                    for r in rows:
                        rid = r.get("bp_id")
                        if isinstance(rid, str) and rid.isdigit():
                            r["bp_id"] = int(rid)
                return _j({"breakpoints": rows})
            if action == "events":
                # drain BP_HIT records from the driver's
                # notify ring. The first call installs the int1 hook —
                # dangerous_ok is the lab consent bit. mode='debug_port'
                # skips the driver path entirely (pure user-mode dbgeng
                # mirror, no kernel IDT touch, no consent needed).
                guard = await _require_driver(ctx, "bp_manage", "events",
                                              name)
                if guard:
                    return _j(guard)
                if not getattr(ctx.cfg.security, "allow_event_stream", False):
                    return _j({"ok": False, "kind": "not_allowed",
                               "error": ("bp event poll is disabled "
                                         "(security.allow_event_stream=false)"),
                               "hint": ("enable security.allow_event_stream in "
                                        "the orchestrator config once the "
                                        "target is known-good")})
                if c.events is None:
                    return _j({"ok": False, "kind": "agent_version",
                               "error": ("bp events: agent < v12 "
                                         "(Events.Poll lacks BP_HIT)"),
                               "hint": ("rebuild + redeploy the agent "
                                        "(scripts/update_target.py "
                                        "--component agent)")})
                if mode == "debug_port":
                    # Explicit skip-the-driver path — go straight to
                    # the user-mode dbgeng mirror.
                    fb = await _bp_events_debug_port(
                        c, ctx, since_seq=int(since_seq), limit=int(limit))
                    if fb.get("ok") is not False:
                        fb.setdefault("coverage", _event_window_cov(
                            fb.get("hits") or [], 0, int(limit)))
                    return _j(fb)
                resp = await c.events_poll(since_seq=int(since_seq),
                                           max_events=int(limit),
                                           kinds_mask=_BP_HIT_KIND_BIT,
                                           dangerous_ok=dangerous_ok)
                if not resp.get("ok"):
                    err = str(resp.get("error", ""))
                    unsupported = ("c00000bb" in err.lower()
                                   or "3221225659" in err
                                   or "not supported" in err.lower()
                                   or "not_supported" in err.lower())
                    refused = "refused" in err.lower()
                    # debug-port fallback: the kernel int1 hook is
                    # impossible under hypervisor descriptor-table exiting
                    # (EPT-RO IDT + lidt intercept — Hyper-V guest default).
                    # dbgeng data bps travel the debug port instead. This
                    # path is pure user-mode dbgeng attach + `ba` mirror —
                    # no kernel IDT patch — so it does NOT need the
                    # `dangerous_ok` consent the IDT hook requires. On
                    # mode='auto' we fall back on BOTH the "not supported"
                    # (hypervisor-blocked) and "refused" (consent-gate)
                    # driver outcomes — the user asked for the hits, we
                    # give them the hits via the surface that works.
                    if (unsupported or refused) and mode == "auto":
                        fb = await _bp_events_debug_port(
                            c, ctx, since_seq=int(since_seq), limit=int(limit))
                        if fb.get("ok") is not False:
                            fb.setdefault("coverage", _event_window_cov(
                                fb.get("hits") or [], 0, int(limit)))
                        return _j(fb)
                    return _j({"ok": False,
                               "kind": ("not_allowed" if "refused" in err
                                        else "bp_hook_failed"),
                               "error": err,
                               "hint": ("pass dangerous_ok=true to consent "
                                        "to the IDT[1] hook (lab targets)"
                                        if "refused" in err else
                                        ("kernel hook unsupported under "
                                         "this hypervisor — pass "
                                         "mode='debug_port' (or leave "
                                         "mode='auto') for the user-space "
                                         "dbgeng-mirror fallback; it needs "
                                         "no dangerous_ok consent"
                                         if unsupported else
                                         "check agent log / BPTRAP lines"))})
                hits = []
                for e in resp.get("events", []):
                    hits.append({"seq": e["seq"], "ts_ms": e["ts_ms"],
                                 "pid": e["pid"], "tid": e["tid"],
                                 "rip": e["address"],
                                 "rip_hex": hex(e["address"]),
                                 "dr6": e["dr6"], "dr6_hex": hex(e["dr6"]),
                                 "bp_id": e["bp_id"], "slot": e["slot"],
                                 "access": e["access"], "irql": e["irql"]})
                # best-effort module attribution for the faulting RIP
                try:
                    mods = await c.mem_modules(0, True)
                    ranges = [(int(m.get("base", 0) or 0),
                               int(m.get("base", 0) or 0) + int(m.get("size", 0) or 0),
                               str(m.get("name", "")))
                              for m in (mods or []) if m.get("base")]
                    for h in hits:
                        rip = h["rip"]
                        m = next(((lo, nm) for lo, hi, nm in ranges
                                  if lo <= rip < hi), None)
                        if m:
                            h["module"] = m[1]
                            h["module_offset"] = hex(rip - m[0])
                except Exception:
                    pass
                return _j({"ok": True, "hits": hits, "count": len(hits),
                           "last_seq": resp.get("last_seq", 0),
                           "dropped": resp.get("dropped", 0),
                           "subscribed": resp.get("subscribed", False),
                           "hook_installed": resp.get("bp_hook", False),
                           "coverage": _event_window_cov(
                               hits, int(resp.get("dropped", 0) or 0),
                               int(limit)),
                           "delivery": "idt_hook",
                           "hint": ("empty: no hits drained — the hook is "
                                    "installed and the ring armed; hits "
                                    "appear after a watched access" if
                                    not hits else "")})
            if action in ("remove", "enable", "disable"):
                if ctx.ownership is not None:
                    foreign = await ctx.ownership.is_foreign_or_none(
                        cat, str(bp_id), current_client_id())
                    if foreign is True and not force:
                        owner = await ctx.ownership.owner_of(cat, str(bp_id))
                        return _j({"ok": False,
                                   "kind": "foreign_owned",
                                   "owner": owner,
                                   "hint": "pass force=true to override"})
                if action == "remove":
                    result = await c.bp_remove(bp_id)
                    if ctx.ownership is not None:
                        await ctx.ownership.release(cat, str(bp_id))
                    return _j(result)
                if action == "enable":
                    return _j(await c.bp_set_enabled(bp_id, True))
                if action == "disable":
                    return _j(await c.bp_set_enabled(bp_id, False))
            return _unknown_action("bp_manage", action, BP_ACTIONS, _BP_ACTION_HELP)

        return await _guard(ctx, "bp_manage", action, args, run)
