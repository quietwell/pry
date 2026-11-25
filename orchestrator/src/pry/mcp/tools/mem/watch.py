"""``watch`` / ``watch_list`` / ``watch_stop`` verb bodies.

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
The orchestrator-side ``_WATCHES`` / ``_WATCH_SEQ`` registry is now
module-level: it survives the orchestrator lifetime the same way the
closure variant did, but is no longer rebuilt per ``register()`` call.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from .._runtime.addrs import _enrich_win32
from .._runtime.response import _j


# Orchestrator-side registry of active watches. Each entry is
#   {watch_id, task, events: [...], started_ts, tag, target}
# The gRPC stream is drained by a background task; the MCP caller
# polls via `watch_events`. Live only for the orchestrator lifetime.
_WATCHES: dict[str, dict[str, Any]] = {}
_WATCH_SEQ = [0]


async def handle_watch(ctx, c, *, pid: int, addr: int, size: int,
                       space: str, name: str, pattern_hex: str,
                       timeout_s: float, max_results: int,
                       filter: Any, mode: str = "poll",
                       access: str = "write", tid: int = 0,
                       slot: int = 0xFF, preempt_ok: bool = False) -> str:
    # ---- SI #25 HW-watch (v14) ----
    # mode='hw' arms a driver-managed DR slot through the agent's WatchHw
    # service (WatchHw.Add) and lets hits ring back through the CLASS_BP
    # notify path. Refused unless security.allow_hw_bp_hook; points the
    # caller at mode='poll' when the driver ABI is < 14 / mismatched or the
    # client has no WatchHw binding. The returned WatchCookie is stashed so
    # watch_stop releases the DR via WatchHw.Remove.
    _mode = str(mode or "poll").lower()
    if _mode == "hw":
        return await _handle_watch_hw(
            ctx, c, pid=pid, tid=tid, addr=addr, size=size,
            access=access, slot=slot, preempt_ok=preempt_ok,
            tag=filter or "", name=name,
        )
    if not hasattr(c, "mem_watch_stream"):
        return _j({"ok": False,
                   "error": "watch: agent < v7 (Memory.Watch missing)",
                   "hint": "rebuild agent with ABI v7"})
    if not size or size > 256:
        return _j({"ok": False,
                   "error": "watch: `size` must be 1..256 (small-object watcher)",
                   "hint": "for larger reads use memory_manage read directly"})
    # Auto-poll (blocking-collect) mode when max_results is
    # small and interval*count is under 30 s. Otherwise
    # kick off a background task and return a handle for
    # `watch_list` / `watch_stop` / `watch_events` polling.
    interval_ms = max(int(timeout_s * 1000) or 100, 10)
    # `max_results` doubles as max_events for the watch.
    dur_s = min(max(int(max_results or 60), 1), 600)
    events_cap = min(int(max_results or 0), 256)
    expected = bytes.fromhex(pattern_hex) if pattern_hex else b""
    # Fast-path: short duration -> collect inline (auto-poll).
    if dur_s <= 30 and events_cap <= 32:
        r = await c.mem_watch_collect(
            address=addr, length=size, space=space, pid=pid,
            interval_ms=interval_ms, duration_s=dur_s,
            expected_hex=expected, max_events=events_cap,
            tag=(filter or ""))
        r.update({"address": hex(addr), "space": space, "pid": pid,
                  "length": size, "interval_ms": interval_ms,
                  "duration_s": dur_s, "mode": "collect"})
        return _j(r)
    # Long-running: register a background task and return a handle.
    _WATCH_SEQ[0] += 1
    watch_id = f"w{_WATCH_SEQ[0]:04d}"
    bucket: dict[str, Any] = {
        "id": watch_id, "events": [], "reason": "",
        "started_ts": time.time(),
        "tag": filter or "", "target": name,
        "spec": {"address": hex(addr), "space": space, "pid": pid,
                 "length": size, "interval_ms": interval_ms,
                 "duration_s": dur_s, "max_events": events_cap},
        "done": False,
    }
    async def _drain() -> None:
        try:
            async for ev in c.mem_watch_stream(
                address=addr, length=size, space=space, pid=pid,
                interval_ms=interval_ms, duration_s=dur_s,
                expected_hex=expected, max_events=events_cap,
                tag=filter or ""):
                if ev.get("eof"):
                    bucket["reason"] = ev.get("reason") or ""
                    bucket["done"] = True
                    break
                bucket["events"].append(ev)
        except Exception as exc:  # noqa: BLE001
            bucket["error"] = _enrich_win32(str(exc))
            bucket["done"] = True
    bucket["task"] = asyncio.create_task(_drain())
    _WATCHES[watch_id] = bucket
    return _j({"ok": True, "watch_id": watch_id, "mode": "background",
               "hint": "poll with memory_manage(action='watch_list') then "
                       "read events (currently on the bucket); "
                       "stop with watch_stop(name=watch_id)"})


def handle_watch_list() -> str:
    out = []
    for wid, w in list(_WATCHES.items()):
        out.append({"id": wid, "done": w["done"],
                    "events": len(w["events"]),
                    "reason": w.get("reason", ""),
                    "started_ts": w["started_ts"],
                    "tag": w.get("tag", ""),
                    "spec": w.get("spec", {}),
                    "error": w.get("error")})
    return _j({"ok": True, "watches": out})


def handle_watch_stop(*, module: str, filter: Any) -> str:
    """Sync stop for poll-mode watches (kept for direct callers). A
    ``mode='hw'`` watch needs :func:`handle_watch_stop_async`, which also
    releases the DR slot on the agent."""
    wid = module or filter
    w = _WATCHES.get(wid)
    if not w:
        return _j({"ok": False,
                   "error": f"watch_stop: no watch with id {wid!r}"})
    if w.get("task") and not w["task"].done():
        w["task"].cancel()
    w["done"] = True
    events = list(w["events"])
    _WATCHES.pop(wid, None)
    return _j({"ok": True, "watch_id": wid,
               "events": events, "count": len(events),
               "reason": w.get("reason") or "stopped"})


async def handle_watch_stop_async(ctx, *, module: str, filter: Any) -> str:
    """``watch_stop`` for both modes: a hardware watch is disarmed through
    ``WatchHw.Remove`` (``bp_hw_watch_remove``) on the view that armed it
    before its bucket is dropped."""
    wid = module or filter
    w = _WATCHES.get(wid)
    spec = (w or {}).get("spec") or {}
    if not w or spec.get("mode") != "hw":
        return handle_watch_stop(module=module, filter=filter)
    cookie = int(spec.get("watch_cookie") or 0)
    removed: dict[str, Any] = {"ok": False, "error": "no client"}
    c = None
    try:
        c = ctx.session.clients.get(w.get("view") or "") if ctx else None
        if c is None and ctx is not None:
            c = ctx.session.require_client(w.get("target") or "")
    except Exception as exc:  # noqa: BLE001 — view gone: report, still drop
        removed = {"ok": False, "error": f"view not connected: {exc}"}
    if c is not None and cookie and hasattr(c, "bp_hw_watch_remove"):
        try:
            removed = dict(await c.bp_hw_watch_remove(cookie) or {})
        except Exception as exc:  # noqa: BLE001
            removed = {"ok": False, "error": _enrich_win32(str(exc))}
    _WATCHES.pop(wid, None)
    out = {"ok": bool(removed.get("ok")), "watch_id": wid, "mode": "hw",
           "watch_cookie": cookie, "events": [], "count": 0,
           "reason": "stopped", "remove": removed}
    if not removed.get("ok"):
        out["warning"] = ("the DR slot may still be armed on the target: "
                          f"WatchHw.Remove failed ({removed.get('error')}); "
                          "it is released when the watched thread exits or "
                          "the driver unloads")
    return _j(out)


# ------------------------------------------------------------- SI #25 (v14) --
# HW-watch — DR0..DR3-backed data watchpoint armed through the agent's
# WatchHw service (the client binds the stub).

# PING flag bit mirrored from comm/abi/version.h.
_PRY_FLAG_WATCH_HVCI_FALLBACK = 0x10
_PRY_ABI_MIN_HW_WATCH = 14


async def _abi_preflight(c) -> tuple[int, int, bool | None]:
    """``(driver_abi_version, flags, driver_abi_ok)`` from Status
    (StatusResponse.driver_abi_*). Zeros / None when the
    agent predates the fields - never a refusal on its own. The HVCI
    fallback bit arrives on WatchHwAddResponse instead."""
    abi, ok = 0, None
    try:
        st = await c.status() if hasattr(c, "status") else None
        if isinstance(st, dict):
            abi = int(st.get("driver_abi_version") or 0)
            if abi and "driver_abi_ok" in st:
                ok = bool(st.get("driver_abi_ok"))
    except Exception:  # noqa: BLE001 - preflight is advisory
        pass
    return abi, 0, ok


async def _handle_watch_hw(ctx, c, *, pid: int, tid: int, addr: int,
                           size: int, access: str, slot: int,
                           preempt_ok: bool, tag: str,
                           name: str) -> str:
    # Request shape mirrors memory_manage's existing watch verb — size is the
    # data-watchpoint length in bytes (DR limit: 1/2/4/8), access is one
    # of "read" (PRY_HW_RW promoted — Intel DRs can't observe reads
    # alone), "write", or "rw".
    if size not in (1, 2, 4, 8):
        return _j({"ok": False,
                   "error": "watch(hw): size must be 1, 2, 4, or 8",
                   "hint": "the x86 DR length encoding only covers those "
                           "sizes; split a wider range into multiple watches"})
    _access = (access or "write").lower()
    if _access == "read":
        _access = "rw"  # Intel DRs can't observe reads alone
    if _access not in ("write", "rw"):
        return _j({"ok": False,
                   "error": f"watch(hw): access must be write|rw (got {_access!r})"})
    # the hardware path arms a DR through the driver's int1 hook
    # (PatchGuard-sensitive) — same opt-in as AccessTrace's watchhw driver.
    cfg = getattr(ctx, "cfg", None) if ctx is not None else None
    if cfg is not None and not getattr(cfg.security, "allow_hw_bp_hook", False):
        return _j({"ok": False, "kind": "hw_bp_hook_disabled",
                   "error": ("watch(hw): refused — security.allow_hw_bp_hook "
                             "is false"),
                   "hint": ("mode='poll' needs no driver hook; set "
                            "security.allow_hw_bp_hook=true in the config "
                            "for the int1-hook-backed hardware watchpoint "
                            "(lab-only)"),
                   "fallback": "poll"})
    # Preflight the ABI version + HVCI-fallback bit. Any failure to
    # read it is treated as "unknown", never as a refusal.
    _abi, _flags, _abi_ok = await _abi_preflight(c)
    hvci_fallback = bool(_flags & _PRY_FLAG_WATCH_HVCI_FALLBACK)
    if _abi_ok is False:
        return _j({"ok": False, "kind": "driver_absent_or_stale",
                   "error": (f"watch(hw): the loaded driver's ABI v{_abi} "
                             "does not match the agent"),
                   "hint": "reload a matching driver build "
                           "(scripts/update_target.py --component driver)",
                   "abi_version": _abi, "fallback": "poll"})
    if _abi and _abi < _PRY_ABI_MIN_HW_WATCH:
        return _j({"ok": False,
                   "error": f"watch(hw): driver ABI v{_abi} < v{_PRY_ABI_MIN_HW_WATCH}",
                   "hint": "rebuild driver with ABI v14 or pass mode='poll'",
                   "abi_version": _abi, "fallback": "poll"})
    if not hasattr(c, "bp_hw_watch_add"):
        return _j({"ok": True,
                   "mode": "hw_pending",
                   "note": ("watch(hw): this view's client has no WatchHw "
                            "binding (bp_hw_watch_add) — pass mode='poll'"),
                   "address": hex(addr), "size": size,
                   "access": _access, "pid": pid, "tid": tid,
                   "slot": slot, "preempt_ok": preempt_ok,
                   "abi_version": _abi,
                   "hvci_fallback": hvci_fallback,
                   "fallback": "poll"})
    try:
        r = await c.bp_hw_watch_add(
            pid=pid, tid=tid, address=addr, size=size,
            access=_access, slot=slot, preempt_ok=preempt_ok,
            tag=tag,
        )
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False,
                   "error": _enrich_win32(str(exc)),
                   "mode": "hw",
                   "address": hex(addr), "size": size, "access": _access,
                   "pid": pid, "tid": tid, "slot": slot,
                   "abi_version": _abi,
                   "hvci_fallback": hvci_fallback,
                   "fallback": "poll"})
    r = dict(r or {})
    if r.get("ok") is False:
        return _j({"ok": False, "mode": "hw",
                   "kind": r.get("kind") or r.get("agent_kind") or "watchhw_arm_failed",
                   "error": _enrich_win32(str(r.get("error") or "WatchHw.Add failed")),
                   "address": hex(addr), "size": size, "access": _access,
                   "pid": pid, "tid": tid, "slot": slot,
                   "abi_version": _abi, "fallback": "poll"})
    hvci_fallback = hvci_fallback or bool(r.get("hvci_fallback"))
    cookie = int(r.get("watch_cookie") or 0)
    view = ""
    try:
        if ctx is not None:
            view = ctx.session.resolve_view_name(name)
    except Exception:  # noqa: BLE001
        view = ""
    _WATCH_SEQ[0] += 1
    watch_id = f"hw{_WATCH_SEQ[0]:04d}"
    _WATCHES[watch_id] = {
        "id": watch_id, "events": [],
        "reason": "", "done": False,
        "started_ts": time.time(),
        "tag": tag, "target": name, "view": view,
        "spec": {"mode": "hw", "address": hex(addr),
                 "size": size, "access": _access, "pid": pid,
                 "tid": tid, "slot": int(r.get("slot") or slot),
                 "preempt_ok": preempt_ok,
                 "watch_cookie": cookie},
    }
    out = {"ok": True, "mode": "hw", "watch_id": watch_id,
           "watch_cookie": cookie, "address": hex(addr),
           "size": size, "access": _access, "pid": pid, "tid": tid,
           "slot": int(r.get("slot") or slot),
           "threads_patched": int(r.get("threads_patched") or 0),
           "abi_version": _abi,
           "hvci_fallback": hvci_fallback,
           "hint": ("hits ring through event_manage (class=bp, bit 6) and "
                    "route by watch_cookie; stop with "
                    f"memory_manage(action='watch_stop', module={watch_id!r})")}
    if hvci_fallback:
        out["note"] = ("HVCI/hypervisor refuses the int1 hook — DRs "
                       "arm but hits won't ring; prefer mode='poll'")
    return _j(out)
