"""Orchestrator-side AccessTrace job registry + MCP verb bodies.

Mirrors the ``_PJOBS`` shape in ``tools/scripts.py`` — same OrderedDict
hard-cap pattern, same ``env`` / ``status`` / ``list`` / ``cancel``
idioms so the job surface feels identical to ``script_manage``.

Four verbs:

  access_trace_start(pid, address, size=8, access='rw', tid=0,
                     driver='auto'|'watchhw'|'dbgeng',
                     max_hits=4096, symbolize=true, disasm=true,
                     stackwalk=true, timeout_sec=300,
                     redact_regs=true)
                           -> {job_id, driver_used, watch_cookie|bp_id,
                               slot, hvci_fallback, threads_patched}

  access_trace_status(job_id, limit, offset, verbosity='normal')
                           -> {state, hits_so_far, kernel_dropped,
                               kernel_missed, ring_truncated,
                               last_hit_ts, elapsed_ms, hits: [...]}

  access_trace_stop(job_id) -> disarm (WatchHw.Remove or
                               bp_manage.remove); state -> 'cancelled'

  access_trace_list()      -> mirror of ``script_manage.jobs``

The orchestrator ring is capped at 4096 entries; older hits age out
with ``ring_truncated=True`` on the status.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Any

from ._dbgeng_driver import run_dbgeng_driver
from ._watchhw_driver import WatchhwJobCtx, run_watchhw_driver
from ...._redact import apply_hit_redaction


# MCP verb enum — appended to DEBUG_ACTIONS by debug/__init__.py.
ACCESS_TRACE_VERBS: tuple[str, ...] = (
    "access_trace_start",
    "access_trace_status",
    "access_trace_stop",
    "access_trace_list",
)

# Help entries merged into debug/__init__.py's _DEBUG_ACTION_HELP.
ACCESS_TRACE_HELP: dict[str, dict] = {
    "access_trace_start": {
        "one_liner": ("arm a HW watchpoint on (pid, address); drain BP_HIT "
                      "events, decode the memop at RIP, record a hit ring "
                      "(cap 4096). driver='watchhw'|'dbgeng'|'auto'; the "
                      "watchhw path needs security.allow_hw_bp_hook=true"),
        "key_args": ("pid, address, size, access, tid, driver, max_hits, "
                     "timeout_s"),
        "example": ("debug_manage(action='access_trace_start', pid=1234, "
                    "address=0x7ffe0000, size=8, access='rw')"),
    },
    "access_trace_status": {
        "one_liner": ("poll an access_trace_start() job: hits so far, "
                      "kernel loss counters, ring truncation. "
                      "verbosity='full' opts out of the GPR+RIP-bytes "
                      "redaction."),
        "key_args": "job_id, limit, offset, verbosity",
        "example": ("debug_manage(action='access_trace_status', "
                    "job_id='at0001', limit=64)"),
    },
    "access_trace_stop": {
        "one_liner": ("disarm the watchpoint and finalize the job; the "
                      "ring survives for status polling."),
        "key_args": "job_id",
        "example": ("debug_manage(action='access_trace_stop', "
                    "job_id='at0001')"),
    },
    "access_trace_list": {
        "one_liner": "list recent access_trace jobs (most recent first).",
        "key_args": "none",
        "example": "debug_manage(action='access_trace_list')",
    },
}


# Per-job ring + registry (mirrors _PJOBS in scripts.py).
_ATJOBS: "OrderedDict[str, dict]" = OrderedDict()
_ATJOB_SEQ = [0]
_ATJOB_CAP = 8                   # max concurrent jobs retained
_ATJOB_RING_CAP = 4096            # per-job hit ring cap (plan §4)

# Watchdog id reserved for AccessTrace jobs — stays stable so repeat
# starts kick the same slot. 0x414353 = 'ACS' (AccessTrace),
# high enough to avoid clashing with lab-tooling choices.
_ATJOB_WDG_ID = 0x4154_4341   # 'ATCA'


def _symbolize_batcher(ctx, view: str, pid: int):
    """Build an awaitable ``(rips) -> {rip: symbol-rec}`` batcher using
    F1's ``_lookup_batch_core`` — matches the plan's "batch of 32 RIPs
    or 100 ms" contract.
    """
    async def _call(rips):
        if not rips:
            return {}
        try:
            # Local import — avoids a cycle when access_trace.py is
            # imported before tools.symbols.
            from ..symbols import _lookup_batch_core
        except Exception:
            return {}
        try:
            return await _lookup_batch_core(ctx, view=view, pid=int(pid),
                                             vas=[int(r) for r in rips])
        except Exception:
            return {}
    return _call


async def _watchdog_kick_start(ctx, c, job_id: str) -> None:
    """Register a 10 s watchdog kick on the AccessTrace slot so the
    DR auto-releases if the orchestrator crashes."""
    try:
        if not hasattr(c, "watchdog_arm"):
            return
        # Arm (deadline 60 s, cookie derived from job_id) + fire the
        # background kicker at 10 s cadence.
        wid = _ATJOB_WDG_ID
        try:
            cookie = int(job_id[2:], 10)
        except ValueError:
            cookie = 0
        arm = await c.watchdog_arm(
            wid, deadline_ms=60_000,
            bugcheck_code=0, flags=1, cookie=cookie,
            label=f"accesstrace:{job_id}")
        if not arm.get("ok"):
            return
        async def _kick():
            try:
                while True:
                    await asyncio.sleep(10.0)
                    try:
                        await c.watchdog_kick(wid, deadline_ms=60_000,
                                              cookie=cookie)
                    except Exception:
                        continue
            except asyncio.CancelledError:
                raise
        # Stash the kicker task on the job row so stop() can cancel it.
        job = _ATJOBS.get(job_id)
        if job is not None:
            job["_watchdog_task"] = asyncio.create_task(
                _kick(), name=f"at-watchdog-{job_id}")
    except Exception:
        # Watchdog is advisory — never fail the job start over it.
        pass


async def _watchdog_kick_stop(c, job: dict) -> None:
    t = job.pop("_watchdog_task", None)
    if t is not None and not t.done():
        t.cancel()
        try:
            await asyncio.wait_for(t, timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    try:
        if hasattr(c, "watchdog_disarm"):
            await c.watchdog_disarm(_ATJOB_WDG_ID)
    except Exception:
        pass


def _env(job: dict) -> dict:
    """Public projection used by ``status`` / ``list``."""
    return {
        "job_id": job["job_id"],
        "state": job["state"],
        "driver_used": job["driver_used"],
        "started_at": job["started_ts"],
        "finished_at": job.get("finished_ts"),
        "hits_so_far": int(job.get("hits_so_far") or 0),
        "kernel_dropped": int(job.get("kernel_dropped") or 0),
        "kernel_missed": int(job.get("kernel_missed") or 0),
        "ring_truncated": bool(job.get("ring_truncated")),
        "last_hit_ts": job.get("last_hit_ts") or 0.0,
        "elapsed_ms": int((time.time() - job["started_ts"]) * 1000),
    }


def _resolve_driver(ctx, pid: int, driver_req: str, view: str) -> str:
    """Resolve ``driver='auto'`` to a concrete choice.

    ``watchhw`` wins when ``security.allow_hw_bp_hook=True`` AND the
    agent client exposes ``bp_hw_watch_add``; otherwise ``dbgeng``.
    The explicit kwarg always wins — ``watchhw`` with the flag off
    is refused by ``assert_allowed`` in session/core and surfaces as
    a ``kind='hw_bp_hook_disabled'`` envelope.
    """
    if driver_req in ("watchhw", "dbgeng"):
        return driver_req
    # auto path
    cfg = getattr(ctx, "cfg", None)
    sec = getattr(cfg, "security", None) if cfg else None
    hook_ok = bool(getattr(sec, "allow_hw_bp_hook", False))
    if not hook_ok:
        return "dbgeng"
    try:
        c = ctx.session.require_client(view) if view else None
    except Exception:
        c = None
    if c is None or not hasattr(c, "bp_hw_watch_add"):
        return "dbgeng"
    return "watchhw"


async def at_start(ctx, *, c, view: str, owner: str, name: str,
                    pid: int, address: int, size: int, access: str,
                    tid: int, driver: str, max_hits: int,
                    symbolize: bool, disasm: bool, stackwalk: bool,
                    timeout_s: int, redact_regs: bool) -> dict[str, Any]:
    """``access_trace_start``. Allocates a job row, spawns the driver
    task, kicks the watchdog, returns ``{job_id, driver_used, ...}``.

    This function is reachable only after ``_guard`` has run
    ``assert_allowed`` (session/core gates the watchhw driver on
    ``allow_hw_bp_hook`` + ``min_trust_actuator``).
    """
    if not pid or not address:
        return {"ok": False, "kind": "bad_arg",
                "error": "access_trace_start requires pid= and address="}
    if int(size) not in (1, 2, 4, 8):
        return {"ok": False, "kind": "bad_arg",
                "error": "access_trace_start: size must be 1, 2, 4, or 8",
                "hint": "DRs only encode those widths; split wider ranges"}
    acc = (access or "rw").lower()
    if acc not in ("write", "rw", "read"):
        return {"ok": False, "kind": "bad_arg",
                "error": f"access must be write|rw|read (got {access!r})"}
    if acc == "read":
        acc = "rw"  # Intel DRs can't observe reads alone.
    driver_used = _resolve_driver(ctx, int(pid), (driver or "auto").lower(),
                                   view=view)
    # Preflight the watchhw gate so the caller sees ``kind='hw_bp_hook_disabled'``
    # verbatim (the session/core gate is the hard refuse; here we surface
    # the typed envelope directly so tests don't need to decode the
    # generic "error" shape).
    hook_ok = bool(getattr(getattr(ctx, "cfg", None), "security", None)
                    and getattr(ctx.cfg.security, "allow_hw_bp_hook", False))
    if driver_used == "watchhw" and not hook_ok:
        return {"ok": False, "kind": "hw_bp_hook_disabled",
                "error": ("access_trace_start with driver='watchhw' requires "
                          "security.allow_hw_bp_hook=true (the int1-hook-backed "
                          "HW watchpoint is PatchGuard-sensitive, lab-only)"),
                "hint": ("pass driver='dbgeng' for the fallback path, or "
                         "enable security.allow_hw_bp_hook in the orchestrator "
                         "config once the agent + driver are known-good")}

    _ATJOB_SEQ[0] += 1
    job_id = f"at{_ATJOB_SEQ[0]:04d}"
    started_ts = time.time()
    job: dict[str, Any] = {
        "job_id": job_id,
        "state": "running",
        "driver_used": driver_used,
        "owner": owner,
        "view": view,
        "started_ts": started_ts,
        "finished_ts": None,
        "hits": [],
        "hits_so_far": 0,
        "kernel_dropped": 0,
        "kernel_missed": 0,
        "ring_truncated": False,
        "last_hit_ts": 0.0,
        "ring_cap": _ATJOB_RING_CAP,
        "redact_regs": bool(redact_regs),
        "params": {
            "pid": int(pid), "address": int(address),
            "size": int(size), "access": acc, "tid": int(tid),
            "max_hits": int(max_hits), "symbolize": bool(symbolize),
            "disasm": bool(disasm), "stackwalk": bool(stackwalk),
            "timeout_s": int(timeout_s or 300),
        },
        "task": None,
        "arm_result": None,
    }
    _ATJOBS[job_id] = job
    # Trim registry if we'd blow the cap.
    while len(_ATJOBS) > _ATJOB_CAP:
        oldest_id, oldest = next(iter(_ATJOBS.items()))
        if oldest.get("state") == "running":
            break  # never evict a running job
        _ATJOBS.pop(oldest_id, None)

    job_ctx = WatchhwJobCtx(
        pid=int(pid), tid=int(tid), address=int(address),
        size=int(size), access=acc, max_hits=int(max_hits),
        disasm=bool(disasm), stackwalk=bool(stackwalk),
        symbolize=bool(symbolize), timeout_s=int(timeout_s or 300),
        symbolize_batch=_symbolize_batcher(ctx, view=view, pid=int(pid))
                        if symbolize else None,
    )

    async def _run():
        try:
            if driver_used == "watchhw":
                r = await run_watchhw_driver(
                    ctx=ctx, client=c, job=job, job_ctx=job_ctx,
                    symbolize_batch=job_ctx.symbolize_batch)
            else:
                r = await run_dbgeng_driver(
                    ctx=ctx, client=c, job=job, job_ctx=job_ctx,
                    symbolize_batch=job_ctx.symbolize_batch)
            job["arm_result"] = r
            if job["state"] == "running":
                job["state"] = "ready" if r.get("ok") else "error"
                if not r.get("ok"):
                    job["error"] = r.get("error") or ""
        except asyncio.CancelledError:
            job["state"] = "cancelled"
            raise
        except Exception as exc:  # noqa: BLE001
            job["state"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            job["finished_ts"] = time.time()
            try:
                await _watchdog_kick_stop(c, job)
            except Exception:
                pass

    job["task"] = asyncio.create_task(_run(), name=f"pry-at-{job_id}")
    # Kick the watchdog AFTER the task is live, so a crash before the
    # DR is armed still rings the slot (the watchdog's goal is a dead
    # DR after our death, not a dead DR inside a race window).
    await _watchdog_kick_start(ctx, c, job_id)
    # Give the driver a tick to report its arm result before we return
    # (so the envelope can carry watch_cookie / bp_id / slot /
    # hvci_fallback — plan §4 wants them in the start envelope).
    for _ in range(50):
        if job.get("arm_result") is not None:
            break
        if job["state"] != "running":
            break
        await asyncio.sleep(0.01)
    arm = job.get("arm_result") or {}
    env = {"ok": True, "job_id": job_id, "driver_used": driver_used,
           "state": job["state"],
           "hint": ("poll with debug_manage(action='access_trace_status', "
                    f"job_id='{job_id}') or stop with "
                    f"action='access_trace_stop'")}
    if arm.get("ok") is False:
        env["ok"] = False
        env["kind"] = arm.get("kind") or "arm_failed"
        env["error"] = arm.get("error")
    if "watch_cookie" in arm:
        env["watch_cookie"] = int(arm.get("watch_cookie") or 0)
    if "bp_id" in arm:
        env["bp_id"] = int(arm.get("bp_id") or 0)
    if "slot" in arm:
        env["slot"] = int(arm.get("slot") or 0xFF)
    if "hvci_fallback" in arm:
        env["hvci_fallback"] = bool(arm.get("hvci_fallback"))
    # Plan §4 asks for threads_patched for the dbgeng path — not all
    # agent builds compute it, so default to 0 when the driver didn't
    # report it.
    env["threads_patched"] = int(arm.get("threads_patched") or 0)
    return env


def at_status(*, job_id: str, limit: int, offset: int,
               verbosity: str, redact_regs: bool) -> dict[str, Any]:
    """``access_trace_status``. Pure read; never mutates the job."""
    if not job_id:
        return {"ok": False, "kind": "bad_arg",
                "error": "access_trace_status requires job_id="}
    job = _ATJOBS.get(job_id)
    if job is None:
        return {"ok": False, "kind": "unknown_job",
                "error": f"job_id {job_id!r} not found",
                "hint": "debug_manage(action='access_trace_list') to see jobs"}
    out = _env(job)
    out["ok"] = True
    hits = list(job.get("hits") or [])
    eff_offset = max(0, int(offset or 0))
    # ``limit=0`` surfaces the whole buffer; mirrors scripts.py.
    eff_limit = int(limit or 0)
    sliced = hits[eff_offset:eff_offset + eff_limit] if eff_limit > 0 else hits[eff_offset:]
    # Redact unless the caller opted out (verbosity='full' AND passed
    # redact_regs=False explicitly). The default is ALWAYS to redact.
    effective_redact = bool(redact_regs) if redact_regs is not None else True
    # The job was created with a redact_regs setting; honor that too so
    # a mid-poll flip doesn't suddenly leak the ring.
    job_default = bool(job.get("redact_regs", True))
    effective_redact = effective_redact and job_default
    out["hits"] = [apply_hit_redaction(h, verbosity=verbosity,
                                        redact=effective_redact)
                   for h in sliced]
    out["returned"] = len(out["hits"])
    out["total_in_ring"] = len(hits)
    return out


async def at_cancel(ctx, *, c, job_id: str) -> dict[str, Any]:
    """``access_trace_stop``. Cancels the driver task, which triggers
    the driver's own ``finally`` disarm path; also disarms the watchdog.
    """
    if not job_id:
        return {"ok": False, "kind": "bad_arg",
                "error": "access_trace_stop requires job_id="}
    job = _ATJOBS.get(job_id)
    if job is None:
        return {"ok": False, "kind": "unknown_job",
                "error": f"job_id {job_id!r} not found"}
    if job["state"] in ("ready", "error", "cancelled"):
        return {"ok": True, "job_id": job_id, "state": job["state"],
                "note": "already finished"}
    task = job.get("task")
    if task is not None and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    job["state"] = "cancelled"
    await _watchdog_kick_stop(c, job)
    return {"ok": True, "job_id": job_id, "state": "cancelled"}


def at_jobs() -> dict[str, Any]:
    """``access_trace_list``. Mirrors ``script_manage.jobs`` output."""
    rows = [_env(j) for j in reversed(_ATJOBS.values())]
    return {"ok": True, "count": len(rows), "jobs": rows}


# Test helpers ------------------------------------------------------
# These never ship as MCP verbs; the unit tests reach in and set up /
# tear down the registry directly.

def _reset_for_tests() -> None:
    _ATJOBS.clear()
    _ATJOB_SEQ[0] = 0


def _get_job_for_tests(job_id: str) -> dict | None:
    return _ATJOBS.get(job_id)
