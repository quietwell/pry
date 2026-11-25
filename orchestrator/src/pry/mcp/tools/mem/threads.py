"""``threads`` verb body (NtQSI system-wide per-thread inventory).

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.

Eight opt-in enrichment columns via the new
``ThreadInspect`` service. Each ``include_<field>=True`` kwarg fans out
one additional RPC per row through ``asyncio.gather`` with a 16-way
concurrency cap. The base response shape stays bit-identical to the original
when every include flag is off — see slice doc §Feature 4.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.envelope import _list_envelope
from .._runtime.response import _j, _j_hex


# --------------------------------------------------------------------------
# Opt-in column fan-out
# --------------------------------------------------------------------------

# Column name -> (client method name, driver-sourced?).
# Driver-sourced columns live behind the ``ThreadInspect.WaitInfo`` /
# ``ThreadInspect.IrpList`` RPCs; umagent-only ones ride direct Win32.
_OPTIN_COLUMNS: dict[str, tuple[str, bool]] = {
    # Driver-sourced (share one WAIT_INFO RPC in principle; here each
    # include flag names the column that lands in the row).
    "last_syscall":       ("thread_wait_info", True),
    "kernel_stack_usage": ("thread_wait_info", True),
    "pending_irp":        ("thread_irp_list", True),
    # Umagent-only (direct Win32).
    "impersonation":      ("thread_impersonation", False),
    "com_apartment":      ("thread_com_apartment", False),
    "rpc_usage":          ("thread_rpc_usage", False),
    "power_throttling":   ("thread_power_throttling", False),
    "fiber":              ("thread_fiber", False),
}


def _degrade_sentinel(error: str) -> dict[str, Any]:
    """Build a ``{"error": "..."}`` sentinel for a column that didn't
    populate. Keys stay slice-doc-compatible so the operator eyeballs
    one shape across all columns."""
    return {"error": error}


def _column_from_waitinfo(column: str, res: dict[str, Any]) -> dict[str, Any] | None:
    if not res.get("ok"):
        err = (res.get("error") or res.get("kind") or "").lower()
        if "wave_3_pending" in err or err == "wave_3_pending":
            return _degrade_sentinel("wave_3_pending")
        if "no_driver" in err or err == "no_driver":
            return _degrade_sentinel("no_driver")
        if "no_thread" in err:
            return _degrade_sentinel("no_thread")
        if "access_denied" in err:
            return _degrade_sentinel("access_denied")
        if err:
            return _degrade_sentinel(err)
        return _degrade_sentinel("unknown")
    if column == "last_syscall":
        return {
            "number": int(res.get("last_syscall_number") or 0),
            "name": res.get("last_syscall_name") or "",
            "status_hex": res.get("last_syscall_status_hex") or "",
        }
    if column == "kernel_stack_usage":
        return {
            "base_hex": int(res.get("kernel_stack_base_hex") or 0),
            "limit_hex": int(res.get("kernel_stack_limit") or 0),
            "rsp_hex": int(res.get("kernel_stack_rsp") or 0),
            "excursion": int(res.get("kernel_stack_excursion") or 0),
            "max_excursion": 0,
        }
    return None


def _column_from_irp(res: dict[str, Any]) -> dict[str, Any] | None:
    if not res.get("ok"):
        err = (res.get("error") or res.get("kind") or "").lower()
        for key in ("wave_3_pending", "no_driver", "no_thread",
                    "access_denied"):
            if key in err or err == key:
                return _degrade_sentinel(key)
        return _degrade_sentinel(err or "unknown")
    return {
        "pending": bool(res.get("pending")),
        "irp_count": int(res.get("irp_count") or 0),
        "irps": list(res.get("irps") or []),
    }


def _column_from_impersonation(res: dict[str, Any]) -> dict[str, Any]:
    if not res.get("ok"):
        err = (res.get("error") or res.get("kind") or "").lower()
        if "no_thread" in err:
            return _degrade_sentinel("no_thread")
        if "access_denied" in err:
            return {"present": None, "error": "access_denied"}
        if "not_supported" in err:
            return _degrade_sentinel("not_supported")
        return _degrade_sentinel(err or "unknown")
    return {
        "present": bool(res.get("present")),
        "user": res.get("user") or "",
        "level": res.get("level") or "",
        "is_self": bool(res.get("is_self")),
        "sid": res.get("sid") or "",
    }


def _column_from_com(res: dict[str, Any]) -> dict[str, Any]:
    if not res.get("ok"):
        err = (res.get("error") or res.get("kind") or "").lower()
        for key in ("no_thread", "no_teb", "not_supported"):
            if key in err or err == key:
                return _degrade_sentinel(key)
        return _degrade_sentinel(err or "unknown")
    return {
        "type": res.get("type") or "none",
        "flags": list(res.get("flags") or []),
        "teb_rfo_hex": int(res.get("teb_rfo") or 0),
    }


def _column_from_rpc(res: dict[str, Any]) -> dict[str, Any]:
    if not res.get("ok"):
        err = (res.get("error") or res.get("kind") or "").lower()
        if "wct_timeout" in err or err == "wct_timeout":
            return {"error": "wct_timeout"}
        if "no_thread" in err:
            return _degrade_sentinel("no_thread")
        if "not_supported" in err:
            return _degrade_sentinel("not_supported")
        return _degrade_sentinel(err or "unknown")
    return {
        "in_rpc_call": bool(res.get("in_rpc_call")),
        "server": res.get("server") or "",
        "chain_length": int(res.get("chain_length") or 0),
    }


def _column_from_power(res: dict[str, Any]) -> dict[str, Any]:
    if not res.get("ok"):
        err = (res.get("error") or res.get("kind") or "").lower()
        for key in ("no_thread", "not_supported"):
            if key in err or err == key:
                return _degrade_sentinel(key)
        return _degrade_sentinel(err or "unknown")
    return {
        "control_mask_hex": int(res.get("control_mask") or 0),
        "state_mask_hex": int(res.get("state_mask") or 0),
    }


def _column_from_fiber(res: dict[str, Any]) -> bool | dict[str, Any]:
    if not res.get("ok"):
        err = (res.get("error") or res.get("kind") or "").lower()
        for key in ("no_thread", "no_teb", "not_supported"):
            if key in err or err == key:
                return _degrade_sentinel(key)
        return _degrade_sentinel(err or "unknown")
    return bool(res.get("has_fiber_data"))


async def _enrich_one_row(c, row: dict[str, Any], flags: dict[str, bool],
                            sem: asyncio.Semaphore) -> dict[str, Any]:
    tid = int(row.get("tid") or 0)
    if tid <= 0:
        return row
    row = dict(row)
    async with sem:
        waitinfo_res: dict[str, Any] | None = None
        if flags.get("last_syscall") or flags.get("kernel_stack_usage"):
            waitinfo_res = await c.thread_wait_info(tid)
        if flags.get("last_syscall"):
            row["last_syscall"] = _column_from_waitinfo("last_syscall",
                                                         waitinfo_res or {})
        if flags.get("kernel_stack_usage"):
            row["kernel_stack"] = _column_from_waitinfo(
                "kernel_stack_usage", waitinfo_res or {})
        if flags.get("pending_irp"):
            irp = await c.thread_irp_list(tid)
            row["pending_irp"] = _column_from_irp(irp)
        if flags.get("impersonation"):
            imp = await c.thread_impersonation(tid)
            row["impersonation"] = _column_from_impersonation(imp)
        if flags.get("com_apartment"):
            com = await c.thread_com_apartment(tid)
            row["com_apartment"] = _column_from_com(com)
        if flags.get("rpc_usage"):
            rpc = await c.thread_rpc_usage(tid)
            row["rpc_usage"] = _column_from_rpc(rpc)
        if flags.get("power_throttling"):
            pow_ = await c.thread_power_throttling(tid)
            row["power_throttling"] = _column_from_power(pow_)
        if flags.get("fiber"):
            fib = await c.thread_fiber(tid)
            row["fiber"] = _column_from_fiber(fib)
    return row


async def _enrich_rows(c, rows: list[dict[str, Any]],
                        flags: dict[str, bool],
                        concurrency: int = 16) -> list[dict[str, Any]]:
    if not any(flags.values()):
        return rows
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    tasks = [_enrich_one_row(c, r, flags, sem) for r in rows]
    return list(await asyncio.gather(*tasks))


async def handle_threads(ctx, c, *, pid: int, kernel: bool,
                         with_context: bool, filter: Any,
                         summary: bool, fields: list[str] | None,
                         limit: int, offset: int,
                         max_results: int,
                         # opt-in columns:
                         include_last_syscall: bool = False,
                         include_kernel_stack_usage: bool = False,
                         include_pending_irp: bool = False,
                         include_impersonation: bool = False,
                         include_com_apartment: bool = False,
                         include_rpc_usage: bool = False,
                         include_power_throttling: bool = False,
                         include_fiber: bool = False) -> str:
    try:
        res = await c.thread_list(pid=pid, kernel=kernel,
                                  with_context=with_context)
    except Exception as exc:
        msg = str(exc)
        if "UNIMPLEMENTED" in msg:
            return _j({"ok": False, "kind": "agent_version",
                       "error": ("threads: agent < v11 "
                                 "(Memory.ThreadList missing)"),
                       "hint": ("rebuild + redeploy the agent "
                                "(scripts/update_target.py "
                                "--component agent)")})
        return _j({"ok": False, "kind": "thread_enum_failed",
                   "error": msg})
    if not res.get("ok"):
        return _j({"ok": False, "kind": "thread_enum_failed",
                   "error": res.get("error",
                                    "thread list failed")})
    rows = res.get("threads", [])
    # Module attribution: flag start VAs outside every loaded
    # module (the injected-thread *sense* — a fact, not a
    # verdict). Kernel list for kernel threads, the pid's user
    # list otherwise.
    mods = []
    try:
        mods = await c.mem_modules(pid, True)
    except Exception:
        mods = []
    ranges = []
    for m in mods or []:
        try:
            b = int(m.get("base", 0) or 0)
            z = int(m.get("size", 0) or 0)
            if b and z:
                ranges.append((b, b + z, str(m.get("name", ""))))
        except Exception:
            continue
    for r in rows:
        sv = int(r.get("start_va", 0) or 0)
        hit = next(((lo, hi, nm) for lo, hi, nm in ranges
                    if lo <= sv < hi), None)
        r["in_module"] = hit is not None
        if hit:
            r["module"] = hit[2]

    include_flags: dict[str, bool] = {
        "last_syscall": bool(include_last_syscall),
        "kernel_stack_usage": bool(include_kernel_stack_usage),
        "pending_irp": bool(include_pending_irp),
        "impersonation": bool(include_impersonation),
        "com_apartment": bool(include_com_apartment),
        "rpc_usage": bool(include_rpc_usage),
        "power_throttling": bool(include_power_throttling),
        "fiber": bool(include_fiber),
    }
    rows = await _enrich_rows(c, rows, include_flags, concurrency=16)

    cov_limits: list[str] = []
    if res.get("truncated"):
        cov_limits.append("provider_truncated")
    # Partial coverage marker: at least one enrichment degraded on at
    # least one row. We walk the enriched rows once to find any
    # ``error`` sentinels under a known column key.
    if any(include_flags.values()):
        reasons: set[str] = set()
        for r in rows:
            for col in ("last_syscall", "kernel_stack", "pending_irp",
                        "impersonation", "com_apartment", "rpc_usage",
                        "power_throttling", "fiber"):
                v = r.get(col)
                if isinstance(v, dict) and v.get("error"):
                    reasons.add(str(v["error"]))
        for key in sorted(reasons):
            # Keep the coverage limits terse — slice doc §Edge cases
            # names the canonical reasons.
            if key in {"wave_3_pending", "no_driver", "no_thread",
                        "access_denied", "wct_timeout", "no_teb",
                        "not_supported"}:
                cov_limits.append(key)
            else:
                cov_limits.append("partial")
    extras = {"source": res.get("source", "agent"),
              "truncated": res.get("truncated", False),
              "note": ("start_va outside every loaded module "
                       "is the injected-thread shape — an "
                       "observation, not a verdict")}
    enabled = [k for k, v in include_flags.items() if v]
    if enabled:
        extras["include_columns"] = enabled

    env = _list_envelope(
        rows, tool="memory_manage", action="threads",
        limit=limit or max_results, offset=offset,
        fields=fields or (),
        filter=filter if isinstance(filter, str) else "",
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras=extras,
    )
    scope = "thread-columns" if any(include_flags.values()) else "enumeration"
    status = "partial" if cov_limits else "complete"
    if scope == "enumeration" and not res.get("truncated"):
        status = "complete"
    env["coverage"] = _coverage(scope, status, *cov_limits)
    return _j_hex(env)
