"""Driver-state preflight + driver_load/unload status merge.

``_require_driver`` returns an error envelope dict when the kernel
driver isn't up; ``_merge_driver_state`` follows a driver_load /
driver_unload RPC with one ``status()`` probe and merges the result
into the response so callers don't need a second round-trip.
"""

from __future__ import annotations

from ..._error_enrich import enrich_error as _enrich_error


async def _merge_driver_state(ctx, result: dict, verb: str,
                              view: str = "") -> dict:
    """after driver_load / driver_unload, follow up with one status()
    probe and merge driver_state / driver_present / driver_version into the
    response envelope so callers don't need a second round-trip to know
    whether the SCM operation actually took effect.

    The status probe is best-effort: if it fails we still return the RPC's
    result unchanged. Failures at this layer would just mean an extra
    status call for the caller — we don't want to mask the load/unload
    result behind a status-probe error.
    """
    if not isinstance(result, dict):
        return result
    try:
        client = ctx.session.require_client(view)
    except Exception:
        return result
    try:
        st = await client.status()
    except Exception as exc:
        result.setdefault("driver_state_probe_error", f"{type(exc).__name__}: {exc}")
        return result
    driver_state = st.get("driver_state")
    if driver_state is not None:
        result.setdefault("driver_state", driver_state)
    ds_upper = str(driver_state or "").upper()
    driver_present = ds_upper in ("LOADED", "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED",
                                   "SERVICE", "MANUAL_MAPPED")
    result.setdefault("driver_present", driver_present)
    if "driver_version" in st:
        result.setdefault("driver_version", st.get("driver_version"))
    if "service_state" in st:
        result.setdefault("service_state", st.get("service_state"))
    result.setdefault("verb", verb)
    return result


async def _require_driver(ctx, tool: str, action: str,
                          name: str = "") -> dict | None:
    """Preflight check for actions that need the kernel driver loaded.

    Returns an error envelope dict (to be _j()'d and returned) if the driver
    isn't up; returns None to signal "OK to proceed". Every driver-dependent
    action calls this as its first line so the LLM gets a clean, actionable
    error instead of a deep gRPC failure."""
    try:
        c = ctx.session.require_client(name) if name else ctx.session.require_client()
    except Exception as exc:
        return {"ok": False, **_enrich_error(tool, action, f"no target connected: {exc}"),
                "kind": "no_target",
                "hint": "run target_manage(action='connect') first"}
    try:
        st = await c.status()
    except Exception as exc:
        return {"ok": False, **_enrich_error(tool, action, str(exc)),
                "kind": "status_probe_failed",
                "hint": "check target_manage(action='status')"}
    ds = str(st.get("driver_state", ""))
    # driver_state is a string on the LLM side; the driver-absent
    # envelope wraps each flag as {value, confidence, source}. Accept both
    # legacy scalars and the new envelope shape.
    if ds and ds not in ("loaded", "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED"):
        driver_present = bool(st.get("driver_present", False))
        if not driver_present:
            return {"ok": False,
                    "error": f"{tool} {action}: driver not loaded on target (state={ds!r})",
                    "kind": "driver_absent",
                    "hint": "run target_manage(action='driver_load') and retry; "
                            "check target_manage(action='status') to confirm "
                            "driver_state == 'loaded'",
                    "tool": tool, "action": action}
    return None


__all__ = [
    "_merge_driver_state",
    "_require_driver",
]
