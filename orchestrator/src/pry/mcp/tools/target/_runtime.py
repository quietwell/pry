"""Target-package runtime helpers — monitor cadences, watchdog auto-arm,
and the shared boot-monitor wiring.

These helpers used to live at module scope in ``tools/target.py`` as free
functions callable from ``register()``'s closures. R6 lifts them out so
they're testable in isolation and reused across the verb modules.

Zero behavior change: every function body is the pre-R6 implementation,
imports moved to this module's scope. ``_maybe_start_boot_monitor``
remains the single wire-up point for the session boot monitor and still
captures its callbacks via local ``async def``.
"""

from __future__ import annotations

from typing import Any


def _monitor_poll_s(ctx) -> float:
    """Boot-monitor poll interval.

    WP3 owns ``config.py`` — when a ``monitor.boot_poll_s`` section lands
    it's honored; absent config degrades to the spec default of 5 s
    (default ON — silent BSODs are the pain point being fixed). An
    explicit ``0``/negative is the documented disable.
    """
    mon = getattr(ctx.cfg, "monitor", None)
    if mon is None:
        return 5.0
    try:
        return float(getattr(mon, "boot_poll_s", 5.0))
    except (TypeError, ValueError):
        return 5.0


def _monitor_scan_idle_s(ctx) -> float:
    """Idle cadence for the folded-in minidump-dir watch (60 s default;
    too chatty to run every tick)."""
    mon = getattr(ctx.cfg, "monitor", None)
    try:
        v = float(getattr(mon, "dump_scan_idle_s", 60.0)) if mon else 60.0
    except (TypeError, ValueError):
        return 60.0
    return v if v > 0 else 60.0


def _auto_arm_cfg_status(ctx) -> dict[str, Any]:
    """``watchdog.auto_arm`` config status, for responses that touch the
    auto-arm seam — the hook is config-gated and silent otherwise, so
    callers can tell "protected" from "nobody configured it"."""
    wdg = getattr(ctx.cfg, "watchdog", None)
    spec = (getattr(wdg, "auto_arm", None) or {}) \
        if wdg is not None else {}
    if not spec or not (spec.get("id") or 0):
        return {
            "configured": False,
            "note": "watchdog.auto_arm is UNCONFIGURED — no automatic "
                    "re-arm across driver_load/reboot. Set [watchdog."
                    "auto_arm] {id, deadline_ms, interval_ms} in config.",
        }
    return {
        "configured": True,
        "id": int(spec.get("id") or 0),
        "deadline_ms": int(spec.get("deadline_ms") or 45000),
        "interval_ms": int(spec.get("interval_ms") or 10000),
        "label": str(spec.get("label") or "auto_arm"),
    }


async def _auto_arm_after_load(ctx, client, view: str) -> dict | None:
    """WP3 seam — ``snapshot.auto_arm_after_load(ctx, client, view)``.

    WP1 inserts the call sites per the _shared.md contract (watchdog
    auto-arm after driver_load, plus the post-reboot reconnect path
    where the driver survived); when WP3's snapshot module hasn't landed
    yet — or lacks the hook — the call is a silent no-op. Errors are
    swallowed: re-arming must never fail the driver_load that just
    succeeded. Returns the hook's result dict (or None) so callers can
    surface what happened in their response.
    """
    try:
        from ... import snapshot as _snapshot
    except ImportError:
        return None
    fn = getattr(_snapshot, "auto_arm_after_load", None)
    if fn is None:
        return None
    try:
        res = fn(ctx, client, view)
        import inspect as _inspect
        if _inspect.isawaitable(res):
            res = await res
        return res if isinstance(res, dict) else None
    except Exception:  # noqa: BLE001 — best-effort hook
        return None


async def _monitor_pull_minidump(ctx, view: str, *,
                                 boot_epoch_ms: int = 0) -> dict | None:
    """Best-effort pull+parse of the newest target minidump — shared by
    the boot monitor's on_change/on_scan hooks and the connect path.

    Returns the parse dict (with ``source``), or None when no dump exists
    or the pull failed. Also re-seeds the dir-watch's seen-set from the
    ListDir result so a just-pulled dump doesn't re-notify on the next
    idle scan.
    """
    client = ctx.session.clients.get(view)
    if client is None:
        return None
    try:
        from .. import dump as _dump
        got = await _dump._latest_minidump(ctx, client)
        if got is None:
            return None
        entries = got.pop("entries", None) or []
        ctx.session._dump_seen.setdefault(view, set()).update(
            str(e.get("name") or "") for e in entries)
        res = await _dump._parse_artifact(
            ctx, client, got["local_path"],
            boot_epoch_ms=int(boot_epoch_ms or 0))
        res["source"] = {k: got[k] for k in
                         ("remote_path", "local_path", "name",
                          "mtime_unix", "size", "dir")}
        return res
    except Exception:  # noqa: BLE001 — monitor work is best-effort
        return None


def _park_minidump_notice(ctx, view: str, res: dict, *, source: str) -> None:
    """Attach a parsed-dump result to the view's parked boot notice, or
    park a standalone ``kind:"minidump"`` notice when none exists — the
    next status()/wait_boot_change call drains it."""
    pending = ctx.session.pending_boot_notices.get(view)
    if pending is not None:
        pending["minidump"] = res
    else:
        # No ``kind`` field on purpose: boot-change notices discriminate
        # on it; the ``minidump`` key alone marks this as a dump notice.
        ctx.session.pending_boot_notices[view] = {
            "view": view, "source": source, "minidump": res}


def _maybe_start_boot_monitor(ctx, view: str) -> None:
    """Wire the session boot monitor for ``view`` (idempotent) with the
    WP1 hooks: state sweep + parked notice on boot change, opportunistic
    minidump pull, and the ~60 s idle dir-watch."""
    async def _on_change(name: str, change: dict) -> None:
        try:
            change["swept"] = await ctx.sweep_view_state(name)
        except Exception:  # noqa: BLE001 — sweep is best-effort here
            pass
        if change.get("kind") == "new_boot":
            # A service-loaded driver survived the reboot — WP3's hook
            # re-arms watchdog.auto_arm when it reports loaded; a no-op
            # otherwise (absent driver / unconfigured).
            await _auto_arm_after_load(
                ctx, ctx.session.clients.get(name), name)
        res = await _monitor_pull_minidump(
            ctx, name,
            boot_epoch_ms=int(change.get("boot_epoch_ms") or 0))
        if res is not None:
            change["minidump"] = res

    async def _on_scan(name: str, boot_epoch_ms: int) -> None:
        client = ctx.session.clients.get(name)
        if client is None:
            return
        from .. import dump as _dump
        dumps = await _dump._list_dumps(client)
        if not dumps:
            return
        seen = ctx.session._dump_seen.setdefault(name, set())
        if not seen:
            # First scan after monitor start — seed without notifying;
            # the dumps may be ancient history.
            seen.update(str(e.get("name") or "") for e in dumps)
            return
        fresh = [e for e in dumps
                 if str(e.get("name") or "") not in seen
                 and (not boot_epoch_ms
                      or int(e.get("mtime_unix") or 0) * 1000
                      >= boot_epoch_ms)]
        seen.update(str(e.get("name") or "") for e in dumps)
        if not fresh:
            return
        res = await _monitor_pull_minidump(
            ctx, name, boot_epoch_ms=boot_epoch_ms)
        if res is not None:
            _park_minidump_notice(ctx, name, res, source="boot_monitor")

    ctx.session.start_boot_monitor(
        view, _monitor_poll_s(ctx), on_change=_on_change,
        on_scan=_on_scan, scan_idle_s=_monitor_scan_idle_s(ctx))


__all__ = [
    "_monitor_poll_s",
    "_monitor_scan_idle_s",
    "_auto_arm_cfg_status",
    "_auto_arm_after_load",
    "_monitor_pull_minidump",
    "_park_minidump_notice",
    "_maybe_start_boot_monitor",
]
