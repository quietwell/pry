"""``target_manage`` timeline verbs — ``timeline``, ``recent_ops``,
``recent_ops_agent``.

``timeline`` is the merged view: boot identity, agent
restarts, watchdog arms/fires, recent ops ring, crash state, and fresh
minidumps in one chronological reel. The persistent on-disk op log is
reachable through ``recent_ops(persistent=True)``.
"""

from __future__ import annotations

from typing import Any

from ..common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)


async def do_timeline(ctx, *, name: str, since_iso: str, until_iso: str,
                      samples: int) -> str:
    # merged chronological view of a target
    # that stitches together the pieces already recorded
    # elsewhere — boot identity, agent restarts, watchdog
    # arms/fires, recent orchestrator ops, crash state, and
    # fresh minidumps. Windowed by since_iso/until_iso when
    # the caller passes them; defaults to the current ring.
    import datetime as _dt
    try:
        view = ctx.session.resolve_view_name(name) if name \
            else ctx.session.primary
    except Exception:
        view = ctx.session.primary
    events: list[dict[str, Any]] = []

    def _parse_iso(s: str) -> float:
        if not s:
            return 0.0
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return _dt.datetime.fromisoformat(s).timestamp()
        except Exception:
            return 0.0
    lo = _parse_iso(since_iso)
    hi = _parse_iso(until_iso)

    def _in_window(ts: float) -> bool:
        if lo and ts < lo:
            return False
        if hi and ts > hi:
            return False
        return True
    # Boot identity (last-seen only — no persistent ring yet)
    bid = ctx.session.boot_identity(view)
    if bid:
        boot_ms = int(bid.get("boot_epoch_ms") or 0)
        boot_ts = boot_ms / 1000.0 if boot_ms else 0.0
        if _in_window(boot_ts) or not boot_ts:
            events.append({
                "ts": boot_ts,
                "kind": "boot_identity",
                "view": view,
                "boot_epoch_ms": boot_ms,
                "agent_instance_id": bid.get("agent_instance_id"),
            })
    # Recent orchestrator ops (ring).
    for call in list(ctx.session.tool_log)[-200:]:
        ts = float(call.ts or 0)
        if not _in_window(ts):
            continue
        events.append({
            "ts": ts,
            "kind": "op",
            "tool": call.tool,
            "action": call.action,
            "ok": call.ok,
            "destructive": call.destructive,
            "error": call.error if not call.ok else "",
        })
    # Watchdog state (live).
    try:
        client = ctx.session.clients.get(view)
        if client is not None:
            listing = await client.watchdog_list()
            rows = listing.get("entries", []) \
                if isinstance(listing, dict) else (listing or [])
            for r in rows or []:
                events.append({
                    "ts": 0.0,  # driver side; no epoch
                    "kind": "watchdog_armed",
                    "id": r.get("id"),
                    "deadline_ms": r.get("deadline_ms"),
                    "label": r.get("label"),
                })
    except Exception:  # noqa: BLE001 — watchdog list best-effort
        pass
    # Pending boot notice (parked by boot monitor).
    pending = ctx.session.pending_boot_notices.get(view)
    if pending:
        boot_ms = int(pending.get("boot_epoch_ms") or 0)
        events.append({
            "ts": boot_ms / 1000.0 if boot_ms else 0.0,
            "kind": "boot_notice",
            "notice": dict(pending),
        })
    # Sort newest-first, cap.
    events.sort(key=lambda e: float(e.get("ts") or 0),
                reverse=True)
    cap = int(samples) if samples else 100
    events = events[:cap]
    return _j({
        "ok": True,
        "action": "timeline",
        "view": view,
        "since_iso": since_iso,
        "until_iso": until_iso,
        "count": len(events),
        "events": events,
        "hint": ("timeline merges boot_identity, orchestrator "
                 "op log, watchdog state, and pending boot "
                 "notices. Use target_manage(action="
                 "'crash_state') for full post-crash detail."),
    })


async def do_recent_ops(ctx, *, name: str, samples: int, persistent: bool,
                        op_method: str, op_owner: str,
                        since_iso: str, until_iso: str) -> str:
    # persistent=True routes the query to the
    # on-disk JSONL sink so callers can reconstruct the
    # tool history across orchestrator restarts and
    # per-client ring wipes. `op_method` / `op_owner` /
    # since_iso / until_iso filter; `samples` caps rows.
    if persistent:
        from ....audit import query as _audit_query
        limit = int(samples or 500)
        if limit <= 0:
            limit = 500
        rows = _audit_query(
            session_id=ctx.session.audit_session_id(),
            owner=op_owner or None,
            method=op_method or None,
            since_iso=since_iso or None,
            until_iso=until_iso or None,
            limit=limit,
        )
        return _j({"ok": True, "persistent": True,
                    "session_id": ctx.session.audit_session_id(),
                    "count": len(rows),
                    "ops": rows})
    # Post-crash forensics: what did the orchestrator send to
    # the agent right before it wedged? Doesn't require the
    # agent to be reachable now.
    client = ctx.session.get_client(name) if hasattr(
        ctx.session, "get_client") else None
    if client is None:
        try:
            client = ctx.session.require_client(name)
        except Exception:
            client = None
    # Fall back to the primary target when name isn't connected
    # (so 'recent_ops' answers even mid-outage on the alias).
    if client is None:
        for view in ctx.session.clients.values() if hasattr(
                ctx.session, "clients") else []:
            client = view
            break
    if client is None:
        return _j({"ok": False,
                   "error": "no client instance available; "
                            "the ring is per-client. Try after a connect."})
    return _j({"target": getattr(client, "endpoint", "?"),
               "ops": client.recent_ops(samples or 32)})


async def do_recent_ops_agent(ctx, *, name: str, samples: int) -> str:
    # Persistent breadcrumb on the target's disk. Survives an
    # agent crash — `prior.status_kind == "wedged"` marks the
    # calls in flight when the previous lifetime died.
    view = ctx.session.resolve_view_name(name)
    try:
        client = ctx.session.require_client(view)
    except Exception as exc:
        return _j({"ok": False, "error": str(exc)})
    return _j(await client.recent_ops_agent(
        limit=samples or 32, include_prior=True))
