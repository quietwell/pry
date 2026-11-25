"""``target_manage`` peer verbs — ``list_peers``, ``release_peer``,
``subscribe_peers``.

MCP tool responses can't stream; ``subscribe_peers`` returns a
point-in-time snapshot and the dashboard SSE feed carries the live
peer/lease stream.
"""

from __future__ import annotations

from ..common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)


async def do_whoami(ctx) -> str:
    cid = current_client_id()
    return _j({"ok": True, "client_id": cid,
               "focus": ctx.session.focus_of(cid)})


async def do_list_peers(ctx) -> str:
    if ctx.clients is None:
        return _j({"ok": True, "peers": []})
    peers = await ctx.clients.list_peers()
    # surface the session-ledger refs next to the
    # registry's connected_views — when the two disagree,
    # driver_unload busy-blocks are diagnosable from list_peers
    # alone instead of "it just says busy".
    session_refs = ctx.session.refs
    for row in peers:
        pid_ = row.get("client_id")
        row["session_view_refs"] = {
            v: n for v, owners in session_refs.items()
            if (n := owners.get(pid_, 0)) > 0}
        row["focus"] = ctx.session.focus_of(pid_)
    return _j({"ok": True, "peers": peers})


async def do_release_peer(ctx, *, peer_id: str, force: bool) -> str:
    if not peer_id:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "release_peer: peer_id is required",
                   "hint": "target_manage(action='list_peers') to "
                           "enumerate active peers"})
    # self-release is always allowed. The `force=true`
    # gate exists to stop a peer from kicking ANOTHER peer by
    # accident; it never needed to guard your own id. Without
    # this relaxation the only recovery path from a self-leaked
    # lease (e.g. a timed-out debug_attach — see B11) was to
    # pass force=true to a verb whose own error text said the
    # flag only exists for "another peer's" leases, which read
    # as a missing feature rather than the intended usage.
    self_release = (peer_id == current_client_id())
    if not force and not self_release:
        return _j({"ok": False, "kind": "confirm_required",
                   "error": "release_peer: pass force=true to release "
                            "another peer's leases and view refs",
                   "peer_id": peer_id})
    released_leases: list[str] = []
    if ctx.leases is not None:
        released_leases = await ctx.leases.release_by_owner(peer_id)
    released_views = await ctx.session.release_by_owner(peer_id)
    return _j({"ok": True, "peer_id": peer_id,
               "released_leases": released_leases,
               "released_views": released_views,
               "hint": "the ClientRegistry entry is left in place; "
                        "the idle reaper will drop it once its "
                        "last_op ages out"})


async def do_subscribe_peers(ctx) -> str:
    # MCP tool responses can't stream; return a point-in-time
    # snapshot. Live SSE lives on the dashboard.
    peers = await ctx.clients.list_peers() if ctx.clients is not None else []
    for row in peers:
        row["focus"] = ctx.session.focus_of(
            row.get("client_id"))
    leases = ctx.leases.snapshot() if ctx.leases is not None else {}
    return _j({"ok": True, "peers": peers, "leases": leases,
               "hint": "snapshot only; wire the dashboard SSE "
                        "feed for live join/leave/lease events"})
