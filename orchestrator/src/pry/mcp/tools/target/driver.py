"""``target_manage`` driver verbs — ``driver_load``, ``driver_unload``.

Both are destructive, lease-gated when ``ctx.leases`` is wired, and go
through ``_merge_driver_state`` so the merged driver_state reflects
agent reality before replying. On successful load the shared watchdog
auto-arm hook (``_auto_arm_after_load``) fires once; the
``_dedupe_watchdog_unconfigured`` quiets repeated UNCONFIGURED hints.
"""

from __future__ import annotations

from ..common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)

from ._plumbing import _dedupe_watchdog_unconfigured
from ._runtime import _auto_arm_after_load, _auto_arm_cfg_status


async def do_driver_load(ctx, *, name: str, method: str, verbose: bool) -> str:
    cid = current_client_id()
    view = ctx.session.resolve_view_name(name)
    if ctx.leases is None:
        result = await ctx.session.require_client(view).driver_load(method=method)
        merged = await _merge_driver_state(ctx, result, verb="driver_load",
                                           view=view)
        if merged.get("ok") is not False:
            # _shared contract: WP3's watchdog auto-arm hook.
            arm = await _auto_arm_after_load(
                ctx, ctx.session.clients.get(view),
                view)
            arm_info = (arm if arm is not None
                        else _auto_arm_cfg_status(ctx))
            # T2.7 (PR#2): quiet the UNCONFIGURED hint on
            # repeated loads of the same machine unless
            # verbose=True.
            merged["watchdog_auto_arm"] = \
                _dedupe_watchdog_unconfigured(
                    ctx, ctx.session.machine_of(view),
                    arm_info, verbose)
        return _j(merged)
    wait_s = getattr(ctx.cfg.leases, "driver_timeout_s", 10.0)
    lease = await ctx.leases.acquire("driver", cid, wait_s=wait_s)
    if isinstance(lease, BusyInfo):
        return _j({"ok": False, "kind": "busy",
                   "error": f"driver_load: lease held by {lease.held_by}",
                   "held_by": lease.held_by,
                   "since_iso": lease.since_iso,
                   "waited_s": lease.waited_s,
                   "hint": "another peer is currently loading/unloading "
                           "the driver; retry, or use target_manage(action="
                           "'list_peers') to see who holds it"})
    try:
        result = await ctx.session.require_client(view).driver_load(method=method)
        merged = await _merge_driver_state(ctx, result, verb="driver_load",
                                           view=view)
        if merged.get("ok") is not False:
            arm = await _auto_arm_after_load(
                ctx, ctx.session.clients.get(view),
                view)
            arm_info = (arm if arm is not None
                        else _auto_arm_cfg_status(ctx))
            # T2.7 (PR#2): dedupe UNCONFIGURED hint.
            merged["watchdog_auto_arm"] = \
                _dedupe_watchdog_unconfigured(
                    ctx, ctx.session.machine_of(view),
                    arm_info, verbose)
        return _j(merged)
    finally:
        await ctx.leases.release(lease)


async def do_selfprot_config(ctx, *, name: str, enable: int, flags: int,
                             process_access_keep: int, thread_access_keep: int,
                             protected_pids: list[int] | None,
                             disable_token: int) -> str:
    """target_manage(action='selfprot_config') — install/refresh/disable the
    driver's ObRegisterCallbacks pre-op. See SI #21."""
    view = ctx.session.resolve_view_name(name)
    client = ctx.session.require_client(view)
    pids = [int(p) for p in (protected_pids or []) if int(p) > 0]
    result = await client.selfprot_config(
        enable=int(enable), flags=int(flags),
        process_access_keep=int(process_access_keep),
        thread_access_keep=int(thread_access_keep),
        protected_pids=pids,
        disable_token=int(disable_token))
    return _j(result)


async def do_selfprot_status(ctx, *, name: str) -> str:
    view = ctx.session.resolve_view_name(name)
    return _j(await ctx.session.require_client(view).selfprot_status())


async def do_driver_unload(ctx, *, name: str, force: bool) -> str:
    cid = current_client_id()
    view = ctx.session.resolve_view_name(name)
    refs = ctx.session.refs.get(view, {})
    other_owners = [o for o in refs if o != cid]
    # session.refs and the ClientRegistry can disagree
    # (crashed peer, release_peer leftover) — a peer the
    # registry shows as user-view-only (umagent) must not block
    # a driver unload. Cross-check every ref-holder against
    # the live registry before refusing.
    blocking: list[str] = []
    stale_refs: list[str] = []
    peer_holds: dict[str, dict] = {}
    for o in other_owners:
        info = (await ctx.clients.get(o)
                if ctx.clients is not None else None)
        view_n = int(info.refs.get(view, 0)) if info else 0
        attach = sorted(p for v, p in (info.held_attach or set())
                        if v == view) if info else []
        if view_n > 0 or attach:
            blocking.append(o)
            peer_holds[o] = {
                "view_refs": view_n,
                "held_attach_pids": attach,
            }
        else:
            stale_refs.append(o)
    if blocking and not force:
        return _j({"ok": False, "kind": "busy",
                   "error": "driver_unload: kernel view still in use "
                            "by other peers",
                   "in_use_by": blocking,
                   "held_by": peer_holds,
                   "stale_refs_ignored": stale_refs,
                   "hint": "wait for peers to disconnect, or pass "
                           "force=true to override (they will lose "
                           "the kernel view on the next call)"})
    for o in stale_refs:
        # Registry agrees the peer is gone — drop the dead ref so
        # session.refs stops blocking future unloads.
        ctx.session.drop_view_ref(view, o)
    if stale_refs and not blocking:
        log.info("driver_unload: pruned stale kernel-view refs "
                 "from %s (registry shows no kernel view)",
                 stale_refs)
    if ctx.leases is None:
        result = await ctx.session.require_client(view).driver_unload()
        return _j(await _merge_driver_state(ctx, result, verb="driver_unload",
                                            view=view))
    wait_s = getattr(ctx.cfg.leases, "driver_timeout_s", 10.0)
    lease = await ctx.leases.acquire("driver", cid, wait_s=wait_s)
    if isinstance(lease, BusyInfo):
        return _j({"ok": False, "kind": "busy",
                   "error": f"driver_unload: lease held by {lease.held_by}",
                   "held_by": lease.held_by,
                   "since_iso": lease.since_iso,
                   "waited_s": lease.waited_s,
                   "hint": "another peer is currently loading/unloading "
                           "the driver; retry, or use target_manage(action="
                           "'list_peers') to see who holds it"})
    try:
        result = await ctx.session.require_client(view).driver_unload()
        return _j(await _merge_driver_state(ctx, result, verb="driver_unload",
                                            view=view))
    finally:
        await ctx.leases.release(lease)
