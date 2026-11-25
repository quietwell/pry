"""``target_manage`` connect-family verbs — ``use``, ``connect``,
``disconnect``, ``reconnect``.

``connect`` carries the heavy lifting: v14 boot-change detection + sweep,
watchdog auto-arm hook, best-effort minidump pull, machine_info banner,
and the self-healing observed_endpoints update that lets a
DHCP-flapped box reconnect without an explicit ``host=``.

``reconnect`` tears down the gRPC channel + preserves co-owner refs so
other peers keep their references through the swap. PR#2 T1.1b lets the
caller push ``hosts=``/``cidr=`` into observed_endpoints before the fresh
connect fan-out so a box that moved outside the known set is still
reachable.
"""

from __future__ import annotations

from typing import Any

from ..common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)
from ....session import VIEW_KINDS

from ._plumbing import (
    _attach_machine_info,
    _auto_prepare,
    _compact_connect_status,
    _expand_cidr,
    _filter_allowed,
    _resolve_port,
)
from ._runtime import (
    _auto_arm_after_load,
    _maybe_start_boot_monitor,
    _monitor_pull_minidump,
    _park_minidump_notice,
)


async def do_use(ctx, *, machine: str, name: str) -> str:
    # Per-chat focus: bare/empty name= selectors on later calls
    # resolve to this machine. 'none'/'off'/'clear' drops it.
    cid = current_client_id()
    sel = (machine or name or "").strip()
    if sel.lower() in ("none", "off", "clear"):
        return _j({"ok": True, "focus": None,
                   "cleared": ctx.session.clear_focus(cid)})
    try:
        # this used to assign to a local
        # named `focus`, which shadowed the connect-path's
        # focus= parameter in the enclosing scope. Rename to
        # keep run()'s closures to the kwarg clean.
        focus_info = ctx.session.set_focus(cid, sel)
    except RuntimeError as exc:
        return _j({"ok": False, "kind": "bad_target",
                   "error": str(exc)})
    # set_focus's dict already carries machine/kind/view plus
    # the machine_label fields (computer_name, endpoint).
    return _j({"ok": True, "client_id": cid,
               "focus": focus_info,
               "computer_name": focus_info.get("computer_name", ""),
               "hint": ("bare/empty name= selectors now resolve "
                        "to this machine; target_manage(action="
                        "'use', machine='none') clears")})


async def do_connect(ctx, *, machine: str, name: str, views: str,
                      host: str, port: int, token: str, method: str,
                      force: bool, focus: bool, verbose: bool,
                      auto_prepare: bool) -> str:
    cid = current_client_id()

    async def _connect_one(sel: str) -> dict:
        """One view connect + post-connect bookkeeping. The
        stored key (``status['view']``) is '<machine>.<kind>' —
        *sel* is only the requested selector."""
        # connect() resolves the endpoint via target_for +
        # check_target internally now.
        status = await ctx.session.connect(
            host or None, port or None, token or None,
            name=sel, machine=machine or None,
            owner=cid, force=bool(force),
            focus=bool(focus))
        view = status.get("view") or sel
        status["resolved_address"] = getattr(
            ctx.session.clients.get(view), "endpoint", "")
        status["target_name"] = sel
        # v14: connect is where a post-reboot reconnect lands —
        # sweep the orphaned follows/shells/handles the moment
        # the boot change is confirmed, same as the status path.
        # T1.3 (PR#2): first_connect is a classification, not
        # a change — never sweeps and never warns.
        change = status.get("boot_change")
        if change and change.get("kind") in (
                "new_boot", "agent_restart"):
            status["swept"] = await ctx.sweep_view_state(
                change.get("view") or view)
            status["warnings"] = [
                f"view {view!r}: "
                f"{change['kind'].replace('_', ' ')} detected — "
                "stale shells/follows/watchdog arms/detached "
                "handles were swept; resX artifacts predate "
                "this boot." +
                (" Reload the driver before kernel ops."
                 if change["kind"] == "new_boot" else "")]
        if change and change.get("kind") == "new_boot":
            # _shared contract: a service-loaded driver survives
            # the reboot the caller just reconnected through —
            # WP3's hook re-arms watchdog.auto_arm when the
            # driver reports loaded. No-op when the driver is
            # absent or auto_arm is unconfigured.
            await _auto_arm_after_load(
                ctx, ctx.session.clients.get(view), view)
        # every connected view gets its own debug-event pump and
        # boot monitor (they used to start for the primary view only, so a
        # second machine's reboot / debug events went unnoticed). Both are
        # idempotent per view and run in a fresh context, not as this chat.
        ctx.start_event_pump(view)
        # timely reboot detection — the status
        # poll inside the monitor makes a silent BSOD
        # surface as a parked new_boot notice on the next
        # status call, instead of waiting for someone to
        # notice lazily.
        _maybe_start_boot_monitor(ctx, view)
        if change and change.get("kind") in (
                "new_boot", "agent_restart"):
            # The connect path just saw the reboot — the
            # monitor (just started) won't re-fire for an
            # identity it already recorded, so kick the
            # best-effort minidump pull here; the parse parks
            # as a pending notice and the next status() drains it.
            async def _pull() -> None:
                res = await _monitor_pull_minidump(
                    ctx, view,
                    boot_epoch_ms=int(
                        change.get("boot_epoch_ms") or 0))
                if res is not None:
                    _park_minidump_notice(ctx, view, res,
                                          source="connect")
            try:
                from ....caller import spawn_background
                spawn_background(_pull(), name=f"pry-dumppull-{view}",
                                 owner="orchestrator:minidump")
            except Exception:  # noqa: BLE001 — best-effort
                pass
        if ctx.clients is not None:
            await ctx.clients.register(cid, transport="http")
            await ctx.clients.refcount_add(cid, view)
        if not ctx.get_current_session_id(cid):
            ctx.set_current_session_id(
                cid, ctx.ledger.start_session(
                    ctx.session.cfg.target_endpoint))
        # self-heal — the endpoint that
        # just answered is now registry-known for this machine,
        # and every IPv4 the agent sees on an up-adapter joins
        # it (so a flap to another lease self-heals in one
        # step). YAML aliases participate (observed_endpoints
        # is pure learned metadata, never overrides reviewed
        # endpoints).
        try:
            ep = str(status.get("resolved_address") or "")
            mlabel = ctx.session.machine_of(view)
            boot_ms = int(status.get("boot_epoch_ms") or 0)
            ep_p = 0
            if ":" in ep:
                eh, ep_s = ep.rsplit(":", 1)
                try:
                    ep_p = int(ep_s)
                except ValueError:
                    ep_p = 0
                if eh and ep_p:
                    # PR#8: operator explicitly minted this
                    # alias via connect(machine=...), so
                    # allow_create=True.
                    ctx.registry.record_observed_endpoint(
                        mlabel, host=eh, port=ep_p,
                        boot_epoch_ms=boot_ms,
                        allow_create=True)
            # If the agent reports an ipv4[] list on Status,
            # record every live address under the same port.
            for a in (status.get("ipv4") or []):
                if isinstance(a, dict) and a.get("up") \
                        and a.get("address"):
                    # PR#8: ride along with the explicit
                    # mint from the resolved_address above.
                    ctx.registry.record_observed_endpoint(
                        mlabel, host=str(a["address"]),
                        port=ep_p or 0,
                        boot_epoch_ms=boot_ms,
                        allow_create=True)
            # DHCP self-heal: remember who this machine is, so a later
            # connect can refuse a *different* box that inherited one of its
            # old addresses. Write-once, and only learned from endpoints we
            # trust to be the right machine — one the operator typed, a
            # fresh phone-home beacon, or a label that is the machine's own
            # name — never from a remembered/stale address.
            cn = str(status.get("computer_name") or "")
            src = str(status.get("endpoint_source") or "")
            if cn and (src in ("explicit", "beacon")
                       or cn.lower() == mlabel.lower()):
                ctx.registry.learn_computer_name(mlabel, cn)
        except Exception:  # noqa: BLE001 — self-heal is best-effort
            pass
        return status

    sel = (machine or name or "").strip()
    views_l = (views or "").strip().lower()
    if views_l in ("both", "all"):
        # Fan out over every view kind; a kind whose endpoint
        # can't be resolved (KeyError) is skipped, not fatal.
        out: dict[str, Any] = {"ok": True, "views": {}}
        for kind in VIEW_KINDS:
            try:
                vst = await _connect_one(
                    f"{sel}.{kind}" if sel else kind)
                # T2.1 (PR#2): compact per sub-view unless
                # verbose=True. machine_info rides on the
                # parent dict, not per sub-view (unchanged).
                out["views"][kind] = (
                    vst if verbose
                    else _compact_connect_status(vst))
                if "machine_info" not in out:
                    mi = _attach_machine_info(
                        ctx, cid, str(vst.get("view") or ""))
                    if mi:
                        out["machine_info"] = mi
            except KeyError as exc:
                out["views"][kind] = {"ok": False,
                                      "skipped": True,
                                      "error": str(exc)}
            except Exception as exc:  # noqa: BLE001 — per-view
                out["ok"] = False
                out["views"][kind] = {"ok": False,
                                      "error": str(exc)}
        # T2.7 (PR#2): auto_prepare on 'both' applies to the
        # kernel view (where driver_load belongs).
        if auto_prepare and out.get("ok"):
            prep = await _auto_prepare(
                ctx, cid, machine=sel,
                view=out["views"].get("kernel", {}).get("view") or "",
                method=method, verbose=verbose)
            out["auto_prepare"] = prep
        return _j(out)
    kind = views_l if views_l in VIEW_KINDS else ""
    status = await _connect_one(
        f"{sel}.{kind}" if sel and kind else sel or kind)
    mi = _attach_machine_info(ctx, cid, str(status.get("view") or ""))
    if mi:
        status["machine_info"] = mi
    # T2.1 (PR#2): compact connect response is the new default.
    # verbose=True returns the pre-T2.1 dict exactly.
    if verbose:
        out_payload: dict = dict(status)
    else:
        out_payload = _compact_connect_status(status)
        if "machine_info" in status:
            out_payload["machine_info"] = status["machine_info"]
    if auto_prepare and out_payload.get("ok"):
        prep = await _auto_prepare(
            ctx, cid,
            machine=(sel or ctx.session.machine_of(
                str(status.get("view") or ""))),
            view=str(status.get("view") or ""),
            method=method, verbose=verbose)
        return _j({"ok": True, "action": "connect",
                   "connect": out_payload,
                   "use": prep.get("use"),
                   "driver_load": prep.get("driver_load")})
    return _j(out_payload)


async def do_disconnect(ctx, *, name: str) -> str:
    cid = current_client_id()
    # Empty name keeps the historical 'release every view I
    # hold' behavior; a selector resolves to its view key.
    result = await ctx.session.disconnect(
        ctx.session.resolve_view_name(name) if name else None,
        owner=cid)
    if ctx.clients is not None:
        for n in list(result.get("disconnected", [])) + \
                 list(result.get("partial_release", [])):
            await ctx.clients.refcount_remove(cid, n)
    return _j(result)


async def do_reconnect(ctx, *, name: str, host: str, port: int,
                        token: str, hosts: list[str] | None,
                        cidr: str) -> str:
    # replace a wedged / stale client for a view
    # without going through the disconnect → connect dance
    # (which drops all co-owner refs). The current endpoint +
    # co-owner refcounts are preserved; the gRPC channel is
    # torn down and a fresh AgentClient is built.
    #
    # Anything in flight on the old channel is cancelled by
    # ``close()`` — a caller should wait for its prior call
    # to error out before invoking reconnect.
    cid = current_client_id()
    view = ctx.session.resolve_view_name(name)
    old_client = ctx.session.clients.get(view)
    if old_client is None:
        return _j({"ok": False,
                   "kind": "no_target",
                   "error": (f"reconnect: view {view!r} is "
                             "not currently connected"),
                   "hint": (f"call target_manage(action="
                            f"'connect', name={view!r}) first")})
    # Preserve endpoint + co-owner refs so the fresh client
    # points at the same target and other peers keep their
    # references. host/port/token defaults fall back to
    # config via Session.connect().
    endpoint = getattr(old_client, "endpoint", "") or ""
    r_host, r_port = "", 0
    if ":" in endpoint:
        try:
            r_host, port_s = endpoint.rsplit(":", 1)
            r_port = int(port_s)
        except ValueError:
            r_host, r_port = "", 0
    old_refs = dict(ctx.session.refs.get(view, {}))
    # PR#2 T1.1b: let the caller push extra candidate hosts
    # (and a cidr) into the registry's observed-endpoint
    # list *before* Session.connect fans out, so a
    # DHCP-flapped box that moved outside the known set is
    # reachable without an explicit `host=`.
    r_mlabel = ctx.session.machine_of(view)
    extra_hosts: list[str] = []
    for h in (hosts or []):
        s = str(h or "").strip()
        if s and s not in extra_hosts:
            extra_hosts.append(s)
    cidr_hosts, cidr_err = _expand_cidr(cidr)
    if cidr_err:
        return _j({"ok": False, "kind": "cidr_too_broad",
                   "action": "reconnect",
                   "view": view,
                   "error": cidr_err})
    extra_hosts.extend(h for h in cidr_hosts
                        if h not in extra_hosts)
    # operator-supplied candidates go through the allowlist before
    # they are recorded as observed endpoints (and later dialed).
    extra_hosts, extra_refused = await _filter_allowed(ctx, extra_hosts)
    r_port_eff = _resolve_port(
        r_mlabel, ctx.session.cfg, ctx.registry,
        explicit=(port or r_port) or None)
    for eh in extra_hosts:
        try:
            # PR#8: reconnect(hosts=/cidr=) is operator-
            # supplied candidate priority — mint if needed.
            ctx.registry.record_observed_endpoint(
                r_mlabel, host=eh, port=r_port_eff,
                allow_create=True)
        except Exception:  # noqa: BLE001
            pass
    # Tear down: close the channel + drop bookkeeping.
    try:
        await old_client.close()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass
    ctx.session.clients.pop(view, None)
    ctx.session.owners.pop(view, None)
    ctx.session.refs.pop(view, None)
    # Fresh connect for the current owner. The token is always
    # a string (never None): a learned-label machine has no
    # config TargetConfig for connect()'s `t.token` fallback
    # to dereference, and the old client's token is the one
    # that was actually in effect.
    auto_expanded_cidr = ""
    try:
        new_status = await ctx.session.connect(
            (host or r_host) or None,
            (port or r_port) or None,
            token or getattr(old_client, "token", "") or "",
            name=view,
            owner=cid,
            force=False,
        )
    except OSError as _rc_exc:
        # PR#2 T1.1b: when the candidate set couldn't reach
        # anything, auto-expand to /24 of last-known-good
        # and retry once with a 5s/host budget. Logs the
        # expansion so operators can trace the recovery.
        import ipaddress as _ip
        last_good = ""
        try:
            last_good = ctx.session._last_good_host.get(
                r_mlabel, "") or r_host or ""
        except Exception:
            last_good = r_host or ""
        if not last_good:
            raise
        try:
            base = _ip.IPv4Address(last_good)
            net = _ip.IPv4Network(f"{base}/24", strict=False)
        except (ValueError, _ip.AddressValueError):
            raise _rc_exc from None
        auto_expanded_cidr = str(net)
        log.info(
            "reconnect: candidate set exhausted; auto-"
            "expanding to %s (last_good=%s)",
            auto_expanded_cidr, last_good)
        # the /24 sweep is filtered through the CIDR allowlist —
        # the last-good host's neighbours are not automatically lab boxes.
        expanded, _refused = await _filter_allowed(
            ctx, [str(h) for h in net.hosts()])
        if not expanded:
            raise _rc_exc
        probed = await __import__(
            "pry.session", fromlist=["probe_hosts_concurrent"]
        ).probe_hosts_concurrent(
            expanded, r_port_eff, timeout_s=5.0, limit=32)
        live = [h for h, _p, ok, _lat in probed if ok]
        for lh in live:
            try:
                # PR#8: /24 auto-expand is a passive scan
                # after a failed reconnect — allow_create
                # stays False so a scan can't mint a shell
                # for an unknown alias.
                ctx.registry.record_observed_endpoint(
                    r_mlabel, host=lh, port=r_port_eff,
                    allow_create=False)
            except Exception:  # noqa: BLE001
                pass
        if not live:
            raise _rc_exc
        # Retry the connect once; Session.connect will see
        # the newly recorded observed_endpoints.
        new_status = await ctx.session.connect(
            None, (port or r_port) or None,
            token or getattr(old_client, "token", "") or "",
            name=view,
            owner=cid,
            force=False,
        )
    # Preserve co-owner refs — a peer that held a ref before
    # reconnect keeps it; only its next call sees the new
    # channel. This is by design: a peer that had a live
    # co-lease shouldn't get a spurious "not connected"
    # error just because someone else pressed reconnect.
    refs = ctx.session.refs.setdefault(view, {})
    for owner_id, count in old_refs.items():
        if owner_id == cid:
            continue
        refs[owner_id] = count
    # v14: a reconnect across a reboot carries the boot_change
    # marker in new_status — sweep now, while the caller still
    # expects churn, rather than on the next status call.
    # T1.3 (PR#2): first_connect is a classification — only
    # new_boot/agent_restart are real changes.
    change = new_status.get("boot_change")
    real_change = (change is not None
                   and change.get("kind") in ("new_boot",
                                               "agent_restart"))
    swept = None
    if real_change:
        swept = await ctx.sweep_view_state(view)
    data = {"action": "reconnect", "view": view,
            "reconnected": True,
            "endpoint": getattr(
                ctx.session.clients.get(view), "endpoint", ""),
            "coowner_refs": {o: c for o, c in old_refs.items()
                              if o != cid},
            "status": new_status}
    if swept is not None:
        data["swept"] = swept
    if auto_expanded_cidr:
        data["auto_expanded_cidr"] = auto_expanded_cidr
    if extra_refused:
        data["refused_hosts"] = extra_refused
    mi = _attach_machine_info(ctx, cid, view)
    if mi:
        data["machine_info"] = mi
    env = _envelope_ok(
        data,
        kind=_resolve_kind("target_manage", "reconnect"),
        tool="target_manage",
        action="reconnect",
    )
    from ..._envelope import warn as _envelope_warn
    _envelope_warn(env,
        f"target_manage(reconnect): view {view!r} was torn "
        f"down and re-established; anything in flight on the "
        "old channel was cancelled. Co-owner refcounts "
        "preserved.")
    if auto_expanded_cidr:
        _envelope_warn(env,
            f"reconnect auto-expanded to {auto_expanded_cidr} "
            "after the known candidate set exhausted; a live "
            "host was found and recorded in observed_endpoints.")
    if real_change:
        _envelope_warn(env,
            f"view {view!r}: {change['kind'].replace('_', ' ')} "
            "detected — shells/follows/watchdog arms/detached "
            "handles from the previous lifetime are dead" +
            ("; reload the driver before kernel ops."
             if change["kind"] == "new_boot" else "."))
    return _j(env)
