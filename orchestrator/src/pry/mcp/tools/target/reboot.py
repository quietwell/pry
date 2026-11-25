"""``target_manage`` wait verbs — ``wait_connectable``,
``wait_boot_change``, ``wait_agent``.

These are the post-reboot/post-driver_load pollers. All three use the
same bounded backoff (0.3-0.5 s initial, ramping to 3 s). ``AgentClient``
is looked up from the dispatcher's module namespace at call time so
tests that monkey-patch ``pry.mcp.tools.target.AgentClient`` reach
the probe clients built here.
"""

from __future__ import annotations

from ..common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)

from ._plumbing import _check_allowed, _expand_cidr, _resolve_port


def _lookup_agent_client():
    """Resolve the AgentClient factory from ``target`` (the package
    __init__.py) at call time so tests that patch
    ``pry.mcp.tools.target.AgentClient`` see the replacement."""
    from . import AgentClient  # late-bound; respects test patches
    return AgentClient


async def do_wait_connectable(ctx, *, name: str, host: str, port: int,
                              token: str, timeout_s: float,
                              hosts: list[str] | None, cidr: str) -> str:
    # poll a TCP handshake + gRPC status roundtrip
    # until the deadline, using bounded exponential backoff.
    # Distinct from action="connect" (which fails hard on the
    # first probe): wait_connectable is what you call after
    # `driver_load` or an agent restart when the target is
    # expected to come up but not there yet.
    # PR#2 T1.1b: hosts/cidr widen the TCP side of the probe
    # — the first host that answers wins; the gRPC status
    # roundtrip then runs against that winner.
    import time as _t
    from ....session import _probe_tcp
    from ....session import probe_hosts_concurrent as _probe_many
    # name= picks the configured view endpoint ('lab2' ->
    # 'lab2.kernel'); an explicit host/port path is untouched.
    view = ctx.session.resolve_view_name(name) if name else ""
    try:
        t = ctx.session.cfg.target_for(view or None)
    except KeyError:
        # Learned/raw view with no config entry — fall back to
        # the primary target's endpoint defaults.
        t = ctx.session.cfg.target_for(None)
    probe_host = host or t.host
    probe_port = int(port or t.port)
    probe_token = token if token else t.token
    # PR#2 T1.1b: build the extended candidate list once.
    extra_hosts: list[str] = []
    # The configured host goes stale when the VM moves by DHCP; prefer the
    # address the view is (or was last) actually using and keep the
    # configured one as a fallback candidate.
    if not host and view:
        live = ""
        cl = ctx.session.clients.get(view)
        ep = str(getattr(cl, "endpoint", "") or "") if cl is not None else ""
        if ep:
            live = ep.rpartition(":")[0]
        if not live:
            try:
                label = ctx.session.machine_of(view)
            except Exception:  # noqa: BLE001
                label = ""
            live = str(getattr(ctx.session, "_last_good_host", {})
                       .get(label or "", "") or "")
        if live and live != probe_host:
            # Range mode probes only extra_hosts, so list both, live first.
            extra_hosts.extend(h for h in (live, probe_host) if h)
            probe_host = live
    for h in (hosts or []):
        s = str(h or "").strip()
        if s and s not in extra_hosts:
            extra_hosts.append(s)
    cidr_hosts, cidr_err = _expand_cidr(cidr)
    if cidr_err:
        return _j({"ok": False, "kind": "cidr_too_broad",
                   "action": "wait_connectable",
                   "error": cidr_err})
    extra_hosts.extend(h for h in cidr_hosts
                        if h not in extra_hosts)
    range_mode = bool(extra_hosts)
    # Validate allowlist before any network activity; this raises
    # TargetNotAllowedError which the guard maps. Names are
    # resolved off the loop, every address must be allowed, and the
    # checked IP literal is what gets dialed.
    if range_mode:
        extra_hosts = list(dict.fromkeys(
            [await _check_allowed(ctx, cand) for cand in extra_hosts]))
    else:
        probe_host = await _check_allowed(ctx, probe_host)
    deadline_s = float(timeout_s) if timeout_s and timeout_s > 0 else 15.0
    mcp_deadline_note = (
        f"timeout_s={deadline_s:g} exceeds ~60s — the MCP "
        "host's own request deadline usually kills the call "
        "first (error -32001); prefer timeout_s<=60 and "
        "re-call in a loop"
        if deadline_s > 60 else "")
    deadline = _t.monotonic() + deadline_s
    delay = 0.3
    attempts = 0
    last_err: str = ""
    last_kind: str = ""
    started = _t.monotonic()
    AgentClient = _lookup_agent_client()
    while _t.monotonic() < deadline:
        attempts += 1
        remaining = max(0.0, deadline - _t.monotonic())
        probe_budget = min(2.0, remaining) if remaining > 0 else 0.2
        winner_host: str = ""
        if range_mode:
            probed = await _probe_many(
                extra_hosts, probe_port,
                timeout_s=probe_budget, limit=16)
            for h, _p, ok, _lat in probed:
                if ok:
                    winner_host = h
                    break
            if not winner_host:
                last_err = (f"no TCP answer from "
                            f"{len(extra_hosts)} candidate(s)")
                last_kind = "connect_timeout"
        else:
            try:
                await _probe_tcp(probe_host, probe_port,
                                  timeout_s=probe_budget)
                winner_host = probe_host
            except OSError as exc:
                last_err = str(exc)
                _kind, _hint = _classify(str(exc))
                last_kind = _kind
        if winner_host:
            # TCP up — attempt a real gRPC status roundtrip
            # so a listening-but-broken agent still fails the
            # readiness check.
            probe_client = AgentClient(
                winner_host, probe_port, probe_token,
                t.connect_timeout_ms, max_inflight=t.max_inflight)
            try:
                await probe_client.connect()
                st = await probe_client.status()
                await probe_client.close()
                elapsed_s = round(_t.monotonic() - started, 3)
                ok_out = {
                    "ok": True,
                    "action": "wait_connectable",
                    "view": view or PRIMARY_TARGET,
                    "endpoint": f"{winner_host}:{probe_port}",
                    "attempts": attempts,
                    "elapsed_s": elapsed_s,
                    "status": st,
                }
                if range_mode:
                    ok_out["winner_host"] = winner_host
                if mcp_deadline_note:
                    ok_out["note"] = mcp_deadline_note
                return _j(ok_out)
            except Exception as exc:  # noqa: BLE001 - polled retry
                last_err = str(exc)
                _kind, _hint = _classify(str(exc))
                last_kind = _kind
                try:
                    await probe_client.close()
                except Exception:  # noqa: BLE001 - best-effort close
                    pass
        remaining = deadline - _t.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(delay, max(0.05, remaining)))
        delay = min(delay * 1.7, 3.0)
    elapsed_s = round(_t.monotonic() - started, 3)
    timeout_out = {
        "ok": False,
        "action": "wait_connectable",
        "view": view or PRIMARY_TARGET,
        "endpoint": f"{probe_host}:{probe_port}",
        "attempts": attempts,
        "elapsed_s": elapsed_s,
        "kind": "wait_timeout",
        "error": (
            f"wait_connectable timed out after {attempts} "
            f"attempt(s) over {elapsed_s}s: {last_err or 'no probe attempted'}"
        ),
        "last_probe_kind": last_kind or "unknown",
        "hint": (
            "target still not reachable; check the agent service, "
            "network reachability, and firewall — the last probe "
            f"classified as {last_kind or 'unknown'}. "
            "See _error_enrich HINT_RULES for the net-layer "
            "classifier docs."
        ),
    }
    if mcp_deadline_note:
        timeout_out["note"] = mcp_deadline_note
    return _j(timeout_out)


async def do_wait_agent(ctx, *, hosts: list[str] | None, cidr: str,
                        mlabel: str, machine: str, port: int, token: str,
                        timeout_s: float, interval_s: float,
                        strict: bool) -> str:
    # PR#2 T1.1c: cold-start endpoint discovery. Needs no
    # connected view — probes the union of hosts/cidr/mlabel
    # (configured + alt_hosts + observed_endpoints) until a
    # TCP+Status roundtrip answers, then returns the
    # winner's identity. ``strict=True`` additionally
    # requires driver_state == 'loaded'.
    import time as _t
    from ....session import probe_hosts_concurrent as _probe_many
    # Build the candidate set.
    cand: list[str] = []
    for h in (hosts or []):
        s = str(h or "").strip()
        if s and s not in cand:
            cand.append(s)
    cidr_hosts, cidr_err = _expand_cidr(cidr)
    if cidr_err:
        return _j({"ok": False, "kind": "cidr_too_broad",
                   "action": "wait_agent",
                   "error": cidr_err})
    cand.extend(h for h in cidr_hosts if h not in cand)
    mlab = (mlabel or machine or "").strip()
    resolved_port = _resolve_port(
        mlab, ctx.session.cfg, ctx.registry,
        explicit=port or None) if mlab else int(port or 50099)
    if mlab:
        try:
            tc = ctx.session.cfg.target_for(mlab)
            if tc.host and tc.host not in cand:
                cand.append(tc.host)
            for h in (getattr(tc, "alt_hosts", None) or []):
                if h and h not in cand:
                    cand.append(h)
        except Exception:
            pass
        try:
            for o in ctx.registry.observed_endpoints(mlab):
                oh = o.get("host") if isinstance(o, dict) else None
                if oh and oh not in cand:
                    cand.append(str(oh))
        except Exception:
            pass
    if not cand:
        return _j({"ok": False, "kind": "no_candidates",
                   "action": "wait_agent",
                   "error": "wait_agent: nothing to probe — "
                            "pass hosts=[...] or cidr= or "
                            "mlabel= with a known machine"})
    # allowlist every candidate (names resolved off the loop,
    # all addresses checked) and probe/dial the checked IP literals.
    cand = list(dict.fromkeys([await _check_allowed(ctx, h) for h in cand]))
    deadline_s = float(timeout_s) if timeout_s and timeout_s > 0 else 120.0
    poll_s = float(interval_s) if interval_s and interval_s > 0 else 1.0
    started = _t.monotonic()
    deadline = started + deadline_s
    attempts = 0
    last_err = ""
    # Use the primary machine's token when the mlabel
    # resolves there, else no token (the agent service may
    # not require one; connection fails fast otherwise).
    probe_token = token or ""
    try:
        t_cfg = ctx.session.cfg.target_for(mlab or None)
        probe_token = probe_token or getattr(t_cfg, "token",
                                              "") or ""
    except Exception:
        pass
    connect_timeout_ms = int(
        getattr(ctx.session.cfg.target, "connect_timeout_ms",
                10000) or 10000)
    max_inflight = int(
        getattr(ctx.session.cfg.target, "max_inflight", 16)
        or 16)
    AgentClient = _lookup_agent_client()
    while _t.monotonic() < deadline:
        attempts += 1
        remaining = max(0.0, deadline - _t.monotonic())
        probe_budget = min(2.0, remaining) if remaining > 0 else 0.2
        probed = await _probe_many(
            cand, resolved_port, timeout_s=probe_budget,
            limit=32)
        winner = ""
        winner_latency_ms = 0.0
        for h, _p, ok, lat in probed:
            if ok:
                winner = h
                winner_latency_ms = lat
                break
        if not winner:
            last_err = ("no TCP answer from "
                        f"{len(cand)} candidate(s)")
        else:
            probe_client = AgentClient(
                winner, resolved_port, probe_token,
                connect_timeout_ms,
                max_inflight=max_inflight)
            try:
                await probe_client.connect()
                st = await probe_client.status()
                try:
                    await probe_client.close()
                except Exception:  # noqa: BLE001
                    pass
                ds = str(st.get("driver_state") or "").upper()
                driver_loaded = ds in (
                    "DRIVER_SERVICE",
                    "DRIVER_MANUAL_MAPPED",
                    "SERVICE", "MANUAL_MAPPED", "LOADED")
                if strict and not driver_loaded:
                    last_err = (f"driver not loaded on "
                                f"{winner}:{resolved_port} "
                                f"(driver_state={ds!r})")
                else:
                    elapsed_s = round(
                        _t.monotonic() - started, 3)
                    resolved = {
                        "host": winner,
                        "port": resolved_port,
                        "latency_ms": winner_latency_ms,
                        "agent_version": st.get(
                            "agent_version") or st.get(
                                "version") or "",
                        "boot_epoch_ms": int(
                            st.get("boot_epoch_ms") or 0),
                        "agent_instance_id": str(
                            st.get("agent_instance_id") or ""),
                        "driver_state": st.get("driver_state"),
                    }
                    return _j({
                        "ok": True,
                        "action": "wait_agent",
                        "attempts": attempts,
                        "elapsed_s": elapsed_s,
                        "resolved": resolved,
                        "mlabel": mlab or "",
                        "strict": bool(strict),
                    })
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
                try:
                    await probe_client.close()
                except Exception:  # noqa: BLE001
                    pass
        remaining = deadline - _t.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(poll_s, max(0.05, remaining)))
    elapsed_s = round(_t.monotonic() - started, 3)
    return _j({
        "ok": False,
        "action": "wait_agent",
        "kind": "wait_agent_timeout",
        "attempts": attempts,
        "elapsed_s": elapsed_s,
        "candidates": len(cand),
        "mlabel": mlab or "",
        "port": resolved_port,
        "error": (f"wait_agent timed out after "
                  f"{attempts} probe pass(es) over "
                  f"{elapsed_s}s: {last_err}"),
        "hint": ("widen hosts/cidr, raise timeout_s, drop "
                 "strict=True, or verify the agent service "
                 "is running on the target"),
    })


async def do_wait_boot_change(ctx, *, name: str, timeout_s: float) -> str:
    # block until the view's boot identity —
    # (boot_epoch_ms, agent_instance_id) — changes. Same
    # detector as status(), polled with the same bounded
    # backoff as wait_connectable (0.5s ramping to 3s).
    # A notice the boot monitor already parked also
    # satisfies the wait. Typical use: driver_load → trigger
    # a test that may BSOD → wait_boot_change →
    # wait_connectable → crash_state has the parsed dump.
    import time as _t
    view = ctx.session.resolve_view_name(name)
    client = ctx.session.require_client(view)
    deadline_s = float(timeout_s) if timeout_s and timeout_s > 0 else 15.0
    deadline = _t.monotonic() + deadline_s
    started = _t.monotonic()
    delay = 0.5
    attempts = 0
    last_kind = ""
    while _t.monotonic() < deadline:
        attempts += 1
        try:
            s = await client.status()
        except Exception:  # noqa: BLE001 — target may be mid-reboot
            last_kind = "status_error"
        else:
            last_kind = "ok"
            change = ctx.session.note_boot_identity(view, s)
            # T1.3 (PR#2): first_connect doesn't satisfy a
            # wait for a BOOT change — treat it as "no
            # change" and keep polling.
            if change is not None and change.get("kind") \
                    not in ("new_boot", "agent_restart"):
                change = None
            pending = ctx.session.pending_boot_notices.pop(
                view, None)
            if pending is not None:
                if change is None:
                    if pending.get("kind") in (
                            "new_boot", "agent_restart"):
                        # Monitor won the race — report
                        # what it parked.
                        change = pending
                    else:
                        # A parked minidump result isn't a
                        # boot change; re-park it so
                        # status() still drains it.
                        ctx.session.pending_boot_notices[
                            view] = pending
                elif pending.get("minidump") is not None:
                    change.setdefault("minidump",
                                      pending["minidump"])
            if change is not None:
                elapsed_s = round(_t.monotonic() - started, 3)
                swept = None
                if "swept" not in change:
                    swept = await ctx.sweep_view_state(view)
                return _j({
                    "ok": True,
                    "action": "wait_boot_change",
                    "view": view,
                    "boot_change": change,
                    "swept": change.get("swept", swept),
                    "minidump": change.get("minidump"),
                    "attempts": attempts,
                    "elapsed_s": elapsed_s,
                })
        remaining = deadline - _t.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(delay, max(0.05, remaining)))
        delay = min(delay * 1.7, 3.0)
    elapsed_s = round(_t.monotonic() - started, 3)
    return _j({
        "ok": False,
        "action": "wait_boot_change",
        "view": view,
        "attempts": attempts,
        "elapsed_s": elapsed_s,
        "kind": "wait_timeout",
        "error": (
            f"wait_boot_change: view {view!r} showed no boot "
            f"identity change after {attempts} poll(s) over "
            f"{elapsed_s}s"),
        "last_status_kind": last_kind or "unknown",
        "boot_identity": ctx.session.boot_identity(view),
        "hint": (
            "the view's (boot_epoch_ms, agent_instance_id) "
            "pair never changed — no reboot/agent restart "
            "seen. For 'did it crash' triage use "
            "target_manage(action='crash_state'); to force a "
            "check now, status() runs the same detector."),
    })
