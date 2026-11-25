"""``target_manage`` post-reboot recovery verbs — ``boot_recover``,
``rediscover``, ``crash_state``.

Carved out of the dispatcher so ``reboot.py`` can stay under the
line-count cap (slice doc 03 projected ``reboot.py`` at ~700 lines; the
600-line cap enforced by ``tools/check_line_count.py`` makes a split
necessary). ``boot_recover`` is the one-call post-reboot choreography
(connect → sweep → driver_load → watchdog auto-arm → minidump pull);
``rediscover`` re-probes a machine's known endpoints in parallel;
``crash_state`` is the point-in-time post-mortem snapshot.
"""

from __future__ import annotations

from typing import Any

from ..common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)

from ._plumbing import _expand_cidr, _filter_allowed, _resolve_port
from ._runtime import (
    _auto_arm_after_load,
    _auto_arm_cfg_status,
    _monitor_pull_minidump,
)


async def do_rediscover(ctx, *, machine: str, name: str, port: int,
                        hosts: list[str] | None, cidr: str,
                        timeout_s: float) -> str:
    # re-probe a machine's
    # known endpoints in parallel. Candidate set now also
    # accepts caller-supplied ``hosts=[...]`` / ``cidr=`` and
    # the port resolution precedence is observed > YAML >
    # 50099 so a stale 50099 fallback no longer eats the
    # real observed port of a registry-only machine (plan
    # §T1.1a).
    import socket as _socket
    from ....session import probe_hosts_concurrent as _probe_many
    mlabel_in = (machine or name or "").strip()
    if not mlabel_in:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "rediscover: machine= required"})
    mlabel_resolved = ctx.session._match_machine(mlabel_in) or mlabel_in
    # T1.1a: single-call port precedence helper.
    port_guess = _resolve_port(
        mlabel_resolved, ctx.session.cfg, ctx.registry,
        explicit=port or None)
    # Candidate hosts.
    hosts_list: list[str] = []
    try:
        tc = ctx.session.cfg.target_for(mlabel_resolved)
        if tc.host:
            hosts_list.append(tc.host)
        for h in (getattr(tc, "alt_hosts", None) or []):
            if h and h not in hosts_list:
                hosts_list.append(h)
    except Exception:
        pass
    for o in ctx.registry.observed_endpoints(mlabel_resolved):
        oh = o.get("host")
        if oh and oh not in hosts_list:
            hosts_list.append(str(oh))
    # T1.1b: user-supplied extras.
    for h in (hosts or []):
        s = str(h or "").strip()
        if s and s not in hosts_list:
            hosts_list.append(s)
    cidr_hosts, cidr_err = _expand_cidr(cidr)
    if cidr_err:
        return _j({"ok": False, "kind": "cidr_too_broad",
                   "action": "rediscover",
                   "machine": mlabel_resolved,
                   "error": cidr_err})
    for h in cidr_hosts:
        if h not in hosts_list:
            hosts_list.append(h)
    # Hostname resolution — add every A record we see. Resolved
    # off the event loop (a missing name stalls mDNS/LLMNR for seconds).
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(loop.getaddrinfo(
            mlabel_resolved, port_guess, family=_socket.AF_INET,
            type=_socket.SOCK_STREAM), timeout=3.0)
        for info in infos:
            ip = info[4][0]
            if ip and ip not in hosts_list:
                hosts_list.append(ip)
    except Exception:
        pass
    if not hosts_list:
        return _j({"ok": False, "kind": "no_candidates",
                   "machine": mlabel_resolved,
                   "error": "rediscover: nothing to probe — "
                            "configured, observed, alt_hosts, "
                            "hosts/cidr, and DNS all empty"})
    # every candidate — configured, observed, caller-supplied,
    # cidr-expanded, DNS answers — goes through the CIDR allowlist; the
    # checked IP is what gets probed.
    allowed, refused = await _filter_allowed(ctx, hosts_list)
    if not allowed:
        return _j({"ok": False, "kind": "not_allowed",
                   "action": "rediscover", "machine": mlabel_resolved,
                   "error": "rediscover: every candidate is outside "
                            "security.authorized_targets",
                   "refused": refused,
                   "hint": "widen security.authorized_targets in the "
                           "config if these addresses are lab machines"})
    probe_s = max(1.0, float(timeout_s) if timeout_s else 2.0)
    probed = await _probe_many(allowed, port_guess,
                                timeout_s=probe_s, limit=16)
    answered = [(h, lat) for h, _p, ok, lat in probed if ok]
    failures = [{"host": h}
                for h, _p, ok, _lat in probed if not ok]
    for h, _lat in answered:
        try:
            # PR#8: rediscover is a passive probe sweep — do
            # not mint a shell for a brand-new alias.
            ctx.registry.record_observed_endpoint(
                mlabel_resolved, host=h, port=port_guess,
                allow_create=False)
        except Exception:  # noqa: BLE001
            pass
    out_refused = {"refused": refused} if refused else {}
    return _j({
        "ok": bool(answered),
        "action": "rediscover",
        "machine": mlabel_resolved,
        "port": port_guess,
        "tried": allowed,
        **out_refused,
        "answered": [h for h, _ in answered],
        "latencies_ms": {h: lat for h, lat in answered},
        "failed": failures,
        "hint": ("record_observed_endpoint updated for every "
                 "live host; call target_manage(action="
                 f"'reconnect', name={mlabel_resolved!r}) to swap the "
                 "channel, or just wait for the next connect "
                 "(the candidate list now sees the new IP)"),
    })


async def do_boot_recover(ctx, *, name: str, host: str, port: int,
                           token: str, load_driver: bool, method: str,
                           include_dump: bool) -> str:
    # the post-reboot choreography as one call —
    # verify/restore the view connection, sweep stale boot
    # state, load the driver if it did not survive, re-arm
    # watchdog.auto_arm, pull + parse the newest minidump.
    # Every step degrades honestly; the report shows which
    # steps ran and which failed.
    cid = current_client_id()
    view = ctx.session.resolve_view_name(name) if name \
        else ctx.session.primary
    out: dict[str, Any] = {"ok": True, "action": "boot_recover",
                           "view": view}
    client = ctx.session.clients.get(view)
    was_connected = client is not None
    reachable = False
    if client is not None:
        try:
            st = await client.status()
            reachable = bool(st.get("ok", True))
            out["status"] = {
                k: st.get(k) for k in
                ("boot_epoch_ms", "agent_instance_id",
                 "driver_state", "os_version", "os_build")
                if k in st}
        except Exception as exc:
            out["status_error"] = str(exc)
    boot_change = None
    if not reachable:
        try:
            st2 = await ctx.session.connect(
                host or None, port or None, token or None,
                name=view, owner=cid, force=False)
            boot_change = st2.get("boot_change")
            out["connect"] = {
                "was_connected": was_connected,
                "endpoint": getattr(
                    ctx.session.clients.get(view), "endpoint",
                    ""),
                "boot_change": boot_change,
            }
        except Exception as exc:
            e = _enrich_error("target_manage", "connect",
                              str(exc))
            out["ok"] = False
            out["connect"] = {"was_connected": was_connected,
                              "error": e}
            out["error"] = (
                f"boot_recover: view {view!r} unreachable — "
                "restore connectivity, then retry")
            return _j(out)
    else:
        out["connect"] = {"was_connected": True,
                          "boot_change": None}
    # Stale-state sweep on a boot change (shells, follows,
    # watchdog arms, detached handles).
    if boot_change:
        try:
            out["swept"] = await ctx.sweep_view_state(view)
        except Exception as exc:
            out["sweep_error"] = str(exc)
    # Driver check + optional load.
    drv: dict[str, Any] = {}
    try:
        c = ctx.session.require_client(view)
        st = await c.status()
        state = str(st.get("driver_state", "")).upper()
        drv["state"] = st.get("driver_state")
        present = state in ("DRIVER_SERVICE",
                            "DRIVER_MANUAL_MAPPED",
                            "SERVICE", "MANUAL_MAPPED")
        drv["present"] = present
        if not present and load_driver:
            lease = None
            try:
                if ctx.leases is not None:
                    wait_s = getattr(
                        ctx.cfg.leases, "driver_timeout_s",
                        10.0)
                    lease = await ctx.leases.acquire(
                        "driver", cid, wait_s=wait_s)
                    if isinstance(lease, BusyInfo):
                        drv["load_error"] = (
                            "driver lease held by "
                            f"{lease.held_by}")
                        lease = None
                if lease is not None or ctx.leases is None:
                    r = await c.driver_load(method=method)
                    merged = await _merge_driver_state(
                        ctx, r, verb="driver_load", view=view)
                    drv["loaded"] = merged.get("ok") is not False
                    drv["load_result"] = {
                        k: v for k, v in merged.items()
                        if k in ("ok", "driver_state",
                                 "error")}
            finally:
                if lease is not None:
                    await ctx.leases.release(lease)
        # Auto-arm after (re)load or on a driver that
        # survived the reboot.
        if (not drv.get("present")) or load_driver or \
                boot_change is not None:
            arm = await _auto_arm_after_load(
                ctx, ctx.session.clients.get(view), view)
            drv["watchdog_auto_arm"] = (
                arm if arm is not None
                else _auto_arm_cfg_status(ctx))
    except Exception as exc:
        drv["error"] = str(exc)
    out["driver"] = drv
    # Newest minidump — the "what killed the box" answer.
    # Default on for the post-reboot case (fresh connect or
    # a boot change); include_dump forces it otherwise.
    if include_dump or boot_change or not was_connected:
        res = await _monitor_pull_minidump(ctx, view)
        if res is not None:
            out["crash_dump"] = {
                "bugcheck": res.get("bugcheck"),
                "params": res.get("params"),
                "faulting_module": res.get("faulting_module"),
                "resolution": res.get("resolution"),
                "source": res.get("source"),
                "hint": "dump_manage(action='stack', "
                        "path=<source.local_path>) walks "
                        "the saved stack offline",
            }
        else:
            out["crash_dump"] = None
    return _j(out)


async def do_crash_state(ctx, *, name: str, samples: int,
                          read_bytes: int, include_dump: bool) -> str:
    # Phase 0.3: one-call post-mortem. Composes recent_ops_agent
    # (agent-side persistent breadcrumb) + kernel log tail + a
    # reboot-detection heuristic (agent_uptime vs last-seen delta).
    import time as _time
    view = ctx.session.resolve_view_name(name)
    out: dict[str, Any] = {"ok": True, "target": view}
    # 1. recent_ops_agent (durable). If agent < v5, degrades cleanly.
    try:
        c = ctx.session.require_client(view)
        r = await c.recent_ops_agent(limit=samples or 32,
                                     include_prior=True)
        out["breadcrumb"] = r
        now = _time.time()
        last_op = c.last_op_ts
        # If agent uptime_ms < (now - last_op)*1000, the agent
        # restarted between our last call and now. Attach a hint.
        if r.get("agent_start_epoch_ms") and last_op:
            agent_start_s = r["agent_start_epoch_ms"] / 1000.0
            if agent_start_s > last_op:
                out["rebooted"] = True
                out["wedge_window_s"] = round(agent_start_s - last_op, 2)
            else:
                out["rebooted"] = False
    except Exception as exc:
        out["breadcrumb_error"] = str(exc)
    # 2. kernel log tail (32 KiB by default; read_bytes overrides).
    tail_bytes = (read_bytes if read_bytes and read_bytes > 0
                  else 32 * 1024)
    log_path = r"C:\Users\Public\Desktop\pry_kernel.log"
    try:
        c = ctx.session.require_client(view)
        out["kernel_log_tail"] = await c.file_tail(
            log_path, bytes_wanted=tail_bytes, line_align=True)
    except Exception as exc:
        out["kernel_log_error"] = str(exc)
    # 3. Recent orchestrator-side ops for context (per-client ring).
    try:
        c = ctx.session.require_client(view)
        out["recent_orch_ops"] = c.recent_ops(samples or 16)
    except Exception:
        pass
    # 4. newest crash dump, parsed in-line. Runs when
    # the breadcrumb heuristic says the far end restarted
    # (rebooted=True) or the caller passed include_dump — the
    # post-BSOD "what just killed the box" answer without a
    # manual download. Failure attaches `minidump_error`; the
    # breadcrumb/log-tail data above always survives.
    try:
        c = ctx.session.require_client(view)
        if out.get("rebooted") or include_dump:
            from .. import dump as _dump
            got = await _dump._latest_minidump(
                ctx, c, _dump.DEFAULT_DUMP_DIR)
            if got is None:
                out["minidump_error"] = (
                    "no parseable .dmp files in "
                    f"{_dump.DEFAULT_DUMP_DIR}")
            else:
                entries = got.pop("entries", None)
                res = await _dump._parse_artifact(
                    ctx, c, got["local_path"],
                    boot_epoch_ms=await _dump._boot_epoch_ms(c))
                res["source"] = {
                    k: got[k] for k in
                    ("remote_path", "local_path", "name",
                     "mtime_unix", "size", "dir")}
                res["source"]["dumps_seen"] = len(entries or [])
                out["minidump"] = res
    except Exception as exc:
        out["minidump_error"] = str(exc)
    return _j(out)
