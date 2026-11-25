"""Target-package plumbing helpers — pre-register pure utilities that
every verb module imports.

R6 lifted these out of ``tools/target.py`` module scope. They are
imported by both the dispatcher (which re-exports a few of them so test
monkey-patches targeting ``pry.mcp.tools.target._resolve_port``,
``_expand_cidr``, ``_compact_connect_status``, ``_attach_machine_info``
keep working) and by the per-verb modules.
"""

from __future__ import annotations

from typing import Any

from ..common import _merge_driver_state  # noqa: F401 — relied on by _auto_prepare


def _dedupe_watchdog_unconfigured(ctx, machine: str, arm_info: dict | None,
                                   verbose: bool) -> dict | None:
    """PR#2 T2.7: silence a repeated ``watchdog.auto_arm UNCONFIGURED``
    hint for the same machine. The first occurrence per orchestrator
    process surfaces as usual; subsequent ones are stripped unless the
    caller passed ``verbose=True``. Returns the arm_info either
    untouched or with the ``note`` key omitted."""
    if not isinstance(arm_info, dict):
        return arm_info
    if arm_info.get("configured"):
        return arm_info
    key = str(machine or "").strip().lower() or "<default>"
    seen = ctx._watchdog_unconf_seen
    if key in seen and not verbose:
        copy = dict(arm_info)
        copy.pop("note", None)
        copy["note_suppressed"] = True
        return copy
    seen.add(key)
    return arm_info


async def _auto_prepare(ctx, cid: str, *, machine: str, view: str,
                         method: str, verbose: bool) -> dict:
    """PR#2 T2.7: run the use + driver_load follow-up after a successful
    connect. Returns ``{use, driver_load}``; each block carries
    ``{ok, ...}``. driver_load is skipped when the status reports
    the driver already loaded (noop with a note). Errors are captured,
    never re-raised."""
    from ._runtime import _auto_arm_after_load, _auto_arm_cfg_status
    out: dict = {}
    # Prefer the resolved view-prefix machine (``machine_of(view)``) over
    # the caller's selector so an IP-shaped machine label still focuses:
    # set_focus() partitions at the first dot, so passing a dotted
    # machine like ``127.0.0.1`` would resolve the wrong token. The
    # view key resolves unambiguously via Session.machine_of(view).
    sel_machine = (machine or "").strip()
    view_machine = ctx.session.machine_of(view) if view else ""
    sel = view_machine or sel_machine or view
    try:
        focus_info = ctx.session.set_focus(cid, sel)
        out["use"] = {"ok": True, "focus": focus_info}
    except Exception as exc:  # noqa: BLE001
        # Fall back to a direct per-caller focus write — set_focus()'s
        # partition can't resolve a machine label that itself contains
        # dots (IP), but we already know the exact machine+kind from
        # the view we just connected.
        if view_machine:
            kind = ctx.session.view_kind_of(view) or "kernel"
            ctx.session._focus[cid] = {"machine": view_machine,
                                        "kind": kind}
            out["use"] = {"ok": True,
                          "focus": {"machine": view_machine,
                                     "kind": kind, "view": view},
                          "note": f"fallback focus set (set_focus "
                                  f"declined {sel!r}: {exc})"}
        else:
            out["use"] = {"ok": False, "error": str(exc)}
    client = ctx.session.clients.get(view)
    if client is None:
        out["driver_load"] = {"ok": False, "skipped": True,
                              "error": f"view {view!r} not connected"}
        return out
    try:
        st = await client.status()
    except Exception as exc:  # noqa: BLE001
        out["driver_load"] = {"ok": False, "skipped": True,
                              "error": f"status probe failed: {exc}"}
        return out
    ds = str(st.get("driver_state") or "").upper()
    loaded = ds in ("LOADED", "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED",
                    "SERVICE", "MANUAL_MAPPED")
    if loaded:
        out["driver_load"] = {"ok": True, "already_loaded": True,
                              "driver_state": st.get("driver_state")}
        return out
    try:
        r = await client.driver_load(method=method or "service")
        merged = await _merge_driver_state(ctx, r, verb="driver_load",
                                           view=view)
        if merged.get("ok") is not False:
            arm = await _auto_arm_after_load(ctx, client, view)
            arm_info = (arm if arm is not None
                        else _auto_arm_cfg_status(ctx))
            merged["watchdog_auto_arm"] = _dedupe_watchdog_unconfigured(
                ctx, machine, arm_info, verbose)
        out["driver_load"] = merged
    except Exception as exc:  # noqa: BLE001
        out["driver_load"] = {"ok": False, "error": str(exc)}
    return out


def _compact_connect_status(status: dict) -> dict:
    """PR#2 T2.1: trim a Session.connect() status dict to the compact
    connect envelope. The field set is the plan's §T2.1 list — adds
    ``os_boot_epoch_ms`` / ``agent_instance_id`` (T1.3) explicitly, plus
    ``boot_change`` / ``warnings`` when the full status carried them.
    """
    if not isinstance(status, dict):
        return status
    out: dict = {
        "ok": bool(status.get("ok", True)),
        "view": status.get("view"),
        "machine": status.get("machine"),
        "agent_version": status.get("agent_version") or status.get("version") or "",
        "resolved_address": status.get("resolved_address") or "",
        "driver_state": status.get("driver_state"),
        "os_boot_epoch_ms": int(status.get("boot_epoch_ms") or 0),
        "agent_instance_id": str(status.get("agent_instance_id") or ""),
    }
    if status.get("boot_change") is not None:
        out["boot_change"] = status["boot_change"]
    warnings = status.get("warnings")
    if warnings:
        out["warnings"] = list(warnings)
    # machine_info is carried on the parent response's banner slot, not
    # inside the per-view compact dict — leave it to the caller to lift.
    return out


def _resolve_port(mlabel: str, cfg, registry,
                  explicit: int | None = None) -> int:
    """T1.1a (PR#2): endpoint-port resolution precedence for a machine
    label.

    1. ``explicit`` kwarg from the call site, if truthy.
    2. The newest observation in ``registry.observed_endpoints(mlabel)``.
    3. ``cfg.target_for(mlabel).port`` ONLY when ``cfg.has_machine(mlabel)``
       — i.e. the machine was declared in reviewed YAML. A registry-only
       alias with no observed endpoint falls through to the literal
       default, avoiding the stale-50099 bug where ``target_for`` would
       return the primary target's port on an unknown machine.
    4. Literal ``50099`` (the historical kernel-view default).
    """
    if explicit:
        try:
            return int(explicit)
        except (TypeError, ValueError):
            pass
    try:
        obs = registry.observed_endpoints(mlabel) if registry is not None \
            else []
    except Exception:
        obs = []
    for o in obs:
        p = o.get("port") if isinstance(o, dict) else None
        if p:
            try:
                return int(p)
            except (TypeError, ValueError):
                continue
    try:
        has = cfg.has_machine(mlabel) if cfg is not None else False
    except Exception:
        has = False
    if has:
        try:
            tc = cfg.target_for(mlabel)
            if tc.port:
                return int(tc.port)
        except Exception:
            pass
    return 50099


def _expand_cidr(cidr: str, cap_prefix: int = 20) -> tuple[list[str], str]:
    """T1.1b (PR#2): expand ``cidr`` into a host list.

    Returns ``(hosts, error)`` — on an invalid CIDR or one broader than
    ``cap_prefix`` the host list is empty and the error string is set.
    """
    import ipaddress as _ip
    cidr = (cidr or "").strip()
    if not cidr:
        return [], ""
    try:
        net = _ip.IPv4Network(cidr, strict=False)
    except (ValueError, _ip.AddressValueError) as exc:
        return [], f"invalid cidr {cidr!r}: {exc}"
    if net.prefixlen < cap_prefix:
        return [], (f"cidr {cidr!r} covers {net.num_addresses} hosts — "
                    f"wider than /{cap_prefix} is refused; pick a tighter "
                    "range")
    hosts = [str(h) for h in net.hosts()]
    if not hosts and net.num_addresses:
        # /32 or /31 — hosts() is empty for those; use the network addr.
        hosts = [str(net.network_address)]
    return hosts, ""


async def _check_allowed(ctx, host: str) -> str:
    """Allowlist gate for one probe candidate: returns the checked IP
    literal to dial (names resolved off the event loop, EVERY resolved
    address must be inside security.authorized_targets). Raises
    TargetNotAllowed. Falls back to the sync check for duck-typed sessions
    without ``check_target_async``."""
    fn = getattr(ctx.session, "check_target_async", None)
    if callable(fn):
        return await fn(host)
    return ctx.session.check_target(host)


async def _filter_allowed(ctx, hosts: list[str]) -> tuple[list[str], list[dict]]:
    """every discovery probe list (rediscover hosts/cidr/DNS
    answers, reconnect's /24 auto-expand, wait_agent) goes through the CIDR
    allowlist before a packet leaves. Returns ``(ips_to_dial, refused)`` —
    de-duplicated checked IP literals in input order, plus
    ``[{host, error}]`` for the candidates the allowlist refused."""
    out: list[str] = []
    refused: list[dict] = []
    for h in hosts:
        try:
            ip = await _check_allowed(ctx, h)
        except Exception as exc:  # noqa: BLE001 — TargetNotAllowed / resolve
            refused.append({"host": h, "error": str(exc)})
            continue
        if ip not in out:
            out.append(ip)
    return out, refused


def _attach_machine_info(ctx, cid: str, view: str) -> dict | None:
    """One-time machine_info banner: the first time a caller touches
    a machine, its trust/purpose/notes/endpoints ride along on the connect
    response. Subsequent connects to the same machine stay silent — full
    detail is always one call away via target_manage(action='machines').
    Never raises.

    Dedup bucket: callers with a real session id get per-client dedup;
    stateless transports synthesise a rotating ``anon-*`` id per call, so
    those land in ONE stable 'anonymous' bucket (once per machine per
    orchestrator process — the banner is not re-spammed per call)."""
    if not view:
        return None
    try:
        label = ctx.session.machine_of(view)
    except Exception:
        return None
    bucket = cid if (cid and not str(cid).startswith("anon-")) else "anonymous"
    seen = ctx._machine_info_seen.setdefault(bucket, set())
    if label.lower() in seen:
        return None
    seen.add(label.lower())
    try:
        info = ctx.registry.describe(label, cfg=ctx.cfg)
    except Exception:
        return None
    if info is None:
        return None
    try:
        info["computer_name"] = str(
            ctx.session.machine_label(view).get("computer_name") or "")
    except Exception:
        pass
    return info


__all__ = [
    "_dedupe_watchdog_unconfigured",
    "_auto_prepare",
    "_compact_connect_status",
    "_resolve_port",
    "_expand_cidr",
    "_check_allowed",
    "_filter_allowed",
    "_attach_machine_info",
]
