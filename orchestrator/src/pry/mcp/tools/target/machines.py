"""``target_manage`` machine registry verbs — ``machines_register``,
``machines_set``, ``machines_unregister``, ``machines``,
``machines_prune``.

The registry is persisted to ``artifacts/targets.json`` and is
hot-reloadable (no restart).  YAML aliases flow in as reviewed metadata;
``machines_set`` on a YAML alias only touches metadata unless the caller
passes ``force=True``.  ``machines_prune`` drops alias-only shells that
passive probes left behind (never YAML or shadow entries).
"""

from __future__ import annotations

from typing import Any

from ..common import *  # noqa: F401,F403 — closure helpers (_j, _guard, ...)


async def do_machines_prune(ctx, *, dry_run: bool) -> str:
    # PR#8: drop alias-only shells that passive-discovery
    # probes left behind. Pure orchestrator metadata — no
    # target traffic.
    sess_machines = {}
    try:
        sess_machines = dict(ctx.session.machines() or {})
    except Exception:  # noqa: BLE001 — best-effort snapshot
        sess_machines = {}
    report = ctx.registry.prune_empty_shells(
        session_machines=sess_machines,
        dry_run=bool(dry_run))
    return _j({"ok": True, "action": "machines_prune",
               **report,
               "hint": ("re-run with dry_run=false to apply"
                        if report.get("dry_run")
                        else "artifacts/targets.json rewritten "
                             "with the shells removed")})


async def do_machines_cmd(ctx, *, action: str, name: str, machine: str,
                           host: str, port: int, user_port: int, token: str,
                           trust: str, purpose: str, note: str,
                           operator: str, tags: str,
                           computer_name: str,
                           alt_hosts: list[str] | None,
                           force: bool) -> str:
    # machine registry — persisted in
    # artifacts/targets.json, hot-reloadable, no restart.
    # computer_name + alt_hosts underpin the DHCP-flapping /
    # NIC-change recovery recipe. computer_name is the Windows NetBIOS
    # name the agent reports in its phone-home beacon; storing it on
    # the entry lets the beacon land under the operator's alias
    # instead of minting a split-brain shell. alt_hosts widens the
    # probe set used by wait_agent / rediscover.
    reg = ctx.registry
    alias = (machine or name or "").strip()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    alt_hosts_list: list[str] = []
    if isinstance(alt_hosts, list):
        alt_hosts_list = [str(h).strip() for h in alt_hosts if str(h).strip()]
    cn = str(computer_name or "").strip()
    if action == "machines":
        rows: list[dict] = []
        seen: set[str] = set()

        def _row(a: str) -> dict:
            r = reg.describe(a, cfg=ctx.cfg) or {"machine": a}
            r["connected_views"] = sorted(
                ctx.session.machines().get(
                    str(r.get("machine") or a), []))
            return r

        for a in list(reg.all().keys()) + list(
                (getattr(ctx.cfg, "machines", None) or {}).keys()):
            if a.lower() not in seen:
                seen.add(a.lower())
                rows.append(_row(a))
        for m in sorted(ctx.session.machines()):
            if m.lower() not in seen:
                seen.add(m.lower())
                rows.append(_row(m))
        if not rows and getattr(ctx.cfg.target, "host", ""):
            rows.append(_row("default"))
        return _j({"ok": True, "count": len(rows),
                   "machines": rows,
                   "min_trust_actuator": getattr(
                       ctx.cfg.security, "min_trust_actuator",
                       "untrusted")})
    if not alias and action == "machines_set":
        # empty selector annotates the caller's machine
        try:
            alias = ctx.session.machine_of(
                ctx.session.resolve_view_name(""))
        except Exception:
            alias = "default"
    if not alias:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"{action}: machine= (alias) "
                            "is required"})
    # alias hygiene. If the caller registers
    # a machine whose alias looks like an IPv4 (or ends in a
    # digit cluster that matches a live view's computer_name
    # suffix), warn: this is the k205/k207/k206 litter — the
    # same box ends up with multiple aliases because the IP
    # changed between runs. The call still succeeds; the
    # response's warnings[] names the live alias instead.
    dup_hint: str | None = None
    if action == "machines_register":
        def _looks_like_ip(s: str) -> bool:
            parts = s.split(".")
            return (len(parts) == 4
                    and all(p.isdigit() and 0 <= int(p) <= 255
                            for p in parts))
        def _digit_tail(s: str) -> str:
            i = len(s)
            while i > 0 and s[i - 1].isdigit():
                i -= 1
            return s[i:]
        live_label: str | None = None
        tail = _digit_tail(alias)
        for key in ctx.session.clients:
            mi = ctx.session.machine_label(key)
            cn = str(mi.get("computer_name") or "")
            m_label = str(mi.get("machine") or "")
            if not cn:
                continue
            if _looks_like_ip(alias) and alias in (
                    getattr(ctx.session.clients[key],
                            "endpoint", "") or ""):
                live_label = m_label
                break
            if tail and len(tail) >= 2 and cn.lower().endswith(
                    tail.lower()):
                live_label = m_label
                break
        if live_label and live_label.lower() != alias.lower():
            dup_hint = (f"alias {alias!r} looks like it points "
                        f"at a machine already known as "
                        f"{live_label!r}; consider "
                        f"machines_manage(action='set', "
                        f"machine={live_label!r}, host=...) "
                        "instead of a fresh alias — multiple "
                        "aliases for one box fragment history")
    try:
        if action == "machines_register":
            info = reg.register(
                alias, host=host, kernel_port=port,
                user_port=user_port, token=token,
                trust=trust, purpose=purpose, note=note,
                operator=operator, tags=tag_list,
                computer_name=cn,
                alt_hosts=alt_hosts_list or None,
                force=bool(force))
        elif action == "machines_set":
            info = reg.set(
                alias, host=host or None,
                kernel_port=port or None,
                user_port=user_port or None,
                token=token or None,
                trust=trust or None, purpose=purpose or None,
                note=note or None, operator=operator or None,
                tags=tag_list if tags else None,
                computer_name=cn if cn else None,
                alt_hosts=alt_hosts_list if alt_hosts_list else None,
                force=bool(force))
        else:
            removed = reg.unregister(alias, force=bool(force))
            return _j({"ok": bool(removed), "machine": alias,
                       "removed": removed})
    except ValueError as exc:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": str(exc)})
    out: dict[str, Any] = {"ok": True, "machine_info": info}
    if dup_hint:
        out["warnings"] = [dup_hint]
    return _j(out)
