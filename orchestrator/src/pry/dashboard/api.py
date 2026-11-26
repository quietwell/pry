"""Dashboard REST + WebSocket routes, registered on the main FastAPI app
before the MCP mount takes the / fallback.

Read endpoints (status/config/findings/toollog) stay GET; the machine
registry gets a small write surface (register/set/unregister +
connect/disconnect) so the dashboard can manage targets without the
operator dropping to the MCP tool. Every write wraps ``ctx.registry`` /
``ctx.session`` — the same code paths ``target_manage`` uses — and tokens
are never echoed back (``token_set`` only).

Every registry / trust / connect write is audited (tool
``dashboard`` in the tool log + the persistent JSONL sink); JSON bodies are
required to be ``application/json`` (form posts are refused even when the
control-plane guard is not in front); the agent beacon is validated and
capped; the WebSocket checks ``Origin`` and only ever unsubscribes its own
queue."""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

from fastapi import Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from .. import __version__
from ..endpoint_hints import usable_ipv4
from ..session import VIEW_KINDS
from .control_plane import ControlPlaneGuard, _is_json

STATIC_DIR = Path(__file__).parent / "static"

# Owner tag for views the dashboard connects, so refcount bookkeeping can
# tell dashboard-initiated connects from MCP-client ones.
_DASH_OWNER = "dashboard"

# T3.3: process uptime anchor for /health. Captured at module import so a
# single number spans both the main-app and dashboard-app mounts (the
# routes register once per app from the same module import).
_START = time.monotonic()


def _uptime_ms() -> int:
    """Milliseconds since this module was first imported — proxy for the
    orchestrator process uptime. Monotonic so clock changes don't warp it."""
    return int((time.monotonic() - _START) * 1000)


def _probe_connected_views(session) -> list[dict]:
    """Lightweight per-view health probe. Does NOT round-trip to the agent
    (that would pin /health latency to the slowest link). Reads only what
    the orchestrator already tracks on the AgentClient: endpoint, last
    successful call timestamp, inflight counter. Returns one row per
    currently connected view in a stable shape so the dashboard pill and
    external monitors can parse it.

    Fields per row:
      * ``view``       – '<machine>.<kind>' key as stored in session.clients
      * ``machine``    – machine label (``view.split('.')[0]``)
      * ``kind``       – view kind ('kernel' / 'user' / …)
      * ``endpoint``   – 'host:port' the AgentClient dials
      * ``state``      – 'connected' | 'stale' (no successful call for >60s)
                         | 'cold' (never answered since connect)
      * ``last_rtt_ms``– None, or ms since the last successful call
                         (max(now - last_seen_ts, now - last_op_ts))
      * ``inflight``   – outstanding gRPC calls on this view
    """
    now = time.time()
    rows: list[dict] = []
    for view, client in getattr(session, "clients", {}).items():
        last_seen = max(
            float(getattr(client, "last_seen_ts", 0.0) or 0.0),
            float(getattr(client, "last_op_ts", 0.0) or 0.0),
        )
        if last_seen > 0.0:
            age_ms = max(0, int((now - last_seen) * 1000))
            state = "connected" if age_ms < 60_000 else "stale"
        else:
            age_ms = None
            state = "cold"
        rows.append({
            "view": view,
            "machine": session.machine_of(view),
            "kind": session.view_kind_of(view),
            "endpoint": getattr(client, "endpoint", ""),
            "state": state,
            "last_rtt_ms": age_ms,
            "inflight": int(getattr(client, "_inflight_count", 0) or 0),
        })
    rows.sort(key=lambda r: (r["machine"], r["kind"]))
    return rows


#: Seconds the dashboard reuses a view's HostInfo + pry-driver probe. Those
#: two fan out into ~8 agent RPCs (registry + file stats); the page polls
#: status every few seconds, so without a cache the dashboard alone kept
#: the lab agent busy. ``/api/status?refresh=1`` bypasses it.
_RICH_TTL_S = 30.0

#: Tool-log arg keys whose values never leave the orchestrator.
_SECRET_KEY_RE = re.compile(r"token|passw|secret|credential|auth|cookie",
                            re.IGNORECASE)
_ARG_STR_CAP = 200
_ARG_LIST_CAP = 20
_ARG_KEYS_CAP = 40
_ARG_DEPTH_CAP = 4
#: Internal bookkeeping keys the dashboard audit threads into args.
_ARG_HIDDEN = frozenset({"_peer", "_current_owner"})


def _clean_args(value: Any, depth: int = 0) -> Any:
    """JSON-safe, size-capped, secret-free copy of a tool call's args for
    the dashboard's expandable tool-log rows. Secret-looking keys keep
    booleans (``token_set``) and lose everything else."""
    if depth > _ARG_DEPTH_CAP:
        return "…"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in list(value.items())[:_ARG_KEYS_CAP]:
            key = str(k)
            if key in _ARG_HIDDEN:
                continue
            if _SECRET_KEY_RE.search(key) and not isinstance(v, bool):
                out[key] = "<redacted>"
                continue
            out[key] = _clean_args(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        seq = list(value)
        items = [_clean_args(v, depth + 1) for v in seq[:_ARG_LIST_CAP]]
        if len(seq) > _ARG_LIST_CAP:
            items.append(f"… +{len(seq) - _ARG_LIST_CAP} more")
        return items
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    s = str(value)
    return s if len(s) <= _ARG_STR_CAP else s[:_ARG_STR_CAP] + "…"


def _call_target(args: dict[str, Any] | None) -> str:
    """The machine / view a tool call addressed, when its args name one."""
    for key in ("name", "machine", "alias"):
        v = (args or {}).get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()[:80]
    return ""


#: Beacon label / computer_name shape (NetBIOS names and operator aliases).
_BEACON_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
#: A beacon reporting more addresses than this is truncated.
_BEACON_MAX_IPV4 = 16


async def _json_body(req: Request) -> tuple[dict[str, Any] | None,
                                            JSONResponse | None]:
    """Parse a JSON object body. An empty body is ``{}``; a non-JSON
    Content-Type is 415 (CSRF: a cross-site form post can't send JSON);
    malformed JSON / a non-object is 400."""
    raw = await req.body()
    if not raw:
        return {}, None
    ctype = req.headers.get("content-type", "")
    if not _is_json(ctype):
        return None, JSONResponse(
            {"ok": False, "kind": "unsupported_media_type",
             "error": "body must be Content-Type: application/json"},
            status_code=415)
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None, JSONResponse({"ok": False, "error": "invalid json"},
                                  status_code=400)
    if not isinstance(body, dict):
        return None, JSONResponse(
            {"ok": False, "error": "body must be a JSON object"},
            status_code=400)
    return body, None


def _audit(ctx, action: str, args: dict[str, Any], *, ok: bool = True,
           error: str = "", req: Request | None = None) -> None:
    """Record a dashboard write in the tool log + persistent audit sink.
    Tokens never land in the row (``token_set`` instead)."""
    clean = {k: v for k, v in (args or {}).items() if k != "token"}
    if "token" in (args or {}):
        clean["token_set"] = bool(args.get("token"))
    peer = ""
    if req is not None and req.client is not None:
        peer = str(req.client.host or "")
    clean["_peer"] = peer
    clean["_current_owner"] = _DASH_OWNER
    try:
        ctx.session.record_tool_call("dashboard", action, args=clean,
                                     ok=ok, error=error)
    except Exception:  # noqa: BLE001 — audit must never fail the write
        pass


def _tag_list(value) -> list[str]:
    """Accept tags as a JSON list or a comma-separated string."""
    if isinstance(value, list):
        return [str(t).strip() for t in value if str(t).strip()]
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    return []


def _str_list(value) -> list[str]:
    """parser for alt_hosts (and any other free-form host/CIDR
    list). JSON list OR comma-separated string, same shape as _tag_list,
    but kept as a separate helper so the two input surfaces can diverge
    (e.g. CIDR validation) without entangling the tag parsing."""
    if isinstance(value, list):
        return [str(t).strip() for t in value if str(t).strip()]
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    return []


def register_dashboard_routes(app, ctx) -> None:  # noqa: ANN001 - FastAPI app
    @app.get("/health")
    @app.get("/healthz")
    async def health() -> JSONResponse:
        """T3.3: lightweight supervision probe. Unblocks the dashboard JS
        pill (static/app.js:154) which fetches /health and was 404'ing on
        the standalone dashboard app (/health lives on the main MCP app
        only — see server.py). Also serves external monitors / SCM
        failure-recovery health checks.

        Shape mirrors server.py's /health so monitors already pointed at
        the MCP port keep working against the dashboard port: ok,
        server_version, uptime_ms, driver_health (per-view probe), plus
        the tool_count / tools fields the dashboard JS reads for its pill.
        """
        sess = ctx.session
        tools: list[str] = []
        try:
            # Enumerate tool names from the Session's assertion allowlist
            # without touching FastMCP (the server lives on another mount).
            tools = sorted({c.tool for c in sess.tool_log if c.tool})
        except Exception:  # noqa: BLE001 — probe never fails /health
            tools = []
        return JSONResponse({
            "ok": True,
            "server_version": __version__,
            "version": __version__,
            "uptime_ms": _uptime_ms(),
            "driver_health": _probe_connected_views(sess),
            "tool_count": len(tools),
        })

    # view -> (monotonic ts, client object, driver_state, host_info, probe).
    # Keyed on the client object + driver_state too, so a reconnect or a
    # driver load/unload invalidates the entry instead of serving 30s of
    # stale posture.
    rich_cache: dict[str, tuple[float, Any, str, dict, dict]] = {}

    def _status_view(machine: str) -> str | None:
        """Which connected view /api/status describes: the requested
        machine's default view (kernel, else its first live view), else
        the dashboard focus, else the session primary. ``None`` when the
        caller named a machine that has no live view."""
        sess = ctx.session
        if not sess.clients:
            return None
        asked = (machine or "").strip()
        sel = asked
        if not sel:
            focus = sess.focus_of(_DASH_OWNER) or {}
            sel = str(focus.get("machine") or "")
        if sel:
            try:
                view = sess.resolve_view_name(sel, client_id=_DASH_OWNER)
            except Exception:  # noqa: BLE001 — unknown machine
                view = ""
            if view in sess.clients:
                return view
            if asked:
                return None
        primary = getattr(sess, "primary", None)
        if primary in sess.clients:
            return primary
        return next(iter(sess.clients))

    async def _rich(view: str, client, driver_state: str,
                    refresh: bool) -> tuple[dict, dict, float]:
        """HostInfo + pry-driver probe for *view*, cached ``_RICH_TTL_S``."""
        now = time.monotonic()
        hit = rich_cache.get(view)
        if (hit is not None and not refresh and hit[1] is client
                and hit[2] == driver_state and now - hit[0] < _RICH_TTL_S):
            return hit[3], hit[4], now - hit[0]
        try:
            hi = await client.host_info(include_hardware=False)
        except Exception as exc:  # noqa: BLE001
            hi = {"ok": False, "error": str(exc)}
        try:
            from ..mcp._pry_driver_probe import probe_pry_driver
            probe = await probe_pry_driver(client, driver_state=driver_state)
        except Exception as exc:  # noqa: BLE001
            probe = {"ok": False, "error": f"probe failed: {exc}"}
        rich_cache[view] = (time.monotonic(), client, driver_state, hi, probe)
        return hi, probe, 0.0

    @app.get("/api/status")
    async def status(machine: str = "", refresh: bool = False) -> JSONResponse:
        sess = ctx.session
        view = _status_view(machine)
        out = {
            "connected": sess.connected,
            "views_connected": len(sess.clients),
            "target": sess.cfg.target_endpoint,
            "active_ida_sessions": ctx.bridge.sessions,
            "tool_calls": len(sess.tool_log),
            "view": view,
            "machine": sess.machine_of(view) if view else (machine or None),
        }
        client = sess.clients.get(view) if view else None
        for stale in [v for v in rich_cache if v not in sess.clients]:
            rich_cache.pop(stale, None)
        if client is not None:
            try:
                agent = await client.status()
            except Exception as exc:
                out["agent_error"] = str(exc)
                return JSONResponse(out)
            # Enrich the slim agent status with
            # host_info security fields + the pry-driver health probe
            # so the dashboard shows HVCI / driver_blocklist / KVA shadow /
            # PC uptime and explains WHY driver_state might be ABSENT.
            driver_present = str(agent.get("driver_state", "")).upper() in (
                "DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED", "SERVICE", "MANUAL_MAPPED")
            agent["driver_present"] = driver_present
            hi, probe, age = await _rich(
                view, client, str(agent.get("driver_state") or ""), refresh)
            out["rich_age_s"] = round(age, 1)
            if hi.get("ok"):
                sec = hi.get("security") or {}
                uptime = hi.get("uptime") or {}
                # Overwrite HVCI with the host_info-verified value.
                hvci_pair = sec.get("hvci")
                if isinstance(hvci_pair, dict) and hvci_pair.get("source") not in (
                        None, "unknown"):
                    agent["hvci"] = hvci_pair
                agent["memory_integrity"] = hvci_pair
                agent["driver_blocklist_on"] = sec.get("driver_blocklist_on")
                agent["kva_shadow"] = sec.get("kva_shadow")
                agent["vbs_enabled"] = sec.get("vbs_enabled")
                agent["credential_guard"] = sec.get("credential_guard")
                agent["lsa_protected"] = sec.get("lsa_protected")
                agent["kernel_debugger"] = sec.get("kernel_debugger")
                agent["secureboot"] = sec.get("secureboot")
                agent["patchguard_state"] = sec.get("patchguard_state")
                agent["pc_uptime_ms"] = uptime.get("pc_uptime_ms")
                agent["service_uptime_ms"] = uptime.get("service_uptime_ms")
                agent["boot_time"] = (hi.get("os") or {}).get("boot_time")
                agent["os"] = hi.get("os") or agent.get("os")
                agent["identity"] = hi.get("identity") or {}
            else:
                agent["host_info_hint"] = ("HostInfo RPC unavailable "
                                            "(agent < v8?) — rich fields skipped")
            # Pry-driver health explains DRIVER_ABSENT.
            agent["pry_driver_health"] = probe
            out["agent"] = agent
        return JSONResponse(out)

    @app.get("/api/findings")
    async def findings() -> JSONResponse:
        return JSONResponse([f.__dict__ for f in ctx.ledger.list_findings()])

    @app.get("/api/toollog")
    async def toollog(limit: int = 200) -> JSONResponse:
        n = max(1, min(int(limit or 200), 500))
        return JSONResponse([
            {
                "tool": c.tool,
                "action": c.action,
                "destructive": c.destructive,
                "ok": c.ok,
                "error": c.error,
                "ts": c.ts,
                "target": _call_target(c.args),
                "args": _clean_args(c.args or {}),
            }
            for c in ctx.session.tool_log[-n:]
        ])

    # -------------------------------------------------------- machines ----

    def _machine_rows() -> list[dict]:
        """Every known machine (registry + YAML + live) with its
        describe() block and connected view kinds — mirrors
        target_manage(action='machines')."""
        reg = ctx.registry
        rows: list[dict] = []
        seen: set[str] = set()
        live = ctx.session.machines()
        # Per-view live state (dialled endpoint, last answer age) so a
        # card shows the address actually in use, not just the registry's.
        probes: dict[str, list[dict]] = {}
        for p in _probe_connected_views(ctx.session):
            probes.setdefault(p["machine"], []).append(p)
        # The same verdict "Clean up empty shells" would act on (dry run:
        # read-only), so the UI can fold shells away without guessing.
        try:
            shells = {a.lower() for a in reg.prune_empty_shells(
                session_machines=live, dry_run=True).get("removed", [])}
        except Exception:  # noqa: BLE001 — cosmetic only
            shells = set()

        def _row(alias: str) -> dict:
            r = reg.describe(alias, cfg=ctx.cfg) or {"machine": alias}
            label = str(r.get("machine") or alias)
            views = live.get(label, [])
            r["connected_views"] = sorted(
                ctx.session.view_kind_of(v) for v in views)
            r["connected"] = bool(views)
            r["live"] = probes.get(label, [])
            r["shell"] = alias.lower() in shells or label.lower() in shells
            return r

        for a in list(reg.all().keys()) + list(
                (getattr(ctx.cfg, "machines", None) or {}).keys()):
            if a.lower() not in seen:
                seen.add(a.lower())
                rows.append(_row(a))
        for m in sorted(live):
            if m.lower() not in seen:
                seen.add(m.lower())
                rows.append(_row(m))
        if not rows and ctx.cfg.target.host:
            rows.append(_row("default"))
        return rows

    @app.get("/api/machines")
    async def machines_list() -> JSONResponse:
        return JSONResponse({
            "ok": True,
            "machines": _machine_rows(),
            "min_trust_actuator": getattr(
                ctx.cfg.security, "min_trust_actuator", "untrusted"),
            "focus": ctx.session.focus_of(_DASH_OWNER),
        })

    @app.post("/api/machines")
    async def machines_register(req: Request) -> JSONResponse:
        body, bad = await _json_body(req)
        if bad is not None:
            return bad
        alias = str(body.get("alias") or body.get("machine") or "").strip()
        if not alias:
            return JSONResponse({"ok": False, "error": "alias is required"},
                                status_code=400)
        try:
            info = ctx.registry.register(
                alias,
                host=str(body.get("host") or ""),
                kernel_port=int(body.get("kernel_port") or body.get("port") or 0),
                user_port=int(body.get("user_port") or 0),
                token=str(body.get("token") or ""),
                trust=str(body.get("trust") or ""),
                purpose=str(body.get("purpose") or ""),
                note=str(body.get("note") or ""),
                operator=str(body.get("operator") or ""),
                tags=_tag_list(body.get("tags")),
                computer_name=str(body.get("computer_name") or ""),
                alt_hosts=_str_list(body.get("alt_hosts")),
                force=bool(body.get("force")),
            )
        except (ValueError, TypeError) as exc:
            _audit(ctx, "machines_register", {"alias": alias, **body},
                   ok=False, error=str(exc), req=req)
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        _audit(ctx, "machines_register", {"alias": alias, **body}, req=req)
        return JSONResponse({"ok": True, "machine_info": info})

    @app.post("/api/machines/prune")
    async def machines_prune(req: Request) -> JSONResponse:
        """PR#8: sweep alias-only shell entries that past releases minted
        behind the operator's back. Honours the live view set — a shell
        with a currently connected view is held back under
        ``kept_connected``. ``dry_run=True`` previews the report without
        touching the registry file. Must be registered before the
        ``POST /api/machines/{alias}`` route below so Starlette doesn't
        route the literal ``prune`` path into ``machines_set``."""
        body, bad = await _json_body(req)
        if bad is not None:
            if bad.status_code == 415:
                return bad
            body = {}
        # Safety: default to dry_run=True when the body is missing or omits
        # the key. A bare POST (buggy curl, double-click, preflight retry)
        # should preview, never nuke the registry. The dashboard button
        # sends an explicit `dry_run: false` on the apply step.
        dry_run = bool(body.get("dry_run", True))
        live = ctx.session.machines()
        try:
            result = ctx.registry.prune_empty_shells(
                session_machines=live, dry_run=dry_run)
        except (ValueError, TypeError) as exc:
            if not dry_run:
                _audit(ctx, "machines_prune", {"dry_run": False},
                       ok=False, error=str(exc), req=req)
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        if not dry_run:
            _audit(ctx, "machines_prune",
                   {"dry_run": False, "removed": result.get("removed")},
                   req=req)
        return JSONResponse({"ok": True, **result})

    @app.post("/api/agent_report")
    async def agent_report(req: Request) -> JSONResponse:
        """T1.1d — agent phone-home intake. The agent POSTs its endpoint
        (hostname, port, filtered private-range IPv4 set, boot epoch,
        instance id) every 30s and on IPv4-set change. Each observed
        host is recorded against ``registry.observed_endpoints(label)``
        with ``allow_create=True`` — the phone-home path is explicitly
        allowed to mint a brand-new registry entry (prior PR#8 reserved
        implicit shell creation for user-driven paths; this is the
        agent-driven counterpart). Must be registered before
        ``POST /api/machines/{alias}`` so Starlette doesn't route the
        literal ``agent_report`` path into ``machines_set``.

        The beacon carries both ``machine_label`` (operator-chosen
        when the agent was launched with --machine-label) AND
        ``computer_name`` (Windows NetBIOS, stable across NIC/MAC flaps).
        ``record_observed_endpoint`` now reverse-looks-up by
        ``computer_name`` before minting a shell, so a beacon arriving as
        ``DESKTOP-ABC`` is attributed to the operator's alias ``lab2``
        when ``lab2`` was registered with ``computer_name='DESKTOP-ABC'``.
        """
        body, bad = await _json_body(req)
        if bad is not None:
            return bad
        label = str(body.get("machine_label")
                    or body.get("computer_name") or "").strip()
        computer_name = str(body.get("computer_name") or "").strip()
        # this route is reachable from the whole LAN without
        # auth (the agent has no secret to send) — validate everything.
        try:
            port = int(body.get("port") or 0)
            boot = int(body.get("boot_epoch_ms") or 0)
        except (TypeError, ValueError):
            return JSONResponse(
                {"ok": False, "error": "port / boot_epoch_ms must be integers"},
                status_code=400)
        raw_ips = body.get("ipv4") or []
        if not isinstance(raw_ips, list):
            raw_ips = []
        ipv4: list[str] = []
        for a in raw_ips[:_BEACON_MAX_IPV4]:
            sa = str(a or "").strip()
            if sa and usable_ipv4(sa) and sa not in ipv4:
                ipv4.append(sa)
        if not label or not port or not ipv4:
            return JSONResponse(
                {"ok": False, "error": "label, port, and ipv4 required"},
                status_code=400)
        for what, val in (("machine_label/computer_name", label),
                          ("computer_name", computer_name)):
            if val and not _BEACON_LABEL_RE.match(val):
                return JSONResponse(
                    {"ok": False, "error": f"invalid {what} {val[:80]!r}"},
                    status_code=400)
        if not (0 < port < 65536) or boot < 0:
            return JSONResponse(
                {"ok": False, "error": "port must be 1..65535, "
                                       "boot_epoch_ms >= 0"},
                status_code=400)
        known = ctx.registry.is_known_label(label, computer_name)
        if not known:
            cap = int(getattr(getattr(ctx.cfg, "mcp", None),
                              "beacon_max_new_machines", 16) or 0)
            if ctx.registry.beacon_minted_count() >= cap:
                _audit(ctx, "agent_report_refused",
                       {"label": label, "computer_name": computer_name,
                        "port": port, "ipv4": ipv4, "reason": "beacon_cap"},
                       ok=False, error="beacon cap reached", req=req)
                return JSONResponse(
                    {"ok": False, "kind": "beacon_cap",
                     "error": (f"refusing to mint machine {label!r}: "
                               f"{cap} beacon-created entries already exist "
                               "(mcp.beacon_max_new_machines); register it "
                               "with machines_manage(action='register') or "
                               "prune unused ones")},
                    status_code=429)
        # resolve the beacon label to an owning alias up-front so
        # the response can echo back which registry entry got updated.
        # The record call below also does this per-host, but doing it once
        # here keeps the status payload honest when the beacon's label
        # differs from the resolved alias.
        resolved = (
            ctx.registry.find_alias_by_computer_name(computer_name)
            or ctx.registry.find_alias_by_computer_name(label)
            or label)
        # One registry write per beacon (it used to save once per IP).
        ctx.registry.record_observed_endpoints(
            label, hosts=ipv4, port=port, boot_epoch_ms=boot,
            allow_create=True, fallback_computer_name=computer_name,
            origin="beacon")
        if not known:
            _audit(ctx, "agent_report_mint",
                   {"label": label, "computer_name": computer_name,
                    "port": port, "ipv4": ipv4}, req=req)
        return JSONResponse({"ok": True, "updated": resolved,
                             "beacon_label": label,
                             "endpoints": len(ipv4)})

    @app.post("/api/machines/{alias}")
    async def machines_set(alias: str, req: Request) -> JSONResponse:
        body, bad = await _json_body(req)
        if bad is not None:
            return bad

        def _opt(key, cast=str):
            v = body.get(key)
            if v in (None, ""):
                return None
            try:
                return cast(v)
            except (ValueError, TypeError):
                return None

        # The edit form always prefills host/ports and submits them
        # unchanged. Registry.set treats ANY endpoint field as an endpoint
        # write, which YAML aliases reject (reviewed config) — so a pure
        # metadata edit (note/purpose/trust/tags) 400'd and "Save did
        # nothing". Drop endpoint fields that match the current effective
        # values; only real changes count.
        cur = ctx.registry.describe(alias, cfg=ctx.cfg) or {}
        cur_eps = cur.get("endpoints") or {}
        cur_kh, _, cur_kp = (cur_eps.get("kernel") or "").rpartition(":")
        cur_uh, _, cur_up = (cur_eps.get("user") or "").rpartition(":")
        host = _opt("host")
        kport = _opt("kernel_port", int) or _opt("port", int)
        uport = _opt("user_port", int)
        if host is not None and str(host) == str(cur_kh or ""):
            host = None
        if kport is not None and int(kport) == int(cur_kp or 0):
            kport = None
        if uport is not None and int(uport) == int(cur_up or 0):
            uport = None

        # Present-but-empty CLEARS a metadata field (the form sends every
        # key on every submit; _opt swallowing "" made clearing notes
        # impossible — save "did nothing"). Absent key = no change.
        def _meta(key):
            v = body.get(key)
            return None if v is None else str(v)

        try:
            info = ctx.registry.set(
                alias,
                host=host,
                kernel_port=kport,
                user_port=uport,
                token=_opt("token"),
                trust=_opt("trust"),
                purpose=_meta("purpose"),
                note=_meta("note"),
                operator=_meta("operator"),
                tags=_tag_list(body["tags"]) if "tags" in body else None,
                computer_name=(_meta("computer_name")
                               if "computer_name" in body else None),
                alt_hosts=(_str_list(body["alt_hosts"])
                           if "alt_hosts" in body else None),
                force=bool(body.get("force")),
            )
        except (ValueError, TypeError) as exc:
            _audit(ctx, "machines_set", {"alias": alias, **body}, ok=False,
                   error=str(exc), req=req)
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        _audit(ctx, "machines_set", {"alias": alias, **body}, req=req)
        return JSONResponse({"ok": True, "machine_info": info})

    @app.delete("/api/machines/{alias}")
    async def machines_unregister(alias: str, req: Request,
                                  force: bool = False) -> JSONResponse:
        try:
            removed = ctx.registry.unregister(alias, force=force)
        except (ValueError, TypeError) as exc:
            _audit(ctx, "machines_unregister", {"alias": alias,
                                                "force": force},
                   ok=False, error=str(exc), req=req)
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        # A machine card can outlive its registry entry while a session
        # still holds a live view of it (k223/k225 on the lab LAN: the
        # registry entries were gone, the cards stayed because the views
        # were connected). "Delete" clears both: the entry AND any live
        # views (owner=None — management override, same as Disconnect).
        dropped: list[str] = []
        for view in list(ctx.session.machines().get(alias, [])):
            try:
                r = await ctx.session.disconnect(view, owner=None)
                dropped.extend(r.get("disconnected", []))
            except Exception:  # noqa: BLE001 — best-effort
                pass
        _audit(ctx, "machines_unregister",
               {"alias": alias, "force": force, "removed": removed,
                "disconnected": dropped}, req=req)
        return JSONResponse({"ok": True, "machine": alias,
                             "removed": removed, "disconnected": dropped})

    @app.post("/api/machines/{alias}/connect")
    async def machine_connect(alias: str, req: Request) -> JSONResponse:
        body, bad = await _json_body(req)
        if bad is not None:
            if bad.status_code == 415:
                return bad
            body = {}
        views = str(body.get("views") or "kernel").strip().lower()
        kinds = list(VIEW_KINDS) if views in ("both", "all") \
            else [views if views in VIEW_KINDS else "kernel"]
        out: dict = {"ok": True, "views": {}}
        for kind in kinds:
            sel = f"{alias}.{kind}"
            try:
                st = await ctx.session.connect(
                    None, None, None, name=sel, machine=alias,
                    owner=_DASH_OWNER, force=bool(body.get("force")))
                view = st.get("view") or sel
                out["views"][kind] = {
                    "ok": True,
                    "view": view,
                    "endpoint": getattr(
                        ctx.session.clients.get(view), "endpoint", ""),
                }
                # dashboard-connected views get the same boot
                # monitor + debug-event pump an MCP connect starts.
                try:
                    from ..mcp.tools.target._runtime import (
                        _maybe_start_boot_monitor,
                    )
                    ctx.start_event_pump(view)
                    _maybe_start_boot_monitor(ctx, view)
                except Exception:  # noqa: BLE001 — best-effort
                    pass
            except KeyError as exc:
                out["views"][kind] = {"ok": False, "skipped": True,
                                      "error": str(exc)}
            except Exception as exc:  # noqa: BLE001 — per-view
                out["ok"] = False
                out["views"][kind] = {"ok": False, "error": str(exc)}
        _audit(ctx, "machine_connect",
               {"alias": alias, "views": views, "force": bool(body.get("force")),
                "result": {k: v.get("ok") for k, v in out["views"].items()}},
               ok=bool(out.get("ok")), req=req)
        return JSONResponse(out)

    @app.post("/api/machines/{alias}/disconnect")
    async def machine_disconnect(alias: str, req: Request) -> JSONResponse:
        # Drop every connected view of this machine. owner=None force-closes
        # the named view regardless of which peer connected it — the
        # dashboard "Disconnect" button is a management override.
        live = ctx.session.machines().get(alias, [])
        if not live:
            return JSONResponse({"ok": True, "disconnected": [],
                                 "note": "no connected views"})
        dropped: list[str] = []
        for view in list(live):
            try:
                r = await ctx.session.disconnect(view, owner=None)
                dropped.extend(r.get("disconnected", []))
            except Exception as exc:  # noqa: BLE001
                _audit(ctx, "machine_disconnect", {"alias": alias},
                       ok=False, error=str(exc), req=req)
                return JSONResponse({"ok": False, "error": str(exc)},
                                    status_code=400)
        _audit(ctx, "machine_disconnect",
               {"alias": alias, "disconnected": dropped}, req=req)
        return JSONResponse({"ok": True, "disconnected": dropped})

    @app.post("/api/machines/{alias}/use")
    async def machine_use(alias: str) -> JSONResponse:
        try:
            if alias.lower() in ("none", "off", "clear"):
                return JSONResponse({"ok": True, "focus": None,
                                     "cleared": ctx.session.clear_focus(
                                         _DASH_OWNER)})
            focus = ctx.session.set_focus(_DASH_OWNER, alias)
        except (RuntimeError, ValueError) as exc:
            return JSONResponse({"ok": False, "error": str(exc)},
                                status_code=400)
        return JSONResponse({"ok": True, "focus": focus})

    # ------------------------------------------------------- websocket ----

    @app.websocket("/ws")
    async def ws(ws: WebSocket) -> None:  # noqa: ANN001
        # a browser always sends Origin on the WS handshake; a
        # cross-site page must not be able to read the live event feed.
        origin = ws.headers.get("origin")
        if origin is not None and not ControlPlaneGuard.origin_allowed(
                origin, ws.headers.get("host")):
            await ws.close(code=1008)
            return
        await ws.accept()
        sub_id = None
        queue = None
        sub_bus = None      # the bus WE subscribed to — never another's

        def _resubscribe() -> None:
            nonlocal sub_id, queue, sub_bus
            client = ctx.session.client
            bus = getattr(client, "bus", None) if client is not None else None
            if bus is sub_bus:
                return
            if sub_bus is not None and sub_id is not None:
                sub_bus.unsubscribe(sub_id)
            sub_id, queue, sub_bus = None, None, None
            if bus is not None:
                sub_id, queue = bus.subscribe()
                sub_bus = bus

        _resubscribe()
        try:
            while True:
                # The primary view can change (reconnect, another machine):
                # follow it without leaking or stealing a subscription.
                _resubscribe()
                payload = {
                    "type": "snapshot",
                    "connected": ctx.session.connected,
                    "toollog": [
                        {"tool": c.tool, "action": c.action, "destructive": c.destructive,
                         "ok": c.ok, "error": c.error, "ts": c.ts}
                        for c in ctx.session.tool_log[-30:]
                    ],
                    "events": [e.data for e in ctx.session.client.bus.recent[-30:]]
                    if ctx.session.client else [],
                    "ida_sessions": ctx.bridge.sessions,
                }
                await ws.send_text(json.dumps(payload))
                if queue is not None:
                    try:
                        await asyncio.wait_for(queue.get(), timeout=1.0)
                    except asyncio.TimeoutError:
                        pass
                else:
                    await asyncio.sleep(1.0)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            if sub_id is not None and sub_bus is not None:
                sub_bus.unsubscribe(sub_id)

    # Always revalidate the static assets. They are tiny and change on
    # every dashboard edit; without this a browser heuristically caches
    # app.js/style.css and serves a stale build against a fresh index.html
    # (new layout, dead panels). ETag/Last-Modified still make the
    # revalidation a cheap 304 when nothing changed.
    _NO_CACHE = {"Cache-Control": "no-cache"}

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers=_NO_CACHE)

    @app.get("/app.js")
    async def app_js() -> FileResponse:
        return FileResponse(STATIC_DIR / "app.js", media_type="text/javascript",
                            headers=_NO_CACHE)

    @app.get("/style.css")
    async def style_css() -> FileResponse:
        return FileResponse(STATIC_DIR / "style.css", media_type="text/css",
                            headers=_NO_CACHE)

    @app.get("/favicon.svg")
    async def favicon() -> FileResponse:
        return FileResponse(STATIC_DIR / "mark.svg",
                            media_type="image/svg+xml", headers=_NO_CACHE)
