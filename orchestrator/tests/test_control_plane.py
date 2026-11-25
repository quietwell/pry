"""The orchestrator control plane.

The listener binds 0.0.0.0 so lab agents can phone home, so everything but
``/api/agent_report`` must refuse non-loopback peers, and loopback requests
must survive DNS rebinding / CSRF (Host, Origin, Content-Type) checks.
"""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pry.config import PryConfig, TargetConfig
from pry.dashboard.api import register_dashboard_routes
from pry.dashboard.control_plane import ControlPlaneGuard
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.mcp.tools import Context
from pry.session import Session

LAN = ("192.168.2.50", 51000)
LOOP = ("127.0.0.1", 51000)
BEACON = {"machine_label": "lab2", "computer_name": "LAB2-WIN",
          "port": 50074, "ipv4": ["192.168.2.36", "192.168.2.37"],
          "boot_epoch_ms": 1_700_000_000_000}


def _ctx(tmp_path, monkeypatch, **mcp):
    monkeypatch.setenv("PRY_AUDIT_DISABLE", "1")
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=50099)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    for k, v in mcp.items():
        setattr(cfg.mcp, k, v)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    return Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge)


def _app(ctx, guarded: bool = True):
    app = FastAPI()
    register_dashboard_routes(app, ctx)

    @app.post("/mcp")
    async def _mcp() -> dict:          # stand-in for the mounted MCP app
        return {"ok": True}

    if guarded:
        app.add_middleware(ControlPlaneGuard, cfg=ctx.cfg)
    return app


def _client(app, peer, **kw):
    return TestClient(app, client=peer, base_url="http://127.0.0.1:8765", **kw)


# --------------------------------------------------------------------------- #
# who may talk to it
# --------------------------------------------------------------------------- #

def test_lan_peer_reaches_only_the_beacon(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    with _client(_app(ctx), LAN) as c:
        assert c.post("/api/agent_report", json=BEACON).status_code == 200
        for method, path in (("post", "/mcp"), ("get", "/api/machines"),
                             ("get", "/health"), ("get", "/"),
                             ("post", "/api/machines/prune"),
                             ("delete", "/api/machines/lab2")):
            r = getattr(c, method)(path)
            assert r.status_code == 403, (method, path, r.status_code)
            assert r.json()["kind"] == "forbidden"
        assert c.get("/api/agent_report").status_code == 405
        r = c.post("/api/agent_report", content=json.dumps(BEACON),
                   headers={"content-type": "text/plain"})
        assert r.status_code == 415


def test_remote_cidrs_admit_a_listed_network(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, remote_cidrs=["192.168.2.0/24"])
    with _client(_app(ctx), LAN) as c:
        assert c.get("/api/machines").status_code == 200
    with _client(_app(ctx), ("10.1.1.1", 4)) as c:
        assert c.get("/api/machines").status_code == 403


def test_loopback_v6_and_mapped_v4_are_loopback(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    for peer in (("::1", 5), ("::ffff:127.0.0.1", 5)):
        with _client(_app(ctx), peer) as c:
            assert c.get("/api/machines").status_code == 200, peer


# --------------------------------------------------------------------------- #
# DNS rebinding / CSRF on loopback
# --------------------------------------------------------------------------- #

def test_foreign_host_header_is_refused(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    with _client(_app(ctx), LOOP) as c:
        r = c.get("/api/machines", headers={"host": "evil.example:8765"})
        assert r.status_code == 403 and r.json()["kind"] == "forbidden_host"
        assert c.get("/api/machines",
                     headers={"host": "localhost:8765"}).status_code == 200
        assert c.get("/api/machines",
                     headers={"host": "127.0.0.1:8765"}).status_code == 200


def test_allowed_hosts_extends_the_host_check(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, allowed_hosts=["devbox.lab"])
    with _client(_app(ctx), LOOP) as c:
        assert c.get("/api/machines",
                     headers={"host": "devbox.lab:8765"}).status_code == 200


def test_cross_origin_post_is_refused_same_origin_allowed(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    with _client(_app(ctx), LOOP) as c:
        r = c.post("/api/machines/prune", json={"dry_run": True},
                   headers={"origin": "http://attacker.example"})
        assert r.status_code == 403 and r.json()["kind"] == "forbidden_origin"
        r = c.post("/api/machines/prune", json={"dry_run": True},
                   headers={"origin": "http://127.0.0.1:8765"})
        assert r.status_code == 200
        r = c.post("/api/machines/prune", json={"dry_run": True},
                   headers={"origin": "null"})
        assert r.status_code == 403


def test_non_json_post_is_refused(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    with _client(_app(ctx), LOOP) as c:
        r = c.post("/api/machines/lab2/disconnect", content=b"a=1",
                   headers={"content-type": "application/x-www-form-urlencoded"})
        assert r.status_code == 415
        # a browser POST without a body/content type but with an Origin
        r = c.post("/api/machines/lab2/disconnect",
                   headers={"origin": "http://127.0.0.1:8765"})
        assert r.status_code == 415
        # a non-browser empty POST (curl / the dashboard prune preview) is fine
        assert c.post("/api/machines/prune").status_code == 200


def test_route_level_json_check_without_the_guard(tmp_path, monkeypatch):
    """Even with no guard in front, a form post can't drive a registry write."""
    ctx = _ctx(tmp_path, monkeypatch)
    with _client(_app(ctx, guarded=False), LOOP) as c:
        r = c.post("/api/machines", content=b"alias=x",
                   headers={"content-type": "application/x-www-form-urlencoded"})
        assert r.status_code == 415
        assert "x" not in ctx.registry.all()


def test_websocket_rejects_a_foreign_origin(tmp_path, monkeypatch):
    from starlette.websockets import WebSocketDisconnect
    # Starlette's TestClient always sends 'Host: testserver' on websockets.
    ctx = _ctx(tmp_path, monkeypatch, allowed_hosts=["testserver"])
    with _client(_app(ctx), LOOP) as c:
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect(
                    "/ws", headers={"origin": "http://attacker.example"}) as ws:
                ws.receive_text()
        with c.websocket_connect(
                "/ws", headers={"origin": "http://testserver"}) as ws:
            assert json.loads(ws.receive_text())["type"] == "snapshot"


def test_websocket_route_checks_origin_without_the_guard(tmp_path, monkeypatch):
    from starlette.websockets import WebSocketDisconnect
    ctx = _ctx(tmp_path, monkeypatch)
    with _client(_app(ctx, guarded=False), LOOP) as c:
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect(
                    "/ws", headers={"origin": "http://attacker.example"}) as ws:
                ws.receive_text()


# --------------------------------------------------------------------------- #
# bearer token
# --------------------------------------------------------------------------- #

def test_bearer_token_required_except_for_the_beacon(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, auth_token="s3cret")
    with _client(_app(ctx), LOOP) as c:
        assert c.get("/api/machines").status_code == 401
        assert c.post("/mcp", json={}).status_code == 401
        assert c.get("/api/machines", headers={
            "authorization": "Bearer wrong"}).status_code == 401
        assert c.get("/api/machines", headers={
            "authorization": "Bearer s3cret"}).status_code == 200
        assert c.post("/api/agent_report", json=BEACON).status_code == 200


def test_browser_login_sets_a_strict_cookie(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, auth_token="s3cret")
    with _client(_app(ctx), LOOP, follow_redirects=False) as c:
        r = c.get("/?token=s3cret")
        assert r.status_code == 303 and r.headers["location"] == "/"
        cookie = r.headers["set-cookie"]
        assert "pry_token=s3cret" in cookie
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
        # the client's cookie jar now carries the login
        assert c.get("/api/machines").status_code == 200
    with _client(_app(ctx), LOOP, follow_redirects=False) as fresh:
        assert fresh.get("/?token=nope").status_code == 401
        assert fresh.get("/api/machines", headers={
            "cookie": "pry_token=s3cret"}).status_code == 200


def test_token_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_TEST_MCP_TOKEN", "fromenv")
    ctx = _ctx(tmp_path, monkeypatch, auth_token="${PRY_TEST_MCP_TOKEN}")
    with _client(_app(ctx), LOOP) as c:
        assert c.get("/api/machines", headers={
            "authorization": "Bearer fromenv"}).status_code == 200


# --------------------------------------------------------------------------- #
# the beacon route itself
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("label", ["bad label", "../../x", "a" * 80, "lab2;rm"])
def test_beacon_rejects_bad_labels(tmp_path, monkeypatch, label):
    ctx = _ctx(tmp_path, monkeypatch)
    with _client(_app(ctx), LAN) as c:
        r = c.post("/api/agent_report", json={**BEACON, "machine_label": label})
    assert r.status_code == 400
    assert ctx.registry.all() == {}


def test_beacon_drops_unusable_addresses_and_caps_the_list(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    ips = ["127.0.0.1", "169.254.1.1", "not-an-ip", "0.0.0.0"] + \
        [f"10.0.0.{i}" for i in range(1, 40)]
    with _client(_app(ctx), LAN) as c:
        r = c.post("/api/agent_report", json={**BEACON, "ipv4": ips})
    assert r.status_code == 200
    hosts = [o["host"] for o in ctx.registry.observed_endpoints("lab2")]
    assert "127.0.0.1" not in hosts and "169.254.1.1" not in hosts
    assert all(h.startswith("10.0.0.") for h in hosts)


def test_beacon_saves_once_per_report(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    reg = ctx.registry
    saves = []
    real = reg._save
    monkeypatch.setattr(reg, "_save", lambda: (saves.append(1), real())[1])
    with _client(_app(ctx), LAN) as c:
        assert c.post("/api/agent_report", json={
            **BEACON, "ipv4": ["10.0.0.1", "10.0.0.2", "10.0.0.3"]}
        ).status_code == 200
    assert len(saves) == 1
    assert len(reg.observed_endpoints("lab2")) == 3


def test_beacon_creation_is_capped(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch, beacon_max_new_machines=2)
    with _client(_app(ctx), LAN) as c:
        for i in range(2):
            assert c.post("/api/agent_report", json={
                **BEACON, "machine_label": f"box{i}", "computer_name": ""}
            ).status_code == 200
        r = c.post("/api/agent_report", json={
            **BEACON, "machine_label": "box9", "computer_name": ""})
        assert r.status_code == 429 and r.json()["kind"] == "beacon_cap"
        # an already-known machine keeps reporting past the cap
        assert c.post("/api/agent_report", json={
            **BEACON, "machine_label": "box0", "computer_name": "",
            "ipv4": ["10.0.0.99"]}).status_code == 200
    assert "box9" not in ctx.registry.all()
    assert ctx.registry.all()["box0"]["origin"] == "beacon"


def test_dashboard_writes_are_audited_without_tokens(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    with _client(_app(ctx), LOOP) as c:
        assert c.post("/api/machines", json={
            "alias": "lab9", "host": "127.0.0.9", "kernel_port": 50074,
            "token": "supersecret", "trust": "lab"}).status_code == 200
        assert c.post("/api/machines/lab9", json={
            "note": "hello"}).status_code == 200
    rows = [t for t in ctx.session.tool_log if t.tool == "dashboard"]
    assert [t.action for t in rows] == ["machines_register", "machines_set"]
    reg_row = rows[0]
    assert reg_row.args["token_set"] is True
    assert "token" not in reg_row.args
    assert "supersecret" not in json.dumps(reg_row.args)
    assert reg_row.args["_peer"] == "127.0.0.1"
