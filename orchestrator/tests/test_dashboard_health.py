"""T3.3: /health + /healthz endpoints on the dashboard app.

The dashboard JS (static/app.js:154) fetches /health unconditionally;
before T3.3 the standalone dashboard app had no such route, so the
"version" pill 404'd silently. These tests cover the shape the pill +
external monitors read, the module-level uptime anchor, and the
per-view probe helper.

No live MCP, no gRPC, no AgentClient round-trip — the probe reads only
what the orchestrator already tracks on `Session.clients[view]`.
"""
from __future__ import annotations

import time
import types

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pry.config import PryConfig, TargetConfig
from pry.dashboard.api import (
    _probe_connected_views,
    _uptime_ms,
    register_dashboard_routes,
)
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.mcp.tools import Context
from pry.session import Session


def _build_ctx(tmp_path):
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=50099)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge)
    return ctx


def _app_for(ctx):
    app = FastAPI()
    register_dashboard_routes(app, ctx)
    return app


def test_health_endpoint_shape(tmp_path):
    ctx = _build_ctx(tmp_path)
    with TestClient(_app_for(ctx)) as client:
        for path in ("/health", "/healthz"):
            resp = client.get(path)
            assert resp.status_code == 200, path
            body = resp.json()
            assert body["ok"] is True
            # Keys the T3.3 plan calls out explicitly:
            assert "driver_health" in body
            assert isinstance(body["driver_health"], list)
            assert "uptime_ms" in body
            assert isinstance(body["uptime_ms"], int)
            assert body["uptime_ms"] >= 0
            assert "version" in body
            # Dashboard JS (app.js:154) reads these two:
            assert "server_version" in body
            assert "tool_count" in body


def test_health_uptime_is_monotonic(tmp_path):
    ctx = _build_ctx(tmp_path)
    with TestClient(_app_for(ctx)) as client:
        first = client.get("/health").json()["uptime_ms"]
        # A no-op sleep makes the second sample strictly larger on every
        # reasonable platform. If the host is so slow it can't advance a
        # millisecond, `>=` still holds.
        time.sleep(0.01)
        second = client.get("/health").json()["uptime_ms"]
    assert second >= first
    assert _uptime_ms() >= second - 1  # module-level helper agrees


def test_probe_empty_when_no_views(tmp_path):
    ctx = _build_ctx(tmp_path)
    assert _probe_connected_views(ctx.session) == []


def test_probe_surfaces_connected_view_fields(tmp_path):
    """_probe_connected_views reads session.clients without an RPC. Inject
    a stand-in AgentClient-shaped stub so we can assert the row shape in
    isolation (no gRPC, no agent)."""
    ctx = _build_ctx(tmp_path)
    now = time.time()
    stub = types.SimpleNamespace(
        endpoint="192.168.56.10:50099",
        last_seen_ts=now - 2.0,     # 2s ago -> 'connected'
        last_op_ts=now - 2.0,
        _inflight_count=3,
    )
    ctx.session.clients["lab2.kernel"] = stub  # type: ignore[assignment]
    rows = _probe_connected_views(ctx.session)
    assert len(rows) == 1
    row = rows[0]
    assert row["view"] == "lab2.kernel"
    assert row["machine"] == "lab2"
    assert row["kind"] == "kernel"
    assert row["endpoint"] == "192.168.56.10:50099"
    assert row["state"] == "connected"
    assert row["last_rtt_ms"] is not None
    assert row["last_rtt_ms"] < 10_000  # 2s ago, under the 60s stale cutoff
    assert row["inflight"] == 3


def test_probe_marks_stale_view(tmp_path):
    ctx = _build_ctx(tmp_path)
    stub = types.SimpleNamespace(
        endpoint="192.168.56.10:50099",
        last_seen_ts=time.time() - 300.0,  # 5 min ago
        last_op_ts=0.0,
        _inflight_count=0,
    )
    ctx.session.clients["lab2.kernel"] = stub  # type: ignore[assignment]
    rows = _probe_connected_views(ctx.session)
    assert rows[0]["state"] == "stale"


def test_probe_marks_cold_view(tmp_path):
    ctx = _build_ctx(tmp_path)
    stub = types.SimpleNamespace(
        endpoint="192.168.56.10:50099",
        last_seen_ts=0.0,
        last_op_ts=0.0,
        _inflight_count=0,
    )
    ctx.session.clients["lab2.kernel"] = stub  # type: ignore[assignment]
    rows = _probe_connected_views(ctx.session)
    assert rows[0]["state"] == "cold"
    assert rows[0]["last_rtt_ms"] is None


def test_health_contains_driver_rows_when_views_connected(tmp_path):
    """End-to-end: a connected view shows up in /health.driver_health."""
    ctx = _build_ctx(tmp_path)
    stub = types.SimpleNamespace(
        endpoint="192.168.56.10:50099",
        last_seen_ts=time.time(),
        last_op_ts=time.time(),
        _inflight_count=0,
    )
    ctx.session.clients["lab2.user"] = stub  # type: ignore[assignment]
    with TestClient(_app_for(ctx)) as client:
        body = client.get("/health").json()
    assert len(body["driver_health"]) == 1
    assert body["driver_health"][0]["view"] == "lab2.user"
    assert body["driver_health"][0]["kind"] == "user"


def test_classify_orchestrator_dead_catches_connection_refused():
    """T3.3: ConnectionRefusedError + grpc UNAVAILABLE route to the
    orchestrator_unreachable envelope kind."""
    from pry.mcp.tools.common import _classify_orchestrator_dead

    out = _classify_orchestrator_dead(ConnectionRefusedError("ECONNREFUSED"))
    assert out is not None
    assert out["kind"] == "orchestrator_unreachable"
    assert "install_orchestrator_service.ps1" in out["hint"]
    assert "start_orchestrator.ps1" in out["hint"]


def test_classify_orchestrator_dead_ignores_other_errors():
    from pry.mcp.tools.common import _classify_orchestrator_dead

    assert _classify_orchestrator_dead(ValueError("bad arg")) is None
    assert _classify_orchestrator_dead(RuntimeError("x")) is None


def test_classify_orchestrator_dead_catches_grpc_unavailable():
    import grpc
    from pry.mcp.tools.common import _classify_orchestrator_dead

    class _Rpc(grpc.RpcError):
        def code(self):
            return grpc.StatusCode.UNAVAILABLE

        def details(self):
            return "channel is in state TRANSIENT_FAILURE"

    out = _classify_orchestrator_dead(_Rpc())
    assert out is not None
    assert out["kind"] == "orchestrator_unreachable"
