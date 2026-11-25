"""T1.1d — agent phone-home intake route on the dashboard app.

The agent POSTs {machine_label|computer_name, port, ipv4[], boot_epoch_ms,
agent_instance_id, written_at} to /api/agent_report every 30s and on
IPv4-set change. These tests cover the HTTP shape, missing-field 400s,
and the allow_create=True contract that lets this (and only this) path
mint a brand-new registry entry — PR#8 explicitly reserved the default
(allow_create=False) for passive discovery.

Fixture pattern mirrors tests/test_dashboard_health.py: build an isolated
Session + registry + FastAPI app, no live gRPC, no agent round-trip.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pry.config import PryConfig, TargetConfig
from pry.dashboard.api import register_dashboard_routes
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


def test_agent_report_records_two_ipv4(tmp_path):
    """Happy path: a POST with two private-range IPv4 addresses records
    both as observed endpoints for the label and returns 200."""
    ctx = _build_ctx(tmp_path)
    with TestClient(_app_for(ctx)) as client:
        resp = client.post("/api/agent_report", json={
            "machine_label": "lab2",
            "computer_name": "LAB2-WIN11",
            "port": 50074,
            "ipv4": ["192.168.2.36", "192.168.2.37"],
            "boot_epoch_ms": 1_700_000_000_000,
            "agent_instance_id": "1234-9999",
            "written_at": "2026-10-27T15:04:05Z",
        })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["updated"] == "lab2"
    assert body["endpoints"] == 2
    obs = ctx.registry.observed_endpoints("lab2")
    hosts = sorted(o["host"] for o in obs)
    assert hosts == ["192.168.2.36", "192.168.2.37"]
    assert all(o["port"] == 50074 for o in obs)
    # boot_epoch_ms is persisted alongside the endpoint (used by
    # target_manage(action='wait_agent') to pick the newest observation).
    assert all(o["boot_epoch_ms"] == 1_700_000_000_000 for o in obs)


def test_agent_report_missing_label_is_400(tmp_path):
    """No machine_label and no computer_name — orchestrator can't key the
    observation, so return 400 with a readable error (the agent surfaces
    this via OutputDebugStringA so a field build with a broken probe is
    easier to debug than a silent drop)."""
    ctx = _build_ctx(tmp_path)
    with TestClient(_app_for(ctx)) as client:
        resp = client.post("/api/agent_report", json={
            "port": 50074,
            "ipv4": ["192.168.2.36"],
        })
    assert resp.status_code == 400
    body = resp.json()
    assert body["ok"] is False
    assert "label" in body["error"]
    assert "port" in body["error"]
    assert "ipv4" in body["error"]


def test_agent_report_empty_ipv4_is_400(tmp_path):
    """ipv4=[] means the agent couldn't enumerate a usable private-range
    address — there's nothing for the orchestrator to record, so 400."""
    ctx = _build_ctx(tmp_path)
    with TestClient(_app_for(ctx)) as client:
        resp = client.post("/api/agent_report", json={
            "machine_label": "lab2",
            "port": 50074,
            "ipv4": [],
        })
    assert resp.status_code == 400
    body = resp.json()
    assert body["ok"] is False
    assert "ipv4" in body["error"]


def test_agent_report_mints_new_entry_for_unknown_label(tmp_path):
    """PR#8 locked ``record_observed_endpoint`` to known aliases by
    default (``allow_create=False``). The phone-home path IS allowed to
    create — it's the only intake where the agent itself drives the
    "I exist, here's where" signal, so refusing would make the
    orchestrator unable to find a freshly-provisioned box."""
    ctx = _build_ctx(tmp_path)
    # Sanity: label is not yet known to the registry.
    assert ctx.registry.observed_endpoints("fresh-box") == []
    assert "fresh-box" not in ctx.registry.all()

    with TestClient(_app_for(ctx)) as client:
        resp = client.post("/api/agent_report", json={
            "machine_label": "fresh-box",
            "port": 50074,
            "ipv4": ["10.9.0.42"],
            "boot_epoch_ms": 1_700_000_000_000,
        })
    assert resp.status_code == 200, resp.text
    # ``beacon_label`` is returned in the response so split-brain
    # beacons (NetBIOS vs operator alias) can be audited; the resolved
    # ``updated`` alias stays authoritative.
    assert resp.json() == {"ok": True, "updated": "fresh-box",
                           "beacon_label": "fresh-box", "endpoints": 1}

    # New entry minted; endpoint recorded.
    obs = ctx.registry.observed_endpoints("fresh-box")
    assert len(obs) == 1
    assert obs[0]["host"] == "10.9.0.42"
    assert obs[0]["port"] == 50074
