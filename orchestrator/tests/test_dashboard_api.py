"""Dashboard REST additions: per-machine /api/status with a cached rich
probe, tool-log args (redacted + capped), live view rows on
/api/machines, and the favicon route.

No gRPC: fake agent clients are dropped straight into
``Session.clients`` and the pry-driver probe is monkeypatched.
"""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pry.mcp._pry_driver_probe as driver_probe
from pry.config import PryConfig, TargetConfig
from pry.dashboard.api import _clean_args, register_dashboard_routes
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.mcp.tools import Context
from pry.session import Session


class _FakeAgent:
    def __init__(self, endpoint: str, computer: str) -> None:
        self.endpoint = endpoint
        self.computer = computer
        self.last_seen_ts = time.time()
        self.last_op_ts = 0.0
        self._inflight_count = 0
        self.status_calls = 0
        self.host_info_calls = 0
        self.driver_state = "DRIVER_SERVICE"

    async def status(self):
        self.status_calls += 1
        return {"ok": True, "driver_state": self.driver_state,
                "agent_version": "9.1"}

    async def host_info(self, include_hardware: bool = True):
        self.host_info_calls += 1
        return {
            "ok": True,
            "identity": {"computer_name": self.computer},
            "os": {"build_major": 26200, "display_version": "25H2"},
            "security": {"hvci": {"value": False, "source": "registry"},
                         "kva_shadow": {"value": True, "source": "ntqsi"}},
            "uptime": {"pc_uptime_ms": 5000, "service_uptime_ms": 4000},
        }


@pytest.fixture
def probe_calls(monkeypatch):
    calls: list[str] = []

    async def _fake_probe(client, *, driver_state=None):
        calls.append(client.computer)
        return {"loaded": True, "verdict": "loaded", "hint": ""}

    monkeypatch.setattr(driver_probe, "probe_pry_driver", _fake_probe)
    return calls


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
    return Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge)


def _client(ctx) -> TestClient:
    app = FastAPI()
    register_dashboard_routes(app, ctx)
    return TestClient(app)


def _two_machines(ctx):
    a = _FakeAgent("127.0.0.2:50074", "LAB-A")
    b = _FakeAgent("127.0.0.3:50074", "LAB-B")
    ctx.session.clients["laba.kernel"] = a
    ctx.session.clients["labb.kernel"] = b
    ctx.session.primary = "laba.kernel"
    return a, b


def test_status_without_clients_is_safe(tmp_path, probe_calls):
    ctx = _build_ctx(tmp_path)
    with _client(ctx) as c:
        body = c.get("/api/status").json()
        assert body["connected"] is False
        assert body["view"] is None
        assert "agent" not in body
        body = c.get("/api/status", params={"machine": "nope"}).json()
        assert body["view"] is None
    assert probe_calls == []


def test_status_picks_requested_machine(tmp_path, probe_calls):
    ctx = _build_ctx(tmp_path)
    a, b = _two_machines(ctx)
    with _client(ctx) as c:
        body = c.get("/api/status", params={"machine": "labb"}).json()
        assert body["view"] == "labb.kernel"
        assert body["machine"] == "labb"
        assert body["agent"]["identity"]["computer_name"] == "LAB-B"
        assert body["agent"]["pry_driver_health"]["verdict"] == "loaded"
        assert body["views_connected"] == 2
        # No machine -> primary view.
        assert c.get("/api/status").json()["view"] == "laba.kernel"
        # A named machine with no live view never falls back to another one.
        miss = c.get("/api/status", params={"machine": "ghost"}).json()
        assert miss["view"] is None and "agent" not in miss
    assert a.status_calls == 1 and b.status_calls == 1


def test_status_caches_rich_probe(tmp_path, probe_calls):
    ctx = _build_ctx(tmp_path)
    a, _ = _two_machines(ctx)
    with _client(ctx) as c:
        first = c.get("/api/status", params={"machine": "laba"}).json()
        second = c.get("/api/status", params={"machine": "laba"}).json()
        assert a.status_calls == 2          # cheap status: every call
        assert a.host_info_calls == 1       # rich probe: cached
        assert probe_calls == ["LAB-A"]
        assert first["rich_age_s"] == 0.0
        assert second["rich_age_s"] >= 0.0
        assert second["agent"]["kva_shadow"]["value"] is True

        c.get("/api/status", params={"machine": "laba", "refresh": "1"})
        assert a.host_info_calls == 2       # refresh bypasses the cache

        # A driver-state change invalidates the entry on its own.
        a.driver_state = "DRIVER_ABSENT"
        c.get("/api/status", params={"machine": "laba"})
        assert a.host_info_calls == 3


def test_toollog_carries_redacted_args(tmp_path):
    ctx = _build_ctx(tmp_path)
    ctx.session.record_tool_call(
        "memory_manage", "read",
        args={"name": "lab2.kernel", "address": "0xfffff800",
              "token": "s3cret", "auth_token": "x", "blob": "A" * 500,
              "_peer": "127.0.0.1", "_current_owner": "dashboard"},
        ok=False, error="boom")
    with _client(ctx) as c:
        rows = c.get("/api/toollog").json()
    assert len(rows) == 1
    row = rows[0]
    assert row["target"] == "lab2.kernel"
    assert row["ok"] is False and row["error"] == "boom"
    args = row["args"]
    assert args["token"] == "<redacted>"
    assert args["auth_token"] == "<redacted>"
    assert "s3cret" not in str(row)
    assert "_peer" not in args and "_current_owner" not in args
    assert len(args["blob"]) <= 201
    assert args["address"] == "0xfffff800"


def test_toollog_limit(tmp_path):
    ctx = _build_ctx(tmp_path)
    for i in range(30):
        ctx.session.record_tool_call("target_manage", f"a{i}")
    with _client(ctx) as c:
        rows = c.get("/api/toollog", params={"limit": 5}).json()
        assert [r["action"] for r in rows] == [f"a{i}" for i in range(25, 30)]
        assert len(c.get("/api/toollog").json()) == 30


def test_clean_args_keeps_bool_secret_flags_and_caps_lists():
    out = _clean_args({"token_set": True, "password": 123,
                       "items": list(range(50)), "raw": b"\x00" * 9,
                       "nested": {"a": {"b": {"c": {"d": {"e": 1}}}}}})
    assert out["token_set"] is True
    assert out["password"] == "<redacted>"
    assert len(out["items"]) == 21 and out["items"][-1].endswith("more")
    assert out["raw"] == "<9 bytes>"
    assert "…" in str(out["nested"])


def test_machines_rows_carry_live_views(tmp_path):
    ctx = _build_ctx(tmp_path)
    _two_machines(ctx)
    with _client(ctx) as c:
        body = c.get("/api/machines").json()
    rows = {r["machine"]: r for r in body["machines"]}
    assert rows["laba"]["connected"] is True
    live = rows["laba"]["live"]
    assert len(live) == 1
    assert live[0]["endpoint"] == "127.0.0.2:50074"
    assert live[0]["state"] == "connected"
    assert rows["laba"]["shell"] is False


def test_favicon_served(tmp_path):
    ctx = _build_ctx(tmp_path)
    with _client(ctx) as c:
        r = c.get("/favicon.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert b"<svg" in r.content
