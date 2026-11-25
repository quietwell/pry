"""PR#8: dashboard half — ``POST /api/machines/prune`` + stale-endpoint
surface in :meth:`MachineRegistry.describe`.

The backend half (``machines_prune`` MCP verb +
``Registry.prune_empty_shells``) is covered by
``test_pr8_registry_prune.py``. This file covers the dashboard route
and the ``describe()`` tweak that surfaces ``endpoints_stale`` so the
dashboard can replace the "no endpoint" line for alias-only shells.

Fixture style mirrors ``test_dashboard_health.py`` — no live MCP, no
gRPC, no AgentClient round-trip; the registry is seeded directly and
the FastAPI app is driven through ``TestClient``.
"""
from __future__ import annotations

import json

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


def _seed_shells(reg) -> None:
    """Three alias-only shells, matching the real-world shape
    (``k032`` / ``k034`` / ``k247``) — only ``alias`` +
    ``observed_endpoints`` keys."""
    for alias, host in [("k032", "192.168.2.32"),
                        ("k034", "192.168.2.34"),
                        ("k247", "192.168.2.247")]:
        reg._entries[alias] = {
            "alias": alias,
            "observed_endpoints": [{
                "host": host, "port": 50074,
                "seen_at": "2026-10-27T01:23:15Z"}],
        }
    reg._save()


# ---------------------------------------------------------------------------
# POST /api/machines/prune
# ---------------------------------------------------------------------------


def test_prune_dry_run_reports_without_mutating(tmp_path):
    ctx = _build_ctx(tmp_path)
    _seed_shells(ctx.registry)
    snapshot_before = json.loads(ctx.registry.path.read_text(encoding="utf-8"))
    with TestClient(_app_for(ctx)) as client:
        resp = client.post("/api/machines/prune", json={"dry_run": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["dry_run"] is True
    assert body["count_removed"] == 3
    assert sorted(body["removed"]) == ["k032", "k034", "k247"]
    # Filesystem untouched
    snapshot_after = json.loads(ctx.registry.path.read_text(encoding="utf-8"))
    assert snapshot_after == snapshot_before
    # In-memory entries still present
    for a in ("k032", "k034", "k247"):
        assert ctx.registry.entry(a) is not None


def test_prune_apply_removes_entries(tmp_path):
    ctx = _build_ctx(tmp_path)
    _seed_shells(ctx.registry)
    with TestClient(_app_for(ctx)) as client:
        resp = client.post("/api/machines/prune", json={"dry_run": False})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["dry_run"] is False
    assert body["count_removed"] == 3
    assert sorted(body["removed"]) == ["k032", "k034", "k247"]
    for a in ("k032", "k034", "k247"):
        assert ctx.registry.entry(a) is None
    on_disk = json.loads(ctx.registry.path.read_text(encoding="utf-8"))
    assert on_disk["machines"] == {}


def test_prune_no_body_defaults_to_dry_run(tmp_path):
    """POST with no body falls through to ``dry_run=True`` (preview). A
    bare POST (buggy curl, double-click, preflight retry) must NEVER
    nuke the registry — the dashboard button sends an explicit
    ``dry_run: false`` on the apply step after showing the preview."""
    ctx = _build_ctx(tmp_path)
    _seed_shells(ctx.registry)
    with TestClient(_app_for(ctx)) as client:
        resp = client.post("/api/machines/prune")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    # No body => dry_run=True by default (safe preview). Registry untouched.
    assert body["dry_run"] is True
    assert body["count_removed"] == 3
    for a in ("k032", "k034", "k247"):
        assert ctx.registry.entry(a) is not None


def test_machines_list_surfaces_endpoints_stale(tmp_path):
    """``GET /api/machines`` returns the ``describe()`` block for each
    machine. For a shell with observed_endpoints + no primary endpoint,
    the row must expose ``endpoints_stale`` so the dashboard can replace
    "no endpoint" with the last-known host:port."""
    ctx = _build_ctx(tmp_path)
    _seed_shells(ctx.registry)
    with TestClient(_app_for(ctx)) as client:
        resp = client.get("/api/machines")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    rows = {str(m.get("machine")): m for m in body["machines"]}
    k247 = rows.get("k247")
    assert k247 is not None, rows
    # Primary endpoints came up empty — but endpoints_stale carries the
    # observed host:port and the seen_at timestamp.
    assert k247.get("endpoints") == {}
    stale = k247.get("endpoints_stale")
    assert isinstance(stale, dict), k247
    assert stale.get("kernel") == "192.168.2.247:50074"
    assert stale.get("when") == "2026-10-27T01:23:15Z"
