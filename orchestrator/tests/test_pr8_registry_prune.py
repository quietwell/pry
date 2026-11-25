"""PR#8: machine-registry cleanup + prevention.

Covers the two halves of the fix:

- :meth:`MachineRegistry.record_observed_endpoint` grows an opt-in
  ``allow_create`` flag so passive-discovery call sites can no longer
  mint alias-only shells behind the operator's back.
- :meth:`MachineRegistry.prune_empty_shells` lets the operator sweep
  the shells that past releases left behind, with ``dry_run=True`` for
  a safe preview and a wire verb (``target_manage(action=
  'machines_prune')``) that returns the same report.
"""

from __future__ import annotations

import json

import pytest

from pry.config import MachineConfig, PryConfig
from pry.registry import MachineRegistry


def _cfg(tmp_path):
    cfg = PryConfig()
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    return cfg


def _registry(tmp_path, cfg=None) -> MachineRegistry:
    cfg = cfg or _cfg(tmp_path)
    return MachineRegistry(cfg, tmp_path / "artifacts" / "targets.json")


# ---------------------------------------------------------------------------
# Prevention — allow_create gate
# ---------------------------------------------------------------------------


class TestRecordObservedEndpointGate:
    def test_unknown_alias_without_allow_create_returns_false(self, tmp_path):
        reg = _registry(tmp_path)
        ok = reg.record_observed_endpoint(
            "k247", host="192.168.2.247", port=50074)
        assert ok is False
        assert reg.entry("k247") is None
        # The on-disk file must not have been written for a dropped
        # record either — nothing to persist.
        assert not reg.path.exists() or reg.all() == {}

    def test_unknown_alias_with_allow_create_mints(self, tmp_path):
        reg = _registry(tmp_path)
        ok = reg.record_observed_endpoint(
            "k247", host="192.168.2.247", port=50074,
            boot_epoch_ms=1793062455500, allow_create=True)
        assert ok is True
        ent = reg.entry("k247")
        assert ent is not None
        assert ent["alias"] == "k247"
        obs = ent.get("observed_endpoints") or []
        assert len(obs) == 1
        assert obs[0]["host"] == "192.168.2.247"
        assert obs[0]["port"] == 50074
        assert obs[0]["boot_epoch_ms"] == 1793062455500

    def test_known_yaml_alias_records_without_allow_create(self, tmp_path):
        cfg = _cfg(tmp_path)
        cfg.machines["lab2"] = MachineConfig(
            host="10.0.2.15", kernel_port=50099, token="t")
        reg = _registry(tmp_path, cfg)
        # YAML aliases are known even with no registry entry — passive
        # discovery is free to update their observed_endpoints.
        ok = reg.record_observed_endpoint(
            "lab2", host="10.0.2.15", port=50099)
        assert ok is True
        obs = reg.observed_endpoints("lab2")
        assert len(obs) == 1
        assert obs[0]["host"] == "10.0.2.15"
        assert obs[0]["port"] == 50099

    def test_existing_registry_entry_records_without_allow_create(
            self, tmp_path):
        reg = _registry(tmp_path)
        reg.register("box1", host="10.0.0.1", kernel_port=50074,
                     trust="lab")
        ok = reg.record_observed_endpoint(
            "box1", host="10.0.0.2", port=50074)
        assert ok is True
        obs = reg.observed_endpoints("box1")
        assert obs[0]["host"] == "10.0.0.2"


# ---------------------------------------------------------------------------
# Pruning — prune_empty_shells
# ---------------------------------------------------------------------------


def _seed_shells(reg: MachineRegistry) -> None:
    """Install three alias-only shells (the real-world k032/k034/k247
    shape — only alias + observed_endpoints keys)."""
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


class TestPruneEmptyShells:
    def test_dry_run_reports_without_mutating(self, tmp_path):
        cfg = _cfg(tmp_path)
        cfg.machines["yamlbox"] = MachineConfig(
            host="10.0.1.10", kernel_port=50099)
        reg = _registry(tmp_path, cfg)
        _seed_shells(reg)
        # One YAML-sourced metadata overlay (empty-looking by itself,
        # but YAML-known) and one real operator entry.
        reg.register("yamlbox", trust="lab", purpose="reviewed box")
        reg.register("trusted1", host="10.0.0.5", kernel_port=50074,
                     trust="lab", purpose="primary rig")
        snapshot_before = json.loads(reg.path.read_text(encoding="utf-8"))
        report = reg.prune_empty_shells(dry_run=True)
        assert report["dry_run"] is True
        assert report["count_removed"] == 3
        assert sorted(report["removed"]) == ["k032", "k034", "k247"]
        assert report["kept_connected"] == []
        # File untouched
        snapshot_after = json.loads(reg.path.read_text(encoding="utf-8"))
        assert snapshot_after == snapshot_before
        # Registry entries still present
        for a in ("k032", "k034", "k247"):
            assert reg.entry(a) is not None

    def test_apply_removes_shells_and_saves(self, tmp_path):
        reg = _registry(tmp_path)
        _seed_shells(reg)
        reg.register("trusted1", host="10.0.0.5", kernel_port=50074,
                     trust="lab", purpose="primary rig")
        report = reg.prune_empty_shells(dry_run=False)
        assert report["dry_run"] is False
        assert report["count_removed"] == 3
        assert sorted(report["removed"]) == ["k032", "k034", "k247"]
        for a in ("k032", "k034", "k247"):
            assert reg.entry(a) is None
        # Real entry survives
        assert reg.entry("trusted1") is not None
        # Persistence actually happened
        on_disk = json.loads(reg.path.read_text(encoding="utf-8"))
        remaining = set(on_disk["machines"].keys())
        assert remaining == {"trusted1"}

    def test_connected_shell_is_kept_connected(self, tmp_path):
        reg = _registry(tmp_path)
        _seed_shells(reg)
        report = reg.prune_empty_shells(
            session_machines={"k247": ["k247.kernel"]},
            dry_run=False)
        assert "k247" in report["kept_connected"]
        assert sorted(report["removed"]) == ["k032", "k034"]
        assert reg.entry("k247") is not None  # live view keeps its entry
        assert reg.entry("k032") is None
        assert reg.entry("k034") is None

    def test_yaml_alias_never_pruned_even_when_metadata_blank(
            self, tmp_path):
        cfg = _cfg(tmp_path)
        cfg.machines["yamlbox"] = MachineConfig(
            host="10.0.1.10", kernel_port=50099)
        reg = _registry(tmp_path, cfg)
        # A YAML alias with no explicit metadata overlay still produces
        # a looks-empty entry when passive discovery records against it.
        # (allow_create=False is fine because the YAML alias is known.)
        reg.record_observed_endpoint(
            "yamlbox", host="10.0.1.10", port=50099)
        # Also drop a shadowed entry — shadowed means operator-minted.
        reg._entries["shadowbox"] = {"alias": "shadowbox", "shadow": True}
        # And one with a token set — never a shell.
        reg._entries["tokenbox"] = {
            "alias": "tokenbox", "token": "${X_TOKEN}"}
        reg._save()
        report = reg.prune_empty_shells(dry_run=False)
        assert report["count_removed"] == 0
        assert "yamlbox" in report["kept_registered"]
        assert "shadowbox" in report["kept_registered"]
        assert "tokenbox" in report["kept_registered"]


# ---------------------------------------------------------------------------
# Wire verb — target_manage(action='machines_prune')
# ---------------------------------------------------------------------------


async def test_mcp_verb_dry_run_reports_shape(tmp_path, monkeypatch):
    import asyncio

    from pry.caller import CLIENT_ID
    from pry.clients import ClientRegistry
    from pry.config import TargetConfig
    from pry.findings import FindingsLedger
    from pry.ida_bridge import IdaBridge, IdaConfigLite
    from pry.leases import LeaseManager
    from pry.mcp.tools import Context, build_server
    from pry.ownership import OwnershipRegistry
    from pry.session import Session

    cfg = PryConfig()
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients = ClientRegistry()
    leases = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients, leases=leases,
                  ownership=OwnershipRegistry())
    # Seed three alias-only shells via the live registry.
    _seed_shells(ctx.registry)

    server = build_server(ctx)
    token = CLIENT_ID.set("peer-prune-test")
    try:
        result = await server.call_tool(
            "machines_manage",
            {"action": "prune", "dry_run": True})
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    assert body["ok"] is True, body
    assert body["action"] == "prune", body
    # Guard-wrapped responses carry the structured payload under "data".
    data = body.get("data", body)
    assert data["dry_run"] is True
    assert data["count_removed"] == 3
    assert sorted(data["removed"]) == ["k032", "k034", "k247"]
    assert data["kept_connected"] == []
    assert "hint" in data
    # dry_run must not have written the file
    for a in ("k032", "k034", "k247"):
        assert ctx.registry.entry(a) is not None
    # Trusted action — no provenance block on the envelope.
    assert "provenance" not in body
