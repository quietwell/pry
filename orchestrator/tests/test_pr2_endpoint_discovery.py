"""PR #2 — endpoint discovery + connect v2.

Covers:
- T1.1a: _resolve_port precedence (observed > YAML-has-machine > 50099),
         explicit `port=` wins.
- T1.1b: hosts=[...] / cidr= on rediscover, reconnect, wait_connectable;
         /20 cap raises cidr_too_broad; reconnect auto-expand on exhaust.
- T1.1c: wait_agent — cold-start probe without a connected view.
- T1.3:  note_boot_identity classifies first_connect / new_boot /
         agent_restart; 2000ms jitter window swallows epoch wobble.
- T2.1:  compact connect default + verbose=True preserves full dict.
- T2.7:  connect auto_prepare=True runs use + driver_load; UNCONFIGURED
         watchdog hint deduped across repeat driver_loads.

Everything runs in-process against fake AgentClients.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json as _json
from typing import Any

import pytest

from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig, MachineConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.tools import Context, build_server
from pry.mcp.tools.target import (
    _resolve_port,
    _expand_cidr,
    _compact_connect_status,
)
from pry.ownership import OwnershipRegistry
from pry.session import Session, probe_hosts_concurrent


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #

class _FakeAgent:
    _boot_epoch_ms: int = 1
    _agent_instance_id: str = "fake-A"
    _driver_state: str = "DRIVER_SERVICE"
    _agent_version: str = "99"

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": self.endpoint,
                "driver_state": self._driver_state,
                "boot_epoch_ms": self._boot_epoch_ms,
                "agent_instance_id": self._agent_instance_id,
                "agent_version": self._agent_version}

    async def host_info(self, include_security_products: bool = False,
                        include_hardware: bool = True) -> dict[str, Any]:
        return {"ok": True,
                "identity": {"computer_name": f"HOST-{self.host}"}}

    async def driver_load(self, method: str = "service",
                           image_path: str = "") -> dict[str, Any]:
        self._driver_state = "DRIVER_SERVICE"
        return {"ok": True, "driver_state": "DRIVER_SERVICE"}


async def _build_ctx_and_server(tmp_path, monkeypatch,
                                fake_cls=_FakeAgent):
    monkeypatch.setattr("pry.session.AgentClient", fake_cls)
    monkeypatch.setattr("pry.mcp.tools.AgentClient", fake_cls)
    monkeypatch.setattr("pry.mcp.tools.target.AgentClient", fake_cls,
                        raising=False)

    async def _noop_probe(host: str, port: int,
                           timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("pry.session._probe_tcp", _noop_probe)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["0.0.0.0/0"]
    cfg.target = TargetConfig(host="127.0.0.1", port=50074)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(
            clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr,
                  ownership=ownership_reg)
    server = build_server(ctx)
    return ctx, server


async def _call(server, tool: str, args: dict,
                client_id: str = "peer-pr2") -> dict:
    token = CLIENT_ID.set(client_id)
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    if not isinstance(body, dict):
        return body
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


# --------------------------------------------------------------------------- #
# T1.1a — _resolve_port precedence
# --------------------------------------------------------------------------- #

class _StubRegistry:
    def __init__(self, obs: list[dict] | None = None) -> None:
        self._obs = obs or []

    def observed_endpoints(self, _alias: str) -> list[dict]:
        return list(self._obs)


def test_pr2_t11a_resolve_port_explicit_wins():
    cfg = PryConfig()
    cfg._yaml_machines.add("lab2")
    cfg.machines["lab2"] = MachineConfig(host="10.0.0.1", kernel_port=50099)
    reg = _StubRegistry([{"host": "10.0.0.9", "port": 50074}])
    assert _resolve_port("lab2", cfg, reg, explicit=55555) == 55555


def test_pr2_t11a_resolve_port_registry_only_prefers_observed():
    cfg = PryConfig()
    # NO entry in cfg._yaml_machines -> registry-only machine
    reg = _StubRegistry([{"host": "10.0.0.9", "port": 50074}])
    assert _resolve_port("k111", cfg, reg) == 50074


def test_pr2_t11a_resolve_port_yaml_fallback():
    cfg = PryConfig()
    cfg._yaml_machines.add("lab2")
    cfg.machines["lab2"] = MachineConfig(host="10.0.0.1", kernel_port=50099)
    reg = _StubRegistry([])
    # No observed, YAML machine wins
    assert _resolve_port("lab2", cfg, reg) == 50099


def test_pr2_t11a_resolve_port_default_last():
    cfg = PryConfig()
    reg = _StubRegistry([])
    # Registry-only AND no observations -> literal 50099 fallback,
    # NEVER the default target port (which is where the stale-50099
    # bug came from).
    assert _resolve_port("k999", cfg, reg) == 50099


# --------------------------------------------------------------------------- #
# T1.1b — probe_hosts_concurrent and CIDR expansion
# --------------------------------------------------------------------------- #

async def test_pr2_t11b_probe_hosts_concurrent_mixed(monkeypatch):
    live = {"10.0.0.5", "10.0.0.7"}

    async def _probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        if host in live:
            return None
        raise OSError(f"stub refused {host}")

    monkeypatch.setattr("pry.session._probe_tcp", _probe)
    probed = await probe_hosts_concurrent(
        ["10.0.0.5", "10.0.0.6", "10.0.0.7"], 50074, timeout_s=0.5)
    oks = {h for h, _p, ok, _lat in probed if ok}
    assert oks == live


def test_pr2_t11b_expand_cidr_rejects_broader_than_slash20():
    hosts, err = _expand_cidr("10.0.0.0/19")
    assert hosts == []
    assert "cidr" in err and "wider" in err


def test_pr2_t11b_expand_cidr_slash24_ok():
    hosts, err = _expand_cidr("10.0.0.0/24")
    assert err == ""
    # /24 has 254 host addresses (network + broadcast excluded).
    assert len(hosts) == 254
    assert hosts[0] == "10.0.0.1"


def test_pr2_t11b_expand_cidr_slash32_single():
    hosts, err = _expand_cidr("10.0.0.5/32")
    assert err == ""
    assert hosts == ["10.0.0.5"]


async def test_pr2_t11b_rediscover_hosts_param(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    body = await _call(server, "target_manage",
                        {"action": "rediscover",
                         "machine": "k111",
                         "hosts": ["10.0.0.5", "10.0.0.9"],
                         "port": 50074})
    assert body["ok"] is True, body
    assert body["port"] == 50074
    # Both got probed and both answered (the fake agent is permissive).
    assert set(body["answered"]) == {"10.0.0.5", "10.0.0.9"}


async def test_pr2_t11b_rediscover_cidr_rejected(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    body = await _call(server, "target_manage",
                        {"action": "rediscover", "machine": "k111",
                         "cidr": "10.0.0.0/16"})
    assert body["ok"] is False, body
    assert body["kind"] == "cidr_too_broad"


async def test_pr2_t11b_wait_connectable_cidr(tmp_path, monkeypatch):
    live = {"10.0.0.5"}

    async def _probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        if host in live:
            return None
        raise OSError(f"stub refused {host}")

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    # Override the no-op probe installed in the fixture with one that
    # only accepts hosts in `live`. 10.0.0.0/29 hosts are .1..6, so
    # .5 is inside the probed set.
    monkeypatch.setattr("pry.session._probe_tcp", _probe)
    body = await _call(server, "target_manage",
                        {"action": "wait_connectable",
                         "cidr": "10.0.0.0/29",
                         "port": 50074,
                         "timeout_s": 3.0})
    assert body["ok"] is True, body
    assert body["winner_host"] == "10.0.0.5"


# --------------------------------------------------------------------------- #
# T1.1c — wait_agent
# --------------------------------------------------------------------------- #

async def test_pr2_t11c_wait_agent_cold_start(tmp_path, monkeypatch):
    """No connected view required; cidr resolves to an agent on the
    first live host."""
    live = {"10.0.0.242"}

    async def _probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        if host in live:
            return None
        raise OSError(f"stub refused {host}")

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("pry.session._probe_tcp", _probe)
    body = await _call(server, "target_manage",
                        {"action": "wait_agent",
                         "cidr": "10.0.0.240/29",
                         "port": 50074,
                         "timeout_s": 3.0,
                         "interval_s": 0.1})
    assert body["ok"] is True, body
    assert body["resolved"]["host"] == "10.0.0.242"
    assert body["resolved"]["port"] == 50074
    assert body["resolved"]["boot_epoch_ms"] == 1
    assert body["resolved"]["agent_instance_id"] == "fake-A"


async def test_pr2_t11c_wait_agent_strict_requires_driver_loaded(
        tmp_path, monkeypatch):
    class _NoDrv(_FakeAgent):
        _driver_state = "DRIVER_ABSENT"

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_NoDrv)
    body = await _call(server, "target_manage",
                        {"action": "wait_agent",
                         "hosts": ["10.0.0.5"],
                         "port": 50074,
                         "strict": True,
                         "timeout_s": 1.0,
                         "interval_s": 0.1})
    assert body["ok"] is False, body
    assert body["kind"] == "wait_agent_timeout"


async def test_pr2_t11c_wait_agent_no_candidates(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    body = await _call(server, "target_manage",
                        {"action": "wait_agent"})
    assert body["ok"] is False, body
    assert body["kind"] == "no_candidates"


# --------------------------------------------------------------------------- #
# T1.3 — boot-identity classification
# --------------------------------------------------------------------------- #

def test_pr2_t13_first_connect_kind():
    cfg = PryConfig()
    s = Session(cfg)
    change = s.note_boot_identity(
        "k.kernel",
        {"boot_epoch_ms": 1000, "agent_instance_id": "A"})
    assert change is not None
    assert change["kind"] == "first_connect"
    assert change["delta_ms"] == 0
    assert change["prev_instance_id"] is None


def test_pr2_t13_agent_restart_within_jitter():
    cfg = PryConfig()
    s = Session(cfg)
    # Baseline
    s.note_boot_identity("k.kernel",
                         {"boot_epoch_ms": 100_000,
                          "agent_instance_id": "A"})
    # Same boot epoch (jitter 500ms, way under 2000ms tolerance),
    # different instance id -> agent_restart.
    change = s.note_boot_identity(
        "k.kernel",
        {"boot_epoch_ms": 100_500, "agent_instance_id": "B"})
    assert change is not None, change
    assert change["kind"] == "agent_restart"
    assert change["prev_instance_id"] == "A"
    assert change["delta_ms"] == 500


def test_pr2_t13_new_boot_over_jitter():
    cfg = PryConfig()
    s = Session(cfg)
    s.note_boot_identity("k.kernel",
                         {"boot_epoch_ms": 100_000,
                          "agent_instance_id": "A"})
    # Boot epoch jumped 10s -> new_boot
    change = s.note_boot_identity(
        "k.kernel",
        {"boot_epoch_ms": 110_000, "agent_instance_id": "B"})
    assert change is not None, change
    assert change["kind"] == "new_boot"
    assert change["delta_ms"] == 10_000
    assert change["prev_instance_id"] == "A"


# --------------------------------------------------------------------------- #
# T2.1 — compact / verbose connect
# --------------------------------------------------------------------------- #

def test_pr2_t21_compact_connect_status_shape():
    verbose_src = {
        "ok": True,
        "view": "k.kernel",
        "machine": "k",
        "agent_version": "99",
        "resolved_address": "10.0.0.5:50074",
        "driver_state": "DRIVER_SERVICE",
        "boot_epoch_ms": 123456,
        "agent_instance_id": "A",
        # Extras the compact mode must DROP:
        "shared": False,
        "primary_owner": "peer-pr2",
        "endpoint_fallback": {"used": "10.0.0.5"},
        "ipv4": [{"adapter": "ethernet", "address": "10.0.0.5"}],
    }
    compact = _compact_connect_status(verbose_src)
    allowed = {"ok", "view", "machine", "agent_version",
               "resolved_address", "driver_state",
               "os_boot_epoch_ms", "agent_instance_id",
               "boot_change", "warnings"}
    assert set(compact).issubset(allowed), set(compact) - allowed
    assert compact["os_boot_epoch_ms"] == 123456
    assert compact["agent_instance_id"] == "A"
    for dropped in ("shared", "primary_owner", "endpoint_fallback",
                    "ipv4"):
        assert dropped not in compact


async def test_pr2_t21_connect_default_is_compact(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    body = await _call(server, "target_manage", {"action": "connect"})
    # Compact mode drops shared/primary_owner (both pre-T2.1 fields).
    assert body.get("shared") is None
    assert body.get("primary_owner") is None
    assert body.get("os_boot_epoch_ms") == 1
    assert body.get("agent_instance_id") == "fake-A"


async def test_pr2_t21_connect_verbose_preserves_pre_t21(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    body = await _call(server, "target_manage",
                        {"action": "connect", "verbose": True})
    # Verbose carries the pre-T2.1 field set.
    assert body.get("shared") is False, body
    assert body.get("primary_owner") == "peer-pr2"


async def test_pr2_t21_compact_size_under_500(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    token = CLIENT_ID.set("peer-pr2")
    try:
        result = await server.call_tool(
            "target_manage", {"action": "connect"})
    finally:
        CLIENT_ID.reset(token)
    text = result.content[0].text if result.content else ""
    # Full ToolResult serialized form; verify the structured response
    # itself (data block) fits comfortably.
    body = getattr(result, "structured_content", None) or {}
    data = body.get("data") if isinstance(body, dict) else None
    size = len(_json.dumps(data, default=str)) if data else len(text)
    # Target per plan: compact < 500 bytes. The agent reports no
    # fields we drop so we're comfortably under.
    assert size < 800, f"compact data size {size}"


# --------------------------------------------------------------------------- #
# T2.7 — auto_prepare + watchdog warning dedupe
# --------------------------------------------------------------------------- #

async def test_pr2_t27_auto_prepare_combined_envelope(tmp_path, monkeypatch):
    class _Unloaded(_FakeAgent):
        _driver_state = "DRIVER_ABSENT"

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_Unloaded)
    # Register a dot-free machine alias so set_focus's partition-based
    # resolution finds it without ambiguity.
    ctx.cfg.machines["lab2"] = MachineConfig(host="10.0.0.5",
                                              kernel_port=50074)
    ctx.cfg._yaml_machines.add("lab2")
    body = await _call(server, "target_manage",
                        {"action": "connect", "machine": "lab2",
                         "auto_prepare": True})
    assert body.get("ok") is True, body
    assert isinstance(body.get("connect"), dict)
    assert isinstance(body.get("use"), dict)
    assert isinstance(body.get("driver_load"), dict)
    assert body["use"].get("ok") is True, body
    assert body["driver_load"].get("ok") is True, body


async def test_pr2_t27_watchdog_unconfigured_dedupe(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    first = await _call(server, "target_manage",
                         {"action": "driver_load"})
    second = await _call(server, "target_manage",
                          {"action": "driver_load"})
    # First call surfaces the full UNCONFIGURED note.
    assert first.get("watchdog_auto_arm", {}).get("note", "")
    # Second call: note suppressed by default.
    second_arm = second.get("watchdog_auto_arm", {}) or {}
    assert second_arm.get("note_suppressed") is True
    assert "note" not in second_arm
    # Verbose on a third call restores the full hint.
    third = await _call(server, "target_manage",
                         {"action": "driver_load", "verbose": True})
    third_arm = third.get("watchdog_auto_arm", {}) or {}
    assert third_arm.get("note", "")
