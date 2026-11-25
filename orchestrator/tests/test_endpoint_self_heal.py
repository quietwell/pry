"""DHCP endpoint self-heal.

The lab VM gets a new address on most boots, so "remember the old address"
cannot find it. These tests pin the three fixes that can:

1. a failed connect names where the machines were last seen (beacons) and
   what to do next, instead of "check the service on the target";
2. ``Session.connect`` tries the machine's fresh phone-home beacons and its
   *name* (mDNS/LLMNR/DNS) ahead of stale addresses, and refuses a host
   that answers as a different machine;
3. a per-view link watcher re-points a dead view at a verified new address
   (same client object), reporting reboot / endpoint change.

Everything runs against an in-memory "world" of live addresses — no
sockets, no resolver, no sleeps beyond a few tens of milliseconds.
"""
from __future__ import annotations

import asyncio
import json as _json
import socket
import time
from typing import Any

import pytest

from pry import endpoint_hints
from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import MachineConfig, PryConfig, TargetConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp._error_enrich import classify
from pry.mcp.error_maps import KNOWN_KINDS
from pry.mcp.tools import Context, build_server
from pry.ownership import OwnershipRegistry
from pry.registry import MachineRegistry
from pry.session import Session, WrongMachineError

BOOT = 1_700_000_000_000


# --------------------------------------------------------------------------- #
# A tiny world: which addresses answer, and as whom
# --------------------------------------------------------------------------- #

class _World:
    def __init__(self) -> None:
        self.live: dict[str, str] = {}   # host -> computer_name answering
        self.boot: dict[str, int] = {}   # host -> boot_epoch_ms
        self.probed: list[str] = []      # hosts TCP-probed, in call order
        self.no_hostinfo_ports: set[int] = set()  # ports that cannot self-name


def _fake_agent(world: _World, *, rebind: bool = True):
    class FakeAgent:
        instances: list = []

        def __init__(self, host, port, token="", timeout_ms=10000,
                     max_inflight=16):
            self._host, self._port = host, int(port)
            self.token = token
            self.timeout_ms = timeout_ms
            self.closed = False
            FakeAgent.instances.append(self)

        @property
        def endpoint(self) -> str:
            return f"{self._host}:{self._port}"

        @property
        def last_seen_ts(self) -> float:
            return 0.0

        # view rendering (targets / status) reads these
        last_op_ts = 1.0
        connected_ts = 1.0

        async def connect(self) -> None:
            if self._host not in world.live:
                raise OSError(None, f"WSAETIMEDOUT grpc to {self._host}")

        async def close(self) -> None:
            self.closed = True

        async def status(self) -> dict[str, Any]:
            if self._host not in world.live:
                raise OSError(f"channel to {self._host} is dead")
            name = world.live[self._host]
            boot = world.boot.get(self._host, BOOT)
            return {"ok": True, "boot_epoch_ms": boot,
                    "agent_instance_id": f"inst-{name}-{boot}",
                    "driver_state": "DRIVER_SERVICE",
                    "scan_service_version": 1}

        async def host_info(self, **_kw) -> dict[str, Any]:
            name = world.live.get(self._host, "")
            if not name or self._port in world.no_hostinfo_ports:
                return {"ok": False}      # e.g. the umagent: no HostInfo
            return {"ok": True, "identity": {"computer_name": name}}

    if rebind:
        async def _rebind(self, host, port=None):
            self._host = host
            self._port = int(port or self._port)
        FakeAgent.rebind = _rebind
    return FakeAgent


def _install(monkeypatch, world: _World, *, rebind: bool = True):
    fake = _fake_agent(world, rebind=rebind)
    monkeypatch.setattr("pry.session.AgentClient", fake)

    async def _probe(host, port, timeout_s: float = 3.0) -> None:
        world.probed.append(host)
        if host not in world.live:
            raise OSError(None, f"WSAETIMEDOUT tcp probe to {host}:{port} "
                                f"failed: connection timed out after "
                                f"{timeout_s:.1f}s")

    monkeypatch.setattr("pry.session._probe_tcp", _probe)
    monkeypatch.setenv("PRY_AUDIT_DISABLE", "1")
    return fake


def _cfg(tmp_path, *, allow="10.0.0.0/24", configured="10.0.0.9"):
    cfg = PryConfig()
    cfg.security.authorized_targets = [allow]
    cfg.target = TargetConfig(host="10.0.0.200", port=50074, token="tok")
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    cfg.machines = {"lab2": MachineConfig(
        host=configured, kernel_port=50074, user_port=50075, token="tok",
        trust="lab", alt_hosts=["10.0.0.200"])}
    return cfg


def _session(cfg, *, with_registry: bool = True):
    session = Session(cfg)
    reg = MachineRegistry.load(cfg) if with_registry else None
    if reg is not None:
        session.set_registry_provider(lambda: reg)
    return session, reg


def _beacon(reg: MachineRegistry, *hosts: str, port: int = 50074,
            age_s: float = 0.0) -> None:
    """Record *hosts* as observed endpoints of lab2, *age_s* seconds ago."""
    for h in hosts:
        reg.record_observed_endpoint("lab2", host=h, port=port,
                                     boot_epoch_ms=BOOT, allow_create=True)
    if age_s:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                              time.gmtime(time.time() - age_s))
        for o in reg._entries["lab2"]["observed_endpoints"]:
            if o["host"] in hosts:
                o["seen_at"] = stamp


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def test_usable_ipv4_filters_non_machine_addresses():
    assert endpoint_hints.usable_ipv4("192.168.2.71")
    for bad in ("127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1",
                "::1", "not-an-ip"):
        assert not endpoint_hints.usable_ipv4(bad), bad


def test_age_s_parses_beacon_timestamps():
    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 42))
    assert 41 <= endpoint_hints.age_s(stamp, now) <= 43
    assert endpoint_hints.age_s("garbage") is None
    assert endpoint_hints.age_s(stamp, now - 1000) == 0.0  # never negative


async def test_resolve_name_hosts_dedups_and_drops_unusable(monkeypatch):
    def fake_getaddrinfo(name, *_a, **_k):
        table = {"lab2": ["10.0.0.5", "127.0.0.1"],
                 "lab2.local": ["10.0.0.5", "10.0.0.6"]}
        if name not in table:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0))
                for a in table[name]]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    got = await endpoint_hints.resolve_name_hosts(
        ["lab2", "lab2.local", "ghost", "lab2"])
    assert got == ["10.0.0.5", "10.0.0.6"]


def test_connect_failure_hint_names_live_beacons_and_the_next_step():
    hint = endpoint_hints.connect_failure_hint({"beacons": [
        {"machine": "lab2", "hosts": ["10.0.0.7", "10.0.0.8"],
         "age_s": 12.0, "fresh": True}]})
    assert "lab2" in hint and "10.0.0.7" in hint and "12s ago" in hint
    assert "connect" in hint and "machine=" in hint


def test_connect_failure_hint_without_beacons_points_at_name_and_scan():
    hint = endpoint_hints.connect_failure_hint({"beacons": []})
    assert "no agent beacon is on record" in hint
    assert "ping" in hint and "wait_agent" in hint


def test_wrong_machine_and_new_kinds_are_registered():
    kind, hint = classify("WrongMachineError: wrong_machine: 10.0.0.9:50074 "
                          "answered as 'X', but 'lab2' is 'Y' — refusing")
    assert kind == "wrong_machine" and "different machine" in hint
    assert {"wrong_machine", "endpoint_moved"} <= KNOWN_KINDS


# --------------------------------------------------------------------------- #
# Registry: beacons, identity, reverse lookup
# --------------------------------------------------------------------------- #

def test_registry_fresh_endpoints_respect_age(tmp_path):
    cfg = _cfg(tmp_path)
    _, reg = _session(cfg)
    _beacon(reg, "10.0.0.7")
    _beacon(reg, "10.0.0.8", age_s=600)
    fresh = reg.fresh_endpoints("lab2", 120)
    assert [o["host"] for o in fresh] == ["10.0.0.7"]
    assert fresh[0]["age_s"] < 5


def test_registry_beacon_overview_groups_one_beat_and_skips_shells(tmp_path):
    cfg = _cfg(tmp_path)
    _, reg = _session(cfg)
    _beacon(reg, "10.0.0.7", "10.0.0.8")          # a two-NIC box, one beat
    reg.record_observed_endpoint(                 # an IP-named ghost shell
        "10.0.0.7", host="10.0.0.7", port=50074, allow_create=True)
    rows = reg.beacon_overview()
    assert [r["machine"] for r in rows] == ["lab2"]
    assert sorted(rows[0]["hosts"]) == ["10.0.0.7", "10.0.0.8"]
    assert rows[0]["fresh"] is True


def test_registry_alias_for_host_ignores_shells_and_refuses_ambiguity(tmp_path):
    cfg = _cfg(tmp_path)
    _, reg = _session(cfg)
    assert reg.alias_for_host("10.0.0.200") == "lab2"       # via alt_hosts
    _beacon(reg, "10.0.0.7")
    reg.record_observed_endpoint(
        "10.0.0.7", host="10.0.0.7", port=50074, allow_create=True)
    assert reg.alias_for_host("10.0.0.7") == "lab2"          # shell ignored
    assert reg.alias_for_host("10.9.9.9") is None
    cfg.machines["lab3"] = MachineConfig(host="10.0.0.9", token="t")
    assert reg.alias_for_host("10.0.0.9") is None            # lab2 AND lab3


def test_registry_learn_computer_name_is_write_once(tmp_path):
    cfg = _cfg(tmp_path)
    _, reg = _session(cfg)
    assert reg.learn_computer_name("lab2", "LAB2-WIN") is True
    assert reg.learn_computer_name("lab2", "SOMEONE-ELSE") is False
    assert reg.computer_name_for("lab2") == "LAB2-WIN"
    assert reg.learn_computer_name("nope", "X") is False     # unknown alias
    # the learned name also resolves beacons that arrive under it
    assert reg.find_alias_by_computer_name("lab2-win") == "lab2"


# --------------------------------------------------------------------------- #
# Fix 2 — Session.connect: beacon-first, names, identity
# --------------------------------------------------------------------------- #

async def test_connect_prefers_fresh_beacon_over_stale_configured_host(
        tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.77": "LAB2-WIN"}        # configured .9 is dead
    _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))
    # a learned (beacon) address is attached only once it proves
    # it is lab2 — here through the stored computer_name.
    reg.set("lab2", computer_name="LAB2-WIN")
    _beacon(reg, "10.0.0.77")
    st = await session.connect(machine="lab2", owner="o1")
    assert st["endpoint_source"] == "beacon"
    assert session.clients["lab2.kernel"].endpoint == "10.0.0.77:50074"
    assert st["endpoint_fallback"]["used"] == "10.0.0.77"
    assert st["endpoint_fallback"]["configured"] == "10.0.0.9"


async def test_stale_beacon_is_not_trusted_as_current(tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.9": "LAB2-WIN", "10.0.0.77": "LAB2-WIN"}
    _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))
    _beacon(reg, "10.0.0.77", age_s=900)          # a quarter hour old
    st = await session.connect(machine="lab2", owner="o1")
    assert st["endpoint_source"] == "configured"   # not 'beacon'


async def test_name_resolution_finds_machine_when_nothing_remembered_answers(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_NAME_RESOLVE", "1")
    world = _World()
    world.live = {"10.0.0.77": "LAB2-WIN"}
    _install(monkeypatch, world)
    asked: list[list[str]] = []

    async def fake_resolve(names, **_k):
        asked.append(list(names))
        return ["10.0.0.77"]

    monkeypatch.setattr(
        "pry.session.endpoint_heal.resolve_name_hosts", fake_resolve)
    session, reg = _session(_cfg(tmp_path))
    reg.set("lab2", computer_name="LAB2-WIN")     # proof required
    st = await session.connect(machine="lab2", owner="o1")
    assert st["endpoint_source"] == "name"
    assert session.clients["lab2.kernel"].endpoint == "10.0.0.77:50074"
    assert asked and {"lab2", "lab2.local"} <= set(asked[0])


async def test_name_resolution_is_skipped_when_disabled(tmp_path, monkeypatch):
    world = _World()
    _install(monkeypatch, world)
    called = []

    async def fake_resolve(names, **_k):
        called.append(names)
        return ["10.0.0.77"]

    monkeypatch.setattr(
        "pry.session.endpoint_heal.resolve_name_hosts", fake_resolve)
    session, _ = _session(_cfg(tmp_path))       # conftest: NAME_RESOLVE=0
    with pytest.raises(OSError):
        await session.connect(machine="lab2", owner="o1")
    assert called == []


async def test_connect_refuses_a_host_that_answers_as_another_machine(
        tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.9": "OTHER-BOX"}         # recycled lease
    fake = _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))
    reg.set("lab2", computer_name="LAB2-WIN")
    with pytest.raises(WrongMachineError) as ei:
        await session.connect(machine="lab2", owner="o1")
    assert "wrong_machine" in str(ei.value)
    assert ei.value.answered == "OTHER-BOX" and ei.value.expected == "LAB2-WIN"
    assert "lab2.kernel" not in session.clients
    # the rejected channel was dialed, then closed — not left open
    assert fake.instances and all(c.closed for c in fake.instances)


async def test_connect_skips_the_wrong_machine_and_uses_the_right_one(
        tmp_path, monkeypatch):
    world = _World()
    # A *fresh beacon* address that has since been recycled to another box,
    # while the configured address is still the real machine.
    world.live = {"10.0.0.77": "OTHER-BOX", "10.0.0.9": "LAB2-WIN"}
    _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))
    reg.set("lab2", computer_name="LAB2-WIN")
    _beacon(reg, "10.0.0.77")
    st = await session.connect(machine="lab2", owner="o1")
    assert st["endpoint_source"] == "configured"
    assert session.clients["lab2.kernel"].endpoint == "10.0.0.9:50074"


async def test_explicit_host_is_trusted_as_typed(tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.5": "OTHER-BOX"}
    _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))
    reg.set("lab2", computer_name="LAB2-WIN")
    st = await session.connect(machine="lab2", host="10.0.0.5",
                               port=50074, owner="o1")
    assert st["endpoint_source"] == "explicit"


async def test_unknown_identity_never_blocks_a_connect(tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.9": "ANYTHING"}
    _install(monkeypatch, world)
    session, _ = _session(_cfg(tmp_path))          # no stored computer_name
    st = await session.connect(machine="lab2", owner="o1")
    assert st["endpoint_source"] == "configured"


async def test_learned_candidates_outside_the_allowlist_are_skipped(
        tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.9": "LAB2-WIN", "192.168.56.101": "LAB2-WIN"}
    _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))
    _beacon(reg, "192.168.56.101")                 # the VM's host-only NIC
    st = await session.connect(machine="lab2", owner="o1")
    assert st["endpoint_source"] == "configured"
    assert "192.168.56.101" not in world.probed    # never even dialed


async def test_operator_supplied_hosts_outside_the_allowlist_still_abort(
        tmp_path, monkeypatch):
    from pry.allowlist import TargetNotAllowed
    world = _World()
    _install(monkeypatch, world)
    session, _ = _session(_cfg(tmp_path))
    with pytest.raises(TargetNotAllowed):
        await session.connect(machine="lab2", host="8.8.8.8", port=50074,
                              owner="o1")


async def test_bare_connect_follows_the_beacons_of_the_machine_that_owned_the_stale_host(
        tmp_path, monkeypatch):
    """The default `connect()` uses the legacy configured endpoint, which
    went stale. It must follow the machine that address belonged to."""
    world = _World()
    world.live = {"10.0.0.77": "LAB2-WIN"}         # legacy .200 is dead
    _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))        # lab2 lists .200 as alt
    reg.set("lab2", computer_name="LAB2-WIN")      # proof required
    _beacon(reg, "10.0.0.77")
    st = await session.connect(name="kernel", owner="o1")
    assert st["endpoint_source"] == "beacon"
    assert st["view"].lower() == "lab2-win.kernel"  # label learned from host_info


async def test_bare_connect_with_an_explicit_host_is_not_second_guessed(
        tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.77": "LAB2-WIN"}
    _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))
    _beacon(reg, "10.0.0.77")
    with pytest.raises(OSError) as ei:
        await session.connect(host="10.0.0.200", port=50074, token="tok",
                              owner="o1")
    # the operator typed a dead address: respected, but the failure carries
    # where the machines actually are
    info = ei.value.endpoint_info
    assert info["explicit"] is True
    assert info["beacons"][0]["machine"] == "lab2"
    assert info["beacons"][0]["hosts"] == ["10.0.0.77"]


# --------------------------------------------------------------------------- #
# Fix 1 — the failure envelope (through the MCP surface)
# --------------------------------------------------------------------------- #

async def _mcp(tmp_path, monkeypatch, world, *, rebind=True):
    _install(monkeypatch, world, rebind=rebind)
    cfg = _cfg(tmp_path)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg,
                  leases=LeaseManager(
                      publish_event=lambda ev: asyncio.create_task(
                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    _ = ctx.registry            # production loads it at startup
    return ctx, build_server(ctx)


async def _call(server, args: dict) -> dict:
    token = CLIENT_ID.set("peer-heal")
    try:
        result = await server.call_tool("target_manage", args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    err = body.get("error")
    merged["kind"] = (err["kind"] if isinstance(err, dict) and "kind" in err
                      else body.get("kind"))
    return merged


async def test_failed_connect_lists_live_beacons_and_the_next_step(
        tmp_path, monkeypatch):
    world = _World()                                # nothing answers
    ctx, server = await _mcp(tmp_path, monkeypatch, world)
    _beacon(ctx.registry, "10.0.0.77", "10.0.0.78")
    body = await _call(server, {"action": "connect", "host": "10.0.0.250",
                                "port": 50074, "token": "tok"})
    assert body["ok"] is False
    assert body["kind"] == "connect_timeout"
    assert body["beacons"][0]["machine"] == "lab2"
    assert sorted(body["beacons"][0]["hosts"]) == ["10.0.0.77", "10.0.0.78"]
    assert "10.0.0.250 (explicit)" in body["tried"]
    assert "beaconing right now" in body["hint"]
    assert "machine='<that alias>'" in body["hint"]
    # the old advice was the whole hint; it must no longer be the only text
    assert "DHCP" in body["hint"]


async def test_failed_connect_without_any_beacon_says_so_and_offers_a_scan(
        tmp_path, monkeypatch):
    world = _World()
    ctx, server = await _mcp(tmp_path, monkeypatch, world)
    body = await _call(server, {"action": "connect", "host": "10.0.0.250",
                                "port": 50074, "token": "tok"})
    assert body["kind"] == "connect_timeout"
    assert "no agent beacon is on record" in body["hint"]
    assert "wait_agent" in body["hint"] and "ping" in body["hint"]
    assert "beacons" not in body


async def test_wrong_machine_surfaces_as_its_own_kind(tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.9": "OTHER-BOX"}
    ctx, server = await _mcp(tmp_path, monkeypatch, world)
    ctx.registry.set("lab2", computer_name="LAB2-WIN")
    body = await _call(server, {"action": "connect", "machine": "lab2"})
    assert body["ok"] is False
    assert body["kind"] == "wrong_machine"
    assert "OTHER-BOX" in body["error"] and "LAB2-WIN" in body["error"]


async def test_connect_learns_identity_only_from_trusted_sources(
        tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.77": "LAB2-WIN", "10.0.0.9": "LAB2-WIN"}
    ctx, server = await _mcp(tmp_path, monkeypatch, world)
    # reached through the configured address: label 'lab2' != 'LAB2-WIN', and
    # a configured host may be a stale lease — don't pin an identity to it
    body = await _call(server, {"action": "connect", "machine": "lab2"})
    assert body["ok"] is True, body
    assert ctx.registry.computer_name_for("lab2") == ""
    await _call(server, {"action": "disconnect", "name": "lab2.kernel"})
    # reached through a fresh beacon: that is the machine itself
    _beacon(ctx.registry, "10.0.0.77")
    body = await _call(server, {"action": "connect", "machine": "lab2"})
    assert body["ok"] is True, body
    assert ctx.registry.computer_name_for("lab2") == "LAB2-WIN"


# --------------------------------------------------------------------------- #
# Fix 3 — link failover
# --------------------------------------------------------------------------- #

async def _connected(tmp_path, monkeypatch, world, *, rebind=True):
    """A session with lab2.kernel connected at .9, plus its registry."""
    world.live = {"10.0.0.9": "LAB2-WIN"}
    _install(monkeypatch, world, rebind=rebind)
    session, reg = _session(_cfg(tmp_path))
    await session.connect(machine="lab2", owner="o1")
    return session, reg


def _move(world, *, to="10.0.0.77", name="LAB2-WIN", boot=BOOT):
    """The machine leaves .9 and shows up at *to*."""
    world.live.pop("10.0.0.9", None)
    world.live[to] = name
    world.boot[to] = boot


async def test_failover_repoints_the_same_client_object(tmp_path, monkeypatch):
    world = _World()
    session, reg = await _connected(tmp_path, monkeypatch, world)
    client = session.clients["lab2.kernel"]
    _move(world)
    _beacon(reg, "10.0.0.77")
    notice = await session._try_failover("lab2.kernel")
    assert notice and notice["kind"] == "endpoint_moved"
    assert notice["from"] == "10.0.0.9:50074" and notice["to"] == "10.0.0.77:50074"
    assert session.clients["lab2.kernel"] is client            # same object
    assert client.endpoint == "10.0.0.77:50074"
    assert session.pending_endpoint_notices["lab2.kernel"] == notice
    assert session._last_good_host["lab2"] == "10.0.0.77"
    assert "boot_change" not in notice                          # no reboot


async def test_failover_swaps_the_object_for_clients_without_rebind(
        tmp_path, monkeypatch):
    world = _World()
    session, reg = await _connected(tmp_path, monkeypatch, world, rebind=False)
    old = session.clients["lab2.kernel"]
    _move(world)
    _beacon(reg, "10.0.0.77")
    notice = await session._try_failover("lab2.kernel")
    assert notice
    new = session.clients["lab2.kernel"]
    assert new is not old and new.endpoint == "10.0.0.77:50074"
    assert old.closed is True


async def test_failover_refuses_a_different_machine(tmp_path, monkeypatch):
    world = _World()
    session, reg = await _connected(tmp_path, monkeypatch, world)
    client = session.clients["lab2.kernel"]
    _move(world, name="OTHER-BOX")
    _beacon(reg, "10.0.0.77")
    assert await session._try_failover("lab2.kernel") is None
    assert client.endpoint == "10.0.0.9:50074"
    assert "lab2.kernel" not in session.pending_endpoint_notices


async def test_failover_needs_proof_when_the_name_is_unknown(
        tmp_path, monkeypatch):
    """No stored/learned computer_name: only the same OS boot proves it."""
    world = _World()
    world.live = {"10.0.0.9": ""}                   # HostInfo gives no name
    _install(monkeypatch, world)
    session, reg = _session(_cfg(tmp_path))
    await session.connect(machine="lab2", owner="o1")
    # moved AND rebooted: nothing ties the new address to this machine
    world.live.pop("10.0.0.9")
    world.live["10.0.0.77"] = ""
    world.boot["10.0.0.77"] = BOOT + 600_000
    _beacon(reg, "10.0.0.77")
    assert await session._try_failover("lab2.kernel") is None
    # same boot, new address: provably the same running machine
    world.boot["10.0.0.77"] = BOOT
    assert (await session._try_failover("lab2.kernel"))["to"] == "10.0.0.77:50074"


async def test_failover_reports_a_reboot_and_calls_the_heal_hook(
        tmp_path, monkeypatch):
    world = _World()
    session, reg = await _connected(tmp_path, monkeypatch, world)
    seen: list[tuple] = []

    async def hook(name, notice, change):
        seen.append((name, notice, change))

    session.set_link_heal_hook(hook)
    _move(world, boot=BOOT + 600_000)               # new address AND new boot
    _beacon(reg, "10.0.0.77")
    notice = await session._try_failover("lab2.kernel")
    assert notice["boot_change"] == "new_boot"
    assert session.pending_boot_notices["lab2.kernel"]["kind"] == "new_boot"
    assert session.pending_boot_notices["lab2.kernel"]["source"] == "link_watch"
    assert len(seen) == 1 and seen[0][0] == "lab2.kernel"
    assert seen[0][2]["kind"] == "new_boot"


async def test_user_view_follows_its_verified_kernel_sibling(
        tmp_path, monkeypatch):
    """The umagent has no HostInfo, and the machine rebooted on the way, so
    neither a name nor a boot epoch proves the new address — but its kernel
    sibling was already verified there."""
    world = _World()
    world.no_hostinfo_ports = {50075}
    session, reg = await _connected(tmp_path, monkeypatch, world)
    await session.connect(machine="lab2", name="lab2.user", owner="o1")
    assert {"lab2.kernel", "lab2.user"} <= set(session.clients)
    _move(world, boot=BOOT + 600_000)               # new address AND new boot
    _beacon(reg, "10.0.0.77")
    # user first: nothing vouches for the new address yet
    assert await session._try_failover("lab2.user") is None
    assert (await session._try_failover("lab2.kernel"))["boot_change"] == "new_boot"
    notice = await session._try_failover("lab2.user")
    assert notice and notice["to"] == "10.0.0.77:50075"
    assert session.clients["lab2.user"].endpoint == "10.0.0.77:50075"


async def test_no_failover_when_the_beacon_is_the_current_address(
        tmp_path, monkeypatch):
    world = _World()
    session, reg = await _connected(tmp_path, monkeypatch, world)
    _beacon(reg, "10.0.0.9")                        # same host: a blip, not a move
    assert await session._try_failover("lab2.kernel") is None


async def test_failover_falls_back_to_name_resolution(tmp_path, monkeypatch):
    monkeypatch.setenv("PRY_NAME_RESOLVE", "1")
    world = _World()
    session, reg = await _connected(tmp_path, monkeypatch, world)
    _move(world)                                    # and no beacon at all

    async def fake_resolve(names, **_k):
        return ["10.0.0.77"]

    monkeypatch.setattr(
        "pry.session.endpoint_heal.resolve_name_hosts", fake_resolve)
    notice = await session._try_failover("lab2.kernel")
    assert notice and notice["source"] == "name"


async def test_link_watch_fails_over_after_consecutive_failures(
        tmp_path, monkeypatch):
    world = _World()
    session, reg = await _connected(tmp_path, monkeypatch, world)
    # enabled only now: connect() would otherwise arm its own default-
    # interval watcher and this fast one would be refused as a duplicate
    monkeypatch.setenv("PRY_LINK_HEAL", "1")
    assert session.start_link_watch("lab2.kernel", interval_s=0.02,
                                    fail_threshold=2, cooldown_s=0.05)
    assert session.start_link_watch("lab2.kernel") is False   # idempotent
    try:
        await asyncio.sleep(0.15)                    # healthy: nothing happens
        assert "lab2.kernel" not in session.pending_endpoint_notices
        _move(world)
        _beacon(reg, "10.0.0.77")
        for _ in range(100):
            if "lab2.kernel" in session.pending_endpoint_notices:
                break
            await asyncio.sleep(0.03)
        notice = session.pending_endpoint_notices.get("lab2.kernel")
        assert notice and notice["to"] == "10.0.0.77:50074"
    finally:
        session.stop_link_watch()


async def test_link_watch_backs_off_when_there_is_nowhere_to_go(
        tmp_path, monkeypatch):
    world = _World()
    session, reg = await _connected(tmp_path, monkeypatch, world)
    monkeypatch.setenv("PRY_LINK_HEAL", "1")
    tries: list[int] = []
    real = session._try_failover

    async def counting(name):
        tries.append(1)
        return await real(name)

    session._try_failover = counting                # type: ignore[assignment]
    world.live.clear()                              # machine is simply off
    session.start_link_watch("lab2.kernel", interval_s=0.02,
                             fail_threshold=1, cooldown_s=0.3)
    try:
        await asyncio.sleep(0.5)
    finally:
        session.stop_link_watch()
    # 25 ticks passed, but the cooldown (0.3s, doubling) caps the attempts
    assert 1 <= len(tries) <= 3


async def test_link_watch_exits_when_the_view_is_gone(tmp_path, monkeypatch):
    world = _World()
    session, _ = await _connected(tmp_path, monkeypatch, world)
    monkeypatch.setenv("PRY_LINK_HEAL", "1")
    assert session.start_link_watch("lab2.kernel", interval_s=0.02)
    task = session._link_watchers["lab2.kernel"]
    session.clients.pop("lab2.kernel")
    await asyncio.wait_for(task, timeout=2.0)
    assert task.done()


async def test_link_watch_is_off_when_disabled(tmp_path, monkeypatch):
    world = _World()
    session, _ = await _connected(tmp_path, monkeypatch, world)
    # conftest sets PRY_LINK_HEAL=0: connect() armed nothing
    assert session._link_watchers == {}
    assert session.start_link_watch("lab2.kernel") is False


async def test_status_reports_the_endpoint_move_once(tmp_path, monkeypatch):
    world = _World()
    world.live = {"10.0.0.9": "LAB2-WIN"}
    ctx, server = await _mcp(tmp_path, monkeypatch, world)
    body = await _call(server, {"action": "connect", "machine": "lab2"})
    assert body["ok"] is True, body
    ctx.session.pending_endpoint_notices["lab2.kernel"] = {
        "kind": "endpoint_moved", "view": "lab2.kernel",
        "from": "10.0.0.8:50074", "to": "10.0.0.9:50074", "source": "beacon"}
    first = await _call(server, {"action": "status", "name": "lab2.kernel"})
    assert first["endpoint_change"]["to"] == "10.0.0.9:50074"
    assert any("moved from 10.0.0.8:50074 to 10.0.0.9:50074" in w
               for w in first.get("warnings", []))
    second = await _call(server, {"action": "status", "name": "lab2.kernel"})
    assert "endpoint_change" not in second
