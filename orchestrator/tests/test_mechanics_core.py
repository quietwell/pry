"""mechanics audit — orchestrator core regressions.

Allowlist (resolve once, check every address, loopback equivalence),
config warnings + the soft-fault gate, atomic / read-only registry, focus
expiry, connection-scoped caller ids, fresh-context background tasks,
audit reaping + cancelled-call auditing, link-heal rebind bounds, the
snapshot pump view, lease touch, and memory_manage watch mode='hw'.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from pry import allowlist
from pry.allowlist import TargetNotAllowed, check_authorized
from pry.caller import CLIENT_ID
from pry.config import PryConfig, TargetConfig, load_config


def _fake_gai(table):
    def fake(name, *_a, **_k):
        if name not in table:
            raise socket.gaierror("no such host")
        out = []
        for a in table[name]:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            sa = (a, 0, 0, 0) if fam == socket.AF_INET6 else (a, 0)
            out.append((fam, socket.SOCK_STREAM, 6, "", sa))
        return out
    return fake


# --------------------------------------------------------------------------- #
# item 3 — allowlist
# --------------------------------------------------------------------------- #

def test_localhost_v6_first_passes_a_v4_only_loopback_allowlist(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        _fake_gai({"localhost": ["::1", "127.0.0.1"]}))
    # Windows resolves localhost to ::1 first; 127.0.0.0/8 must still admit
    # it, and the IPv4 literal is what gets dialed.
    assert check_authorized("localhost", ["127.0.0.0/8"]) == "127.0.0.1"
    assert allowlist.address_allowed("::1", ["127.0.0.0/8"])
    assert allowlist.address_allowed("127.0.0.5", ["::1/128"])
    assert allowlist.address_allowed("::ffff:10.0.0.5", ["10.0.0.0/24"])


def test_every_resolved_address_must_be_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_gai(
        {"split.lab": ["10.0.0.5", "8.8.8.8"], "ok.lab": ["10.0.0.6"]}))
    with pytest.raises(TargetNotAllowed) as ei:
        check_authorized("split.lab", ["10.0.0.0/24"])
    assert "8.8.8.8" in str(ei.value)
    assert check_authorized("ok.lab", ["10.0.0.0/24"]) == "10.0.0.6"


async def test_async_check_resolves_off_the_event_loop(monkeypatch):
    seen: list[int] = []
    real = allowlist.resolve_all

    def spy(host):
        seen.append(threading.get_ident())
        return ["10.0.0.7"]

    monkeypatch.setattr(allowlist, "resolve_all", spy)
    ip = await allowlist.check_authorized_async("lab.example", ["10.0.0.0/24"])
    assert ip == "10.0.0.7"
    assert seen and seen[0] != threading.get_ident()
    # IP literals never touch the resolver
    seen.clear()
    monkeypatch.setattr(allowlist, "resolve_all", real)
    assert await allowlist.check_authorized_async(
        "10.0.0.8", ["10.0.0.0/24"]) == "10.0.0.8"


async def test_session_connect_dials_the_checked_ip(tmp_path, monkeypatch):
    """A configured host NAME is resolved once and the checked literal is
    what the client dials — the resolver can't hand gRPC another answer."""
    from pry.session import Session
    monkeypatch.setenv("PRY_AUDIT_DISABLE", "1")
    monkeypatch.setattr(socket, "getaddrinfo",
                        _fake_gai({"labvm.lab": ["10.0.0.9"]}))
    dialed: list[str] = []

    class Fake:
        def __init__(self, host, port, token="", timeout_ms=0, max_inflight=16):
            self.endpoint = f"{host}:{port}"
            dialed.append(host)

        async def connect(self):
            return None

        async def status(self):
            return {"ok": True}

        async def host_info(self, **_k):
            return {"ok": False}

        async def close(self):
            return None

    async def probe(host, port, timeout_s=3.0):
        dialed.append(f"probe:{host}")

    monkeypatch.setattr("pry.session.AgentClient", Fake)
    monkeypatch.setattr("pry.session._probe_tcp", probe)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["10.0.0.0/24"]
    cfg.target = TargetConfig(host="labvm.lab", port=50074, token="t")
    s = Session(cfg)
    st = await s.connect(owner="o1")
    assert dialed == ["probe:10.0.0.9", "10.0.0.9"]
    assert s.clients[st["view"]].endpoint == "10.0.0.9:50074"


async def test_rediscover_filters_every_candidate_through_the_allowlist(
        tmp_path, monkeypatch):
    from pry.mcp.tools.target import recover
    monkeypatch.setenv("PRY_AUDIT_DISABLE", "1")
    probed: list[list[str]] = []

    async def fake_probe_many(hosts, port, timeout_s, limit=16):
        probed.append(list(hosts))
        return [(h, port, h == "10.0.0.7", 1.0) for h in hosts]

    monkeypatch.setattr("pry.session.probe_hosts_concurrent",
                        fake_probe_many)
    ctx = _ctx(tmp_path, monkeypatch, allow=["10.0.0.0/24"])
    out = json.loads(await recover.do_rediscover(
        ctx, machine="lab2", name="", port=50074,
        hosts=["10.0.0.7", "8.8.8.8", "192.168.56.1"], cidr="",
        timeout_s=1.0))
    # the configured host (10.0.0.9) + the allowed caller host only
    assert probed == [["10.0.0.9", "10.0.0.7"]]
    assert {r["host"] for r in out["refused"]} == {"8.8.8.8", "192.168.56.1"}
    assert out["answered"] == ["10.0.0.7"]


# --------------------------------------------------------------------------- #
# item 5 — config
# --------------------------------------------------------------------------- #

def test_unknown_and_mistyped_keys_are_reported(tmp_path, caplog):
    p = tmp_path / "c.yaml"
    p.write_text(
        "security:\n"
        "  allow_kernel_softfualt: true\n"      # typo
        "  allow_delete: 'false'\n"             # string bool
        "  allow_driver_load: maybe\n"          # garbage bool
        "mcp:\n  remote_cidrs: 10.0.0.0/24\n"   # scalar for a list
        "bogus_root: 1\n", encoding="utf-8")
    with caplog.at_level("WARNING", logger="pry.config"):
        cfg = load_config(p)
    w = cfg.config_warnings
    assert any("security.allow_kernel_softfualt" in x
               and "allow_kernel_softfault" in x for x in w)   # did-you-mean
    assert any("bogus_root" in x for x in w)
    assert any("allow_driver_load" in x for x in w)
    assert cfg.security.allow_kernel_softfault is False         # fail-safe
    assert cfg.security.allow_delete is False
    assert cfg.security.allow_driver_load is True               # default kept
    assert cfg.mcp.remote_cidrs == ["10.0.0.0/24"]
    assert any("allow_kernel_softfualt" in r.getMessage() for r in caplog.records)


def test_machine_dict_keys_are_not_views(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "machines:\n"
        "  lab2:\n"
        "    host: 10.0.0.5\n"
        "    scan: {dir: scans, disk_quota_bytes: 1}\n"
        "    pointer_map: {max_maps: 2}\n"
        "    user: {port: 50075}\n"
        "    gadget: {port: 1}\n", encoding="utf-8")
    cfg = load_config(p)
    m = cfg.machines["lab2"]
    assert set(m.views) == {"user"}
    assert m.scan == {"dir": "scans", "disk_quota_bytes": 1}
    assert m.pointer_map == {"max_maps": 2}
    assert any("machines.lab2.gadget" in x for x in cfg.config_warnings)


def test_local_and_example_configs_load_clean():
    root = Path(__file__).resolve().parents[2] / "configs"
    for name in ("example.yaml", "local.yaml"):
        if (root / name).is_file():
            assert load_config(root / name, log_warnings=False) \
                .config_warnings == [], name


async def test_memory_manage_refuses_allow_fault_by_default(tmp_path, monkeypatch):
    from pry.mcp.tools import build_server
    ctx = _ctx(tmp_path, monkeypatch)
    server = build_server(ctx)
    body = await _call_tool(server, "memory_manage", {
        "action": "read", "address": "0x1000", "size": 8,
        "space": "kernel", "allow_fault": True})
    assert body["ok"] is False
    assert body["kind"] == "not_allowed"
    assert "allow_kernel_softfault" in json.dumps(body)


def test_agent_client_strips_allow_fault_unless_enabled():
    from pry.agent_client import AgentClient
    c = AgentClient("127.0.0.1", 1, "t")
    assert c._softfault_ok(True) is False
    c.allow_softfault = True
    assert c._softfault_ok(True) is True
    assert c._softfault_ok(False) is False


# --------------------------------------------------------------------------- #
# item 6 — registry persistence
# --------------------------------------------------------------------------- #

def _reg(tmp_path):
    from pry.registry import MachineRegistry
    cfg = PryConfig()
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    return cfg, MachineRegistry.load(cfg)


def test_registry_writes_atomically_and_keeps_a_backup(tmp_path):
    cfg, reg = _reg(tmp_path)
    reg.register("lab2", trust="lab", purpose="one")
    reg.set("lab2", purpose="two")
    path = reg.path
    assert json.loads(path.read_text())["machines"]["lab2"]["purpose"] == "two"
    assert json.loads(reg.backup_path.read_text())["machines"]["lab2"][
        "purpose"] == "one"
    assert not list(path.parent.glob("targets.json.tmp-*"))


def test_corrupt_registry_is_never_overwritten(tmp_path):
    from pry.registry import MachineRegistry, RegistryReadOnly
    cfg, reg = _reg(tmp_path)
    reg.register("lab2", trust="lab", purpose="keep me")
    reg.register("lab3", trust="lab")              # .bak now holds lab2
    reg.path.write_text("{ this is not json", encoding="utf-8")
    cfg2 = PryConfig()
    cfg2.artifacts.dir = cfg.artifacts.dir
    reg2 = MachineRegistry.load(cfg2)
    assert reg2.read_only
    assert "lab2" in reg2.all()                    # served from the .bak
    with pytest.raises(RegistryReadOnly):
        reg2.register("lab4", trust="lab")
    with pytest.raises(RegistryReadOnly):
        reg2.unregister("lab2")
    # a beacon is still learned in memory (DHCP heal) but never saved
    assert reg2.record_observed_endpoint("lab2", host="10.0.0.5", port=1)
    assert reg2.path.read_text(encoding="utf-8") == "{ this is not json"
    assert reg2.observed_endpoints("lab2")[0]["host"] == "10.0.0.5"


async def test_read_only_registry_is_a_status_warning(tmp_path, monkeypatch):
    from pry.mcp.tools.target.status import _status_health_warnings
    ctx = _ctx(tmp_path, monkeypatch)
    ctx.registry.read_only_reason = "targets.json failed to parse (x)"
    ctx.cfg._warnings.append("unknown config key 'security.x' ignored")
    out = _status_health_warnings(ctx, {"driver_abi_version": 17,
                                        "agent_abi_version": 18,
                                        "driver_abi_ok": False}, True)
    assert any("READ-ONLY" in w for w in out)
    assert any("security.x" in w for w in out)
    assert any("ABI mismatch" in w for w in out)
    # an old agent (all-zero ABI fields) is not a mismatch
    assert not any("ABI" in w for w in _status_health_warnings(
        ctx, {"driver_abi_ok": False}, True))


# --------------------------------------------------------------------------- #
# item 7 — caller identity and focus
# --------------------------------------------------------------------------- #

def test_reused_port_after_the_keepalive_window_is_a_new_identity(monkeypatch):
    import pry.caller as caller
    from _multi_fakes import _FakeRequest
    caller._ENDPOINTS.clear()
    clock = [1000.0]
    monkeypatch.setattr(caller.time, "monotonic", lambda: clock[0])
    req = _FakeRequest({}, host="127.0.0.1", port=61000)

    def call() -> str:
        caller._endpoint_begin("127.0.0.1", 61000)
        try:
            return caller._resolve_client_id(req, None)
        finally:
            caller._endpoint_end("127.0.0.1", 61000)

    first = call()
    clock[0] += 2.0                       # same keep-alive burst
    assert call() == first == "anon-127.0.0.1:61000"
    clock[0] += caller.KEEPALIVE_S + 5    # socket closed by the server
    second = call()
    assert second == "anon-127.0.0.1:61000#2" and second != first
    # a long call in flight never splits its own connection
    caller._endpoint_begin("127.0.0.1", 61000)
    clock[0] += 60
    assert caller._resolve_client_id(req, None) == second
    caller._endpoint_end("127.0.0.1", 61000)


def test_focus_entries_expire_and_fail_closed(monkeypatch):
    from pry.session import Session
    monkeypatch.setenv("PRY_AUDIT_DISABLE", "1")
    s = Session(PryConfig())
    s.clients = {"lab2.kernel": object(), "lab3.kernel": object()}
    s._set_focus_entry("chat-a", "lab2", "kernel")
    s._set_focus_entry("anon-127.0.0.1:5", "lab3", "kernel")
    assert s.focus_of("chat-a")["machine"] == "lab2"
    stamps = s._focus_stamps()
    stamps["anon-127.0.0.1:5"] -= s.ANON_FOCUS_TTL_S + 1
    assert s.focus_of("anon-127.0.0.1:5") is None          # anon: short TTL
    stamps["chat-a"] -= s.FOCUS_TTL_S + 1
    dropped = s.prune_focus(now=time.monotonic())
    assert dropped == ["chat-a"] and "chat-a" not in s._focus


# --------------------------------------------------------------------------- #
# item 8 — background tasks never run as the chat
# --------------------------------------------------------------------------- #

async def test_background_tasks_start_in_a_fresh_context(monkeypatch):
    from pry.caller import current_client_id, spawn_background
    from pry.session import Session
    monkeypatch.setenv("PRY_AUDIT_DISABLE", "1")
    seen: dict[str, str] = {}

    async def probe():
        seen["id"] = current_client_id()

    token = CLIENT_ID.set("chat-42")
    try:
        await spawn_background(probe(), name="t", owner="orchestrator:test")
        s = Session(PryConfig())

        class C:
            async def status(self):
                seen["mon"] = current_client_id()
                return {}

        s.clients["lab2.kernel"] = C()
        assert s.start_boot_monitor("lab2.kernel", interval_s=0.01)
        for _ in range(100):
            if "mon" in seen:
                break
            await asyncio.sleep(0.01)
        s.stop_boot_monitor()
    finally:
        CLIENT_ID.reset(token)
    assert seen["id"] == "orchestrator:test"
    assert seen["mon"] == "orchestrator:boot_monitor"


async def test_watchdog_auto_arm_runs_as_the_orchestrator(tmp_path, monkeypatch):
    from pry import snapshot
    from pry.caller import current_client_id
    ctx = _ctx(tmp_path, monkeypatch)
    ctx.cfg.watchdog.auto_arm = {"id": 7, "deadline_ms": 45000,
                                 "interval_ms": 10000}
    seen = {}

    async def fake_kick_start(ctx_, c, view, wid, *a):
        seen["owner"] = current_client_id()
        return {"ok": True}

    monkeypatch.setattr(snapshot, "_auto_kick_start", fake_kick_start)

    class C:
        async def status(self):
            return {"driver_state": "DRIVER_SERVICE"}

        async def watchdog_list(self):
            return {"entries": []}

    token = CLIENT_ID.set("chat-42")
    try:
        res = await snapshot.auto_arm_after_load(ctx, C(), "lab2.kernel")
        after = current_client_id()
    finally:
        CLIENT_ID.reset(token)
    assert res == {"ok": True}
    assert seen["owner"] == snapshot.AUTO_ARM_OWNER
    assert after == "chat-42"


# --------------------------------------------------------------------------- #
# item 9 — link heal: rebind is bounded and never wedges the client
# --------------------------------------------------------------------------- #

async def test_rebind_gives_up_and_restores_the_old_target(monkeypatch):
    from pry.agent_client import AgentClient
    c = AgentClient("127.0.0.1", 1, "t")
    c.REBIND_READY_S = 0.05
    c.REBIND_ATTEMPTS = 2
    monkeypatch.setattr(asyncio, "sleep", _fast_sleep)
    c._open_channel()
    old = c.endpoint
    # 192.0.2.1 is TEST-NET-1: never answers
    with pytest.raises(OSError) as ei:
        await c.rebind("192.0.2.1", 50074)
    assert "rebind to 192.0.2.1:50074 failed" in str(ei.value)
    assert c.endpoint == old
    assert c._channel is not None and c.agent is not None   # not wedged
    await c.close()


_real_sleep = asyncio.sleep


async def _fast_sleep(delay, *a, **k):
    await _real_sleep(0)


async def test_channel_closed_usage_error_is_retryable():
    import grpc

    from pry.agent_client import AgentClient
    from pry.agent_client._errors import AgentRpcError
    c = AgentClient("127.0.0.1", 1, "t")

    async def closed(*_a, **_k):
        raise grpc.aio.UsageError("Channel is closed")

    with pytest.raises(AgentRpcError) as ei:
        await c._call(closed, object())
    assert ei.value.kind == "unavailable"
    assert c.recent_ops()[-1]["status"] == "error"


async def test_link_heal_restarts_the_event_pump(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, monkeypatch)
    started: list[str] = []
    monkeypatch.setattr(ctx, "restart_event_pump",
                        lambda name=None: started.append(name))
    await ctx._on_link_healed("lab2.kernel", {"to": "10.0.0.9:50074"}, None)
    assert started == ["lab2.kernel"]


# --------------------------------------------------------------------------- #
# item 10 — audit
# --------------------------------------------------------------------------- #

def test_old_per_boot_audit_dirs_are_reaped(tmp_path):
    from pry.audit import reap_sibling_dirs
    old = tmp_path / "orch-1-1"
    new = tmp_path / "orch-2-2"
    keep = tmp_path / "orch-3-3"
    other = tmp_path / "orch-4-4"
    for d in (old, new, keep, other):
        d.mkdir()
    ancient = time.time() - 30 * 86400
    (old / "a.jsonl").write_text("{}\n")
    os.utime(old / "a.jsonl", (ancient, ancient))
    (new / "b.jsonl").write_text("{}\n")
    (keep / "c.jsonl").write_text("{}\n")
    os.utime(keep / "c.jsonl", (ancient, ancient))
    (other / "notes.txt").write_text("not audit")
    res = reap_sibling_dirs(tmp_path, keep, retain_days=14)
    assert not old.exists()                  # emptied, then removed
    assert (new / "b.jsonl").exists()        # fresh
    assert (keep / "c.jsonl").exists()       # the live writer's own dir
    assert other.exists()                    # non-audit content survives
    assert res == {"files": 1, "dirs": 1}


async def test_guard_audits_cancelled_calls_with_args(tmp_path, monkeypatch):
    from pry.mcp.tools._runtime.guard import _guard
    ctx = _ctx(tmp_path, monkeypatch)

    async def hang():
        await asyncio.sleep(30)

    task = asyncio.create_task(_guard(ctx, "memory_manage", "read",
                                      {"address": "0x10", "size": 4}, hang))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    row = ctx.session.tool_log[-1]
    assert (row.tool, row.action, row.ok, row.error) == (
        "memory_manage", "read", False, "cancelled")
    assert row.args["address"] == "0x10"


async def test_guard_audits_failures_once_with_args(tmp_path, monkeypatch):
    from pry.mcp.tools._runtime.guard import _guard
    ctx = _ctx(tmp_path, monkeypatch)

    async def boom():
        raise RuntimeError("UNAVAILABLE: agent gone")

    out = _body(await _guard(ctx, "memory_manage", "read",
                             {"address": "0x20"}, boom))
    assert out["ok"] is False
    rows = [t for t in ctx.session.tool_log if t.tool == "memory_manage"]
    assert len(rows) == 1
    assert rows[0].ok is False and rows[0].args["address"] == "0x20"
    assert "agent gone" in rows[0].error


async def test_slow_call_leaves_an_in_flight_audit_row(tmp_path, monkeypatch):
    import pry.mcp.tools._runtime.guard as guard
    ctx = _ctx(tmp_path, monkeypatch)
    rows: list[dict] = []
    ctx.session.audit_event = rows.append
    monkeypatch.setattr(guard, "_INFLIGHT_AUDIT_S", 0.02)

    async def slow():
        await asyncio.sleep(0.1)
        return {"ok": True}

    await guard._guard(ctx, "debug_manage", "wait", {"pid": 1}, slow)
    assert rows and rows[0]["phase"] == "in_flight"
    assert rows[0]["args"] == {"pid": 1}


# --------------------------------------------------------------------------- #
# item 11 — snapshot pump + lease touch
# --------------------------------------------------------------------------- #

def test_server_snapshot_pump_follows_the_primary():
    src = (Path(__file__).resolve().parents[1] / "src" / "pry"
           / "server.py").read_text(encoding="utf-8")
    assert "SnapshotPump(ctx, \"\"," in src
    assert "SnapshotPump(ctx, session.primary" not in src


async def test_debug_calls_touch_the_holders_lease(tmp_path, monkeypatch):
    from pry.leases import LeaseManager
    from pry.mcp.tools import build_server
    ctx = _ctx(tmp_path, monkeypatch)
    ctx.leases = LeaseManager(publish_event=lambda ev: None)

    class C:
        async def debug_status(self, include_context=False):
            return {"ok": True, "state": {"active": True}}

    ctx.session.clients["lab2.kernel"] = C()
    lease = await ctx.leases.acquire("debug:lab2.kernel:pid=7", "chat-1", 0)
    ctx._attach_leases[("lab2.kernel", 7)] = lease
    lease.last_touched_at -= 500
    before = lease.last_touched_at
    server = build_server(ctx)
    token = CLIENT_ID.set("chat-1")
    try:
        await server.call_tool("debug_manage", {"action": "status"})
    finally:
        CLIENT_ID.reset(token)
    assert lease.last_touched_at > before + 400


# --------------------------------------------------------------------------- #
# item 12 — memory_manage watch mode='hw'
# --------------------------------------------------------------------------- #

class _HwClient:
    def __init__(self) -> None:
        self.added: list[dict] = []
        self.removed: list[int] = []

    async def status(self):
        return {"driver_abi_version": 17, "agent_abi_version": 17,
                "driver_abi_ok": True}

    async def bp_hw_watch_add(self, **kw):
        self.added.append(kw)
        return {"ok": True, "watch_cookie": 77, "slot": 1,
                "threads_patched": 2, "hvci_fallback": False}

    async def bp_hw_watch_remove(self, cookie):
        self.removed.append(cookie)
        return {"ok": True}


async def test_hw_watch_arms_and_stop_releases_the_slot(tmp_path, monkeypatch):
    from pry.mcp.tools.mem import watch
    ctx = _ctx(tmp_path, monkeypatch)
    ctx.cfg.security.allow_hw_bp_hook = True
    c = _HwClient()
    ctx.session.clients["lab2.kernel"] = c
    out = json.loads(await watch._handle_watch_hw(
        ctx, c, pid=4, tid=0, addr=0x7FF600001000, size=8, access="write",
        slot=0xFF, preempt_ok=False, tag="t", name="lab2.kernel"))
    assert out["ok"] is True and out["mode"] == "hw"
    assert out["watch_cookie"] == 77 and out["abi_version"] == 17
    assert c.added[0]["address"] == 0x7FF600001000
    stop = json.loads(await watch.handle_watch_stop_async(
        ctx, module=out["watch_id"], filter=""))
    assert stop["ok"] is True and c.removed == [77]
    assert out["watch_id"] not in watch._WATCHES


async def test_hw_watch_is_gated_and_checks_the_driver_abi(tmp_path, monkeypatch):
    from pry.mcp.tools.mem import watch
    ctx = _ctx(tmp_path, monkeypatch)
    c = _HwClient()
    gated = json.loads(await watch._handle_watch_hw(
        ctx, c, pid=4, tid=0, addr=0x1000, size=8, access="write",
        slot=0xFF, preempt_ok=False, tag="", name=""))
    assert gated["ok"] is False and gated["kind"] == "hw_bp_hook_disabled"
    assert c.added == []
    ctx.cfg.security.allow_hw_bp_hook = True

    async def bad_status():
        return {"driver_abi_version": 16, "agent_abi_version": 17,
                "driver_abi_ok": False}

    c.status = bad_status
    out = json.loads(await watch._handle_watch_hw(
        ctx, c, pid=4, tid=0, addr=0x1000, size=8, access="write",
        slot=0xFF, preempt_ok=False, tag="", name=""))
    assert out["ok"] is False and out["fallback"] == "poll"
    assert c.added == []


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _ctx(tmp_path, monkeypatch, *, allow=("127.0.0.0/8",)):
    from pry.config import MachineConfig
    from pry.findings import FindingsLedger
    from pry.ida_bridge import IdaBridge, IdaConfigLite
    from pry.mcp.tools import Context
    from pry.session import Session
    monkeypatch.setenv("PRY_AUDIT_DISABLE", "1")
    cfg = PryConfig()
    cfg.security.authorized_targets = list(allow)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    cfg.machines = {"lab2": MachineConfig(host="10.0.0.9", token="t",
                                          kernel_port=50074, trust="lab")}
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    return Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge)


def _body(result) -> dict:
    if isinstance(result, str):
        return json.loads(result)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    return body


async def _call_tool(server, tool: str, args: dict) -> dict:
    result = await server.call_tool(tool, args)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    merged = dict(body.get("data") or {})
    err = body.get("error")
    if isinstance(err, dict):
        merged.update(err)
    merged.setdefault("ok", body.get("ok"))
    merged["kind"] = (err.get("kind") if isinstance(err, dict)
                      else body.get("kind"))
    return merged
