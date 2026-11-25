"""`memory_manage(action='global_find')` — SI feature #7 smoke test.

Fan-out across a synthetic 10-process inventory with 20 modules each.
Pins the lifecycle contract:
- substring match against module name finds one hit per process.
- regex kwarg honoured.
- bad regex surfaces synchronously as kind='bad_arg'.
- the find-job registry is SEPARATE from the scan-job registry — a
  scan_cancel against a global_find id refuses with kind='unknown_scan'.
"""

from __future__ import annotations

import asyncio
import json as _json
from typing import Any

import pytest

from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.tools import Context, build_server
from pry.ownership import OwnershipRegistry
from pry.session import Session

pytestmark = pytest.mark.asyncio


class _FanoutClient:
    """Serves a 10-pid inventory. Each pid has 20 modules; one of them
    is always 'kernelbase.dll'. Pid-even gets a handle table with a
    'MyEvent' named object."""

    N_PIDS = 10
    MODULES_PER_PID = 20

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:0",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.2"}

    async def mem_processes(self, *, limit: int = 0, offset: int = 0,
                            with_cmdline: bool = False, full: bool = False):
        procs = [{"pid": 100 + i, "parent_pid": 4,
                  "image_name": f"proc{i}.exe"}
                 for i in range(self.N_PIDS)]
        if full:
            return {"processes": procs, "source": "agent"}
        return procs

    async def mem_modules(self, pid: int, kernel: bool = False,
                          *, limit: int = 0, offset: int = 0):
        rows = [{"name": f"mod{j}.dll",
                 "path": f"C:\\\\Windows\\\\System32\\\\mod{j}.dll",
                 "base": 0x7FF000000 + j * 0x1000, "size": 0x1000}
                for j in range(self.MODULES_PER_PID - 1)]
        rows.append({"name": "kernelbase.dll",
                     "path": "C:\\\\Windows\\\\System32\\\\kernelbase.dll",
                     "base": 0x7FF000FF0, "size": 0x1000})
        return rows

    async def handle_list(self, pid: int, want_names: bool = False,
                          *, limit: int = 0, offset: int = 0):
        if pid % 2:
            return []
        rows = [{"handle": 0x4, "type_name": "Event",
                 "object": 0xFFFF0001,
                 "granted_access": 0x1FFFFF,
                 "name": "MyEvent" if want_names else ""}]
        return rows


async def _server(tmp_path, monkeypatch):
    monkeypatch.setattr("pry.session.AgentClient", _FanoutClient)
    monkeypatch.setattr("pry.mcp.tools.AgentClient", _FanoutClient)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0):
        return None
    monkeypatch.setattr("pry.session._probe_tcp", _noop_probe)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg,
                  leases=LeaseManager(publish_event=lambda ev:
                                      asyncio.create_task(
                                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict,
                 client: str = "peer-A") -> dict:
    token = CLIENT_ID.set(client)
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    if not isinstance(body, dict):
        return {"raw": body}
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    err = body.get("error")
    if isinstance(err, dict):
        merged.update(err)
    merged.setdefault("ok", body.get("ok"))
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


async def _wait_done(server, find_id, timeout_s: float = 3.0):
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        body = await _call(server, "object_manage", {
            "action": "find_status", "scan_id": find_id})
        if body["status"] != "running":
            return body
        await asyncio.sleep(0.02)
    pytest.fail(f"global_find {find_id} never finished within {timeout_s}s")


async def test_global_find_fanout(tmp_path, monkeypatch):
    """Substring match on 'kernelbase' hits every pid exactly once;
    find-job id is prefixed `g` (separate from scan `s` registry)."""
    _ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    start = await _call(server, "object_manage", {
        "action": "find",
        "pattern": "kernelbase",
        "kinds": ["module"],
        "max_results": 100,
    })
    assert start["ok"] is True, start
    find_id = start["find_id"]
    assert find_id.startswith("g")
    final = await _wait_done(server, find_id)
    assert final["status"] == "done", final
    rows = final["items"]
    # One hit per pid.
    assert len(rows) == _FanoutClient.N_PIDS
    assert {r["pid"] for r in rows} == set(range(100, 100 + 10))
    for r in rows:
        assert r["kind"] == "module"
        assert "kernelbase" in r["name"].lower()
        assert r["extra"]["module_path"].endswith("kernelbase.dll")


async def test_global_find_regex_and_handle_kind(tmp_path, monkeypatch):
    _ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    start = await _call(server, "object_manage", {
        "action": "find",
        "pattern": r"^MyEv",
        "kinds": ["handle"],
        "regex": True,
        "want_object_names": True,
    })
    assert start["ok"] is True
    final = await _wait_done(server, start["find_id"])
    rows = final["items"]
    # 5 even-pid procs each yield one handle hit.
    assert len(rows) == 5
    assert all(r["kind"] == "handle" for r in rows)
    assert all(r["name"] == "MyEvent" for r in rows)
    assert all(r["pid"] % 2 == 0 for r in rows)


async def test_global_find_bad_regex_synchronous_error(tmp_path, monkeypatch):
    _ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "object_manage", {
        "action": "find",
        "pattern": "([",
        "regex": True,
    })
    assert body["ok"] is False, body
    assert body["kind"] == "bad_arg"
    assert "regex" in body["error"].lower()


async def test_global_find_registry_is_separate_from_scan(tmp_path, monkeypatch):
    """A ``scan_cancel`` targeting a global_find id must be refused with
    ``kind='unknown_scan'`` — the two registries never cross."""
    _ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    start = await _call(server, "object_manage", {
        "action": "find", "pattern": "kernelbase",
        "kinds": ["module"]})
    find_id = start["find_id"]
    assert find_id.startswith("g")
    # scan_cancel lives on memory_manage; must refuse a find-job id so
    # the two registries never cross.
    refused = await _call(server, "memory_manage", {
        "action": "scan_cancel", "scan_id": find_id})
    assert refused["ok"] is False
    assert refused["kind"] == "unknown_scan", refused
    # Clean up: let the job drain.
    await _wait_done(server, find_id)


async def test_global_find_list_and_cancel(tmp_path, monkeypatch):
    _ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    start = await _call(server, "object_manage", {
        "action": "find", "pattern": "mod",
        "kinds": ["module"], "max_results": 10})
    find_id = start["find_id"]
    # List enumeration surfaces the job.
    lst = await _call(server, "object_manage", {
        "action": "find_list"})
    assert lst["ok"] is True
    assert any(f["find_id"] == find_id for f in lst["finds"])
    # Cancel + drain.
    cancel = await _call(server, "object_manage", {
        "action": "find_cancel", "scan_id": find_id})
    assert cancel["ok"] is True
    await _wait_done(server, find_id)
