"""memory_manage(action='heap_info') segment-heap.

Covers:

* ``space='kernel'`` refused with ``kind='bad_arg'`` (segment heaps are
  user-space-only — slice doc §Feature 7);
* ``pid=0`` refused with ``kind='bad_arg'``;
* happy path returns a scaffolded row set with ``coverage='partial'`` +
  hint='dyn_data_wave_3_pending' (Wave 3 dyn-data not yet shipped);
* PPL asymmetry: umagent-view ``access_denied`` surfaces the operator
  hint about using the agent/driver view;
* agent_version fallthrough on older bindings.
"""
from __future__ import annotations

import asyncio
import json as _json

from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.tools import Context, build_server
from pry.ownership import OwnershipRegistry
from pry.session import Session


class _FakeClient:
    def __init__(self, response) -> None:
        self._response = response
        self.calls: list[dict] = []
        self.last_op_ts = 0.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.endpoint = "lab:50051"

    async def mem_heap_info(self, pid: int, *,
                            heap_filter: int = 0,
                            include_segments: bool = False,
                            include_lfh_buckets: bool = False) -> dict:
        self.calls.append({"pid": pid, "heap_filter": heap_filter,
                           "include_segments": include_segments,
                           "include_lfh_buckets": include_lfh_buckets})
        if isinstance(self._response, Exception):
            raise self._response
        return dict(self._response)

    async def mem_modules(self, pid: int, kernel: bool):
        return []

    def recent_ops(self, n: int) -> list[dict]:
        return []


async def _build(tmp_path, monkeypatch, *, client: _FakeClient | None = None,
                 view: str = "user"):
    async def _noop(host, p, timeout_s: float = 3.0):
        return None

    monkeypatch.setattr("pry.session._probe_tcp", _noop)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=50051)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    if client is not None:
        session.require_client = lambda _name="", _c=client: _c  # type: ignore[assignment]
        session.view_kind_of = lambda _name="", _k=view: view  # type: ignore[assignment]
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
    return ctx, build_server(ctx)


async def _call(server, args) -> dict:
    token = CLIENT_ID.set("peer-heap")
    try:
        result = await server.call_tool("memory_manage", args)
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
    if isinstance(body.get("coverage"), dict):
        merged.setdefault("coverage", body["coverage"])
    if body.get("hint"):
        merged.setdefault("hint", body["hint"])
    return merged


async def test_heap_info_rejects_kernel_space(tmp_path, monkeypatch):
    client = _FakeClient({})
    _ctx, server = await _build(tmp_path, monkeypatch, client=client)
    body = await _call(server, {"action": "heap_info", "pid": 1234,
                                 "space": "kernel", "name": "user"})
    assert body.get("ok") is False
    assert body.get("kind") == "bad_arg"
    assert "user" in str(body.get("error") or "")


async def test_heap_info_rejects_pid_zero(tmp_path, monkeypatch):
    client = _FakeClient({})
    _ctx, server = await _build(tmp_path, monkeypatch, client=client)
    body = await _call(server, {"action": "heap_info", "pid": 0,
                                 "name": "user"})
    assert body.get("ok") is False
    assert body.get("kind") == "bad_arg"


async def test_heap_info_happy_scaffold(tmp_path, monkeypatch):
    client = _FakeClient({
        "ok": True, "heaps": [],
        "coverage": "partial", "hint": "dyn_data_wave_3_pending",
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client=client)
    body = await _call(server, {"action": "heap_info", "pid": 1234,
                                 "name": "user"})
    assert body.get("ok") is True, body
    assert body["coverage"]["status"] == "partial"
    assert "dyn_data_wave_3_pending" in body["coverage"]["limits"]
    assert client.calls == [{"pid": 1234, "heap_filter": 0,
                             "include_segments": False,
                             "include_lfh_buckets": False}]


async def test_heap_info_ppl_access_denied_hint(tmp_path, monkeypatch):
    client = _FakeClient(RuntimeError("ACCESS_DENIED on OpenProcess"))
    _ctx, server = await _build(tmp_path, monkeypatch, client=client,
                                 view="user")
    body = await _call(server, {"action": "heap_info", "pid": 4,
                                 "name": "user"})
    assert body.get("ok") is False
    assert body.get("kind") == "access_denied"
    assert "agent/driver view" in str(body.get("hint") or "")


async def test_heap_info_agent_version(tmp_path, monkeypatch):
    client = _FakeClient({"ok": False, "kind": "agent_version",
                           "error": "heap_info: older agent"})
    _ctx, server = await _build(tmp_path, monkeypatch, client=client)
    body = await _call(server, {"action": "heap_info", "pid": 1234,
                                 "name": "user"})
    assert body.get("ok") is False
    assert body.get("kind") == "agent_version"
    assert "rebuild" in str(body.get("hint") or "")
