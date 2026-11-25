"""memory_manage(action='threads') opt-in columns.

Covers:

* base response (no include_* flags) stays bit-identical to the earlier shape —
  no new keys on the thread rows;
* each of the 8 include_* kwargs lands its column on the row;
* driver-sourced columns (last_syscall / kernel_stack / pending_irp)
  degrade to ``{error: 'wave_3_pending'}`` while Wave 3 dyn-data is
  pending (SI #3 WAIT_INFO + IRP_LIST both land here);
* ``include_rpc_usage`` degrades to ``{error: 'wct_timeout'}`` when
  the 2s std::future wrap on GetThreadWaitChain fires;
* ``include_impersonation`` on a PP target surfaces
  ``{present: null, error: 'access_denied'}`` (slice doc §Edge cases);
* ``no_thread`` (thread exited mid-enrichment) lands cleanly in the
  column sentinel.
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
    """Captures per-row RPC calls; serves a canned response per method."""

    def __init__(self, *, threads=None, overrides=None) -> None:
        self._threads = threads or []
        self._overrides = overrides or {}
        self.last_op_ts = 0.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.endpoint = "lab:50051"

    def _default(self, method: str, tid: int) -> dict:
        if method == "thread_wait_info":
            return {"ok": False, "error": "wave_3_pending"}
        if method == "thread_irp_list":
            return {"ok": False, "error": "wave_3_pending",
                    "pending": False, "irp_count": 0, "irps": []}
        if method == "thread_impersonation":
            return {"ok": True, "present": False, "user": "", "level": "",
                    "is_self": False, "sid": ""}
        if method == "thread_com_apartment":
            return {"ok": True, "type": "none", "flags": [], "teb_rfo": 0}
        if method == "thread_rpc_usage":
            return {"ok": True, "in_rpc_call": False, "server": "",
                    "chain_length": 0}
        if method == "thread_power_throttling":
            return {"ok": True, "control_mask": 0, "state_mask": 0}
        if method == "thread_fiber":
            return {"ok": True, "has_fiber_data": False}
        return {"ok": True}

    def _answer(self, method: str, tid: int) -> dict:
        ov = self._overrides.get((method, tid))
        if ov is not None:
            return dict(ov)
        default_ov = self._overrides.get(method)
        if default_ov is not None:
            return dict(default_ov)
        return self._default(method, tid)

    async def thread_list(self, *, pid: int, kernel: bool,
                          with_context: bool):
        return {"ok": True, "threads": list(self._threads),
                "source": "agent", "truncated": False}

    async def mem_modules(self, pid: int, kernel: bool):
        return []

    async def thread_wait_info(self, tid: int):
        return self._answer("thread_wait_info", tid)

    async def thread_irp_list(self, tid: int):
        return self._answer("thread_irp_list", tid)

    async def thread_impersonation(self, tid: int):
        return self._answer("thread_impersonation", tid)

    async def thread_com_apartment(self, tid: int):
        return self._answer("thread_com_apartment", tid)

    async def thread_rpc_usage(self, tid: int):
        return self._answer("thread_rpc_usage", tid)

    async def thread_power_throttling(self, tid: int):
        return self._answer("thread_power_throttling", tid)

    async def thread_fiber(self, tid: int):
        return self._answer("thread_fiber", tid)

    def recent_ops(self, n: int):
        return []


async def _build(tmp_path, monkeypatch, client: _FakeClient):
    async def _noop(host, p, timeout_s: float = 3.0):
        return None

    monkeypatch.setattr("pry.session._probe_tcp", _noop)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=50051)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    session.require_client = lambda _name="", _c=client: _c  # type: ignore[assignment]
    session.view_kind_of = lambda _name="", _k="user": "user"  # type: ignore[assignment]
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


async def _call(server, args):
    token = CLIENT_ID.set("peer-threads")
    try:
        result = await server.call_tool("thread_manage", args)
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
    if isinstance(body.get("coverage"), dict):
        merged.setdefault("coverage", body["coverage"])
    return merged


_THREADS = [
    {"tid": 100, "pid": 42, "start_va": 0x7ffe00000000, "state": 5},
    {"tid": 101, "pid": 42, "start_va": 0x7ffe00001000, "state": 5},
]


async def test_threads_base_shape_unchanged(tmp_path, monkeypatch):
    client = _FakeClient(threads=_THREADS)
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "list", "pid": 42,
                                 "name": "user", "verbosity": "full"})
    assert body["ok"] is True
    rows = body["items"]
    assert all("last_syscall" not in r for r in rows)
    assert all("impersonation" not in r for r in rows)
    # No column sentinels — coverage stays 'enumeration'/'complete'.
    assert body["coverage"]["scope"] == "enumeration"
    assert body["coverage"]["status"] == "complete"


async def test_threads_opt_in_impersonation(tmp_path, monkeypatch):
    client = _FakeClient(threads=_THREADS, overrides={
        "thread_impersonation": {
            "ok": True, "present": True, "user": "DOMAIN\\svc",
            "level": "Impersonation", "is_self": False,
            "sid": "S-1-5-18",
        }})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "list", "pid": 42,
                                 "include_impersonation": True,
                                 "name": "user", "verbosity": "full"})
    assert body["ok"] is True
    row = body["items"][0]
    assert row["impersonation"]["present"] is True
    assert row["impersonation"]["user"] == "DOMAIN\\svc"
    assert body["coverage"]["scope"] == "thread-columns"


async def test_threads_impersonation_ppl_access_denied(tmp_path, monkeypatch):
    client = _FakeClient(threads=_THREADS, overrides={
        "thread_impersonation": {"ok": False, "kind": "access_denied",
                                   "error": "access_denied"},
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "list", "pid": 4,
                                 "include_impersonation": True,
                                 "name": "user", "verbosity": "full"})
    row = body["items"][0]
    assert row["impersonation"] == {"present": None, "error": "access_denied"}
    assert "access_denied" in body["coverage"]["limits"]


async def test_threads_wave_3_pending_driver_columns(tmp_path, monkeypatch):
    """SI #3 WAIT_INFO + Feature 4 IRP_LIST both degrade cleanly while Wave 3 is pending."""
    client = _FakeClient(threads=_THREADS)  # defaults -> wave_3_pending
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "list", "pid": 42,
                                 "include_last_syscall": True,
                                 "include_kernel_stack_usage": True,
                                 "include_pending_irp": True,
                                 "name": "user", "verbosity": "full"})
    row = body["items"][0]
    assert row["last_syscall"] == {"error": "wave_3_pending"}
    assert row["kernel_stack"] == {"error": "wave_3_pending"}
    assert row["pending_irp"] == {"error": "wave_3_pending"}
    assert "wave_3_pending" in body["coverage"]["limits"]


async def test_threads_rpc_wct_timeout(tmp_path, monkeypatch):
    client = _FakeClient(threads=_THREADS, overrides={
        "thread_rpc_usage": {"ok": False, "error": "wct_timeout"},
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "list", "pid": 42,
                                 "include_rpc_usage": True,
                                 "name": "user", "verbosity": "full"})
    row = body["items"][0]
    assert row["rpc_usage"] == {"error": "wct_timeout"}
    assert "wct_timeout" in body["coverage"]["limits"]


async def test_threads_no_thread_mid_enrichment(tmp_path, monkeypatch):
    client = _FakeClient(threads=_THREADS, overrides={
        ("thread_impersonation", 101): {"ok": False, "error": "no_thread"},
        "thread_impersonation": {"ok": True, "present": False,
                                   "user": "", "level": "",
                                   "is_self": False, "sid": ""},
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "list", "pid": 42,
                                 "include_impersonation": True,
                                 "name": "user", "verbosity": "full"})
    r0 = next(r for r in body["items"] if r["tid"] == 100)
    r1 = next(r for r in body["items"] if r["tid"] == 101)
    assert r0["impersonation"]["present"] is False
    assert r1["impersonation"] == {"error": "no_thread"}
    assert "no_thread" in body["coverage"]["limits"]


async def test_threads_fiber_and_power(tmp_path, monkeypatch):
    client = _FakeClient(threads=_THREADS, overrides={
        "thread_fiber": {"ok": True, "has_fiber_data": True},
        "thread_power_throttling": {"ok": True,
                                      "control_mask": 1,
                                      "state_mask": 1},
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "list", "pid": 42,
                                 "include_fiber": True,
                                 "include_power_throttling": True,
                                 "name": "user", "verbosity": "full"})
    row = body["items"][0]
    assert row["fiber"] is True
    assert row["power_throttling"]["control_mask_hex"] == 1
    assert row["power_throttling"]["state_mask_hex"] == 1
