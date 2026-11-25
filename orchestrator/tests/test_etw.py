"""SI #10 · event_manage(action='etw_*') — private kernel ETW
session verbs.

Contracts pinned here:
- missing EtwTrace stub (older agent) → agent_version kind,
  and the dispatcher never touches the client.
- etw_start without session_name or providers → bad_arg.
- etw_start forwards providers / level / ring_capacity straight through.
- etw_stop forwards the session_name and surfaces events_total/dropped.
- etw_trace_sessions returns the SI #10 private-session roster from
  the agent view (renamed from ``etw_sessions``; the
  box-wide canonical ``etw_sessions`` now lives on event_manage and
  calls c.etw_sessions, see taxonomy brief §5.11).
- etw_tail / etw_events / etw_stats forward (session_name, limits).
- action='actions' lists every etw_* verb in the help bundle.
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


class _FakeAgentClient:
    """Agent with EtwTrace stub. Canned replies per RPC."""

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.events = object()  # non-None: Events service exists
        self.etw = object()     # non-None: EtwTrace service exists
        self.calls: list[dict[str, Any]] = []

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def status(self) -> dict[str, Any]:
        return {"ok": True}

    # --- EtwTrace RPC fakes --------------------------------------------
    async def etw_start(self, session_name: str, providers: list[str],
                        keywords_any: int = 0, keywords_all: int = 0,
                        level: int = 0, buffer_size_kb: int = 0,
                        min_buffers: int = 0, max_buffers: int = 0,
                        ring_capacity: int = 0) -> dict[str, Any]:
        self.calls.append({"op": "etw_start", "session_name": session_name,
                            "providers": list(providers),
                            "keywords_any": int(keywords_any),
                            "level": int(level),
                            "ring_capacity": int(ring_capacity)})
        return {"ok": True, "error": "", "session_name": session_name,
                "session_handle": 0x1234,
                "ring_capacity": ring_capacity or 16384,
                "started_providers": list(providers),
                "failed_providers": []}

    async def etw_stop(self, session_name: str) -> dict[str, Any]:
        self.calls.append({"op": "etw_stop", "session_name": session_name})
        return {"ok": True, "error": "", "events_total": 7,
                "events_dropped": 1}

    async def etw_trace_sessions(self) -> dict[str, Any]:
        self.calls.append({"op": "etw_trace_sessions"})
        return {"ok": True, "error": "",
                "sessions": [{"session_name": "pry-img",
                               "events_total": 10, "events_dropped": 0,
                               "providers": 1, "running": True}]}

    async def etw_tail(self, session_name: str, since_seq: int = 0,
                       limit: int = 0) -> dict[str, Any]:
        self.calls.append({"op": "etw_tail", "session_name": session_name,
                            "since_seq": int(since_seq),
                            "limit": int(limit)})
        return {"ok": True, "error": "", "events": [
            {"seq": 1, "ts_100ns": 132000000000000000,
             "provider_guid": "15A2B423-635B-4B7F-B8CF-1BAB9F9AD5C7",
             "event_id": 10, "pid": 4321, "tid": 1234,
             "opcode": 10, "version": 0, "level": 4, "keywords": 0,
             "kind": "image", "fields": {"ImageName": "notepad.exe"}}
        ], "last_seq": 1, "dropped": 0}

    async def etw_events(self, session_name: str, max_events: int = 0,
                         timeout_ms: int = 0) -> dict[str, Any]:
        self.calls.append({"op": "etw_events", "session_name": session_name,
                            "max_events": int(max_events),
                            "timeout_ms": int(timeout_ms)})
        return {"ok": True, "error": "", "events": [],
                "last_seq": 0, "dropped": 0}

    async def etw_stats(self, session_name: str) -> dict[str, Any]:
        self.calls.append({"op": "etw_stats", "session_name": session_name})
        return {"ok": True, "error": "", "session_name": session_name,
                "events_total": 42, "events_dropped": 0,
                "events_lost": 0, "buffers_written": 3, "buffers_lost": 0,
                "ring_capacity": 16384, "ring_used": 0, "running": True}

    def recent_ops(self, limit: int = 32):
        return []


class _OldAgentClient(_FakeAgentClient):
    """Older agent: no EtwTrace service."""

    def __init__(self, *a, **kw) -> None:
        super().__init__(*a, **kw)
        self.etw = None


async def _server(tmp_path, monkeypatch, client_cls=_FakeAgentClient):
    monkeypatch.setattr("pry.session.AgentClient", client_cls)
    monkeypatch.setattr("pry.mcp.tools.AgentClient", client_cls)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0):
        return None

    monkeypatch.setattr("pry.session._probe_tcp", _noop_probe)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.security.allow_event_stream = True
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


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-etw")
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


async def _connect(server) -> None:
    body = await _call(server, "target_manage", {"action": "connect"})
    assert body.get("ok") is not False, body


# --------------------------------------------------------------------------- #
# Older agent: service missing surfaces agent_version without ever
# calling the client.
# --------------------------------------------------------------------------- #


async def test_etw_old_agent_gets_agent_version(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                 client_cls=_OldAgentClient)
    await _connect(server)
    body = await _call(server, "event_manage",
                        {"action": "etw_trace_sessions"})
    assert body["ok"] is False
    assert body["kind"] == "agent_version"
    assert "EtwTrace" in body["error"]


# --------------------------------------------------------------------------- #
# etw_start arg validation + happy path
# --------------------------------------------------------------------------- #


async def test_etw_start_requires_session_name(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage",
                        {"action": "etw_start",
                         "etw_providers": ["image"]})
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"


async def test_etw_start_requires_providers(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage",
                        {"action": "etw_start",
                         "etw_session_name": "pry-img"})
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"


async def test_etw_start_happy_path(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage",
                        {"action": "etw_start",
                         "etw_session_name": "pry-img",
                         "etw_providers": ["image", "process"],
                         "etw_level": 4,
                         "etw_ring_capacity": 1024})
    assert body["ok"] is True, body
    assert body["session_name"] == "pry-img"
    assert body["started_providers"] == ["image", "process"]
    assert body["ring_capacity"] >= 1024


# --------------------------------------------------------------------------- #
# etw_stop / etw_sessions / etw_tail / etw_events / etw_stats forwarding
# --------------------------------------------------------------------------- #


async def test_etw_stop_passes_session_name(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage",
                        {"action": "etw_stop",
                         "etw_session_name": "pry-img"})
    assert body["ok"] is True, body
    assert body["events_total"] == 7
    assert body["events_dropped"] == 1


async def test_etw_sessions_lists_private_sessions(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    # taxonomy: the agent-view private-session roster moved from
    # ``etw_sessions`` to ``etw_trace_sessions`` so the canonical ETW
    # consolidation (device_manage -> event_manage) could take the
    # shorter name box-wide. See taxonomy brief §5.11.
    body = await _call(server, "event_manage",
                        {"action": "etw_trace_sessions"})
    assert body["ok"] is True, body
    assert body["sessions"]
    assert body["sessions"][0]["session_name"] == "pry-img"


async def test_etw_tail_returns_decoded_events(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage",
                        {"action": "etw_tail",
                         "etw_session_name": "pry-img",
                         "etw_since_seq": 0, "etw_limit": 64})
    assert body["ok"] is True, body
    assert body["events"]
    row = body["events"][0]
    assert row["kind"] == "image"
    assert row["fields"]["ImageName"] == "notepad.exe"


async def test_etw_events_forwards_timeout(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage",
                        {"action": "etw_events",
                         "etw_session_name": "pry-img",
                         "etw_max_events": 128, "etw_timeout_ms": 50})
    assert body["ok"] is True, body


async def test_etw_stats_reports_ring_counters(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage",
                        {"action": "etw_stats",
                         "etw_session_name": "pry-img"})
    assert body["ok"] is True, body
    assert body["events_total"] == 42
    assert body["ring_capacity"] == 16384
    assert body["running"] is True


# --------------------------------------------------------------------------- #
# action='actions' lists every etw_* verb
# --------------------------------------------------------------------------- #


async def test_etw_actions_help_bundle(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage", {"action": "actions"})
    assert body["ok"] is True, body
    bundle = body["actions"]
    for verb in ("etw_start", "etw_stop", "etw_trace_sessions",
                  "etw_sessions", "etw_providers",
                  "etw_tail", "etw_events", "etw_stats"):
        assert verb in bundle, (verb, list(bundle))
