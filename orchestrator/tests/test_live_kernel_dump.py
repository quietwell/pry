"""dump_manage(action='create_kernel_dump').

Covers:

* gate refusal when ``security.allow_live_kernel_dump`` stays at its
  default (``False``);
* clean success envelope + flag resolution on an opt-in gate;
* unknown flag echo through ``flags_unknown`` + ``coverage.partial``;
* agent-side ``kind='not_supported'`` surface when the view answers
  it (umagent-only);
* actions discovery lists the new verb.

Mocks the agent client at the ``live_kernel_dump`` method so the test
suite doesn't need the real NtSystemDebugControl path (which only works
in-kernel on an actual target).
"""
from __future__ import annotations

import asyncio
import json as _json
from typing import Any

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
    """Minimal fake with the single RPC the live-kernel-dump path needs."""

    def __init__(self, response: dict | Exception) -> None:
        self._response = response
        self.calls: list[dict] = []
        self.last_op_ts = 0.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.endpoint = "lab:50051"
        self.view = "user"

    async def live_kernel_dump(self, *, output_path: str,
                               flags: list[str],
                               compression: bool,
                               allow_cancel: bool) -> dict:
        self.calls.append({
            "output_path": output_path, "flags": list(flags),
            "compression": compression, "allow_cancel": allow_cancel,
        })
        if isinstance(self._response, Exception):
            raise self._response
        return dict(self._response)

    def recent_ops(self, n: int) -> list[dict]:
        return []


async def _build(tmp_path, monkeypatch, *, allow_dump: bool = False,
                 client: _FakeClient | None = None):
    async def _noop_probe(host, p, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("pry.session._probe_tcp", _noop_probe)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.security.allow_live_kernel_dump = bool(allow_dump)
    cfg.target = TargetConfig(host="127.0.0.1", port=50051)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    if client is not None:
        session._clients = {"primary.user": client}  # type: ignore[attr-defined]

        async def _require(_name: str = "") -> _FakeClient:
            return client

        # The real Session.require_client is sync, not async — stub it.
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


async def _call(server, args: dict) -> dict:
    token = CLIENT_ID.set("peer-livedump")
    try:
        result = await server.call_tool("dump_manage", args)
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
    return merged


# ----------------------------------------------------------------------------
# actions discovery + help blurb
# ----------------------------------------------------------------------------

async def test_actions_lists_create_kernel_dump(tmp_path, monkeypatch):
    _ctx, server = await _build(tmp_path, monkeypatch)
    body = await _call(server, {"action": "actions"})
    assert body["ok"] is True
    assert "create_kernel_dump" in set(body["actions"])


# ----------------------------------------------------------------------------
# gate refusal (default: off)
# ----------------------------------------------------------------------------

async def test_create_kernel_dump_refused_by_default_gate(tmp_path, monkeypatch):
    _ctx, server = await _build(tmp_path, monkeypatch, allow_dump=False)
    body = await _call(server, {"action": "create_kernel_dump",
                                "name": "user",
                                "output_path": "C:\\dumps\\live.dmp",
                                "dump_flags": ["stack_only"]})
    assert body.get("ok") is False
    # Session.assert_allowed raises PermissionError -> envelope kind.
    err_text = str(body.get("error") or "")
    assert "allow_live_kernel_dump" in err_text


# ----------------------------------------------------------------------------
# happy path through the umagent view
# ----------------------------------------------------------------------------

async def test_create_kernel_dump_happy_path(tmp_path, monkeypatch):
    client = _FakeClient({
        "ok": True, "kind": "",
        "path": r"C:\dumps\live_42.dmp",
        "size": 2_000_000,
        "sha256": "deadbeef" * 8,
        "flags_used_mask": 0x15,
        "flags_unknown": [],
        "error_detail": "",
    })
    _ctx, server = await _build(tmp_path, monkeypatch,
                                 allow_dump=True, client=client)
    body = await _call(server, {"action": "create_kernel_dump",
                                 "name": "user",
                                 "output_path": r"C:\dumps\live.dmp",
                                 "dump_flags": ["stack_only", "compression"],
                                 "allow_cancel": True})
    assert body.get("ok") is True, body
    assert body["path"].endswith("live_42.dmp")
    assert body["size"] == 2_000_000
    assert body["sha256"].startswith("deadbeef")
    assert body["flags_used_mask"] == 0x15
    assert "stack_only" in body["flags_used"]
    assert body["flags_unknown"] == []
    assert body.get("source") == "umagent"
    # Request was passed through verbatim.
    assert client.calls and client.calls[0]["allow_cancel"] is True
    assert "stack_only" in client.calls[0]["flags"]


# ----------------------------------------------------------------------------
# unknown flag names echo + partial coverage
# ----------------------------------------------------------------------------

async def test_create_kernel_dump_unknown_flags(tmp_path, monkeypatch):
    client = _FakeClient({
        "ok": True, "kind": "",
        "path": r"C:\dumps\live.dmp", "size": 1, "sha256": "a" * 64,
        "flags_used_mask": 0x4,
        "flags_unknown": ["nonsense"],
    })
    _ctx, server = await _build(tmp_path, monkeypatch,
                                 allow_dump=True, client=client)
    body = await _call(server, {"action": "create_kernel_dump",
                                 "name": "user",
                                 "output_path": r"C:\dumps\live.dmp",
                                 "dump_flags": ["stack_only", "nonsense"]})
    assert body.get("ok") is True, body
    assert "nonsense" in body["flags_unknown"]
    assert body["coverage"]["status"] == "partial"


# ----------------------------------------------------------------------------
# agent-side degrade (umagent-only)
# ----------------------------------------------------------------------------

async def test_create_kernel_dump_agent_side_degrades(tmp_path, monkeypatch):
    client = _FakeClient({
        "ok": False, "kind": "not_supported",
        "error": "live_kernel_dump: agent-side disabled — "
                  "use the umagent view (name='user')",
        "error_detail": "", "path": "", "size": 0, "sha256": "",
        "flags_used_mask": 0, "flags_unknown": [],
    })
    _ctx, server = await _build(tmp_path, monkeypatch,
                                 allow_dump=True, client=client)
    body = await _call(server, {"action": "create_kernel_dump",
                                 "name": "kernel",
                                 "output_path": r"C:\dumps\live.dmp"})
    assert body.get("ok") is False
    assert body.get("kind") == "not_supported"


# ----------------------------------------------------------------------------
# agent_version fallthrough
# ----------------------------------------------------------------------------

async def test_create_kernel_dump_older_agent(tmp_path, monkeypatch):
    client = _FakeClient({
        "ok": False, "kind": "agent_version",
        "error": "live_kernel_dump: older agent/umagent",
    })
    _ctx, server = await _build(tmp_path, monkeypatch,
                                 allow_dump=True, client=client)
    body = await _call(server, {"action": "create_kernel_dump",
                                 "name": "user"})
    assert body.get("ok") is False
    assert body.get("kind") == "agent_version"
