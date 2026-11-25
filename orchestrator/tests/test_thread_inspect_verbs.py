"""thread_manage per-thread verbs: wait / irp / impersonation / com / rpc /
power / fiber call their ThreadInspect wrapper instead of answering
``kind='not_implemented'``.

Covers:

* each verb calls its wrapper with the tid and returns the column shape the
  ``list`` include_* columns carry (``*_hex`` / ``*_va`` fields as '0x…');
* ``tid=`` is required;
* ``wave_3_pending`` (the agent's WaitInfo / IrpList placeholder) is
  reported by name, not swallowed;
* the wrong view (``not_supported`` / ``no_driver``) points at the right one;
* thread-gone / protected / timeout tokens map to their kinds, unknown
  text to ``thread_inspect_failed``;
* a transport UNIMPLEMENTED or a client without the wrapper becomes
  ``agent_version``;
* the per-verb help no longer claims the verbs are reserved.
"""
from __future__ import annotations

import asyncio
import json as _json

import pytest

from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.tools import Context, build_server
from pry.mcp.tools.thread import _INSPECT_VERBS, _THREAD_ACTION_HELP
from pry.ownership import OwnershipRegistry
from pry.session import Session


# verb -> (client wrapper, ok answer, predicate over the merged body)
_VERBS = {
    "wait": (
        "thread_wait_info",
        {"ok": True, "last_syscall_number": 4,
         "last_syscall_name": "NtWaitForSingleObject",
         "last_syscall_status_hex": "0x0",
         "kernel_stack_base_hex": 0xFFFFF80012340000,
         "kernel_stack_limit": 0xFFFFF8001233B000,
         "kernel_stack_rsp": 0xFFFFF8001233F000,
         "kernel_stack_excursion": 4096,
         "wait_reason": 6, "wait_mode": 1, "wait_status": 0,
         "thread_state": 5},
        lambda b: (b["last_syscall"]["name"] == "NtWaitForSingleObject"
                   and b["kernel_stack"]["rsp_hex"] == "0xfffff8001233f000"
                   and b["thread_state"] == 5),
    ),
    "irp": (
        "thread_irp_list",
        {"ok": True, "pending": True, "irp_count": 1,
         "irps": [{"irp_va": 0xFFFFA00000001000,
                   "device_name": "\\Device\\Harddisk0",
                   "major_fn": 3, "minor_fn": 0,
                   "cancel_routine_va": 0}]},
        lambda b: (b["pending"] is True and b["irp_count"] == 1
                   and b["irps"][0]["irp_va"] == "0xffffa00000001000"),
    ),
    "impersonation": (
        "thread_impersonation",
        {"ok": True, "present": True, "user": "NT AUTHORITY\\SYSTEM",
         "level": "Impersonation", "is_self": False, "sid": "S-1-5-18"},
        lambda b: b["present"] is True and b["user"] == "NT AUTHORITY\\SYSTEM",
    ),
    "com": (
        "thread_com_apartment",
        {"ok": True, "type": "MTA", "flags": ["INIT"], "teb_rfo": 0x1A2B},
        lambda b: b["type"] == "MTA" and b["teb_rfo_hex"] == "0x1a2b",
    ),
    "rpc": (
        "thread_rpc_usage",
        {"ok": True, "in_rpc_call": True, "server": "lsass.exe",
         "chain_length": 2},
        lambda b: b["in_rpc_call"] is True and b["server"] == "lsass.exe",
    ),
    "power": (
        "thread_power_throttling",
        {"ok": True, "control_mask": 1, "state_mask": 3},
        lambda b: (b["control_mask_hex"] == "0x1"
                   and b["state_mask_hex"] == "0x3"),
    ),
    "fiber": (
        "thread_fiber",
        {"ok": True, "has_fiber_data": True},
        lambda b: b["has_fiber_data"] is True,
    ),
}


class _InspectClient:
    """Serves one canned answer per ThreadInspect wrapper and records calls."""

    def __init__(self, answers: dict | None = None,
                 raises: dict | None = None) -> None:
        self.calls: list[tuple[str, int]] = []
        self._answers = answers or {}
        self._raises = raises or {}
        self.last_op_ts = 0.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.endpoint = "lab:50051"

    def _do(self, method: str, tid: int) -> dict:
        self.calls.append((method, tid))
        if method in self._raises:
            raise self._raises[method]
        default = {"ok": True}
        for verb_method, answer, _check in _VERBS.values():
            if verb_method == method:
                default = answer
        return dict(self._answers.get(method, default))

    async def thread_wait_info(self, tid):
        return self._do("thread_wait_info", tid)

    async def thread_irp_list(self, tid):
        return self._do("thread_irp_list", tid)

    async def thread_impersonation(self, tid):
        return self._do("thread_impersonation", tid)

    async def thread_com_apartment(self, tid):
        return self._do("thread_com_apartment", tid)

    async def thread_rpc_usage(self, tid):
        return self._do("thread_rpc_usage", tid)

    async def thread_power_throttling(self, tid):
        return self._do("thread_power_throttling", tid)

    async def thread_fiber(self, tid):
        return self._do("thread_fiber", tid)

    def recent_ops(self, n):
        return []


class _BareClient:
    """An agent client that predates ThreadInspect: no thread_* wrappers."""

    last_op_ts = 0.0
    last_seen_ts = 0.0
    connected_ts = 0.0
    endpoint = "lab:50051"

    def recent_ops(self, n):
        return []


async def _build(tmp_path, monkeypatch, client):
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
    # Deterministic view label for the hints: '' -> lab.kernel, else verbatim.
    session.resolve_view_name = (  # type: ignore[assignment]
        lambda name="", client_id=None: name or "lab.kernel")
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
    token = CLIENT_ID.set("peer-ti-verbs")
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
        if "kind" in body["error"]:
            merged["kind"] = body["error"]["kind"]
    merged.setdefault("ok", body.get("ok"))
    return merged


@pytest.mark.parametrize("verb", list(_VERBS))
async def test_verb_calls_its_wrapper_and_returns_the_column(
        verb, tmp_path, monkeypatch):
    method, answer, check = _VERBS[verb]
    client = _InspectClient({method: answer})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": verb, "tid": 4})
    assert body["ok"] is True, body
    assert client.calls == [(method, 4)]
    assert body["tid"] == 4
    assert check(body), body


@pytest.mark.parametrize("verb", list(_VERBS))
async def test_tid_is_required(verb, tmp_path, monkeypatch):
    client = _InspectClient()
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": verb})
    assert body["ok"] is False, body
    assert body["kind"] == "bad_arg", body
    assert client.calls == []


async def test_wave_3_pending_is_named_not_swallowed(tmp_path, monkeypatch):
    """The agent's WaitInfo is a placeholder that answers wave_3_pending;
    the verb reports that by name instead of 'reserved for a later release'."""
    client = _InspectClient({"thread_wait_info": {
        "ok": False, "error": "wave_3_pending"}})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "wait", "tid": 4})
    assert body["ok"] is False, body
    assert body["kind"] == "wave_3_pending", body
    assert "Wave 3" in body["hint"], body
    assert "not_implemented" not in _json.dumps(body)


async def test_user_verb_on_kernel_view_points_at_the_user_view(
        tmp_path, monkeypatch):
    client = _InspectClient({"thread_impersonation": {
        "ok": False, "error": "not_supported"}})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "impersonation", "tid": 4,
                                "name": "lab.kernel"})
    assert body["ok"] is False, body
    assert body["kind"] == "not_supported", body
    assert "name='lab.user'" in body["hint"], body


async def test_kernel_verb_on_user_view_points_at_the_kernel_view(
        tmp_path, monkeypatch):
    client = _InspectClient({"thread_irp_list": {
        "ok": False, "error": "no_driver"}})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "irp", "tid": 4,
                                "name": "lab.user"})
    assert body["ok"] is False, body
    assert body["kind"] == "no_driver", body
    assert "name='lab.kernel'" in body["hint"], body


@pytest.mark.parametrize("text,kind", [
    ("no_thread", "no_thread"),
    ("no_teb", "no_teb"),
    ("access_denied", "access_denied"),
    ("wct_timeout", "wct_timeout"),
    ("0xC0000022", "access_denied"),
    ("wct_failed", "thread_inspect_failed"),
    ("open_thread_token_failed", "thread_inspect_failed"),
])
async def test_agent_error_tokens_map_to_kinds(
        text, kind, tmp_path, monkeypatch):
    client = _InspectClient({"thread_com_apartment": {
        "ok": False, "error": text}})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "com", "tid": 4,
                                "name": "lab.user"})
    assert body["ok"] is False, body
    assert body["kind"] == kind, body
    assert text in body["error"], body


async def test_transport_unimplemented_becomes_agent_version(
        tmp_path, monkeypatch):
    client = _InspectClient(raises={
        "thread_fiber": RuntimeError("UNIMPLEMENTED: no such method")})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "fiber", "tid": 4,
                                "name": "lab.user"})
    assert body["ok"] is False, body
    assert body["kind"] == "agent_version", body
    assert "update_target" in body["hint"], body


async def test_client_without_the_wrapper_is_agent_version(
        tmp_path, monkeypatch):
    _ctx, server = await _build(tmp_path, monkeypatch, _BareClient())
    body = await _call(server, {"action": "rpc", "tid": 4,
                                "name": "lab.user"})
    assert body["ok"] is False, body
    assert body["kind"] == "agent_version", body


def test_help_no_longer_claims_the_verbs_are_reserved():
    text = _json.dumps(_THREAD_ACTION_HELP)
    assert "P4 wires" not in text
    assert "reserved" not in text
    assert set(_INSPECT_VERBS) <= set(_THREAD_ACTION_HELP)
