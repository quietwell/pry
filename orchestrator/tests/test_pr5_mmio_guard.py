"""PR #5 — T3.1 Physical MMIO guard.

Covers:
- Physical read without ``allow_mmio`` where the mocked agent raises
  STATUS_ACCESS_DENIED (driver's new default-deny) surfaces as
  ``kind='mmio_blocked'`` with the device-wedge warning hint.
- Physical read with ``allow_mmio=True`` propagates the kwarg into the
  agent-client call; the mocked agent returns bytes; the orchestrator
  echoes the bytes to the caller unchanged.
- Plain in-range physical read (no guard trip, no opt-in flag) is
  unaffected by the new surface and returns bytes.

The driver + agent-gRPC + proto edits that land in this PR are not
exercised here — the tests mock the agent at the ``AgentClient``
boundary (same pattern as PR#1/#2), so no live gRPC + no regenerated
proto bindings are required for pytest.
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


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #

class _FakePhysAgent:
    """Minimal AgentClient-shaped fake with configurable mem_read behavior.

    Behavior switches:
    - ``phys_denied`` : when True, physical reads raise RuntimeError with
      a STATUS_ACCESS_DENIED message (what the T3.1 driver guard emits).
    - ``phys_bytes``  : bytes returned when ``phys_denied`` is False.
    """

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.phys_denied: bool = False
        self.phys_bytes: bytes = b""
        # Captured on every mem_read call so tests can assert what the
        # orchestrator forwarded (allow_mmio, allow_fault, size, ...).
        self.mem_read_calls: list[dict[str, Any]] = []

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": self.endpoint,
                "driver_state": "DRIVER_SERVICE",
                "boot_epoch_ms": 1,
                "agent_instance_id": "fake-mmio",
                "agent_version": "99"}

    async def host_info(self, include_security_products: bool = False,
                        include_hardware: bool = True) -> dict[str, Any]:
        return {"ok": True,
                "identity": {"computer_name": "HOST-FAKE"}}

    async def mem_read(self, pid: int, address: int, size: int,
                       space: str = "user", allow_fault: bool = False,
                       partial: bool = False,
                       timeout: float | None = None,
                       want_meta: bool = False,
                       *,
                       max_bytes: int = 0,
                       allow_mmio: bool = False):
        self.mem_read_calls.append({
            "pid": pid, "address": address, "size": size, "space": space,
            "allow_fault": allow_fault, "partial": partial,
            "want_meta": want_meta, "allow_mmio": allow_mmio,
        })
        # Only physical reads participate in the T3.1 guard.
        if space == "physical" and self.phys_denied and not allow_mmio:
            # Shape mirrors what the real agent client raises when the
            # agent surfaces an unsuccessful status — the string carries
            # the NTSTATUS so the orchestrator's _looks_mmio_guard scanner
            # can classify it.
            raise RuntimeError(
                "driver: DeviceIoControl status=0xC0000022 "
                "(STATUS_ACCESS_DENIED) gle=5")
        data = self.phys_bytes[:size]
        if want_meta:
            return data, {"read_bytes": len(data), "first_bad_offset": 0}
        return data


# --------------------------------------------------------------------------- #
# shared ctx builder
# --------------------------------------------------------------------------- #

async def _build_ctx_and_server(tmp_path, monkeypatch,
                                fake_cls=_FakePhysAgent):
    monkeypatch.setattr("pry.session.AgentClient", fake_cls)
    monkeypatch.setattr("pry.mcp.tools.AgentClient", fake_cls)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0) -> None:
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
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(
            clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr,
                  ownership=ownership_reg)
    server = build_server(ctx)
    return ctx, server


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-pr5")
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
# T3.1 — physical MMIO guard
# --------------------------------------------------------------------------- #

async def test_pr5_t31_physical_read_without_allow_mmio_blocks(
        tmp_path, monkeypatch):
    """A physical read without allow_mmio where the mocked agent raises
    STATUS_ACCESS_DENIED (the T3.1 driver guard) surfaces as
    kind='mmio_blocked' with the device-wedge hint."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.phys_denied = True  # Driver's new default-deny.

    body = await _call(server, "memory_manage",
                        {"action": "read", "space": "physical",
                         "address": 0x1000, "size": 0x100})
    assert body.get("ok") is False, body
    assert body.get("kind") == "mmio_blocked", body
    hint = body.get("hint", "")
    assert "allow_mmio=True" in hint
    assert "wedge" in hint.lower()
    # The orchestrator forwarded exactly one mem_read, with allow_mmio=False
    # (default) — same byte path the driver guard is matching against.
    assert len(fake.mem_read_calls) == 1
    assert fake.mem_read_calls[0]["space"] == "physical"
    assert fake.mem_read_calls[0]["allow_mmio"] is False


async def test_pr5_t31_physical_read_allow_mmio_true_passes_through(
        tmp_path, monkeypatch):
    """allow_mmio=True forwards the opt-in flag into the agent client and
    the orchestrator returns the bytes the agent provided."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    # Even with phys_denied, allow_mmio=True takes the open path and the
    # mock returns bytes — exact mirror of the driver's AllowOutOfRam=1
    # branch (where behavior is "as today").
    fake.phys_denied = True
    fake.phys_bytes = bytes.fromhex("de ad be ef ca fe ba be".replace(" ", ""))

    body = await _call(server, "memory_manage",
                        {"action": "read", "space": "physical",
                         "address": 0xFE60_0000, "size": 8,
                         "allow_mmio": True})
    assert body.get("ok") is not False, body
    # Bytes echo through unchanged.
    assert body.get("hex", "").lower() == "deadbeefcafebabe"
    # The orchestrator forwarded allow_mmio=True in the single mem_read it
    # issued. The agent client would then set the proto field.
    assert len(fake.mem_read_calls) == 1
    call = fake.mem_read_calls[0]
    assert call["space"] == "physical"
    assert call["allow_mmio"] is True


async def test_pr5_t31_physical_in_range_read_unaffected(
        tmp_path, monkeypatch):
    """An in-range RAM read (no guard trip) returns bytes exactly as
    before — the new flag path is opt-in and does not perturb the
    legacy success path."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.phys_denied = False
    fake.phys_bytes = b"RAMRAMRAMRAMRAMR"  # 16 bytes

    body = await _call(server, "memory_manage",
                        {"action": "read", "space": "physical",
                         "address": 0x1_0000, "size": 16})
    assert body.get("ok") is not False, body
    assert body.get("hex", "").lower() == b"RAMRAMRAMRAMRAMR".hex()
    # allow_mmio defaults off; the mem_read call reflects that.
    assert len(fake.mem_read_calls) == 1
    assert fake.mem_read_calls[0]["allow_mmio"] is False


async def test_pr5_t31_mmio_blocked_slug_registered():
    """Anti-drift: ``mmio_blocked`` is registered in KNOWN_KINDS so the
    schema test and the result enricher both recognize it."""
    from pry.mcp.error_maps import KNOWN_KINDS, is_known_kind
    assert "mmio_blocked" in KNOWN_KINDS
    assert is_known_kind("mmio_blocked")


# --------------------------------------------------------------------------- #
# Compatibility note: proto-field hasattr probe
# --------------------------------------------------------------------------- #

async def test_pr5_t31_agent_client_hasattr_probe_shape():
    """The agent_client.mem.mem_read uses a DESCRIPTOR.fields_by_name
    probe on pb.MemoryReadRequest to decide whether to set the new
    proto field. This test asserts the probe exists so an inadvertent
    rename of the field path (e.g. moving to a positional kwarg) is
    caught before it ships. The probe is in-process bytecode, not a
    live gRPC call."""
    import inspect

    from pry.agent_client.mem import MemMixin

    src = inspect.getsource(MemMixin.mem_read)
    assert "allow_mmio" in src
    # Probe pattern — do not harden on the exact string, just on the
    # fields_by_name mechanism that upgrades gracefully.
    assert "fields_by_name" in src
