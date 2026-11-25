"""PR #6 T3.2 — cpu_manage (MSR / CPUID reader).

Pure-Python tests at the orchestrator layer. A FakeAgent stands in for
the gRPC/driver round trip; everything about the per-core walk is tested
through the MCP tool surface so a schema or envelope drift breaks loudly.

- action='actions' returns the help shape (parity with other tools).
- msr_read VM_CR cores='all' decodes msr_name=VM_CR and surfaces
  per-core {core,value,nt_status}.
- msr_read 0x1337 cores=[0] with mocked STATUS_UNSUCCESSFUL leaves the
  nt_status on the row and marks read_ok=False — no exception.
- cpuid leaf=1 cores='all' decodes hypervisor_present + vmx_available.
- list_known_msrs returns the catalog with VM_CR / IA32_EFER /
  IA32_FEATURE_CONTROL present.
"""
from __future__ import annotations

import asyncio
import json as _json
from typing import Any

import pytest

from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig
from pry.cpu_consts import KNOWN_MSRS, msr_resolve
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.tools import Context, build_server
from pry.ownership import OwnershipRegistry
from pry.session import Session


_STATUS_SUCCESS = 0
_STATUS_UNSUCCESSFUL = 0xC0000001


# --------------------------------------------------------------------------- #
# shared fake AgentClient — only the surface cpu_manage touches
# --------------------------------------------------------------------------- #


class _CpuFake:
    """Minimal AgentClient-shaped fake for cpu_manage. Lets each test
    pre-seed per-core MSR / CPUID outputs by writing to .msr_rows /
    .cpuid_rows."""

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.msr_calls: list[tuple[int, list[int] | None, bool]] = []
        self.cpuid_calls: list[tuple[int, int, list[int] | None, bool]] = []
        # Callbacks: (msr, cores, all_cores) -> list[dict]; override per test.
        self.msr_rows: list[dict[str, Any]] = []
        self.cpuid_rows: list[dict[str, Any]] = []

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
                "agent_instance_id": "fake-pr6"}

    async def host_info(self, include_security_products: bool = False,
                        include_hardware: bool = True) -> dict[str, Any]:
        return {"ok": True}

    async def msr_read(self, msr: int, cores: list[int] | None,
                       all_cores: bool) -> list[dict[str, Any]]:
        self.msr_calls.append((int(msr), list(cores or []), bool(all_cores)))
        return list(self.msr_rows)

    async def cpuid(self, leaf: int, subleaf: int = 0,
                    cores: list[int] | None = None,
                    all_cores: bool = False) -> list[dict[str, Any]]:
        self.cpuid_calls.append((int(leaf), int(subleaf),
                                 list(cores or []), bool(all_cores)))
        return list(self.cpuid_rows)


# --------------------------------------------------------------------------- #
# shared ctx builder — same shape as test_pr1_ergonomics
# --------------------------------------------------------------------------- #


async def _build_ctx_and_server(tmp_path, monkeypatch, fake_cls=_CpuFake):
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
    token = CLIENT_ID.set("peer-pr6")
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
# cpu_consts smoke
# --------------------------------------------------------------------------- #


def test_pr6_msr_resolve_accepts_name_hex_and_int():
    assert msr_resolve("VM_CR") == 0xC0010114
    assert msr_resolve("0xC0010114") == 0xC0010114
    assert msr_resolve(0xC0010114) == 0xC0010114
    assert msr_resolve("vm_cr") == 0xC0010114
    with pytest.raises(ValueError):
        msr_resolve("")


# --------------------------------------------------------------------------- #
# action='actions' — same help shape as every other tool
# --------------------------------------------------------------------------- #


async def test_pr6_actions_help_shape(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    body = await _call(server, "cpu_manage", {"action": "actions"})
    assert body["ok"] is True, body
    actions = body.get("actions", {})
    assert set(actions.keys()) >= {"actions", "msr_read", "cpuid",
                                   "list_known_msrs"}
    for verb, spec in actions.items():
        assert "one_liner" in spec and spec["one_liner"]
        assert "key_args" in spec
        assert "example" in spec and spec["example"]
    assert isinstance(body.get("count"), int)
    assert body.get("count") == len(actions)
    assert "hint" in body


# --------------------------------------------------------------------------- #
# list_known_msrs
# --------------------------------------------------------------------------- #


async def test_pr6_list_known_msrs(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    body = await _call(server, "cpu_manage",
                        {"action": "list_known_msrs"})
    assert body["ok"] is True, body
    table = body.get("known_msrs") or {}
    # Required entries called out in the plan.
    for name in ("VM_CR", "IA32_EFER", "IA32_FEATURE_CONTROL"):
        assert name in table, (name, table)
    # Hex formatting is uppercase, 8-wide, 0x-prefixed.
    assert table["VM_CR"] == "0xC0010114"
    assert body.get("count") == len(table)


# --------------------------------------------------------------------------- #
# msr_read VM_CR cores='all'
# --------------------------------------------------------------------------- #


async def test_pr6_msr_read_vm_cr_all_cores(tmp_path, monkeypatch):
    """msr_read msr='0xC0010114' cores='all' decodes msr_name='VM_CR'
    and carries one row per core with {core,value,nt_status}."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.msr_rows = [
        {"core": 0, "value": 0x8, "nt_status": _STATUS_SUCCESS},
        {"core": 1, "value": 0x0, "nt_status": _STATUS_SUCCESS},
    ]

    body = await _call(server, "cpu_manage",
                        {"action": "msr_read",
                         "msr": "0xC0010114",
                         "cores": "all"})
    assert body["ok"] is True, body
    # Pretty-print caught the well-known name.
    assert body.get("msr_name") == "VM_CR"
    assert body.get("msr") == 0xC0010114 \
        or body.get("msr") == "0xC0010114"  # _j_hex may hexify
    rows = body.get("rows", [])
    assert len(rows) == 2
    cores_seen: set[int] = set()
    for r in rows:
        # Numeric fields may be hex-stringified by _j_hex; the "_int"
        # mirror holds the raw int.
        core = r.get("core")
        if isinstance(core, str):
            core = int(core, 16) if core.startswith("0x") else int(core)
        cores_seen.add(int(core))
        assert "value" in r
        assert "nt_status" in r
        # per-row MSR name annotation
        assert r.get("msr_name") == "VM_CR"
        assert r.get("read_ok") is True
    assert cores_seen == {0, 1}

    # Agent saw a single call with all_cores=True.
    assert len(fake.msr_calls) == 1
    msr, cores_arg, all_cores = fake.msr_calls[0]
    assert msr == 0xC0010114
    assert all_cores is True


# --------------------------------------------------------------------------- #
# msr_read unimplemented MSR
# --------------------------------------------------------------------------- #


async def test_pr6_msr_read_unimplemented_surfaces_ntstatus(tmp_path,
                                                             monkeypatch):
    """A STATUS_UNSUCCESSFUL per-core row (unimplemented MSR) comes
    back cleanly — no exception, read_ok=False, no msr_name because
    0x1337 isn't well-known."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.msr_rows = [
        {"core": 0, "value": 0, "nt_status": _STATUS_UNSUCCESSFUL},
    ]

    body = await _call(server, "cpu_manage",
                        {"action": "msr_read",
                         "msr": 0x1337,
                         "cores": [0]})
    assert body["ok"] is True, body
    # Not well-known -> no msr_name on the top-level envelope.
    assert body.get("msr_name") == ""
    rows = body.get("rows", [])
    assert len(rows) == 1
    row = rows[0]
    # Un-decoded status survives the round trip.
    nts = row.get("nt_status")
    if isinstance(nts, str):
        nts = int(nts, 16)
    assert nts == _STATUS_UNSUCCESSFUL
    assert row.get("read_ok") is False
    assert "msr_name" not in row

    assert len(fake.msr_calls) == 1
    msr, cores_arg, all_cores = fake.msr_calls[0]
    assert msr == 0x1337
    assert cores_arg == [0]
    assert all_cores is False


# --------------------------------------------------------------------------- #
# cpuid leaf=1 cores='all' decode
# --------------------------------------------------------------------------- #


async def test_pr6_cpuid_leaf1_decodes_hv_present_and_vmx(tmp_path,
                                                            monkeypatch):
    """CPUID leaf 1 ECX bit 31 (hypervisor_present) and bit 5
    (vmx_available) decode from the mocked register values."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    ecx = (1 << 31) | (1 << 5)  # hypervisor + VMX
    fake.cpuid_rows = [
        {"core": 0, "eax": 0, "ebx": 0, "ecx": ecx, "edx": 0},
        {"core": 1, "eax": 0, "ebx": 0, "ecx": ecx, "edx": 0},
    ]

    body = await _call(server, "cpu_manage",
                        {"action": "cpuid",
                         "leaf": 1,
                         "cores": "all"})
    assert body["ok"] is True, body
    rows = body.get("rows", [])
    assert len(rows) == 2
    for row in rows:
        decoded = row.get("decoded") or {}
        assert decoded.get("hypervisor_present") is True
        assert decoded.get("vmx_available") is True

    assert len(fake.cpuid_calls) == 1
    leaf, subleaf, cores_arg, all_cores = fake.cpuid_calls[0]
    assert leaf == 1
    assert subleaf == 0
    assert all_cores is True


# --------------------------------------------------------------------------- #
# Guardrail: KNOWN_MSRS exposes the minimum set the plan calls out.
# --------------------------------------------------------------------------- #


def test_pr6_known_msrs_minimum_set():
    names = set(KNOWN_MSRS.values())
    for required in ("IA32_FEATURE_CONTROL", "IA32_EFER", "VM_CR",
                     "IA32_VMX_BASIC", "IA32_SYSENTER_CS", "MTRRCAP"):
        assert required in names, required
