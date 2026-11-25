"""SI #8 — modules enrichment via verify_signatures=True.

Covers:
- Default `memory_manage(action='modules')` response is bit-identical to the
  pre-signer shape (do-not-break matrix §7 — no `signer` / `signing_level`
  / `is_signed` keys appear on rows when the kwarg is False).
- `verify_signatures=True` fires one batched Signatures.Verify RPC and
  joins the response onto each module row by path, surfacing a
  ``signatures`` meta block with cache_hits/probed counters.
- A `None` ``signatures`` stub (older agent) degrades gracefully:
  rows still return, ``signatures.ok`` is False, each row carries an
  empty-shaped signer column so no join field is missing.
- Shape parity: both views (kernel + user) honor the kwarg and emit the
  same signer-row key set.
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


_SEED_MODS = [
    {"name": "ntoskrnl.exe", "base": 0xFFFFF80000000000,
     "size": 0xA00000, "path": r"C:\Windows\System32\ntoskrnl.exe"},
    {"name": "tcpip.sys", "base": 0xFFFFF80000A00000,
     "size": 0x200000, "path": r"C:\Windows\System32\drivers\tcpip.sys"},
    {"name": "ndis.sys", "base": 0xFFFFF80000C00000,
     "size": 0x180000, "path": r"C:\Windows\System32\drivers\ndis.sys"},
]


_SEED_SIGS: dict[str, dict[str, Any]] = {
    r"C:\Windows\System32\ntoskrnl.exe": {
        "signer": "Microsoft Windows", "issuer": "Microsoft Windows Production PCA 2011",
        "signing_level": "windows", "is_signed": True, "catalog": True,
        "cache_timestamp_100ns": 132_000_000_000_000_000, "cache_hit": False,
        "error": "",
    },
    r"C:\Windows\System32\drivers\tcpip.sys": {
        "signer": "Microsoft Windows", "issuer": "Microsoft Windows Production PCA 2011",
        "signing_level": "windows", "is_signed": True, "catalog": False,
        "cache_timestamp_100ns": 132_000_000_000_000_001, "cache_hit": True,
        "error": "",
    },
    r"C:\Windows\System32\drivers\ndis.sys": {
        "signer": "", "issuer": "", "signing_level": "unsigned",
        "is_signed": False, "catalog": False,
        "cache_timestamp_100ns": 0, "cache_hit": False, "error": "",
    },
}


class _FakeAgentClient:
    """Serves the shared seed inventory + Signatures.Verify fan-in."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0
        # Non-None sentinel so `verify_signatures` reaches the stub rather
        # than returning agent_version.
        self.signatures = object()
        self.sig_calls: list[dict[str, Any]] = []

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.2"}

    async def mem_modules(self, pid: int, kernel: bool) -> list[dict]:
        return [dict(m) for m in _SEED_MODS]

    async def verify_signatures(self, paths, *, force_recheck: bool = False
                                 ) -> dict[str, Any]:
        self.sig_calls.append({"paths": list(paths),
                                "force_recheck": force_recheck})
        rows = []
        hits = 0
        probed = 0
        for p in paths:
            s = _SEED_SIGS.get(p)
            if s is None:
                rows.append({
                    "path": p, "signer": "", "issuer": "",
                    "signing_level": "unknown", "is_signed": False,
                    "catalog": False, "cache_timestamp_100ns": 0,
                    "cache_hit": False, "error": "unknown path",
                })
                continue
            row = {"path": p, **s}
            rows.append(row)
            if row.get("cache_hit"):
                hits += 1
            else:
                probed += 1
        return {"ok": True, "rows": rows,
                "cache_hits": hits, "probed": probed}


async def _build_ctx_and_server(tmp_path, monkeypatch, *,
                                 fake_cls=_FakeAgentClient):
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
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr, ownership=ownership_reg)
    server = build_server(ctx)
    return ctx, server


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-B")
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
    # Preserve the top-level signatures meta block (lives alongside data).
    if "signatures" in body:
        merged["signatures"] = body["signatures"]
    elif isinstance(body.get("data"), dict) and "signatures" in body["data"]:
        merged["signatures"] = body["data"]["signatures"]
    return merged


# -----------------------------------------------------------------------
# Default response is unchanged (do-not-break matrix §7)
# -----------------------------------------------------------------------


async def test_modules_default_no_signer_columns(
        tmp_path, monkeypatch) -> None:
    """memory_manage(action='modules') with no verify_signatures= must emit the
    exact pre-signer row shape — no signer / signing_level / is_signed
    key, no signatures meta block."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "module_manage", {
        "action": "list", "kernel": True,
    })
    assert body["ok"] is not False
    rows = body.get("items", [])
    assert len(rows) == len(_SEED_MODS)
    for r in rows:
        assert "signer" not in r
        assert "signing_level" not in r
        assert "is_signed" not in r
        assert "catalog" not in r
        assert "signer_cache_hit" not in r
    assert body.get("signatures") is None, (
        "no signatures meta block without the opt-in kwarg")


# -----------------------------------------------------------------------
# verify_signatures=True attaches columns + emits meta block
# -----------------------------------------------------------------------


async def test_modules_verify_signatures_attaches_columns(
        tmp_path, monkeypatch) -> None:
    """verify_signatures=True joins the Signatures.Verify response onto
    each module row by path and surfaces cache_hits / probed in a
    sibling `signatures` meta block."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "module_manage", {
        "action": "list", "kernel": True,
        "verify_signatures": True,
    })
    assert body["ok"] is not False
    rows = {r["name"]: r for r in body.get("items", [])}
    assert set(rows) == {"ntoskrnl.exe", "tcpip.sys", "ndis.sys"}

    assert rows["ntoskrnl.exe"]["signing_level"] == "windows"
    assert rows["ntoskrnl.exe"]["is_signed"] is True
    assert rows["ntoskrnl.exe"]["catalog"] is True
    assert rows["ntoskrnl.exe"]["signer"] == "Microsoft Windows"

    assert rows["tcpip.sys"]["signer_cache_hit"] is True
    assert rows["ndis.sys"]["signing_level"] == "unsigned"
    assert rows["ndis.sys"]["is_signed"] is False

    meta = body.get("signatures")
    assert isinstance(meta, dict)
    assert meta["ok"] is True
    assert meta["cache_hits"] == 1
    assert meta["probed"] == 2
    assert meta.get("skipped_rows", 0) == 0


# -----------------------------------------------------------------------
# Agent-missing path degrades gracefully
# -----------------------------------------------------------------------


class _FakeAgentNoSig(_FakeAgentClient):
    """Older agent variant: verify_signatures returns the stub
    error that the real HostMixin wrapper surfaces when the gRPC
    SignaturesStub is absent."""

    async def verify_signatures(self, paths, *, force_recheck: bool = False
                                 ) -> dict[str, Any]:
        return {"ok": False, "kind": "agent_version",
                "error": "verify_signatures: older agent/umagent "
                         "(Signatures service missing)",
                "rows": [], "cache_hits": 0, "probed": 0}


async def test_modules_verify_signatures_old_agent_degrades(
        tmp_path, monkeypatch) -> None:
    """When the agent lacks the Signatures service, rows still answer
    and each one carries an empty-shaped signer column (so downstream
    shape parity tests still find the join columns). The meta block
    carries ``ok: False`` with a labelled error."""
    ctx, server = await _build_ctx_and_server(
        tmp_path, monkeypatch, fake_cls=_FakeAgentNoSig)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "module_manage", {
        "action": "list", "kernel": True,
        "verify_signatures": True,
    })
    assert body["ok"] is not False
    rows = body.get("items", [])
    for r in rows:
        assert r.get("signing_level") == ""
        assert r.get("is_signed") is False
        assert r.get("signer_cache_hit") is False
    meta = body.get("signatures")
    assert isinstance(meta, dict)
    assert meta["ok"] is False
    assert "signatures" in (meta.get("error") or "").lower()


# -----------------------------------------------------------------------
# compact=True + verify_signatures=True is a documented error (no path)
# -----------------------------------------------------------------------


async def test_modules_verify_signatures_compact_meta_error(
        tmp_path, monkeypatch) -> None:
    """`compact=True` drops the `path` column, so verify_signatures has
    nothing to join on. Return a documented error in the meta block
    rather than silently dropping the enrichment."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "module_manage", {
        "action": "list", "kernel": True,
        "verify_signatures": True, "compact": True,
    })
    assert body["ok"] is not False
    meta = body.get("signatures")
    assert isinstance(meta, dict)
    assert meta["ok"] is False
    assert "compact" in (meta.get("error") or "").lower()


# -----------------------------------------------------------------------
# Unit test: pure helper (no server scaffolding)
# -----------------------------------------------------------------------


class _StubEnrichClient:
    def __init__(self, canned: dict) -> None:
        self._canned = canned
        self.last_call: dict | None = None

    async def verify_signatures(self, paths, *, force_recheck: bool = False
                                 ) -> dict[str, Any]:
        self.last_call = {"paths": list(paths), "force_recheck": force_recheck}
        return self._canned


async def test_enrich_signatures_merges_by_path() -> None:
    from pry.mcp.tools.mem.modules import _enrich_signatures

    mods = [
        {"name": "a.sys", "path": "C:/a.sys"},
        {"name": "b.sys", "path": "C:/b.sys"},
    ]
    canned = {"ok": True, "cache_hits": 1, "probed": 1, "rows": [
        {"path": "C:/a.sys", "signer": "A Signer", "issuer": "Issuer A",
         "signing_level": "microsoft", "is_signed": True, "catalog": False,
         "cache_hit": False, "error": ""},
        {"path": "C:/b.sys", "signer": "", "issuer": "",
         "signing_level": "unsigned", "is_signed": False, "catalog": False,
         "cache_hit": True, "error": ""},
    ]}
    client = _StubEnrichClient(canned)
    out, meta = await _enrich_signatures(client, mods, force_recheck=False)
    assert out[0]["signing_level"] == "microsoft"
    assert out[0]["signer"] == "A Signer"
    assert out[1]["is_signed"] is False
    assert out[1]["signer_cache_hit"] is True
    assert meta["ok"] is True
    assert meta["cache_hits"] == 1
    assert meta["probed"] == 1
    # One batched call, with each unique path exactly once.
    assert client.last_call == {
        "paths": ["C:/a.sys", "C:/b.sys"], "force_recheck": False,
    }


async def test_enrich_signatures_handles_exception() -> None:
    """A raising RPC degrades to empty-column rows + meta.ok=False."""
    from pry.mcp.tools.mem.modules import _enrich_signatures

    class _Boom:
        async def verify_signatures(self, paths, *, force_recheck=False):
            raise RuntimeError("nope")

    mods = [{"name": "x.sys", "path": "C:/x.sys"}]
    out, meta = await _enrich_signatures(_Boom(), mods, force_recheck=False)
    assert out[0]["signing_level"] == ""
    assert out[0]["is_signed"] is False
    assert meta["ok"] is False
    assert "nope" in meta["error"]
