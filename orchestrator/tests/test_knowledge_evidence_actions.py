"""knowledge_manage evidence actions (Part 3, Task 3.5).

evidence_get (paging + missing_evidence), evidence_summary, evidence_list
(metadata only, no payload leak), evidence_prune gating behind
security.allow_delete.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.evidence import store as ev_store
from pry.mcp.evidence import views as ev_views
from pry.mcp.tools import Context, build_server
from pry.ownership import OwnershipRegistry
from pry.session import Session

MARKER = "decafbad" * 4096  # 32 KiB payload string


async def _build_ctx(tmp_path, monkeypatch):
    async def _noop_probe(host, p, timeout_s: float = 3.0) -> None:
        return None
    monkeypatch.setattr("pry.session._probe_tcp", _noop_probe)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=50051)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
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


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-evidence")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    return body


def _seed(ctx, *, data: dict, tool: str = "memory_manage", action: str = "read",
          detail: str = "complete") -> dict:
    return ev_store.retain(
        request={"action": action, "pid": 1234}, data=data,
        artifacts_root=Path(ctx.cfg.artifacts_dir()), ledger=ctx.ledger,
        tool=tool, action=action, detail=detail)


# ---------------------------------------------------------------- evidence_get ----

async def test_evidence_get_unknown_and_invalid_ids(tmp_path, monkeypatch):
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)

    def _boom(*a: object, **k: object) -> None:
        raise AssertionError("filesystem touched for an invalid id")

    monkeypatch.setattr(Path, "read_text", _boom, raising=False)
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_get", "evidence_id": "../../etc"})
    assert body["ok"] is False
    assert body["error"]["kind"] == "missing_evidence"
    assert "../../etc" in body["error"]["error"]
    assert "re-run the producing action" in body["error"]["hint"]

    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_get",
                        "evidence_id": "ev_" + "a" * 31})
    assert body["error"]["kind"] == "missing_evidence"

    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_get", "evidence_id": "ev_" + "0" * 32})
    assert body["error"]["kind"] == "missing_evidence"


async def test_evidence_get_pages_record_back(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    block = _seed(ctx, data={"hex": MARKER, "addr": "0x1000"})
    ev = block["evidence_id"]

    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_get", "evidence_id": ev,
                        "offset": 0, "limit": 64})
    assert body["ok"] is True
    assert body["data"]["evidence_id"] == ev
    assert body["data"]["field"] == "hex"
    page1 = body["data"]["content"]
    assert page1 == MARKER[:64]
    assert body["summary"]["next_cursor"] == "offset:64"
    assert body["summary"]["truncated"] is True
    assert body["summary"]["item_total"] == len(MARKER)

    # Page 2 via the advertised cursor — bytes equal the retained payload.
    body2 = await _call(server, "knowledge_manage",
                        {"action": "evidence_get", "evidence_id": ev,
                         "offset": 64, "limit": 64})
    assert body2["data"]["content"] == MARKER[64:128]

    # Past the end: empty page, no next cursor.
    body3 = await _call(server, "knowledge_manage",
                        {"action": "evidence_get", "evidence_id": ev,
                         "offset": len(MARKER), "limit": 64})
    assert body3["data"]["content"] == ""
    assert "next_cursor" not in body3.get("summary", {})


async def test_evidence_get_paged_rows_list(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    rows = [{"i": i, "blob": "x" * 40} for i in range(10)]
    block = _seed(ctx, data={"matches": rows}, tool="memory_manage",
                  action="pattern_scan")
    ev = block["evidence_id"]
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_get", "evidence_id": ev,
                        "offset": 0, "limit": 4})
    assert body["data"]["field"] == "matches"
    assert body["data"]["content"] == rows[:4]
    assert body["summary"]["item_total"] == 10
    assert body["summary"]["next_cursor"] == "offset:4"


# ------------------------------------------------------------ evidence_summary ----

async def test_evidence_summary_counts_only(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    block = _seed(ctx, data={"hex": MARKER}, detail="summary")
    ev = block["evidence_id"]
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_summary", "evidence_id": ev})
    assert body["ok"] is True
    out = body.get("data") or {}
    assert out["counts"] == {"hex": len(MARKER)}
    assert out["tool"] == "memory_manage"
    assert out["action"] == "read"
    assert out["detail"] == "summary"
    assert out["size_bytes"] > 0
    assert out["created"] > 0
    # No payload leak.
    assert MARKER[:32] not in json.dumps(body)


async def test_evidence_summary_missing(tmp_path, monkeypatch):
    _ctx, server = await _build_ctx(tmp_path, monkeypatch)
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_summary",
                        "evidence_id": "ev_" + "f" * 32})
    assert body["error"]["kind"] == "missing_evidence"


# -------------------------------------------------------------- evidence_list ----

async def test_evidence_list_metadata_only_and_paging(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    for i in range(3):
        _seed(ctx, data={"hex": MARKER, "seq": i},
              tool="memory_manage" if i < 2 else "ida_manage",
              action="read" if i < 2 else "decompile")

    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_list", "limit": 2, "offset": 0})
    assert body["ok"] is True
    assert body["summary"]["item_total"] == 3
    assert len(body["data"]["items"]) == 2
    assert body["summary"]["next_cursor"] == "offset:2"
    row: dict[str, Any] = body["data"]["items"][0]
    assert set(row) == {"evidence_id", "tool", "action", "detail",
                        "size_bytes", "coverage", "created"}
    assert row["evidence_id"].startswith("ev_")

    # No payload leak anywhere in the response.
    blob = json.dumps(body)
    assert len(blob) < 4096
    assert MARKER[:64] not in blob

    # Substring filter on tool/action.
    body_f = await _call(server, "knowledge_manage",
                         {"action": "evidence_list", "filter": "decompile"})
    assert body_f["summary"]["item_total"] == 1
    assert body_f["data"]["items"][0]["tool"] == "ida_manage"


# ------------------------------------------------------------- evidence_prune ----

async def test_evidence_prune_gated_by_allow_delete(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    block = _seed(ctx, data={"hex": MARKER})
    ev = block["evidence_id"]

    # Default config: allow_delete=false -> refused.
    assert ctx.cfg.security.allow_delete is False
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_prune", "evidence_id": ev})
    assert body["ok"] is False
    assert "allow_delete" in json.dumps(body["error"])
    # Record still there.
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_get", "evidence_id": ev,
                        "offset": 0, "limit": 8})
    assert body["ok"] is True

    ctx.cfg.security.allow_delete = True
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_prune", "evidence_id": ev})
    assert body["ok"] is True, body
    payload = body.get("data") or {}
    assert payload.get("deleted", body.get("deleted", 0)) in (0, 1)
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_get", "evidence_id": ev,
                        "offset": 0, "limit": 8})
    assert body["error"]["kind"] == "missing_evidence"
    assert not (Path(ctx.cfg.artifacts_dir()) / "evidence" / ev[3:5]
                / f"{ev}.json").exists()


async def test_evidence_prune_bulk_requires_confirm(tmp_path, monkeypatch):
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    _seed(ctx, data={"hex": MARKER})
    ctx.cfg.security.allow_delete = True
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_prune"})
    assert body["ok"] is False
    assert body["error"]["kind"] == "bad_arg"
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_prune", "confirm": True})
    assert body["ok"] is True, body
    body = await _call(server, "knowledge_manage",
                       {"action": "evidence_list"})
    assert body["summary"]["item_total"] == 0


# ----------------------------------------------- findings_manage removed ----
# taxonomy brief §7.1: the ``findings_manage`` deprecated alias
# is removed outright. The old forwarder test (``evidence_summary``
# round-trip through findings_manage) is retired alongside it. See
# tests/test_tool_catalog.py::test_findings_manage_is_absent for the
# tool-level regression.
