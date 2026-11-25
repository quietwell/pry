"""`memory_manage(action='pool_scan')` enrichment — SI feature #4.

Two tests pin the contract:

- ``enrich_tags`` defaults to True; each entry row grows ``owner_driver``
  and ``tag_description`` from the vendored ``pooltag.txt`` lookup, and
  the envelope carries ``tags_enriched=True``.
- ``enrich_tags=False`` leaves every entry row bit-identical to the
  pre-R5 default (no ``owner_driver`` key, no ``tag_description`` key)
  and the envelope omits the ``tags_enriched`` flag entirely.

The driver's wire ``PoolScanResponse`` is untouched regardless (the
enrichment is pure orchestrator decoration on top).
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


class _PoolScanClient:
    """Fakes a driver response with 3 canonical pool-tagged allocations."""

    ENTRIES: list[dict[str, Any]] = [
        {"va": 0xFFFF0001000, "size": 0x3F0,
         "tag": int.from_bytes(b"Proc", "little"),
         "tag_ascii": "Proc", "nonpaged": True, "matched_offset": 0},
        {"va": 0xFFFF0002000, "size": 0x240,
         "tag": int.from_bytes(b"Even", "little"),
         "tag_ascii": "Even", "nonpaged": True, "matched_offset": 0},
        # Deliberately uncommon tag so the enrichment lookup MISSES.
        {"va": 0xFFFF0003000, "size": 0x40,
         "tag": int.from_bytes(b"ZzZz", "little"),
         "tag_ascii": "ZzZz", "nonpaged": False, "matched_offset": 0},
    ]

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

    async def pool_scan(self, **kw):
        return {
            "required": len(self.ENTRIES),
            "considered": 2048,
            "holes": 0, "span_truncated": 0,
            "last_index": 0, "next_cursor": 0,
            "entries": [dict(e) for e in self.ENTRIES],
        }


async def _server(tmp_path, monkeypatch, client_cls):
    monkeypatch.setattr("pry.session.AgentClient", client_cls)
    monkeypatch.setattr("pry.mcp.tools.AgentClient", client_cls)

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


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-A")
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
    merged.setdefault("ok", body.get("ok"))
    return merged


async def test_pool_scan_enrich_tags_default_true(tmp_path, monkeypatch):
    _ctx, server = await _server(tmp_path, monkeypatch, _PoolScanClient)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "kernel_manage", {
        "action": "pool_scan"})
    assert body["ok"] is True, body
    # Envelope flag + hit counter.
    assert body["tags_enriched"] is True
    assert body["tags_enriched_hits"] == 2  # Proc, Even hit; ZzZz misses
    rows = body["items"]
    assert len(rows) == 3
    by_tag = {r["tag_ascii"]: r for r in rows}
    assert by_tag["Proc"]["owner_driver"] == "nt"
    assert "Process" in by_tag["Proc"]["tag_description"]
    assert by_tag["Even"]["owner_driver"] == "nt"
    # Miss row carries empty-string fields, not absent keys.
    assert by_tag["ZzZz"]["owner_driver"] == ""
    assert by_tag["ZzZz"]["tag_description"] == ""


async def test_pool_scan_enrich_tags_false_is_bit_identical(tmp_path,
                                                              monkeypatch):
    """When enrich_tags=False, rows must look exactly like the pre-R5
    default: no owner_driver / tag_description keys, no tags_enriched
    flag in the envelope."""
    _ctx, server = await _server(tmp_path, monkeypatch, _PoolScanClient)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "kernel_manage", {
        "action": "pool_scan",
        "enrich_tags": False})
    assert body["ok"] is True, body
    assert "tags_enriched" not in body
    assert "tags_enriched_hits" not in body
    for r in body["items"]:
        assert "owner_driver" not in r
        assert "tag_description" not in r
        # Legacy fields are still present (unchanged wire shape).
        assert "tag" in r and "tag_ascii" in r
        assert "va" in r and "size" in r
