"""Unit tests for svc_manage.

Covers the orchestrator layer: happy-path ``list`` with the
``kind='service'|'driver'`` discriminator, ``verify_signatures`` opt-in
threading through to ``verify_signatures``, and the umagent-only guard
on ``.kernel`` suffix. Read-only this cycle — no mutator tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP

from pry.config import PryConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.mcp.tools import Context
from pry.mcp.tools import svc as svc_tool
from pry.mcp.tools.svc import (_enrich_svc_signatures, _empty_sig_cols,
                                    _row_kind)
from pry.session import Session


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeSvcClient:
    """Satisfies the SvcMixin surface plus the signer-enrichment call."""

    def __init__(self, *, list_rows=None, get_item=None,
                 drivers=None, dependencies=None,
                 sig_rows=None, sig_ok=True) -> None:
        self.services = object()
        self.network = None
        self.signatures = object()
        self._list_rows = list_rows or []
        self._get_item = get_item
        self._drivers = drivers or []
        self._dependencies = dependencies or []
        self._sig_rows = sig_rows or []
        self._sig_ok = sig_ok
        self.last_list_kw: dict[str, Any] | None = None
        self.last_verify_paths: list[str] | None = None

    async def svc_list(self, **kw):
        self.last_list_kw = kw
        return {"ok": True, "items": list(self._list_rows),
                "total": len(self._list_rows),
                "truncated": False, "degraded_rows": 0}

    async def svc_get(self, **kw):
        if self._get_item is None:
            return {"ok": False, "kind": "svc_get_failed",
                    "error": "not found"}
        return {"ok": True, "item": dict(self._get_item)}

    async def svc_dependencies(self, **kw):
        return {"ok": True, "items": list(self._dependencies)}

    async def svc_drivers(self, **kw):
        return {"ok": True, "items": list(self._drivers)}

    async def verify_signatures(self, paths, *, force_recheck=False):
        self.last_verify_paths = list(paths)
        if not self._sig_ok:
            return {"ok": False, "error": "boom", "rows": [],
                    "cache_hits": 0, "probed": 0}
        return {"ok": True, "rows": list(self._sig_rows),
                "cache_hits": 1, "probed": max(0, len(paths) - 1)}


class _FakeSvcSession:
    def __init__(self, client: _FakeSvcClient) -> None:
        self._client = client
        self.clients = {"lab.user": client}
        self.primary = "lab.user"

    def resolve_view_name(self, name: str = "", client_id: str = "") -> str:
        n = (name or "").strip().lower()
        return n or "lab.user"

    def require_client(self, name: str = ""):
        n = (name or "").strip().lower()
        if n.endswith(".kernel"):
            raise RuntimeError(f"not connected: {n}")
        return self._client

    def assert_allowed(self, tool, action, args):
        return None

    def stamp_needed(self, view: str) -> bool:
        return False

    def target_stamp(self, name: str = ""):
        return None

    def record_tool_call(self, *args, **kwargs) -> None:
        return None


def _mk_ctx(tmp_path: Path, client: _FakeSvcClient) -> Context:
    cfg = PryConfig()
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = _FakeSvcSession(client)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                        tmp_path / "artifacts")
    return Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge)


async def _call_tool(server, name: str, args: dict) -> dict:
    result = await server.call_tool(name, args)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    return body


def _build(ctx: Context) -> FastMCP:
    mcp = FastMCP("pry-svc-test")
    svc_tool.register(mcp, ctx)
    return mcp


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_row_kind_derives_from_service_type() -> None:
    assert _row_kind({"service_type": "driver"}) == "driver"
    assert _row_kind({"service_type": "win32_own"}) == "service"
    # Explicit kind wins.
    assert _row_kind({"kind": "driver", "service_type": "win32_own"}) == "driver"


def test_empty_sig_cols_shape() -> None:
    cols = _empty_sig_cols()
    for k in ("signer", "signing_level", "signer_error"):
        assert cols[k] == ""
    for k in ("is_signed", "catalog", "signer_cache_hit"):
        assert cols[k] is False


async def test_enrich_svc_signatures_merges_rows() -> None:
    items = [
        {"name": "A", "image_path": r"C:\Windows\System32\a.exe"},
        {"name": "B", "image_path": r"C:\Windows\System32\b.exe"},
    ]
    sig = [
        {"path": r"C:\Windows\System32\a.exe", "signer": "Microsoft",
         "signing_level": "Microsoft", "is_signed": True,
         "catalog": False, "cache_hit": True, "error": ""},
        {"path": r"C:\Windows\System32\b.exe", "signer": "", "signing_level": "",
         "is_signed": False, "catalog": False, "cache_hit": False,
         "error": "unsigned"},
    ]
    client = _FakeSvcClient(sig_rows=sig)
    out, meta = await _enrich_svc_signatures(client, items, force_recheck=False)
    assert meta["ok"] is True
    assert out[0]["signer"] == "Microsoft"
    assert out[0]["is_signed"] is True
    assert out[1]["signer_error"] == "unsigned"
    assert out[1]["is_signed"] is False


async def test_enrich_svc_signatures_degrades_on_rpc_failure() -> None:
    items = [{"name": "A", "image_path": r"C:\a.exe"}]
    client = _FakeSvcClient(sig_ok=False)
    out, meta = await _enrich_svc_signatures(client, items, force_recheck=False)
    assert meta["ok"] is False
    # Row still gets empty signer columns so downstream readers don't crash.
    assert out[0]["signer"] == ""
    assert out[0]["signer_error"] == ""


# ---------------------------------------------------------------------------
# Handler integration
# ---------------------------------------------------------------------------


async def test_svc_list_discriminates_service_vs_driver(tmp_path) -> None:
    rows = [
        {"name": "Spooler", "display_name": "Print Spooler",
         "state": "RUNNING", "start_type": "AUTO_START",
         "service_type": "win32_own", "kind": "service",
         "image_path": r"C:\Windows\System32\spoolsv.exe", "pid": 1234},
        {"name": "disk", "display_name": "Disk Driver",
         "state": "RUNNING", "start_type": "BOOT_START",
         "service_type": "driver", "kind": "driver",
         "image_path": r"C:\Windows\System32\drivers\disk.sys", "pid": 0,
         "module_base": 0xFFFFF8070A000000, "module_size": 0x20000},
    ]
    client = _FakeSvcClient(list_rows=rows)
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)
    body = await _call_tool(server, "svc_manage",
                             {"action": "list", "limit": 10})
    assert body.get("ok") is True
    items = (body.get("data") or {}).get("items") or []
    kinds = {r["name"]: r["kind"] for r in items}
    assert kinds["Spooler"] == "service"
    assert kinds["disk"] == "driver"


async def test_svc_list_signer_enrichment_opt_in(tmp_path) -> None:
    rows = [
        {"name": "Spooler", "image_path": r"C:\Windows\System32\spoolsv.exe",
         "service_type": "win32_own", "state": "RUNNING",
         "start_type": "AUTO_START"},
    ]
    sig = [
        {"path": r"C:\Windows\System32\spoolsv.exe",
         "signer": "Microsoft Windows", "signing_level": "Windows",
         "is_signed": True, "catalog": False, "cache_hit": True, "error": ""},
    ]
    client = _FakeSvcClient(list_rows=rows, sig_rows=sig)
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)

    # Default: no verify, no sig_meta.
    body = await _call_tool(server, "svc_manage",
                             {"action": "list", "limit": 10})
    assert body.get("ok") is True
    extras = (body.get("data") or {})
    assert "signer_enrichment" not in extras
    assert client.last_verify_paths is None  # not fired

    # Opt in: enrichment call fires, signer columns populated.
    body = await _call_tool(server, "svc_manage",
                             {"action": "list",
                              "verify_signatures": True, "limit": 10})
    assert body.get("ok") is True
    items = (body.get("data") or {}).get("items") or []
    assert items[0]["signer"] == "Microsoft Windows"
    assert items[0]["signer_cache_hit"] is True
    assert client.last_verify_paths == [r"C:\Windows\System32\spoolsv.exe"]


async def test_svc_rejects_kernel_name(tmp_path) -> None:
    client = _FakeSvcClient()
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)
    body = await _call_tool(server, "svc_manage",
                             {"action": "list", "name": "lab2.kernel"})
    assert body.get("ok") is False
    err = body.get("error") or {}
    assert err.get("kind") == "bad_arg"
    assert client.last_list_kw is None


async def test_svc_get_requires_name(tmp_path) -> None:
    client = _FakeSvcClient()
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)
    body = await _call_tool(server, "svc_manage", {"action": "get"})
    assert body.get("ok") is False
    err = body.get("error") or {}
    assert err.get("kind") == "bad_arg"


async def test_svc_drivers_coerces_kind(tmp_path) -> None:
    drivers = [
        {"name": "disk", "image_path": r"C:\Windows\System32\drivers\disk.sys",
         "service_type": "driver", "state": "RUNNING"},
    ]
    client = _FakeSvcClient(drivers=drivers)
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)
    body = await _call_tool(server, "svc_manage",
                             {"action": "drivers", "limit": 10})
    assert body.get("ok") is True
    items = (body.get("data") or {}).get("items") or []
    assert items[0]["kind"] == "driver"


async def test_svc_actions_lists_verbs(tmp_path) -> None:
    client = _FakeSvcClient()
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)
    body = await _call_tool(server, "svc_manage", {"action": "actions"})
    data = body.get("data") or {}
    verbs = set((data.get("actions") or {}).keys())
    for v in ("list", "get", "dependencies", "drivers", "actions"):
        assert v in verbs, f"missing verb {v!r} in {verbs}"
