"""Unit tests for net_manage.

Covers the orchestrator layer: happy-path ``list`` row shape, umagent-only
guard on ``.kernel`` suffix, and the ``kill`` gate refusal when
``security.allow_kill_connection=False``. The umagent C++ side is
exercised separately in the parity / smoketest harnesses.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP

from pry.config import PryConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.mcp.tools import Context
from pry.mcp.tools import net as net_tool
from pry.mcp.tools.net import _is_kernel_name, _list_row
from pry.session import Session


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeNetClient:
    """Satisfies the NetMixin surface the net_manage tool consumes.

    ``network`` is set to a sentinel so ``_net_missing`` short-circuits
    do not fire; every ``net_*`` coroutine returns a canned dict.
    """

    def __init__(self, *, list_rows=None, interfaces=None, stats=None,
                 kill_ok=True, kill_killed=True, kill_error=""):
        self.network = object()  # sentinel: NetMixin stub is "present"
        self.services = None
        self._list_rows = list_rows or []
        self._interfaces = interfaces or []
        self._stats = stats or []
        self._kill_ok = kill_ok
        self._kill_killed = kill_killed
        self._kill_error = kill_error
        self.last_list_kw: dict[str, Any] | None = None
        self.last_kill_kw: dict[str, Any] | None = None

    async def net_list(self, **kw):
        self.last_list_kw = kw
        return {
            "ok": True, "items": list(self._list_rows),
            "total": len(self._list_rows),
            "truncated": False,
            "dns_cache_hits": 0, "dns_cache_misses": 0, "dns_cache_size": 0,
        }

    async def net_interfaces(self, **kw):
        return {"ok": True, "items": list(self._interfaces)}

    async def net_stats(self, **kw):
        return {"ok": True, "counters": list(self._stats)}

    async def net_kill(self, **kw):
        self.last_kill_kw = kw
        return {"ok": self._kill_ok, "error": self._kill_error,
                "killed": self._kill_killed}


class _FakeSession:
    """Minimal Session shim: single-view, name-agnostic require_client."""

    def __init__(self, client: _FakeNetClient, *,
                 reject_kernel: bool = True) -> None:
        self._client = client
        self._reject_kernel = reject_kernel
        self.clients = {"lab.user": client}
        self.primary = "lab.user"

    def resolve_view_name(self, name: str = "", client_id: str = "") -> str:
        n = (name or "").strip().lower()
        if n.endswith(".kernel") and self._reject_kernel:
            return n
        if n and n != "lab.user":
            return n or "lab.user"
        return "lab.user"

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


def _mk_ctx(tmp_path: Path, client: _FakeNetClient, *,
             allow_kill: bool = False) -> Context:
    cfg = PryConfig()
    cfg.security.allow_kill_connection = allow_kill
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = _FakeSession(client)
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
    mcp = FastMCP("pry-net-test")
    net_tool.register(mcp, ctx)
    return mcp


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_is_kernel_name_matches_suffix() -> None:
    assert _is_kernel_name("lab2.kernel") is True
    assert _is_kernel_name("DESKTOP-ABC.kernel") is True
    assert _is_kernel_name("kernel") is True
    assert _is_kernel_name("Kernel") is True  # case-insensitive


def test_is_kernel_name_rejects_user_views() -> None:
    assert _is_kernel_name("lab2.user") is False
    assert _is_kernel_name("") is False
    assert _is_kernel_name("mykernel.user") is False
    assert _is_kernel_name("user") is False


def test_list_row_compact_dropped_fields() -> None:
    r = {
        "proto": "tcp", "family": "v4", "pid": 1234, "process": "chrome.exe",
        "state": "ESTABLISHED", "local": "10.0.0.5:49231",
        "remote": "93.184.216.34:443",
        "service_tag": "", "remote_host": "edge.example.com",
        "create_time_ms": 7000, "offload": "", "owning_module_names": ["chrome.dll"],
        "scope_id_local": 0, "scope_id_remote": 0,
    }
    compact = _list_row(r, verbosity="compact")
    assert "create_time_ms" not in compact
    assert "owning_module_names" not in compact
    assert compact["process"] == "chrome.exe"
    assert compact["remote_host"] == "edge.example.com"


def test_list_row_normal_keeps_module_names() -> None:
    r = {"proto": "tcp", "family": "v4", "pid": 1, "process": "p",
         "state": "", "local": "", "remote": "", "service_tag": "",
         "remote_host": "", "create_time_ms": 42,
         "owning_module_names": ["a.dll"],
         "offload": "", "scope_id_local": 0, "scope_id_remote": 0}
    normal = _list_row(r, verbosity="normal")
    assert normal["create_time_ms"] == 42
    assert normal["owning_module_names"] == ["a.dll"]
    assert "scope_id_local" not in normal


def test_list_row_full_adds_scope_ids() -> None:
    r = {"proto": "tcp", "family": "v6", "pid": 1, "process": "p",
         "state": "", "local": "", "remote": "", "service_tag": "",
         "remote_host": "", "create_time_ms": 0,
         "owning_module_names": [], "offload": "",
         "scope_id_local": 5, "scope_id_remote": 9}
    full = _list_row(r, verbosity="full")
    assert full["scope_id_local"] == 5
    assert full["scope_id_remote"] == 9


# ---------------------------------------------------------------------------
# Handler integration
# ---------------------------------------------------------------------------


async def test_net_list_happy_path(tmp_path, request) -> None:
    rows = [
        {"proto": "tcp", "family": "v4", "pid": 1234, "process": "svchost.exe",
         "state": "LISTEN", "local": "0.0.0.0:135", "remote": "",
         "service_tag": "RpcSs", "remote_host": "",
         "create_time_ms": 10, "offload": "", "scope_id_local": 0,
         "scope_id_remote": 0, "owning_module_names": []},
    ]
    client = _FakeNetClient(list_rows=rows)
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)
    body = await _call_tool(server, "net_manage",
                             {"action": "list", "limit": 10})
    assert body.get("ok") is True
    data = body.get("data") or {}
    assert data.get("items")
    assert data["items"][0]["service_tag"] == "RpcSs"
    assert data["items"][0]["state"] == "LISTEN"
    # Umagent-only guard didn't fire.
    assert client.last_list_kw is not None
    assert client.last_list_kw["limit"] == 10


async def test_net_rejects_kernel_name(tmp_path) -> None:
    client = _FakeNetClient()
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)
    body = await _call_tool(server, "net_manage",
                             {"action": "list", "name": "lab2.kernel"})
    assert body.get("ok") is False
    err = body.get("error") or {}
    assert err.get("kind") == "bad_arg"
    # The guard should fire before net_list touches the client.
    assert client.last_list_kw is None


async def test_net_kill_gate_default_off(tmp_path) -> None:
    client = _FakeNetClient()
    ctx = _mk_ctx(tmp_path, client, allow_kill=False)
    server = _build(ctx)
    body = await _call_tool(server, "net_manage", {
        "action": "kill",
        "local": "10.0.0.5:49231", "remote": "93.184.216.34:443",
    })
    assert body.get("ok") is False
    err = body.get("error") or {}
    assert err.get("kind") == "not_allowed"
    # Agent client never saw the call.
    assert client.last_kill_kw is None


async def test_net_kill_gate_on_requires_endpoints(tmp_path) -> None:
    client = _FakeNetClient()
    ctx = _mk_ctx(tmp_path, client, allow_kill=True)
    server = _build(ctx)
    body = await _call_tool(server, "net_manage",
                             {"action": "kill", "local": "", "remote": ""})
    assert body.get("ok") is False
    err = body.get("error") or {}
    assert err.get("kind") == "bad_arg"


async def test_net_kill_gate_on_fires_rpc(tmp_path) -> None:
    client = _FakeNetClient(kill_ok=True, kill_killed=True)
    ctx = _mk_ctx(tmp_path, client, allow_kill=True)
    server = _build(ctx)
    body = await _call_tool(server, "net_manage", {
        "action": "kill",
        "local": "10.0.0.5:49231", "remote": "93.184.216.34:443",
    })
    assert body.get("ok") is True
    data = body.get("data") or {}
    assert data.get("killed") is True
    assert client.last_kill_kw == {
        "local": "10.0.0.5:49231",
        "remote": "93.184.216.34:443",
        "state_hint": "ESTABLISHED",
    }


async def test_net_actions_lists_verbs(tmp_path) -> None:
    client = _FakeNetClient()
    ctx = _mk_ctx(tmp_path, client)
    server = _build(ctx)
    body = await _call_tool(server, "net_manage", {"action": "actions"})
    data = body.get("data") or {}
    verbs = set((data.get("actions") or {}).keys())
    # Must include every real verb plus the actions self-reference.
    for v in ("list", "interfaces", "stats", "kill", "actions"):
        assert v in verbs, f"missing verb {v!r} in {verbs}"
