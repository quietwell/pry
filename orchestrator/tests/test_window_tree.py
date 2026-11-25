"""desktop_manage window_props / window_tree.

Covers the new verbs:

* ``window_props`` requires an hwnd, forwards to ``ListWindowProps`` RPC;
* ``window_tree`` roots at HWND / GetDesktopWindow() and surfaces
  depth-capped nested structure;
* ``window_by_thread`` is pure orchestrator-side regrouping of the
  existing ListWindows wire payload;
* new ``include_children`` / ``include_props`` kwargs on
  ``action='windows'`` keep the pre-slice-03 default off (base response
  shape bit-identical);
* agent_version fallthrough when the agent predates the new RPCs.
"""
from __future__ import annotations

import asyncio
import json as _json

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
    def __init__(self, *, list_windows=None, props=None, tree=None) -> None:
        self._list = list_windows
        self._props = props
        self._tree = tree
        self.list_calls: list[dict] = []
        self.last_op_ts = 0.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.endpoint = "lab:50051"

    async def list_windows(self, *, pid: int = 0, process_name: str = "",
                           query: str = "", include_hidden: bool = False,
                           include_details: bool = True,
                           include_children: bool = False,
                           include_props: bool = False):
        self.list_calls.append({
            "pid": pid, "process_name": process_name, "query": query,
            "include_hidden": include_hidden,
            "include_details": include_details,
            "include_children": include_children,
            "include_props": include_props,
        })
        return dict(self._list or {"ok": True, "total_windows": 0,
                                     "windows_json": "{}"})

    async def list_window_props(self, hwnd: int,
                                 include_values: bool = True):
        return dict(self._props or {"ok": True, "hwnd": hwnd, "props": []})

    async def get_window_tree(self, *, hwnd: int = 0, pid: int = 0,
                              max_depth: int = 12,
                              include_props: bool = False):
        return dict(self._tree or {"ok": True, "root": {"hwnd": hwnd,
                                                         "pid": pid,
                                                         "children": []}})

    def recent_ops(self, n: int):
        return []


async def _build(tmp_path, monkeypatch, client: _FakeClient):
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


async def _call(server, args) -> dict:
    token = CLIENT_ID.set("peer-win")
    try:
        result = await server.call_tool("desktop_manage", args)
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


async def test_actions_lists_new_verbs(tmp_path, monkeypatch):
    _ctx, server = await _build(tmp_path, monkeypatch, _FakeClient())
    body = await _call(server, {"action": "actions"})
    assert body["ok"] is True
    assert {"window_props", "window_tree", "window_by_thread"} <= set(body["actions"])


async def test_window_props_requires_hwnd(tmp_path, monkeypatch):
    _ctx, server = await _build(tmp_path, monkeypatch, _FakeClient())
    body = await _call(server, {"action": "window_props", "name": "user"})
    assert body.get("ok") is False
    assert body.get("kind") == "bad_arg"


async def test_window_props_round_trips_props(tmp_path, monkeypatch):
    client = _FakeClient(props={
        "ok": True, "hwnd": 0x1000,
        "props": [{"name": "FooProp", "atom": 0, "data": 0x4242}],
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "window_props",
                                 "hwnd": "0x1000", "name": "user"})
    assert body.get("ok") is True, body
    assert body["hwnd"] == 0x1000
    assert body["props"][0]["name"] == "FooProp"


async def test_window_tree_default_root_desktop(tmp_path, monkeypatch):
    client = _FakeClient(tree={
        "ok": True, "root": {"hwnd": 0, "pid": 0,
                              "children": [{"hwnd": 123, "pid": 1}]},
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "window_tree", "name": "user"})
    assert body.get("ok") is True, body
    assert body["kind"] == "window_tree"
    assert body["max_depth"] == 12
    assert body["root"]["children"][0]["hwnd"] == 123


async def test_window_by_thread_regroups(tmp_path, monkeypatch):
    """Pure orchestrator regrouping; the ListWindows RPC payload stays bit-stable."""
    # Real OS semantics: a TID is system-wide unique and lives in exactly
    # one process. Thread 20 belongs to pid=100; thread 21 belongs to
    # pid=200. The regrouping flips the hierarchy from (pid -> windows)
    # to (tid -> windows) and carries the owning pid along.
    payload = {
        "processes": [
            {"pid": 100, "process_name": "a.exe",
             "windows": [
                 {"hwnd": 1, "tid": 20, "title": "x1"},
                 {"hwnd": 2, "tid": 20, "title": "x2"},
             ]},
            {"pid": 200, "process_name": "b.exe",
             "windows": [{"hwnd": 3, "tid": 21, "title": "y1"}]},
        ],
    }
    client = _FakeClient(list_windows={
        "ok": True, "total_windows": 3,
        "windows_json": _json.dumps(payload),
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "window_by_thread", "name": "user"})
    assert body.get("ok") is True, body
    tids = {t["tid"] for t in body["threads"]}
    assert tids == {20, 21}
    tid20 = [t for t in body["threads"] if t["tid"] == 20][0]
    assert tid20["pid"] == 100
    assert len(tid20["windows"]) == 2
    assert body["total_windows"] == 3


async def test_window_by_thread_filters_tid(tmp_path, monkeypatch):
    payload = {"processes": [{"pid": 100, "process_name": "a",
                              "windows": [
                                  {"hwnd": 1, "tid": 10},
                                  {"hwnd": 2, "tid": 11},
                              ]}]}
    client = _FakeClient(list_windows={
        "ok": True, "total_windows": 2,
        "windows_json": _json.dumps(payload),
    })
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "window_by_thread",
                                 "tid": 11, "name": "user"})
    assert body["total_windows"] == 1
    assert body["threads"][0]["tid"] == 11


async def test_windows_include_kwargs_forwarded(tmp_path, monkeypatch):
    client = _FakeClient(list_windows={
        "ok": True, "total_windows": 0, "windows_json": "{}"})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "windows",
                                 "include_children": True,
                                 "include_props": True,
                                 "name": "user"})
    assert body.get("ok") is True
    assert client.list_calls[-1]["include_children"] is True
    assert client.list_calls[-1]["include_props"] is True


async def test_window_tree_agent_version(tmp_path, monkeypatch):
    client = _FakeClient(tree={
        "ok": False, "kind": "agent_version",
        "error": "get_window_tree: older agent"})
    _ctx, server = await _build(tmp_path, monkeypatch, client)
    body = await _call(server, {"action": "window_tree", "name": "user"})
    assert body.get("ok") is False
    assert body.get("kind") == "agent_version"
    assert "rebuild" in str(body.get("hint") or "")
