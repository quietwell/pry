"""debug_manage state loop + set_regs zero round-trip.

Covers the Agent 6 scope from
``an internal plan``:

- ``set_regs(rax=0)`` round-trips 0 (B1, no more silent zero-skip).
- ``debug_manage(action='run', timeout_s=1)`` on a busy session
  returns ``{ok:true, state:{timed_out:true}}`` (never a gRPC
  deadline).
- ``debug_manage(action='status')`` on an inactive session returns
  ``state.active=false``.
- ``DEBUG_ACTIONS`` exposes the verbs (``run``, ``wait``,
  ``pause``, ``status``, ``modules``, ``disasm``, ``resolve``, ...).

The tests lean on a hand-written fake ``AgentClient`` that implements
the Agent 5 contract: every mutating wrapper returns a dict with a
``state`` key. We never open a gRPC channel.
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
# Fake Agent 5 client
# --------------------------------------------------------------------------- #


class _FakeAgentClient:
    """Fakes just enough of the Agent 5 debug/bp wrapper surface to
    exercise the MCP dispatch and the state echo."""

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.events = object()  # non-None so Agent 5-dependent branches don't wedge
        # In-memory session; mutating wrappers mutate this + echo the
        # resulting StopInfo on their response.
        self._session = {
            "active": False,
            "stopped": False,
            "seq": 0,
            "regs": {"rax": 0, "rcx": 0, "rdx": 0, "rip": 0, "rflags": 0},
        }
        # So test-side introspection can tweak "the next run times out"
        # independently from everything else.
        self.next_run_times_out = False

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.3"}

    def recent_ops(self, limit: int = 32):
        return []

    # Helper: build a StopInfo snapshot for the current session.
    def _state(self, stopped: bool | None = None,
               reason: str = "", timed_out: bool = False,
               **extra: Any) -> dict[str, Any]:
        self._session["seq"] += 1
        state: dict[str, Any] = {
            "active": self._session["active"],
            "stopped": bool(self._session["stopped"] if stopped is None
                            else stopped),
            "timed_out": timed_out,
            "pid": self._session.get("pid", 0),
            "tid": self._session.get("tid", 0),
            "rip": hex(self._session.get("rip", 0)),
            "symbol": self._session.get("symbol", ""),
            "stop_reason": reason or self._session.get("stop_reason", "none"),
            "seq": self._session["seq"],
            "arch": "x64",
            "exception_code": 0,
            "first_chance": False,
            "bp_id": 0,
        }
        state.update(extra)
        return state

    # ------------------------------------------------------------------ Debug

    async def debug_launch(self, cmdline: str, workdir: str = "",
                           break_on_entry: bool = True,
                           monitor: bool = False) -> dict[str, Any]:
        self._session.update(active=True, stopped=True,
                             pid=4321, tid=5678, rip=0x140001000,
                             stop_reason="launch", monitor=monitor)
        return {"ok": True, "pid": 4321, "tid": 5678,
                "state": self._state(reason="launch")}

    async def debug_attach(self, pid: int,
                           monitor: bool = False) -> dict[str, Any]:
        self._session.update(active=True, stopped=True, pid=pid,
                             stop_reason="attach", monitor=monitor)
        return {"ok": True, "state": self._state(reason="attach")}

    async def debug_detach(self, kill: bool = False) -> dict[str, Any]:
        self._session.update(active=False, stopped=False,
                             stop_reason="none")
        return {"ok": True, "state": {"active": False, "stopped": False,
                                      "timed_out": False,
                                      "seq": self._session["seq"] + 1}}

    # the MCP wait-family dispatchers now thread
    # `include_context` through every wrapper, so the fake has to
    # accept (and ignore, in the generic stub) the kwarg. Subclasses in
    # other test modules override and observe it.
    async def debug_continue(self, *, include_context: bool = False) -> dict[str, Any]:
        self._session.update(stopped=False)
        return {"ok": True, "state": self._state(reason="none",
                                                  stopped=False)}

    async def debug_step(self, over: bool = False,
                         count: int = 1, *,
                         include_context: bool = False) -> dict[str, Any]:
        self._session.update(stopped=True, stop_reason="step")
        return {"ok": True, "state": self._state(reason="step")}

    async def debug_step_out(self, timeout_ms: int, *,
                             include_context: bool = False) -> dict[str, Any]:
        self._session.update(stopped=True, stop_reason="step")
        return {"ok": True, "state": self._state(reason="step")}

    async def debug_run(self, timeout_ms: int, *,
                        include_context: bool = False) -> dict[str, Any]:
        if self.next_run_times_out:
            self._session.update(stopped=False)
            return {"ok": True, "state": self._state(reason="none",
                                                     stopped=False,
                                                     timed_out=True)}
        self._session.update(stopped=True, stop_reason="bp_sw")
        return {"ok": True, "state": self._state(reason="bp_sw",
                                                 bp_id=3)}

    async def debug_run_to(self, address: int,
                           timeout_ms: int, *,
                           include_context: bool = False) -> dict[str, Any]:
        self._session.update(stopped=True, rip=address,
                             stop_reason="bp_sw")
        return {"ok": True, "state": self._state(reason="bp_sw",
                                                 bp_id=99)}

    async def debug_wait(self, timeout_ms: int, *,
                         include_context: bool = False) -> dict[str, Any]:
        self._session.update(stopped=True, stop_reason="bp_sw")
        return {"ok": True, "state": self._state(reason="bp_sw")}

    async def debug_pause(self, timeout_ms: int, *,
                          include_context: bool = False) -> dict[str, Any]:
        self._session.update(stopped=True, stop_reason="pause")
        return {"ok": True, "state": self._state(reason="pause")}

    async def debug_status(self, *,
                           include_context: bool = False) -> dict[str, Any]:
        if not self._session["active"]:
            return {"ok": True, "state": {"active": False,
                                           "stopped": False,
                                           "timed_out": False,
                                           "seq": self._session["seq"]}}
        return {"ok": True, "state": self._state()}

    async def debug_regs(self) -> dict[str, Any]:
        return dict(self._session["regs"])

    async def debug_set_regs(self, **kwargs: Any) -> dict[str, Any]:
        """Mirror B1's fix: every provided GPR is written, including 0."""
        for k, v in kwargs.items():
            if k in self._session["regs"]:
                self._session["regs"][k] = (int(v, 16) if isinstance(v, str)
                                            and v.startswith("0x")
                                            else int(v))
        return {"ok": True, "state": self._state()}

    async def debug_threads(self) -> dict[str, Any]:
        return {"current_tid": self._session.get("tid", 0),
                "threads": []}

    async def debug_stacktrace(self, max_frames: int = 32) -> list:
        return []

    async def debug_read(self, address: int, size: int) -> bytes:
        return b""

    async def debug_write(self, address: int, data: bytes) -> dict[str, Any]:
        return {"ok": True, "state": self._state()}

    async def debug_regions(self, pid: int = 0, *,
                            limit: int = 0, offset: int = 0) -> list:
        return []

    async def debug_disasm(self, address: int, count: int) -> dict[str, Any]:
        return {"ok": True, "lines": [
            {"address": address + 2 * i, "bytes_hex": "90",
             "text": f"nop  ; {i}"} for i in range(count)]}

    async def debug_resolve(self, symbol: str) -> dict[str, Any]:
        return {"ok": True, "address": 0x140001000,
                "canonical": symbol or "mod!sym"}

    async def debug_dump(self, path: str, kind: str) -> dict[str, Any]:
        return {"ok": True, "path": path, "bytes": 4096}

    async def debug_modules(self) -> list[dict[str, Any]]:
        return [{"base": 0x140000000, "size": 0x4000,
                 "name": "victim.exe", "path": r"C:\lab\victim.exe",
                 "timestamp": 0, "loaded": True}]

    async def debug_exception(self, code: int, action: str) -> dict[str, Any]:
        return {"ok": True}

    async def debug_cmd(self, command: str) -> dict[str, Any]:
        if command == ".detach":
            self._session.update(active=False, stopped=False)
            return {"ok": True, "output": "ModLoad: ... .detach\n",
                    "state": {"active": False, "stopped": False,
                              "timed_out": False,
                              "seq": self._session["seq"] + 1}}
        return {"ok": True, "output": f"<{command}>",
                "state": self._state()}

    async def dbg_cmd(self, command: str) -> str:
        """Legacy string-returning path (kept for older call sites)."""
        out = await self.debug_cmd(command)
        return out["output"]

    async def debug_events(self, from_seq: int = 0):
        if False:
            yield {}
        return

    # ---------------------------------------------------------------- Memory
    # Enough to keep require_client / mem_processes happy.

    async def mem_processes(self):
        return []


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


async def _server(tmp_path, monkeypatch,
                  client_cls=_FakeAgentClient):
    monkeypatch.setattr("pry.session.AgentClient", client_cls)
    monkeypatch.setattr("pry.mcp.tools.AgentClient", client_cls)

    async def _noop_probe(host: str, port: int,
                          timeout_s: float = 3.0) -> None:
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
        return body
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    # state is attached directly under data (via _attach_state); the
    # envelope's finalize carries it through.
    if isinstance(body.get("data"), dict) and "state" in body["data"]:
        merged["state"] = body["data"]["state"]
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


async def _connect(server) -> None:
    body = await _call(server, "target_manage", {"action": "connect"})
    assert body.get("ok") is not False, body


# --------------------------------------------------------------------------- #
# Enum coverage
# --------------------------------------------------------------------------- #


async def test_debug_actions_enum_has_state_loop_verbs(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    tools = {t.name: t for t in await server.list_tools()}
    enum = set(tools["debug_manage"].parameters["properties"]["action"]["enum"])
    for verb in ("run", "wait", "pause", "status", "run_to", "step_out",
                 "disasm", "resolve", "dump", "modules", "exception"):
        assert verb in enum, f"debug_manage missing {verb}"


# --------------------------------------------------------------------------- #
# Zero round-trip (B1)
# --------------------------------------------------------------------------- #


async def test_set_regs_rax_zero_round_trips(tmp_path, monkeypatch):
    """B1 — Writing rax=0 via set_regs must actually clear rax.

    Previously the agent's `if (vals[i] && ...)` skipped SetValue when
    the value was 0, so `set_regs(rax=0)` was a silent no-op. The fake
    client above mirrors the fix: every provided GPR is applied. The
    round-trip assertion is the test."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)

    launch = await _call(server, "debug_manage",
                         {"action": "launch",
                          "cmdline": r"C:\lab\victim.exe"})
    assert launch.get("ok") is not False, launch

    # Seed rax to something non-zero via set_regs first so the test
    # actually proves zero-write works (not "it was 0 already").
    await _call(server, "debug_manage",
                {"action": "set_regs",
                 "regs_json": _json.dumps({"rax": "0xdeadbeef"})})
    regs = await _call(server, "debug_manage", {"action": "regs"})
    assert regs.get("rax") in ("0xdeadbeef", 0xDEADBEEF), regs

    # The actual B1 check.
    await _call(server, "debug_manage",
                {"action": "set_regs",
                 "regs_json": _json.dumps({"rax": "0x0"})})
    regs = await _call(server, "debug_manage", {"action": "regs"})
    assert regs.get("rax") in ("0x0", 0), regs


# --------------------------------------------------------------------------- #
# 30s cap + timed_out surface
# --------------------------------------------------------------------------- #


async def test_run_timed_out_envelope(tmp_path, monkeypatch):
    """run on a busy session: the agent reports timed_out=True; the MCP
    envelope stays ok=True with state.timed_out=True. Never a gRPC
    DEADLINE_EXCEEDED."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    await _call(server, "debug_manage",
                {"action": "launch",
                 "cmdline": r"C:\lab\victim.exe"})
    c = ctx.session.clients[ctx.session.primary]
    c.next_run_times_out = True
    body = await _call(server, "debug_manage",
                       {"action": "run", "timeout_s": 1})
    assert body.get("ok") is not False, body
    state = body.get("state") or {}
    assert state.get("timed_out") is True, body
    assert state.get("stopped") is False, body


# --------------------------------------------------------------------------- #
# status on an inactive session
# --------------------------------------------------------------------------- #


async def test_status_inactive_session_reports_dead(tmp_path, monkeypatch):
    """`debug_manage(action='status')` on a never-launched session
    returns `state.active=false` without an error. Pure read, no gate."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "debug_manage", {"action": "status"})
    assert body.get("ok") is not False, body
    state = body.get("state") or {}
    assert state.get("active") is False, body
    assert state.get("stopped") is False, body


# --------------------------------------------------------------------------- #
# cmd state echo (B8)
# --------------------------------------------------------------------------- #


async def test_cmd_detach_echoes_inactive_state(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    await _call(server, "debug_manage",
                {"action": "launch",
                 "cmdline": r"C:\lab\victim.exe"})
    body = await _call(server, "debug_manage",
                       {"action": "cmd", "command": ".detach"})
    assert body.get("ok") is not False, body
    state = body.get("state") or {}
    assert state.get("active") is False, body
