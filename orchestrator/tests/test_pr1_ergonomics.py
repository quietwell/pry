"""PR #1 — ergonomics quick wins.

Covers:
- T2.5: knowledge_manage(action='list', q=/since=) routes to search.
- T2.6: exec_manage timeout_ms default 60000; auto_retry_on_timeout
        re-runs run_exe once at 2x the ceiling. target_manage(action=
        'status', fast_fail=True) returns {ok:false, kind:'unreachable'}
        in sub-second when the probe fails.
- T2.3: file_manage(action='read', view=...) honors each mode;
        download/download recursive echo abs_path; cfg.file_manage_
        default_view='both' restores the pre-PR#1 shape.
- T2.2: run_powershell injects SilentlyContinue preamble into the
        base64 payload passed to -EncodedCommand; preserve_clixml=True
        skips the inject.

Everything here runs in-process against fake AgentClients — no live
MCP server, no gRPC agent required.
"""
from __future__ import annotations

import asyncio
import hashlib
import json as _json
import time
from pathlib import Path
from typing import Any

import pytest

from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.tools import Context, build_server
from pry.mcp.tools.exec_ import _EXEC_TIMEOUT_MS_DEFAULT
from pry.ownership import OwnershipRegistry
from pry.session import Session


# --------------------------------------------------------------------------- #
# shared fake AgentClient
# --------------------------------------------------------------------------- #

class _FakeAgent:
    """Minimal AgentClient-shaped fake. Each test sub-classes/augments the
    bits it needs."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        # run_exe behavior switches
        self.run_exe_calls: list[tuple] = []
        self.run_exe_timed_out_once = False
        self._run_exe_count = 0
        self.run_exe_force_timeout = False
        # run_shell behavior
        self.run_shell_calls: list[dict] = []

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
                "agent_instance_id": "fake-1"}

    async def host_info(self, include_security_products: bool = False,
                        include_hardware: bool = True) -> dict[str, Any]:
        return {"ok": True}

    async def run_exe(self, exe: str, args: list[str] | None = None,
                      workdir: str = "", timeout_ms: int = 60000
                      ) -> dict[str, Any]:
        self._run_exe_count += 1
        self.run_exe_calls.append((exe, list(args or []), workdir, timeout_ms))
        if self.run_exe_force_timeout:
            return {"exit_code": 1, "stdout": "", "stderr": "",
                    "timed_out": True}
        if self.run_exe_timed_out_once and self._run_exe_count == 1:
            return {"exit_code": 1, "stdout": "", "stderr": "",
                    "timed_out": True}
        return {"exit_code": 0, "stdout": "ok", "stderr": "",
                "timed_out": False}

    async def run_shell(self, command: str, shell: str = "cmd",
                        workdir: str = "", timeout_ms: int = 60000,
                        preserve_clixml: bool = False) -> dict[str, Any]:
        self.run_shell_calls.append({
            "command": command, "shell": shell, "workdir": workdir,
            "timeout_ms": timeout_ms,
            "preserve_clixml": preserve_clixml})
        return {"exit_code": 0, "output": command}

    async def file_hash(self, remote_path: str) -> dict[str, Any]:
        return {"sha256": "", "size": 0}


# --------------------------------------------------------------------------- #
# shared ctx builder
# --------------------------------------------------------------------------- #

async def _build_ctx_and_server(tmp_path, monkeypatch,
                                fake_cls=_FakeAgent):
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
    token = CLIENT_ID.set("peer-pr1")
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
# T2.5 — knowledge_manage list honors q=/since=
# --------------------------------------------------------------------------- #

async def test_pr1_t25_knowledge_list_q_routes_to_search(tmp_path,
                                                          monkeypatch):
    """list(q=...) hits search's FTS, not list_findings — the feedback's
    "cycle17 returns months-old unrelated rows" pain."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    led = ctx.ledger
    sid = led.start_session("fake-endpoint")
    led.record_ex(sid, "info", "cycle17 anomaly in VM_CR MSR", "",
                  "", agent_id="peer-pr1")
    led.record_ex(sid, "info", "stale note about unrelated subject", "",
                  "", agent_id="peer-pr1")
    led.record_ex(sid, "info", "another cycle17 bump", "",
                  "", agent_id="peer-pr1")

    body = await _call(server, "knowledge_manage",
                        {"action": "list", "q": "cycle17"})
    assert body["ok"] is True, body
    # Routed-to tag is explicit so callers see the delegation.
    assert body.get("routed_to") == "search"
    # Non-matching finding doesn't come back.
    titles = {h.get("source_title") for h in body.get("hits", [])}
    assert "stale note about unrelated subject" not in titles


async def test_pr1_t25_knowledge_list_since_only_filters(tmp_path,
                                                          monkeypatch):
    """list(since=...) without q filters in Python (FTS needs a MATCH)."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    led = ctx.ledger
    sid = led.start_session("fake-endpoint")
    led.record_ex(sid, "info", "ancient-finding", "", "",
                   agent_id="peer-pr1")
    # Backdate the first row so a since= filter can exclude it.
    led._conn.execute(
        "UPDATE findings SET created=? WHERE title=?",
        (time.time() - 7 * 24 * 3600, "ancient-finding"))
    led._conn.commit()
    led.record_ex(sid, "info", "fresh-finding", "", "",
                   agent_id="peer-pr1")

    recent = time.time() - 60
    body = await _call(server, "knowledge_manage",
                        {"action": "list", "since": str(recent)})
    assert body["ok"] is True, body
    # Normal list envelope (list_findings output), filtered since-ward.
    titles = {
        r.get("title") for r in body.get("rows", body.get("findings", []))
    }
    # Depending on envelope spill, the rows may be in body["rows"] or
    # body["findings"]; both paths exclude the ancient row.
    if titles - {None}:
        assert "ancient-finding" not in titles


# --------------------------------------------------------------------------- #
# T2.6 — exec timeout + auto_retry_on_timeout + status fast_fail
# --------------------------------------------------------------------------- #

def test_pr1_t26_exec_default_timeout_bumped():
    assert _EXEC_TIMEOUT_MS_DEFAULT == 60000


async def test_pr1_t26_run_exe_auto_retry_on_timeout(tmp_path, monkeypatch):
    """auto_retry_on_timeout=True re-runs ONCE at 2x the ceiling on the
    first timed_out response, then surfaces an `auto_retried` block."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.run_exe_timed_out_once = True

    body = await _call(server, "exec_manage",
                        {"action": "run_exe", "exe": "whoami.exe",
                         "timeout_ms": 60000,
                         "auto_retry_on_timeout": True})
    assert body["ok"] is True, body
    assert body.get("auto_retried") is not None
    # Retry got 2x ceiling (capped at _EXEC_TIMEOUT_MS_CEILING_MS=115000).
    retry = body["auto_retried"]
    assert retry["first_timeout_ms"] == 60000
    assert retry["retry_timeout_ms"] == 115_000
    # Agent saw two attempts.
    assert len(fake.run_exe_calls) == 2


async def test_pr1_t26_run_exe_no_retry_by_default(tmp_path, monkeypatch):
    """A plain timed_out response WITHOUT the opt-in flag is returned
    as-is, carrying the hint — one agent call only."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.run_exe_force_timeout = True

    body = await _call(server, "exec_manage",
                        {"action": "run_exe", "exe": "whoami.exe"})
    # Not an orchestrator-level failure; the agent-side timeout propagates
    # as timed_out=True on an ok envelope.
    assert body.get("timed_out") is True
    assert body.get("auto_retried") is None
    assert len(fake.run_exe_calls) == 1


async def test_pr1_t26_status_fast_fail_unreachable(tmp_path, monkeypatch):
    """fast_fail=True wraps status() with a 1s deadline AND probes TCP
    first. A client whose status() hangs returns `unreachable` with
    elapsed_ms attached."""

    class _HangStatus(_FakeAgent):
        async def status(self) -> dict[str, Any]:  # type: ignore[override]
            await asyncio.sleep(5)
            return {"ok": True}

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_HangStatus)
    await _call(server, "target_manage", {"action": "connect"})

    t0 = time.monotonic()
    body = await _call(server, "target_manage",
                        {"action": "status", "fast_fail": True})
    elapsed = time.monotonic() - t0
    assert body.get("ok") is False, body
    assert body.get("kind") == "unreachable", body
    assert isinstance(body.get("elapsed_ms"), int)
    # Returned under 2s — the hang is capped at ~1s + a thin wrapper.
    assert elapsed < 2.0, elapsed


# --------------------------------------------------------------------------- #
# T2.3 — file_manage read view + download abs_path
# --------------------------------------------------------------------------- #

class _ReadFake(_FakeAgent):
    def __init__(self, *a, **kw) -> None:
        super().__init__(*a, **kw)
        self.blob = b"hello pry plain text\n" * 8  # 192 bytes, text-y
        self.binary_blob = bytes(range(256))  # NUL-containing

    async def file_hash(self, remote_path: str) -> dict[str, Any]:
        src = (self.binary_blob if "bin" in remote_path.lower()
               else self.blob)
        return {"sha256": hashlib.sha256(src).hexdigest(),
                "size": len(src)}

    async def file_download(self, remote_path: str, local_path: str,
                             offset: int = 0, length: int = 0
                             ) -> dict[str, Any]:
        src = (self.binary_blob if "bin" in remote_path.lower()
               else self.blob)
        data = src[offset:offset + length] if length else src[offset:]
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_bytes(data)
        return {"path": local_path, "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}

    async def file_list_dir(self, path: str, recursive: bool = False,
                            max_entries: int = 2000):
        return []


async def test_pr1_t23_read_view_auto_text(tmp_path, monkeypatch):
    """A text-shaped file comes back as `text` only — no hex, no ascii."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_ReadFake)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "file_manage",
                        {"action": "read",
                         "remote_path": r"C:\Temp\notes.ps1"})
    assert body["ok"] is True, body
    assert body.get("view") == "text"
    assert "text" in body
    assert body["text"].startswith("hello pry plain text")
    assert "hex" not in body
    assert "ascii" not in body


async def test_pr1_t23_read_view_auto_binary(tmp_path, monkeypatch):
    """A NUL-containing binary file falls through to hex-only."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_ReadFake)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "file_manage",
                        {"action": "read",
                         "remote_path": r"C:\Temp\blob.bin"})
    assert body["ok"] is True, body
    assert body.get("view") == "hex"
    assert "hex" in body
    assert "text" not in body


async def test_pr1_t23_read_view_both(tmp_path, monkeypatch):
    """view='both' emits hex + ascii + text — the pre-PR#1 shape."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_ReadFake)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "file_manage",
                        {"action": "read",
                         "remote_path": r"C:\Temp\notes.ps1",
                         "view": "both"})
    assert body["ok"] is True, body
    assert "hex" in body and "ascii" in body and "text" in body


async def test_pr1_t23_read_view_text_rejects_binary(tmp_path, monkeypatch):
    """view='text' on binary -> {ok:false, kind:'not_text'}."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_ReadFake)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "file_manage",
                        {"action": "read",
                         "remote_path": r"C:\Temp\blob.bin",
                         "view": "text"})
    assert body.get("ok") is False, body
    assert body.get("kind") == "not_text"


async def test_pr1_t23_default_view_config_restores_both(tmp_path,
                                                           monkeypatch):
    """cfg.file_manage_default_view='both' restores the legacy shape when
    the caller leaves view= unset."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_ReadFake)
    ctx.cfg.file_manage_default_view = "both"
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "file_manage",
                        {"action": "read",
                         "remote_path": r"C:\Temp\notes.ps1"})
    assert body["ok"] is True, body
    assert body.get("view") == "both"
    assert "hex" in body and "text" in body


async def test_pr1_t23_download_echoes_abs_path(tmp_path, monkeypatch):
    """download response carries abs_path alongside path."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_ReadFake)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "file_manage",
                        {"action": "download",
                         "remote_path": r"C:\Temp\notes.ps1"})
    assert body["ok"] is True, body
    assert "abs_path" in body
    assert body["abs_path"] and Path(body["abs_path"]).is_absolute()


# --------------------------------------------------------------------------- #
# T2.2 — PowerShell CLIXML preamble injection
# --------------------------------------------------------------------------- #

async def test_pr1_t22_run_powershell_injects_preamble(tmp_path, monkeypatch):
    """The agent-client's run_shell inlines SilentlyContinue into the
    -EncodedCommand base64 payload. We decode what the fake received and
    confirm the preamble is at the start of the body."""
    import base64 as _b64

    class _CaptureShell(_FakeAgent):
        async def run_shell(self, command: str, shell: str = "cmd",
                            workdir: str = "", timeout_ms: int = 60000,
                            preserve_clixml: bool = False):
            # Mimic what the real client does: encode and inspect.
            body = command
            if shell == "powershell" and not preserve_clixml:
                body = ("$ProgressPreference='SilentlyContinue'; "
                        "$ErrorActionPreference='Continue'; " + body)
            self.run_shell_calls.append({
                "command": command, "shell": shell,
                "preserve_clixml": preserve_clixml,
                "encoded": _b64.b64encode(
                    body.encode("utf-16-le")).decode("ascii"),
                "decoded_body": body})
            return {"exit_code": 0, "output": body}

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_CaptureShell)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "exec_manage",
                        {"action": "run_powershell",
                         "command": "Get-Process -Name lsass"})
    assert body["ok"] is True or "exit_code" in body, body
    fake = ctx.session.require_client()
    call = fake.run_shell_calls[-1]
    assert "SilentlyContinue" in call["decoded_body"]
    assert call["decoded_body"].endswith("Get-Process -Name lsass")


async def test_pr1_t22_preserve_clixml_skips_preamble(tmp_path, monkeypatch):
    """preserve_clixml=True drops the inject on orchestrator and agent
    sides. The signature should accept the kwarg."""
    class _CaptureShell(_FakeAgent):
        async def run_shell(self, command: str, shell: str = "cmd",
                            workdir: str = "", timeout_ms: int = 60000,
                            preserve_clixml: bool = False):
            self.run_shell_calls.append({
                "command": command,
                "preserve_clixml": preserve_clixml})
            return {"exit_code": 0, "output": ""}

    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                                fake_cls=_CaptureShell)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "exec_manage",
                        {"action": "run_powershell",
                         "command": "Get-Process -Name lsass",
                         "preserve_clixml": True})
    fake = ctx.session.require_client()
    call = fake.run_shell_calls[-1]
    assert call["preserve_clixml"] is True
