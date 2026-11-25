"""SI adoption feature #6 — handle_dup / handle_close / handle_compare.

Covers the orchestrator-side wire for the three new memory_manage actions:
registration, action-help blurbs, dispatcher argument wiring, and the
graceful degrade when the agent is older (no HandleOps stub).

The driver-side kernel implementation (PryHandleDuplicate etc.) is
tested end-to-end on `lab2` via `drv_exerciser`; here we only cover the
orchestrator contract so the full suite stays driver-free.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import re

import pytest

from pry.mcp.tools.mem import _MEMORY_ACTIONS_MASTER
from pry.mcp.tools.mem._action_help import _MEMORY_ACTION_HELP
from pry.mcp.tools.mem import handle_ops as _handle_ops


def test_handle_actions_registered() -> None:
    for a in ("handle_dup", "handle_close", "handle_compare"):
        assert a in _MEMORY_ACTIONS_MASTER, f"missing memory_manage action {a!r}"


def test_handle_actions_have_help() -> None:
    for a in ("handle_dup", "handle_close", "handle_compare"):
        row = _MEMORY_ACTION_HELP[a]
        assert "SI #6" in row["one_liner"], row
        assert a in row["example"]


# ---- degrade on an older agent -----------------------------------


class _StubNoHandleOps:
    """A client whose handle_* RPC wrappers are absent — mirrors an
    older agent whose generated proto bindings don't carry the
    HandleOps service.
    """
    # intentionally no handle_dup / handle_close_remote / handle_compare


def _run(coro):
    return asyncio.run(coro)


def test_handle_dup_agent_missing_surfaces_clean_error() -> None:
    out = _run(_handle_ops.handle_handle_dup(
        ctx=None, c=_StubNoHandleOps(),
        src_pid=1234, src_handle=0x1a4,
        desired_access=0x120089, options=0, privilege_cookie=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "agent_version"
    assert "HandleOps service missing" in r["error"]


def test_handle_close_agent_missing_surfaces_clean_error() -> None:
    out = _run(_handle_ops.handle_handle_close(
        ctx=None, c=_StubNoHandleOps(),
        target_pid=1234, target_handle=0x1a4, privilege_cookie=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "agent_version"


def test_handle_compare_agent_missing_surfaces_clean_error() -> None:
    out = _run(_handle_ops.handle_handle_compare(
        ctx=None, c=_StubNoHandleOps(),
        pid_a=1234, handle_a=0x1a4, pid_b=5678, handle_b=0x1a4,
        privilege_cookie=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "agent_version"


# ---- happy path forwarding --------------------------------------------------


class _StubHandleOps:
    """Minimal fake exercising the forwarding path."""

    def __init__(self) -> None:
        self.last_dup: dict | None = None
        self.last_close: dict | None = None
        self.last_cmp: dict | None = None

    async def handle_dup(self, **kw):
        self.last_dup = dict(kw)
        return {
            "ok": True, "error": None,
            "new_handle": 0xBEEF, "object_addr": 0xFFFFFA8000112233,
            "granted_access": 0x120089, "type_index": 7,
            "type_name": "File",
        }

    async def handle_close_remote(self, **kw):
        self.last_close = dict(kw)
        return {"ok": True, "error": None}

    async def handle_compare(self, **kw):
        self.last_cmp = dict(kw)
        return {
            "ok": True, "error": None, "same": True,
            "object_a": 0xFFFFFA8000112233, "object_b": 0xFFFFFA8000112233,
            "type_index_a": 7, "type_index_b": 7,
        }


def test_handle_dup_forwards_kwargs() -> None:
    stub = _StubHandleOps()
    out = _run(_handle_ops.handle_handle_dup(
        ctx=None, c=stub, src_pid=1234, src_handle=0x1a4,
        desired_access=0x120089, options=1, privilege_cookie=0xDEADBEEF,
    ))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["new_handle"] == 0xBEEF
    assert r["type_name"] == "File"
    assert stub.last_dup == {
        "src_pid": 1234, "src_handle": 0x1a4,
        "desired_access": 0x120089, "options": 1,
        "privilege_cookie": 0xDEADBEEF,
    }


def test_handle_close_forwards_kwargs() -> None:
    stub = _StubHandleOps()
    out = _run(_handle_ops.handle_handle_close(
        ctx=None, c=stub, target_pid=1234, target_handle=0x1a4,
        privilege_cookie=0xDEADBEEF,
    ))
    r = json.loads(out)
    assert r["ok"] is True
    assert stub.last_close == {
        "target_pid": 1234, "target_handle": 0x1a4,
        "privilege_cookie": 0xDEADBEEF,
    }


def test_handle_compare_forwards_kwargs() -> None:
    stub = _StubHandleOps()
    out = _run(_handle_ops.handle_handle_compare(
        ctx=None, c=stub, pid_a=1234, handle_a=0x1a4,
        pid_b=5678, handle_b=0x1b8, privilege_cookie=0,
    ))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["same"] is True
    assert stub.last_cmp == {
        "pid_a": 1234, "handle_a": 0x1a4,
        "pid_b": 5678, "handle_b": 0x1b8,
        "privilege_cookie": 0,
    }


# ---- input validation -------------------------------------------------------


def test_handle_dup_rejects_zero_pid() -> None:
    out = _run(_handle_ops.handle_handle_dup(
        ctx=None, c=_StubHandleOps(), src_pid=0, src_handle=0x1a4,
        desired_access=0, options=0, privilege_cookie=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert "src_pid" in r["error"]


def test_handle_dup_rejects_zero_handle() -> None:
    out = _run(_handle_ops.handle_handle_dup(
        ctx=None, c=_StubHandleOps(), src_pid=1234, src_handle=0,
        desired_access=0, options=0, privilege_cookie=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert "src_handle" in r["error"]


def test_handle_compare_rejects_missing_second_pair() -> None:
    out = _run(_handle_ops.handle_handle_compare(
        ctx=None, c=_StubHandleOps(), pid_a=1234, handle_a=0x1a4,
        pid_b=0, handle_b=0x1a4, privilege_cookie=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False


# ---- ABI header gate --------------------------------------------------------


def test_abi_proc_header_defines_handle_ops_codes() -> None:
    """Guards against a parallel-agent revert of comm/abi/proc.h — the
    SI #6 handle_ops bundle ships three new IOCTL function codes in
    the 0x8D0..0x8FF reserved band."""
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "comm" / "abi" / "proc.h").read_text(encoding="utf-8")
    for sym, code in (
        ("PRY_FUNC_HANDLE_DUP", 0x8E2),
        ("PRY_FUNC_HANDLE_CLOSE_REMOTE", 0x8E3),
        ("PRY_FUNC_HANDLE_COMPARE", 0x8E4),
    ):
        m = re.search(rf"#define\s+{sym}\s+0x([0-9A-Fa-f]+)", txt)
        assert m, f"{sym} missing from comm/abi/proc.h"
        assert int(m.group(1), 16) == code, (
            f"{sym} must be 0x{code:X} (got 0x{m.group(1)})")


def test_abi_proc_header_defines_handle_ops_structs() -> None:
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "comm" / "abi" / "proc.h").read_text(encoding="utf-8")
    for sym in ("PRY_HANDLE_DUP_IN", "PRY_HANDLE_DUP_OUT",
                "PRY_HANDLE_CLOSE_IN", "PRY_HANDLE_CLOSE_OUT",
                "PRY_HANDLE_CMP_IN", "PRY_HANDLE_CMP_OUT"):
        assert sym in txt, f"{sym} missing from comm/abi/proc.h"


def test_proto_file_carries_handle_ops_messages() -> None:
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "proto" / "pry.proto").read_text(encoding="utf-8")
    for sym in ("message HandleDupRequest",
                "message HandleDupResponse",
                "message HandleCloseRemoteRequest",
                "message HandleCloseRemoteResponse",
                "message HandleCompareRequest",
                "message HandleCompareResponse",
                "service HandleOps"):
        assert sym in txt, f"{sym!r} missing from proto/pry.proto"
