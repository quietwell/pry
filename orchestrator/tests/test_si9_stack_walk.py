"""SI adoption feature #9 — kernel-stack walk primitive.

Covers the orchestrator-side wire for ``memory_manage(action='stack_walk', ...)``:
registration, action-help blurb, flag/mode packing, graceful degrade when
the agent is older (no StackWalk stub), and the ABI header gate.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import re

from pry.mcp.tools.mem import _MEMORY_ACTIONS_MASTER
from pry.mcp.tools.mem._action_help import _MEMORY_ACTION_HELP
from pry.mcp.tools.mem import stack_walk as _stack_walk


def _run(coro):
    return asyncio.run(coro)


def test_stack_walk_action_registered() -> None:
    assert "stack_walk" in _MEMORY_ACTIONS_MASTER


def test_stack_walk_action_has_help() -> None:
    row = _MEMORY_ACTION_HELP["stack_walk"]
    assert "SI #9" in row["one_liner"]
    assert "stack_walk" in row["example"]
    assert "RtlWalkFrameChain" in row["one_liner"]


def test_stack_walk_mode_flag_packing() -> None:
    # Three mode selectors map to the KERNEL/USER/BOTH flag bits.
    assert _stack_walk._resolve_flags(
        mode="kernel", force_apc=False,
        timeout_partial_ok=False) == _stack_walk._FLAG_KERNEL
    assert _stack_walk._resolve_flags(
        mode="user", force_apc=False,
        timeout_partial_ok=False) == _stack_walk._FLAG_USER
    assert _stack_walk._resolve_flags(
        mode="both", force_apc=False,
        timeout_partial_ok=False) == _stack_walk._FLAG_BOTH
    # Extra flag bits OR cleanly into the base.
    flags = _stack_walk._resolve_flags(
        mode="both", force_apc=True, timeout_partial_ok=True)
    assert flags & _stack_walk._FLAG_FORCE_APC
    assert flags & _stack_walk._FLAG_TIMEOUT_PARTIAL_OK


# ---- degrade on an older agent -----------------------------------


class _StubNoStackWalk:
    pass


def test_stack_walk_agent_missing_surfaces_clean_error() -> None:
    out = _run(_stack_walk.handle_stack_walk(
        ctx=None, c=_StubNoStackWalk(), tid=1234,
        mode="both", max_frames=0, timeout_ms=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "agent_version"
    assert "StackWalk service missing" in r["error"]


# ---- happy path forwarding --------------------------------------------------


class _StubStackWalk:
    def __init__(self) -> None:
        self.last_kwargs: dict | None = None

    async def stack_walk(self, **kw):
        self.last_kwargs = dict(kw)
        return {
            "ok": True, "error": None,
            "pid": 1234, "flags": 0x1,
            "rip": 0xFFFFF80012340000, "rsp": 0xFFFFF88000000F00,
            "kernel_frames": [
                {"rip": 0xFFFFF80012340000, "module_tag": 0,
                 "module_base": 0xFFFFF80012000000},
            ],
            "user_frames": [],
        }


def test_stack_walk_default_timeout_bounded_at_500ms() -> None:
    stub = _StubStackWalk()
    out = _run(_stack_walk.handle_stack_walk(
        ctx=None, c=stub, tid=1234, mode="both",
        max_frames=0, timeout_ms=0,
    ))
    r = json.loads(out)
    assert r["ok"] is True
    # Default timeout flows through as 500 ms per plan README §6.
    assert stub.last_kwargs["timeout_ms"] == 500
    # Default max_frames clamps to the IOCTL cap.
    assert stub.last_kwargs["max_frames"] == 128


def test_stack_walk_forwards_custom_timeout_and_frames() -> None:
    stub = _StubStackWalk()
    out = _run(_stack_walk.handle_stack_walk(
        ctx=None, c=stub, tid=1234, mode="kernel",
        max_frames=16, timeout_ms=250,
    ))
    r = json.loads(out)
    assert r["ok"] is True
    assert stub.last_kwargs["timeout_ms"] == 250
    assert stub.last_kwargs["max_frames"] == 16
    assert stub.last_kwargs["flags"] & _stack_walk._FLAG_KERNEL
    assert not (stub.last_kwargs["flags"] & _stack_walk._FLAG_USER)


def test_stack_walk_rejects_zero_tid() -> None:
    out = _run(_stack_walk.handle_stack_walk(
        ctx=None, c=_StubStackWalk(), tid=0, mode="both",
        max_frames=0, timeout_ms=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert "tid" in r["error"]


def test_stack_walk_rejects_oversize_max_frames() -> None:
    out = _run(_stack_walk.handle_stack_walk(
        ctx=None, c=_StubStackWalk(), tid=1234, mode="both",
        max_frames=4096, timeout_ms=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert "max_frames" in r["error"]


def test_stack_walk_rejects_bad_mode() -> None:
    out = _run(_stack_walk.handle_stack_walk(
        ctx=None, c=_StubStackWalk(), tid=1234, mode="bogus",
        max_frames=0, timeout_ms=0,
    ))
    r = json.loads(out)
    assert r["ok"] is False
    assert "mode" in r["error"]


# ---- ABI header + proto gate ----------------------------------------------


def test_abi_proc_header_defines_stackwalk_code() -> None:
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "comm" / "abi" / "proc.h").read_text(encoding="utf-8")
    m = re.search(r"#define\s+PRY_FUNC_STACKWALK\s+0x([0-9A-Fa-f]+)", txt)
    assert m, "PRY_FUNC_STACKWALK missing from comm/abi/proc.h"
    assert int(m.group(1), 16) == 0x8E5


def test_abi_proc_header_defines_stackwalk_structs() -> None:
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "comm" / "abi" / "proc.h").read_text(encoding="utf-8")
    for sym in ("PRY_STACKWALK_IN", "PRY_STACKWALK_HDR",
                "PRY_STACKWALK_FRAME",
                "PRY_STACKWALK_FLAG_KERNEL",
                "PRY_STACKWALK_FLAG_USER",
                "PRY_STACKWALK_FLAG_FORCE_APC",
                "PRY_STACKWALK_FLAG_TIMEOUT_PARTIAL_OK",
                "PRY_STACKWALK_HDR_TIMED_OUT",
                "PRY_STACKWALK_MAX_FRAMES",
                "PRY_STACKWALK_DEFAULT_TIMEOUT_MS"):
        assert sym in txt, f"{sym} missing from comm/abi/proc.h"


def test_proto_file_carries_stack_walk_messages() -> None:
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "proto" / "pry.proto").read_text(encoding="utf-8")
    for sym in ("message StackWalkRequest",
                "message StackWalkResponse",
                "message StackWalkFrame",
                "service StackWalk"):
        assert sym in txt, f"{sym!r} missing from proto/pry.proto"


def test_abi_version_at_least_fourteen() -> None:
    """SI #6 and #9 landed at ABI v14 (added by SI #25) — the actual
    live-ABI header may have moved on since (a later change
    bumped to v15 for pending-IRP columns), but SI #6/#9 wire shape is
    pinned at 14 and MUST NOT regress below it."""
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "comm" / "abi" / "version.h").read_text(encoding="utf-8")
    m = re.search(r"#define PRY_ABI_VERSION\s+(\d+)", txt)
    assert m, "PRY_ABI_VERSION not found in comm/abi/version.h"
    assert int(m.group(1)) >= 14, (
        f"ABI must be >= 14 for SI #6/#9 (got {m.group(1)})")
