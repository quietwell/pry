"""SI #14 process-snapshot minidump orchestrator verb dispatch tests.

Exercises ``dump_manage(action='process_snapshot')`` via the
``_mem_process_snapshot`` helper directly against a stub AgentClient
that returns a canned response. The C++ ladder is covered by the
agent-side integration smoke test; these tests just assert the
orchestrator-side flag resolver, verdict labels and the response
envelope stay honest.
"""

from __future__ import annotations

import pytest

from pry.mcp.tools.dump import (
    DUMP_ACTIONS,
    _DEFAULT_MINIDUMP_FLAGS,
    _MINIDUMP_FLAG_MAP,
    _mem_process_snapshot,
    _resolve_minidump_flags,
)


class _StubCtx:
    class _Session:
        def view_kind_of(self, name: str) -> str:
            return "user" if name == "user" else "kernel"

    def __init__(self) -> None:
        self.session = self._Session()


class _StubClient:
    def __init__(self, canned: dict) -> None:
        self._canned = canned
        self.last_call: dict | None = None

    async def process_dump(self, **kw) -> dict:
        self.last_call = kw
        return self._canned


def test_dump_actions_includes_process_snapshot() -> None:
    assert "process_snapshot" in DUMP_ACTIONS


def test_minidump_flag_map_covers_defaults() -> None:
    assert _MINIDUMP_FLAG_MAP["WithFullMemory"] == 0x00000002
    assert _MINIDUMP_FLAG_MAP["WithThreadInfo"] == 0x00001000
    # Default mask includes all six documented flags.
    for name in ("WithFullMemory", "WithThreadInfo", "WithHandleData",
                 "WithUnloadedModules", "WithFullMemoryInfo",
                 "WithTokenInformation"):
        assert (_DEFAULT_MINIDUMP_FLAGS & _MINIDUMP_FLAG_MAP[name]) \
            == _MINIDUMP_FLAG_MAP[name], name


def test_resolve_minidump_flags_default() -> None:
    mask, used, unknown = _resolve_minidump_flags(None)
    assert mask == _DEFAULT_MINIDUMP_FLAGS
    assert used == []
    assert unknown == []
    mask2, _, _ = _resolve_minidump_flags([])
    assert mask2 == _DEFAULT_MINIDUMP_FLAGS


def test_resolve_minidump_flags_accepts_minidump_prefix() -> None:
    mask, used, unknown = _resolve_minidump_flags(
        ["MiniDumpWithFullMemory", "WithThreadInfo", "GarbageFlag"])
    assert mask == (_MINIDUMP_FLAG_MAP["WithFullMemory"]
                     | _MINIDUMP_FLAG_MAP["WithThreadInfo"])
    assert used == ["WithFullMemory", "WithThreadInfo"]
    assert unknown == ["GarbageFlag"]


async def test_process_snapshot_requires_positive_pid() -> None:
    out = await _mem_process_snapshot(
        _StubCtx(), _StubClient({"ok": True}),
        pid=0, dump_flags=None, output_path="",
        use_snapshot=True, name="")
    assert out["ok"] is False
    assert out["kind"] == "bad_arg"


async def test_process_snapshot_happy_path_envelope() -> None:
    ctx = _StubCtx()
    canned = {
        "ok": True, "kind": "",
        "path": "C:\\\\Temp\\\\pry\\\\dumps\\\\pid_1234_42.dmp",
        "size": 128 * 1024,
        "sha256": ("a" * 64),
        "access_mask_used": 0x1FFFFF,  # PROCESS_ALL_ACCESS
        "snapshot_used": True,
    }
    client = _StubClient(canned)
    out = await _mem_process_snapshot(
        ctx, client, pid=1234,
        dump_flags=["WithFullMemory", "WithThreadInfo"],
        output_path="", use_snapshot=True, name="user")
    assert out["ok"] is True
    assert out["pid"] == 1234
    assert out["source"] == "umagent"
    assert out["remote_path"].endswith(".dmp")
    assert out["size"] == 128 * 1024
    assert out["sha256"] == "a" * 64
    assert out["access_mask_used"] == 0x1FFFFF
    assert out["access_mask_used_hex"].lower() == "0x1fffff"
    assert out["snapshot_used"] is True
    assert set(out["flags_used"]) == {"WithFullMemory", "WithThreadInfo"}
    assert out["flags_unknown"] == []
    assert out["coverage"]["scope"] == "process-snapshot"
    assert out["coverage"]["status"] == "complete"
    # The client got the resolved bitmask.
    expected = (_MINIDUMP_FLAG_MAP["WithFullMemory"]
                 | _MINIDUMP_FLAG_MAP["WithThreadInfo"])
    assert client.last_call["flags"] == expected
    assert client.last_call["pid"] == 1234
    assert client.last_call["use_snapshot"] is True


async def test_process_snapshot_pp_target_surfaces_feature23() -> None:
    """PP target returns kind='pp_target_requires_feature_23' from the
    agent — the orchestrator must pass that through unchanged (never
    reach for an alternate tactic in Wave 1)."""
    ctx = _StubCtx()
    canned = {
        "ok": False, "kind": "pp_target_requires_feature_23",
        "error": "target is protected (PP/PPL); requires PP open "
                  "(feature #23, Wave 3)",
        "path": "", "size": 0, "sha256": "",
        "access_mask_used": 0, "snapshot_used": False,
    }
    out = await _mem_process_snapshot(
        ctx, _StubClient(canned), pid=4, dump_flags=None,
        output_path="", use_snapshot=True, name="")
    assert out["ok"] is False
    assert out["kind"] == "pp_target_requires_feature_23"
    assert "feature #23" in out["error"]


async def test_process_snapshot_unknown_flag_marks_partial() -> None:
    ctx = _StubCtx()
    canned = {
        "ok": True, "kind": "",
        "path": "C:\\\\x.dmp", "size": 1, "sha256": "b" * 64,
        "access_mask_used": 0x410, "snapshot_used": False,
    }
    out = await _mem_process_snapshot(
        ctx, _StubClient(canned), pid=1234,
        dump_flags=["WithFullMemory", "TotallyMadeUp"],
        output_path="", use_snapshot=False, name="user")
    assert out["ok"] is True
    assert out["flags_unknown"] == ["TotallyMadeUp"]
    assert out["coverage"]["status"] == "partial"
    assert "unknown_flags" in out["coverage"]["limits"]


async def test_process_snapshot_client_exception_wrapped() -> None:
    ctx = _StubCtx()

    class _Boom:
        async def process_dump(self, **_: object) -> dict:
            raise RuntimeError("gRPC transport died")

    out = await _mem_process_snapshot(
        ctx, _Boom(), pid=1234, dump_flags=None,
        output_path="", use_snapshot=True, name="")
    assert out["ok"] is False
    assert out["kind"] == "process_snapshot_failed"
    assert "RuntimeError" in out["error"]
