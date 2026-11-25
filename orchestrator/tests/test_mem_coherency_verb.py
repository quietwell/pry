"""SI #1 image-coherency orchestrator verb dispatch tests.

Exercises ``memory_manage(action='coherency')`` via the mem.coherency handler
directly against a stub AgentClient that returns a canned response.
The classifier runs orchestrator-side on whatever mismatches the
stub returns, so these tests cover both the dispatcher and the
classifier integration.
"""

from __future__ import annotations

import json

import pytest

from pry.mcp.tools.mem.coherency import handle_coherency


def _parse(result) -> dict:
    """Normalize handler returns: success paths may return a plain dict
    envelope (the dispatcher _j-wraps it on the way out); error paths
    pass through _j (either a JSON string or a ToolResult)."""
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        return json.loads(result)
    sc = getattr(result, "structured_content", None)
    if sc is not None:
        return sc
    return json.loads(result.content[0].text)


class _StubCtx:
    class _Session:
        def view_kind_of(self, name: str) -> str:
            # The verb only uses this to label `source=`.
            return "user" if name == "user" else "kernel"

    class _Cfg:
        def mcp_max_items(self) -> int:
            return 1024

    def __init__(self) -> None:
        self.session = self._Session()
        self.cfg = self._Cfg()


class _StubClient:
    """Minimal AgentClient stub: carries a `coherency` sentinel for the
    agent-version gate and returns ``canned`` from mem_coherency."""

    def __init__(self, canned: dict) -> None:
        self.coherency = object()  # non-None satisfies the version gate
        self._canned = canned
        self.last_call: dict | None = None

    async def mem_coherency(self, **kw) -> dict:
        self.last_call = kw
        return self._canned


async def test_coherency_bad_mode() -> None:
    ctx = _StubCtx()
    client = _StubClient({"ok": True})
    out = _parse(await handle_coherency(
        ctx, client, pid=1234, module="ntdll.dll", module_base=0,
        mode="turbo", name="",
        max_mismatch_ranges=0, include_mismatch_hex=False,
        fields=None, filter="", summary=False, limit=0, offset=0,
    ))
    assert out["ok"] is False
    assert out["kind"] == "bad_arg"
    assert "quick" in out["error"]


async def test_coherency_requires_module_or_base() -> None:
    ctx = _StubCtx()
    client = _StubClient({"ok": True})
    out = _parse(await handle_coherency(
        ctx, client, pid=1234, module="", module_base=0,
        mode="normal", name="",
        max_mismatch_ranges=0, include_mismatch_hex=False,
        fields=None, filter="", summary=False, limit=0, offset=0,
    ))
    assert out["ok"] is False
    assert out["kind"] == "bad_arg"


async def test_coherency_agent_version_gate() -> None:
    ctx = _StubCtx()
    client = _StubClient({"ok": True})
    client.coherency = None
    out = _parse(await handle_coherency(
        ctx, client, pid=1234, module="ntdll.dll", module_base=0,
        mode="quick", name="",
        max_mismatch_ranges=0, include_mismatch_hex=False,
        fields=None, filter="", summary=False, limit=0, offset=0,
    ))
    assert out["ok"] is False
    assert out["kind"] == "agent_version"


async def test_coherency_clean_full_mode_response_shape() -> None:
    """Full mode + no mismatches ⇒ classification='clean' + coverage=complete."""
    ctx = _StubCtx()
    canned = {
        "ok": True,
        "module": "ntdll.dll",
        "module_path_disk": "C:\\Windows\\System32\\ntdll.dll",
        "size_of_image": 0x200000,
        "bytes_compared": 0x200000,
        "bytes_mismatched": 0,
        "coherency": 1.0,
        "sections_total": 5,
        "sections_skipped_relocatable": 2,
        "truncated": False,
        "reloc_dir_rva": 0x6000,
        "reloc_dir_size": 0x200,
        "sections": [
            {"name": ".text", "va": 0x1000, "size": 0x2000,
             "characteristics": 0x60000020},
            {"name": ".rdata", "va": 0x3000, "size": 0x1000,
             "characteristics": 0x40000040},
        ],
        "mismatches": [],
    }
    client = _StubClient(canned)
    body = _parse(await handle_coherency(
        ctx, client, pid=1234, module="ntdll.dll", module_base=0,
        mode="full", name="user",
        max_mismatch_ranges=128, include_mismatch_hex=False,
        fields=None, filter="", summary=False, limit=0, offset=0,
    ))
    # _list_envelope wraps success extras under 'data', items under
    # 'data.items', coverage at the top level alongside the envelope
    # scaffolding.
    data = body.get("data") or {}
    assert data.get("classification") == "clean"
    assert data.get("source") == "umagent"
    assert data.get("mode") == "full"
    assert body["coverage"]["scope"] == "coherency-window"
    assert body["coverage"]["status"] == "complete"
    assert any(r["name"] == "relocs"
               for r in data.get("coherency_excluded_regions", []))


async def test_coherency_iat_hook_classification() -> None:
    """Mismatches inside .idata ⇒ classification='iat_hooked'."""
    ctx = _StubCtx()
    canned = {
        "ok": True, "module": "foo.dll", "module_path_disk": "C:\\foo.dll",
        "size_of_image": 0x8000, "bytes_compared": 0x4000,
        "bytes_mismatched": 16, "coherency": 1.0 - 16 / 0x4000,
        "sections_total": 1, "sections_skipped_relocatable": 0,
        "truncated": False, "reloc_dir_rva": 0, "reloc_dir_size": 0,
        "sections": [
            {"name": ".idata", "va": 0x5000, "size": 0x400,
             "characteristics": 0x40000040},
        ],
        "mismatches": [
            {"rva": 0x5000, "length": 8, "section": ".idata", "hint": "iat_slot",
             "in_memory_hex": "aabbccdd", "on_disk_hex": "00000000"},
            {"rva": 0x5020, "length": 8, "section": ".idata", "hint": "iat_slot",
             "in_memory_hex": "aabbccdd", "on_disk_hex": "00000000"},
        ],
    }
    client = _StubClient(canned)
    body = _parse(await handle_coherency(
        ctx, client, pid=1234, module="foo.dll", module_base=0,
        mode="quick", name="user",
        max_mismatch_ranges=128, include_mismatch_hex=True,
        fields=None, filter="", summary=False, limit=0, offset=0,
    ))
    data = body.get("data") or {}
    assert data.get("classification") == "iat_hooked"
    assert body["coverage"]["status"] == "partial"
    assert "sampling_cap_reached" in body["coverage"]["limits"]


async def test_coherency_underlying_error_passthrough() -> None:
    ctx = _StubCtx()
    client = _StubClient({"ok": False, "module": "nope.dll",
                           "error": "coherency: module not found in pid 1"})
    out = _parse(await handle_coherency(
        ctx, client, pid=1234, module="nope.dll", module_base=0,
        mode="normal", name="user",
        max_mismatch_ranges=0, include_mismatch_hex=False,
        fields=None, filter="", summary=False, limit=0, offset=0,
    ))
    assert out["ok"] is False
    assert out["kind"] == "coherency_failed"


async def test_coherency_dispatcher_registers_action() -> None:
    """memory_manage action='coherency' is on _MEMORY_ACTIONS_MASTER + driver_free."""
    from pry.mcp.tools.mem import _MEMORY_ACTIONS_MASTER
    from pry.mcp.tools.mem._action_help import _MEMORY_ACTION_HELP
    assert "coherency" in _MEMORY_ACTIONS_MASTER
    assert "coherency" in _MEMORY_ACTION_HELP
    assert "SI #1" in _MEMORY_ACTION_HELP["coherency"]["one_liner"]
