"""SI #2 hidden-process orchestrator verb tests.

Exercises ``memory_manage(action='hidden_proc')`` through the per-verb module
directly against a stub AgentClient. The verb's job is to cross-join
the oracle rows (brute / registry / ETW) with the NtQSI ground truth
and produce one ``is_hidden`` + ``verdict`` + ``confidence`` row per
candidate PID.

Wave 1 only — CSRSS mode is accepted and dropped (it needs the slice-1
HANDLE_LIST enrichment that lands in Wave 2).
"""

from __future__ import annotations

import json

import pytest

from pry.mcp.tools.mem.hidden_proc import (handle_hidden_proc,
                                              _confidence, _normalize_modes,
                                              _verdict)


def _parse(result) -> dict:
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
            return "user" if name == "user" else "kernel"

    class _Cfg:
        def mcp_max_items(self) -> int:
            return 1024

    def __init__(self) -> None:
        self.session = self._Session()
        self.cfg = self._Cfg()


class _StubClient:
    """Non-None hidden_proc sentinel satisfies the version gate;
    mem_processes + hidden_proc_scan return canned data."""

    def __init__(self, *, nqsi_pids: list[int], oracle_rows: list[dict],
                 modes_run: list[str] | None = None,
                 modes_failed: list[str] | None = None,
                 scan_ok: bool = True,
                 scan_error: str = "") -> None:
        self.hidden_proc = object()
        self._nqsi = [{"pid": p, "image": f"proc_{p}.exe"} for p in nqsi_pids]
        self._oracle = oracle_rows
        self._modes_run = modes_run or ["brute", "registry", "etw"]
        self._modes_failed = modes_failed or []
        self._scan_ok = scan_ok
        self._scan_error = scan_error
        self.last_scan_call: dict | None = None
        self.last_proc_call: dict | None = None

    async def mem_processes(self, **kw) -> dict:
        self.last_proc_call = kw
        return {"processes": self._nqsi, "source": "agent"}

    async def hidden_proc_scan(self, **kw) -> dict:
        self.last_scan_call = kw
        if not self._scan_ok:
            return {"ok": False, "error": self._scan_error,
                    "modes_run": self._modes_run,
                    "modes_failed": self._modes_failed}
        return {
            "ok": True,
            "rows": self._oracle,
            "modes_run": self._modes_run,
            "modes_failed": self._modes_failed,
            "pid_max_used": 100000,
            "step_used": 4,
        }


# -----------------------------------------------------------------------
# Pure helpers.
# -----------------------------------------------------------------------

def test_normalize_modes_defaults_to_wave1_when_empty() -> None:
    sent, dropped = _normalize_modes(None)
    assert sent == ["brute", "registry", "etw"]
    assert dropped == []


def test_normalize_modes_drops_csrss_and_unknown() -> None:
    sent, dropped = _normalize_modes(["brute", "csrss", "banana"])
    assert sent == ["brute"]
    assert "csrss" in dropped
    assert "banana" in dropped


def test_normalize_modes_only_unknown_falls_back_to_wave1() -> None:
    sent, dropped = _normalize_modes(["csrss"])
    assert sent == ["brute", "registry", "etw"]
    assert dropped == ["csrss"]


def test_verdict_present_in_nqsi_is_clean() -> None:
    row = {"present_brute": True, "present_etw": True}
    assert _verdict(row, True) == "clean"


def test_verdict_only_brute_is_unlinked() -> None:
    row = {"present_brute": True, "present_registry": False,
           "present_etw": False, "exit_time_100ns": 0}
    assert _verdict(row, False) == "unlinked_from_pslist"


def test_verdict_zombie_wins_on_exit_time() -> None:
    row = {"present_brute": True, "exit_time_100ns": 132_000_000_000_000_000}
    assert _verdict(row, False) == "zombie"


def test_verdict_only_etw_is_ghost() -> None:
    row = {"present_etw": True}
    assert _verdict(row, False) == "ghost_etw_owner"


def test_verdict_only_registry_is_stale() -> None:
    row = {"present_registry": True}
    assert _verdict(row, False) == "stale_registry"


def test_confidence_zero_when_present_in_nqsi() -> None:
    row = {"present_brute": True, "present_etw": True, "present_registry": True}
    assert _confidence(row, True) == 0.0


def test_confidence_scales_with_mode_hits() -> None:
    one = _confidence({"present_brute": True}, False)
    two = _confidence({"present_brute": True, "present_etw": True}, False)
    three = _confidence({"present_brute": True, "present_etw": True,
                          "present_registry": True}, False)
    assert 0 < one < two < three == 1.0


def test_confidence_zombie_bonus() -> None:
    base = _confidence({"present_brute": True}, False)
    boost = _confidence({"present_brute": True,
                          "exit_time_100ns": 1}, False)
    assert boost > base
    assert boost <= 1.0


# -----------------------------------------------------------------------
# Handler integration.
# -----------------------------------------------------------------------

async def test_hidden_proc_agent_version_gate() -> None:
    ctx = _StubCtx()
    client = _StubClient(nqsi_pids=[1, 2], oracle_rows=[])
    client.hidden_proc = None
    out = _parse(await handle_hidden_proc(
        ctx, client, modes=None, pid_max=0, step=0, timeout_ms=0,
        fields=None, filter="", summary=False, limit=0, offset=0,
        max_results=0,
    ))
    assert out["ok"] is False
    assert out["kind"] == "agent_version"


async def test_hidden_proc_clean_box_no_hidden() -> None:
    """When every oracle PID is in NtQSI, nothing surfaces as hidden."""
    ctx = _StubCtx()
    client = _StubClient(
        nqsi_pids=[100, 200, 300],
        oracle_rows=[
            {"pid": 100, "image": "a.exe", "present_brute": True,
             "sources": "brute"},
            {"pid": 200, "image": "b.exe", "present_brute": True,
             "present_etw": True, "sources": "brute,etw"},
        ],
    )
    body = _parse(await handle_hidden_proc(
        ctx, client, modes=None, pid_max=0, step=0, timeout_ms=0,
        fields=None, filter="", summary=False, limit=0, offset=0,
        max_results=100,
    ))
    data = body.get("data") or {}
    assert data["scan_summary"]["hidden_candidates"] == 0
    for item in data["items"]:
        assert item["is_hidden"] is False
        assert item["verdict"] == "clean"


async def test_hidden_proc_unlinked_from_pslist_surfaces() -> None:
    """Brute sees PID 999, NtQSI does not ⇒ is_hidden=True."""
    ctx = _StubCtx()
    client = _StubClient(
        nqsi_pids=[100],
        oracle_rows=[
            {"pid": 100, "image": "a.exe", "present_brute": True,
             "sources": "brute"},
            {"pid": 999, "image": "ghost.exe", "present_brute": True,
             "sources": "brute"},
        ],
    )
    body = _parse(await handle_hidden_proc(
        ctx, client, modes=None, pid_max=0, step=0, timeout_ms=0,
        fields=None, filter="", summary=False, limit=0, offset=0,
        max_results=100,
    ))
    data = body.get("data") or {}
    hidden = [r for r in data["items"] if r["is_hidden"]]
    assert len(hidden) == 1
    assert hidden[0]["pid"] == 999
    assert hidden[0]["verdict"] == "unlinked_from_pslist"
    assert data["scan_summary"]["hidden_candidates"] == 1


async def test_hidden_proc_mode_failed_marks_partial() -> None:
    ctx = _StubCtx()
    client = _StubClient(
        nqsi_pids=[1],
        oracle_rows=[{"pid": 1, "image": "a.exe", "present_brute": True,
                       "sources": "brute"}],
        modes_run=["brute"],
        modes_failed=["etw"],
    )
    body = _parse(await handle_hidden_proc(
        ctx, client, modes=None, pid_max=0, step=0, timeout_ms=0,
        fields=None, filter="", summary=False, limit=0, offset=0,
        max_results=0,
    ))
    assert body["coverage"]["status"] == "partial"
    assert any("mode_unavailable:etw" in l
                for l in body["coverage"]["limits"])


async def test_hidden_proc_csrss_mode_dropped_wave2() -> None:
    ctx = _StubCtx()
    client = _StubClient(nqsi_pids=[], oracle_rows=[])
    body = _parse(await handle_hidden_proc(
        ctx, client, modes=["csrss"], pid_max=0, step=0, timeout_ms=0,
        fields=None, filter="", summary=False, limit=0, offset=0,
        max_results=0,
    ))
    # CSRSS was accepted-and-dropped; coverage says why.
    assert body["coverage"]["status"] == "partial"
    assert any("csrss_mode_wave2" in l for l in body["coverage"]["limits"])
    # modes_send ends up with the Wave 1 default fallback.
    assert client.last_scan_call is not None
    assert set(client.last_scan_call["modes"]) == {"brute", "registry", "etw"}


async def test_hidden_proc_scan_error_passthrough() -> None:
    ctx = _StubCtx()
    client = _StubClient(nqsi_pids=[], oracle_rows=[],
                          scan_ok=False, scan_error="etw: insufficient priv")
    out = _parse(await handle_hidden_proc(
        ctx, client, modes=None, pid_max=0, step=0, timeout_ms=0,
        fields=None, filter="", summary=False, limit=0, offset=0,
        max_results=0,
    ))
    assert out["ok"] is False
    assert out["kind"] == "hidden_proc_failed"
    assert "etw" in out["error"]


async def test_hidden_proc_registered_in_mem_actions() -> None:
    from pry.mcp.tools.mem import _MEMORY_ACTIONS_MASTER
    from pry.mcp.tools.mem._action_help import _MEMORY_ACTION_HELP
    assert "hidden_proc" in _MEMORY_ACTIONS_MASTER
    assert "hidden_proc" in _MEMORY_ACTION_HELP
    assert "SI #2" in _MEMORY_ACTION_HELP["hidden_proc"]["one_liner"]
