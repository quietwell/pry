"""SI adoption feature #25 — HW-watchpoint-backed ``memory_manage watch``.

Covers the orchestrator-side wire for ABI v14's new watch mode:
``memory_manage(action='watch', mode='hw', ...)`` kwargs register through the
dispatcher + MemArgs schema, the action-help blurb mentions the new
mode, and the fallback path (agent missing ``bp_hw_watch_add``) returns
a clean ``hw_pending`` envelope instead of a traceback.
"""

from __future__ import annotations

import asyncio
import json

from pry.mcp.tools.mem import _MEMORY_ACTIONS_MASTER
from pry.mcp.tools.mem._args import MemArgs
from pry.mcp.tools.mem._action_help import _MEMORY_ACTION_HELP
from pry.mcp.tools.mem import watch as _watch_mod


def test_watch_action_still_registered() -> None:
    # The watch verb is append-only — mode='hw' is additive, the
    # existing poll mode stays reachable with no changes to the enum.
    assert "watch" in _MEMORY_ACTIONS_MASTER
    assert "watch_list" in _MEMORY_ACTIONS_MASTER
    assert "watch_stop" in _MEMORY_ACTIONS_MASTER


def test_memargs_carries_hw_watch_fields() -> None:
    args = MemArgs(action="watch")
    # Defaults — the poll path must stay the no-arg behaviour.
    assert args.mode == "poll"
    assert args.access == "write"
    assert args.tid == 0
    assert args.slot == 0xFF
    assert args.preempt_ok is False
    hw = MemArgs(action="watch", mode="hw", access="rw",
                 tid=4321, slot=2, preempt_ok=True)
    assert hw.mode == "hw"
    assert hw.access == "rw"
    assert hw.tid == 4321
    assert hw.slot == 2
    assert hw.preempt_ok is True


def test_watch_action_help_mentions_hw_mode() -> None:
    row = _MEMORY_ACTION_HELP["watch"]
    assert "mode" in row["key_args"]
    assert "mode='hw'" in row["example"]
    assert "hw" in row["one_liner"].lower()


def test_hw_watch_size_validation() -> None:
    class _Stub:
        async def status(self):
            return {"driver_abi_version": 14, "agent_abi_version": 14,
                    "driver_abi_ok": True}

    out = asyncio.run(_watch_mod._handle_watch_hw(
        ctx=None, c=_Stub(), pid=1234, tid=0, addr=0x7ff600001000,
        size=3, access="write", slot=0xFF, preempt_ok=False,
        tag="t", name=""))
    r = json.loads(out)
    assert r["ok"] is False
    assert "size" in r["error"]


def test_hw_watch_access_validation() -> None:
    class _Stub:
        async def status(self):
            return {"driver_abi_version": 14, "agent_abi_version": 14,
                    "driver_abi_ok": True}

    out = asyncio.run(_watch_mod._handle_watch_hw(
        ctx=None, c=_Stub(), pid=1234, tid=0, addr=0x7ff600001000,
        size=8, access="exec", slot=0xFF, preempt_ok=False,
        tag="t", name=""))
    r = json.loads(out)
    assert r["ok"] is False
    assert "access" in r["error"]


def test_hw_watch_degrades_without_shim() -> None:
    """Agent missing the ABI v14 bp_hw_watch_add shim returns a
    well-shaped ``hw_pending`` envelope so a caller can transparently
    retry with ``mode='poll'``."""

    class _Stub:
        async def status(self):
            return {"driver_abi_version": 14, "agent_abi_version": 14,
                    "driver_abi_ok": True}

    out = asyncio.run(_watch_mod._handle_watch_hw(
        ctx=None, c=_Stub(), pid=1234, tid=0, addr=0x7ff600001000,
        size=8, access="write", slot=0xFF, preempt_ok=False,
        tag="t", name=""))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["mode"] == "hw_pending"
    assert r["fallback"] == "poll"


def test_hw_watch_refuses_old_abi() -> None:
    class _Stub:
        async def status(self):
            return {"driver_abi_version": 13, "agent_abi_version": 13,
                    "driver_abi_ok": True}

    out = asyncio.run(_watch_mod._handle_watch_hw(
        ctx=None, c=_Stub(), pid=1234, tid=0, addr=0x7ff600001000,
        size=8, access="write", slot=0xFF, preempt_ok=False,
        tag="t", name=""))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["abi_version"] == 13
    assert r["fallback"] == "poll"


def test_hvci_fallback_flag_surfaces() -> None:
    """the HVCI-fallback flag comes back on WatchHwAddResponse
    (the real client has no ``ping``) and is surfaced to the caller so it
    can skip the hw path cleanly instead of silently losing hits."""

    class _Stub:
        async def status(self):
            return {"driver_abi_version": 14, "agent_abi_version": 14,
                    "driver_abi_ok": True}

        async def bp_hw_watch_add(self, **kwargs):
            return {"ok": True, "watch_cookie": 42, "slot": 1,
                    "hvci_fallback": True}

    out = asyncio.run(_watch_mod._handle_watch_hw(
        ctx=None, c=_Stub(), pid=1234, tid=0, addr=0x7ff600001000,
        size=8, access="write", slot=0xFF, preempt_ok=False,
        tag="t", name=""))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["mode"] == "hw"
    assert r["hvci_fallback"] is True
    assert r["watch_cookie"] == 42


def test_abi_version_header_bumped() -> None:
    """Guards against a parallel-agent revert of comm/abi/version.h —
    SI #25 ships ABI v14 as part of the Wave 1 bundle."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "comm" / "abi" / "version.h").read_text(encoding="utf-8")
    m = re.search(r"#define PRY_ABI_VERSION\s+(\d+)", txt)
    assert m, "PRY_ABI_VERSION not found in comm/abi/version.h"
    assert int(m.group(1)) >= 14, f"ABI < 14 (got {m.group(1)})"
    # The watch-fallback ping bit is the surface SI #25 depends on.
    assert "PRY_FLAG_WATCH_HVCI_FALLBACK" in txt


def test_bp_header_carries_watch_flags() -> None:
    """PRY_BPHW_FLAG_IS_WATCH / _PREEMPT_OK + PRY_BP_HW_SLOT_AUTO
    live in comm/abi/bp.h — the agent packs them into the SET IOCTL."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "comm" / "abi" / "bp.h").read_text(encoding="utf-8")
    for sym in ("PRY_BPHW_FLAG_IS_WATCH",
                "PRY_BPHW_FLAG_PREEMPT_OK",
                "PRY_BP_HW_SLOT_AUTO",
                "WatchCookie"):
        assert sym in txt, f"{sym} missing from comm/abi/bp.h"


def test_notify_header_carries_watchcookie() -> None:
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2]
    txt = (root / "comm" / "abi" / "notify.h").read_text(encoding="utf-8")
    assert "WatchCookie" in txt
