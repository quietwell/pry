"""Memory scanner wave 3 §6.4 — ``InvariantFieldFinder`` scanner.

The walker is pure logic: hand it an async ``read(va, size)`` and a
candidate EPROCESS base, and it reports offsets for
``ActiveProcessLinks`` / ``UniqueProcessId`` / ``ImageFileName`` by
chasing the DISPATCHER_HEADER anchor + three-hop ring + ASCII-run
heuristics. These tests drive the scanner against a synthetic blob —
no agent, no PDB.
"""
from __future__ import annotations

import asyncio
import struct
import sys
from pathlib import Path

import pytest  # noqa: F401 — collector-side

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.kernel import _invariants  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# Synthetic "kernel" memory. Three EPROCESS-like blocks linked by
# ActiveProcessLinks at offset 0x1F0 (Wave 3 fallback works any
# 8-byte aligned slot in [0x100, 0x400); we use the plan's §6.4
# example offset so the test doubles as a spec check).

EPROCESS_SIZE   = 0x800
APL_OFFSET      = 0x1F0
UPID_OFFSET     = 0x1E8     # 0x1F0 - 0x08
IMAGENAME_OFF   = 0x5A8     # inside the forward scan window
PROC_A_BASE = 0xFFFF_E000_1000_0000
PROC_B_BASE = 0xFFFF_E000_2000_0000
PROC_C_BASE = 0xFFFF_E000_3000_0000


def _make_eprocess(pid: int, image: bytes,
                   flink: int, blink: int) -> bytearray:
    """Build one EPROCESS blob with the fields at the plan's example
    offsets. Only the bits the walker reads are populated.
    """
    blob = bytearray(EPROCESS_SIZE)
    # DISPATCHER_HEADER: Type=0x03 (ProcessObject), TimerType=0x00.
    blob[0] = 0x03
    blob[1] = 0x00
    # UniqueProcessId (HANDLE) at UPID_OFFSET.
    struct.pack_into("<Q", blob, UPID_OFFSET, pid)
    # ActiveProcessLinks (Flink, Blink) at APL_OFFSET.
    struct.pack_into("<QQ", blob, APL_OFFSET, flink, blink)
    # ImageFileName (CHAR[15]).
    name = image.ljust(15, b"\x00")[:15]
    blob[IMAGENAME_OFF:IMAGENAME_OFF + 15] = name
    return blob


def _make_memory():
    """Three-node process ring with Flink/Blink pointing at each
    peer's ActiveProcessLinks field (the structural invariant the
    walker exploits)."""
    def apl_va(base: int) -> int:
        return base + APL_OFFSET

    a = _make_eprocess(100, b"system",
                       flink=apl_va(PROC_B_BASE),
                       blink=apl_va(PROC_C_BASE))
    b = _make_eprocess(4242, b"notepad.exe",
                       flink=apl_va(PROC_C_BASE),
                       blink=apl_va(PROC_A_BASE))
    c = _make_eprocess(1234, b"explorer.exe",
                       flink=apl_va(PROC_A_BASE),
                       blink=apl_va(PROC_B_BASE))
    return {PROC_A_BASE: bytes(a), PROC_B_BASE: bytes(b),
            PROC_C_BASE: bytes(c)}


def _make_reader(mem):
    async def read(va, size):
        for base, blob in mem.items():
            if base <= va < base + len(blob):
                off = va - base
                return bytes(blob[off:off + size])
        raise RuntimeError(f"no fixture for va=0x{va:x} size={size}")
    return read


# ----------------------------------------------------------------------
# Scanner tests
# ----------------------------------------------------------------------

def test_scanner_finds_all_three_fields_with_pid_hint():
    walker = _invariants.InvariantFieldFinder()
    res = _run(walker.scan(_make_reader(_make_memory()),
                           PROC_B_BASE, hint_pid=4242))
    assert res["ok"], res
    e = res["eprocess"]
    assert e["ActiveProcessLinks"]["offset"] == APL_OFFSET
    assert e["UniqueProcessId"]["offset"] == UPID_OFFSET
    assert e["UniqueProcessId"]["kind"] == "scalar"
    assert e["ImageFileName"]["offset"] == IMAGENAME_OFF
    assert e["ImageFileName"]["kind"] == "string_ansi"


def test_scanner_rejects_candidate_without_dispatcher_header():
    """A base VA whose byte 0 is not 0x03 never passes the anchor —
    r1's PID scan would false-positive here, r2 doesn't.
    """
    mem = _make_memory()
    # Blank out the dispatcher header on PROC_A so it no longer
    # looks like an EPROCESS.
    bad = bytearray(mem[PROC_A_BASE])
    bad[0] = 0x05  # KOBJECTS::EventObject — anything but 0x03
    mem[PROC_A_BASE] = bytes(bad)
    walker = _invariants.InvariantFieldFinder()
    res = _run(walker.scan(_make_reader(mem),
                           PROC_A_BASE, hint_pid=100))
    assert not res["ok"]
    assert res["kind"] == "eprocess_anchor_failed"


def test_scanner_rejects_ring_that_does_not_close():
    """A single EPROCESS whose Flink points off into the weeds must
    not look like a valid ring.
    """
    # A standalone block pointing nowhere.
    lone = _make_eprocess(777, b"lone.exe",
                          flink=PROC_A_BASE + 0xDEAD,
                          blink=PROC_A_BASE + 0xBEEF)
    mem = {PROC_A_BASE: bytes(lone)}
    walker = _invariants.InvariantFieldFinder()
    res = _run(walker.scan(_make_reader(mem),
                           PROC_A_BASE, hint_pid=777))
    # No neighbor passes the dispatcher check, so the ring is open.
    assert not res["ok"]
    assert res["kind"] == "eprocess_anchor_failed"


def test_baked_loader_returns_none_on_unknown_build(tmp_path):
    """Unknown build number must return None, not raise — the
    unknown-build hint lands in the handler."""
    assert _invariants.load_baked(0, baked_dir=tmp_path) is None
    assert _invariants.load_baked(99999, baked_dir=tmp_path) is None


def test_baked_loader_picks_matching_file_from_shipped_tree():
    """Walks the real `artifacts/invariants/eprocess/` directory to
    confirm the mapping from build_major -> filename."""
    data = _invariants.load_baked(19041)
    assert data is not None
    assert data.get("build") == "19041"
    data = _invariants.load_baked(22631)
    assert data is not None
    assert data.get("build") == "22631"
    data = _invariants.load_baked(26100)
    assert data is not None
    assert data.get("build") == "26100"


def test_cache_discovered_writes_to_artifacts(tmp_path):
    offsets = {"ActiveProcessLinks": {"offset": 0x1F0, "size": 16,
                                      "kind": "ptr"}}
    _invariants.cache_discovered("19045", offsets, tmp_path)
    out = tmp_path / "invariants" / "eprocess" / "19045.discovered.json"
    assert out.is_file()
    import json
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["build"] == "19045"
    assert body["eprocess"] == offsets


def test_load_discovered_round_trips_cache(tmp_path):
    offsets = {"ActiveProcessLinks": {"offset": 0x1F0, "size": 16,
                                      "kind": "ptr"}}
    _invariants.cache_discovered("26200.9186", offsets, tmp_path)
    assert _invariants.load_discovered("26200.9186", tmp_path) == offsets
    assert _invariants.load_discovered("26200.1", tmp_path) is None


def test_discovered_cache_rejects_unsafe_build_keys(tmp_path):
    """The build key comes from the target's host_info: a separator or
    '..' must never reach the filesystem, for writes or reads."""
    root = tmp_path / "artifacts"
    offsets = {"ActiveProcessLinks": {"offset": 0x1F0, "size": 16,
                                      "kind": "ptr"}}
    for bad in ("", "..", "../evil", "a/b", "a\b", "x..y", ".hidden"):
        _invariants.cache_discovered(bad, offsets, root)
        assert _invariants.load_discovered(bad, root) is None, bad
    assert not any(tmp_path.rglob("*.json"))
