"""v16 (Memory scanner wave 1 Phase G): value_scan + next_scan + scan_undo
+ scan_destroy orchestrator-RAM path (the v15 fallback).

Mocked agent client, no server contact. The toy target is a 64 KiB
buffer served through ``mem_read``; the mock also honours
``vad_list`` / ``mem_heaps`` so ``resolve_spans`` can run.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.mem.value_scan import (  # noqa: E402
    pack_probe, _validate_create_args, _width_of,
    _is_string_type, _decode_from_raw,
    handle_value_scan, handle_next_scan, handle_scan_undo,
    handle_scan_destroy,
)
from src.pry.mcp.tools.mem import scan as _mem_scan  # noqa: E402


# ---------------------------------------------------------------- probes --

@pytest.mark.parametrize("vt,v,buf,expect", [
    ("int32",  42, struct.pack("<iiii", 10, 42, 100, 7),  [False, True, False, False]),
    ("uint32", 0xDEADBEEF, struct.pack("<II", 0xDEADBEEF, 0),  [True, False]),
    ("int64",  -1, struct.pack("<qq", -1, 0),  [True, False]),
    ("uint8",  0xAB, b"\x01\xAB\xCD", [False, True, False]),
    ("int16",  -17, struct.pack("<hh", -17, 5), [True, False]),
])
def test_pack_probe_eq_on_ints(vt, v, buf, expect):
    probe = pack_probe(value_type=vt, op="eq", value=v, endian="le")
    w = _width_of(vt, "", v)
    got = [probe(buf, off) for off in range(0, len(buf), w)]
    assert got == expect


def test_pack_probe_eq_be_endian():
    """Big-endian reads must match a BE-encoded buffer."""
    probe = pack_probe(value_type="int32", op="eq", value=0x11223344,
                       endian="be")
    buf = struct.pack(">i", 0x11223344)
    assert probe(buf, 0) is True


@pytest.mark.parametrize("op,val,hi,buf,expect", [
    ("lt", 100, None, struct.pack("<ii", 50, 150), [True, False]),
    ("gt", 100, None, struct.pack("<ii", 50, 150), [False, True]),
    ("between", 10, 50, struct.pack("<iii", 5, 25, 70), [False, True, False]),
])
def test_pack_probe_comparison_ops(op, val, hi, buf, expect):
    probe = pack_probe(value_type="int32", op=op, value=val,
                       value_hi=hi, endian="le")
    got = [probe(buf, off) for off in range(0, len(buf), 4)]
    assert got == expect


def test_pack_probe_float_tolerance():
    probe = pack_probe(value_type="float", op="eq", value=3.14,
                       endian="le", tolerance=1e-3)
    buf = struct.pack("<ff", 3.14001, 2.71)
    assert probe(buf, 0) is True
    assert probe(buf, 4) is False


def test_pack_probe_string_fixed_length():
    probe = pack_probe(value_type="string", op="eq", value="hello",
                       encoding="utf8")
    assert probe(b"XXhelloYY", 2) is True
    assert probe(b"XXhelXX", 2) is False


def test_pack_probe_utf16():
    probe = pack_probe(value_type="utf16", op="eq", value="hi",
                       encoding="utf16le")
    buf = "hi".encode("utf-16-le")
    assert probe(buf, 0) is True


def test_pack_probe_unknown_matches_every_slot():
    probe = pack_probe(value_type="int32", op="unknown", value=None,
                       endian="le")
    buf = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert probe(buf, 0) is True
    assert probe(buf, 4) is True
    assert probe(buf, 5) is False  # off + width > len


def test_pack_probe_rejects_bad_op():
    with pytest.raises(ValueError):
        pack_probe(value_type="int32", op="weird", value=1)


def test_pack_probe_string_rejects_non_eq():
    with pytest.raises(ValueError):
        pack_probe(value_type="string", op="changed", value="hi")


# ---------------------------------------------------- validator table ----

def test_validate_rejects_unknown_type():
    err = _validate_create_args(
        value_type="float128", op="eq", endian="le", encoding="",
        tolerance=0, value=1.0, value_hi=None, align=4)
    assert err and err["kind"] == "bad_arg"


def test_validate_rejects_tolerance_on_int():
    err = _validate_create_args(
        value_type="int32", op="eq", endian="le", encoding="",
        tolerance=1e-4, value=1, value_hi=None, align=4)
    assert err and "tolerance" in err["error"].lower()


def test_validate_rejects_between_without_hi():
    err = _validate_create_args(
        value_type="int32", op="between", endian="le", encoding="",
        tolerance=0, value=1, value_hi=None, align=4)
    assert err and "value_hi" in err["error"]


def test_validate_rejects_unknown_with_value():
    err = _validate_create_args(
        value_type="int32", op="unknown", endian="le", encoding="",
        tolerance=0, value=42, value_hi=None, align=4)
    assert err


# ------------------------------------------------- v15 end-to-end flow ---

class _MockClient:
    """Tiny agent client for the value_scan loop. Serves one span of
    memory and a small VAD + heap set."""
    def __init__(self, base: int, data: bytes):
        self._base = base
        self._data = bytearray(data)
        self._vads = [
            {"start": base, "end": base + len(data),
             "protect": 0x04, "vad_type": 0},  # PAGE_READWRITE / private
        ]
        self._heaps = [{"base": base, "committed": len(data)}]

    async def vad_list(self, pid, *, limit=0, offset=0):
        return list(self._vads)

    async def mem_heaps(self, pid, want_blocks=False, max_blocks=0):
        return list(self._heaps)

    async def mem_modules(self, pid, kernel=False, *, limit=0, offset=0):
        return []

    async def thread_list(self, pid=0, kernel=False, with_context=False):
        return {"threads": []}

    async def mem_read(self, pid, address, size, space="user",
                       allow_fault=False, partial=False, timeout=None,
                       want_meta=False, *, max_bytes=0, allow_mmio=False):
        off = int(address) - self._base
        if off < 0 or off >= len(self._data):
            raise RuntimeError("read out of range")
        end = min(off + int(size), len(self._data))
        return bytes(self._data[off:end])

    def write_u32(self, va: int, v: int) -> None:
        off = va - self._base
        self._data[off:off + 4] = struct.pack("<I", v)


class _MockCtx:
    class _Cfg:
        def mcp_max_items(self): return 1024
    class _Session:
        _machine_info = {"": {"scan_service_version": 0}}
        def focus_view(self): return ""
    def __init__(self):
        self.cfg = self._Cfg()
        self.session = self._Session()


def _run(coro):
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


def test_value_scan_v15_eq_int32_finds_known_hit():
    """Plant a known int32 in a heap-shaped span, scan for it, check
    the snapshot carries exactly that address + value."""
    base = 0x100_000
    # Four int32s: 0, 42, 100, 42
    data = struct.pack("<IIII", 0, 42, 100, 42) + b"\x00" * 0x4000
    c = _MockClient(base, data)
    ctx = _MockCtx()
    # Clear scan registry between tests.
    _mem_scan._SCANS.clear()
    import json
    out = json.loads(_run(handle_value_scan(
        ctx, c, pid=42, address=base, size=len(data), space="user",
        kernel_lookup=False, value_type="int32", op="eq",
        value=42, value_hi="", tolerance=0, endian="le", encoding="",
        align="auto", sections="", module="",
        writable=False, executable=False, cow=False,
        include_guarded=False, mem_types=None, scope="",
        max_results=16, confirm_full_space=True, name="",
        limit=0, offset=0,
    )))
    assert out["ok"] is True, out
    d = out["data"]
    assert d["hit_count"] == 2
    hex_hits = {r["va"]: r["value"] for r in d["items"]}
    assert hex(base + 4) in hex_hits
    assert hex(base + 12) in hex_hits
    assert hex_hits[hex(base + 4)] == 42
    assert d["agent_abi"] == "v15"
    assert d["fallback"] is True


def test_value_scan_v15_then_next_scan_narrows():
    """First scan int32 == 10 (3 hits), mutate one, next_scan 'changed'
    returns just the mutated address."""
    base = 0x200_000
    data = struct.pack("<IIII", 10, 10, 10, 99)
    c = _MockClient(base, data)
    ctx = _MockCtx()
    _mem_scan._SCANS.clear()
    import json

    first = json.loads(_run(handle_value_scan(
        ctx, c, pid=1, address=base, size=16, space="user",
        kernel_lookup=False, value_type="int32", op="eq",
        value=10, value_hi="", tolerance=0, endian="le", encoding="",
        align="auto", sections="", module="",
        writable=False, executable=False, cow=False,
        include_guarded=False, mem_types=None, scope="",
        max_results=16, confirm_full_space=True, name="",
        limit=0, offset=0,
    )))
    assert first["ok"] is True
    assert first["data"]["hit_count"] == 3
    scan_id = first["data"]["scan_id"]

    # Mutate the middle 10 → 7
    c.write_u32(base + 4, 7)

    # next_scan op='changed' should keep just that one
    refined = json.loads(_run(handle_next_scan(
        ctx, c, scan_id=scan_id, op="changed",
        value="", value_hi="", delta="", tolerance=0,
        limit=0, offset=0,
    )))
    assert refined["ok"] is True
    assert refined["hit_count"] == 1
    assert refined["dropped"] == 2
    row = refined["hits"][0]
    assert row["prev_value"] == 10
    assert row["curr_value"] == 7


def test_value_scan_v15_decreased_filters_correctly():
    base = 0x300_000
    data = struct.pack("<III", 100, 100, 100)
    c = _MockClient(base, data)
    ctx = _MockCtx()
    _mem_scan._SCANS.clear()
    import json

    first = json.loads(_run(handle_value_scan(
        ctx, c, pid=1, address=base, size=12, space="user",
        kernel_lookup=False, value_type="int32", op="eq",
        value=100, value_hi="", tolerance=0, endian="le", encoding="",
        align="auto", sections="", module="",
        writable=False, executable=False, cow=False,
        include_guarded=False, mem_types=None, scope="",
        max_results=16, confirm_full_space=True, name="",
        limit=0, offset=0,
    )))
    scan_id = first["data"]["scan_id"]
    # Decrease only the middle one
    c.write_u32(base + 4, 50)
    refined = json.loads(_run(handle_next_scan(
        ctx, c, scan_id=scan_id, op="decreased",
        value="", value_hi="", delta="", tolerance=0,
        limit=0, offset=0,
    )))
    assert refined["ok"] is True
    assert refined["hit_count"] == 1


def test_scan_undo_restores_previous_generation():
    base = 0x400_000
    data = struct.pack("<II", 7, 7)
    c = _MockClient(base, data)
    ctx = _MockCtx()
    _mem_scan._SCANS.clear()
    import json

    first = json.loads(_run(handle_value_scan(
        ctx, c, pid=1, address=base, size=8, space="user",
        kernel_lookup=False, value_type="int32", op="eq",
        value=7, value_hi="", tolerance=0, endian="le", encoding="",
        align="auto", sections="", module="",
        writable=False, executable=False, cow=False,
        include_guarded=False, mem_types=None, scope="",
        max_results=16, confirm_full_space=True, name="",
        limit=0, offset=0,
    )))
    scan_id = first["data"]["scan_id"]
    assert first["data"]["hit_count"] == 2

    c.write_u32(base, 999)
    refined = json.loads(_run(handle_next_scan(
        ctx, c, scan_id=scan_id, op="eq",
        value=7, value_hi="", delta="", tolerance=0,
        limit=0, offset=0,
    )))
    assert refined["hit_count"] == 1
    assert refined["generation"] == 1

    undone = json.loads(_run(handle_scan_undo(ctx, c, scan_id=scan_id)))
    assert undone["ok"] is True
    assert undone["hit_count"] == 2
    assert undone["generation"] == 0


def test_scan_undo_empty_stack_returns_no_undo():
    from src.pry.caller import current_client_id
    _mem_scan._SCANS["v9999"] = {
        "scan_kind": "value", "owner": current_client_id(),
        "undo_stack": [],
        "snapshot_vas": __import__("array").array("Q"),
        "snapshot_raw": bytearray(), "generation": 0,
        "agent_abi": "v15",
    }
    import json
    out = json.loads(_run(handle_scan_undo(
        _MockCtx(), None, scan_id="v9999")))
    assert out["ok"] is False
    assert out["kind"] == "no_undo"
    _mem_scan._SCANS.pop("v9999", None)


def test_scan_destroy_removes_entry():
    base = 0x500_000
    data = struct.pack("<II", 5, 5)
    c = _MockClient(base, data)
    ctx = _MockCtx()
    _mem_scan._SCANS.clear()
    import json

    first = json.loads(_run(handle_value_scan(
        ctx, c, pid=1, address=base, size=8, space="user",
        kernel_lookup=False, value_type="int32", op="eq",
        value=5, value_hi="", tolerance=0, endian="le", encoding="",
        align="auto", sections="", module="",
        writable=False, executable=False, cow=False,
        include_guarded=False, mem_types=None, scope="",
        max_results=16, confirm_full_space=True, name="",
        limit=0, offset=0,
    )))
    sid = first["data"]["scan_id"]
    assert sid in _mem_scan._SCANS
    out = json.loads(_run(handle_scan_destroy(ctx, c, scan_id=sid)))
    assert out["ok"] is True
    assert sid not in _mem_scan._SCANS


def test_value_scan_whole_space_without_confirm_rejects():
    c = _MockClient(0, b"")
    ctx = _MockCtx()
    _mem_scan._SCANS.clear()
    import json
    out = json.loads(_run(handle_value_scan(
        ctx, c, pid=1, address=0, size=0, space="user",
        kernel_lookup=False, value_type="int32", op="eq",
        value=42, value_hi="", tolerance=0, endian="le", encoding="",
        align="auto", sections="", module="",
        writable=False, executable=False, cow=False,
        include_guarded=False, mem_types=None, scope="",
        max_results=16, confirm_full_space=False, name="",
        limit=0, offset=0,
    )))
    assert out["ok"] is False
    assert out["kind"] == "would_exceed"


def test_next_scan_unknown_scan_returns_unknown_scan():
    import json
    out = json.loads(_run(handle_next_scan(
        _MockCtx(), None, scan_id="nope", op="eq",
        value=1, value_hi="", delta="", tolerance=0,
        limit=0, offset=0,
    )))
    assert out["ok"] is False
    assert out["kind"] == "unknown_scan"


def test_decode_from_raw_roundtrip():
    """Smoke-check the response-formatting helper."""
    raw = struct.pack("<i", -42)
    assert _decode_from_raw(raw, 0, 4, "int32", "le", "") == -42
    raw = struct.pack("<I", 0xDEADBEEF)
    assert _decode_from_raw(raw, 0, 4, "uint32", "le", "") == 0xDEADBEEF
    raw = "hello".encode("utf-8")
    assert _decode_from_raw(raw, 0, 5, "string", "le", "utf8") == "hello"
