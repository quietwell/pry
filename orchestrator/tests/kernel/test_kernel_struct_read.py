"""Memory scanner wave 3 §6 — ``kernel_manage(action='struct_read')``.

These tests mock out the two inputs the handler composes
(``symbols_manage(action='layout')`` + ``memory_manage(action='read',
view='kernel')``) so they need neither a live agent nor a cached PDB.
The focus is on the field decoder:

* ``scalar`` — 1/2/4/8-byte little-endian unpack.
* ``ptr``    — raw ``u64``.
* ``string_ansi`` — fixed CHAR array trimmed at the first NUL.
* ``string_us``   — UNICODE_STRING header + follow-on buffer read.
* Partial reads — a kernel_read_failed on one field does not take
  down the response; it lands in ``errors[]`` with ``partial: true``.
"""
from __future__ import annotations

import asyncio
import struct
import sys
from pathlib import Path

import pytest  # noqa: F401 — collector-side marker

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.kernel import _struct_read  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ----------------------------------------------------------------------
# Synthetic EPROCESS-like blob — one byte stream with every supported
# kind laid out at known offsets. Keeps the memory fixture close to the
# decoder so a layout change here is loud.
# ----------------------------------------------------------------------

# Layout the decoder consumes — mirrors `symbols_manage.layout` output
# after `_normalise_layout`. Covers every supported `kind`.
FIVE_FIELD_LAYOUT = {
    # 4-byte scalar — Flags
    "Flags":           {"offset": 0x40, "size": 4, "kind": "scalar"},
    # 8-byte scalar — UniqueProcessId
    "UniqueProcessId": {"offset": 0x80, "size": 8, "kind": "scalar"},
    # 8-byte pointer — Peb
    "Peb":             {"offset": 0xA0, "size": 8, "kind": "ptr"},
    # 15-byte CHAR[15] — ImageFileName, trims at NUL
    "ImageFileName":   {"offset": 0xC0, "size": 15, "kind": "string_ansi"},
    # UNICODE_STRING header at 0xE0, buffer at a follow-on VA
    "ImagePathName":   {"offset": 0xE0, "size": 16, "kind": "string_us"},
}

EPROCESS_BASE = 0xFFFF_E000_1234_5000
BUFFER_VA     = 0x0000_7FF6_0000_1000


def _make_memory() -> dict[int, bytes]:
    """Lay out a sparse address map keyed by VA -> bytes.

    The reader fixture answers any (va, size) range by slicing out of
    this map. Keeping the map sparse keeps the assertions readable.
    """
    mem: dict[int, bytes] = {}
    # Flags = 0xDEADBEEF
    mem[EPROCESS_BASE + 0x40] = struct.pack("<I", 0xDEADBEEF)
    # UniqueProcessId = 4242
    mem[EPROCESS_BASE + 0x80] = struct.pack("<Q", 4242)
    # Peb = BUFFER_VA + 0x800 (arbitrary non-null kernel pointer)
    mem[EPROCESS_BASE + 0xA0] = struct.pack("<Q", 0xFFFF_8ABC_DEF0_1234)
    # ImageFileName = "notepad.exe\x00\x00\x00\x00" trimmed to "notepad.exe"
    name = b"notepad.exe\x00\x00\x00\x00"[:15]
    mem[EPROCESS_BASE + 0xC0] = name
    # UNICODE_STRING: Length=16 (8 wchars), Max=40, Buffer=BUFFER_VA
    mem[EPROCESS_BASE + 0xE0] = (
        struct.pack("<HHI", 16, 40, 0) + struct.pack("<Q", BUFFER_VA)
    )
    # UNICODE_STRING body at BUFFER_VA — 8 wchars ("C:\\x.exe") in UTF-16-LE
    mem[BUFFER_VA] = "C:\\x.exe".encode("utf-16-le")
    return mem


def _make_reader(mem: dict[int, bytes], *, failing_vas: set[int] | None = None):
    async def read(va: int, size: int) -> bytes:
        if failing_vas and va in failing_vas:
            raise RuntimeError(f"kernel read failed @ 0x{va:x}")
        # Exact-key lookup first; otherwise linear search over keys that
        # *contain* [va, va+size).
        if va in mem and len(mem[va]) >= size:
            return mem[va][:size]
        for k, buf in mem.items():
            if k <= va < k + len(buf):
                off = va - k
                return buf[off:off + size]
        raise RuntimeError(f"no fixture for va=0x{va:x} size={size}")
    return read


# ----------------------------------------------------------------------
# Decoder round-trip
# ----------------------------------------------------------------------

def test_decode_fields_covers_all_four_kinds():
    mem = _make_memory()
    reader = _make_reader(mem)
    fields, errors = _run(_struct_read.decode_fields(
        reader, EPROCESS_BASE, FIVE_FIELD_LAYOUT,
        ["Flags", "UniqueProcessId", "Peb", "ImageFileName",
         "ImagePathName"]))
    assert errors == []
    assert fields["Flags"] == 0xDEADBEEF
    assert fields["UniqueProcessId"] == 4242
    assert fields["Peb"] == 0xFFFF_8ABC_DEF0_1234
    assert fields["ImageFileName"] == "notepad.exe"
    assert fields["ImagePathName"] == "C:\\x.exe"


def test_decode_fields_default_is_scalar_only():
    """``fields=None`` returns every top-level *scalar* field — the
    plan's §6.2 default avoids pulling huge string bodies unless asked.
    """
    mem = _make_memory()
    reader = _make_reader(mem)
    fields, errors = _run(_struct_read.decode_fields(
        reader, EPROCESS_BASE, FIVE_FIELD_LAYOUT, None))
    assert errors == []
    assert set(fields.keys()) == {"Flags", "UniqueProcessId"}


def test_decode_fields_unknown_name_lands_in_errors():
    mem = _make_memory()
    reader = _make_reader(mem)
    fields, errors = _run(_struct_read.decode_fields(
        reader, EPROCESS_BASE, FIVE_FIELD_LAYOUT,
        ["Flags", "Bogus"]))
    assert fields["Flags"] == 0xDEADBEEF
    assert any(e["field"] == "Bogus" and e["kind"] == "field_not_in_layout"
               for e in errors)


def test_decode_fields_partial_on_read_failure():
    """One failing field must not take down the whole response."""
    mem = _make_memory()
    reader = _make_reader(mem,
                          failing_vas={EPROCESS_BASE + 0x80})
    fields, errors = _run(_struct_read.decode_fields(
        reader, EPROCESS_BASE, FIVE_FIELD_LAYOUT,
        ["Flags", "UniqueProcessId", "ImageFileName"]))
    # UniqueProcessId fails; the other two still return.
    assert fields["Flags"] == 0xDEADBEEF
    assert fields["ImageFileName"] == "notepad.exe"
    assert "UniqueProcessId" not in fields
    assert any(e["field"] == "UniqueProcessId" for e in errors)


def test_decode_fields_scalar_sizes():
    """1/2/4/8-byte scalar sizes all round-trip through the unpacker."""
    mem = {
        0x1000: bytes([0xAB]),
        0x1010: struct.pack("<H", 0xBEEF),
        0x1020: struct.pack("<I", 0xCAFEBABE),
        0x1030: struct.pack("<Q", 0x1122_3344_5566_7788),
    }
    layout = {
        "u8":  {"offset": 0, "size": 1, "kind": "scalar"},
        "u16": {"offset": 0x10, "size": 2, "kind": "scalar"},
        "u32": {"offset": 0x20, "size": 4, "kind": "scalar"},
        "u64": {"offset": 0x30, "size": 8, "kind": "scalar"},
    }
    fields, errors = _run(_struct_read.decode_fields(
        _make_reader(mem), 0x1000, layout,
        ["u8", "u16", "u32", "u64"]))
    assert errors == []
    assert fields == {"u8": 0xAB, "u16": 0xBEEF,
                      "u32": 0xCAFEBABE,
                      "u64": 0x1122_3344_5566_7788}


# ----------------------------------------------------------------------
# PDB layout -> normalised shape
# ----------------------------------------------------------------------

def test_normalise_layout_from_pdb_members():
    """`symbols_manage.layout` returns a `members` list with a `type`
    string — _normalise_layout must infer the kind from the type."""
    pdb_layout = {
        "ok": True, "name": "_EPROCESS", "size": 0x800,
        "members": [
            {"name": "Flags", "offset": 0x40, "size": 4,
             "type": "unsigned long"},
            {"name": "UniqueProcessId", "offset": 0x80, "size": 8,
             "type": "HANDLE"},
            {"name": "Peb", "offset": 0xA0, "size": 8, "type": "_PEB*"},
            {"name": "ImageFileName", "offset": 0xC0, "size": 15,
             "type": "UCHAR[15]"},
            {"name": "ImagePathName", "offset": 0xE0, "size": 16,
             "type": "_UNICODE_STRING"},
            # A bitfield — decoder skips it rather than returning
            # partial bits.
            {"name": "Flags2", "offset": 0x44, "size": 4,
             "type": "unsigned long", "bit_position": 1, "bit_length": 1},
        ],
    }
    layout = _struct_read._normalise_layout(pdb_layout)
    assert layout["Flags"] == {"offset": 0x40, "size": 4, "kind": "scalar"}
    assert layout["UniqueProcessId"]["kind"] == "scalar"
    assert layout["Peb"]["kind"] == "ptr"
    assert layout["ImageFileName"]["kind"] == "string_ansi"
    assert layout["ImagePathName"]["kind"] == "string_us"
    # Bitfield is skipped — the Wave 3 decoder can't slice bits.
    assert "Flags2" not in layout


def test_normalise_layout_from_baked_json_skips_null_offsets():
    """A placeholder field (offset: null) must not land in the
    normalised dict — the loader treats null as "unverified, miss".
    """
    baked = {
        "UniqueProcessId": {"offset": "0x1e8", "size": 8, "kind": "scalar"},
        "Peb":             {"offset": None, "size": 8, "kind": "ptr"},
    }
    layout = _struct_read._normalise_layout(baked)
    assert "UniqueProcessId" in layout
    assert layout["UniqueProcessId"]["offset"] == 0x1E8
    assert "Peb" not in layout


# ----------------------------------------------------------------------
# Handler: a null-offset baked stub must not block the invariant walker
# ----------------------------------------------------------------------

import json  # noqa: E402
from types import SimpleNamespace  # noqa: E402

_APL = 0x1F0
_UPID = 0x1E8
_IMG = 0x5A8
_RING = (0xFFFF_E000_1000_0000, 0xFFFF_E000_2000_0000,
         0xFFFF_E000_3000_0000)

# The shape of artifacts/invariants/eprocess/*.json today: every
# offset is a null placeholder.
_NULL_STUB = {
    "build": "26100", "arch": "x64", "type_name": "_EPROCESS",
    "eprocess": {
        "UniqueProcessId":    {"offset": None, "size": 8,
                               "kind": "scalar"},
        "ActiveProcessLinks": {"offset": None, "size": 16, "kind": "ptr"},
        "ImageFileName":      {"offset": None, "size": 15,
                               "kind": "string_ansi"},
    },
    "assertion": {"dispatcher_header_type_at": "0x00",
                  "dispatcher_header_type_value": "0x03"},
}


def _ring_memory() -> dict[int, bytes]:
    """Three EPROCESS-like blocks linked through ActiveProcessLinks."""
    mem: dict[int, bytes] = {}
    pids = (100, 4242, 1234)
    names = (b"system", b"notepad.exe", b"explorer.exe")
    for i, base in enumerate(_RING):
        blob = bytearray(0x800)
        blob[0] = 0x03                       # DISPATCHER_HEADER ProcessObject
        struct.pack_into("<Q", blob, _UPID, pids[i])
        struct.pack_into("<QQ", blob, _APL,
                         _RING[(i + 1) % 3] + _APL, _RING[i - 1] + _APL)
        blob[_IMG:_IMG + 15] = names[i].ljust(15, b"\x00")
        mem[base] = bytes(blob)
    return mem


class _FakeClient:
    def __init__(self, mem: dict[int, bytes]):
        self._read = _make_reader(mem)

    async def host_info(self, **_kw):
        return {"ok": True, "build_major": 26100,
                "full_build_string": "26100.1"}

    async def mem_read(self, _pid, va, size, _view):
        return await self._read(va, size)


def _struct_read_with_stub(monkeypatch, tmp_path, lookup_by):
    async def no_pdb(*_a, **_kw):
        return None, {"ok": False, "kind": "pdb_missing", "error": "no pdb"}

    monkeypatch.setattr(_struct_read, "_resolve_pdb_layout", no_pdb)
    monkeypatch.setattr(_struct_read._invariants, "load_baked",
                        lambda *_a, **_kw: _NULL_STUB)
    ctx = SimpleNamespace(
        session=SimpleNamespace(view_kind_of=lambda _n: "kernel"),
        cfg=SimpleNamespace(artifacts_dir=lambda: tmp_path))
    out = _run(_struct_read.handle_struct_read(
        ctx, _FakeClient(_ring_memory()), name="lab.kernel", module="",
        type_name="_EPROCESS", va=hex(_RING[1]), lookup_by=lookup_by,
        fields=None, max_depth=1))
    return json.loads(out)


def test_null_offset_stub_falls_through_to_invariant_walker(
        monkeypatch, tmp_path):
    res = _struct_read_with_stub(monkeypatch, tmp_path,
                                 {"pid": 4242, "allow_invariant": True})
    assert res["ok"], res
    assert res["layout_source"] == "invariant_scan"
    upid = res["fields"]["UniqueProcessId"]
    assert (upid if isinstance(upid, int) else int(upid, 0)) == 4242
    assert (tmp_path / "invariants" / "eprocess"
            / "26100.1.discovered.json").is_file()


def test_null_offset_stub_without_walker_reports_offsets_unknown(
        monkeypatch, tmp_path):
    res = _struct_read_with_stub(monkeypatch, tmp_path, None)
    assert res["ok"] is False
    assert res["kind"] == "eprocess_offsets_unknown"
    assert "stub" in res["error"]
    assert res["assertion_source"]["source"] == "baked_stub"


# ----------------------------------------------------------------------
# Handler: walker results are cached per build and reused, gated
# ----------------------------------------------------------------------

_WALK = {"pid": 4242, "allow_invariant": True}


def _forbid_rescan(monkeypatch):
    async def no_scan(*_a, **_kw):
        raise AssertionError("walker rescanned despite a valid cache")
    monkeypatch.setattr(_struct_read._invariants.InvariantFieldFinder,
                        "scan", no_scan)


def test_second_walker_call_reuses_discovered_cache(monkeypatch, tmp_path):
    first = _struct_read_with_stub(monkeypatch, tmp_path, _WALK)
    assert first["layout_source"] == "invariant_scan"
    _forbid_rescan(monkeypatch)
    second = _struct_read_with_stub(monkeypatch, tmp_path, _WALK)
    assert second["ok"], second
    assert second["layout_source"] == "discovered_cache"
    upid = second["fields"]["UniqueProcessId"]
    assert (upid if isinstance(upid, int) else int(upid, 0)) == 4242


def test_discovered_cache_with_wrong_pid_offset_is_rescanned(
        monkeypatch, tmp_path):
    # A bad cache entry: UniqueProcessId points at a zero slot.
    _struct_read._invariants.cache_discovered(
        "26100.1",
        {"ActiveProcessLinks": {"offset": _APL, "size": 16, "kind": "ptr"},
         "UniqueProcessId": {"offset": 0x1E0, "size": 8, "kind": "scalar"}},
        tmp_path)
    res = _struct_read_with_stub(monkeypatch, tmp_path, _WALK)
    assert res["layout_source"] == "invariant_scan"
    fixed = _struct_read._invariants.load_discovered("26100.1", tmp_path)
    assert fixed["UniqueProcessId"]["offset"] == _UPID


def test_discovered_cache_needs_allow_invariant(monkeypatch, tmp_path):
    _struct_read_with_stub(monkeypatch, tmp_path, _WALK)
    res = _struct_read_with_stub(monkeypatch, tmp_path, None)
    assert res["ok"] is False
    assert res["kind"] == "eprocess_offsets_unknown"
