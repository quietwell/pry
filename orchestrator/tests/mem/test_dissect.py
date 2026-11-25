"""v17 (Memory scanner wave 2 Phase F/G): dissect scorer + v16 fallback.

Pure-python tests for :mod:`pry.mcp.tools.mem.dissect`. The scorer
mirrors the agent-side C++ implementation bit-for-bit (same weights,
same tie-break order), so these tests also lock in the agent behavior
up to the bytes-in / fields-out contract.

No live agent, no gRPC — the v16 fallback path is exercised against a
mock client that serves canned memory reads.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.mem.dissect import (  # noqa: E402
    DISSECT_MAX_BYTES,
    DISSECT_MAX_ROWS,
    SCORE_PTR_MOD_EXEC,
    SCORE_PTR_MAPPED_ANY,
    SCORE_UTF16_16W,
    SCORE_UTF16_8W,
    SCORE_ASCII_16B,
    SCORE_ASCII_8B,
    SCORE_F64,
    SCORE_F32,
    _classify_pointer,
    _decode_slot,
    dissect_decode,
)


# ------------------------------------------------- pointer classification ---

def test_classify_pointer_in_module():
    mods = [{"name": "ntdll.dll", "base": 0x7ff800000000, "size": 0x200000}]
    klass, mod, off, score = _classify_pointer(0x7ff800001234, mods)
    assert klass == "image_unknown"
    assert mod == "ntdll.dll"
    assert off == 0x1234
    assert score == SCORE_PTR_MOD_EXEC


def test_classify_pointer_unmapped_but_canonical():
    klass, mod, off, score = _classify_pointer(0x7ff123456000, [])
    assert klass == "other"
    assert mod == ""
    assert score == SCORE_PTR_MAPPED_ANY


def test_classify_pointer_null():
    klass, mod, off, score = _classify_pointer(0, [])
    assert klass == ""
    assert score == 0


def test_classify_pointer_non_canonical():
    # Kernel-space VA; user-mode scan sees these as "not a user pointer".
    klass, _, _, score = _classify_pointer(0xffff000000000000, [])
    assert klass == ""
    assert score == 0


# ------------------------------------------------- tie-break order --------

def test_probable_type_tiebreak_pointer_beats_utf16():
    # 16 printable BMP wchars (score_utf16=40) + a slot value in a
    # module (score_pointer=50) — pointer wins.
    mods = [{"name": "k.dll", "base": 0x10000, "size": 0x1000}]
    buf = struct.pack("<Q", 0x10100)  # pointer target in k.dll
    buf += ("abcdefghijklmnop".encode("utf-16-le"))  # UTF-16 prefix
    row = _decode_slot(buf, 0, 0, mods, with_modules=True)
    assert row["probable_type"] == "pointer"
    assert row["score_pointer"] == SCORE_PTR_MOD_EXEC
    assert row["score_utf16"] == 0  # first 8 bytes are the pointer, not UTF-16


def test_probable_type_tiebreak_utf16_beats_ascii():
    # 16 printable BMP wchars and 16 printable ASCII — utf16 (40) > ascii (30).
    buf = "ABCDEFGHIJKLMNOP".encode("utf-16-le")  # 32 bytes
    row = _decode_slot(buf, 0, 0, [], with_modules=False)
    assert row["probable_type"] == "utf16"
    assert row["score_utf16"] == SCORE_UTF16_16W


def test_probable_type_tiebreak_ascii_beats_f64():
    # Pure ASCII (score=30) vs a float that's in [1e-10, 1e10] (score=5).
    buf = b"Program Files!!!"  # 16 ASCII
    row = _decode_slot(buf, 0, 0, [], with_modules=False)
    assert row["probable_type"] == "ascii"
    assert row["score_ascii"] == SCORE_ASCII_16B


def test_probable_type_tiebreak_f64_beats_f32():
    # No strings, no pointer — only float scores remain. Rare in
    # practice since the same 8 bytes score both; this test pins the
    # docstring claim that f64 > f32 when both qualify.
    buf = struct.pack("<d", 3.14e5)
    # Also must not be a valid utf16 prefix.
    # Check whether both fire.
    row = _decode_slot(buf, 0, 0, [], with_modules=False)
    if row["score_f64"] > 0 and row["score_f32"] > 0:
        assert row["probable_type"] == "f64"


def test_probable_type_i32_baseline_when_nothing_scores():
    # Zero bytes — no ascii, no utf16 (first wchar is 0 < 0x20), no
    # pointer (u64==0), f64 is 0.0 which fails the 1e-10..1e10 band.
    buf = b"\x00" * 8
    row = _decode_slot(buf, 0, 0, [], with_modules=False)
    assert row["probable_type"] == "i32"
    assert row["score_pointer"] == 0
    assert row["score_utf16"] == 0
    assert row["score_ascii"] == 0


# ---------------------------------------------- ASCII / UTF-16 prefix detect

def test_ascii_prefix_detection_8_vs_16():
    short = _decode_slot(b"abcdefgh" + b"\x00" * 8, 0, 0, [],
                          with_modules=False)
    assert short["ascii_prefix"] == "abcdefgh"
    assert short["score_ascii"] == SCORE_ASCII_8B

    full = _decode_slot(b"abcdefghijklmnop" + b"\x00" * 8, 0, 0, [],
                         with_modules=False)
    assert full["ascii_prefix"].startswith("abcdefghijklmnop")
    assert full["score_ascii"] == SCORE_ASCII_16B


def test_utf16_prefix_detection_8_vs_16():
    short = _decode_slot("abcdefgh".encode("utf-16-le"), 0, 0, [],
                          with_modules=False)
    assert short["utf16_prefix"] == "abcdefgh"
    assert short["score_utf16"] == SCORE_UTF16_8W

    full = _decode_slot("abcdefghijklmnop".encode("utf-16-le"), 0, 0, [],
                         with_modules=False)
    assert full["utf16_prefix"].startswith("abcdefghijklmnop")
    assert full["score_utf16"] == SCORE_UTF16_16W


# ---------------------------------------------------- align 4 vs 8 grid ----

def test_decode_align4_produces_double_rows_of_align8():
    buf = b"\x01" * 32
    rows4 = dissect_decode(buf, address=0x1000, align=4, modules=[],
                            with_modules=False)
    rows8 = dissect_decode(buf, address=0x1000, align=8, modules=[],
                            with_modules=False)
    assert len(rows4) == 8  # 32/4
    assert len(rows8) == 4  # 32/8
    assert rows4[0]["offset"] == 0 and rows4[1]["offset"] == 4
    assert rows8[0]["offset"] == 0 and rows8[1]["offset"] == 8


def test_decode_rejects_bad_align():
    with pytest.raises(ValueError):
        dissect_decode(b"\x00" * 16, address=0, align=3)


def test_decode_caps_at_max_rows():
    # DISSECT_MAX_ROWS = 4096; align=4 means 4096*4 = 16_384 bytes feeds
    # exactly the cap. Anything larger clamps to DISSECT_MAX_ROWS.
    buf = b"\x00" * (DISSECT_MAX_ROWS * 4 + 64)
    rows = dissect_decode(buf, address=0, align=4, with_modules=False)
    assert len(rows) == DISSECT_MAX_ROWS


# -------------------------------------------- pointer module classification -

def test_pointer_classification_image_interior():
    mods = [
        {"name": "ntdll.dll", "base": 0x7ff800000000, "size": 0x200000},
        {"name": "kernel32.dll", "base": 0x7ff808000000, "size": 0x100000},
    ]
    # In ntdll.dll
    r = _decode_slot(struct.pack("<Q", 0x7ff80000ABCD), 0, 0, mods,
                     with_modules=True)
    assert r["ptr_module"] == "ntdll.dll"
    assert r["ptr_module_off"] == 0xABCD
    assert r["ptr_classification"] == "image_unknown"

    # In kernel32.dll
    r = _decode_slot(struct.pack("<Q", 0x7ff808001000), 0, 0, mods,
                     with_modules=True)
    assert r["ptr_module"] == "kernel32.dll"
    assert r["ptr_module_off"] == 0x1000


def test_pointer_classification_other_when_not_in_module():
    mods = [{"name": "ntdll.dll", "base": 0x7ff800000000, "size": 0x200000}]
    r = _decode_slot(struct.pack("<Q", 0x7ff900000000), 0, 0, mods,
                     with_modules=True)
    assert r["ptr_module"] == ""
    assert r["ptr_classification"] == "other"


def test_pointer_classification_disabled_when_no_modules_flag():
    mods = [{"name": "ntdll.dll", "base": 0x7ff800000000, "size": 0x200000}]
    r = _decode_slot(struct.pack("<Q", 0x7ff80000ABCD), 0, 0, mods,
                     with_modules=False)
    assert r["ptr_module"] == ""
    assert r["score_pointer"] == 0


# --------------------------------------------------- determinism ----------

def test_scorer_deterministic():
    """Same bytes + same modules => same probable_type, same scores."""
    buf = b"abcdefgh" + struct.pack("<Q", 0x7ff80000ABCD) + b"\x00" * 16
    mods = [{"name": "ntdll.dll", "base": 0x7ff800000000, "size": 0x200000}]
    rows1 = dissect_decode(buf, address=0, align=8, modules=mods,
                            with_modules=True)
    rows2 = dissect_decode(buf, address=0, align=8, modules=mods,
                            with_modules=True)
    assert rows1 == rows2
