"""SI #1 image-coherency orchestrator-side classifier.

Pure-Python unit tests over fabricated ``MismatchRange`` + section
layout dicts. Validates every label the classifier can emit:

* clean (no mismatches)
* iat_hooked (every mismatch inside an IAT thunk run)
* inline_hooked (short run near a .text start)
* section_overwritten (>60% of a section mismatched)
* relocs_unresolved (reloc dir overlap, drift signal)
* unknown (none of the above)
"""

from __future__ import annotations

import pytest

from pry.analysis.coherency import classify


_SECTIONS_X64 = [
    {"name": ".text", "va": 0x1000, "size": 0x2000, "characteristics": 0x60000020},
    {"name": ".rdata", "va": 0x3000, "size": 0x1000, "characteristics": 0x40000040},
    {"name": ".data", "va": 0x4000, "size": 0x1000, "characteristics": 0xC0000040},
    {"name": ".idata", "va": 0x5000, "size": 0x400, "characteristics": 0x40000040},
    {"name": ".reloc", "va": 0x6000, "size": 0x200, "characteristics": 0x42000040},
]


def test_classify_clean_on_empty() -> None:
    assert classify([], sections=_SECTIONS_X64) == "clean"


def test_classify_iat_from_section_name() -> None:
    mismatches = [
        {"rva": 0x5000, "length": 8, "section": ".idata", "hint": ""},
        {"rva": 0x5020, "length": 8, "section": ".idata", "hint": ""},
    ]
    assert classify(mismatches, sections=_SECTIONS_X64) == "iat_hooked"


def test_classify_iat_from_hint() -> None:
    mismatches = [
        {"rva": 0x1200, "length": 8, "section": ".text", "hint": "iat_slot"},
    ]
    assert classify(mismatches, sections=_SECTIONS_X64) == "iat_hooked"


def test_classify_inline_hook_short_text_run_near_start() -> None:
    mismatches = [
        {"rva": 0x1000, "length": 5, "section": ".text", "hint": ""},
    ]
    assert classify(mismatches, sections=_SECTIONS_X64) == "inline_hooked"


def test_classify_section_overwritten_60pct() -> None:
    mismatches = [
        {"rva": 0x3000, "length": 0xA00, "section": ".rdata", "hint": ""},
    ]
    assert classify(mismatches, sections=_SECTIONS_X64) == "section_overwritten"


def test_classify_relocs_unresolved_on_reloc_overlap() -> None:
    mismatches = [
        {"rva": 0x6020, "length": 32, "section": ".reloc", "hint": "reloc"},
    ]
    out = classify(mismatches, sections=_SECTIONS_X64,
                   reloc_dir=(0x6000, 0x200))
    assert out == "relocs_unresolved"


def test_classify_unknown_fallback() -> None:
    mismatches = [
        {"rva": 0x4080, "length": 0x40, "section": ".data", "hint": ""},
    ]
    out = classify(mismatches, sections=_SECTIONS_X64)
    assert out == "unknown"


def test_classify_handles_missing_fields_gracefully() -> None:
    mismatches = [{"rva": 0x1004, "length": 4}]
    out = classify(mismatches, sections=_SECTIONS_X64)
    assert out in {"inline_hooked", "unknown"}


def test_classify_bad_row_tolerated() -> None:
    """A bad row poisons the per-bucket tracking but does not raise;
    the overall label falls back to 'unknown'."""
    mismatches = [
        {"rva": "nope", "length": 8},
        {"rva": 0x1000, "length": 5, "section": ".text"},
    ]
    out = classify(mismatches, sections=_SECTIONS_X64)
    assert out in {"unknown", "inline_hooked"}
