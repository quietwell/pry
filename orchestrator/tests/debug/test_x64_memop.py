"""Unit coverage for the AccessTrace x64 memop decoder.

The table below is a bag of canonical encodings covering every case
§4.5 of the Memory scanner wave 3 plan calls out explicitly:

  * plain ``MOV [mem], reg`` + ``MOV reg, [mem]``
  * ``CMP [mem], imm`` / ``TEST [mem], imm``
  * ``XCHG [mem], reg`` (read+write, implicit LOCK)
  * ``ADD [mem], imm`` / ``SUB [mem], imm`` (read-modify-write)
  * RIP-relative ``MOV reg, [rip+rel]``
  * memop with SIB (scale+index), displacement-only [rip-less] form
"""

from __future__ import annotations

import pytest

pytest.importorskip(
    "capstone",
    reason="capstone install pending at integration",
)

from pry.mcp.tools.debug._x64_memop import (  # noqa: E402
    Memop,
    decode_memop,
    effective_address,
)


# Each row: (name, hex-encoded instruction bytes, expected mnemonic,
#           expected Memop fields as a dict overlaying the defaults below).
#
# ``_DEFAULT_MEMOP`` keeps the common case terse — only the fields
# that differ from "simple base-register memop" are listed per-case.
_DEFAULT_MEMOP = {
    "base_reg": "none",
    "index_reg": "none",
    "scale": 1,
    "disp": 0,
    "size_bytes": 0,
    "access": "read",
    "rip_relative": False,
}


_CASES: list[tuple[str, str, str, dict]] = [
    # MOV [rdi], rax  -> 48 89 07    (write-only, 8-byte)
    ("mov_write_qword", "48 89 07", "mov",
     {"base_reg": "rdi", "size_bytes": 8, "access": "write"}),

    # MOV rax, [rdi]  -> 48 8b 07    (read-only, 8-byte)
    ("mov_read_qword", "48 8b 07", "mov",
     {"base_reg": "rdi", "size_bytes": 8, "access": "read"}),

    # MOV dword ptr [rbx], 0x11223344 -> c7 03 44 33 22 11
    ("mov_imm_to_mem_dword", "c7 03 44 33 22 11", "mov",
     {"base_reg": "rbx", "size_bytes": 4, "access": "write"}),

    # CMP qword ptr [rcx], 0x7f -> 48 83 39 7f   (read only)
    ("cmp_mem_imm", "48 83 39 7f", "cmp",
     {"base_reg": "rcx", "size_bytes": 8, "access": "read"}),

    # TEST byte ptr [rdx], 1 -> f6 02 01   (read only)
    ("test_mem_imm", "f6 02 01", "test",
     {"base_reg": "rdx", "size_bytes": 1, "access": "read"}),

    # XCHG [r8], rax -> 49 87 00    (locked rmw on memop)
    ("xchg_mem_reg", "49 87 00", "xchg",
     {"base_reg": "r8", "size_bytes": 8, "access": "rw"}),

    # ADD qword ptr [rsi], 0x10 -> 48 83 06 10  (rmw)
    ("add_mem_imm", "48 83 06 10", "add",
     {"base_reg": "rsi", "size_bytes": 8, "access": "rw"}),

    # SUB dword ptr [rbp+0x20], 1 -> 83 6d 20 01  (rmw, disp8)
    ("sub_mem_imm_disp8", "83 6d 20 01", "sub",
     {"base_reg": "rbp", "disp": 0x20, "size_bytes": 4, "access": "rw"}),

    # MOV rax, [rip+0x100]  -> 48 8b 05 00 01 00 00    (RIP-relative read)
    # Capstone's mem.disp field is the raw displacement encoded in the
    # instruction (0x100), independent of RIP; the effective address
    # computation adds rip_next when ``rip_relative=True``. We exercise
    # the RIP-relative resolution path in test_effective_address_*
    # below, so here we just confirm the decoder flags it and keeps
    # the raw disp.
    ("mov_read_rip_rel", "48 8b 05 00 01 00 00", "mov",
     {"base_reg": "rip", "disp": 0x100, "size_bytes": 8,
      "access": "read", "rip_relative": True}),

    # MOV dword ptr [rax+rcx*4], edx -> 89 14 88     (SIB, scale 4, no disp)
    ("mov_sib_write", "89 14 88", "mov",
     {"base_reg": "rax", "index_reg": "rcx", "scale": 4,
      "size_bytes": 4, "access": "write"}),
]


def _hexbytes(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


@pytest.mark.parametrize("case", _CASES, ids=[c[0] for c in _CASES])
def test_decode_memop_table(case):
    name, hex_s, expect_mn, overrides = case
    memop = decode_memop(_hexbytes(hex_s), rip=0)
    assert memop is not None, f"{name}: decode returned None"
    assert memop.mnemonic == expect_mn, (
        f"{name}: mnemonic {memop.mnemonic!r} != {expect_mn!r}")
    expected = dict(_DEFAULT_MEMOP)
    expected.update(overrides)
    for field, want in expected.items():
        got = getattr(memop, field)
        assert got == want, (
            f"{name}: {field}={got!r} (expected {want!r})"
        )


def test_decode_memop_no_memop_returns_none():
    # NOP (90) has no memory operand.
    assert decode_memop(b"\x90") is None
    # XOR rax, rax -> 48 31 c0 (pure register op)
    assert decode_memop(b"\x48\x31\xc0") is None


def test_decode_memop_undecodable_bytes_returns_none():
    # All-zero bytes decode as "add byte ptr [rax], al" on x64, which
    # IS a valid memop — so pick a known-invalid prefix soup instead.
    # Three LOCK prefixes in a row is not a legal encoding.
    assert decode_memop(b"\xf0\xf0\xf0") is None


def test_effective_address_base_only():
    memop = Memop(
        mnemonic="mov", base_reg="rdi", index_reg="none",
        scale=1, disp=0, size_bytes=8, access="write",
        rip_relative=False,
    )
    ea = effective_address(memop, {"rdi": 0x7ffe_8000})
    assert ea == 0x7ffe_8000


def test_effective_address_sib_with_disp():
    memop = Memop(
        mnemonic="mov", base_reg="rax", index_reg="rcx",
        scale=4, disp=0x40, size_bytes=4, access="write",
        rip_relative=False,
    )
    ea = effective_address(memop, {"rax": 0x1000, "rcx": 3})
    assert ea == 0x1000 + 3 * 4 + 0x40


def test_effective_address_rip_relative_uses_rip_next():
    # Simulate "MOV rax, [rip+0x100]" at RIP 0x7ffe_0000 with next
    # instruction at +7 bytes.
    memop = Memop(
        mnemonic="mov", base_reg="rip", index_reg="none",
        scale=1, disp=0x100, size_bytes=8, access="read",
        rip_relative=True,
    )
    ea = effective_address(memop, {}, rip_next=0x7ffe_0007)
    assert ea == 0x7ffe_0007 + 0x100
