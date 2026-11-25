"""x86_64 memop decoder — thin Capstone wrapper.

AccessTrace's job for every ``BP_HIT`` is to answer two questions:

1. Which memory address did the hit actually touch? The DR6 ``B``-bits
   plus the per-slot watched address answer this for pure reads/writes,
   but a ``MOV [rdi], rax`` records only ``[rdi]`` in the trap context
   — the orchestrator needs to decode the instruction at RIP, resolve
   the memory operand's registers against the live GPR bank, and
   compute the effective address so the hit record carries the
   *actual* byte range touched (not just the DR slot's address).

2. What *kind* of access was it? ``CMP [mem], imm`` reads but DR6 will
   report it as a write on some CPUs (Intel RW-breakpoint semantics);
   using the decoded Capstone access classification is the authority.

The decoder is deliberately narrow: it returns the FIRST memory operand
of the instruction at RIP, as a :class:`Memop` dataclass. Instructions
with no memory operand (pure register ops) return ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Memop:
    """First memory operand of the instruction at RIP.

    Fields mirror Capstone's ``X86OpMem`` plus the mnemonic-derived
    access classification. Register names are the lowercase Capstone
    spelling (``"rax"``, ``"rip"``, ``"none"`` when unused). ``scale``
    is 1 when the operand has no SIB index. ``access`` is one of
    ``"read"``, ``"write"``, ``"rw"``.
    """

    mnemonic: str
    base_reg: str
    index_reg: str
    scale: int
    disp: int
    size_bytes: int
    access: str
    rip_relative: bool


# Capstone "access" bitfield values. Import lazily so the module stays
# importable in environments where capstone is not yet installed
# (``decode_memop`` raises a clean ``RuntimeError`` in that case).
_CS_AC_READ = 1
_CS_AC_WRITE = 2


def _mnemonic_access(mnemonic: str, op_access: int) -> str:
    """Return ``"read"`` / ``"write"`` / ``"rw"``.

    Capstone's per-operand ``access`` bitfield is usually enough, but
    the plan's §4.5 enumerated corner cases are:

      * ``CMP/TEST [mem], imm`` — the memory operand is read only, which
        Capstone classifies correctly.
      * ``XCHG [mem], reg`` — Capstone reports both bits.
      * ``ADD/SUB [mem], imm`` — read-modify-write; both bits.
      * ``MOV [mem], reg`` — write only.
      * ``MOV reg, [rip+rel]`` — read only.

    We trust Capstone's bits; the switch below only exists so a
    pre-5.x binding (which left ``access`` zero for memory operands) is
    not silently misclassified. Capstone 5.0+ fills the bits.
    """
    if op_access:
        if (op_access & _CS_AC_READ) and (op_access & _CS_AC_WRITE):
            return "rw"
        if op_access & _CS_AC_WRITE:
            return "write"
        return "read"
    # Pre-5.x fallback — infer from mnemonic. Keep the list short; the
    # plan's §4.5 enumerates exactly which encodings matter.
    m = mnemonic.lower().split()[0]
    if m in ("cmp", "test"):
        return "read"
    if m in ("xchg", "add", "sub", "adc", "sbb", "and", "or", "xor",
             "inc", "dec", "not", "neg", "shl", "shr", "sar", "rol",
             "ror", "rcl", "rcr", "btc", "btr", "bts", "cmpxchg",
             "xadd"):
        return "rw"
    if m in ("mov", "movs", "movq", "movdqu", "movdqa", "stos",
             "push", "lea"):
        # lea is special (never actually dereferences), but a watched
        # lea against a DR slot still fires; the "access" is write to
        # the destination register but read-only against the memop's
        # effective address bytes. We conservatively return "read" so
        # a DR armed as "write" does not spuriously classify a lea hit.
        return "read" if m == "lea" else "write"
    return "read"


def decode_memop(rip_bytes: bytes, rip: int = 0) -> Optional[Memop]:
    """Decode the instruction at *rip_bytes* and return its first memory
    operand.

    *rip* is the virtual address the bytes were read from; passing it
    lets Capstone compute the real target of RIP-relative addressing
    (``MOV rax, [rip+0x1234]``). ``rip=0`` still decodes, but the
    returned ``disp`` is the raw displacement, not the resolved VA.

    Returns :class:`Memop` on success, or ``None`` when:

      * capstone cannot decode the bytes (``cs_disasm`` returned nothing)
      * the decoded instruction has no memory operand
    """
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
        from capstone.x86 import X86_REG_INVALID
    except ImportError as exc:  # pragma: no cover — guarded at call site
        raise RuntimeError(
            "capstone is required for AccessTrace memop decoding "
            "(pip install 'capstone>=5.0')"
        ) from exc

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    try:
        instrs = list(md.disasm(rip_bytes, rip, count=1))
    except Exception:  # pragma: no cover — capstone internal
        return None
    if not instrs:
        return None
    insn = instrs[0]

    mem_op = None
    for op in insn.operands:
        if op.type == CS_OP_MEM:
            mem_op = op
            break
    if mem_op is None:
        return None

    mem = mem_op.mem
    base_name = (insn.reg_name(mem.base) if mem.base != X86_REG_INVALID
                 else "none")
    index_name = (insn.reg_name(mem.index) if mem.index != X86_REG_INVALID
                  else "none")
    # Capstone spells rip-relative as base='rip'. Guard against None
    # from reg_name (happens on some older bindings when the register
    # id is out of range).
    base_name = (base_name or "none").lower()
    index_name = (index_name or "none").lower()
    rip_relative = (base_name == "rip")

    try:
        op_access = int(getattr(mem_op, "access", 0))
    except Exception:
        op_access = 0

    return Memop(
        mnemonic=str(insn.mnemonic or "").lower(),
        base_reg=base_name,
        index_reg=index_name,
        scale=int(mem.scale or 1),
        disp=int(mem.disp),
        size_bytes=int(mem_op.size or 0),
        access=_mnemonic_access(insn.mnemonic or "", op_access),
        rip_relative=rip_relative,
    )


def effective_address(memop: Memop, regs: dict, rip_next: int = 0) -> int:
    """Resolve *memop*'s effective address against the live GPR bank.

    *regs* is a mapping ``{register_name_lower: int_value}``; missing
    keys are treated as 0 (``"none"`` is reserved for the no-register
    case). *rip_next* is the RIP of the next instruction (used for
    RIP-relative addressing; Capstone already folds this into ``disp``
    when the decoder was given a non-zero rip, but kept here for the
    unit-test paths that decode with rip=0 and pass rip_next separately).
    """
    base = 0
    if memop.base_reg != "none":
        if memop.rip_relative:
            base = int(rip_next or 0)
        else:
            base = int(regs.get(memop.base_reg, 0) or 0)
    index = 0
    if memop.index_reg != "none":
        index = int(regs.get(memop.index_reg, 0) or 0)
    scale = int(memop.scale or 1)
    return (base + index * scale + int(memop.disp)) & ((1 << 64) - 1)
