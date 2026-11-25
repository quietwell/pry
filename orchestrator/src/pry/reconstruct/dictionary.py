"""Constants and compare sites harvested from the original function: the
guided input generator's dictionary.

A comparison in the code is the cheapest hint at the inputs that steer
it. ``cmp al, 0x20`` wants a byte near 0x20, ``cmp edx, 16`` wants a 16,
and a compiler's range check (``lea ecx, [r9 - 0x30]`` then
``cmp cl, 9``) wants the range 0x30..0x39. They are read off the static
blocks; nothing runs.

Constants, in order of first appearance and capped at
:data:`MAX_CONSTANTS`:

* the immediates of ``cmp`` (with ±1, for the ``<`` / ``<=`` edge),
  ``test``, ``sub``, ``add``, ``and``, ``or``, ``xor`` and ``mov``;
* ``k`` from ``lea r, [x - k]`` (no index, ``x`` not the stack/frame);
* range checks: ``lea``/``sub``/``add`` that subtract ``A`` from a
  register, then a ``cmp`` of the same register (any width) against
  ``B`` in the same block, add ``A + B`` and ``A + B + 1``.

Compare sites (:class:`CmpSite`): every ``cmp <reg|mem>, imm``. The
harness hooks them on the original side and logs the value each one
saw, so the generator can write the expected value into the input
where the observed one came from (input-to-state). A site comparing a
register that lost ``A`` just before carries ``bias = A``, so the log
speaks in input terms (``c`` vs ``'9'``, not ``c - '0'`` vs 9).

Stack and frame arithmetic (``sub rsp, 0x28``) is skipped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..analysis.engine import IMM, MEM, REG, Insn

MAX_CONSTANTS = 256
MAX_CMP_SITES = 128
_IMM_OPS = frozenset({"cmp", "test", "sub", "add", "and", "or", "xor",
                      "mov"})
_NO_WRITE = frozenset({"cmp", "test"})
_FRAME = frozenset({"sp", "bp", "ip"})
_PTR_WIDTH = {"byte": 1, "word": 2, "dword": 4, "qword": 8}


@dataclass(frozen=True)
class CmpSite:
    """One ``cmp <operand>, imm`` the harness logs."""

    va: int
    width: int                   # operand bytes
    imm: int
    reg: str = ""                # register operand (capstone name), or
    base: str = ""               # a memory operand: [base + index*scale
    index: str = ""              #                     + disp]
    scale: int = 1
    disp: int = 0
    bias: int = 0                # added back to both sides of the log


@dataclass(frozen=True)
class Harvest:
    constants: tuple[int, ...]
    cmp_sites: tuple[CmpSite, ...]


def _family(reg: str | None) -> str:
    """One name per register, any width: rcx/ecx/cx/cl/ch → 'c',
    r9/r9d/r9w/r9b → 'r9', rsi/esi/si/sil → 'si'."""
    if not reg:
        return ""
    r = reg.lower()
    if r[0] == "r" and r[1:2].isdigit():
        return r.rstrip("dwb")
    if len(r) == 3 and r[0] in "re":
        r = r[1:]
    if r in ("sil", "dil", "bpl", "spl"):
        r = r[:2]
    if len(r) == 2 and r[0] in "abcd" and r[1] in "xlh":
        return r[0]
    return r


def reg_width(reg: str) -> int:
    """Operand bytes of a general register name (0 when unknown)."""
    r = reg.lower()
    if r[0] == "r" and r[1:2].isdigit():
        return {"b": 1, "w": 2, "d": 4}.get(r[-1], 8)
    if r in ("al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil",
             "bpl", "spl"):
        return 1
    if r in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        return 2
    if len(r) == 3 and r[0] == "e":
        return 4
    if len(r) == 3 and r[0] == "r":
        return 8
    return 0


def _cmp_site(ins: Insn, bias: int) -> CmpSite | None:
    ops = ins.ops
    if len(ops) != 2 or ops[1]["kind"] != IMM or ":" in ins.op_str:
        return None              # no immediate, or a segment override
    dst, imm = ops[0], ops[1]["imm"]
    if dst["kind"] == REG:
        w = reg_width(dst["reg"])
        return CmpSite(ins.addr, w, imm, reg=dst["reg"], bias=bias) \
            if w else None
    if dst["kind"] == MEM:
        base, index = dst["base"] or "", dst["index"] or ""
        if _family(base) == "ip" or not (base or index):
            return None
        w = _PTR_WIDTH.get(ins.op_str.split(" ", 1)[0], 0)
        return CmpSite(ins.addr, w, imm, base=base, index=index,
                       scale=dst["scale"] or 1, disp=dst["disp"]) \
            if w else None
    return None


def _block(insns: Iterable[Insn], add, sites: list[CmpSite]) -> None:
    pending: dict[str, int] = {}     # register family → the A it lost
    for ins in insns:
        ops = ins.ops
        dst = ops[0] if ops else None
        fam = _family(dst["reg"]) if dst and dst["kind"] == REG else ""
        if fam in _FRAME:
            continue
        m = ins.mnemonic
        if m == "lea" and fam and len(ops) == 2 and ops[1]["kind"] == MEM:
            mem = ops[1]
            base = _family(mem["base"])
            disp = mem["disp"]
            if mem["index"] is None and base and base not in _FRAME \
                    and disp and abs(disp) < 0x10000:
                add(-disp)
                pending[fam] = -disp
            else:
                pending.pop(fam, None)
            continue
        imm = ins.imm()
        if m == "cmp" and len(sites) < MAX_CMP_SITES:
            site = _cmp_site(ins, pending.get(fam, 0))
            if site is not None:
                sites.append(site)
        if m in _IMM_OPS and imm is not None:
            if m == "cmp" and fam in pending:
                add(pending[fam] + imm)
                add(pending[fam] + imm + 1)
            add(imm)
            if m == "cmp":
                add(imm + 1)
                add(imm - 1)
            if m in ("sub", "add") and fam and len(ops) == 2 and \
                    ops[1]["kind"] == IMM:
                pending[fam] = imm if m == "sub" else -imm
                continue
        if fam and m not in _NO_WRITE:
            pending.pop(fam, None)   # the register was overwritten


def harvest(blocks: Iterable[Iterable[Insn]]) -> Harvest:
    """The dictionary and compare sites of one function, from its
    blocks' instructions."""
    seen: dict[int, None] = {}
    sites: list[CmpSite] = []

    def add(v: int) -> None:
        if len(seen) < MAX_CONSTANTS:
            seen.setdefault(int(v), None)

    for insns in blocks:
        _block(insns, add, sites)
    return Harvest(tuple(seen), tuple(sites))


__all__ = ["CmpSite", "Harvest", "MAX_CMP_SITES", "MAX_CONSTANTS",
           "harvest", "reg_width"]
