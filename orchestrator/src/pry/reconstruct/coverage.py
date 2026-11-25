"""Coverage — the original's static blocks vs the blocks it executed.

Static blocks come from the analysis engine's single-function recovery
(x64 or x86 decoder). Known function starts (``.pdata``, exports) bound
the walk, so a tail jump ends the function instead of absorbing the
callee. x86 images have no ``.pdata``; a tail jump there can add the
callee's blocks, which only ever *lowers* the reported coverage.

A static block counts as covered when any executed translation block
overlaps it. Engine blocks end at branches but not at calls, Unicorn's
end at both; overlap handles the difference and loop heads reached by
fall-through.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Any

from ..analysis.engine import Engine, ImageView
from .dictionary import CmpSite, harvest

MASK52 = (1 << 52) - 1
STATIC_BUDGET = 200_000


@dataclass(frozen=True)
class StaticBlock:
    start: int
    end: int
    first: str          # first instruction text


@dataclass
class StaticFunction:
    start: int
    blocks: list[StaticBlock]
    truncated: bool
    indirect_jumps: int
    constants: tuple[int, ...] = ()     # the guided-input dictionary
    cmp_sites: tuple[CmpSite, ...] = ()  # compares the harness logs

    @property
    def lo(self) -> int:
        return min((b.start for b in self.blocks), default=self.start)

    @property
    def hi(self) -> int:
        return max((b.end for b in self.blocks), default=self.start + 1)


def static_function(view: ImageView, func_va: int, *,
                    bits: int) -> StaticFunction:
    eng = Engine(view, budget=STATIC_BUDGET, bits=bits)
    others = set(view.pdata_starts)
    others |= {va for va in view.names if view.is_exec(va)}
    fn = eng.recover_function(func_va, other_starts=others)
    blocks: list[StaticBlock] = []
    indirect = 0
    ordered = sorted(fn.blocks.values(), key=lambda x: x.start)
    starts = sorted({b.start for b in ordered if b.end > b.start})
    for b in ordered:
        if b.end <= b.start or (blocks and blocks[-1].start == b.start):
            continue
        # The engine does not split a block that falls through into a
        # jump target found later, so blocks can share a tail. Cap each
        # at the next block's start: overlapping blocks let one executed
        # tail (a shared `ret`) mark every block that runs into it as
        # covered.
        i = bisect.bisect_right(starts, b.start)
        end = min(b.end, starts[i]) if i < len(starts) else b.end
        first = ""
        if b.insns:
            first = f"{b.insns[0].mnemonic} {b.insns[0].op_str}".strip()
        blocks.append(StaticBlock(b.start, end, first))
        indirect += sum(1 for _d, kind in b.edges if kind == "jump_indirect")
    found = harvest(b.insns for b in ordered)
    sites = {s.va: s for s in found.cmp_sites}    # shared tails repeat
    return StaticFunction(start=func_va, blocks=blocks,
                          truncated=eng.result.truncated,
                          indirect_jumps=indirect,
                          constants=found.constants,
                          cmp_sites=tuple(sites.values()))


def coverage(fn: StaticFunction, executed: dict[int, int]) -> dict[str, Any]:
    """Coverage block for a report. *executed*: masked TB start → size."""
    spans = sorted((a, a + s) for a, s in executed.items())
    starts = [a for a, _ in spans]
    # Running max of span ends lets one bisect answer "does any span
    # overlap [lo, hi)?" in O(log n).
    max_end: list[int] = []
    cur = 0
    for _a, e in spans:
        cur = max(cur, e)
        max_end.append(cur)
    hit: list[StaticBlock] = []
    miss: list[StaticBlock] = []
    for b in fn.blocks:
        lo, hi = b.start & MASK52, b.end & MASK52
        i = bisect.bisect_left(starts, hi) - 1
        covered = i >= 0 and max_end[i] > lo
        (hit if covered else miss).append(b)
    total = len(fn.blocks)
    out = {"blocks_hit": len(hit), "blocks_total": total,
           "ratio": round(len(hit) / total, 4) if total else 0.0,
           "uncovered": [{"va": b.start, "first": b.first}
                         for b in miss[:32]]}
    if len(miss) > 32:
        out["uncovered_truncated"] = len(miss)
    if fn.truncated:
        out["note"] = "static recovery hit its budget; totals are partial"
    elif fn.indirect_jumps:
        out["note"] = (f"{fn.indirect_jumps} unresolved indirect jump(s): "
                       "blocks reached only through them are not counted")
    return out


__all__ = ["StaticBlock", "StaticFunction", "coverage", "static_function"]
