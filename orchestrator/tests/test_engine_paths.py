"""analysis.engine.Analysis.paths_to — real root->target call chains."""

from __future__ import annotations

from types import SimpleNamespace

from pry.analysis.engine import Analysis, Function


def _analysis(calls: dict[int, set], *, entry_rva: int = 0,
              exports: tuple[int, ...] = (), base: int = 0x1000) -> Analysis:
    img = SimpleNamespace(entry_rva=entry_rva) if entry_rva else None
    names = {base + entry_rva: "entry"} if entry_rva else {}
    for va in exports:
        names[va] = f"exp_{va:x}"
    view = SimpleNamespace(img=img, base_va=base, names=names)
    a = Analysis(view)  # type: ignore[arg-type]
    for va, callees in calls.items():
        a.functions[va] = Function(start=va, name=f"sub_{va:X}",
                                   calls=set(callees))
    return a


def test_chain_from_entry_is_root_first_and_deep() -> None:
    # entry(0x1100) -> A -> B -> C -> target; old code stopped at depth 2
    # (every function was a root) and returned the chain reversed.
    calls = {0x1100: {0x2000}, 0x2000: {0x3000}, 0x3000: {0x4000},
             0x4000: {0x5000}, 0x5000: set()}
    a = _analysis(calls, entry_rva=0x100)
    assert a.paths_to(0x5000) == [[0x1100, 0x2000, 0x3000, 0x4000, 0x5000]]


def test_exports_and_uncalled_functions_are_roots() -> None:
    # export E -> X -> T ; orphan O -> T ; entry N -> X
    calls = {0x1100: {0x2000}, 0x6000: {0x2000}, 0x2000: {0x7000},
             0x8000: {0x7000}, 0x7000: set()}
    a = _analysis(calls, entry_rva=0x100, exports=(0x6000,))
    got = a.paths_to(0x7000)
    assert [0x8000, 0x7000] in got            # orphan caller is a root
    assert [0x1100, 0x2000, 0x7000] in got     # entry chain
    assert [0x6000, 0x2000, 0x7000] in got     # export chain
    # shortest first
    assert len(got[0]) <= len(got[-1])
    assert 0x6000 in a.roots() and 0x8000 in a.roots()
    assert 0x2000 not in a.roots()


def test_target_that_is_a_root_and_cycles() -> None:
    # R calls itself and T; T calls R back (cycle) — must terminate.
    calls = {0x1100: {0x1100, 0x2000}, 0x2000: {0x1100}}
    a = _analysis(calls, entry_rva=0x100)
    got = a.paths_to(0x2000)
    assert got == [[0x1100, 0x2000]]
    assert a.paths_to(0x1100)[0] == [0x1100]


def test_unknown_target_and_max_depth() -> None:
    chain = {0x1000 + i * 0x100: {0x1000 + (i + 1) * 0x100}
             for i in range(20)}
    chain[0x1000 + 20 * 0x100] = set()
    a = _analysis(chain)
    assert a.paths_to(0xDEAD) == []
    # 21-function chain exceeds max_depth=12 -> nothing within budget
    assert a.paths_to(0x1000 + 20 * 0x100, max_depth=12) == []
    assert len(a.paths_to(0x1000 + 20 * 0x100, max_depth=25)[0]) == 21
