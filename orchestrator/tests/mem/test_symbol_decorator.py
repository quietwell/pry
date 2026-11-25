"""Memory scanner wave 3 Phase D (§5.2): SymbolDecorator unit tests.

The decorator is a pure orchestrator-side wrapper around the shared
``symbols_manage(action='lookup_batch')`` core. These tests mock the
lookup backend so the suite needs neither a live agent nor a cached
PDB — they lock in:

* The ``decorate_vas`` LRU: a cache hit does not re-call the backend.
* Negative cache: a VA that returns ``None`` from the backend is
  cached as ``None`` so a repeat ask also doesn't RPC.
* ``confidence='low'`` -> ``None`` label (SymFromAddrW nearest-match
  guessing isn't audit-grade; the decorator drops it).
* Coverage-unknown skip: records without ``module`` or without
  ``symbol`` resolve to ``None``.
* Chain decoration end-to-end: anchor_va + hops get stamped where
  the lookup succeeded.
* Dissect decoration end-to-end: slots with ``ptr_module`` set get a
  ``ptr_sym`` string.
* No-PDB passthrough: a backend that returns all-``None`` leaves the
  response untouched (empty labels, no error).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.mem._decorate import (  # noqa: E402
    SymbolDecorator,
    _LRU,
)


# --------------------------------------------------------- test helpers -----

def _run(coro):
    """Run a coroutine under a fresh event loop so the test is
    independent of pytest-asyncio installation."""
    return asyncio.new_event_loop().run_until_complete(coro)


class _RecordingBackend:
    """Mock ``_lookup_batch_core`` backend. Records every call so tests
    can assert the batching + LRU behavior."""

    def __init__(self, table: dict[int, dict[str, Any] | None]):
        self.table = table
        self.calls: list[list[int]] = []

    async def __call__(self, ctx, *, view: str, pid: int,
                       vas: list[int], max_disp: int
                       ) -> dict[int, dict[str, Any] | None]:
        self.calls.append(list(vas))
        return {int(v): self.table.get(int(v)) for v in vas}


def _hit(module: str, symbol: str, displacement: int = 0,
         confidence: str = "high") -> dict[str, Any]:
    return {"module": module, "symbol": symbol,
            "displacement": int(displacement),
            "confidence": confidence}


# ----------------------------------------------------- _LRU correctness ----

def test_lru_evicts_oldest_past_cap():
    lru = _LRU(3)
    lru.put(1, "a")
    lru.put(2, "b")
    lru.put(3, "c")
    assert 1 in lru
    lru.put(4, "d")
    assert 1 not in lru
    assert 2 in lru and 3 in lru and 4 in lru


def test_lru_get_touches_access_order():
    lru = _LRU(3)
    lru.put(1, "a")
    lru.put(2, "b")
    lru.put(3, "c")
    # Touch 1 — now 2 is the oldest.
    lru.get(1)
    lru.put(4, "d")
    assert 1 in lru
    assert 2 not in lru
    assert 3 in lru and 4 in lru


def test_lru_stores_none_values():
    lru = _LRU(2)
    sentinel = object()
    lru.put(10, None)
    assert lru.get(10, sentinel) is None
    # A miss returns the sentinel, not None.
    assert lru.get(11, sentinel) is sentinel


# --------------------------------------- _fmt / label formatting -----------

def test_fmt_high_confidence_no_displacement():
    row = _hit("ntdll.dll", "NtClose", 0, "high")
    assert SymbolDecorator._fmt(row) == "ntdll.dll!NtClose"


def test_fmt_high_confidence_with_displacement():
    row = _hit("game.exe", "CWorld::Tick", 0x18, "high")
    assert SymbolDecorator._fmt(row) == "game.exe!CWorld::Tick+0x18"


def test_fmt_low_confidence_is_none():
    row = _hit("ntdll.dll", "RtlAllocateHeap", 0x400, "low")
    assert SymbolDecorator._fmt(row) is None


def test_fmt_absent_module_is_none():
    row = {"module": "", "symbol": "Foo", "displacement": 0,
           "confidence": "high"}
    assert SymbolDecorator._fmt(row) is None


def test_fmt_absent_symbol_is_none():
    row = {"module": "game.exe", "symbol": None,
           "displacement": 0, "confidence": "high"}
    assert SymbolDecorator._fmt(row) is None


def test_fmt_none_record_is_none():
    assert SymbolDecorator._fmt(None) is None


# ------------------------------------------ decorate_vas LRU / batching ----

def test_decorate_vas_single_call_batches_all_misses():
    table = {
        0x1000: _hit("game.exe", "Entry"),
        0x2000: _hit("game.exe", "Update", 0x4),
        0x3000: None,
    }
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    out = _run(dec.decorate_vas("lab2.user", 1234, [0x1000, 0x2000, 0x3000]))
    assert out == {
        0x1000: "game.exe!Entry",
        0x2000: "game.exe!Update+0x4",
        0x3000: None,  # negative — kept in LRU as a None label
    }
    assert len(backend.calls) == 1
    assert sorted(backend.calls[0]) == [0x1000, 0x2000, 0x3000]


def test_decorate_vas_hits_lru_on_second_call():
    table = {0x1000: _hit("game.exe", "Entry")}
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    _run(dec.decorate_vas("lab2.user", 1234, [0x1000]))
    out = _run(dec.decorate_vas("lab2.user", 1234, [0x1000]))
    assert out == {0x1000: "game.exe!Entry"}
    # Only ONE backend call across both invocations.
    assert len(backend.calls) == 1


def test_decorate_vas_negative_cache_prevents_requery():
    """A VA that returned ``None`` from the backend is cached as
    ``None`` so a repeat ask doesn't re-RPC — crucial for pointer-map
    chains full of heap/stack VAs that never have symbols."""
    backend = _RecordingBackend({0x7ffe_1000: None})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    first = _run(dec.decorate_vas("lab2.user", 1, [0x7ffe_1000]))
    second = _run(dec.decorate_vas("lab2.user", 1, [0x7ffe_1000]))
    assert first == second == {0x7ffe_1000: None}
    assert len(backend.calls) == 1


def test_decorate_vas_dedupes_within_a_call():
    table = {0x1000: _hit("game.exe", "Entry")}
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    out = _run(dec.decorate_vas("lab2.user", 1,
                                 [0x1000, 0x1000, 0x1000]))
    assert out == {0x1000: "game.exe!Entry"}
    assert backend.calls == [[0x1000]]


def test_decorate_vas_mixes_hit_and_miss_in_one_batch():
    table = {
        0x1000: _hit("game.exe", "A"),
        0x2000: _hit("ntdll.dll", "B"),
    }
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    # Warm the LRU with 0x1000.
    _run(dec.decorate_vas("lab2.user", 1, [0x1000]))
    # Second call mixes a cached VA with a cold one — only 0x2000 goes
    # to the backend.
    out = _run(dec.decorate_vas("lab2.user", 1, [0x1000, 0x2000]))
    assert out == {0x1000: "game.exe!A", 0x2000: "ntdll.dll!B"}
    assert backend.calls == [[0x1000], [0x2000]]


def test_decorate_vas_low_confidence_skipped():
    """confidence='low' means SymFromAddrW is nearest-match-guessing a
    far-away symbol. The decorator drops it (plan §5.2)."""
    table = {
        0x1000: _hit("ntdll.dll", "RtlpAllocate", 0x4000, "low"),
    }
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    out = _run(dec.decorate_vas("lab2.user", 1, [0x1000]))
    assert out == {0x1000: None}


def test_decorate_vas_handles_empty_input():
    backend = _RecordingBackend({})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)
    assert _run(dec.decorate_vas("lab2.user", 1, [])) == {}
    assert backend.calls == []


def test_decorate_vas_skips_zero_va():
    backend = _RecordingBackend({})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)
    out = _run(dec.decorate_vas("lab2.user", 1, [0]))
    assert out == {}
    assert backend.calls == []


def test_decorate_vas_accepts_hex_string_input():
    table = {0x1000: _hit("game.exe", "Entry")}
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)
    out = _run(dec.decorate_vas("lab2.user", 1, ["0x1000"]))
    assert out == {0x1000: "game.exe!Entry"}


def test_decorate_vas_swallows_backend_exceptions():
    """A raising backend never bubbles up — decoration is advisory."""

    async def _raiser(ctx, *, view, pid, vas, max_disp):
        raise RuntimeError("dbghelp unavailable")

    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=_raiser)
    out = _run(dec.decorate_vas("lab2.user", 1, [0x1000, 0x2000]))
    # Both VAs resolve to None; nothing raises.
    assert out == {0x1000: None, 0x2000: None}


# ----------------------------------------- decorate_chain end-to-end -------

def test_decorate_chain_stamps_anchor_sym():
    """Current pointer_scan shape: anchor_va + offsets (no materialized
    hops). decorate_chain must label the anchor."""
    table = {0x7ff889_ab1000: _hit("game.exe", "g_WorldPtr", 0x4)}
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    chain = {
        "_view": "lab2.user",
        "_pid": 1234,
        "anchor_va": 0x7ff889_ab1000,
        "anchor_module": "game.exe",
        "anchor_module_off": 0x4A2C,
        "offsets": [0x18, 0x20],
        "static": True,
    }
    out = _run(dec.decorate_chain(chain))
    assert out["anchor_sym"] == "game.exe!g_WorldPtr+0x4"
    # Fields not overwritten.
    assert out["anchor_va"] == 0x7ff889_ab1000
    assert out["offsets"] == [0x18, 0x20]


def test_decorate_chain_stamps_hop_sym_when_hops_present():
    """Forward-compat path: when a future ABI adds chain.hops[], each
    hop's va should get a hop_sym label."""
    table = {
        0x1000: _hit("game.exe", "Entry"),
        0x2000: _hit("game.exe", "CWorld::vftable", 0x18),
    }
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    chain = {
        "_view": "lab2.user",
        "_pid": 1234,
        "anchor_va": 0x1000,
        "hops": [{"va": 0x1000}, {"va": 0x2000}, {"va": 0}],
    }
    out = _run(dec.decorate_chain(chain))
    assert out["anchor_sym"] == "game.exe!Entry"
    assert out["hops"][0]["hop_sym"] == "game.exe!Entry"
    assert out["hops"][1]["hop_sym"] == "game.exe!CWorld::vftable+0x18"
    # Zero VA / unresolved hop stays bare.
    assert "hop_sym" not in out["hops"][2]


def test_decorate_chain_noop_without_view():
    backend = _RecordingBackend({})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)
    chain = {"anchor_va": 0x1000, "offsets": []}
    out = _run(dec.decorate_chain(chain))
    assert out is chain
    assert "anchor_sym" not in out
    assert backend.calls == []


def test_decorate_chain_noop_when_no_pdb_coverage():
    """Backend returns None for every VA (no cached PDB). The chain
    should come back untouched — no 'anchor_sym' key, no error."""
    backend = _RecordingBackend({0x1000: None})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)
    chain = {"_view": "lab2.user", "_pid": 1,
             "anchor_va": 0x1000, "offsets": [0x8]}
    out = _run(dec.decorate_chain(chain))
    assert "anchor_sym" not in out
    assert len(backend.calls) == 1


# --------------------------------------- decorate_dissect end-to-end -------

def test_decorate_dissect_stamps_ptr_sym_on_pointer_slots():
    """Only slots whose ptr_module is set get batched. Non-pointer
    slots are skipped (no RPC)."""
    table = {
        0x7ff8_0000_1000: _hit("ntdll.dll", "RtlpHpHeapGlobals"),
        0x7ff8_0000_2000: _hit("ntdll.dll", "NtClose"),
    }
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    resp = {
        "target": "lab2.user",
        "data": {
            "pid": 1234,
            "slots": [
                {"offset": 0x00, "probable_type": "pointer",
                 "ptr_module": "ntdll.dll",
                 "ptr_target_va": 0x7ff8_0000_1000},
                {"offset": 0x08, "probable_type": "pointer",
                 "ptr_module": "ntdll.dll",
                 "ptr_target_va": 0x7ff8_0000_2000},
                {"offset": 0x10, "probable_type": "i32",
                 "ptr_module": "",
                 "ptr_target_va": 0},
            ],
        },
    }
    out = _run(dec.decorate_dissect(resp))
    slots = out["data"]["slots"]
    assert slots[0]["ptr_sym"] == "ntdll.dll!RtlpHpHeapGlobals"
    assert slots[1]["ptr_sym"] == "ntdll.dll!NtClose"
    # Non-pointer slot untouched.
    assert "ptr_sym" not in slots[2]
    # Exactly one batched call — both pointer VAs in it.
    assert len(backend.calls) == 1
    assert sorted(backend.calls[0]) == sorted([0x7ff8_0000_1000,
                                                0x7ff8_0000_2000])


def test_decorate_dissect_noop_without_view():
    """An orchestrator-side dissect fallback sometimes omits ``target``
    (e.g. in the v16 fallback path when the session has no view). The
    decorator should degrade quietly rather than raise."""
    backend = _RecordingBackend({0x1000: _hit("x.exe", "F")})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    resp = {
        "data": {
            "slots": [{"offset": 0, "ptr_module": "x.exe",
                       "ptr_target_va": 0x1000}],
        },
    }
    out = _run(dec.decorate_dissect(resp))
    assert "ptr_sym" not in out["data"]["slots"][0]
    assert backend.calls == []


def test_decorate_dissect_no_pdb_leaves_slots_bare():
    """Backend returns None for every pointer VA (no cached PDB) ->
    the response is returned untouched, no error."""
    backend = _RecordingBackend({0x1000: None, 0x2000: None})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    resp = {
        "target": "lab2.user",
        "data": {
            "pid": 1,
            "slots": [
                {"offset": 0, "ptr_module": "x.exe",
                 "ptr_target_va": 0x1000},
                {"offset": 8, "ptr_module": "x.exe",
                 "ptr_target_va": 0x2000},
            ],
        },
    }
    out = _run(dec.decorate_dissect(resp))
    assert "ptr_sym" not in out["data"]["slots"][0]
    assert "ptr_sym" not in out["data"]["slots"][1]


# ------------------------------------------ decorate_access_trace_page ----

def test_decorate_access_trace_stamps_rip_sym():
    table = {
        0x7ff8_1111_2222: _hit("game.exe", "CWorld::Tick", 0x18),
        0x7ff8_1111_3333: _hit("game.exe", "CWorld::Draw"),
    }
    backend = _RecordingBackend(table)
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)

    page = {
        "target": "lab2.user",
        "data": {
            "pid": 1234,
            "hits": [
                {"rip": 0x7ff8_1111_2222, "tid": 42},
                {"rip": 0x7ff8_1111_3333, "tid": 42},
                {"rip": 0, "tid": 0},
            ],
        },
    }
    out = _run(dec.decorate_access_trace_page(page))
    hits = out["data"]["hits"]
    assert hits[0]["rip_sym"] == "game.exe!CWorld::Tick+0x18"
    assert hits[1]["rip_sym"] == "game.exe!CWorld::Draw"
    assert "rip_sym" not in hits[2]


def test_decorate_access_trace_noop_without_view():
    backend = _RecordingBackend({0x1000: _hit("x.exe", "F")})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)
    page = {"data": {"hits": [{"rip": 0x1000}]}}
    out = _run(dec.decorate_access_trace_page(page))
    assert "rip_sym" not in out["data"]["hits"][0]
    assert backend.calls == []


# ------------------------------------ max_disp / confidence threshold -----

def test_max_disp_drops_far_hits():
    """Backend records come back with 'high' confidence; the decorator
    itself re-checks nothing (backend is responsible for the
    confidence tag). This just locks the ``_fmt`` contract: a
    well-behaved backend handing a high-confidence row produces a
    label, and the decorator's max_disp default threads through to
    the backend as a kwarg."""
    # Spy on the max_disp kwarg handed to the backend.
    seen: dict[str, Any] = {}

    async def _probe(ctx, *, view, pid, vas, max_disp):
        seen["max_disp"] = max_disp
        return {}

    dec = SymbolDecorator(SimpleNamespace(), max_disp=0x80,
                           _lookup_backend=_probe)
    _run(dec.decorate_vas("lab2.user", 1, [0x1000]))
    assert seen["max_disp"] == 0x80


# ------------------------------------------- shape robustness guards ------

def test_decorate_chain_handles_non_dict_input():
    backend = _RecordingBackend({})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)
    assert _run(dec.decorate_chain(None)) is None  # type: ignore[arg-type]
    assert _run(dec.decorate_chain("not-a-chain")) == "not-a-chain"  # type: ignore[arg-type]


def test_decorate_dissect_handles_missing_slots():
    backend = _RecordingBackend({})
    dec = SymbolDecorator(SimpleNamespace(), _lookup_backend=backend)
    resp: dict[str, Any] = {"target": "lab2.user", "data": {"pid": 1}}
    out = _run(dec.decorate_dissect(resp))
    assert out is resp
    assert backend.calls == []


# ------------------------------- lookup_batch core (integration-light) ----

def test_lookup_batch_core_returns_all_vas_as_none_without_view():
    """The symbols-tool backend is a soft resolver — when ``view`` is
    empty, every input VA comes back as ``None`` (not an exception).
    This is the contract the decorator relies on."""
    from src.pry.mcp.tools.symbols import _lookup_batch_core

    out = _run(_lookup_batch_core(SimpleNamespace(), view="",
                                   pid=0, vas=[0x1000, 0x2000],
                                   max_disp=0x400))
    assert out == {0x1000: None, 0x2000: None}
