"""Unit tests for ``mem.region_filter`` (Wave 1 Phase A).

Pure Python — the agent client is a hand-written mock. No live target
or pry server involvement.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.mem.region_filter import (  # noqa: E402
    _any_region_flag_set,
    _coalesce,
    _intersect,
    _mem_types_to_ints,
    _vad_predicate,
    resolve_spans,
)


# PAGE_* flag constants used by the tests (kept local so the test
# doesn't have to track module-private names).
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100


# ----------------------------------------------------------- mock client ----

class _Fail:
    """Raise when called — used to assert code paths don't touch a
    particular RPC."""
    def __init__(self, label: str):
        self._label = label

    def __call__(self, *_a, **_kw):
        raise AssertionError(f"mock: unexpected call to {self._label}")

    async def __acall__(self, *_a, **_kw):  # pragma: no cover
        raise AssertionError(f"mock: unexpected await on {self._label}")


class MockClient:
    """Agent client stub. Each method is set per-test to control the
    call surface explicitly."""
    def __init__(self, *, vads=None, heaps=None, modules=None,
                 threads=None, reads=None, raises=None):
        self._vads = vads
        self._heaps = heaps
        self._modules = modules
        self._threads = threads or {"threads": []}
        self._reads = reads or {}
        self._raises = raises or {}

    async def vad_list(self, pid, *, limit=0, offset=0):
        if "vad_list" in self._raises:
            raise self._raises["vad_list"]
        if self._vads is None:
            raise AssertionError("mock: vad_list unexpectedly called")
        return list(self._vads)

    async def mem_heaps(self, pid, want_blocks=False, max_blocks=0):
        if "mem_heaps" in self._raises:
            raise self._raises["mem_heaps"]
        if self._heaps is None:
            raise AssertionError("mock: mem_heaps unexpectedly called")
        return list(self._heaps)

    async def mem_modules(self, pid, kernel=False, *, limit=0, offset=0):
        if "mem_modules" in self._raises:
            raise self._raises["mem_modules"]
        if self._modules is None:
            raise AssertionError("mock: mem_modules unexpectedly called")
        return list(self._modules)

    async def thread_list(self, pid=0, kernel=False, with_context=False):
        if "thread_list" in self._raises:
            raise self._raises["thread_list"]
        return dict(self._threads)

    async def mem_read(self, pid, address, size, space="user",
                       allow_fault=False, partial=False, timeout=None,
                       want_meta=False, *, max_bytes=0, allow_mmio=False):
        if "mem_read" in self._raises:
            raise self._raises["mem_read"]
        key = (int(address), int(size))
        data = self._reads.get(key)
        if data is None:
            raise AssertionError(
                f"mock: mem_read unexpected (addr=0x{address:x}, size={size})")
        return data


# ----------------------------------------------- pure-function unit tests --

def test_any_region_flag_set_default_false():
    assert _any_region_flag_set(
        writable=False, executable=False, cow=False,
        include_guarded=False, mem_types=None, scope="") is False
    assert _any_region_flag_set(
        writable=False, executable=False, cow=False,
        include_guarded=False, mem_types=None, scope="all") is False


@pytest.mark.parametrize("flag", [
    {"writable": True}, {"executable": True}, {"cow": True},
    {"include_guarded": True}, {"mem_types": ["private"]},
    {"scope": "heap"}, {"scope": "image"}, {"scope": "stack"},
])
def test_any_region_flag_set_true_for_each(flag):
    defaults = {
        "writable": False, "executable": False, "cow": False,
        "include_guarded": False, "mem_types": None, "scope": "",
    }
    defaults.update(flag)
    assert _any_region_flag_set(**defaults) is True


def test_mem_types_to_ints_labels_and_ints():
    notes: list[str] = []
    # "mapped" removed this wave (review H1); "private"/"image" are
    # the short labels, Vad* names + raw ints also accepted.
    out = _mem_types_to_ints(["private", "image", "7", "0x3"], notes)
    assert out == {0, 2, 3, 7}
    assert notes == []


def test_mem_types_to_ints_unknown_labels_land_in_notes():
    notes: list[str] = []
    out = _mem_types_to_ints(["private", "weird_label"], notes)
    assert out == {0}
    assert any(n.startswith("mem_types_unknown:weird_label") for n in notes)


def test_mem_types_to_ints_none_returns_none():
    assert _mem_types_to_ints(None, []) is None
    assert _mem_types_to_ints([], []) is None


def test_vad_predicate_writable_drops_readonly():
    pred = _vad_predicate(writable=True, executable=False, cow=False,
                          include_guarded=False, want_types=None)
    assert pred({"protect": PAGE_READONLY}) is False
    assert pred({"protect": PAGE_READWRITE}) is True
    assert pred({"protect": PAGE_EXECUTE_READWRITE}) is True
    assert pred({"protect": PAGE_WRITECOPY}) is True


def test_vad_predicate_executable_drops_data():
    pred = _vad_predicate(writable=False, executable=True, cow=False,
                          include_guarded=False, want_types=None)
    assert pred({"protect": PAGE_READONLY}) is False
    assert pred({"protect": PAGE_READWRITE}) is False
    assert pred({"protect": PAGE_EXECUTE}) is True
    assert pred({"protect": PAGE_EXECUTE_READ}) is True
    assert pred({"protect": PAGE_EXECUTE_READWRITE}) is True


def test_vad_predicate_cow_drops_non_copy_on_write():
    pred = _vad_predicate(writable=False, executable=False, cow=True,
                          include_guarded=False, want_types=None)
    assert pred({"protect": PAGE_READWRITE}) is False
    assert pred({"protect": PAGE_WRITECOPY}) is True
    assert pred({"protect": PAGE_EXECUTE_WRITECOPY}) is True


def test_vad_predicate_guard_dropped_unless_include_guarded():
    pred_strict = _vad_predicate(writable=True, executable=False, cow=False,
                                 include_guarded=False, want_types=None)
    pred_loose = _vad_predicate(writable=True, executable=False, cow=False,
                                include_guarded=True, want_types=None)
    guarded_rw = {"protect": PAGE_READWRITE | PAGE_GUARD}
    assert pred_strict(guarded_rw) is False
    assert pred_loose(guarded_rw) is True


def test_vad_predicate_mem_types_subset():
    pred = _vad_predicate(writable=False, executable=False, cow=False,
                          include_guarded=False, want_types={2})  # image only
    assert pred({"protect": PAGE_READWRITE, "vad_type": 0}) is False
    assert pred({"protect": PAGE_READWRITE, "vad_type": 2}) is True


def test_coalesce_merges_overlapping():
    out = _coalesce([(0x1000, 0x1000), (0x1500, 0x1000),
                      (0x3000, 0x1000)])
    # [0x1000, 0x2000) + [0x1500, 0x2500) merge to [0x1000, 0x2500)
    assert out == [(0x1000, 0x1500), (0x3000, 0x1000)]


def test_coalesce_drops_zero_and_merges_adjacent():
    out = _coalesce([(0x1000, 0), (0x1000, 0x1000), (0x2000, 0x1000)])
    assert out == [(0x1000, 0x2000)]


def test_intersect_basic():
    a = [(0x1000, 0x2000)]     # [0x1000, 0x3000)
    b = [(0x2000, 0x2000)]     # [0x2000, 0x4000)
    assert _intersect(a, b) == [(0x2000, 0x1000)]  # [0x2000, 0x3000)


def test_intersect_disjoint_is_empty():
    a = [(0x1000, 0x1000)]
    b = [(0x3000, 0x1000)]
    assert _intersect(a, b) == []


def test_intersect_multi_span():
    a = [(0x1000, 0x1000), (0x3000, 0x1000)]
    b = [(0x0500, 0x2000), (0x3500, 0x0500)]
    # Expected: a ∩ b = [0x1000, 0x2000) + [0x3500, 0x3A00)
    assert _intersect(a, b) == [(0x1000, 0x1000), (0x3500, 0x0500)]


# ----------------------------------------------- resolve_spans() tests ----

def _run(coro):
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


def test_resolve_no_flags_no_sections_whole_space():
    """With no region filter and no base range, resolve_spans returns
    empty spans — caller's whole-space fast path applies."""
    c = MockClient()
    spans, info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False))
    assert err is None
    assert spans == []
    assert info["region_filter"]["scope"] == "all"
    assert info["notes"] == []


def test_resolve_address_size_only():
    """address+size alone becomes a one-element base span list."""
    c = MockClient()
    spans, info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False,
        address=0x1000, size=0x4000))
    assert err is None
    assert spans == [(0x1000, 0x4000)]


def test_resolve_writable_filters_vad_rows():
    vads = [
        {"start": 0x10000, "end": 0x11000, "protect": PAGE_READONLY,
         "vad_type": 0},
        {"start": 0x20000, "end": 0x23000, "protect": PAGE_READWRITE,
         "vad_type": 0},
        {"start": 0x30000, "end": 0x31000,
         "protect": PAGE_EXECUTE_READ, "vad_type": 2},
    ]
    c = MockClient(vads=vads)
    spans, info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True))
    assert err is None
    assert spans == [(0x20000, 0x3000)]  # only the RW row
    assert info["vad_match_count"] == 1


def test_resolve_executable_filters_vad_rows():
    vads = [
        {"start": 0x10000, "end": 0x11000, "protect": PAGE_READWRITE,
         "vad_type": 0},
        {"start": 0x20000, "end": 0x21000, "protect": PAGE_EXECUTE_READ,
         "vad_type": 2},
    ]
    c = MockClient(vads=vads)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, executable=True))
    assert err is None
    assert spans == [(0x20000, 0x1000)]


def test_resolve_mem_types_subsets_by_label():
    vads = [
        {"start": 0x10000, "end": 0x11000, "protect": PAGE_READWRITE,
         "vad_type": 0},  # private
        {"start": 0x20000, "end": 0x21000, "protect": PAGE_READWRITE,
         "vad_type": 2},  # image
    ]
    c = MockClient(vads=vads)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True,
        mem_types=["image"]))
    assert err is None
    assert spans == [(0x20000, 0x1000)]


def test_resolve_guard_dropped_by_default():
    vads = [
        {"start": 0x10000, "end": 0x11000,
         "protect": PAGE_READWRITE | PAGE_GUARD, "vad_type": 0},
        {"start": 0x20000, "end": 0x21000, "protect": PAGE_READWRITE,
         "vad_type": 0},
    ]
    c = MockClient(vads=vads)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True))
    assert err is None
    assert spans == [(0x20000, 0x1000)]


def test_resolve_guard_kept_with_include_guarded():
    vads = [
        {"start": 0x10000, "end": 0x11000,
         "protect": PAGE_READWRITE | PAGE_GUARD, "vad_type": 0},
    ]
    c = MockClient(vads=vads)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True,
        include_guarded=True))
    assert err is None
    assert spans == [(0x10000, 0x1000)]


def test_resolve_scope_heap_intersects_with_vad():
    vads = [
        {"start": 0x10000, "end": 0x20000, "protect": PAGE_READWRITE,
         "vad_type": 0},
        {"start": 0x20000, "end": 0x30000, "protect": PAGE_READWRITE,
         "vad_type": 0},
    ]
    heaps = [{"base": 0x15000, "committed": 0x2000}]
    c = MockClient(vads=vads, heaps=heaps)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True,
        scope="heap"))
    assert err is None
    assert spans == [(0x15000, 0x2000)]


def test_resolve_scope_image_uses_modules():
    vads = [
        {"start": 0x400000, "end": 0x500000,
         "protect": PAGE_EXECUTE_READ, "vad_type": 2},
        {"start": 0x10000, "end": 0x11000, "protect": PAGE_READWRITE,
         "vad_type": 0},
    ]
    modules = [{"base": 0x400000, "size": 0x100000}]
    c = MockClient(vads=vads, modules=modules)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, executable=True,
        scope="image"))
    assert err is None
    assert spans == [(0x400000, 0x100000)]


def test_resolve_scope_stack_walks_tebs():
    vads = [
        {"start": 0x7FFFF0000000, "end": 0x7FFFF0010000,
         "protect": PAGE_READWRITE, "vad_type": 0},
    ]
    threads = {"threads": [
        {"tid": 100, "teb": 0x7FFFF0100000},
    ]}
    # TEB+0x08 = StackBase (high), TEB+0x10 = StackLimit (low)
    teb = 0x7FFFF0100000
    stack_base = 0x7FFFF0008000
    stack_limit = 0x7FFFF0001000
    reads = {(teb + 0x08, 16):
             stack_base.to_bytes(8, "little")
             + stack_limit.to_bytes(8, "little")}
    c = MockClient(vads=vads, threads=threads, reads=reads)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True,
        scope="stack"))
    assert err is None
    # Expected: VAD-writable (0x7FFFF0000000..0x7FFFF0010000) ∩ stack
    # (0x7FFFF0001000..0x7FFFF0008000) = (0x7FFFF0001000, 0x7000)
    assert spans == [(0x7FFFF0001000, 0x7000)]


def test_resolve_kernel_space_degrades_to_noop_with_note():
    """Kernel space has no VAD; the region filter degrades to a
    passthrough with a note."""
    c = MockClient()  # no vad_list / heaps / modules required
    spans, info, err = _run(resolve_spans(
        c, pid=4, space="kernel", kernel_lookup=True, writable=True))
    assert err is None
    assert spans == []  # no base spans given
    assert "kernel_space_filter_degraded" in info["notes"]


def test_resolve_no_match_returns_err():
    vads = [
        {"start": 0x10000, "end": 0x11000, "protect": PAGE_READONLY,
         "vad_type": 0},
    ]
    c = MockClient(vads=vads)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True))
    assert spans == []
    assert err is not None
    assert err["kind"] == "no_match"


def test_resolve_unknown_scope_bad_arg():
    c = MockClient(vads=[])
    _spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, scope="weird"))
    assert err is not None
    assert err["kind"] == "bad_arg"
    assert "weird" in err["error"]


def test_resolve_vad_failure_falls_back_with_note():
    """When vad_list raises, resolve_spans should degrade to base
    spans + notes rather than hard-failing."""
    c = MockClient(raises={"vad_list": RuntimeError("fake")})
    spans, info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True,
        address=0x1000, size=0x1000))
    assert err is None
    assert spans == [(0x1000, 0x1000)]
    assert any(n.startswith("vad_failed:") for n in info["notes"])


def test_resolve_scope_heap_intersects_with_base_range():
    """If address+size is set alongside region flags, the intersect
    drops heap regions outside that window."""
    vads = [
        {"start": 0x10000, "end": 0x40000, "protect": PAGE_READWRITE,
         "vad_type": 0},
    ]
    heaps = [{"base": 0x15000, "committed": 0x10000},  # inside window
             {"base": 0x30000, "committed": 0x10000}]  # outside window
    c = MockClient(vads=vads, heaps=heaps)
    spans, _info, err = _run(resolve_spans(
        c, pid=1, space="user", kernel_lookup=False, writable=True,
        scope="heap", address=0x14000, size=0x8000))
    assert err is None
    # intersect: (heaps ∩ writable-vad) ∩ (0x14000..0x1C000)
    # heaps ∩ vad = [0x15000, 0x25000) + [0x30000, 0x40000)
    # ∩ [0x14000, 0x1C000) = [0x15000, 0x1C000) size 0x7000
    assert spans == [(0x15000, 0x7000)]
