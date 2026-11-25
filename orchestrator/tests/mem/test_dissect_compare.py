"""DissectCompare classification +
orchestrator dispatch.

Two layers:

1. ``test_classifier_*`` — exercise the python port of the agent-side
   classifier (``dissect.dissect_compare_decode``) on synthetic byte
   windows that cover every taxonomy branch. The port is kept bit-
   identical to ``agent/src/scan/dissect_service.cpp::Compare`` so
   mocking the agent response means mocking what the agent would have
   produced; here we just run the classifier directly.

2. ``test_handle_*`` — mock the agent client (same shape as
   ``test_wave3_p5.py``) and drive ``handle_dissect_compare`` end-to-
   end. Covers the ``dissect_version`` gate (= 1 refuses, = 2
   proceeds), decoration, kwarg preflight.
"""
from __future__ import annotations

import asyncio
import json
import struct
import sys
from pathlib import Path
from typing import Any

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.mcp.tools.mem import dissect as ds  # noqa: E402


# ----------------------------------------------- shared fixtures -------------

_ALIGN = 8
_WINDOW = 0x40  # 8 slots per instance


def _buf(*slots: int) -> bytes:
    """Pack N u64 LE values into a buffer sized to ``_WINDOW``."""
    out = b"".join(struct.pack("<Q", v) for v in slots)
    # Pad to _WINDOW so n_offsets is stable across tests.
    if len(out) < _WINDOW:
        out = out + b"\x00" * (_WINDOW - len(out))
    return out[:_WINDOW]


def _mods() -> list[dict[str, Any]]:
    """Two canonical modules with ample interior room."""
    return [
        {"name": "game.exe", "base": 0x7FF800000000, "size": 0x1000000},
        {"name": "ntdll.dll", "base": 0x7FF900000000, "size": 0x200000},
    ]


# ============================================================================
# 1. Classification taxonomy — pure python classifier on synthetic buffers
# ============================================================================

def test_classifier_all_stable():
    """Every instance has the exact same u64 at every offset ->
    every classified offset is 'stable'."""
    bases = [0x1000, 0x2000, 0x3000, 0x4000]
    bufs = [_buf(0xCAFE, 0xBABE, 0xDEAD, 0xBEEF,
                 0x1111, 0x2222, 0x3333, 0x4444) for _ in bases]
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=False)
    assert res["n_offsets"] == 8
    for off in res["offsets"]:
        assert off["classification"] == "stable", (
            f"offset {off['offset']:#x} should be stable, got "
            f"{off['classification']!r}")
        assert off["readable_instances"] == 4
        assert off["distinct_values"] == 1


def test_classifier_per_instance_scalar():
    """Each instance has a *unique* non-pointer value at every offset —
    D == R, pointer_frac == 0 -> 'per_instance_scalar'."""
    bases = [0x1000, 0x2000, 0x3000, 0x4000]
    bufs = []
    for i, _ in enumerate(bases):
        bufs.append(_buf(100 + i, 200 + i, 300 + i, 400 + i,
                          500 + i, 600 + i, 700 + i, 800 + i))
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=False)
    for off in res["offsets"]:
        assert off["classification"] == "per_instance_scalar"
        assert off["distinct_values"] == 4


def test_classifier_per_instance_ptr():
    """Every instance has a *distinct* pointer into game.exe at every
    offset — D == R, pointer_frac == 1.0 -> 'per_instance_ptr'."""
    bases = [0x1000, 0x2000, 0x3000, 0x4000]
    mods = _mods()
    game = mods[0]["base"]
    bufs = []
    for i, _ in enumerate(bases):
        # Each instance gets different module-interior pointers at
        # every offset.
        bufs.append(_buf(game + 0x100 + i,
                          game + 0x200 + i,
                          game + 0x300 + i,
                          game + 0x400 + i,
                          game + 0x500 + i,
                          game + 0x600 + i,
                          game + 0x700 + i,
                          game + 0x800 + i))
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=True, modules=mods)
    for off in res["offsets"]:
        assert off["classification"] == "per_instance_ptr", (
            f"offset {off['offset']:#x}: {off['classification']!r}")


def test_classifier_shared_pointer_with_vote_floor():
    """4 of 4 instances share a pointer into game.exe at offset 0,
    while other offsets are per-instance scalars.

    Modal value hits the shared_ptr_min_vote=2 default and the voters
    all share the same module -> 'shared_pointer'.
    """
    bases = [0x1000, 0x2000, 0x3000, 0x4000]
    mods = _mods()
    shared_ptr = mods[0]["base"] + 0x10c0  # into game.exe
    bufs = []
    for i, _ in enumerate(bases):
        # offset 0: shared pointer; the rest: unique scalars.
        bufs.append(_buf(shared_ptr,
                          100 + i, 200 + i, 300 + i,
                          400 + i, 500 + i, 600 + i, 700 + i))
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=True, modules=mods,
                                      shared_ptr_min_vote=2)
    first = res["offsets"][0]
    # 4-way share at offset 0 is actually stable (D == 1); stable+ptr
    # also surfaces shared_target_module.
    assert first["classification"] == "stable"
    assert first["shared_target_module"] == "game.exe"
    assert first["shared_target_module_off"] == 0x10c0
    # Remaining offsets are per_instance_scalar (unique integers, no
    # pointer bias).
    for off in res["offsets"][1:]:
        assert off["classification"] == "per_instance_scalar"


def test_classifier_shared_pointer_true_majority():
    """3 of 5 instances share a pointer, 2 are unique. D == 3, R == 5,
    modal_votes = 3 >= shared_vote (=2) -> 'shared_pointer'."""
    bases = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000]
    mods = _mods()
    shared_ptr = mods[0]["base"] + 0x200
    bufs = []
    for i in range(5):
        if i < 3:
            bufs.append(_buf(shared_ptr, 1, 2, 3, 4, 5, 6, 7))
        else:
            # Different pointer in the same module — different target.
            bufs.append(_buf(mods[0]["base"] + 0x400 + i * 8,
                              1, 2, 3, 4, 5, 6, 7))
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=True, modules=mods,
                                      shared_ptr_min_vote=2)
    first = res["offsets"][0]
    assert first["classification"] == "shared_pointer"
    assert first["modal_votes"] == 3
    assert first["shared_target_module"] == "game.exe"
    assert first["shared_target_module_off"] == 0x200


def test_classifier_shared_ptr_min_vote_floor_respected():
    """shared_ptr_min_vote=5 is above the actual majority (3); offset
    falls out of 'shared_pointer' and the D != R case picks 'noisy'."""
    bases = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000]
    mods = _mods()
    shared = mods[0]["base"] + 0x300
    bufs = []
    for i in range(5):
        if i < 3:
            bufs.append(_buf(shared, 1, 1, 1, 1, 1, 1, 1))
        else:
            bufs.append(_buf(mods[0]["base"] + 0x400 + i * 8,
                              1, 1, 1, 1, 1, 1, 1))
    res_floor2 = ds.dissect_compare_decode(
        bases, bufs, align=_ALIGN, window_size=_WINDOW,
        with_modules=True, modules=mods, shared_ptr_min_vote=2)
    assert res_floor2["offsets"][0]["classification"] == "shared_pointer"
    res_floor5 = ds.dissect_compare_decode(
        bases, bufs, align=_ALIGN, window_size=_WINDOW,
        with_modules=True, modules=mods, shared_ptr_min_vote=5)
    # Floor not met -> fall back. D=3, R=5 -> 'noisy'.
    assert res_floor5["offsets"][0]["classification"] == "noisy"


def test_classifier_noisy():
    """Values repeat but no shared-pointer signal (D != R and the modal
    isn't a module pointer). Pure noise -> 'noisy'."""
    bases = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000]
    # Two groups of integers; neither points into a module.
    bufs = []
    for i in range(5):
        v = 0xDEAD if i % 2 == 0 else 0xBEEF
        bufs.append(_buf(v, 1, 1, 1, 1, 1, 1, 1))
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=True,
                                      modules=_mods(),
                                      shared_ptr_min_vote=2)
    # Offset 0: D=2 (one group of 3, one of 2), R=5, modal 0xDEAD
    # has 3 votes >= shared_vote=2 but the modal is not a module ptr,
    # so we fall through. D (2) != R (5) -> 'noisy'.
    assert res["offsets"][0]["classification"] == "noisy"


def test_classifier_unreadable_instance_mixed_with_readable():
    """One instance returns an empty buffer (``unreadable=True``); the
    nested per-instance row stays in place at the right index, and
    downstream classification still works on the other instances."""
    bases = [0x1000, 0x2000, 0x3000, 0x4000]
    bufs = [
        _buf(0xCAFE, 0xBABE, 0, 0, 0, 0, 0, 0),
        b"",  # instance 1 is unreadable
        _buf(0xCAFE, 0xBABE, 0, 0, 0, 0, 0, 0),
        _buf(0xCAFE, 0xBABE, 0, 0, 0, 0, 0, 0),
    ]
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=False)
    # n_instances includes the unreadable one.
    assert res["n_instances"] == 4
    assert res["per_instance"][1]["unreadable"] is True
    assert res["per_instance"][1]["slots"] == []
    # Other instances kept their slots intact — nested shape, no desync.
    for i in (0, 2, 3):
        assert res["per_instance"][i]["unreadable"] is False
        assert len(res["per_instance"][i]["slots"]) == _WINDOW // _ALIGN
    # Offset 0: readable_instances = 3, all share 0xCAFE -> stable.
    assert res["offsets"][0]["classification"] == "stable"
    assert res["offsets"][0]["readable_instances"] == 3
    assert res["offsets"][0]["modal_value"] == 0xCAFE


def test_classifier_all_unreadable():
    """R == 0 at every offset. With min_instances_for_class defaulting
    to 3, every offset short-circuits on R < min -> 'inconclusive'
    before reaching the unreadable path. That is the documented
    semantics: 'inconclusive' is the correct label when we don't have
    enough data to decide."""
    bases = [0x1000, 0x2000, 0x3000]
    bufs: list[bytes] = [b"", b"", b""]
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=False)
    for off in res["offsets"]:
        assert off["classification"] == "inconclusive"


def test_classifier_inconclusive_too_few_instances():
    """N < min_instances_for_class means every offset is 'inconclusive'
    regardless of value agreement."""
    bases = [0x1000, 0x2000]
    bufs = [_buf(42, 42, 42, 42, 42, 42, 42, 42) for _ in bases]
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=False,
                                      min_instances_for_class=3)
    for off in res["offsets"]:
        assert off["classification"] == "inconclusive"
        assert off["readable_instances"] == 2


# ----------------------------------------------- with_modules off ------------

def test_classifier_with_modules_false_drops_shared_target_module():
    """``with_modules=False`` means slot ``ptr_module`` is always
    empty, so no offset can ever be classified 'shared_pointer' (the
    rule requires module anchoring). The modal pointer falls back to
    the per-instance_* / noisy / stable branches."""
    bases = [0x1000, 0x2000, 0x3000]
    mods = _mods()
    shared = mods[0]["base"] + 0x400
    bufs = [_buf(shared, 1, 2, 3, 4, 5, 6, 7) for _ in bases]
    res = ds.dissect_compare_decode(bases, bufs, align=_ALIGN,
                                      window_size=_WINDOW,
                                      with_modules=False,
                                      modules=mods,
                                      shared_ptr_min_vote=2)
    first = res["offsets"][0]
    # D == 1 for the shared slot; without module anchoring the stable
    # branch still fires but shared_target_module stays empty.
    assert first["classification"] == "stable"
    assert first["shared_target_module"] == ""
    assert first["shared_target_module_off"] == 0


# ----------------------------------------------- align 4 vs 8 ----------------

def test_classifier_alignment_4_vs_8():
    """Alignment 4 means 2x the offsets per window at the same byte
    budget. The row count must track."""
    bases = [0x1000, 0x2000, 0x3000]
    bufs = [b"\xAA" * 32 for _ in bases]
    res4 = ds.dissect_compare_decode(bases, bufs, align=4,
                                       window_size=32,
                                       with_modules=False)
    res8 = ds.dissect_compare_decode(bases, bufs, align=8,
                                       window_size=32,
                                       with_modules=False)
    assert res4["n_offsets"] == 8   # 32 / 4
    assert res8["n_offsets"] == 4   # 32 / 8
    # Every slot has the same bytes -> all stable in both alignments.
    for off in res4["offsets"] + res8["offsets"]:
        assert off["classification"] == "stable"


# ============================================================================
# 2. Orchestrator dispatch / handler — mock the agent client (wave3_p5 shape)
# ============================================================================

class _FakeSession:
    def __init__(self, dissect_version: int = 2,
                 view: str = "lab2.user"):
        self._machine_info = {
            view: {
                "pointer_map_version": 1,
                "dissect_version": dissect_version,
                "scan_service_version": 1,
                "machine": "lab2",
                "computer_name": "LAB2",
            }
        }

    def focus_view(self) -> str:
        return ""

    def machine_of(self, view: str) -> str:
        return view.rsplit(".", 1)[0] if "." in view else view


class _FakeCtx:
    def __init__(self, sess: _FakeSession):
        self.session = sess


class _CannedCompareClient:
    def __init__(self, compare_result: dict[str, Any]):
        self.pointer_map_service = object()
        self.dissect_service = object()
        self._compare_result = compare_result
        self.last_kwargs: dict[str, Any] = {}

    async def dissect_compare(self, **kwargs):
        self.last_kwargs = kwargs
        return self._compare_result


def _canned_response(bases: list[int], offsets_cls: list[dict[str, Any]],
                     ) -> dict[str, Any]:
    """Shape the mock returns — mirrors ``PointerMapMixin.dissect_compare``'s
    orchestrator dict layout."""
    per_instance = [{"base_va": b, "unreadable": False, "slots": []}
                    for b in bases]
    return {"ok": True, "offsets": offsets_cls,
            "per_instance": per_instance,
            "n_instances": len(bases), "n_offsets": len(offsets_cls)}


def test_handle_refuses_when_dissect_version_below_2():
    """dissect_version=1 means a pre-Wave-3-P1 agent registered the
    Dissect handler but not Compare. The orchestrator gate refuses
    with ``kind='feature_unavailable'`` before talking to the agent."""
    sess = _FakeSession(dissect_version=1)
    ctx = _FakeCtx(sess)

    class _ShouldNotCallClient:
        pointer_map_service = object()
        dissect_service = object()

        async def dissect_compare(self, **kwargs):
            raise AssertionError(
                "dissect_compare should not reach the client on "
                "dissect_version=1")

    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, _ShouldNotCallClient(), pid=1234,
        base_vas=[0x1000, 0x2000, 0x3000], window_size=64,
        align=8, space="user", with_modules=True,
        name="lab2.user")))
    assert env["ok"] is False
    assert env["kind"] == "feature_unavailable"


def test_handle_proceeds_on_dissect_version_2():
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    bases = [0x1000, 0x2000, 0x3000]
    canned = _canned_response(bases, [
        {"offset": 0, "classification": "stable",
         "distinct_values": 1, "readable_instances": 3,
         "modal_value": 0xCAFE, "modal_votes": 3,
         "probable_type": "pointer",
         "shared_target_module": "", "shared_target_module_off": 0},
    ])
    c = _CannedCompareClient(canned)
    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=1234, base_vas=bases, window_size=64,
        align=8, space="user", with_modules=False,
        decorate=False, name="lab2.user")))
    assert env["ok"] is True
    assert env["kind"] == "dissect_compare"
    assert env["data"]["n_instances"] == 3
    assert env["data"]["offsets"][0]["classification"] == "stable"


def test_handle_preflight_rejects_empty_base_vas():
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    c = _CannedCompareClient({})
    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=1234, base_vas=[], window_size=64, align=8,
        space="user", with_modules=False, decorate=False,
        name="lab2.user")))
    assert env["ok"] is False
    assert env["kind"] == "bad_arg"


def test_handle_preflight_rejects_too_many_instances():
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    c = _CannedCompareClient({})
    too_many = list(range(0x1000,
                           0x1000 + ds.DISSECT_COMPARE_MAX_INSTANCES + 1))
    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=1234, base_vas=too_many, window_size=64, align=8,
        space="user", with_modules=False, decorate=False,
        name="lab2.user")))
    assert env["ok"] is False
    assert env["kind"] == "too_many_instances"


def test_handle_preflight_rejects_bad_align():
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    c = _CannedCompareClient({})
    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=1234, base_vas=[0x1000, 0x2000, 0x3000],
        window_size=64, align=3, space="user", with_modules=False,
        decorate=False, name="lab2.user")))
    assert env["ok"] is False
    assert env["kind"] == "bad_arg"


def test_handle_preflight_rejects_bad_window_size():
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    c = _CannedCompareClient({})
    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=1234, base_vas=[0x1000, 0x2000, 0x3000],
        window_size=0, align=8, space="user", with_modules=False,
        decorate=False, name="lab2.user")))
    assert env["ok"] is False
    assert env["kind"] == "would_exceed"


def test_handle_forwards_kwargs_to_client():
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    canned = _canned_response([0x1000, 0x2000, 0x3000], [])
    c = _CannedCompareClient(canned)
    asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=42, base_vas=[0x1000, 0x2000, 0x3000],
        window_size=128, align=8, space="kernel",
        with_modules=True, shared_ptr_min_vote=4,
        min_instances_for_class=5, decorate=False,
        name="lab2.kernel"))
    assert c.last_kwargs["pid"] == 42
    assert c.last_kwargs["base_vas"] == [0x1000, 0x2000, 0x3000]
    assert c.last_kwargs["window_size"] == 128
    assert c.last_kwargs["align"] == 8
    assert c.last_kwargs["space"] == "kernel"
    assert c.last_kwargs["with_modules"] is True
    assert c.last_kwargs["shared_ptr_min_vote"] == 4
    assert c.last_kwargs["min_instances_for_class"] == 5


def test_handle_decorator_off_leaves_shared_target_untouched():
    """``decorate=False`` skips the SymbolDecorator pass; the offset
    ``shared_target_module`` row stays raw (no flattened ``shared_target``)."""
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    bases = [0x1000, 0x2000, 0x3000]
    offsets = [{"offset": 0, "classification": "shared_pointer",
                "distinct_values": 1, "readable_instances": 3,
                "modal_value": 0x7FF800001234, "modal_votes": 3,
                "probable_type": "pointer",
                "shared_target_module": "game.exe",
                "shared_target_module_off": 0x1234}]
    canned = _canned_response(bases, offsets)
    c = _CannedCompareClient(canned)
    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=1234, base_vas=bases, window_size=64, align=8,
        space="user", with_modules=True, decorate=False,
        name="lab2.user")))
    assert env["ok"] is True
    off0 = env["data"]["offsets"][0]
    assert off0["shared_target_module"] == "game.exe"
    assert "shared_target" not in off0


def test_handle_decorator_on_falls_back_without_pdb():
    """When no PDB is cached the SymbolDecorator returns ``None`` for
    every VA; the handler falls back to a raw ``module+0x<off>`` string
    so the caller always gets something readable on shared offsets.
    """
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    bases = [0x1000, 0x2000, 0x3000]
    offsets = [{"offset": 0, "classification": "shared_pointer",
                "distinct_values": 1, "readable_instances": 3,
                "modal_value": 0x7FF800001234, "modal_votes": 3,
                "probable_type": "pointer",
                "shared_target_module": "game.exe",
                "shared_target_module_off": 0x1234}]
    canned = _canned_response(bases, offsets)
    c = _CannedCompareClient(canned)

    # Monkey-patch the decorator to short-circuit with empty results —
    # emulates the no-PDB-cached path.
    from src.pry.mcp.tools.mem import _decorate as decorate_mod

    class _StubDecorator:
        def __init__(self, ctx):
            self._ctx = ctx

        async def decorate_vas(self, view, pid, vas):
            return {int(va): None for va in vas}

    orig = decorate_mod.SymbolDecorator
    decorate_mod.SymbolDecorator = _StubDecorator  # type: ignore[misc]
    try:
        env = json.loads(asyncio.run(ds.handle_dissect_compare(
            ctx, c, pid=1234, base_vas=bases, window_size=64, align=8,
            space="user", with_modules=True, decorate=True,
            name="lab2.user")))
    finally:
        decorate_mod.SymbolDecorator = orig  # type: ignore[misc]

    assert env["ok"] is True
    off0 = env["data"]["offsets"][0]
    assert off0["shared_target"] == "game.exe+0x1234"


def test_handle_envelope_wrap_shape_is_consistent():
    """Make sure the handler's envelope matches the other mem/*
    envelopes (tool='memory_manage', action='dissect_compare',
    target=view)."""
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    canned = _canned_response([0x1000, 0x2000, 0x3000], [])
    c = _CannedCompareClient(canned)
    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=1234, base_vas=[0x1000, 0x2000, 0x3000],
        window_size=64, align=8, space="user", with_modules=False,
        decorate=False, name="lab2.user")))
    assert env["tool"] == "memory_manage"
    assert env["action"] == "dissect_compare"
    assert env["target"] == "lab2.user"
    assert "data" in env


def test_handle_unreadable_instance_preserved_in_envelope():
    """A mocked agent response with a per-instance unreadable row must
    thread through the handler envelope unchanged (nested-row
    invariant)."""
    sess = _FakeSession(dissect_version=2)
    ctx = _FakeCtx(sess)
    bases = [0x1000, 0x2000, 0x3000]
    per_instance = [
        {"base_va": 0x1000, "unreadable": False,
         "slots": [{"offset": 0, "u64_le": 0xCAFE,
                    "ptr_target_va": 0, "ptr_module": "",
                    "ptr_module_off": 0, "ptr_classification": "",
                    "ascii_prefix": "", "utf16_prefix": "",
                    "probable_type": "i32",
                    "va": 0x1000, "i32_le": 0, "u32_le": 0,
                    "f32_le": 0.0, "f64_le": 0.0,
                    "score_pointer": 0, "score_utf16": 0,
                    "score_ascii": 0, "score_f64": 0, "score_f32": 0}]},
        {"base_va": 0x2000, "unreadable": True, "slots": []},
        {"base_va": 0x3000, "unreadable": False,
         "slots": [{"offset": 0, "u64_le": 0xCAFE,
                    "ptr_target_va": 0, "ptr_module": "",
                    "ptr_module_off": 0, "ptr_classification": "",
                    "ascii_prefix": "", "utf16_prefix": "",
                    "probable_type": "i32",
                    "va": 0x3000, "i32_le": 0, "u32_le": 0,
                    "f32_le": 0.0, "f64_le": 0.0,
                    "score_pointer": 0, "score_utf16": 0,
                    "score_ascii": 0, "score_f64": 0, "score_f32": 0}]},
    ]
    canned = {"ok": True,
              "offsets": [{"offset": 0, "classification": "stable",
                            "distinct_values": 1, "readable_instances": 2,
                            "modal_value": 0xCAFE, "modal_votes": 2,
                            "probable_type": "i32",
                            "shared_target_module": "",
                            "shared_target_module_off": 0}],
              "per_instance": per_instance,
              "n_instances": 3, "n_offsets": 1}
    c = _CannedCompareClient(canned)
    env = json.loads(asyncio.run(ds.handle_dissect_compare(
        ctx, c, pid=1234, base_vas=bases, window_size=64, align=8,
        space="user", with_modules=False, decorate=False,
        name="lab2.user")))
    assert env["ok"] is True
    pi = env["data"]["per_instance"]
    assert len(pi) == 3
    assert pi[1]["unreadable"] is True
    assert pi[1]["slots"] == []
    # Index alignment: slot rows on readable instances stay in place.
    assert pi[0]["slots"][0]["u64_le"] == 0xCAFE
    assert pi[2]["slots"][0]["u64_le"] == 0xCAFE
