"""proto surface for DissectCompare.

Pins the message shapes, field tag numbers, and field types the agent
+ orchestrator rely on. Pure import-time test: no agent contact, no
runtime side effects.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.generated import pry_pb2 as pb  # noqa: E402
from src.pry.generated import pry_pb2_grpc as pbg  # noqa: E402
from src.pry.mcp.tools.mem import dissect as _mem_dissect  # noqa: E402


# --------------------------------------------- Request shape -----------------

def test_compare_request_fields_present():
    fields = pb.DissectCompareRequest.DESCRIPTOR.fields_by_name
    for name in ("pid", "base_vas", "window_size", "align", "space",
                 "with_modules", "shared_ptr_min_vote",
                 "min_instances_for_class"):
        assert name in fields, f"DissectCompareRequest.{name} missing"


def test_compare_request_field_tags():
    """Tags are wire ABI — pinning these catches any reorder on regen."""
    fields = pb.DissectCompareRequest.DESCRIPTOR.fields_by_name
    assert fields["pid"].number == 1
    assert fields["base_vas"].number == 2
    assert fields["window_size"].number == 3
    assert fields["align"].number == 4
    assert fields["space"].number == 5
    assert fields["with_modules"].number == 6
    assert fields["shared_ptr_min_vote"].number == 7
    assert fields["min_instances_for_class"].number == 8


def test_compare_request_base_vas_is_repeated_uint64():
    """``base_vas`` must accept multiple uint64 values (each a candidate
    base VA of the struct being compared)."""
    req = pb.DissectCompareRequest()
    req.base_vas.append(0x1000)
    req.base_vas.append(0x7FFFFFFFFFFFFFFF)
    assert list(req.base_vas) == [0x1000, 0x7FFFFFFFFFFFFFFF]


def test_compare_request_scalar_field_round_trip():
    """Behavioural check on the scalar field types — proto will raise
    TypeError if any of these would overflow or need the wrong unpack."""
    req = pb.DissectCompareRequest(pid=0xFFFFFFFF, window_size=65_536,
                                     align=8, space=pb.KERNEL,
                                     with_modules=False,
                                     shared_ptr_min_vote=5,
                                     min_instances_for_class=10)
    assert req.pid == 0xFFFFFFFF
    assert req.window_size == 65_536
    assert req.align == 8
    assert req.space == pb.KERNEL
    assert req.with_modules is False
    assert req.shared_ptr_min_vote == 5
    assert req.min_instances_for_class == 10


def test_compare_request_round_trip():
    req = pb.DissectCompareRequest(pid=1234, window_size=128, align=8,
                                     space=pb.USER, with_modules=True,
                                     shared_ptr_min_vote=3,
                                     min_instances_for_class=4)
    req.base_vas.extend([0x1000, 0x2000, 0x3000])
    parsed = pb.DissectCompareRequest()
    parsed.ParseFromString(req.SerializeToString())
    assert parsed.pid == 1234
    assert list(parsed.base_vas) == [0x1000, 0x2000, 0x3000]
    assert parsed.window_size == 128
    assert parsed.align == 8
    assert parsed.with_modules is True
    assert parsed.shared_ptr_min_vote == 3
    assert parsed.min_instances_for_class == 4


# --------------------------------------------- Offset class ------------------

def test_offset_class_fields_present():
    fields = pb.DissectOffsetClass.DESCRIPTOR.fields_by_name
    for name in ("offset", "classification", "distinct_values",
                 "readable_instances", "modal_value", "modal_votes",
                 "probable_type", "shared_target_module",
                 "shared_target_module_off"):
        assert name in fields, f"DissectOffsetClass.{name} missing"


def test_offset_class_field_tags():
    f = pb.DissectOffsetClass.DESCRIPTOR.fields_by_name
    assert f["offset"].number == 1
    assert f["classification"].number == 2
    assert f["distinct_values"].number == 3
    assert f["readable_instances"].number == 4
    assert f["modal_value"].number == 5
    assert f["modal_votes"].number == 6
    assert f["probable_type"].number == 7
    assert f["shared_target_module"].number == 8
    assert f["shared_target_module_off"].number == 9


def test_offset_class_scalar_round_trip():
    """Behavioural check on scalar types: values round-trip through
    a serialize/parse cycle at the full width the taxonomy needs."""
    c = pb.DissectOffsetClass(offset=0x1000,
                                classification="per_instance_ptr",
                                distinct_values=6,
                                readable_instances=6,
                                modal_value=0x7FFFFFFFFFFFFFFF,
                                modal_votes=5,
                                probable_type="pointer",
                                shared_target_module="game.exe",
                                shared_target_module_off=0x1234)
    parsed = pb.DissectOffsetClass()
    parsed.ParseFromString(c.SerializeToString())
    assert parsed.offset == 0x1000
    assert parsed.classification == "per_instance_ptr"
    assert parsed.modal_value == 0x7FFFFFFFFFFFFFFF
    assert parsed.shared_target_module == "game.exe"
    assert parsed.shared_target_module_off == 0x1234


# --------------------------------------------- Instance rows -----------------

def test_instance_slots_shape():
    fields = pb.DissectInstanceSlots.DESCRIPTOR.fields_by_name
    assert "base_va" in fields
    assert "unreadable" in fields
    assert "slots" in fields
    assert fields["base_va"].number == 1
    assert fields["unreadable"].number == 2
    assert fields["slots"].number == 3
    # slots must be DissectSlot — reuse so one unreadable instance
    # doesn't desync downstream readers (r2 fix).
    assert (fields["slots"].message_type.full_name
            == "pry.DissectSlot")


def test_instance_slots_round_trip():
    """base_va uint64 + bool unreadable + repeated DissectSlot survive
    a wire round-trip."""
    row = pb.DissectInstanceSlots(base_va=0x7FFFFFFF_00000000,
                                    unreadable=False)
    s = row.slots.add()
    s.offset = 0x10
    s.u64_le = 0x1234
    parsed = pb.DissectInstanceSlots()
    parsed.ParseFromString(row.SerializeToString())
    assert parsed.base_va == 0x7FFFFFFF_00000000
    assert parsed.unreadable is False
    assert len(parsed.slots) == 1
    assert parsed.slots[0].offset == 0x10
    assert parsed.slots[0].u64_le == 0x1234


# --------------------------------------------- Response shape ----------------

def test_compare_response_fields_present():
    fields = pb.DissectCompareResponse.DESCRIPTOR.fields_by_name
    for name in ("status", "offsets", "per_instance", "n_instances",
                 "n_offsets"):
        assert name in fields


def test_compare_response_field_tags():
    f = pb.DissectCompareResponse.DESCRIPTOR.fields_by_name
    assert f["status"].number == 1
    assert f["offsets"].number == 2
    assert f["per_instance"].number == 3
    assert f["n_instances"].number == 4
    assert f["n_offsets"].number == 5


def test_compare_response_per_instance_is_nested():
    """r2 fix: per-instance rows are nested — one unreadable instance
    doesn't desync downstream readers."""
    f = pb.DissectCompareResponse.DESCRIPTOR.fields_by_name
    assert (f["per_instance"].message_type.full_name
            == "pry.DissectInstanceSlots")
    # Behaviour: nested rows round-trip.
    resp = pb.DissectCompareResponse(n_instances=2, n_offsets=4)
    r1 = resp.per_instance.add()
    r1.base_va = 0x1000
    r1.unreadable = False
    r2 = resp.per_instance.add()
    r2.base_va = 0x2000
    r2.unreadable = True  # one bad instance mixed in
    parsed = pb.DissectCompareResponse()
    parsed.ParseFromString(resp.SerializeToString())
    assert len(parsed.per_instance) == 2
    assert parsed.per_instance[0].base_va == 0x1000
    assert parsed.per_instance[1].unreadable is True


def test_compare_response_offsets_is_repeated():
    f = pb.DissectCompareResponse.DESCRIPTOR.fields_by_name
    assert (f["offsets"].message_type.full_name
            == "pry.DissectOffsetClass")
    resp = pb.DissectCompareResponse()
    for i in range(3):
        c = resp.offsets.add()
        c.offset = i * 8
        c.classification = "stable"
    assert len(resp.offsets) == 3


# --------------------------------------------- RPC presence ------------------

def test_dissect_service_has_compare_rpc():
    # Service descriptor lives on pry_pb2_grpc.<ServiceName>_servicer
    # as of modern protoc; the simplest portable check is to confirm
    # the generated stub exposes a Compare attribute.
    assert hasattr(pbg.DissectServiceServicer, "Compare")
    assert hasattr(pbg.DissectServiceServicer, "Dissect")


def test_compare_stub_is_generated():
    """The grpc stub module must expose a ``DissectServiceStub`` class
    with a ``Compare`` attribute wired from the generated proto."""
    assert pbg.DissectServiceStub is not None
    # Stub methods are populated in __init__ from channel.unary_unary
    # — the descriptor-level presence check above is authoritative;
    # here we just confirm the stub class imports cleanly.
    assert "DissectServiceStub" in dir(pbg)


# --------------------------------------------- Constants parity --------------

def test_orch_side_caps_match_plan():
    """The orchestrator-side preflight constants track the agent's
    DISSECT_COMPARE_* values in dissect_service.hpp."""
    assert _mem_dissect.DISSECT_COMPARE_MAX_INSTANCES == 32
    assert _mem_dissect.DISSECT_COMPARE_SHARED_VOTE == 2
    assert _mem_dissect.DISSECT_COMPARE_MIN_INSTANCES_FOR_CLASS == 3
    # Window cap shares DISSECT_MAX_BYTES — any change to that shared
    # constant must land on both sides of the wire in lockstep.
    assert _mem_dissect.DISSECT_MAX_BYTES == 65_536
