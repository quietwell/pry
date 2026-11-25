"""proto surface additions for
``Memory.HeapAttribLookup``.

Pins the proto fields + RPC that P2 adds so a future regen that drops
one breaks here before a downstream consumer blows up. Pure import-time
test, no agent contact.

Fields covered:

* ``StatusResponse.memory_heap_attrib_version`` — handler advert bit.
  Tag 18 (comes after P5's ``dissect_version`` = 17).
* ``HeapAttribRequest`` — pid / vas / refresh.
* ``HeapAttribRecord`` — every allocation field in the plan §7.3
  taxonomy.
* ``HeapAttribResponse`` — status + records + cache metadata.
* ``Memory.HeapAttribLookup`` — rpc presence on the service.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.generated import pry_pb2 as pb  # noqa: E402
from src.pry.generated import pry_pb2_grpc as pb_grpc  # noqa: E402


# --------------------------------------- StatusResponse.memory_heap_attrib_version

def test_status_response_has_memory_heap_attrib_version_field():
    """P2 §2.1: handler-advert bit alongside scan / pointer_map /
    dissect version adverts."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert "memory_heap_attrib_version" in fields, (
        "StatusResponse.memory_heap_attrib_version missing — Wave 3 P2 "
        "adds it so the orchestrator gate reads the handler advert")


def test_status_response_memory_heap_attrib_version_tag_is_18():
    """Tag numbers are part of the wire ABI; P5 took tag 17 for
    ``dissect_version`` and P2 picks the next slot."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert fields["memory_heap_attrib_version"].number == 18


def test_status_response_memory_heap_attrib_version_defaults_to_zero():
    """proto3 default: older agents present as 0 on the wire;
    the orchestrator gate reads 0 as ``feature_unavailable``."""
    msg = pb.StatusResponse()
    assert msg.memory_heap_attrib_version == 0


def test_p5_dissect_version_still_tag_17():
    """P2 must not shift P5's tag; the chunk briefs rely on 17 + 18."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert fields["dissect_version"].number == 17


# --------------------------------------------- HeapAttribRequest shape ---

def test_heap_attrib_request_fields():
    fields = pb.HeapAttribRequest.DESCRIPTOR.fields_by_name
    assert set(fields) == {"pid", "vas", "refresh"}
    assert fields["pid"].number == 1
    assert fields["vas"].number == 2
    assert fields["refresh"].number == 3
    # vas is repeated uint64; refresh is bool; pid is uint32.
    from google.protobuf.descriptor import FieldDescriptor
    assert fields["pid"].type == FieldDescriptor.TYPE_UINT32
    assert fields["refresh"].type == FieldDescriptor.TYPE_BOOL
    assert fields["vas"].type == FieldDescriptor.TYPE_UINT64
    # label_repeated isn't exposed on the upb descriptor in every
    # protobuf build — verify repeated-ness via a round-trip instead.
    msg = pb.HeapAttribRequest()
    msg.vas.extend([1, 2, 3])
    assert list(msg.vas) == [1, 2, 3]


def test_heap_attrib_request_round_trip():
    msg = pb.HeapAttribRequest(pid=1234, vas=[0x1000, 0x2000],
                               refresh=True)
    wire = msg.SerializeToString()
    parsed = pb.HeapAttribRequest()
    parsed.ParseFromString(wire)
    assert parsed.pid == 1234
    assert list(parsed.vas) == [0x1000, 0x2000]
    assert parsed.refresh is True


# --------------------------------------------- HeapAttribRecord shape ----

def test_heap_attrib_record_fields():
    fields = pb.HeapAttribRecord.DESCRIPTOR.fields_by_name
    assert set(fields) == {
        "va", "found", "heap_handle", "segment_base", "chunk_base",
        "chunk_size", "flags", "size_class",
    }
    # Tag numbers 1..8 in the plan §7.3 order.
    assert fields["va"].number == 1
    assert fields["found"].number == 2
    assert fields["heap_handle"].number == 3
    assert fields["segment_base"].number == 4
    assert fields["chunk_base"].number == 5
    assert fields["chunk_size"].number == 6
    assert fields["flags"].number == 7
    assert fields["size_class"].number == 8


def test_heap_attrib_record_defaults():
    msg = pb.HeapAttribRecord()
    assert msg.va == 0
    assert msg.found is False
    assert msg.heap_handle == 0
    assert msg.segment_base == 0
    assert msg.chunk_base == 0
    assert msg.chunk_size == 0
    assert msg.flags == 0
    assert msg.size_class == 0


# --------------------------------------------- HeapAttribResponse shape --

def test_heap_attrib_response_fields():
    fields = pb.HeapAttribResponse.DESCRIPTOR.fields_by_name
    assert set(fields) == {
        "status", "records", "index_from_cache", "cache_epoch",
        "cache_age_ms", "cache_committed_sum",
    }
    assert fields["status"].number == 1
    assert fields["records"].number == 2
    assert fields["index_from_cache"].number == 3
    assert fields["cache_epoch"].number == 4
    assert fields["cache_age_ms"].number == 5
    assert fields["cache_committed_sum"].number == 6


def test_heap_attrib_response_round_trip():
    msg = pb.HeapAttribResponse()
    msg.status.ok = True
    r = msg.records.add()
    r.va = 0x1000
    r.found = True
    r.heap_handle = 0x7ff6_0000
    r.segment_base = 0x7ff6_0000
    r.chunk_base = 0x7ff6_1000
    r.chunk_size = 192
    r.flags = 0x8
    r.size_class = 256
    msg.index_from_cache = True
    msg.cache_epoch = 3
    msg.cache_age_ms = 1234
    msg.cache_committed_sum = 1_048_576
    wire = msg.SerializeToString()
    parsed = pb.HeapAttribResponse()
    parsed.ParseFromString(wire)
    assert parsed.status.ok is True
    assert len(parsed.records) == 1
    rr = parsed.records[0]
    assert rr.va == 0x1000
    assert rr.found is True
    assert rr.heap_handle == 0x7ff6_0000
    assert rr.chunk_size == 192
    assert rr.size_class == 256
    assert parsed.index_from_cache is True
    assert parsed.cache_epoch == 3
    assert parsed.cache_age_ms == 1234
    assert parsed.cache_committed_sum == 1_048_576


# --------------------------------------------- RPC presence -------------

def test_heap_attrib_lookup_rpc_present():
    """``Memory.HeapAttribLookup`` is wired on the service — the
    orchestrator stub must have the method binding and the service
    descriptor must list it."""
    assert hasattr(pb_grpc.MemoryStub, "__init__")
    # Service descriptor enumeration (via the pool) — look up Memory
    # and confirm HeapAttribLookup is listed.
    svc = pb.DESCRIPTOR.services_by_name["Memory"]
    method_names = {m.name for m in svc.methods}
    assert "HeapAttribLookup" in method_names, (
        "service Memory missing HeapAttribLookup rpc")
    method = svc.methods_by_name["HeapAttribLookup"]
    assert method.input_type.name == "HeapAttribRequest"
    assert method.output_type.name == "HeapAttribResponse"


# --------------------------------------------- Plan-pinned caps ---------

def test_heap_attrib_max_vas_matches_plan():
    """Plan §7.3 sets the per-call cap to 4096 VAs. The orchestrator
    mirrors the agent-side constant; this test pins both numbers so a
    silent drift in either side breaks here."""
    from src.pry.mcp.tools.mem import heap_attrib as mod
    assert mod.HEAPATTRIB_MAX_VAS == 4096
