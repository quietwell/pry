"""proto surface additions.

Pins the proto fields that P5 adds so a future regen that drops one
breaks here before a downstream consumer blows up. Pure import-time
test, no agent contact.

Fields covered:

* ``StatusResponse.dissect_version`` — dedicated DissectService advert
  (P0 item 5 / §A.0). Older agents left this absent; the Wave 2
  Dissect router proxied on ``pointer_map_version``.
* ``PointerScanResponse.wall_exceeded`` + ``fanout_exceeded`` —
  disambiguated truncation cause (P0 item 4).
* ``DissectResponse.total_rows`` + ``truncated`` — DISSECT_MAX_ROWS
  truncation surfacing (P1 item 10).
* ``PointerMapListEntry.needs_load`` — discovery-without-mmap advert
  (P1 item 7).
* ``OpStatus.kind`` — typed agent-set error kind (P1 item 11).
"""
from __future__ import annotations

import sys
from pathlib import Path

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.generated import pry_pb2 as pb  # noqa: E402


# --------------------------------------------- StatusResponse.dissect_version

def test_status_response_has_dissect_version_field():
    """P0 item 5 / §A.0: dedicated DissectService advert alongside
    the Wave 1 ``scan_service_version`` + Wave 2 ``pointer_map_version``.
    Older agents left this absent so the dissect router used
    ``pointer_map_version`` as a proxy."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert "dissect_version" in fields, (
        "StatusResponse.dissect_version missing — Wave 3 P5 adds it so "
        "the dissect router doesn't proxy on pointer_map_version")


def test_status_response_dissect_version_defaults_to_zero():
    """proto3 default: older agents that don't set the field
    present as 0 on the wire. The orchestrator gate reads 0 as
    fallback-only, matching the older (pointer_map_version
    proxy) behaviour."""
    msg = pb.StatusResponse()
    assert msg.dissect_version == 0


def test_status_response_keeps_scan_service_and_pointer_map_versions():
    """A field addition must not displace the Wave 1 / Wave 2 adverts."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert "scan_service_version" in fields
    assert "pointer_map_version" in fields
    assert "dissect_version" in fields


def test_status_response_field_tags_stable():
    """Tag numbers are part of the wire ABI. A regen that reused a
    taken tag silently breaks every old client."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert fields["scan_service_version"].number == 15
    assert fields["pointer_map_version"].number == 16
    assert fields["dissect_version"].number == 17


# -------------------------------------------- PointerScanResponse new bools --

def test_pointer_scan_response_has_wall_and_fanout_exceeded():
    """P0 item 4: disambiguates ``truncated``. Older orchestrators
    tried to re-derive the cause from ``wall_ms_actual > 0`` and got
    every truncated scan tagged as wall_ms_exceeded."""
    fields = pb.PointerScanResponse.DESCRIPTOR.fields_by_name
    assert "wall_exceeded" in fields
    assert "fanout_exceeded" in fields
    msg = pb.PointerScanResponse()
    assert msg.wall_exceeded is False
    assert msg.fanout_exceeded is False


# -------------------------------------------- DissectResponse new fields -----

def test_dissect_response_has_total_rows_and_truncated():
    """P1 item 10: surface the ``DISSECT_MAX_ROWS=4096`` truncation
    so a caller sees "hit cap" vs "short read"."""
    fields = pb.DissectResponse.DESCRIPTOR.fields_by_name
    assert "total_rows" in fields
    assert "truncated" in fields
    msg = pb.DissectResponse()
    assert msg.total_rows == 0
    assert msg.truncated is False


# ------------------------------------------- PointerMapListEntry.needs_load --

def test_pointer_map_list_entry_has_needs_load():
    """P1 item 7: discovery pass seeds Done entries without mmap'ing;
    callers need to know to call Load before Scan/Diff."""
    fields = pb.PointerMapListEntry.DESCRIPTOR.fields_by_name
    assert "needs_load" in fields
    msg = pb.PointerMapListEntry()
    assert msg.needs_load is False


# --------------------------------------------- OpStatus.kind -----------------

def test_op_status_has_kind_field():
    """P1 item 11: agent-set typed error slug. Orchestrator substring
    matching stays as fallback for older agents."""
    fields = pb.OpStatus.DESCRIPTOR.fields_by_name
    assert "kind" in fields
    msg = pb.OpStatus()
    assert msg.kind == ""


def test_op_status_kind_round_trip():
    """A newer agent sets ``kind='too_many_chains'``; the field must
    survive proto serialization + parse."""
    msg = pb.OpStatus()
    msg.ok = False
    msg.error = "too many chains (cap 1024)"
    msg.kind = "too_many_chains"
    wire = msg.SerializeToString()
    parsed = pb.OpStatus()
    parsed.ParseFromString(wire)
    assert parsed.kind == "too_many_chains"
    assert parsed.ok is False
