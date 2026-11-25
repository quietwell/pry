"""v17 (Memory scanner wave 2 Phase A): PointerMapService + DissectService
proto surface sanity.

Asserts the generated ``pry_pb2`` / ``pry_pb2_grpc`` carry the
exact shape locked in by ``an internal plan``
§3.5 — service names, every RPC method, every message type, and every
field the orchestrator depends on. Pure import-time test, no agent /
server contact.

Mirrors ``test_scan_service_proto.py`` from Wave 1. If any test here
fails after a proto regen, something either dropped a field or renamed
one; fix the regen before touching Python callers.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from src.pry.generated import pry_pb2 as pb  # noqa: E402
from src.pry.generated import pry_pb2_grpc as pbg  # noqa: E402


# ----------------------------------------------- PointerMapService surface ---

def test_pointer_map_service_stub_exists():
    assert hasattr(pbg, "PointerMapServiceStub"), (
        "PointerMapServiceStub missing from pry_pb2_grpc — did "
        "gen_proto.ps1 regen against the v17 proto?")
    assert hasattr(pbg, "PointerMapServiceServicer"), \
        "PointerMapServiceServicer missing — unusual (same codegen produces it)"


@pytest.mark.parametrize("rpc", [
    "Create", "Status", "List", "Cancel", "Save", "Load", "Destroy",
    "Scan", "Diff",
])
def test_pointer_map_service_has_rpc(rpc):
    # Servicer base class has the RPC methods as plain method names.
    assert hasattr(pbg.PointerMapServiceServicer, rpc), (
        f"PointerMapService missing RPC {rpc!r}; plan §3.5 lists it as required")


# ----------------------------------------------- DissectService surface ---

def test_dissect_service_stub_exists():
    assert hasattr(pbg, "DissectServiceStub"), (
        "DissectServiceStub missing from pry_pb2_grpc — did "
        "gen_proto.ps1 regen against the v17 proto?")
    assert hasattr(pbg, "DissectServiceServicer"), \
        "DissectServiceServicer missing — unusual (same codegen produces it)"


def test_dissect_service_has_rpc():
    assert hasattr(pbg.DissectServiceServicer, "Dissect"), (
        "DissectService.Dissect RPC missing")


# ---------------------------------------------- PointerMap message fields ---

@pytest.mark.parametrize("msg,expected_fields", [
    ("PointerMapProgress", {
        "regions_scanned", "regions_total", "bytes_scanned",
        "bytes_total", "candidates_so_far", "chunks_skipped"}),
    ("PointerMapCreateRequest", {
        "map_id", "pid", "space", "spans", "max_candidates",
        "owner_client_id", "disk_spill_mode"}),
    ("PointerMapCreateResponse", {
        "status", "map_id", "status_s", "progress"}),
    ("PointerMapStatusRequest", {"map_id"}),
    ("PointerMapStatusResponse", {
        "status", "map_id", "status_s", "progress", "entries",
        "disk_bytes", "error"}),
    ("PointerMapListRequest", set()),
    ("PointerMapListEntry", {
        "map_id", "pid", "space", "status_s", "entries", "disk_bytes",
        "created_ts_ms"}),
    ("PointerMapListResponse", {"status", "entries"}),
    ("PointerMapCancelRequest", {"map_id"}),
    ("PointerMapCancelResponse", {"status", "map_id", "status_s"}),
    ("PointerMapSaveRequest", {"map_id", "remote_path"}),
    ("PointerMapSaveResponse", {"status", "bytes_written"}),
    ("PointerMapLoadRequest", {"remote_path", "map_id"}),
    ("PointerMapLoadResponse", {"status", "map_id", "entries"}),
    ("PointerMapDestroyRequest", {"map_id", "keep_disk"}),
    ("PointerMapDestroyResponse", {
        "status", "ram_bytes_freed", "disk_bytes_freed"}),
    ("PointerScanRequest", {
        "map_id", "target_va", "max_depth", "max_offset", "static_only",
        "max_results", "fanout_per_level", "wall_ms"}),
    ("PointerScanChain", {
        "anchor_va", "anchor_module", "anchor_module_off", "anchor_class",
        "offsets", "static_"}),
    ("PointerScanResponse", {
        "status", "chains", "truncated", "wall_ms_actual",
        "candidates_examined"}),
    ("PointerMapDiffRequest", {
        "map_id_a", "map_id_b", "static_only", "chains"}),
    ("PointerMapDiffRow", {
        "source_va_a", "source_va_b", "target_va_a", "target_va_b",
        "canonical_target", "still_valid", "drift_reason"}),
    ("PointerMapDiffResponse", {
        "status", "rows", "compared_entries", "truncated"}),
])
def test_pointer_map_message_has_fields(msg, expected_fields):
    assert hasattr(pb, msg), f"message {msg} missing from pry_pb2"
    got = set(getattr(pb, msg).DESCRIPTOR.fields_by_name.keys())
    missing = expected_fields - got
    assert not missing, (
        f"{msg} missing fields: {sorted(missing)} (got {sorted(got)})")


# ------------------------------------------------ Dissect message fields ---

@pytest.mark.parametrize("msg,expected_fields", [
    ("DissectRequest", {
        "pid", "address", "size", "space", "with_modules", "decode",
        "align"}),
    ("DissectResponse", {"status", "slots"}),
    ("DissectSlot", {
        "offset", "va", "u64_le", "i32_le", "u32_le", "f32_le", "f64_le",
        "ptr_target_va", "ptr_module", "ptr_module_off",
        "ptr_classification", "ascii_prefix", "utf16_prefix",
        "probable_type", "score_pointer", "score_utf16", "score_ascii",
        "score_f64", "score_f32"}),
])
def test_dissect_message_has_fields(msg, expected_fields):
    assert hasattr(pb, msg), f"message {msg} missing from pry_pb2"
    got = set(getattr(pb, msg).DESCRIPTOR.fields_by_name.keys())
    missing = expected_fields - got
    assert not missing, (
        f"{msg} missing fields: {sorted(missing)} (got {sorted(got)})")


# ---------------------------------------------- Wave 2 StatusResponse advert ---

def test_status_response_has_pointer_map_version():
    """The capability advert the pointer-map router keys off (§2.9)."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert "pointer_map_version" in fields, (
        "StatusResponse.pointer_map_version missing — v17 orchestrator "
        "cannot refuse vs route without this field")
    msg = pb.StatusResponse()
    assert msg.pointer_map_version == 0


def test_status_response_keeps_scan_service_version():
    """Wave 2's bump must not break the Wave 1 advert."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert "scan_service_version" in fields, (
        "StatusResponse.scan_service_version dropped on the v17 bump — "
        "Wave 1 clients cannot route without it")


# -------------------------------------------- Request/response defaults ---

def test_pointer_map_create_request_defaults():
    """Default-constructed request has sane proto3 defaults (empty
    spans, zero caps). Guards against a schema-level change where a
    required-looking field became non-zero by accident."""
    req = pb.PointerMapCreateRequest()
    assert req.map_id == ""
    assert req.pid == 0
    assert list(req.spans) == []
    assert req.max_candidates == 0
    assert req.owner_client_id == ""


def test_pointer_scan_request_defaults():
    req = pb.PointerScanRequest()
    assert req.map_id == ""
    assert req.target_va == 0
    assert req.max_depth == 0
    assert req.max_offset == 0
    assert req.static_only is False
    assert req.max_results == 0
    assert req.fanout_per_level == 0
    assert req.wall_ms == 0


def test_dissect_request_decode_is_repeated_string():
    """``decode`` must be ``repeated string`` so 'auto' and the
    subset-of-types forms share one field."""
    req = pb.DissectRequest()
    req.decode.append("pointer")
    req.decode.append("utf16")
    assert list(req.decode) == ["pointer", "utf16"]


def test_pointer_scan_chain_offsets_is_repeated_uint64():
    """``offsets`` is the per-hop offset list — must accept uint64
    values (CE chains can address every byte of a large object)."""
    chain = pb.PointerScanChain()
    chain.offsets.append(0x1000)
    chain.offsets.append(0xFFFFFFFFFFFF)  # 48-bit, inside uint64
    assert list(chain.offsets) == [0x1000, 0xFFFFFFFFFFFF]


def test_pointer_map_diff_request_chains_is_repeated():
    """A diff may be filtered by a prior scan's chain list; must be
    repeated so an empty list means 'diff every shared source_va'."""
    req = pb.PointerMapDiffRequest()
    chain = req.chains.add()
    chain.anchor_va = 0x7ff000000000
    chain.anchor_module = "ntdll.dll"
    assert len(req.chains) == 1
    assert req.chains[0].anchor_module == "ntdll.dll"


# --------------------------------------------- ScanSpan + ScanDiskSpillMode reuse ---

def test_pointer_map_reuses_scan_span():
    """Wave 2 reuses Wave 1's ScanSpan (§2.4). A new ScanSpan message
    would be a plan violation."""
    req = pb.PointerMapCreateRequest()
    span = req.spans.add()
    span.va = 0x400000
    span.size = 0x10000
    assert len(req.spans) == 1
    assert req.spans[0].va == 0x400000
    assert req.spans[0].size == 0x10000


def test_pointer_map_reuses_scan_disk_spill_mode():
    """Same enum as Wave 1's ScanService."""
    req = pb.PointerMapCreateRequest(disk_spill_mode=pb.SCAN_SPILL_AUTO)
    assert req.disk_spill_mode == pb.SCAN_SPILL_AUTO
    req.disk_spill_mode = pb.SCAN_SPILL_RAM_ONLY
    assert req.disk_spill_mode == pb.SCAN_SPILL_RAM_ONLY
