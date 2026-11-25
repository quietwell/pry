"""v16 (Memory scanner wave 1 Phase B): ScanService proto surface sanity.

Asserts the generated ``pry_pb2`` / ``pry_pb2_grpc`` carry the
exact shape the plan locks in — service name, every RPC method,
every message type, and every field the orchestrator depends on.
Pure import-time test, no agent / server contact.

If this test fails after a proto regen, something either dropped a
field or renamed one; fix the regen before touching Python callers.
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


# -------------------------------------------------------- service surface ----

def test_scan_service_stub_exists():
    assert hasattr(pbg, "ScanServiceStub"), (
        "ScanServiceStub missing from pry_pb2_grpc — did gen_proto.ps1 "
        "regen against the v16 proto?")
    assert hasattr(pbg, "ScanServiceServicer"), \
        "ScanServiceServicer missing — unusual (same codegen produces it)"


@pytest.mark.parametrize("rpc", [
    "Create", "Refine", "Undo", "Fetch",
    "Cancel", "Destroy", "List", "Status",
])
def test_scan_service_has_rpc(rpc):
    # The stub's RPC methods are attributes on the stub class (callables
    # after instantiation). We check the servicer base class because it
    # has them as plain method names — `servicer.<Rpc>` exists.
    assert hasattr(pbg.ScanServiceServicer, rpc), (
        f"ScanService missing RPC {rpc!r}; plan §3.5 lists it as required")


# -------------------------------------------------- message surface --------

@pytest.mark.parametrize("msg,expected_fields", [
    ("ScanSpan", {"va", "size"}),
    ("ScanCreateRequest", {
        "scan_id", "pid", "space", "value_type", "endian", "encoding",
        "align", "op", "value_le", "value_hi_le", "tolerance_bits",
        "spans", "max_results", "owner_client_id", "disk_spill_mode"}),
    ("ScanCreateResponse", {
        "status", "scan_id", "status_s", "generation", "progress"}),
    ("ScanRefineRequest", {
        "scan_id", "op", "value_le", "value_hi_le", "delta_le",
        "tolerance_bits"}),
    ("ScanRefineResponse", {
        "status", "scan_id", "generation", "hit_count", "dropped",
        "reads_failed", "status_s"}),
    ("ScanUndoRequest", {"scan_id"}),
    ("ScanUndoResponse", {"status", "scan_id", "generation", "hit_count"}),
    ("ScanFetchRequest", {"scan_id", "limit", "offset", "generation"}),
    ("ScanRow", {"va", "raw_value"}),
    ("ScanFetchChunk", {
        "status", "generation", "rows", "eof", "total_remaining"}),
    ("ScanCancelRequest", {"scan_id"}),
    ("ScanCancelResponse", {"status", "scan_id", "status_s"}),
    ("ScanDestroyRequest", {"scan_id"}),
    ("ScanDestroyResponse", {
        "status", "scan_id", "disk_bytes_freed", "ram_bytes_freed"}),
    ("ScanListRequest", set()),
    ("ScanListResponse", {"status", "entries"}),
    ("ScanStatusRequest", {"scan_id"}),
    ("ScanStatusResponse", {
        "status", "scan_id", "status_s", "generation", "hit_count",
        "progress", "error"}),
    ("ScanProgress", {
        "bytes_scanned", "bytes_total", "chunks_read", "chunks_skipped",
        "hits_so_far", "reads_failed"}),
    ("ScanEntry", {
        "scan_id", "pid", "space", "value_type", "width", "status",
        "generation", "hit_count", "created_ts_ms", "owner_client_id",
        "disk_bytes", "ram_bytes"}),
])
def test_scan_message_has_fields(msg, expected_fields):
    assert hasattr(pb, msg), f"message {msg} missing from pry_pb2"
    got = set(getattr(pb, msg).DESCRIPTOR.fields_by_name.keys())
    missing = expected_fields - got
    assert not missing, f"{msg} missing fields: {sorted(missing)} (got {sorted(got)})"


def test_scan_disk_spill_mode_enum():
    assert hasattr(pb, "SCAN_SPILL_AUTO")
    assert hasattr(pb, "SCAN_SPILL_RAM_ONLY")
    assert pb.SCAN_SPILL_AUTO == 0
    assert pb.SCAN_SPILL_RAM_ONLY == 1


def test_status_response_has_scan_service_version():
    """The capability advert the scan router keys off (§2.4)."""
    fields = pb.StatusResponse.DESCRIPTOR.fields_by_name
    assert "scan_service_version" in fields, (
        "StatusResponse.scan_service_version missing — v16 orchestrator "
        "cannot pick fallback vs on-target without this field")
    # Proto3 default is 0; agents without the field (v15 or earlier)
    # deserialize to the default, which is exactly what the router expects.
    msg = pb.StatusResponse()
    assert msg.scan_service_version == 0


# -------------------------------------------------- client wrapper mixin ----

def test_scan_mixin_importable():
    """The client-side wrappers land in a dedicated mixin (Phase B
    deliverable). Importing them must not require a live channel."""
    from src.pry.agent_client.scan import ScanMixin
    for name in ("scan_create", "scan_refine", "scan_undo", "scan_cancel",
                 "scan_destroy", "scan_list", "scan_status", "scan_fetch"):
        assert hasattr(ScanMixin, name), (
            f"ScanMixin missing wrapper {name!r}")


def test_agent_client_includes_scan_mixin():
    """Composition check: AgentClient must inherit ScanMixin so every
    client instance exposes the wrappers directly."""
    from src.pry.agent_client.client import AgentClient
    from src.pry.agent_client.scan import ScanMixin
    assert issubclass(AgentClient, ScanMixin), (
        "AgentClient does not inherit ScanMixin — Phase B composition "
        "step was skipped")
