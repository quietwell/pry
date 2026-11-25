"""v17 (Memory scanner wave 2 Phase A): ABI handshake smoke tests.

The authoritative constant lives in ``comm/abi/version.h``. Changing
the number on one side without the other breaks the wire protocol —
these tests guard the version bump so the next ABI edit lands with
every pair updated.

No agent / server contact; these are pure file-read tests that run in
any CI without a Windows target.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_ORCH_DIR = Path(__file__).resolve().parents[2]
_REPO_ROOT = _ORCH_DIR.parent
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))


EXPECTED_ABI = 17


def _read_version_h() -> str:
    return (_REPO_ROOT / "comm" / "abi" / "version.h").read_text(encoding="utf-8")


def _read_comm_cpp() -> str:
    return (_REPO_ROOT / "comm" / "pry_comm.cpp").read_text(encoding="utf-8")


def test_abi_version_header_bumped_to_v17():
    text = _read_version_h()
    m = re.search(r"^#define\s+PRY_ABI_VERSION\s+(\d+)\s*$",
                  text, flags=re.MULTILINE)
    assert m, "PRY_ABI_VERSION define missing in comm/abi/version.h"
    got = int(m.group(1))
    assert got == EXPECTED_ABI, (
        f"PRY_ABI_VERSION is {got}; Memory scanner wave 2 expected "
        f"v{EXPECTED_ABI}. Update either the define or this test.")


def test_abi_static_assert_matches_header():
    """``comm/pry_comm.cpp`` static-asserts the ABI version; a
    stale number here is a build-time failure, but we catch it in CI."""
    text = _read_comm_cpp()
    m = re.search(r"static_assert\s*\(\s*PRY_ABI_VERSION\s*==\s*(\d+)",
                  text)
    assert m, "static_assert on PRY_ABI_VERSION not found in comm/pry_comm.cpp"
    got = int(m.group(1))
    assert got == EXPECTED_ABI, (
        f"static_assert expects ABI v{got}; header is v{EXPECTED_ABI} — "
        f"these two numbers must match or the agent fails to compile.")


def test_version_h_documents_abi_revision_16():
    """Wave 1's doc block must survive the Wave 2 bump."""
    text = _read_version_h()
    assert re.search(r"//\s*16:\s",
                     text), "no ABI revision 16 block comment in version.h"


def test_version_h_documents_current_abi_revision():
    """The ABI bump must document what changed — guard rail against a
    silent number bump with no rationale."""
    text = _read_version_h()
    m = re.search(r"^#define\s+PRY_ABI_VERSION\s+(\d+)\s*$", text, flags=re.MULTILINE)
    assert m, "PRY_ABI_VERSION define missing in comm/abi/version.h"
    rev = m.group(1)
    assert re.search(rf"//\s*{rev}:\s", text), (
        f"no ABI revision {rev} block comment in version.h")


def test_scan_service_version_field_present_in_proto():
    """Ensures the plumbing path StatusResponse → note_machine_identity
    has the Wave 1 field it reads. Imports the generated pb2 so we also
    catch an out-of-date codegen."""
    from src.pry.generated import pry_pb2 as pb
    assert "scan_service_version" in pb.StatusResponse.DESCRIPTOR.fields_by_name
    msg = pb.StatusResponse()
    assert msg.scan_service_version == 0  # proto3 default


def test_pointer_map_version_field_present_in_proto():
    """Wave 2 adds StatusResponse.pointer_map_version alongside the
    Wave 1 scan_service_version. The orchestrator-side router keys on
    this to decide v17 fast-path vs v16 fallback (dissect) /
    kind='needs_v17' refusal (pointer map)."""
    from src.pry.generated import pry_pb2 as pb
    assert "pointer_map_version" in pb.StatusResponse.DESCRIPTOR.fields_by_name
    msg = pb.StatusResponse()
    assert msg.pointer_map_version == 0  # proto3 default


def test_scan_service_version_cached_by_note_machine_identity():
    """Smoke-check: note_machine_identity now accepts and caches the
    field. We don't run a real Session; just verify the mixin accepts
    the kwarg and writes it."""
    from src.pry.session.machines import SessionMachinesMixin

    # Hand-rolled instance: SessionMachinesMixin is a mixin, so we only
    # instantiate the fields it touches.
    obj = SessionMachinesMixin.__new__(SessionMachinesMixin)
    obj._machine_info = {}
    SessionMachinesMixin.note_machine_identity(
        obj, "lab2.kernel",
        computer_name="LAB2", endpoint="127.0.0.1:50051",
        scan_service_version=1)
    cached = obj._machine_info["lab2.kernel"]
    assert cached["scan_service_version"] == 1
    assert cached["computer_name"] == "LAB2"


def test_scan_service_version_defaults_to_zero():
    """A caller that doesn't pass scan_service_version (pre-v16
    callers) must not crash and must land on 0 (fallback)."""
    from src.pry.session.machines import SessionMachinesMixin
    obj = SessionMachinesMixin.__new__(SessionMachinesMixin)
    obj._machine_info = {}
    SessionMachinesMixin.note_machine_identity(
        obj, "lab2.user", computer_name="LAB2")
    assert obj._machine_info["lab2.user"]["scan_service_version"] == 0


def test_pointer_map_version_cached_by_note_machine_identity():
    """Smoke-check: note_machine_identity accepts and caches the
    v17 pointer_map_version field. Same shape as the Wave 1 field;
    0 is a valid cached value for Phase C-K agents."""
    from src.pry.session.machines import SessionMachinesMixin

    obj = SessionMachinesMixin.__new__(SessionMachinesMixin)
    obj._machine_info = {}
    SessionMachinesMixin.note_machine_identity(
        obj, "lab2.kernel",
        computer_name="LAB2", endpoint="127.0.0.1:50051",
        scan_service_version=1, pointer_map_version=1)
    cached = obj._machine_info["lab2.kernel"]
    assert cached["pointer_map_version"] == 1
    assert cached["scan_service_version"] == 1


def test_pointer_map_version_defaults_to_zero():
    """A pre-v17 caller omits pointer_map_version; it must default
    to 0 so the router treats the view as fallback-only."""
    from src.pry.session.machines import SessionMachinesMixin
    obj = SessionMachinesMixin.__new__(SessionMachinesMixin)
    obj._machine_info = {}
    SessionMachinesMixin.note_machine_identity(
        obj, "lab2.user", computer_name="LAB2")
    assert obj._machine_info["lab2.user"]["pointer_map_version"] == 0


# ---------------------------------------------- dissect_version ---

def test_dissect_version_field_present_in_proto():
    """dedicated DissectService advert.
    Older agents left it absent; the dissect router proxied on
    ``pointer_map_version``. Wave 3 P5 adds the field + sets it to 1
    on agents that register the Wave 2 handler; Wave 3 P1 flips it to
    2 when ``Dissect.Compare`` lands."""
    from src.pry.generated import pry_pb2 as pb
    assert "dissect_version" in pb.StatusResponse.DESCRIPTOR.fields_by_name
    msg = pb.StatusResponse()
    assert msg.dissect_version == 0  # proto3 default


def test_dissect_version_cached_by_note_machine_identity():
    """Smoke-check: note_machine_identity accepts and caches the
    ``dissect_version`` field."""
    from src.pry.session.machines import SessionMachinesMixin
    obj = SessionMachinesMixin.__new__(SessionMachinesMixin)
    obj._machine_info = {}
    SessionMachinesMixin.note_machine_identity(
        obj, "lab2.kernel",
        computer_name="LAB2", endpoint="127.0.0.1:50051",
        scan_service_version=1, pointer_map_version=1,
        dissect_version=1)
    cached = obj._machine_info["lab2.kernel"]
    assert cached["dissect_version"] == 1
    # The other verts should remain populated.
    assert cached["pointer_map_version"] == 1
    assert cached["scan_service_version"] == 1


def test_dissect_version_defaults_to_zero():
    """Older callers omit ``dissect_version``; it must default
    to 0 so the router treats the view as fallback-only."""
    from src.pry.session.machines import SessionMachinesMixin
    obj = SessionMachinesMixin.__new__(SessionMachinesMixin)
    obj._machine_info = {}
    SessionMachinesMixin.note_machine_identity(
        obj, "lab2.user", computer_name="LAB2")
    assert obj._machine_info["lab2.user"]["dissect_version"] == 0


def test_agent_sets_dissect_version_two():
    """Grep the agent-side registrars so a future rename of the
    ``set_dissect_version`` call on either view breaks here before
    the orchestrator silently drops back to the fallback path.

    The advert was bumped to 2 once ``Dissect.Compare``
    landed. The orchestrator-side ``dissect_compare`` dispatch gates
    on ``dissect_version >= 2``; if an agent view drops back to 1 the
    compare verb refuses with ``kind='feature_unavailable'``.
    """
    repo_root = _REPO_ROOT
    agent = (repo_root / "agent" / "src" / "grpc"
             / "services_agent.cpp").read_text(encoding="utf-8")
    umagent = (repo_root / "umagent" / "src"
               / "um_services.cpp").read_text(encoding="utf-8")
    assert "set_dissect_version(2)" in agent, (
        "services_agent.cpp doesn't advertise dissect_version=2; "
        "Wave 3 P1 dissect_compare dispatch will refuse")
    assert "set_dissect_version(2)" in umagent, (
        "um_services.cpp doesn't advertise dissect_version=2; umagent "
        "clients will be refused dissect_compare")
