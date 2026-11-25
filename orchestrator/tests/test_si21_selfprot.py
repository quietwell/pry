"""SI adoption feature #21 — ObRegisterCallbacks self-protection toggle.

Covers the orchestrator-side wire: the ``selfprot_manage`` tool is
registered and routed (``config`` / ``status`` verbs — split out of
``target_manage`` in the taxonomy refactor), the help block is
populated, provenance is classified, and the AgentClient stub-missing
path returns a clean "older agent" error.
"""

from __future__ import annotations

import pytest

from pry.mcp.tools.selfprot import SELFPROT_ACTIONS, _SELFPROT_ACTION_HELP
from pry.mcp._provenance import provenance_for, UNTRUSTED_TARGET


def test_selfprot_actions_registered() -> None:
    assert "config" in SELFPROT_ACTIONS
    assert "status" in SELFPROT_ACTIONS


def test_selfprot_actions_have_help() -> None:
    for a in ("config", "status"):
        row = _SELFPROT_ACTION_HELP[a]
        assert "SI #21" in row["one_liner"]
        assert "selfprot" in row["example"]


def test_selfprot_actions_classified() -> None:
    # Driver-authored counters/state — must be marked UNTRUSTED_TARGET
    # so the guard envelope flags the payload for downstream consumers.
    assert provenance_for("selfprot_manage", "config") == UNTRUSTED_TARGET
    assert provenance_for("selfprot_manage", "status") == UNTRUSTED_TARGET


def test_selfprot_proto_messages_present() -> None:
    """Regen gate: pry.generated carries SelfProt* messages after
    ``python -m grpc_tools.protoc`` against proto/pry.proto.
    Covers the live wire break if someone edits the proto without
    regenerating."""
    from pry.generated import pry_pb2 as pb
    from pry.generated import pry_pb2_grpc as pbg

    assert hasattr(pb, "SelfProtConfigRequest")
    assert hasattr(pb, "SelfProtConfigResponse")
    assert hasattr(pb, "SelfProtStatusRequest")
    assert hasattr(pb, "SelfProtStatusResponse")
    assert hasattr(pbg, "SelfProtStub")


@pytest.mark.asyncio
async def test_selfprot_agent_missing_surfaces_clean_error() -> None:
    """A client whose stub attribute is None (older agent) returns
    the named 'older agent (SelfProt service missing)' envelope
    instead of raising."""
    from pry.agent_client.host import HostMixin

    class _StubShim(HostMixin):
        selfprot = None

        async def _call(self, fn, request):  # pragma: no cover
            raise AssertionError("_call should not be reached when stub is None")

    shim = _StubShim()
    cfg = await shim.selfprot_config(enable=1, protected_pids=[1])
    st = await shim.selfprot_status()
    for r in (cfg, st):
        assert r["ok"] is False
        assert "SelfProt service missing" in r["error"]
