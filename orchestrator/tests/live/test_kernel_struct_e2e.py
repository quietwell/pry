"""Memory scanner wave 3 §6.5 — live ``kernel_manage(struct_read)`` end-to-end.

Reads the live EPROCESS for the orchestrator's own pid via the agent's
kernel view, asserts the decoded ``ImageFileName`` / ``UniqueProcessId``
match, and that ``Peb`` resolves to a plausible user-VA.

**Deferred** per the Memory scanner wave 3 kickoff: the C++ agent is not
being rebuilt in this chunk (HARD CONSTRAINT #1), so the handler
cannot be smoke-tested against a running agent from inside this
branch. The test skeleton lives here so the live suite's shape stays
honest; the kickoff orchestrator flips the skip once Stage 3 ships a
fresh agent.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(
    reason="needs rebuilt agent; deferred per Memory scanner wave 3 kickoff"
)


def test_struct_read_live_eprocess_self():
    """Live EPROCESS self-read — see §6.5 for the spec.

    Stage 3 integrator activates this by removing the module-level
    skip and ensuring:

    * ``PRY_LIVE_KERNEL=1`` in the test env.
    * A kernel view connected and focused on the lab target.
    * The orchestrator's own pid resolvable via Memory.ListProcesses
      — or ``va=`` passed explicitly once the first one is captured.

    Expected asserts:

    * ``fields['UniqueProcessId'] == os.getpid()``
    * ``fields['ImageFileName'].lower() in {'python.exe', 'pytest.exe'}``
    * ``fields['Peb']`` is a non-zero user-VA (< 0x0000_8000_0000_0000).
    """
    # intentionally empty; module-level skip handles this at collect-time
    pass
