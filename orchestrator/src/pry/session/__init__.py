"""Session state: named target clients per session, grouped by machine.

View keys are ``'<machine>.<kind>'`` — e.g. ``lab2.kernel`` or
``DESKTOP-ABC.user``. The machine label comes from (in priority order) the
``machine=`` connect arg, a config ``machines:`` alias matching the
endpoint, the target's own ``computer_name`` (HostInfo), or the host
address. ``computer_name`` is also stored per view and resolves as an
alias, so a machine stays identifiable when its IP changes.

Per-client ``focus`` (``target_manage(action='use', machine='lab2')``)
fills in the ``name=`` selector when a tool call leaves it empty — each
MCP client has its own focus, so concurrent chats can sit on different
machines without fighting over a global default. With more than one
machine connected, an unfocused empty selector raises
:class:`AmbiguousTargetError` instead of silently hitting whichever box
happened to be primary.

The primary client (the first connected machine's kernel view) keeps the
historical single-target semantics: session.client / session.connected
refer to it.

This package is the facade for the split modules that used to live in a
single ``session.py``; every public name a pre-split caller imported
still resolves from ``pry.session``.
"""

from __future__ import annotations

# ``AgentClient`` is re-exported here (even though no caller imports it
# via ``pry.session``) so pre-split test fixtures that do
# ``monkeypatch.setattr("pry.session.AgentClient", _Fake)`` still
# influence the connect path — :mod:`.connect` resolves it through this
# package at call time. See the banners there and in :mod:`._probe`.
from ..agent_client import AgentClient
from ._errors import (AmbiguousTargetError, UnverifiedMachineError,
                      WrongMachineError)
from ._models import DESTRUCTIVE_ACTIONS, VIEW_KINDS, ToolCall
from ._probe import _probe_tcp, probe_hosts_concurrent
from .boot_monitor import SessionBootMonitorMixin
from .connect import SessionConnectMixin
from .core import Session
from .endpoint_heal import SessionEndpointHealMixin
from .focus import SessionFocusMixin
from .machines import SessionMachinesMixin
from .views import SessionViewsMixin

__all__ = [
    "AgentClient",
    "AmbiguousTargetError",
    "DESTRUCTIVE_ACTIONS",
    "Session",
    "SessionBootMonitorMixin",
    "SessionConnectMixin",
    "SessionEndpointHealMixin",
    "SessionFocusMixin",
    "SessionMachinesMixin",
    "SessionViewsMixin",
    "ToolCall",
    "UnverifiedMachineError",
    "VIEW_KINDS",
    "WrongMachineError",
    "_probe_tcp",
    "probe_hosts_concurrent",
]
