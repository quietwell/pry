"""Session value types and constants.

Hosts :class:`ToolCall`, the ``DESTRUCTIVE_ACTIONS`` registry, and the
``VIEW_KINDS`` canonical view-kind suffix tuple shared across the
session mixins.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# Canonical view-kind suffixes in '<machine>.<kind>' view keys.
VIEW_KINDS = ("kernel", "user")


@dataclass
class ToolCall:
    tool: str
    action: str
    destructive: bool
    args: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    error: str = ""
    ts: float = field(default_factory=time.time)


DESTRUCTIVE_ACTIONS = {
    ("target_manage", "driver_unload"),
    ("target_manage", "driver_load"),
    ("target_manage", "disconnect"),
    ("file_manage", "delete"),
    ("exec_manage", "kill_process"),
    ("exec_manage", "stop_shell"),
    ("exec_manage", "suspend"),
    # v15: exec_manage call — remote function execution (remote thread /
    # kernel work item). Gated by security.allow_function_call as well.
    ("exec_manage", "call"),
    ("debug_manage", "detach"),
    ("memory_manage", "free"),
    ("bp_manage", "remove"),
    ("script_manage", "run"),
    # v11: event subscribe registers PsSet*NotifyRoutine callbacks —
    # kernel-visible state, gated like driver_load.
    ("event_manage", "subscribe"),
}
