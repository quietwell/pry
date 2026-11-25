"""Capability registry + alias forwarders for the taxonomy refactor.

Every canonical MCP ``(tool, action)`` pair is declared here as a
:class:`Capability` so the surface map stays single-sourced:

* ``_runtime/help.py`` renders ``_actions_help`` / ``_unknown_action`` /
  ``target_manage(action='tool_index')`` entries from this registry.
* ``_runtime/guard.py``'s ``_check_actuator_trust`` looks up the
  canonical capability's :attr:`Capability.gate` instead of hard-matching
  a hand-written set.
* Legacy ``(old_tool, old_action)`` calls route through :data:`ALIASES`
  and emit a ``deprecated`` block in the envelope. Each alias forwards
  to the canonical handler, not to the decorated MCP tool, so gating +
  envelope stamping happens exactly once.

This is the Phase 0 anchor. The capability catalog itself is pre-
populated with every canonical pair the taxonomy brief §5 names, but
most of the per-tool entries carry ``implemented=False`` until the Phase
1 slice branches wire the actual handlers. Lint tests
(``tests/test_tool_taxonomy.py``) enforce internal consistency against
this file alone; forwarder parity tests are gated ``xfail`` until the
real handlers land.

See:

* ``an internal plan`` §6 — registry contract.
* ``an internal plan`` §4 P0c — alias
  table that must be populated here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator


# ---------------------------------------------------------------------------
# Capability shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Capability:
    """One canonical ``(tool, action)`` capability.

    Attributes:
      tool:       canonical tool name (``process_manage``, …).
      action:     canonical verb (``list``, ``mitigations``, …).
      domain:     coarse grouping surfaced by
                  ``target_manage(action='tool_index')``'s domain index
                  (``process``, ``thread``, ``memory``, ``identity``,
                  ``network``, …).
      object:     the OS object the verb operates on (``process``,
                  ``thread``, ``module``, ``handle``, ``connection``,
                  ``service``, ``window``, ``heap``, ``token``, …).
      mutating:   true for verbs that change OS state (kill, suspend,
                  adjust-privilege, kill-connection, create-dump, …).
      gate:       config / trust gate the mutator sits behind (e.g.
                  ``security.allow_token_adjust``) or ``None`` for
                  reads. Must be set when ``mutating=True`` unless an
                  explicit ``gate=None`` is justified in-line.
      views:      which agent view(s) accept this verb — ``kernel``
                  (driver-backed agent), ``user`` (umagent). Defaults
                  to both; ``net_manage`` is ``user``-only, driver IDT
                  reads are ``kernel``-only, etc.
      spaces:     address spaces this verb accepts (``user``,
                  ``kernel``, ``physical``). Taxonomy §6 requires
                  ``memory_manage`` entries to narrow this per verb
                  (``heap_info`` / ``vad`` / ``heaps`` → ``{'user'}``).
                  Non-memory verbs leave the default triple.
      required:   required kwargs on the request (``('pid',)`` etc.).
                  Pure documentation + lint hook — handlers do their
                  own enforcement; the registry just makes the shape
                  discoverable.
      aliases:    legacy ``(old_tool, old_action)`` pairs that should
                  forward here. Also populated into :data:`ALIASES` by
                  :func:`_rebuild_alias_table` so a lookup can go
                  either direction.
      help:       one-line human description used by help / tool_index.
      deprecated: when non-empty, this canonical entry is itself
                  deprecated in favour of ``deprecated``. Used for
                  the handful of actions that moved AGAIN (none yet;
                  the slot is reserved for future moves).
      implemented: ``False`` while the Phase 1 slice branches have not
                  wired the handler. Lint tests allow unimplemented
                  canonical actions to live in the registry; forwarder
                  parity tests ``xfail`` on them until they land.
    """

    tool: str
    action: str
    domain: str
    object: str
    mutating: bool = False
    gate: str | None = None
    views: frozenset[str] = field(default_factory=lambda: frozenset({"kernel", "user"}))
    spaces: frozenset[str] = field(default_factory=lambda: frozenset({"user", "kernel", "physical"}))
    required: tuple[str, ...] = ()
    aliases: tuple[tuple[str, str], ...] = ()
    help: str = ""
    deprecated: str | None = None
    implemented: bool = False


# ---------------------------------------------------------------------------
# Alias table — intentionally empty.
# ---------------------------------------------------------------------------
#
# The lookup helpers below return the canonical capability directly (or None when
# the pair is unknown). The symbol stays exported so downstream code
# that imports it keeps importing; the dict is just empty.
#
# The ``aliases=`` field on individual :class:`Capability` entries
# below is now purely descriptive metadata — it is not rebuilt into
# this table at import time.

AliasEntry = tuple[str, str, str, str]  # (new_tool, new_action, since, remove_in)

ALIASES: dict[tuple[str, str], AliasEntry] = {}


# ---------------------------------------------------------------------------
# Canonical capability catalog
# ---------------------------------------------------------------------------
#
# One block per canonical tool. Keep implementation=False until the
# Phase 1 slice branches wire the handlers; the lint tests tolerate
# that and the forwarder-parity tests ``xfail`` on it.

_READ_SPACES = frozenset({"user", "kernel", "physical"})
_BOTH_VIEWS = frozenset({"kernel", "user"})
_USER_ONLY = frozenset({"user"})
_KERNEL_ONLY = frozenset({"kernel"})


_CAPABILITIES: dict[tuple[str, str], Capability] = {}


def _register(cap: Capability) -> None:
    key = (cap.tool, cap.action)
    if key in _CAPABILITIES:
        raise ValueError(f"duplicate capability for {key!r}")
    _CAPABILITIES[key] = cap


def _bulk(entries: Iterable[Capability]) -> None:
    for cap in entries:
        _register(cap)


# ---- process_manage -------------------------------------------------------

_bulk([
    Capability(
        tool="process_manage", action="list", domain="process", object="process",
        required=(),
        help="process inventory + optional cmdline/context/mitigations enrichment",
        aliases=(("memory_manage", "process_list"),),
    ),
    Capability(
        tool="process_manage", action="get", domain="process", object="process",
        required=("pid",),
        help="single-process identity + protection + session + signature summary",
    ),
    Capability(
        tool="process_manage", action="mitigations", domain="process", object="process",
        required=("pid",),
        help="authoritative GetProcessMitigationPolicy readout (slice 01 Feature 6)",
    ),
    Capability(
        tool="process_manage", action="hidden", domain="process", object="process",
        help="hidden-process detection (brute/registry/etw modes)",
        aliases=(("memory_manage", "hidden_proc"),),
    ),
    Capability(
        tool="process_manage", action="kill", domain="process", object="process",
        mutating=True, gate="min_trust_actuator",
        required=("pid",),
        help="terminate a process (actuator-trust gated)",
        aliases=(("exec_manage", "kill_process"),),
    ),
    Capability(
        tool="process_manage", action="suspend", domain="process", object="process",
        mutating=True, gate=None,  # existing exec_manage.suspend is unguarded; preserved
        required=("pid",),
        help="freeze every thread in a process",
        aliases=(("exec_manage", "suspend"),),
    ),
    Capability(
        tool="process_manage", action="resume", domain="process", object="process",
        mutating=True, gate=None,  # mirror of suspend
        required=("pid",),
        help="unfreeze every thread in a process",
        aliases=(("exec_manage", "resume"),),
    ),
    Capability(
        tool="process_manage", action="actions", domain="process", object="process",
        help="per-verb discovery (one_liner + key_args + example)",
    ),
])


# ---- thread_manage --------------------------------------------------------

_bulk([
    Capability(
        tool="thread_manage", action="list", domain="thread", object="thread",
        help="system-wide thread inventory + opt-in enrichment columns",
        aliases=(("memory_manage", "threads"),),
    ),
    Capability(
        tool="thread_manage", action="get", domain="thread", object="thread",
        required=("tid",),
        help="single-thread detail (state + wait + impersonation)",
    ),
    Capability(
        tool="thread_manage", action="stack", domain="thread", object="thread",
        required=("tid",),
        help="APC-delivered kernel + user frame walk (SI #9)",
        aliases=(("memory_manage", "stack_walk"),),
    ),
    Capability(
        tool="thread_manage", action="wait", domain="thread", object="thread",
        required=("tid",),
        help="analyze-wait readout (last_syscall / wait reason)",
    ),
    Capability(
        tool="thread_manage", action="irp", domain="thread", object="thread",
        views=_KERNEL_ONLY, required=("tid",),
        help="pending IRP walk (slice 03 Feature 4)",
    ),
    Capability(
        tool="thread_manage", action="impersonation", domain="thread", object="thread",
        required=("tid",),
        help="OpenThreadToken + user/level readout (slice 03 Feature 4)",
    ),
    Capability(
        tool="thread_manage", action="com", domain="thread", object="thread",
        views=_USER_ONLY, required=("tid",),
        help="COM apartment type/flags from TEB (slice 03 Feature 4)",
    ),
    Capability(
        tool="thread_manage", action="rpc", domain="thread", object="thread",
        views=_USER_ONLY, required=("tid",),
        help="WCT-driven RPC-wait chain (slice 03 Feature 4)",
    ),
    Capability(
        tool="thread_manage", action="power", domain="thread", object="thread",
        views=_USER_ONLY, required=("tid",),
        help="NtQueryInformationThread(ThreadPowerThrottlingState)",
    ),
    Capability(
        tool="thread_manage", action="fiber", domain="thread", object="thread",
        views=_USER_ONLY, required=("tid",),
        help="TEB.HasFiberData probe (slice 03 Feature 4)",
    ),
    Capability(
        tool="thread_manage", action="actions", domain="thread", object="thread",
        help="per-verb discovery",
    ),
])


# ---- memory_manage --------------------------------------------------------

# Memory canonical verbs stay available on every address space unless
# the slice doc narrows them. heap_info / heaps / vad are user-only.
_bulk([
    Capability(tool="memory_manage", action="read",       domain="memory", object="memory",
               help="raw byte read across user/kernel/physical spaces"),
    Capability(tool="memory_manage", action="write",      domain="memory", object="memory",
               mutating=True, gate="min_trust_actuator",
               help="raw byte write (actuator-trust gated)"),
    Capability(tool="memory_manage", action="alloc",      domain="memory", object="memory",
               mutating=True, gate=None,
               help="user VirtualAlloc / kernel ExAllocatePool wrapper"),
    Capability(tool="memory_manage", action="free",       domain="memory", object="memory",
               mutating=True, gate=None,
               help="paired free for alloc"),
    Capability(tool="memory_manage", action="protect",    domain="memory", object="memory",
               mutating=True, gate=None,
               help="change page protection"),
    Capability(tool="memory_manage", action="vad",        domain="memory", object="memory",
               spaces=_USER_ONLY, required=("pid",),
               help="VAD tree walk (user address space only)"),
    Capability(tool="memory_manage", action="heaps",      domain="memory", object="heap",
               spaces=_USER_ONLY, required=("pid",),
               help="per-heap summary (handle / flags / base / blocks)"),
    Capability(tool="memory_manage", action="heap_info",  domain="memory", object="heap",
               spaces=_USER_ONLY, required=("pid",),
               help="segment-heap decode (slice 03 Feature 7)"),
    Capability(tool="memory_manage", action="pattern_scan", domain="memory", object="memory",
               help="single-shot pattern scan"),
    Capability(tool="memory_manage", action="scan_start",   domain="memory", object="memory",
               help="start a background pattern scan job"),
    Capability(tool="memory_manage", action="scan_status",  domain="memory", object="memory",
               help="poll scan job progress"),
    Capability(tool="memory_manage", action="scan_result",  domain="memory", object="memory",
               help="read scan job results"),
    Capability(tool="memory_manage", action="scan_cancel",  domain="memory", object="memory",
               help="cancel a running scan"),
    Capability(tool="memory_manage", action="scan_list",    domain="memory", object="memory",
               help="list live scan jobs"),
    Capability(tool="memory_manage", action="probe_va",     domain="memory", object="memory",
               help="is a VA mapped / readable"),
    Capability(tool="memory_manage", action="va_translate", domain="memory", object="memory",
               help="walk page tables under a given CR3"),
    Capability(tool="memory_manage", action="phys_ranges",  domain="memory", object="memory",
               spaces=frozenset({"physical"}),
               help="MmGetPhysicalMemoryRanges snapshot"),
    Capability(tool="memory_manage", action="watch",        domain="memory", object="memory",
               help="HW-watchpoint-backed memory watch"),
    Capability(tool="memory_manage", action="watch_list",   domain="memory", object="memory",
               help="list live watches"),
    Capability(tool="memory_manage", action="watch_stop",   domain="memory", object="memory",
               help="stop a watch"),
    Capability(tool="memory_manage", action="resolve",      domain="memory", object="memory",
               help="symbol / name resolution"),
    Capability(tool="memory_manage", action="disasm",       domain="memory", object="memory",
               help="disassemble bytes"),
    Capability(tool="memory_manage", action="assemble",     domain="memory", object="memory",
               help="assemble asm text"),
    Capability(tool="memory_manage", action="read_qwords",  domain="memory", object="memory",
               help="read N 8-byte values"),
    Capability(tool="memory_manage", action="read_unicode_string", domain="memory", object="memory",
               help="read a UNICODE_STRING pair"),
    Capability(tool="memory_manage", action="read_ansi_string", domain="memory", object="memory",
               help="read an ANSI_STRING pair"),
    Capability(tool="memory_manage", action="strings",      domain="memory", object="memory",
               help="extract printable strings from a region"),
    Capability(tool="memory_manage", action="iocs",         domain="memory", object="memory",
               help="scan for IOC patterns"),
    Capability(tool="memory_manage", action="entropy",      domain="memory", object="memory",
               help="rolling entropy over a region"),
    Capability(tool="memory_manage", action="resolve_range", domain="memory", object="memory",
               help="symbolize a VA range"),
    Capability(tool="memory_manage", action="dps",          domain="memory", object="memory",
               help="pointer dump with symbol decoration"),
    Capability(tool="memory_manage", action="dt",           domain="memory", object="memory",
               help="displayed type over a VA"),
    Capability(tool="memory_manage", action="follow_chain", domain="memory", object="memory",
               help="chase a pointer chain"),
    Capability(tool="memory_manage", action="leak_scan",    domain="memory", object="memory",
               help="pool-leak scanner"),
    Capability(tool="memory_manage", action="actions",      domain="memory", object="memory",
               help="per-verb discovery"),
])


# ---- module_manage --------------------------------------------------------

_bulk([
    Capability(tool="module_manage", action="list", domain="module", object="module",
               help="user / kernel loaded modules + signature enrichment",
               aliases=(("memory_manage", "modules"),)),
    Capability(tool="module_manage", action="get", domain="module", object="module",
               required=("pid", "module"),
               help="single-module detail"),
    Capability(tool="module_manage", action="imports", domain="module", object="module",
               required=("pid", "module"),
               help="PE import table walk",
               aliases=(("memory_manage", "imports"),)),
    Capability(tool="module_manage", action="exports", domain="module", object="module",
               required=("pid", "module"),
               help="PE export table walk",
               aliases=(("memory_manage", "exports"),)),
    Capability(tool="module_manage", action="coherency", domain="module", object="module",
               required=("pid", "module"),
               help="image coherency scorer (SI Wave 1 #1)",
               aliases=(("memory_manage", "coherency"),)),
    Capability(tool="module_manage", action="actions", domain="module", object="module",
               help="per-verb discovery"),
])


# ---- object_manage --------------------------------------------------------

_bulk([
    Capability(tool="object_manage", action="handles", domain="object", object="handle",
               required=("pid",),
               help="handle table enumeration",
               aliases=(("memory_manage", "handles"),)),
    Capability(tool="object_manage", action="handle_dup", domain="object", object="handle",
               mutating=True, gate=None,  # existing surface — no new gate per taxonomy §5.5
               help="duplicate a remote handle into the caller",
               aliases=(("memory_manage", "handle_dup"),)),
    Capability(tool="object_manage", action="handle_close", domain="object", object="handle",
               mutating=True, gate=None,
               help="close a remote handle",
               aliases=(("memory_manage", "handle_close"),)),
    Capability(tool="object_manage", action="handle_compare", domain="object", object="handle",
               help="compare two handles for pointer identity",
               aliases=(("memory_manage", "handle_compare"),)),
    Capability(tool="object_manage", action="enum", domain="object", object="namespace",
               help="object directory walk",
               aliases=(("memory_manage", "obj_enum"),)),
    Capability(tool="object_manage", action="find", domain="object", object="namespace",
               help="global object/module find (starts a job)",
               aliases=(("memory_manage", "global_find"),)),
    Capability(tool="object_manage", action="find_status", domain="object", object="namespace",
               help="poll find job progress",
               aliases=(("memory_manage", "find_status"),)),
    Capability(tool="object_manage", action="find_result", domain="object", object="namespace",
               help="read find job matches",
               aliases=(("memory_manage", "find_result"),)),
    Capability(tool="object_manage", action="find_cancel", domain="object", object="namespace",
               help="cancel a find job",
               aliases=(("memory_manage", "find_cancel"),)),
    Capability(tool="object_manage", action="find_list", domain="object", object="namespace",
               help="list live find jobs",
               aliases=(("memory_manage", "find_list"),)),
    Capability(tool="object_manage", action="actions", domain="object", object="namespace",
               help="per-verb discovery"),
])


# ---- kernel_manage --------------------------------------------------------

_bulk([
    Capability(tool="kernel_manage", action="pool_scan", domain="kernel", object="pool",
               views=_KERNEL_ONLY,
               help="pattern pool scan (shared scan registry)",
               aliases=(("memory_manage", "pool_scan"),)),
    Capability(tool="kernel_manage", action="scan_status", domain="kernel", object="pool",
               views=_KERNEL_ONLY,
               help="poll pool-scan job progress",
               aliases=(("memory_manage", "scan_status"),)),
    Capability(tool="kernel_manage", action="scan_result", domain="kernel", object="pool",
               views=_KERNEL_ONLY,
               help="read pool-scan results",
               aliases=(("memory_manage", "scan_result"),)),
    Capability(tool="kernel_manage", action="scan_cancel", domain="kernel", object="pool",
               views=_KERNEL_ONLY,
               help="cancel a pool-scan job",
               aliases=(("memory_manage", "scan_cancel"),)),
    Capability(tool="kernel_manage", action="scan_list", domain="kernel", object="pool",
               views=_KERNEL_ONLY,
               help="list live scan jobs (kind=pool|pattern)",
               aliases=(("memory_manage", "scan_list"),)),
    Capability(tool="kernel_manage", action="idt", domain="kernel", object="idt",
               views=_KERNEL_ONLY,
               help="per-CPU IDT dump (slice 03 pattern-free surface)",
               aliases=(("memory_manage", "idt"),)),
    Capability(tool="kernel_manage", action="actions", domain="kernel", object="idt",
               help="per-verb discovery"),
])


# ---- desktop_manage -------------------------------------------------------

_bulk([
    Capability(tool="desktop_manage", action="capture", domain="desktop", object="screen",
               views=_USER_ONLY,
               help="session-1 screen capture"),
    Capability(tool="desktop_manage", action="displays", domain="desktop", object="display",
               views=_USER_ONLY,
               help="monitor / display enumeration"),
    Capability(tool="desktop_manage", action="windows", domain="desktop", object="window",
               views=_USER_ONLY,
               help="session-1 window inventory"),
    Capability(tool="desktop_manage", action="window_props", domain="desktop", object="window",
               views=_USER_ONLY, required=("hwnd",),
               help="EnumPropsExW walk on one HWND (slice 03 Feature 8)"),
    Capability(tool="desktop_manage", action="window_tree", domain="desktop", object="window",
               views=_USER_ONLY,
               help="parent/child tree builder (slice 03 Feature 8)"),
    Capability(tool="desktop_manage", action="window_by_thread", domain="desktop", object="window",
               views=_USER_ONLY,
               help="windows grouped by tid (slice 03 Feature 8)"),
    # session-1 SendInput injection (umagent Input service).
    # Actuator-trust gated: match process_manage(kill)'s gate so a
    # trust=untrusted machine must pass force=true to drive the
    # target.
    Capability(tool="desktop_manage", action="click", domain="desktop", object="window",
               views=_USER_ONLY, mutating=True, gate="min_trust_actuator",
               help="SendInput mouse click (session-1); actuator-trust gated"),
    Capability(tool="desktop_manage", action="type", domain="desktop", object="window",
               views=_USER_ONLY, mutating=True, gate="min_trust_actuator",
               required=("text",),
               help="SendInput text entry via VkKeyScanW; actuator-trust gated"),
    Capability(tool="desktop_manage", action="key", domain="desktop", object="window",
               views=_USER_ONLY, mutating=True, gate="min_trust_actuator",
               required=("key",),
               help="SendInput key / chord ('Ctrl+C'); actuator-trust gated"),
    Capability(tool="desktop_manage", action="actions", domain="desktop", object="screen",
               help="per-verb discovery"),
])


# ---- token_manage (slice 01 Feature 1) -----------------------------------

_bulk([
    Capability(tool="token_manage", action="view", domain="identity", object="token",
               required=("pid",),
               help="token user / SID / groups / privileges readout"),
    Capability(tool="token_manage", action="lookup_sid", domain="identity", object="sid",
               help="LsaLookupSids2 + well-known-SID short circuit"),
    Capability(tool="token_manage", action="well_known_sids", domain="identity", object="sid",
               help="dump the well-known SID table"),
    Capability(tool="token_manage", action="logon_sessions", domain="identity", object="session",
               help="LsaEnumerateLogonSessions walk"),
    Capability(tool="token_manage", action="enable_privilege", domain="identity", object="token",
               mutating=True, gate="allow_token_adjust",
               required=("pid", "privilege"),
               help="AdjustTokenPrivileges(enable)"),
    Capability(tool="token_manage", action="disable_privilege", domain="identity", object="token",
               mutating=True, gate="allow_token_adjust",
               required=("pid", "privilege"),
               help="AdjustTokenPrivileges(disable)"),
    Capability(tool="token_manage", action="remove_privilege", domain="identity", object="token",
               mutating=True, gate="allow_token_adjust",
               required=("pid", "privilege"),
               help="AdjustTokenPrivileges(SE_PRIVILEGE_REMOVED) — destructive"),
    Capability(tool="token_manage", action="set_integrity_level", domain="identity", object="token",
               mutating=True, gate="allow_token_adjust",
               required=("pid",),
               help="SetTokenInformation(TokenIntegrityLevel)"),
    Capability(tool="token_manage", action="set_virtualization", domain="identity", object="token",
               mutating=True, gate="allow_token_adjust",
               required=("pid", "enabled"),
               help="SetTokenInformation(TokenVirtualizationEnabled)"),
    Capability(tool="token_manage", action="impersonate", domain="identity", object="token",
               mutating=True, gate="allow_token_adjust",
               required=("source_pid",),
               help="DuplicateTokenEx + SetThreadToken on a tombstone worker"),
    Capability(tool="token_manage", action="stop_impersonate", domain="identity", object="token",
               mutating=True, gate=None,  # explicit teardown of a prior impersonate
               required=("impersonation_id",),
               help="clear the agent-side impersonation token"),
    Capability(tool="token_manage", action="modify_default_dacl", domain="identity", object="token",
               mutating=True, gate="allow_token_adjust",
               required=("pid", "aces"),
               help="SetTokenInformation(TokenDefaultDacl)"),
    Capability(tool="token_manage", action="actions", domain="identity", object="token",
               help="per-verb discovery"),
])


# ---- svc_manage (slice 02 Feature 3) --------------------------------------

_bulk([
    Capability(tool="svc_manage", action="list", domain="services", object="service",
               views=_USER_ONLY,
               help="EnumServicesStatusExW walk (service + driver rows)"),
    Capability(tool="svc_manage", action="get", domain="services", object="service",
               views=_USER_ONLY, required=("name",),
               help="single-service deep detail"),
    Capability(tool="svc_manage", action="dependencies", domain="services", object="service",
               views=_USER_ONLY, required=("name",),
               help="EnumDependentServices + QueryServiceConfigW dependencies"),
    Capability(tool="svc_manage", action="drivers", domain="services", object="driver",
               views=_USER_ONLY,
               help="driver-flavor rows + kernel module base when driver loaded"),
    Capability(tool="svc_manage", action="actions", domain="services", object="service",
               help="per-verb discovery"),
])


# ---- net_manage (slice 02 Feature 2) --------------------------------------

_bulk([
    Capability(tool="net_manage", action="list", domain="network", object="connection",
               views=_USER_ONLY,
               help="IPHLPAPI TCP+UDP snapshot (service-tag enriched)"),
    Capability(tool="net_manage", action="get", domain="network", object="connection",
               views=_USER_ONLY,
               help="single-connection detail"),
    Capability(tool="net_manage", action="connections", domain="network", object="connection",
               views=_USER_ONLY,
               help="per-process connection rollup"),
    Capability(tool="net_manage", action="dns", domain="network", object="connection",
               views=_USER_ONLY,
               help="reverse-DNS cache snapshot"),
    Capability(tool="net_manage", action="kill", domain="network", object="connection",
               views=_USER_ONLY,
               mutating=True, gate="allow_kill_connection",
               required=("local", "remote"),
               help="SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)"),
    Capability(tool="net_manage", action="actions", domain="network", object="connection",
               help="per-verb discovery"),
])


# ---- dump_manage (slice 03 Feature 5 extension) ---------------------------

_bulk([
    Capability(tool="dump_manage", action="create_kernel_dump",
               domain="dump", object="kernel_dump",
               mutating=True, gate="allow_live_kernel_dump",
               views=_USER_ONLY,
               help="NtSystemDebugControl(SysDbgGetLiveKernelDump)"),
])


# ---- event_manage (ETW consolidation target) ------------------------------
#
# Only the two forwarders device_manage pointed at get registered here;
# the rest of event_manage's canonical surface (etw_start / etw_stop /
# etw_tail / etw_events / etw_stats) stays unmanaged in the registry
# until Phase 1's P1 taxonomy agent moves them. Registering just the
# aliased landing spots keeps the alias table well-formed in Phase 0.

_bulk([
    Capability(tool="event_manage", action="etw_providers",
               domain="event", object="etw",
               help="ETW provider inventory (consolidated from device_manage)",
               aliases=(("device_manage", "etw_providers"),)),
    Capability(tool="event_manage", action="etw_sessions",
               domain="event", object="etw",
               help="ETW session inventory (consolidated from device_manage)",
               aliases=(("device_manage", "etw_sessions"),)),
])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def canonical(tool: str, action: str) -> Capability | None:
    """Return the canonical capability for ``(tool, action)`` or
    ``None`` if the pair isn't registered. Does NOT follow aliases;
    use :func:`resolve_alias` first when the caller might hold a
    deprecated name.
    """
    return _CAPABILITIES.get((tool, action))


def resolve_alias(tool: str, action: str) -> Capability | None:
    """Follow aliases to the canonical capability, if any.

    Resolution order (taxonomy §6):

    1. If ``(tool, action)`` is already canonical, return it.
    2. If ``(tool, '*')`` is a tool-level alias, rewrite the tool
       and recurse (unless the destination is itself ``'*'`` — then
       the action keeps its name).
    3. If ``(tool, action)`` has an action-level alias entry, follow
       it.

    Returns the canonical :class:`Capability` on success, ``None`` on
    miss (unknown tool or action with no alias). The returned
    capability's ``(tool, action)`` identifies the real handler.
    """
    direct = canonical(tool, action)
    if direct is not None:
        return direct

    # Tool-level rename: (old_tool, '*') -> (new_tool, '*')
    tool_alias = ALIASES.get((tool, "*"))
    if tool_alias is not None:
        new_tool = tool_alias[0]
        # Recurse with the rewritten tool. Guard against a loop by
        # refusing to re-follow a tool alias at the same level.
        remapped = canonical(new_tool, action)
        if remapped is not None:
            return remapped
        action_alias = ALIASES.get((new_tool, action))
        if action_alias is not None:
            return canonical(action_alias[0], action_alias[1])

    # Action-level alias: (old_tool, old_action) -> (new_tool, new_action)
    action_alias = ALIASES.get((tool, action))
    if action_alias is not None:
        return canonical(action_alias[0], action_alias[1])

    return None


def alias_entry(tool: str, action: str) -> AliasEntry | None:
    """Return the raw alias row for ``(tool, action)`` or None.

    Used by the alias forwarder to attach the ``deprecated: {replacement,
    remove_in}`` block to the response envelope.

    Resolution order mirrors :func:`resolve_alias`:

    1. Action-level alias filed under the *old* tool
       (``(memory_manage, 'threads')``) wins — those are the explicit
       verb-move rows and they take the caller to a different canonical
       tool / action.
    2. Tool-level alias ``(tool, '*')`` carries the action name through
       as a pure rename (``memory_manage.read`` → ``memory_manage.read``).
    """
    direct = ALIASES.get((tool, action))
    if direct is not None:
        return direct
    tool_alias = ALIASES.get((tool, "*"))
    if tool_alias is not None:
        new_tool, _, since, remove_in = tool_alias
        # Also check the alias table under the *new* tool, in case a
        # row was filed there (none today, but the resolver would
        # honour it).
        action_alias = ALIASES.get((new_tool, action))
        if action_alias is not None:
            return action_alias
        # Pure tool-level rename: destination keeps the action name.
        return (new_tool, action, since, remove_in)
    return None


def render_help(tool: str) -> dict[str, dict[str, str]]:
    """Produce a ``*_ACTION_HELP`` dict shape for the per-tool
    ``action='actions'`` verb — ``{verb: {one_liner, key_args,
    example}}``.
    """
    out: dict[str, dict[str, str]] = {}
    for (cap_tool, cap_action), cap in _CAPABILITIES.items():
        if cap_tool != tool:
            continue
        key_args = ", ".join(cap.required) if cap.required else ""
        example = f"{tool}(action={cap_action!r}"
        if cap.required:
            example += ", " + ", ".join(f"{k}=…" for k in cap.required)
        example += ")"
        out[cap_action] = {
            "one_liner": cap.help,
            "key_args": key_args,
            "example": example,
        }
    return out


def validate_required(tool: str, action: str,
                      args: dict[str, Any] | None) -> list[str]:
    """Return the list of required kwargs missing from ``args`` for
    ``(tool, action)``. Follows aliases first. Pure compute — the
    caller decides how to surface the miss (envelope error vs. silent
    fallback)."""
    cap = resolve_alias(tool, action)
    if cap is None:
        return []
    args = args or {}
    return [k for k in cap.required if k not in args or args.get(k) in (None, "")]


def validate_space(tool: str, action: str, space: str) -> bool:
    """True when ``space`` is accepted by the canonical capability's
    :attr:`Capability.spaces`. Returns True when the capability
    isn't registered (older verbs the registry hasn't absorbed yet),
    so legacy call paths aren't blocked while Phase 1 is in flight."""
    cap = resolve_alias(tool, action)
    if cap is None:
        return True
    return space in cap.spaces


def gate_for(tool: str, action: str) -> str | None:
    """Config/trust gate name for ``(tool, action)`` or ``None``.

    Follows aliases, so an orchestrator-side guard that calls
    ``gate_for('memory_manage', 'process_list')`` sees the same gate as
    ``gate_for('process_manage', 'list')``.
    """
    cap = resolve_alias(tool, action)
    return cap.gate if cap is not None else None


def iter_domain(domain: str) -> Iterator[Capability]:
    """Yield every canonical capability under ``domain`` in a stable
    sort order (``(tool, action)``)."""
    seen = [cap for cap in _CAPABILITIES.values() if cap.domain == domain]
    for cap in sorted(seen, key=lambda c: (c.tool, c.action)):
        yield cap


def all_capabilities() -> Iterator[Capability]:
    """Yield every canonical capability. Used by lint tests + the
    ``domains`` grouping of ``target_manage(action='tool_index')``.
    """
    for cap in sorted(_CAPABILITIES.values(), key=lambda c: (c.tool, c.action)):
        yield cap


def all_aliases() -> dict[tuple[str, str], AliasEntry]:
    """Return a shallow copy of the alias table. Mutations do not
    affect the live registry — callers that want to add runtime
    aliases must do so via :data:`ALIASES` directly."""
    return dict(ALIASES)


def _actuator_pairs_from_registry() -> frozenset[tuple[str, str]]:
    """Build the ``_ACTUATOR_PAIRS`` set the guard uses from the
    registry (mutating capabilities with a non-None gate OR the
    existing ``min_trust_actuator`` gate).

    ``_runtime/guard.py`` keeps its own ``_ACTUATOR_PAIRS`` snapshot
    at import time to keep hot-path lookups cheap; call this during
    module import to seed it.
    """
    pairs: set[tuple[str, str]] = set()
    for cap in _CAPABILITIES.values():
        if cap.mutating and cap.gate is not None:
            pairs.add((cap.tool, cap.action))
    return frozenset(pairs)


__all__ = [
    "ALIASES",
    "AliasEntry",
    "Capability",
    "alias_entry",
    "all_aliases",
    "all_capabilities",
    "canonical",
    "gate_for",
    "iter_domain",
    "render_help",
    "resolve_alias",
    "validate_required",
    "validate_space",
    "_actuator_pairs_from_registry",
]
