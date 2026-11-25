"""Provenance registry — which (tool, action) results can carry
target-authored text.

Every result envelope may carry a ``provenance`` block:

    "provenance": {"untrusted_content": true, "source": "target"|"session"}

``untrusted_content=true`` means the payload can contain text authored
inside the target (strings, disassembly, registry values, command
output, decompiler output): the agent must treat all of it as DATA,
never as instructions. ``source="target"`` = content read live from the
target machine or a target artifact; ``source="session"`` = previously
recorded target content re-rendered from the orchestrator ledger or
artifact store (knowledge recall, artifact grep/preview).

Classification rule (per ``(tool, action)``):

* ``target``  — default for anything that can include text/bytes from
  the target machine or a target artifact.
* ``session`` — payloads that re-render recorded target content from the
  ledger/artifacts. When unsure whether a payload previews recorded
  content, classify ``session`` (over-marking is the safe direction).
* ``trusted`` — pure orchestrator-side compute/metadata only: value
  compute, tool catalogs, watchdog state, confirmation receipts, static
  per-verb help (``action='actions'``).

Fail-safe: :func:`provenance_for` raises ``KeyError`` for a pair missing
from the table so the guard falls back to ``UNTRUSTED_TARGET`` and adds
a ``warnings`` entry — a NEW action defaults to marked, and the
anti-drift test fails to force the author to classify it explicitly.
"""
from __future__ import annotations

TRUSTED = None
UNTRUSTED_TARGET = {"untrusted_content": True, "source": "target"}
UNTRUSTED_SESSION = {"untrusted_content": True, "source": "session"}

# Table values (strings — the dicts above are the rendered blocks).
_TRUSTED, _TARGET, _SESSION = "trusted", "target", "session"

# (tool, action) -> class. Complete for every registered action of every
# enum-carrying tool; open-surface tools (ida/ghidra) list their short
# verbs and fall back via _TOOL_DEFAULT for passthrough tool names.
_TABLE: dict[str, dict[str, str]] = {
    "target_manage": {
        "actions": _TRUSTED, "tool_index": _TRUSTED,
        "connect": _TARGET, "disconnect": _TARGET, "reconnect": _TARGET,
        "use": _TARGET, "status": _TARGET, "targets": _TARGET,
        "parity": _TARGET, "driver_load": _TARGET,
        "driver_unload": _TARGET, "sysinfo": _TARGET,
        "host_info": _TARGET, "recent_ops": _TARGET,
        "recent_ops_agent": _TARGET, "crash_state": _TARGET,
        "wait_connectable": _TARGET, "wait_boot_change": _TARGET,
        "whoami": _TARGET, "list_peers": _TARGET,
        "release_peer": _TARGET, "subscribe_peers": _TARGET,
        "boot_recover": _TARGET,
        # target_manage.reboot — the response quotes the agent's
        # own ``message`` on failure (Win32 FormatMessageW output) and
        # pre/post identity read from the target, so mark all aliases
        # as target-authored.
        "reboot": _TARGET,
        "shutdown": _TARGET,
        "poweroff": _TARGET,
        "logoff": _TARGET,
        "reboot_abort": _TARGET,
        # Machine registry — register/set/unregister echo
        # operator-authored metadata (trusted, like knowledge
        # record/update); the listing can carry live computer_name
        # (target-authored), so over-mark it.
        "timeline": _TARGET,       # merges op log + boot id + watchdog state
        "rediscover": _TARGET,     # probes target endpoints
        # PR#2 T1.1c
        "wait_agent": _TARGET,     # cold-start endpoint discovery
        # The machine registry
        # (`machines_*`) and the SI #21 self-protection verbs
        # (`selfprot_*`) live in their own dispatchers. See the
        # `machines_manage` and `selfprot_manage` rows below.
    },
    "memory_manage": {
        "actions": _TRUSTED,
        "read": _TARGET, "write": _TARGET, "alloc": _TARGET,
        "free": _TARGET, "protect": _TARGET, "pattern_scan": _TARGET,
        "vad": _TARGET,
        "heaps": _TARGET, "heap_info": _TARGET,
        "probe_va": _TARGET, "phys_ranges": _TARGET,
        "va_translate": _TARGET, "watch": _TARGET,
        "watch_list": _TARGET, "watch_stop": _TARGET, "resolve": _TARGET,
        "disasm": _TARGET, "assemble": _TARGET,
        "walk_list": _TARGET, "read_qwords": _TARGET,
        "read_unicode_string": _TARGET, "read_ansi_string": _TARGET,
        "strings": _TARGET, "iocs": _TARGET, "entropy": _TARGET,
        "resolve_range": _TARGET, "dps": _TARGET, "dt": _TARGET,
        "follow_chain": _TARGET,   # orchestrator-side pointer walk reads
        "leak_scan": _TARGET,      # cross-scope needle sweep reads
        # The forwarders (coherency,
        # global_find, handle_*, handles, hidden_proc, idt, modules,
        # obj_enum, pool_scan, process_list, stack_walk, threads)
        # moved out to their canonical dispatchers (module/object/process/
        # kernel/thread). See those tool rows below.
        #
        # Memory scanner wave 1 — classic scan lifecycle.
        "scan_start": _TARGET, "scan_status": _TARGET,
        "scan_result": _TARGET, "scan_cancel": _TARGET,
        "scan_list": _TARGET, "scan_destroy": _TARGET,
        "scan_undo": _TARGET, "next_scan": _TARGET,
        "value_scan": _TARGET,
        # Memory scanner wave 2 — pointer map + pointer scan.
        "pointer_scan": _TARGET,
        "pointer_map_create": _TARGET, "pointer_map_status": _TARGET,
        "pointer_map_cancel": _TARGET, "pointer_map_destroy": _TARGET,
        "pointer_map_list": _TARGET, "pointer_map_diff": _TARGET,
        "pointer_map_load": _TARGET, "pointer_map_save": _TARGET,
        # Memory scanner wave 3 — DissectCompare, HeapAttrib,
        # pointer-walking dissect. Payloads carry target-authored
        # bytes + decoded offset text.
        "dissect": _TARGET, "dissect_compare": _TARGET,
        "heap_attrib": _TARGET,
    },
    "debug_manage": {
        "actions": _TRUSTED,
        "launch": _TARGET, "attach": _TARGET, "detach": _TARGET,
        "continue": _TARGET, "step_into": _TARGET, "step_over": _TARGET,
        "regs": _TARGET, "set_regs": _TARGET, "threads": _TARGET,
        "stacktrace": _TARGET, "read": _TARGET, "write": _TARGET,
        "regions": _TARGET, "events": _TARGET, "cmd": _TARGET,
        # state-loop additions. `status` echoes a cached
        # StopInfo with target-authored symbol text; the waiting verbs
        # all return StopInfo + optional symbol/arch strings; `disasm`
        # / `resolve` / `modules` carry target-authored disassembly /
        # canonical symbols / module path strings; `dump` writes a
        # file on the target (path echoed back from the agent);
        # `exception` is an orchestrator-side filter toggle that
        # returns only ok/error, but the response carries no extra
        # payload so `_TRUSTED` would be defensible — we over-mark
        # `_TARGET` for consistency with every other debug verb.
        "status": _TARGET, "run": _TARGET, "run_to": _TARGET,
        "wait": _TARGET, "pause": _TARGET, "step_out": _TARGET,
        "disasm": _TARGET, "resolve": _TARGET, "dump": _TARGET,
        "modules": _TARGET, "exception": _TARGET,
        # SetInterrupt-backed cancel echoes a StopInfo state
        # block (same contract as pause / wait).
        "cancel": _TARGET,
        # Memory scanner wave 3 P4 — AccessTrace. Hardware-breakpoint
        # hit records carry target RIPs, GPRs, decoded memop fields
        # (and pre/post bytes when captured), so trust tracks
        # every other debug verb.
        "access_trace_start": _TARGET, "access_trace_status": _TARGET,
        "access_trace_stop": _TARGET, "access_trace_list": _TARGET,
    },
    "bp_manage": {
        "actions": _TRUSTED,
        "add": _TARGET, "remove": _TARGET, "list": _TARGET,
        "enable": _TARGET, "disable": _TARGET, "events": _TARGET,
    },
    "exec_manage": {
        "actions": _TRUSTED,
        "run_exe": _TARGET, "run_powershell": _TARGET,
        "run_cmd": _TARGET, "start_shell": _TARGET,
        "write_console": _TARGET, "read_console": _TARGET,
        "stop_shell": _TARGET, "shells": _TARGET,
        "call": _TARGET, "run_detached": _TARGET,
        "detached_status": _TARGET, "detached_tail": _TARGET,
        "detached_kill": _TARGET, "detached_follow": _TARGET,
        "run_script": _TARGET,
    },
    "file_manage": {
        "actions": _TRUSTED,
        "upload": _TARGET, "download": _TARGET, "read": _TARGET,
        "dump_module": _TARGET, "hash": _TARGET, "list_dir": _TARGET,
        "delete": _TARGET, "yara": _TARGET, "tail": _TARGET,
        "follow_start": _TARGET, "follow_poll": _TARGET,
        "follow_stop": _TARGET, "follow_list": _TARGET,
        "grep_artifact": _SESSION, "read_artifact": _SESSION,
        "list_artifacts": _SESSION, "ingest": _SESSION,
    },
    "ida_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "schemas": _TARGET, "tools": _TARGET,
        "health": _TARGET, "open": _TARGET, "open_async": _TARGET,
        "open_status": _TARGET, "close": _TARGET,
        "dump_layout": _TARGET,
    },
    "ghidra_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "schemas": _TARGET, "tools": _TARGET,
        "health": _TARGET, "open": _TARGET, "open_async": _TARGET,
        "open_status": _TARGET, "close": _TARGET,
        "dump_layout": _TARGET,
    },
    "script_manage": {
        "actions": _TRUSTED, "list": _TRUSTED,
        "run": _TARGET, "history": _TARGET,
        # PR#3 async job surface + params read-out
        "params": _TRUSTED,   # one plugin's static plugin.yaml metadata
        "submit": _TRUSTED,   # job_id + state + started_at only
        "cancel": _TRUSTED,   # orchestrator-only state change
        "status": _TARGET,    # may include plugin result (target-derived)
        "jobs": _TARGET,      # listing echoes per-job progress/result
    },
    "knowledge_manage": {
        "actions": _TRUSTED,
        "record": _TRUSTED, "update": _TRUSTED,
        "add_evidence": _TRUSTED, "annotate": _TRUSTED,
        "link": _TRUSTED, "mark_stale": _TRUSTED, "sessions": _TRUSTED,
        "list": _SESSION, "about": _SESSION, "search": _SESSION,
        "artifacts": _SESSION, "export_json": _SESSION,
        # rea-adoption Part 3 evidence actions — recorded target content
        # re-rendered from the ledger/evidence store.
        "evidence_get": _SESSION, "evidence_summary": _SESSION,
        "evidence_list": _SESSION, "evidence_prune": _SESSION,
    },
    "reg_manage": {
        "actions": _TRUSTED,
        "get": _TARGET, "set": _TARGET, "enum": _TARGET,
        "delete": _TARGET,
    },
    # Orchestrator state only; reclassify if a result ever echoes
    # target text.
    "watchdog_manage": {
        "arm": _TRUSTED, "kick": _TRUSTED, "disarm": _TRUSTED,
        "list": _TRUSTED, "auto_kick": _TRUSTED, "auto_stop": _TRUSTED,
        "auto_status": _TRUSTED, "actions": _TRUSTED,
    },
    "value_manage": {
        "actions": _TRUSTED,
        "cast": _TRUSTED, "views": _TRUSTED, "pack": _TRUSTED,
        "unpack": _TRUSTED, "swap": _TRUSTED, "split": _TRUSTED,
        "join": _TRUSTED, "bits": _TRUSTED, "err_lookup": _TRUSTED,
        "time": _TRUSTED, "guid": _TRUSTED, "encode": _TRUSTED,
        "decode": _TRUSTED, "str_convert": _TRUSTED, "hash": _TRUSTED,
        "eval": _TRUSTED, "constants": _TRUSTED,
        "ioctl_decode": _TRUSTED, "ioctl_encode": _TRUSTED,
    },
    "emulate_manage": {
        "actions": _TRUSTED,
        "create": _TARGET, "load_shellcode": _TARGET,
        "load_pe": _TARGET, "run": _TARGET, "step": _TARGET,
        "regs": _TARGET, "set_regs": _TARGET, "mem_read": _TARGET,
        "mem_write": _TARGET, "map": _TARGET, "unmap": _TARGET,
        "hook_add": _TARGET, "hook_remove": _TARGET,
        "snapshot": _TARGET, "restore": _TARGET,
        "seed_from_target": _TARGET, "close": _TARGET,
        "list": _TARGET,
    },
    "bin_manage": {
        "actions": _TRUSTED,
        "info": _TARGET, "sections": _TARGET, "imports": _TARGET,
        "exports": _TARGET, "hashes": _TARGET, "imphash": _TARGET,
        "sec": _TARGET, "strings": _TARGET, "iocs": _TARGET,
        "entropy": _TARGET, "scan": _TARGET, "caps": _TARGET,
        "funcs": _TARGET, "disasm_func": _TARGET, "xrefs": _TARGET,
        "paths": _TARGET, "callgraph": _TARGET, "cfg": _TARGET,
        "irp_surface": _TARGET, "ioctl_surface": _TARGET,
        "audit": _TARGET, "diff": _TARGET, "pseudo": _TARGET,
        "gadgets": _TARGET, "gadget_check": _TARGET,
        "chain_check": _TARGET, "analyze": _TARGET,
        "analyze_status": _TARGET, "analyze_list": _TARGET,
    },
    # Reconstruct-and-verify. toolchains is host toolchain metadata;
    # compile echoes compiler diagnostics that quote the C source, and
    # that source may carry decompiled target text, so over-mark it;
    # call/verify return the original's outputs, inputs and disassembly.
    "reconstruct_manage": {
        "actions": _TRUSTED, "toolchains": _TRUSTED,
        "compile": _TARGET, "call": _TARGET, "verify": _TARGET,
    },
    "device_manage": {
        "actions": _TRUSTED,
        "ioctl": _TARGET,
    },
    # PR#6 T3.2: MSR / CPUID reader. list_known_msrs is a pure
    # orchestrator-side constants table; msr_read / cpuid rows carry
    # target CPU state (not strings, but still target-sourced).
    "cpu_manage": {
        "actions": _TRUSTED, "list_known_msrs": _TRUSTED,
        "msr_read": _TARGET, "cpuid": _TARGET,
    },
    "event_manage": {
        "actions": _TRUSTED,
        "subscribe": _TARGET, "poll": _TARGET, "unsubscribe": _TARGET,
        "list": _TARGET, "stats": _TARGET,
        # SI #10 private kernel ETW session — events are target-sourced
        # (decoded on the agent/umagent before they reach the orchestrator).
        "etw_start": _TARGET, "etw_stop": _TARGET,
        "etw_trace_sessions": _TARGET, "etw_tail": _TARGET,
        "etw_events": _TARGET, "etw_stats": _TARGET,
        # Canonical ETW inventory.
        "etw_providers": _TARGET, "etw_sessions": _TARGET,
    },
    "symbols_manage": {
        "actions": _TRUSTED,
        "info": _TARGET, "ensure": _TARGET, "resolve": _TARGET,
        "lookup": _TARGET, "layout": _TARGET, "struct_info": _TARGET,
        "resolve_member": _TARGET, "enum_info": _TARGET,
        "layouts": _TARGET,
        # Memory scanner wave 3 F1 — batched VA → nearest-symbol lookup
        # (SymbolDecorator fan-out). Returns target-authored module
        # and symbol names.
        "lookup_batch": _TARGET,
    },
    "dump_manage": {
        "actions": _TRUSTED,
        "parse": _TARGET, "latest": _TARGET, "stack": _TARGET,
        # SI #14: process-snapshot minidump — the writeback
        # contains target memory, so even the "success" envelope's
        # path/sha256 is target-derived.
        "process_snapshot": _TARGET,
        # NtSystemDebugControl kernel dump;
        # the writeback is a full live-kernel snapshot.
        "create_kernel_dump": _TARGET,
    },
    "desktop_manage": {
        "actions": _TRUSTED,
        # window titles / class names / process names are target-authored
        "capture": _TARGET, "windows": _TARGET, "displays": _TARGET,
        # EnumChildWindows / EnumPropsExW walks.
        # Rows carry target-authored window class names, titles, prop keys.
        "window_props": _TARGET, "window_tree": _TARGET,
        "window_by_thread": _TARGET,
        # desktop input injection. Response is a pure ack
        # (ok / error / short diag string); no target-authored data
        # rides along so `_TRUSTED` is correct.
        "click": _TRUSTED, "type": _TRUSTED, "key": _TRUSTED,
    },
    # ----------------------------------------------------------------- #
    # Ten canonical tools. Each one is
    # a thin forwarder onto handlers that already lived under
    # ``memory_manage`` / ``desktop_manage`` (or a kind='not_implemented' shell
    # pending slice fill-in). Classify every verb here so the
    # anti-drift test stays green.
    # ----------------------------------------------------------------- #
    "process_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "get": _TARGET, "mitigations": _TARGET,
        "hidden": _TARGET,
        "kill": _TARGET, "suspend": _TARGET, "resume": _TARGET,
    },
    "thread_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "get": _TARGET, "stack": _TARGET,
        "wait": _TARGET, "irp": _TARGET, "impersonation": _TARGET,
        "com": _TARGET, "rpc": _TARGET, "power": _TARGET, "fiber": _TARGET,
    },
    "module_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "get": _TARGET, "imports": _TARGET,
        "exports": _TARGET, "coherency": _TARGET,
    },
    "object_manage": {
        "actions": _TRUSTED,
        "handles": _TARGET, "handle_dup": _TARGET,
        "handle_close": _TARGET, "handle_compare": _TARGET,
        "enum": _TARGET,
        "find": _TARGET, "find_status": _TARGET, "find_result": _TARGET,
        "find_cancel": _TARGET, "find_list": _TARGET,
    },
    "kernel_manage": {
        "actions": _TRUSTED,
        "pool_scan": _TARGET,
        "idt": _TARGET,
        # Memory scanner wave 3 P3 — struct_read reads live kernel-object
        # bytes (EPROCESS / KPROCESS / …) and decodes them against the
        # module's PDB layout, so every row is target-authored.
        "struct_read": _TARGET,
    },
    "token_manage": {
        # Every verb reads or writes target identity state — target
        # provenance. ``actions`` discovery stays trusted.
        "actions": _TRUSTED,
        **{a: _TARGET for a in (
            "view", "lookup_sid", "well_known_sids", "logon_sessions",
            "enable_privilege", "disable_privilege", "remove_privilege",
            "set_integrity_level", "set_virtualization",
            "impersonate", "stop_impersonate",
            "modify_default_dacl",
        )},
    },
    # net_manage (umagent-only). Every verb
    # returns target-authored data: IPHLPAPI rows carry per-process
    # names (QueryFullProcessImageName), service tags (I_QueryTagInformation),
    # reverse DNS strings (GetNameInfoW over the target resolver), and
    # OWNER_MODULE DLL stacks. kill reports whether SetTcpEntry succeeded.
    "net_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "interfaces": _TARGET,
        "stats": _TARGET, "kill": _TARGET,
    },
    # svc_manage (umagent-only, read-only).
    # SCM-sourced rows carry target-authored display names, image paths,
    # descriptions, trigger GUID decode, and LsaLookupSids-resolved
    # logon accounts. Driver-flavor rows additionally echo kernel-view
    # module base/size when the driver is loaded.
    "svc_manage": {
        "actions": _TRUSTED,
        "list": _TARGET, "get": _TARGET,
        "dependencies": _TARGET, "drivers": _TARGET,
    },
    # The machine registry CRUD moved out of
    # target_manage into its own dispatcher. `register/set/unregister`
    # echo operator-authored metadata (trusted, like knowledge
    # record/update); the listing can carry live computer_name
    # (target-authored), so over-mark it. `prune` is pure
    # orchestrator metadata — it reports the alias list it removed,
    # no target traffic.
    "machines_manage": {
        "actions": _TRUSTED,
        "register": _TRUSTED, "set": _TRUSTED,
        "unregister": _TRUSTED, "prune": _TRUSTED,
        "list": _TARGET,
    },
    # SI #21 driver self-protection moved out
    # of target_manage into its own dispatcher. Both verbs return
    # driver-authored counters/state; the cookie is driver-seeded,
    # not operator-authored.
    "selfprot_manage": {
        "actions": _TRUSTED,
        "config": _TARGET, "status": _TARGET,
    },
}

# Open-surface tools: any passthrough verb defaults to this class so a
# decompile/xref tool name never trips the KeyError fallback.
_TOOL_DEFAULT: dict[str, str] = {
    "ida_manage": _TARGET,
    "ghidra_manage": _TARGET,
}

_BLOCKS: dict[str, dict | None] = {
    _TRUSTED: TRUSTED,
    _TARGET: UNTRUSTED_TARGET,
    _SESSION: UNTRUSTED_SESSION,
}


def provenance_for(tool: str, action: str) -> dict | None:
    """Rendered provenance block for ``(tool, action)`` — ``None`` for
    trusted actions, a fresh dict otherwise. Raises ``KeyError`` when the
    pair is unclassified (the guard falls back to UNTRUSTED_TARGET)."""
    row = _TABLE.get(str(tool))
    cls = row.get(str(action)) if row else None
    if cls is None:
        cls = _TOOL_DEFAULT.get(str(tool))
    if cls is None:
        raise KeyError(f"unclassified action {tool}.{action}")
    block = _BLOCKS[cls]
    return dict(block) if block is not None else None


def classification_table() -> dict[tuple[str, str], str]:
    """Explicit ``(tool, action) -> class`` map (trusted|target|session)
    for every classified pair — the anti-drift test walks this."""
    out: dict[tuple[str, str], str] = {}
    for tool, row in _TABLE.items():
        for action, cls in row.items():
            out[(tool, action)] = cls
    return out


def stamp(env: dict, tool: str, action: str) -> dict:
    """Guard hook: set ``env['provenance']`` per the table. Unclassified
    pairs fall back to UNTRUSTED_TARGET and append a warning so drift is
    visible on the wire AND fails the classification test. Trusted pairs
    leave the envelope untouched (key stays absent, never null)."""
    try:
        prov = provenance_for(tool, action)
    except KeyError:
        prov = dict(UNTRUSTED_TARGET)
        env.setdefault("warnings", []).append(
            f"unclassified action {tool}.{action} treated as untrusted")
    if prov is not None:
        env["provenance"] = prov
    return env
