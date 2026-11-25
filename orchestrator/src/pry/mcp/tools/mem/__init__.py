"""Mem tool registration for the pry MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from ..common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

from ..common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from ..context import Context
from ..._coverage import coverage as _coverage  # noqa: F401 — result stamps
# Part 3 evidence envelope (detail=/retention); aliased to keep the
# closure namespace untouched. split_detail disambiguates the legacy
# disasm bool from the new "summary"|"complete" selector sharing the name.
from ...evidence.store import split_detail as _ev_split_detail
from ...evidence.store import with_evidence as _ev_with
from ..follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)

# R5: per-verb modules. Each one exports an ``async def handle_<verb>``
# (or a bundle for grouped verbs like ``forensics`` and ``pointer``) that
# takes everything the register-scope closure used to capture through
# ``from ..common import *`` as explicit kwargs. The dispatcher inside
# ``register()`` collapses to one-line delegations.
from . import alloc as _mem_alloc
from . import codegen as _mem_codegen
from . import coherency as _mem_coherency
from . import extraction as _mem_extraction
from . import hidden_proc as _mem_hidden_proc
from . import forensics as _mem_forensics
from . import global_find as _mem_global_find
from . import handle_ops as _mem_handle_ops
from . import handles as _mem_handles
from . import heap_attrib as _mem_heap_attrib
from . import heap_info as _mem_heap_info
from . import modules as _mem_modules
from . import obj_browse as _mem_obj_browse
from . import pointer as _mem_pointer
from . import pool as _mem_pool
from . import probes as _mem_probes
from . import processes as _mem_processes
from . import read as _mem_read
from . import resolve as _mem_resolve
from . import scan as _mem_scan
from . import stack_walk as _mem_stack_walk
from . import threads as _mem_threads
from . import vad as _mem_vad
from . import watch as _mem_watch
from . import write as _mem_write
from ._common import (  # noqa: F401 — referenced inside ``register()``
    _IDT_ALLOW_PREFIXES,
    _KERNEL_QWORD_MIN,
    _MMIO_BLOCKED_HINT,
    _USER_QWORD_MAX,
    _USER_QWORD_MIN,
    _fmt_modsym,
    _kernel_va_err,
    _looks_invalid_addr,
    _looks_mmio_guard,
    _lookup_mod,
    _mod_ranges,
    _ptr_symbol,
)
from ._envelope import _scan_window_cov  # noqa: F401 — pool_scan + scan
from ._action_help import _MEMORY_ACTION_HELP

# shared closure reference so ``memory_manage`` (new canonical
# tool in ``tools/memory.py``) can forward every call into memory_manage's full
# dispatcher without duplicating the ~500-line body. Set during
# :func:`register`; ``memory.py``'s forwarder reads it at call time.
_MEMORY_MANAGE_FN = None


# module-level so the lazy action-enum annotation resolves
# (from __future__ import annotations defers eval to module globals).
_MEMORY_ACTIONS_MASTER = ["read", "write", "alloc", "free", "protect", "modules",
               "process_list", "pattern_scan", "vad", "handles",
               "imports", "exports", "heaps", "probe_va",
               "phys_ranges", "pool_scan",
               # v7 additions (ABI v7 agent required):
               "va_translate", "watch", "watch_list", "watch_stop",
               "resolve",
               # codegen extra (Phase 1 of 2026-09-11 plan):
               "disasm", "assemble",
               # long-running scan job surface — a wide-range
               # pattern_scan used to blow the 2 min MCP deadline with
               # no cancel/poll. scan_start returns a scan_id
               # immediately; scan_status/scan_result/scan_cancel/
               # scan_list drive the lifecycle.
               "scan_start", "scan_status", "scan_result",
               "scan_cancel", "scan_list",
               # kernel-RE convenience primitives.
               "walk_list", "read_qwords",
               "read_unicode_string", "read_ansi_string",
               "strings", "iocs", "entropy",
               # system-wide per-thread inventory (agent-side
               # NtQuerySystemInformation; driver enrichment on v11).
               "threads",
               # kernel object-directory enumeration
               # (\Device, \Driver, ... — feeds device_manage ioctl).
               "obj_enum",
               # forensic verbs:
               # dps-style pointer scan, named-type read sugar, IDT dump.
               "resolve_range", "dps", "dt", "idt",
               # pointer-chain chase (orchestrator-side
               # composition). offsets=[0x18, 0x178, ...] from address=,
               # with optional per-hop validators (expect_ascii,
               # expect_nonzero, expect_module).
               "follow_chain",
               # cross-scope needle sweep. Takes
               # needles=[b"..."]/[...hex] and scopes (kernel_pool,
               # module_data, per_process), reuses pool_scan's cursor and
               # the pattern_scan job infra; produces per-scope coverage.
               "leak_scan",
               # system-wide handle/module name search.
               # Orchestrator fan-out; mirrors the scan-job state machine
               # under a separate `g####` id so scan_cancel/global_find
               # cancel never cross.
               "global_find",
               # image coherency scoring. Compares a
               # loaded module's in-memory image against its on-disk
               # file, skipping the exclusion bitmap (relocs, IAT,
               # LoadConfig overrides, CFG tables). Umagent-first;
               # falls back to the agent/driver view for PP targets.
               "coherency",
               # handle manipulation primitives built on
               # top of PryHandleList. Each verb forwards to the
               # matching driver IOCTL (HANDLE_DUP / CLOSE_REMOTE /
               # COMPARE) under KernelMode PreviousMode — SeAccessCheck
               # bypassed (lab-tool contract).
               "handle_dup", "handle_close", "handle_compare",
               # kernel-stack walk via
               # RtlWalkFrameChain delivered through a kernel-mode APC
               # on the target thread (PryRemoteCall + RC_FLAG_KERNEL).
               # Default timeout bounded at 500 ms (sequential IOCTL
               # queue healthiness; see plan README §6).
               "stack_walk",
               # hidden-process detection via
               # brute / registry / ETW usermode PID oracles, joined
               # against NtQSI ground truth. CSRSS mode lands in Wave 2
               # behind the slice-1 HANDLE_LIST enrichment and is
               # accepted-and-dropped by this verb today. Driver-free.
               "hidden_proc",
               # segment-heap decoder. See
               # Feature 7 slice doc — umagent fails on PPL, agent view
               # decodes via the driver read path (PPL coverage
               # asymmetry documented in the help blurb).
               "heap_info",
               # v16 (Memory scanner wave 1): typed value scan + iterative
               # refine. value_scan is a first scan; next_scan refines
               # the most recent snapshot in place (pushes onto an
               # undo stack); scan_undo pops that stack; scan_destroy
               # removes a scan from the registry (and target disk,
               # when the v16 agent path is active). On v15 agents
               # (scan_service_version == 0 in StatusResponse) the
               # snapshot lives in orchestrator RAM capped at 128 MiB;
               # on v16 it lives on the target under
               # <agent_dir>\scans\<view>\<scan_id>\. Routing is
               # frozen at scan creation.
               "value_scan", "next_scan", "scan_undo", "scan_destroy",
               # v17 (Memory scanner wave 2): on-target pointer map
               # snapshot + reverse pointer scan + map-vs-map diff +
               # per-slot dissect. Dissect has a v16 orchestrator
               # fallback; the pointer-map verbs refuse with
               # kind='needs_v17' on pre-v17 agents (no RAM fallback —
               # see plan §2.9).
               "pointer_map_create", "pointer_map_status",
               "pointer_map_list", "pointer_map_cancel",
               "pointer_map_save", "pointer_map_load",
               "pointer_map_destroy", "pointer_scan",
               "pointer_map_diff", "dissect",
               # multi-instance
               # structure compare. Gated on dissect_version >= 2.
               "dissect_compare",
               # VA -> heap allocation
               # attribution. Batched; gated on
               # memory_heap_attrib_version>=1 (kernel view only; the
               # umagent view has no WalkHeaps wiring). See
               # an internal plan §7.
               "heap_attrib",
               # discoverability
               "actions"]


def register(mcp, ctx: Context) -> None:
    """Build the internal ``memory_manage`` dispatcher and publish it as
    :data:`_MEMORY_MANAGE_FN` so the canonical ``*_manage`` tools can forward
    verb bodies through it.

    The dispatcher is no longer registered as an MCP tool —
    ``memory_manage`` / ``process_manage`` / ``thread_manage`` /
    ``module_manage`` / ``object_manage`` / ``kernel_manage`` are the
    public surface. The function still exists in-process as the shared
    handler library, called through ``_MEMORY_MANAGE_FN``. The ``mcp`` argument
    is kept for signature compatibility with ``build_server`` but is
    unused here."""
    del mcp  # unused

    # Per-verb bodies live under ``tools/mem/`` and are called by this
    # dispatcher one-line-delegated into ``_mem_<verb>.handle_<verb>``.
    # ``_WATCHES`` / ``_SCANS`` registries live at the ``mem/`` module
    # scope (orchestrator-lifetime).

    async def memory_manage(action: Annotated[str, Field(json_schema_extra={"enum": _MEMORY_ACTIONS_MASTER})],
                     pid: int = 0, address: int | str = 0, size: int = 0,
                     data_hex: str = "", space: str = "user", protect: int = 0,
                     kernel: bool = False, pattern_hex: str = "", mask: str = "",
                     pattern: str = "", base: int | str = 0, max_results: int = 64,
                     want_names: bool = False, module: str = "",
                     filter: Any = "",
                     # typed module filters (were defined in
                     # _apply_modules_filter but never invoked before).
                     name_regex: str = "",
                     name_glob: str = "",
                     path_contains: str = "",
                     compact: bool = False,
                     summary: bool = False,
                     fields: list[str] | None = None,
                     want_blocks: bool = False, max_blocks: int = 0,
                     allow_fault: bool = False, allow_map_write: bool = False,
                     allow_mmio: bool = False,
                     partial: bool = False,
                     timeout_s: float = 0.0,
                     # value accepts int / float / str: scan verbs coerce
                     # via value_scan._coerce_number; legacy callers
                     # (walk_list, resolve) passed strings.
                     value: Any = "",
                     # --- Phase 1 codegen extras ---
                     bytes_hex: str = "",
                     arch: str = "x64",
                     syntax: str = "intel",
                     count: int = 64,
                     detail: bool | str = False,
                     resolve_symbols: bool = False,
                     code: str = "",
                     write_to: int | str = 0,
                     dry_run: bool = True,
                     # --- unified paging (Layer 3) ---
                     limit: int = 0,
                     offset: int = 0,
                     cursor: str = "",
                     verbosity: str = "normal",
                     # --- long-running scan job surface ---
                     scan_id: str = "",
                     # --- write verify ---
                     verify: bool = False,
                     # --- decode + batch reads ---
                     decode: Any = None,
                     reads: list[dict] | None = None,
                     include_ascii: bool = False,
                     # --- VA -> PA -> physical read shortcut ---
                     from_va: int | str = 0,
                     resolve_physical: bool = False,
                     # --- live extraction params ---
                     min_len: int = 5,
                     buckets: int = 64,
                     entropy: bool = False,
                     # --- obj_enum params ---
                     path: str = "",
                     depth: int = 1,
                     # --- idt per-CPU dump ---
                     all_cpus: bool = False,
                     # --- section-scoped scans ---
                     sections: str = "",
                     # --- v14: NtQSI enrichments (no driver needed) ---
                     with_cmdline: bool = False,
                     with_context: bool = False,
                     # --- follow_chain ---
                     offsets: list[int] | None = None,
                     terminal_size: int = 0,
                     expect_ascii: bool = False,
                     expect_nonzero: bool = False,
                     expect_module: str = "",
                     # --- leak_scan ---
                     needles: list[str] | None = None,
                     scopes: list[str] | None = None,
                     # --- pool-tag enrichment ---
                     enrich_tags: bool = True,
                     # --- global_find fan-out ---
                     kinds: list[str] | None = None,
                     regex: bool = False,
                     want_object_names: bool = True,
                     concurrency: int = 8,
                     # --- HW-watch mode ---
                     mode: str = "poll",
                     access: str = "write",
                     tid: int = 0,
                     slot: int = 0xFF,
                     preempt_ok: bool = False,
                     # --- signer / Authenticode column ---
                     verify_signatures: bool = False,
                     force_recheck: bool = False,
                     # --- thread opt-in columns ---
                     include_last_syscall: bool = False,
                     include_kernel_stack_usage: bool = False,
                     include_pending_irp: bool = False,
                     include_impersonation: bool = False,
                     include_com_apartment: bool = False,
                     include_rpc_usage: bool = False,
                     include_power_throttling: bool = False,
                     include_fiber: bool = False,
                     # --- Wave 1 Phase A: region filter for scans ---
                     # pattern_scan / scan_start accept these alongside
                     # sections=; both unify through mem.region_filter.
                     writable: bool = False,
                     executable: bool = False,
                     cow: bool = False,
                     include_guarded: bool = False,
                     mem_types: list[str] | None = None,
                     scope: str = "",
                     # --- Wave 1 Phase G: typed value scan + next_scan ---
                     # See mem/value_scan.py for the full contract.
                     value_type: str = "",
                     op: str = "",
                     value_hi: Any = "",
                     delta: Any = "",
                     tolerance: float = 0.0,
                     endian: str = "le",
                     encoding: str = "",
                     align: Any = "auto",
                     confirm_full_space: bool = False,
                     # --- v17 Wave 2: pointer map + reverse scan + diff + dissect ---
                     map_id: str = "",
                     map_id_b: str = "",
                     target_va: int | str = 0,
                     max_depth: int = 0,
                     max_offset: int = 0,
                     static_only: bool = True,
                     fanout_per_level: int = 0,
                     wall_ms: int = 0,
                     remote_path: str = "",
                     keep_disk: bool = False,
                     chains: list[dict] | None = None,
                     with_modules: bool = True,
                     disk_spill_mode: str = "auto",
                     max_candidates: int = 0,
                     # Wave 3 Phase D: orchestrator-side symbol decoration
                     # on pointer_scan chains + dissect slots. On by
                     # default; callers can opt out for speed or when
                     # PDBs aren't cached.
                     decorate: bool = True,
                     # --- Wave 3 P1: DissectCompare ---
                     base_vas: list[int] | None = None,
                     window_size: int = 0,
                     shared_ptr_min_vote: int = 0,
                     min_instances_for_class: int = 0,
                     # Wave 3 Phase C (P2): HeapAttrib — batched VA ->
                     # heap allocation. `vas=[...]` is the batched
                     # form; `va=` is a scalar convenience that the
                     # handler merges into the batch. `refresh=True`
                     # bypasses the agent-side TTL + committed-sum
                     # cache and rebuilds the per-pid index.
                     vas: list[int] | None = None,
                     refresh: bool = False,
                     va: int | str = 0,
                     name: str = "") -> str:
        """User/kernel/physical memory R/W, alloc/free/protect, module +
        process lists, pattern scan, VAD/handle tables, decode/dt,
        disasm/assemble, scan jobs, resolve_range/idt forensics.
        name='user' routes through the usermode umagent view (no driver);
        kernel=True is a legacy alias for space='kernel'. Addresses take
        int, '0x...' or 'module+offset'. List verbs take limit/offset
        (cursor=), fields=[...], filter=, summary=true, and
        verbosity='compact'|'normal'|'full' to trade detail for tokens;
        action='read' takes reads=[...] for batched reads. Per-verb help:
        memory_manage(action='actions')."""
        # promote the legacy `kernel=True` shorthand into the canonical
        # space so read/write dispatch matches what the caller asked for. The
        # docstring has always promised this; only pattern_scan was honoring it.
        if kernel and space == "user":
            space = "kernel"
        args = {"action": action, "name": name, "pid": pid,
                "address": address, "size": size, "space": space,
                # Forward the response-shaping kwargs so _guard's
                # _opts_from_args can honor them in finalize (row-collapse,
                # mirror strips, projection, spill budget). Without these in
                # `args` the per-call verbosity/fields/etc. are ignored.
                "verbosity": verbosity, "fields": fields or [],
                "filter": filter, "include_ascii": include_ascii}
        # Part 3: `detail` carries both meanings — the legacy disasm bool
        # and the evidence selector ("summary" bounds the inline payload
        # to counts; "complete" delivers inline AND retains the record
        # under artifacts/evidence/).
        _ev_detail, _disasm_detail = _ev_split_detail(detail)

        async def run() -> str:
            # Reject unknown actions BEFORE we require a connected client so
            # "unknown action X" beats "not connected" as an error.
            if action not in _MEMORY_ACTIONS_MASTER:
                return _unknown_action("memory_manage", action, _MEMORY_ACTIONS_MASTER, _MEMORY_ACTION_HELP)
            if action == "actions":
                # pure-compute discovery — answers unconnected.
                return _actions_help("memory_manage", _MEMORY_ACTION_HELP)
            # allow_fault=true sets the driver's soft-fault flag;
            # faulting a non-resident kernel page in from the driver's
            # IOCTL context wedged the lab VM twice. Refused unless the
            # operator opted in (the agent client also strips the flag
            # from every read when the switch is off).
            if allow_fault and not getattr(
                    ctx.cfg.security, "allow_kernel_softfault", False):
                return _j({
                    "ok": False, "kind": "not_allowed",
                    "error": ("memory_manage: allow_fault=true refused — "
                              "security.allow_kernel_softfault is false"),
                    "hint": ("a driver soft-fault of a non-resident kernel "
                             "page can wedge the target. Retry without "
                             "allow_fault (partial=true reads the resident "
                             "prefix), or set security.allow_kernel_softfault"
                             "=true in the orchestrator config for a lab "
                             "box you may wedge")})
            # `name=` selects a target view (`kernel`|`user`),
            # never a row filter. Callers who wanted to filter modules by
            # substring have always been supposed to use `filter=` or the
            # typed `name_regex=` / `name_glob=`. Refuse the misuse with a
            # named error so the collision doesn't quietly route to the
            # wrong view. '<machine>'/'<machine>.<kind>' selectors
            # pass through — their machine token must resolve.
            if name not in (PRIMARY_TARGET, "user", "kernel", "") \
                    and ctx.session._match_machine(
                        name.rsplit(".", 1)[0]) is None:
                return _j({"ok": False,
                           "kind": "kwarg_collision",
                           "error": ("'name' selects a target view ('kernel'|"
                                     "'user'), not a row filter. Use 'filter' "
                                     "or 'name_regex' to select rows."),
                           "hint": "filter='tcpip' or name_regex='^tcpip\\\\.sys$' "
                                   "for a modules row filter; name='kernel'/"
                                   "'user' picks the view"})
            # Pure-compute short-circuit: `disasm` with a raw hex buffer and
            # `assemble` with no `write_to` do not need a target. Handle
            # them BEFORE `require_client` so the LLM can round-trip bytes
            # without an active connection.
            if action == "disasm" and bytes_hex and not address:
                return await _mem_disasm(
                    ctx, name=name, pid=pid, space=space,
                    address=0, bytes_hex=bytes_hex,
                    arch=arch, syntax=syntax, count=count, size=size,
                    detail=_disasm_detail, resolve_symbols=False,  # symbols need target
                    allow_fault=allow_fault, timeout_s=timeout_s,
                )
            if action == "assemble" and not write_to:
                return await _mem_assemble(
                    ctx, name=name, pid=pid, space=space,
                    code=code, arch=arch, address=_addr(address, "address"),
                    write_to=0, dry_run=True, allow_map_write=allow_map_write,
                )
            c = ctx.session.require_client(name)
            # every kernel-view memory_manage action routes through the
            # pry driver — preflight it ONCE here so a missing driver
            # surfaces as a named `driver_absent` error instead of raw
            # gRPC noise (previously only 5 actions were guarded). The
            # user view (umagent) never touches the driver.
            # v14: process_list + threads(kernel=false) enumerate via
            # agent-side NtQuerySystemInformation — no driver needed, and
            # gating them here is exactly the post-reboot hole this build
            # was made to close.
            _driver_free = {"process_list"}
            if action == "threads" and not kernel:
                _driver_free.add("threads")
            # SI #1 image coherency is a pure usermode compare (mapped
            # file + VM_READ). The umagent view answers it fully; on
            # the agent view the driver is only used when the target
            # is PPL — the preflight guard is skipped either way.
            if action == "coherency":
                _driver_free.add("coherency")
            # SI #2 hidden-process (Wave 1): brute / registry / ETW
            # are pure usermode APIs. Both views answer; no driver.
            if action == "hidden_proc":
                _driver_free.add("hidden_proc")
            # segment-heap decode. Pure
            # usermode reads on both views (agent view uses the driver
            # as the UserReadFn ONLY for PPL targets, same contract as
            # SI #1 image coherency). Preflight gate stays off so a
            # driver-less lab still gets the honest ``dyn_data_wave_3
            # _pending`` envelope rather than ``driver_absent``.
            if action == "heap_info":
                _driver_free.add("heap_info")
            if ctx.session.view_kind_of(name) != "user" \
                    and action not in _driver_free:
                guard = await _require_driver(ctx, "memory_manage", action, name)
                if guard:
                    return _j(guard)
            # module+offset resolution needs live modules; kernel-list for
            # kernel/physical addresses, per-pid user list otherwise.
            _kernel_lookup = kernel or space in ("kernel", "physical")
            addr = await _addr_resolve(address, c, kernel=_kernel_lookup,
                                       pid=pid, name="address")
            base_i = await _addr_resolve(base, c, kernel=_kernel_lookup,
                                         pid=pid, name="base")
            if action == "read":
                return await _mem_read.handle_read(
                    ctx, c, pid=pid, addr=addr, size=size, space=space,
                    decode=decode, reads=reads, from_va=from_va,
                    resolve_physical=resolve_physical, address=address,
                    module=module, path=path, include_ascii=include_ascii,
                    allow_fault=allow_fault, allow_mmio=allow_mmio,
                    partial=partial, timeout_s=timeout_s, offset=offset,
                    kernel_lookup=_kernel_lookup,
                )
            if action == "follow_chain":
                return await _mem_pointer.handle_follow_chain(
                    ctx, c, pid=pid, addr=addr, space=space,
                    offsets=offsets, terminal_size=terminal_size,
                    expect_ascii=expect_ascii,
                    expect_nonzero=expect_nonzero,
                    expect_module=expect_module,
                    kernel_lookup=_kernel_lookup,
                    allow_fault=allow_fault,
                )
            if action == "write":
                return await _mem_write.handle_write(
                    ctx, c, pid=pid, addr=addr, size=size, space=space,
                    data_hex=data_hex, verify=verify,
                    allow_fault=allow_fault,
                    allow_map_write=allow_map_write,
                    timeout_s=timeout_s,
                )
            if action == "alloc":
                return await _mem_alloc.handle_alloc(
                    ctx, c, pid=pid, size=size, protect=protect,
                    kernel=kernel,
                )
            if action == "free":
                return await _mem_alloc.handle_free(
                    ctx, c, pid=pid, addr=addr, kernel=kernel,
                )
            if action == "protect":
                return await _mem_alloc.handle_protect(
                    ctx, c, pid=pid, addr=addr, size=size, protect=protect,
                )
            if action == "modules":
                return await _mem_modules.handle_modules(
                    ctx, c, pid=pid, space=space, kernel=kernel, name=name,
                    name_regex=name_regex, name_glob=name_glob,
                    path_contains=path_contains, compact=compact,
                    summary=summary, filter=filter, fields=fields,
                    limit=limit, offset=offset, max_results=max_results,
                    verify_signatures=verify_signatures,
                    force_recheck=force_recheck,
                )
            if action == "process_list":
                return await _mem_processes.handle_process_list(
                    ctx, c, with_cmdline=with_cmdline, filter=filter,
                    fields=fields, summary=summary, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "resolve":
                return await _mem_resolve.handle_resolve(
                    ctx, c, pid=pid, value=value, address=address,
                    module=module, space=space, kernel=kernel, path=path,
                )
            if action in ("resolve_range", "dps"):
                return await _mem_forensics.handle_resolve_range(
                    ctx, c, action=action, pid=pid, addr=addr,
                    base_i=base_i, size=size, space=space,
                    allow_fault=allow_fault, timeout_s=timeout_s,
                    resolve_symbols=resolve_symbols, path=path,
                    include_ascii=include_ascii, compact=compact,
                    verbosity=verbosity, filter=filter, summary=summary,
                    fields=fields, limit=limit, offset=offset,
                    max_results=max_results,
                )
            if action == "dt":
                return await _mem_forensics.handle_dt(
                    ctx, c, pid=pid, addr=addr, size=size, space=space,
                    value=value, module=module, path=path, decode=decode,
                    include_ascii=include_ascii,
                    allow_fault=allow_fault, timeout_s=timeout_s,
                )
            if action == "idt":
                return await _mem_forensics.handle_idt(
                    ctx, c, pid=pid, all_cpus=all_cpus, path=path,
                    compact=compact, verbosity=verbosity, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "pattern_scan":
                return await _mem_scan.handle_pattern_scan(
                    ctx, c, pid=pid, addr=addr, base_i=base_i, size=size,
                    space=space, kernel=kernel, pattern=pattern,
                    pattern_hex=pattern_hex, mask=mask,
                    max_results=max_results, module=module,
                    sections=sections, kernel_lookup=_kernel_lookup,
                    limit=limit, offset=offset, fields=fields,
                    filter=filter, summary=summary,
                    writable=writable, executable=executable, cow=cow,
                    include_guarded=include_guarded, mem_types=mem_types,
                    scope=scope,
                )
            if action in ("scan_start", "scan_status", "scan_result",
                          "scan_cancel", "scan_list"):
                # long-running scan job surface. Same args as
                # pattern_scan for scan_start; scan_status / scan_result /
                # scan_cancel address by scan_id. All five delegate to
                # ``.mem.scan`` as of R4 (slice §Commit 5).
                if action == "scan_start":
                    return await _mem_scan.handle_scan_start(
                        ctx, c, pid=pid, addr=addr, base_i=base_i,
                        size=size, space=space, kernel=kernel,
                        pattern=pattern, pattern_hex=pattern_hex,
                        mask=mask, max_results=max_results,
                        module=module, sections=sections,
                        writable=writable, executable=executable,
                        cow=cow, include_guarded=include_guarded,
                        mem_types=mem_types, scope=scope,
                    )
                if action == "scan_status":
                    return await _mem_scan.handle_scan_status(scan_id, c=c)
                if action == "scan_result":
                    return await _mem_scan.handle_scan_result(
                        ctx, scan_id, limit=limit, offset=offset, c=c)
                if action == "scan_cancel":
                    return await _mem_scan.handle_scan_cancel(scan_id, c=c)
                if action == "scan_list":
                    return _mem_scan.handle_scan_list()
            # v16 Memory scanner wave 1: typed value_scan + next_scan surface.
            # Routes through mem.value_scan; v15 fallback runs orchestrator-
            # side (works against today's agent), v16 path delegates to
            # ScanService when the agent advertises scan_service_version>=1.
            if action == "value_scan":
                from . import value_scan as _mem_vscan
                return await _mem_vscan.handle_value_scan(
                    ctx, c, pid=pid, address=addr, size=size, space=space,
                    kernel_lookup=_kernel_lookup,
                    value_type=value_type, op=op, value=value,
                    value_hi=value_hi, tolerance=tolerance,
                    endian=endian, encoding=encoding, align=align,
                    sections=sections, module=module,
                    writable=writable, executable=executable, cow=cow,
                    include_guarded=include_guarded, mem_types=mem_types,
                    scope=scope, max_results=max_results,
                    confirm_full_space=confirm_full_space,
                    name=name,
                    limit=limit, offset=offset,
                )
            if action == "next_scan":
                from . import value_scan as _mem_vscan
                return await _mem_vscan.handle_next_scan(
                    ctx, c, scan_id=scan_id, op=op, value=value,
                    value_hi=value_hi, delta=delta,
                    tolerance=tolerance,
                    limit=limit, offset=offset,
                )
            if action == "scan_undo":
                from . import value_scan as _mem_vscan
                return await _mem_vscan.handle_scan_undo(
                    ctx, c, scan_id=scan_id)
            if action == "scan_destroy":
                from . import value_scan as _mem_vscan
                return await _mem_vscan.handle_scan_destroy(
                    ctx, c, scan_id=scan_id)
            # v17 (Memory scanner wave 2): pointer map + reverse scan +
            # diff. See mem/pointer_map.py for the shared v17 gate.
            if action == "pointer_map_create":
                from . import pointer_map as _mem_pmap
                from .region_filter import resolve_spans as _resolve_spans
                _spans, _info, _err = await _resolve_spans(
                    c, pid=pid, space=space,
                    kernel_lookup=_kernel_lookup,
                    address=addr, size=size,
                    sections=sections, module=module, scope=scope,
                    writable=writable, executable=executable, cow=cow,
                    include_guarded=include_guarded, mem_types=mem_types)
                if _err:
                    return _j(_err) if isinstance(_err, dict) else _err
                # If the caller gave neither a scope/section/region nor
                # an address+size, resolve_spans returns [] (its
                # whole-space fast path). For pointer_map_create that's
                # nonsense — refuse with a hint.
                if not _spans:
                    return _j({
                        "ok": False, "kind": "no_spans",
                        "tool": "memory_manage",
                        "action": "pointer_map_create",
                        "error": ("pointer_map_create: no spans resolved "
                                  "from the given filters; pass one of "
                                  "address=+size=, scope=, or sections="),
                        "hint": ("scope='image' + sections='.rdata' + "
                                 "module='<exe>' is the plan's bounded "
                                 "example (plan §4 Phase H)"),
                    })
                return await _mem_pmap.handle_pointer_map_create(
                    ctx, c, pid=pid, spans=list(_spans or []),
                    space=space, name=name,
                    max_candidates=int(max_candidates or max_results),
                    disk_spill_mode=disk_spill_mode, map_id=map_id)
            if action == "pointer_map_status":
                from . import pointer_map as _mem_pmap
                return await _mem_pmap.handle_pointer_map_status(
                    ctx, c, name=name, map_id=map_id)
            if action == "pointer_map_list":
                from . import pointer_map as _mem_pmap
                return await _mem_pmap.handle_pointer_map_list(
                    ctx, c, name=name)
            if action == "pointer_map_cancel":
                from . import pointer_map as _mem_pmap
                return await _mem_pmap.handle_pointer_map_cancel(
                    ctx, c, name=name, map_id=map_id)
            if action == "pointer_map_save":
                from . import pointer_map as _mem_pmap
                return await _mem_pmap.handle_pointer_map_save(
                    ctx, c, name=name, map_id=map_id,
                    remote_path=remote_path)
            if action == "pointer_map_load":
                from . import pointer_map as _mem_pmap
                return await _mem_pmap.handle_pointer_map_load(
                    ctx, c, name=name, remote_path=remote_path,
                    map_id=map_id)
            if action == "pointer_map_destroy":
                from . import pointer_map as _mem_pmap
                return await _mem_pmap.handle_pointer_map_destroy(
                    ctx, c, name=name, map_id=map_id, keep_disk=keep_disk)
            if action == "pointer_scan":
                from . import pointer_map as _mem_pmap
                _tva = (int(target_va, 0) if isinstance(target_va, str)
                        and target_va else int(target_va or 0))
                return await _mem_pmap.handle_pointer_scan(
                    ctx, c, name=name, map_id=map_id, target_va=_tva,
                    max_depth=max_depth, max_offset=max_offset,
                    static_only=static_only, max_results=max_results,
                    fanout_per_level=fanout_per_level, wall_ms=wall_ms,
                    decorate=bool(decorate), pid=int(pid or 0))
            if action == "pointer_map_diff":
                from . import pointer_map as _mem_pmap
                return await _mem_pmap.handle_pointer_map_diff(
                    ctx, c, name=name, map_id_a=map_id,
                    map_id_b=map_id_b, static_only=static_only,
                    chains=chains)
            if action == "dissect":
                from . import dissect as _mem_dissect
                _decode: list[str] | None = None
                if isinstance(decode, list):
                    _decode = [str(d) for d in decode]
                elif isinstance(decode, str) and decode:
                    _decode = [decode]
                _align = int(align) if isinstance(align, int) else 0
                return await _mem_dissect.handle_dissect(
                    ctx, c, pid=pid, address=addr, size=size,
                    space=space, with_modules=with_modules,
                    decode=_decode, align=_align or 4, name=name,
                    decorate=bool(decorate))
            if action == "dissect_compare":
                from . import dissect as _mem_dissect
                _align_c = int(align) if isinstance(align, int) else 0
                _bases: list[int] = []
                for v in (base_vas or []):
                    try:
                        _bases.append(int(v))
                    except (TypeError, ValueError):
                        continue
                return await _mem_dissect.handle_dissect_compare(
                    ctx, c, pid=pid, base_vas=_bases,
                    window_size=int(window_size or 0),
                    align=_align_c or 4,
                    space=space, with_modules=bool(with_modules),
                    shared_ptr_min_vote=int(shared_ptr_min_vote or 0),
                    min_instances_for_class=int(
                        min_instances_for_class or 0),
                    decorate=bool(decorate), name=name,
                )
            if action == "heap_attrib":
                # Wave 3 P2: coerce the scalar `va=` so both `va='0x…'`
                # and `va=0x…` reach the handler as an int. The
                # handler already accepts both scalar and list forms.
                _scalar_va: int | str = 0
                if isinstance(va, int):
                    _scalar_va = va
                elif isinstance(va, str) and va:
                    _scalar_va = va
                return await _mem_heap_attrib.handle_heap_attrib(
                    ctx, c, pid=pid, va=_scalar_va,
                    vas=vas, refresh=bool(refresh), name=name)
            if action == "walk_list":
                return await _mem_forensics.handle_walk_list(
                    ctx, c, pid=pid, addr=addr, size=size, space=space,
                    value=value, decode=decode, count=count,
                    max_results=max_results, allow_fault=allow_fault,
                    timeout_s=timeout_s,
                )
            if action == "read_qwords":
                return await _mem_forensics.handle_read_qwords(
                    ctx, c, pid=pid, addr=addr, space=space, count=count,
                    max_results=max_results, allow_fault=allow_fault,
                    timeout_s=timeout_s,
                )
            if action in ("read_unicode_string", "read_ansi_string"):
                return await _mem_forensics.handle_read_string(
                    ctx, c, action=action, pid=pid, addr=addr, space=space,
                    allow_fault=allow_fault, timeout_s=timeout_s,
                )
            if action == "vad":
                return await _mem_vad.handle_vad(
                    ctx, c, pid=pid, filter=filter, summary=summary,
                    fields=fields, limit=limit, offset=offset,
                    max_results=max_results,
                )
            if action == "handles":
                return await _mem_handles.handle_handles(
                    ctx, c, pid=pid, want_names=want_names, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "imports":
                return await _mem_probes.handle_imports(
                    ctx, c, pid=pid, module=module, name=name,
                    kernel_lookup=_kernel_lookup, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "exports":
                return await _mem_probes.handle_exports(
                    ctx, c, pid=pid, module=module, name=name,
                    kernel_lookup=_kernel_lookup, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "heaps":
                return await _mem_probes.handle_heaps(
                    ctx, c, pid=pid, want_blocks=want_blocks,
                    max_blocks=max_blocks,
                )
            if action == "heap_info":
                # segment-heap decode. The
                # umagent view fails on PPL (ReadProcessMemory ->
                # access_denied); the agent view decodes via the driver
                # read path. Both views degrade to coverage='partial' +
                # hint='dyn_data_wave_3_pending' while Wave 3 lands the
                # signed segment-heap offset table.
                return await _mem_heap_info.handle_heap_info(
                    ctx, c, pid=pid,
                    heap_filter=(int(base_i or 0) or int(base or 0)),
                    include_segments=bool(want_blocks),
                    include_lfh_buckets=bool(include_ascii),
                    space=space, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "phys_ranges":
                return await _mem_probes.handle_phys_ranges(ctx, c)
            if action == "pool_scan":
                return await _mem_pool.handle_pool_scan(
                    ctx, c, pid=pid, size=size, space=space, kernel=kernel,
                    pattern=pattern, pattern_hex=pattern_hex, mask=mask,
                    max_results=max_results, module=module,
                    protect=protect, filter=filter, summary=summary,
                    fields=fields, limit=limit, offset=offset,
                    enrich_tags=enrich_tags,
                )
            if action == "probe_va":
                return await _mem_probes.handle_probe_va(
                    ctx, c, pid=pid, addr=addr, space=space,
                )
            if action == "va_translate":
                return await _mem_probes.handle_va_translate(
                    ctx, c, pid=pid, addr=addr, space=space,
                )
            if action == "watch":
                return await _mem_watch.handle_watch(
                    ctx, c, pid=pid, addr=addr, size=size, space=space,
                    name=name, pattern_hex=pattern_hex,
                    timeout_s=timeout_s, max_results=max_results,
                    filter=filter,
                    # HW-watch opt-in
                    mode=mode, access=access, tid=tid, slot=slot,
                    preempt_ok=preempt_ok,
                )
            if action == "watch_list":
                return _mem_watch.handle_watch_list()
            if action == "watch_stop":
                # async — a mode='hw' watch releases its DR slot
                # through WatchHw.Remove on the view that armed it.
                return await _mem_watch.handle_watch_stop_async(
                    ctx, module=module, filter=filter,
                )
            if action == "disasm":
                return await _mem_codegen.handle_disasm(
                    ctx, c, name=name, pid=pid, space=space, addr=addr,
                    bytes_hex=bytes_hex, arch=arch, syntax=syntax,
                    count=count, size=size, detail=_disasm_detail,
                    resolve_symbols=resolve_symbols,
                    allow_fault=allow_fault, timeout_s=timeout_s,
                    filter=filter, summary=summary, fields=fields,
                    limit=limit, offset=offset, max_results=max_results,
                )
            if action == "assemble":
                return await _mem_codegen.handle_assemble(
                    ctx, c, name=name, pid=pid, space=space, code=code,
                    arch=arch, addr=addr, write_to=write_to,
                    dry_run=dry_run, allow_map_write=allow_map_write,
                )
            if action in ("strings", "iocs"):
                return await _mem_extraction.handle_strings_iocs(
                    ctx, c, action=action, pid=pid, addr=addr, size=size,
                    space=space, min_len=min_len, allow_fault=allow_fault,
                    partial=partial, timeout_s=timeout_s, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "entropy":
                return await _mem_extraction.handle_entropy(
                    ctx, c, pid=pid, addr=addr, size=size, space=space,
                    buckets=buckets, allow_fault=allow_fault,
                    partial=partial, timeout_s=timeout_s, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                )
            if action == "threads":
                # eight opt-in enrichment
                # columns. Each ``include_<field>=True`` fans out one
                # extra per-row RPC through asyncio.gather with a 16-way
                # concurrency cap. Base response shape (every include
                # flag off) stays bit-identical to the original shape.
                return await _mem_threads.handle_threads(
                    ctx, c, pid=pid, kernel=kernel,
                    with_context=with_context, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                    include_last_syscall=bool(include_last_syscall),
                    include_kernel_stack_usage=bool(include_kernel_stack_usage),
                    include_pending_irp=bool(include_pending_irp),
                    include_impersonation=bool(include_impersonation),
                    include_com_apartment=bool(include_com_apartment),
                    include_rpc_usage=bool(include_rpc_usage),
                    include_power_throttling=bool(include_power_throttling),
                    include_fiber=bool(include_fiber),
                )
            if action == "obj_enum":
                return await _mem_obj_browse.handle_obj_enum(
                    ctx, c, path=path, depth=depth,
                    max_results=max_results, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset,
                )
            if action == "leak_scan":
                return await _mem_pointer.handle_leak_scan(
                    ctx, c, pid=pid, space=space, name=name,
                    needles=needles, scopes=scopes,
                    max_results=max_results,
                    kernel_lookup=_kernel_lookup,
                    allow_fault=allow_fault,
                )
            if action == "global_find":
                # SI #7: shape overlaps pattern+scan_id usage. `pattern`
                # starts a job, `scan_id` fetches/polls one. Cancel is
                # explicit via the shared memory_manage cancel path through a
                # dedicated kwarg: pass `scan_id` AND `module='cancel'`
                # OR use the dedicated `scan_cancel`-shaped flow by
                # setting `name='cancel'`? No — keep it simple: pattern=
                # or scan_id= drives the lifecycle; `filter='cancel'`
                # requests cancellation (narrowly scoped keyword).
                _cancel = (isinstance(filter, str)
                           and filter.strip().lower() == "cancel")
                _list_jobs = (isinstance(filter, str)
                              and filter.strip().lower() == "list")
                return await _mem_global_find.handle_global_find(
                    ctx, c,
                    pattern=pattern or pattern_hex,
                    kinds=kinds, regex=regex,
                    want_object_names=want_object_names,
                    max_results=max_results,
                    concurrency=concurrency,
                    scan_id=scan_id,
                    limit=limit, offset=offset,
                    cancel=_cancel, list_jobs=_list_jobs,
                )
            if action == "coherency":
                # SI #1 — image coherency score for one module.
                # `mode` reuses the generic `arch`/`syntax` kwargs via
                # the dedicated `value` str kwarg (quick|normal|full).
                _mode = str(value or "normal").lower() or "normal"
                return await _mem_coherency.handle_coherency(
                    ctx, c, pid=pid, module=module,
                    module_base=base_i or int(base or 0),
                    mode=_mode, name=name,
                    max_mismatch_ranges=max_results,
                    include_mismatch_hex=bool(include_ascii),
                    fields=fields, filter=filter, summary=summary,
                    limit=limit, offset=offset,
                )
            # SI #6/#9 — handle ops + kernel-stack walk. The
            # existing MemArgs kwargs carry the operands (pid+addr for
            # the primary handle; size/protect for access/options; base
            # for the SI #24 PrivilegeCookie; tid+base for the compare
            # second pair; value for the stackwalk mode selector).
            if action == "handle_dup":
                return await _mem_handle_ops.handle_handle_dup(
                    ctx, c, src_pid=int(pid), src_handle=int(addr or 0),
                    desired_access=int(size or 0),
                    options=int(protect or 0),
                    privilege_cookie=int(base_i or 0), name=name)
            if action == "handle_close":
                return await _mem_handle_ops.handle_handle_close(
                    ctx, c, target_pid=int(pid),
                    target_handle=int(addr or 0),
                    privilege_cookie=int(base_i or 0), name=name)
            if action == "handle_compare":
                return await _mem_handle_ops.handle_handle_compare(
                    ctx, c, pid_a=int(pid), handle_a=int(addr or 0),
                    pid_b=int(tid or 0), handle_b=int(base_i or 0),
                    privilege_cookie=0, name=name)
            if action == "stack_walk":
                return await _mem_stack_walk.handle_stack_walk(
                    ctx, c, tid=int(tid),
                    mode=(value or "both").lower(),
                    max_frames=int(max_results or 0),
                    timeout_ms=int(timeout_s * 1000) if timeout_s > 0 else 0,
                    force_apc=bool(preempt_ok),
                    timeout_partial_ok=bool(partial),
                    privilege_cookie=int(base_i or 0), name=name)
            if action == "hidden_proc":
                # SI #2 — hidden-process detection (Wave 1). `kinds`
                # reuses the generic list kwarg already in the
                # dispatcher for picking modes (brute/registry/etw);
                # pid_max/step ride on size/count respectively, and
                # timeout_s is converted to ms server-side.
                _hp_modes = kinds if kinds else None
                return await _mem_hidden_proc.handle_hidden_proc(
                    ctx, c, modes=_hp_modes,
                    pid_max=int(size or 0),
                    step=int(count or 0) if count != 64 else 0,
                    timeout_ms=int(timeout_s * 1000) if timeout_s > 0 else 0,
                    fields=fields, filter=filter, summary=summary,
                    limit=limit, offset=offset,
                    max_results=max_results,
                )

            return _unknown_action("memory_manage", action, _MEMORY_ACTIONS_MASTER, _MEMORY_ACTION_HELP)

        return await _guard(ctx, "memory_manage", action, args,
                            _ev_with(ctx, "memory_manage", action, args, run,
                                     _ev_detail))

    # Expose the dispatcher so the canonical ``*_manage`` tools can
    # forward through the same body without duplicating it.
    global _MEMORY_MANAGE_FN
    _MEMORY_MANAGE_FN = memory_manage
