"""Per-verb help text table for ``memory_manage(action='actions')``.

Lifted verbatim out of ``mem.py``'s ``register()`` closure in Phase R5
to keep the dispatcher under the 700-line cap. Pure data; no runtime
dependencies — tests can import ``_MEMORY_ACTION_HELP`` directly without
pulling in FastMCP or the per-verb modules.
"""

from __future__ import annotations


_MEMORY_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "memory_manage(action='actions')"},
    "read": {"one_liner": "read memory (user/kernel/physical space); "
                          "decode='u64[4]' primitives or decode="
                          "{'type':'_EPROCESS','module':...} named "
                          "type (dt is the shortcut for that). "
                          "space='physical' default-denies out-of-RAM "
                          "with kind='mmio_blocked' — pass "
                          "allow_mmio=True to opt in (WARNING: PCI "
                          "MMIO can wedge the driver)",
             "key_args": "pid, address, size, space, decode, reads, "
                         "allow_mmio",
             "example": "memory_manage(action='read', pid=1234, "
                        "address='0x7ff60000', size=64)"},
    "follow_chain": {"one_liner": "pointer-chain chase — walk "
                                  "address+offsets[0], deref, add "
                                  "offsets[1], ... reports every hop "
                                  "and the terminal read",
                     "key_args": "address, offsets, pid, space, "
                                 "terminal_size, expect_ascii, "
                                 "expect_nonzero, expect_module",
                     "example": "memory_manage(action='follow_chain', "
                                "pid=1234, address='0x7ff60000', "
                                "offsets=[0x18, 0x30], "
                                "terminal_size=16)"},
    "leak_scan": {"one_liner": "look for needle(s) across kernel pool, "
                               "module data sections, and/or every "
                               "process heap; one coverage block per "
                               "scope",
                  "key_args": "needles, scopes, max_results, pid, "
                              "allow_fault",
                  "example": "memory_manage(action='leak_scan', "
                             "needles=['Secret\\x00'], "
                             "scopes=['kernel_pool','module_data'])"},
    "resolve": {"one_liner": "VA <-> module+offset, and "
                             "module!symbol(+addend) -> VA via the "
                             "PDB (needs a dumped/local image)",
                "key_args": "value, pid, space, path",
                "example": "memory_manage(action='resolve', space='kernel', "
                           "value='ntoskrnl.exe!PsLoadedModuleList')"},
    "write": {"one_liner": "write memory (data_hex)",
              "key_args": "pid, address, data_hex, space",
              "example": "memory_manage(action='write', pid=1234, "
                         "address='0x...', data_hex='90')"},
    "alloc": {"one_liner": "VirtualAlloc(Ex) in the target",
              "key_args": "pid, size, protect, space",
              "example": "memory_manage(action='alloc', pid=1234, size=0x1000, "
                         "protect='rwx')"},
    "free": {"one_liner": "free an allocation",
             "key_args": "pid, address",
             "example": "memory_manage(action='free', pid=1234, address='0x...')"},
    "protect": {"one_liner": "change page protection",
                "key_args": "pid, address, size, protect",
                "example": "memory_manage(action='protect', pid=1234, "
                           "address='0x...', size=0x1000, protect='rx')"},
    "modules": {"one_liner": "MOVED → module_manage(action='list'). "
                              "module list for a pid (or kernel list); "
                              "verify_signatures=true attaches signer / "
                              "signing_level / is_signed / catalog / "
                              "signer_cache_hit columns (SI #8). Default "
                              "response is unchanged.",
                "key_args": "pid, filter, fields, limit, "
                            "verify_signatures, force_recheck",
                "example": "memory_manage(action='modules', pid=1234, "
                           "verify_signatures=true)"},
    "process_list": {"one_liner": "MOVED → process_manage(action='list'). "
                                   "process inventory",
                     "key_args": "fields, filter, summary",
                     "example": "memory_manage(action='process_list')"},
    "pattern_scan": {"one_liner": "sync byte-pattern scan over a range "
                                  "(use scan_start for wide sweeps)",
                     "key_args": "pid, address/base, size, pattern|"
                                 "pattern_hex, mask, space, sections",
                     "example": "memory_manage(action='pattern_scan', pid=1234, "
                                "base='ntoskrnl.exe', "
                                "pattern='4C 8B ?? 15')"},
    "vad": {"one_liner": "VAD / memory-region map for a process",
            "key_args": "pid, filter",
            "example": "memory_manage(action='vad', pid=1234)"},
    "handles": {"one_liner": "MOVED → object_manage(action='handles'). "
                             "handle table for a pid (pid=4 = kernel "
                             "objects; prefer summary=true under load)",
                "key_args": "pid, want_names, limit, offset, fields, "
                            "summary",
                "example": "memory_manage(action='handles', pid=4, "
                           "want_names=false, summary=true)"},
    "imports": {"one_liner": "module import table (live image)",
                "key_args": "pid, module",
                "example": "memory_manage(action='imports', pid=1234, "
                           "module='x.dll')"},
    "exports": {"one_liner": "module export table (live image)",
                "key_args": "pid, module",
                "example": "memory_manage(action='exports', module='ntoskrnl.exe', "
                           "space='kernel')"},
    "heaps": {"one_liner": "process heap inventory",
              "key_args": "pid",
              "example": "memory_manage(action='heaps', pid=1234)"},
    "heap_info": {"one_liner": "segment-heap decode: class / size_type / "
                                "front_end_type / lock_status + optional "
                                "SegContext page-descriptor walk. PPL "
                                "asymmetry: umagent fails access_denied "
                                "on PP/PPL (ReadProcessMemory); agent "
                                "view decodes PPL heaps via the driver "
                                "read path (name=''). Coverage "
                                "degrades to partial + "
                                "dyn_data_wave_3_pending while Wave 3 "
                                "owns the signed offset table.",
                  "key_args": "pid, base (heap_filter), want_blocks "
                              "(include_segments), include_ascii "
                              "(include_lfh_buckets), space='user'",
                  "example": "memory_manage(action='heap_info', pid=1234, "
                             "want_blocks=True)"},
    "probe_va": {"one_liner": "probe whether an address is readable "
                              "(no data returned)",
                 "key_args": "pid, address, space",
                 "example": "memory_manage(action='probe_va', space='kernel', "
                            "address='0xfffff800...')"},
    "phys_ranges": {"one_liner": "valid physical-memory ranges "
                                 "(MmPhysicalMemoryBlock)",
                    "key_args": "none",
                    "example": "memory_manage(action='phys_ranges')"},
    "pool_scan": {"one_liner": "MOVED → kernel_manage(action='pool_scan'). "
                                "kernel pool scan by tag; rows carry "
                                "owner_driver + tag_description (set "
                                "enrich_tags=false to skip the "
                                "orchestrator-side pooltag.txt lookup)",
                  "key_args": "tag, pool_type, limit, enrich_tags",
                  "example": "memory_manage(action='pool_scan', module='Proc')"},
    "global_find": {"one_liner": "MOVED → object_manage(action='find'). "
                                 "system-wide handle/module name search; "
                                 "pattern starts a job, scan_id polls it, "
                                 "filter='cancel'|'list' manages jobs",
                    "key_args": "pattern, kinds, regex, "
                                "want_object_names, max_results, "
                                "concurrency, scan_id",
                    "example": "memory_manage(action='global_find', "
                               "pattern='kernelbase', "
                               "kinds=['module'])"},
    "va_translate": {"one_liner": "VA -> PA via the driver's page-table "
                                  "walk (kernel space only; cr3= "
                                  "override needs ABI v12)",
                     "key_args": "pid, address, space",
                     "example": "memory_manage(action='va_translate', pid=1234, "
                                "address='0x...')"},
    "watch": {"one_liner": "arm a memory watch — mode='poll' (default) "
                           "runs an orchestrator-side poll loop "
                           "(<=30 s and <=32 events collect inline, "
                           "longer runs return a watch_id); "
                           "mode='hw' (ABI v14+) arms a DR0..DR3 slot "
                           "via the driver and routes hits through the "
                           "CLASS_BP notify ring (demux by watch_cookie, "
                           "falls back to poll under HVCI)",
              "key_args": "pid, address, size (1..256), mode, access, "
                          "tid, slot, preempt_ok, interval_s, max_events, "
                          "pattern_hex, tag",
              "example": "memory_manage(action='watch', pid=1234, "
                         "address='0x...', size=8, mode='hw')"},
    "watch_list": {"one_liner": "list active watches",
                   "key_args": "none",
                   "example": "memory_manage(action='watch_list')"},
    "watch_stop": {"one_liner": "stop a watch",
                   "key_args": "watch_id",
                   "example": "memory_manage(action='watch_stop', "
                              "watch_id='w0001')"},
    "disasm": {"one_liner": "disassemble bytes or live memory "
                            "(bytes_hex short-circuits with no target; "
                            "space='physical' works — reads via "
                            "mem_read)",
               "key_args": "address|bytes_hex, size, arch, syntax, "
                           "count, detail",
               "example": "memory_manage(action='disasm', bytes_hex='4889C8')"},
    "assemble": {"one_liner": "assemble to bytes (dry-run when no "
                              "write_to)",
                 "key_args": "code, arch, write_to, address",
                 "example": "memory_manage(action='assemble', code='nop;ret')"},
    "scan_start": {"one_liner": "start a background scan job — returns "
                                "scan_id immediately",
                   "key_args": "pid, address/base, size, pattern, "
                               "space, sections, max_results",
                   "example": "memory_manage(action='scan_start', space='kernel', "
                              "base='ntoskrnl.exe', size=0x200000, "
                              "pattern='48 8B ??')"},
    "scan_status": {"one_liner": "poll a scan job's progress",
                    "key_args": "scan_id",
                    "example": "memory_manage(action='scan_status', "
                               "scan_id='s3')"},
    "scan_result": {"one_liner": "fetch a finished scan's hits",
                    "key_args": "scan_id, limit, offset",
                    "example": "memory_manage(action='scan_result', "
                               "scan_id='s3')"},
    "scan_cancel": {"one_liner": "cancel a running scan",
                    "key_args": "scan_id",
                    "example": "memory_manage(action='scan_cancel', "
                               "scan_id='s3')"},
    "scan_list": {"one_liner": "list scan jobs",
                  "key_args": "none",
                  "example": "memory_manage(action='scan_list')"},
    "walk_list": {"one_liner": "follow a linked list from address: read "
                               "the next pointer at next_offset in each "
                               "node; stops on NULL, a revisit or "
                               "max_hops",
                  "key_args": "address, next_offset, max_hops, space, pid, "
                              "size, decode",
                  "example": "memory_manage(action='walk_list', space='kernel', "
                             "address='0xfffff80312345678', "
                             "next_offset='0x448', max_hops=32)"},
    "read_qwords": {"one_liner": "read N qwords as a table (pointer "
                                 "walks)",
                    "key_args": "pid, address, count",
                    "example": "memory_manage(action='read_qwords', "
                               "space='kernel', address='0x...', "
                               "count=16)"},
    "read_unicode_string": {"one_liner": "read a UNICODE_STRING at "
                                         "address",
                            "key_args": "pid, address, space",
                            "example": "memory_manage(action='read_unicode_string', "
                                       "space='kernel', address='0x...')"},
    "read_ansi_string": {"one_liner": "read an ANSI_STRING at address",
                         "key_args": "pid, address, space",
                         "example": "memory_manage(action='read_ansi_string', "
                                    "space='kernel', address='0x...')"},
    "strings": {"one_liner": "extract printable strings from live "
                             "memory",
                "key_args": "pid, address, size, min_len",
                "example": "memory_manage(action='strings', pid=1234, "
                           "address='0x...', size=0x1000)"},
    "iocs": {"one_liner": "extract indicators from live memory",
             "key_args": "pid, address, size",
             "example": "memory_manage(action='iocs', pid=1234, address='0x...', "
                        "size=0x1000)"},
    "entropy": {"one_liner": "entropy profile over a live range",
                "key_args": "pid, address, size, buckets",
                "example": "memory_manage(action='entropy', pid=1234, "
                           "address='0x...', size=0x1000)"},
    "threads": {"one_liner": "MOVED → thread_manage(action='list'). "
                              "system-wide per-thread inventory with opt-in "
                              "columns: include_last_syscall / "
                              "_kernel_stack_usage / _pending_irp "
                              "(driver-sourced; wave_3_pending degrade), "
                              "_impersonation / _com_apartment / "
                              "_rpc_usage / _power_throttling / _fiber "
                              "(umagent-only Win32 APIs; agent view "
                              "returns not_supported, hint='use name=user'). "
                              "PPL note: driver columns work on PP; "
                              "umagent columns degrade to access_denied. "
                              "WCT 2s timeout surfaces rpc_usage: "
                              "{error: wct_timeout} per slice doc "
                              "§Edge cases.",
                "key_args": "pid, fields, filter, include_*",
                "example": "memory_manage(action='threads', pid=1234, "
                           "include_impersonation=True, "
                           "include_pending_irp=True)"},
    "obj_enum": {"one_liner": "MOVED → object_manage(action='enum'). "
                              "kernel object-directory enumeration "
                              "(\\Device, \\Driver, ...)",
                 "key_args": "path",
                 "example": "memory_manage(action='obj_enum', "
                            "path='\\\\Driver')"},
    "resolve_range": {"one_liner": "scan a range, resolve every "
                                   "pointer-looking qword to "
                                   "module!sym+off (dps-style)",
                      "key_args": "address|base, size (<=1 MiB), space, "
                                  "pid, filter ('ptr' default, 'all' "
                                  "dumps everything), include_ascii "
                                  "(=include zeros), resolve_symbols",
                      "example": "memory_manage(action='resolve_range', "
                                 "space='kernel', address='0x...', "
                                 "size=0x200)"},
    "dps": {"one_liner": "alias for resolve_range",
            "key_args": "address|base, size (<=1 MiB), space, pid, "
                        "filter, include_ascii, resolve_symbols",
            "example": "memory_manage(action='dps', space='kernel', "
                       "address='0x...', size=0x200)"},
    "dt": {"one_liner": "named-type read sugar — value='<TYPE>' "
                        "decodes at address via the PDB layout "
                        "(read decode={'type'} without the dict)",
           "key_args": "value (type name), address, module, space, "
                       "pid, size, decode (build_id / source / depth "
                       "keys)",
           "example": "memory_manage(action='dt', value='_KTRAP_FRAME', "
                      "module='ntoskrnl.exe', space='kernel', "
                      "address='0x...')"},
    "idt": {"one_liner": "MOVED → kernel_manage(action='idt'). "
                         "dump the IDT — handler VAs resolved to "
                         "module!sym+off with a `suspicious` flag on "
                         "off-allowlist handlers (needs ABI v12 "
                         "agent)",
            "key_args": "all_cpus (default current CPU only), "
                        "filter, fields, limit",
            "example": "memory_manage(action='idt')"},
    "hidden_proc": {"one_liner": "MOVED → process_manage(action='hidden'). "
                                 "SI #2 hidden-process detection "
                                 "(Wave 1: brute / registry / ETW) — "
                                 "runs each usermode PID oracle, "
                                 "cross-joins with NtQSI ground truth, "
                                 "returns one row per candidate PID "
                                 "with is_hidden + verdict (clean | "
                                 "unlinked_from_pslist | zombie | "
                                 "ghost_etw_owner | stale_registry) + "
                                 "confidence (0..1). CSRSS mode is "
                                 "Wave 2 and is accepted-and-dropped "
                                 "today",
                    "key_args": "kinds (modes list), size (pid_max), "
                                "count (step; default 4), timeout_s, "
                                "filter, limit, name",
                    "example": "memory_manage(action='hidden_proc', "
                               "kinds=['brute','etw'])"},
    "coherency": {"one_liner": "MOVED → module_manage(action='coherency'). "
                               "SI #1 image-coherency score — bytes "
                               "of a loaded module's in-memory image "
                               "matched against its on-disk file, "
                               "skipping relocs/IAT/CFG; returns a "
                               "0..1 score + mismatch ranges + "
                               "classification (clean|iat_hooked|"
                               "inline_hooked|section_overwritten|"
                               "relocs_unresolved|unknown)",
                  "key_args": "pid, module, value='quick'|'normal'|"
                              "'full' (mode), max_results (= "
                              "max_mismatch_ranges), include_ascii "
                              "(= include_mismatch_hex), name "
                              "('user' routes through umagent)",
                  "example": "memory_manage(action='coherency', pid=1234, "
                             "module='ntdll.dll', value='quick')"},
    "handle_dup": {"one_liner": "MOVED → object_manage(action='handle_dup'). "
                                "SI #6 duplicate a handle from another "
                                "process into the caller's handle table "
                                "via ObReferenceObjectByHandle + "
                                "ObOpenObjectByPointer under KernelMode "
                                "PreviousMode (SeAccessCheck bypassed — "
                                "lab-tool contract). Reusable with any "
                                "pid/handle pair that memory_manage(action="
                                "'handles') returns",
                   "key_args": "pid (src_pid), address (src_handle), "
                               "size (desired_access mask; 0 under "
                               "SAME_ACCESS), protect (options bitmask), "
                               "base (SI #24 PrivilegeCookie slot)",
                   "example": "memory_manage(action='handle_dup', pid=1234, "
                              "address='0x1a4', size=0x120089)"},
    "handle_close": {"one_liner": "MOVED → object_manage(action='handle_close'). "
                                  "SI #6 close a handle inside another "
                                  "process via KeStackAttachProcess + "
                                  "ObCloseHandle. Sensitive targets "
                                  "(PID 4 / System) are gated on the SI "
                                  "#24 PrivilegeCookie",
                     "key_args": "pid (target_pid), address "
                                 "(target_handle), base "
                                 "(PrivilegeCookie)",
                     "example": "memory_manage(action='handle_close', "
                                "pid=1234, address='0x1a4')"},
    "handle_compare": {"one_liner": "MOVED → object_manage(action='handle_compare'). "
                                    "SI #6 compare two handles for "
                                    "object pointer identity. Returns "
                                    "`same` plus each side's object VA + "
                                    "type-index — pair with memory_manage"
                                    "(action='handles') for name "
                                    "resolution",
                       "key_args": "pid (pid_a), address (handle_a), tid "
                                   "(pid_b), base (handle_b)",
                       "example": "memory_manage(action='handle_compare', "
                                  "pid=1234, address='0x1a4', tid=5678, "
                                  "base='0x1a4')"},
    "stack_walk": {"one_liner": "MOVED → thread_manage(action='stack'). "
                                "SI #9 kernel+user stack walk via "
                                "RtlWalkFrameChain, delivered through a "
                                "kernel-mode APC on the target thread "
                                "(PryRemoteCall). Frames carry "
                                "module_base so the orchestrator "
                                "resolves names via the existing "
                                "MODULES listing. Default timeout "
                                "bounded at 500 ms (sequential IOCTL "
                                "queue healthiness)",
                   "key_args": "tid, value='kernel'|'user'|'both' "
                               "(mode; default 'both'), max_results "
                               "(= max_frames; cap 128), timeout_s "
                               "(forwarded as timeout_ms), preempt_ok "
                               "(= force_apc), partial (= timeout "
                               "partial_ok)",
                   "example": "memory_manage(action='stack_walk', tid=1234, "
                              "value='both', max_results=64)"},
    # --- v16 Memory scanner wave 1: typed value_scan + next_scan ---
    "value_scan": {
        "one_liner": "typed first-scan over user/kernel memory — "
                     "snapshot every match of (value_type, op, value) "
                     "and keep it for next_scan refine. Region filter: "
                     "sections=/module=, writable/executable/cow/"
                     "include_guarded, mem_types=, scope=heap|stack|"
                     "image|all. v15 fallback runs orchestrator-RAM "
                     "today; v16 agent delegates to on-target ScanService "
                     "once scan_service_version flips to 1.",
        "key_args": "pid, value_type (int8..int64 / uint8..uint64 / "
                    "float / double / string / utf16), op "
                    "(eq|lt|gt|between|unknown), value, value_hi, "
                    "tolerance, endian (le|be), encoding, align, "
                    "address, size, sections, module, writable, "
                    "executable, cow, include_guarded, mem_types, "
                    "scope, max_results, confirm_full_space",
        "example": "memory_manage(action='value_scan', pid=1234, "
                   "value_type='int32', op='eq', value=100, "
                   "scope='heap', writable=True)"},
    "next_scan": {
        "one_liner": "refine a value_scan snapshot — re-read every "
                     "stored VA and keep rows where the new sample "
                     "satisfies op against the prev sample (changed / "
                     "unchanged / increased / decreased / "
                     "increased_by=delta / decreased_by=delta) or "
                     "against value / value_hi (eq / lt / gt / "
                     "between). Pushes the prior snapshot onto the "
                     "scan's undo stack (depth 4).",
        "key_args": "scan_id, op, value, value_hi, delta, tolerance",
        "example": "memory_manage(action='next_scan', scan_id='v0001', "
                   "op='decreased')"},
    "scan_undo": {
        "one_liner": "pop one frame off a value scan's undo stack "
                     "(undoes one next_scan). Depth 4 per scan — "
                     "beyond that the oldest frame is dropped.",
        "key_args": "scan_id",
        "example": "memory_manage(action='scan_undo', scan_id='v0001')"},
    "scan_destroy": {
        "one_liner": "free a value scan's snapshot + undo stack (and, "
                     "for an on-target v16 scan, its agent-side state + "
                     "disk spill). Pattern scans finish on their own "
                     "and don't need this.",
        "key_args": "scan_id",
        "example": "memory_manage(action='scan_destroy', "
                   "scan_id='v0001')"},
    # --- v17 Memory scanner wave 2: pointer map + reverse scan + diff ---
    "pointer_map_create": {
        "one_liner": "scan a target process for every aligned pointer; "
                     "snapshot (source_va -> target_va) on target + "
                     "disk mirror under <agent_dir>\\pointer_maps\\. "
                     "Immutable after create (rescan + diff is the "
                     "workflow). Refuses with kind='needs_v17' on "
                     "pre-v17 agents.",
        "key_args": "pid, scope (image|heap|stack|all), sections, "
                    "writable, executable, include_guarded, mem_types, "
                    "max_candidates, disk_spill_mode",
        "example": "memory_manage(action='pointer_map_create', "
                   "pid=1234, scope='all', writable=True)"},
    "pointer_map_status": {
        "one_liner": "poll in-flight map scan progress.",
        "key_args": "map_id",
        "example": "memory_manage(action='pointer_map_status', "
                   "map_id='pm0017_0001')"},
    "pointer_map_list": {
        "one_liner": "list live pointer maps on this view.",
        "key_args": "(none)",
        "example": "memory_manage(action='pointer_map_list')"},
    "pointer_map_cancel": {
        "one_liner": "cancel an in-flight map scan (observed per-chunk).",
        "key_args": "map_id",
        "example": "memory_manage(action='pointer_map_cancel', "
                   "map_id='pm0017_0001')"},
    "pointer_map_save": {
        "one_liner": "copy a map's on-disk mirror to `remote_path` on "
                     "the target. The live map_id stays usable.",
        "key_args": "map_id, remote_path",
        "example": "memory_manage(action='pointer_map_save', "
                   "map_id='pm0017_0001', "
                   "remote_path='D:/maps/explorer_pre')"},
    "pointer_map_load": {
        "one_liner": "mmap a previously-saved map, restore it to the "
                     "registry.",
        "key_args": "remote_path, map_id (optional; minted when empty)",
        "example": "memory_manage(action='pointer_map_load', "
                   "remote_path='D:/maps/explorer_pre')"},
    "pointer_map_destroy": {
        "one_liner": "unmap + free registry entry. keep_disk=True "
                     "leaves the on-disk mirror in place.",
        "key_args": "map_id, keep_disk",
        "example": "memory_manage(action='pointer_map_destroy', "
                   "map_id='pm0017_0001')"},
    "pointer_scan": {
        "one_liner": "reverse-BFS a pointer map for chains anchored on "
                     "image sections (static) or heap/stack/other "
                     "(dynamic). Chain sort: (depth asc, anchor_va "
                     "asc, offsets asc). Hard caps per plan §2.7 "
                     "(max_depth, max_offset, max_results, "
                     "fanout_per_level, wall_ms). Each chain's "
                     "anchor_va is decorated with 'module!Symbol+disp' "
                     "under 'anchor_sym' when a PDB is cached "
                     "(decorate=True, default — pass decorate=False to "
                     "skip the lookup pass).",
        "key_args": "map_id, target_va, max_depth, max_offset, "
                    "static_only, max_results, fanout_per_level, "
                    "wall_ms, decorate",
        "example": "memory_manage(action='pointer_scan', "
                   "map_id='pm0017_0001', target_va='0x7ff89b162000', "
                   "max_depth=3, static_only=True)"},
    "pointer_map_diff": {
        "one_liner": "diff two maps (same pid, possibly across a "
                     "reboot). Canonical identity is "
                     "'<basename>!<offset>' via each map's stored "
                     "module snapshot. Optional chains= filter narrows "
                     "the diff to chains that still resolve in map B.",
        "key_args": "map_id (A), map_id_b (B), static_only, chains",
        "example": "memory_manage(action='pointer_map_diff', "
                   "map_id='pm_a', map_id_b='pm_b', static_only=True)"},
    "dissect": {
        "one_liner": "one-shot per-slot typed decode of a memory "
                     "window — every aligned slot reports u64/i32/u32/"
                     "f32/f64 + ascii/utf16 prefix + probable_type "
                     "(pointer > utf16 > ascii > f64 > f32 > i32). "
                     "v16 agents fall back to the orchestrator-side "
                     "glue (one read + python decode). Slots whose "
                     "ptr_module is set are decorated with "
                     "'module!Symbol+disp' under 'ptr_sym' when a PDB "
                     "is cached (decorate=True, default — pass "
                     "decorate=False to skip the lookup pass).",
        "key_args": "pid, address, size (max 65536), space, "
                    "with_modules, decode, align (4 or 8), decorate",
        "example": "memory_manage(action='dissect', pid=1234, "
                   "address='0x7ff00000', size=256, align=8, "
                   "with_modules=True)"},
    "dissect_compare": {
        "one_liner": "multi-instance structure compare — decode N "
                     "candidate base VAs of 'same struct' and classify "
                     "each aligned offset (stable, per_instance_ptr, "
                     "per_instance_scalar, shared_pointer, noisy, "
                     "unreadable, inconclusive). Shared_pointer offsets "
                     "carry the resolved 'module!Symbol+disp' under "
                     "'shared_target' when a PDB is cached (decorate="
                     "True, default). Caps: 32 instances, window <= "
                     "65536, min_instances_for_class defaults to 3 "
                     "below which every offset is 'inconclusive'. "
                     "Requires dissect_version >= 2 (Wave 3 P1).",
        "key_args": "pid, base_vas, window_size, align, space, "
                    "with_modules, shared_ptr_min_vote, "
                    "min_instances_for_class, decorate",
        "example": "memory_manage(action='dissect_compare', pid=1234, "
                   "base_vas=[0x7ff00000, 0x7ff10000, 0x7ff20000], "
                   "window_size=256, align=8)"},
    "heap_attrib": {
        "one_liner": "batched VA -> heap allocation attribution. "
                     "Returns one record per input VA with "
                     "{heap_handle, segment_base, chunk_base, "
                     "chunk_size, flags, size_class} and tracks a "
                     "per-pid LRU of interval-tree indices on the "
                     "agent (TTL 2s, committed-sum delta probe > "
                     "max(1 MiB, 1%), explicit refresh=True bypass). "
                     "Gated on memory_heap_attrib_version>=1 — the "
                     "handler lives on the kernel-agent view; the "
                     "umagent view refuses with "
                     "kind='feature_unavailable'.",
        "key_args": "pid, va (scalar) or vas=[int, ...] (batch, cap "
                    "4096), refresh",
        "example": "memory_manage(action='heap_attrib', pid=1234, "
                   "vas=[0x7ff60000, 0x7ff60080], refresh=False)"},
}
