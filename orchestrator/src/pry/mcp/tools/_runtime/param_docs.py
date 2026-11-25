"""Param descriptions + schema overrides for the published tool schemas.

:func:`surface.finalize_surface` writes these into each tool's
``inputSchema`` so an agent reading ``tools/list`` sees what an
overloaded or loosely typed param means without a help round trip.

Precedence for a ``(tool, param)`` description:

1. :data:`OVERLOADED` - curated text for params whose meaning changes per
   verb (the case that most needs explaining);
2. :data:`HARVESTED` - the per-param ``Field(description=...)`` text the
   per-tool pydantic arg models carried (version markers stripped);
3. :data:`COMMON` - params that mean the same thing on every tool, keyed
   by param name, unless the tool is listed in :data:`NAME_IS_NOT_VIEW`.

Only params that need a word get one; the shared paging/shaping params
(limit, offset, fields, filter, summary, verbosity) are explained once
in the server instructions.

Schema overrides (:data:`TYPED`) replace the ``{}`` schema pydantic
emits for ``Any`` params with the real union. FastMCP validates calls
against the Python signature, so these never narrow what is accepted.
"""

from __future__ import annotations

from typing import Any

# Generated once from the per-tool pydantic arg models (MemArgs, EmuArgs,
# FileArgs, ...); edit here, those models are gone.
HARVESTED: dict[str, dict[str, str]] = {'bp_manage': {'address': "int, hex string ('0x140018078'), module+offset "
                          "('ntoskrnl.exe+0x1234'), or module!export "
                          "('user32.dll!GetMessageW')",
               'commands': 'SW: dbgeng command list run every hit',
               'condition': "SW: dbgeng expression (`j (…) 'gc'; 'gc'` on "
                            'hit) — target stays running unless the '
                            'expression is true',
               'dangerous_ok': 'HW: bypass the PatchGuard refusal (lab only)',
               'force': 'ownership: override a foreign-owner refusal',
               'global_': 'HW: system-wide bp, ignores pid (driver cap 2)',
               'hit_count': 'SW: pass_count — ignore the first (N-1) hits, '
                            'break on the Nth',
               'kernel_target': 'display hint only — HW BPs are always '
                                'driver-backed',
               'kind': 'sw|hw',
               'one_shot': 'SW: auto-remove the bp after its first break',
               'tid': 'HW: engine tid filter. SW: match_tid — break only '
                      'when the hitting thread matches this engine tid.'},
 'debug_manage': {'address': "int, '0x...' hex, or 'module+offset'",
                  'command': 'cmd: raw dbgeng command',
                  'exception_action': "exception: 'break' | 'ignore' | "
                                      "'second_chance'",
                  'exception_code': 'exception: exception NTSTATUS '
                                    '(0xC0000005 etc.)',
                  'force': 'mutating actions: override a foreign-owner debug '
                           'lease',
                  'from_seq': 'events: replay from sequence number',
                  'image': 'attach: process image name (pid resolved)',
                  'kind': "dump: 'mini' | 'full'",
                  'monitor': 'launch/attach: auto-resume bp / exception hits '
                             'instead of parking the target',
                  'path': 'dump: output file path on the target',
                  'symbol': "resolve: 'module!name' or 'module+0xN'",
                  'tid': 'regs / set_regs / stacktrace: target thread id (0 '
                         '= current)',
                  'timeout_s': 'run/wait/pause/run_to/step_out: cap 30s, '
                               'default 20s on 0',
                  'wait_s': 'attach: wait seconds for the pid lease before '
                            "kind='busy'"},
 'dump_manage': {'allow_cancel': 'create_kernel_dump: register a cancel '
                                 'event with SysDbg so a client disconnect '
                                 'can cancel',
                 'assume_fresh': 'resolve even on stale-boot dumps (opt-in — '
                                 'wrong bases)',
                 'compression': 'create_kernel_dump: convenience alias for '
                                "dump_flags=['compression'] — ORs in "
                                'SYSDBG_LIVEDUMP_FLAG_COMPRESS_MEMORY_PAGES_DATA',
                 'count': 'stack: max frames returned (of frames_total)',
                 'detail': "parse/stack: 'complete' (default) delivers the "
                           'full payload inline (still retained under '
                           "artifacts/evidence/); 'summary' returns counts + "
                           'provenance + coverage only and pages the full '
                           'record back via...',
                 'dump_flags': 'process_snapshot: MINIDUMP_TYPE flag names '
                               "(e.g. ['WithFullMemory','WithThreadInfo']). "
                               'Empty uses WithFullMemory | WithThreadInfo | '
                               'WithHandleData | WithUnloadedModules | '
                               'WithFullMemoryInfo | WithTokenInformation.',
                 'output_path': 'process_snapshot: absolute Win32 path for '
                                'the written .dmp; empty uses '
                                '%TEMP%\\pry\\dumps\\pid_<pid>_<unix-ms>.dmp',
                 'path': 'parse: orchestrator-local or artifacts-relative '
                         '.dmp path',
                 'pid': 'process_snapshot: target pid (>0; dumping the '
                        'agent/umagent itself is refused as self_pid)',
                 'remote_path': 'parse: target-side .dmp path — pulled into '
                                'artifacts/dumps first',
                 'resolve': 'resolve pointers to module!sym+off (same-boot '
                            'dumps only)',
                 'sha256': 'parse: artifact-store sha256 (prefix ok)',
                 'use_snapshot': 'process_snapshot: true runs '
                                 'PssCaptureSnapshot first (consistent '
                                 'cross-thread view); false invokes '
                                 'MiniDumpWriteDump directly'},
 'emulate_manage': {'address': 'mem_read/mem_write/map: VA',
                    'api': "hook_add(api): 'kernel32!VirtualAlloc'",
                    'arch': 'x64|x86',
                    'bytes_hex': 'load_shellcode: raw hex buffer',
                    'cmdline': 'load_pe: command line',
                    'code': 'load_shellcode: assembly source (auto-assembled '
                            'via keystone)',
                    'engine': 'speakeasy|unicorn',
                    'entry': 'load_shellcode: base VA (default '
                             'engine-picked)',
                    'flavor': 'speakeasy OS build flavor (default|latest)',
                    'hook_action': 'hook_add: log|skip|return',
                    'hook_id': 'hook_remove',
                    'image_base': 'load_pe: preferred image base',
                    'include_ext': 'regs: include xmm/ymm (currently '
                                   'ignored)',
                    'kind': 'hook_add: api|addr',
                    'label': 'map/snapshot: cosmetic tag',
                    'max_ins': 'run: instruction cap',
                    'mode': 'shellcode|pe|module',
                    'n': 'step: number of instructions',
                    'on': 'hook_add: pre|post',
                    'path': 'load_pe or load_shellcode: local file path '
                            '(orchestrator side)',
                    'pid': 'seed_from_target: target pid',
                    'prot': 'map: r/w/x combo (default rwx)',
                    'regions_json': 'seed_from_target: JSON list of '
                                    '{address, size, label}',
                    'regs_json': 'set_regs: JSON object (\'{"rax": 1, "rcx": '
                                 '"0x1000"}\')',
                    'return_value': 'hook_add(action=return): value to '
                                    'return',
                    'session_id': 'from `create`',
                    'size': 'mem_read/map: byte count',
                    'snap_id': 'restore',
                    'target': 'seed_from_target: session view to read from '
                              '(defaults to `view`)',
                    'tid': 'seed_from_target: target tid',
                    'timeout_s': 'run: wall-clock cap',
                    'until': 'run: halt at this VA',
                    'view': 'seed_from_target: user|kernel view'},
 'exec_manage': {'address': "call: function VA — int, '0x…', 'module+offset' "
                            "or 'module!export'",
                 'background': 'run via run_detached, return handle_id',
                 'call_args': 'call: up to 16 fixed64 args (ms64 order)',
                 'force': 'override foreign_owned on shell/detached handles; '
                          'kernel call: skip module-range checks',
                 'handle_id': 'detached_*: the handle from run_detached',
                 'kill_on_timeout': 'call: on user-space timeout, '
                                    'TerminateThread the injected thread + '
                                    'free the page',
                 'local_path': 'run_script: local script to upload+run',
                 'log_path': 'run_detached: stdout+stderr sugar + unbuffer '
                             'env',
                 'script': 'run_script: inline script text',
                 'script_b64': 'base64 UTF-16LE script (decoded server-side)',
                 'shell': 'start_shell/run_script: cmd|powershell|python — '
                          'empty auto-detects',
                 'space': "call: 'user' | 'kernel'",
                 'stderr_path': 'run_detached: redirect stderr',
                 'stdout_path': 'run_detached: redirect stdout',
                 'tail_bytes': 'detached_tail: bytes of log end',
                 'timeout_s': 'orchestrator-side call deadline (s)'},
 'file_manage': {'bytes': 'tail: bytes from the file end',
                 'context': 'grep_artifact: context lines per match',
                 'decode': 'read: typed decode spec (same as memory_manage '
                           'read)',
                 'dump_type': 'dump_module: as_loaded | unrelocated',
                 'duration_s': 'follow_start: stream lifetime (cap 3600)',
                 'follow_id': 'follow_poll/stop: the id from follow_start',
                 'follow_rotation': 'follow_start: reopen on size shrink',
                 'from_offset': 'follow_start: 0 = backfill tail, -1 = start '
                                'at EOF',
                 'from_seq': 'follow_poll: drain chunks since this seq',
                 'initial_tail_bytes': 'follow_start: EOF backfill bytes',
                 'kernel': 'dump_module: kernel module via '
                           'PsLoadedModuleList (driver required)',
                 'length': 'read/read_artifact: bytes to read (0=to EOF, cap '
                           '4 MiB)',
                 'line_align': 'tail/follow_*: skip partial first line',
                 'max_bytes': 'follow_start: 0 = unlimited within duration_s',
                 'max_chunk_bytes': 'follow_start: max bytes per chunk',
                 'max_matches': 'grep_artifact: match cap',
                 'offset': 'read/read_artifact: byte offset',
                 'page': 'read_artifact: page index for .jsonl artifacts',
                 'page_size': 'read_artifact: rows per page for .jsonl (max '
                              '1000)',
                 'pattern': 'grep_artifact: Python regex',
                 'poll_interval_ms': 'follow_start: agent poll interval '
                                     '(floor 10 ms)',
                 'quiesce': 'dump_module: suspend target for a consistent '
                            'image',
                 'ring_cap': 'follow_start: chunks buffered per follow_id',
                 'rule': 'yara: inline rule source',
                 'rule_path': 'yara: local rule file path',
                 'sha256': 'read_artifact: sha256 of the spilled artifact',
                 'side': "read: 'target'|'orchestrator'",
                 'view': "read: '' uses cfg.file_manage_default_view "
                         "(defaults to 'auto'). 'auto'=text when the data "
                         "sniffs as text, else hex; 'text'=force text "
                         "(not_text on binary); 'hex'=hex only; "
                         "'both'=hex+ascii+text (pre-PR#1 shape);..."},
 'memory_manage': {'access': "watch(mode='hw'): DR access filter — 'write' | "
                             "'rw' (reads alone aren't observable on x86)",
                   'address': "int, '0x...' hex, or 'module+offset'",
                   'allow_fault': 'kernel read: permit driver soft-fault of '
                                  'non-resident pages — keep OFF for blind '
                                  'probing',
                   'allow_map_write': 'physical write: opt into the '
                                      'MmMapIoSpaceEx path',
                   'allow_mmio': 'physical read: opt into out-of-RAM reads '
                                 '(MMIO / firmware ROM). Default-deny — the '
                                 "driver refuses with kind='mmio_blocked'. "
                                 'WARNING: PCI device MMIO can wedge the '
                                 'box; prefer the hv UC-alias path for '
                                 'device inspection.',
                   'arch': 'disasm/assemble: x64|x86',
                   'base': 'pattern_scan start (alias for address)',
                   'bytes_hex': 'disasm: raw hex buffer (no target contact)',
                   'code': 'assemble: source (labels allowed)',
                   'compact': 'modules: name/base/size only',
                   'count': 'disasm: max instructions',
                   'data_hex': 'write payload as hex',
                   'decode': "read: typed decode — 'u64[4]' shorthand or "
                             "{'type','module'}",
                   'detail': 'disasm: attach cs.detail (legacy bool); '
                             "read/scan/inventory verbs: 'complete' "
                             "(default) or 'summary' evidence detail",
                   'dry_run': 'assemble: refuse write unless false',
                   'expect_ascii': 'follow_chain: fail-fast if the terminal '
                                   'read is not printable ASCII',
                   'expect_module': 'follow_chain: fail-fast if the terminal '
                                    "pointer falls outside this module's VA "
                                    'range',
                   'expect_nonzero': 'follow_chain: fail-fast if any hop '
                                     'deref is 0',
                   'fields': 'server-side row projection',
                   'filter': 'row filter — name substring or {field: value} '
                             'dict',
                   'force_recheck': 'modules + verify_signatures: bypass the '
                                    "agent's signer LRU cache and run a "
                                    'fresh WinVerifyTrust probe on every '
                                    'path.',
                   'from_va': 'read+space=physical: VA to translate first',
                   'include_ascii': 'read+decode: also emit the ASCII '
                                    'preview',
                   'max_blocks': 'heaps: per-heap block cap',
                   'mode': "watch: 'poll' (orchestrator-side polling; "
                           "default) or 'hw' (driver-managed DR0..DR3 slot, "
                           'DRIVER ABI v14+)',
                   'module': 'imports/exports: module basename or full path',
                   'name_glob': 'modules: case-insensitive name glob',
                   'name_regex': 'modules: case-insensitive name regex',
                   'needles': 'leak_scan: byte needles — raw ASCII, or '
                              "'hex:4D5A...' prefix for binary strings",
                   'offsets': 'follow_chain: hop offsets added before each '
                              'deref (last hop stops before the final deref '
                              'and reads terminal_size bytes instead)',
                   'partial': 'kernel read: per-4KB partial walk (stop at '
                              'first hole)',
                   'path_contains': 'modules: substring on the full path',
                   'pattern': "IDA-style pattern '4D 5A ?? 90'",
                   'preempt_ok': "watch(mode='hw'): when every DR slot is in "
                                 'use, preempt the oldest existing watch '
                                 '(never a plain bp_manage breakpoint). '
                                 'Default = fail with device-busy instead',
                   'reads': 'read: batch {va,size,decode?} list',
                   'resolve_physical': 'read: VA->PA->physical shortcut',
                   'resolve_symbols': 'disasm: annotate operands as '
                                      'module+offset',
                   'scan_id': 'scan job id from scan_start',
                   'scopes': 'leak_scan: scopes to sweep. Any of '
                             "'kernel_pool', 'module_data', 'per_process'; "
                             "default = ['kernel_pool','module_data']",
                   'sections': 'pattern_scan/scan_start: PE section names to '
                               'scan',
                   'slot': "watch(mode='hw'): DR slot 0..3; 0xFF (default) "
                           'lets the driver pick a free slot per (pid, tid)',
                   'space': 'user|kernel|physical; kernel=true is a legacy '
                            'alias',
                   'summary': 'list verbs: compact summary block',
                   'syntax': 'disasm: intel|att',
                   'terminal_size': 'follow_chain: bytes to read at the '
                                    'chain tail (0 skips the terminal read)',
                   'tid': "watch(mode='hw'): tid filter — 0 arms every "
                          'thread of the pid (incl. threads created later)',
                   'timeout_s': 'per-call gRPC timeout (s)',
                   'value': 'resolve: module+offset or absolute VA; dt: type '
                            'name',
                   'verify': 'write: atomic write-then-readback',
                   'verify_signatures': 'modules: attach signer / '
                                        'signing_level / is_signed / catalog '
                                        '/ signer_cache_hit columns via a '
                                        'batched WinVerifyTrust probe. Off '
                                        'by default — the default modules '
                                        'response is bit-identical to '
                                        'pre-shape (do-not-break...',
                   'want_blocks': 'heaps: per-block detail',
                   'want_names': 'handles: resolve object names (slow)',
                   'write_to': 'assemble: write bytes at this VA (needs '
                               'dry_run=false)'},
 'script_manage': {'params_json': 'params, validated against plugin.yaml'}}

COMMON: dict[str, str] = {
    "name": "view '<machine>.<kind>' or '<machine>'; '' = focus machine",
    "space": "'user' | 'kernel' | 'physical'",
    "address": "int, '0x...' hex, 'module+offset' or 'module!export'",
    "force": "override the machine-trust gate on actuator verbs",
}

# Tools whose ``name`` param is not the target view.
NAME_IS_NOT_VIEW: dict[str, str] = {
    "script_manage": "plugin directory name (plugins/<name>)",
    "ida_manage": "IDA session name (from open; defaults to the binary name)",
    "ghidra_manage": "Ghidra program/session name (from open)",
    "symbols_manage": ("symbol name for resolve ('module!sym' or bare "
                       "with module=); the target view is view="),
    "machines_manage": "machine name (same as machine=)",
}

OVERLOADED: dict[str, dict[str, str]] = {
    "memory_manage": {
        "value": ("write/value_scan: the value; resolve: module+offset or "
                  "VA; dt: type name; walk_list: next-pointer offset "
                  "(prefer next_offset=)"),
        "count": ("disasm: max instructions; read_qwords: qword count; "
                  "walk_list: max nodes (prefer max_hops=)"),
        "module": ("module basename for module-relative verbs; watch_stop: "
                   "watch id (prefer watch_id=)"),
        "filter": ("row filter (substring or {field: substring}); watch: "
                   "tag (prefer tag=); resolve_range/dps: also selects "
                   "the row kind"),
        "timeout_s": ("per-call agent timeout in seconds; watch: poll "
                      "interval (prefer interval_s=)"),
        "max_results": ("row cap for scans/lists; watch: event cap and "
                        "duration (prefer max_events=)"),
        "size": "bytes to read/scan; walk_list: bytes decoded per node",
        "base": "scan start (alias for address); heap_info: heap base",
        "include_ascii": ("read+decode: also emit the ASCII preview "
                          "(also adds ASCII mirrors to the envelope)"),
        "want_blocks": "heaps/heap_info: include per-block detail",
    },
    "kernel_manage": {
        "module": ("pool_scan: pool tag (prefer tag=); struct_read: "
                   "module that owns type_name"),
        "protect": ("pool_scan: content offset into each allocation "
                    "(prefer content_offset=)"),
        "size": "pool_scan: content window bytes (required with pattern)",
        "pattern": "pool_scan: IDA-style hex pattern '48 8B ?? 05' (bytes, not text)",
        "name": COMMON["name"],
    },
    "desktop_manage": {
        "mode": ("click: 'click' (default) | 'down' | 'up' - press or "
                 "release only; the mouse button is button="),
    },
    "target_manage": {
        "samples": ("recent_ops/timeline: row cap; parity: number of "
                    "sampled reads"),
    },
    "value_manage": {
        "to_type": "cast: target type; hash: algorithm (md5|sha1|sha256|...)",
        "from_type": "cast/pack/unpack: source type (e.g. 'u64', 'f32')",
        "value": "the input value: int, float, hex string or text",
    },
    "file_manage": {
        "path": ("remote path; list_artifacts: kind/extension filter; "
                 "read side='orchestrator': artifact path"),
        "sha256": "artifact id; list_artifacts: sha256 prefix filter",
    },
    "svc_manage": {
        "service": "get/dependencies: SCM service short name (e.g. 'Spooler')",
    },
    "bp_manage": {
        "global_": "hw: system-wide breakpoint, ignores pid (driver cap 2)",
        "slot": ("hw: debug-register slot 0-3, or 255 = auto (default); an "
                 "explicit slot already in use returns busy"),
    },
    "reconstruct_manage": {
        "sha256": "original: artifact sha256 (as bin_manage)",
        "path": "original: artifacts-relative PE path (as bin_manage)",
        "source": "original: 'artifact' (default) | 'memory' (live image)",
        "module": "original, source='memory': module name to read",
        "pid": "original, source='memory': process id",
        "address": "original, source='memory': image base",
        "size": "original, source='memory': bytes to read",
        "space": "original, source='memory': 'user' | 'kernel'",
        "kernel": "original, source='memory': kernel module",
        "layout": "original: 'auto' | 'file' | 'image'",
        "func": "original's function: VA, 'module+0xRVA' or export name",
        "build_id": "reconstruction: 16-hex id from compile",
        "export": "reconstruction: exported function to call",
        "code": "compile / verify: C source text of the reconstruction",
        "code_path": "compile / verify: artifacts-relative .c file",
        "exports": "compile: function names to export from the DLL",
        "toolchain": "compile: 'msvc' | 'clang-cl' (default from config)",
        "arch": "compile: 'x64' | 'x86'; call/verify: blob originals only",
        "options_json": ("advanced knobs: compile opt (Od|O1|O2), fp, "
                         "intrinsics, defines, x86_arch; run boundary, "
                         "probe, max_insns, inputs (guided|random)"),
        "signature_json": ("prototype {ret, params:[{name,type,...}], cc, "
                           "stubs, ignore} — see docs/RECONSTRUCT.md"),
        "args_json": "call: {param: value} for one run",
        "cases": ("verify: generated cases, coverage-guided unless "
                  "inputs='random' (default 256, max 10000)"),
        "seed": "verify: RNG seed — echoed; same seed, same cases",
        "cases_json": "verify: explicit cases [{param: value}, ...]",
        "cases_path": "verify: replay an inputs.jsonl under artifacts/",
        "timeout_s": "verify: wall-clock budget; past it the result is partial",
        "min_coverage": "verify: 0..1; lower original block coverage → inconclusive",
    },
}

_STR_OR_OBJ = {"anyOf": [{"type": "string"}, {"type": "object"}]}
_INT_OR_STR = {"anyOf": [{"type": "integer"}, {"type": "string"}]}
_NUM_OR_STR = {"anyOf": [{"type": "number"}, {"type": "string"}]}

# (tool or "*", param) -> schema for params declared ``Any``.
TYPED: dict[tuple[str, str], dict[str, Any]] = {
    ("*", "filter"): dict(_STR_OR_OBJ),
    ("*", "decode"): {"anyOf": [{"type": "string"}, {"type": "object"},
                                {"type": "array"}],
                      "description": ("typed decode: 'u64[4]' shorthand, "
                                      "{type, module} or a field list")},
    ("*", "align"): {**_INT_OR_STR,
                     "description": "scan alignment in bytes, or 'auto'"},
    ("*", "value_hi"): {**_NUM_OR_STR,
                        "description": "value_scan op='between': upper bound"},
    ("*", "delta"): {**_NUM_OR_STR,
                     "description": ("value_scan op='increased_by'/"
                                     "'decreased_by': the delta")},
    ("bin_manage", "address"): {**_INT_OR_STR,
                                "description": "VA/RVA (int or hex string)"},
    ("bin_manage", "target"): {**_INT_OR_STR,
                               "description": "xrefs/paths: target VA or symbol"},
    ("bin_manage", "func"): {**_INT_OR_STR,
                             "description": "function VA or name"},
    ("cpu_manage", "msr"): {**_INT_OR_STR,
                            "description": ("MSR index (int/hex) or a "
                                            "well-known name, e.g. 'IA32_EFER'")},
    ("cpu_manage", "leaf"): {**_INT_OR_STR,
                             "description": "CPUID leaf (int or hex string)"},
    ("device_manage", "code"): {**_INT_OR_STR,
                                "description": "IOCTL code (int or hex string)"},
    ("reconstruct_manage", "func"): {
        **_INT_OR_STR,
        "description": "function VA, 'module+0xRVA' or export name"},
    ("reconstruct_manage", "address"): {
        **_INT_OR_STR, "description": "source='memory': image base"},
    ("reconstruct_manage", "signature_json"): {
        **_STR_OR_OBJ, "description": "prototype {ret, params, cc, ...}"},
    ("reconstruct_manage", "args_json"): {
        **_STR_OR_OBJ, "description": "call: {param: value}"},
    ("reconstruct_manage", "options_json"): {
        **_STR_OR_OBJ, "description": ("{opt, fp, intrinsics, defines, "
                                       "x86_arch, boundary, probe, "
                                       "max_insns, inputs}")},
    ("reconstruct_manage", "cases_json"): {
        "anyOf": [{"type": "string"}, {"type": "array"}, {"type": "object"}],
        "description": "verify: explicit cases [{param: value}, ...]"},
}


# Shaping params every list verb shares; the server instructions explain
# them once, so a per-tool copy would only cost tokens.
SHARED_SHAPING = frozenset({"limit", "offset", "cursor", "fields", "filter",
                            "summary", "verbosity", "compact"})

_MAX_DESC = 110


def _cap(text: str) -> str:
    if len(text) <= _MAX_DESC:
        return text
    cut = text[: _MAX_DESC - 3]
    if " " in cut:
        cut = cut[: cut.rfind(" ")]
    return cut.rstrip(",;:") + "..."


def describe_param(tool: str, param: str) -> str:
    """Description for ``(tool, param)`` or ``''``."""
    d = OVERLOADED.get(tool, {}).get(param)
    if d:
        return d
    if param in SHARED_SHAPING:
        return ""
    d = HARVESTED.get(tool, {}).get(param)
    if d:
        return _cap(d)
    if param == "name":
        return NAME_IS_NOT_VIEW.get(tool, COMMON["name"])
    return COMMON.get(param, "")


def schema_override(tool: str, param: str, current: dict) -> dict | None:
    """A replacement schema for an untyped (``{}``) param, or ``None``."""
    if current and any(k in current for k in ("type", "anyOf", "enum",
                                               "$ref", "allOf", "oneOf")):
        return None
    spec = TYPED.get((tool, param)) or TYPED.get(("*", param))
    if spec is None:
        return None
    out = dict(spec)
    if "default" in current:
        out["default"] = current["default"]
    return out


__all__ = ["COMMON", "HARVESTED", "NAME_IS_NOT_VIEW", "OVERLOADED",
           "SHARED_SHAPING", "TYPED",
           "describe_param", "schema_override"]
