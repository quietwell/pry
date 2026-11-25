"""Pydantic argument schema for the ``memory_manage`` tool.

Lifted verbatim out of ``mem.py``'s ``register()`` closure in Phase R5
so the dispatcher stays under the 700-line cap. ``MemArgs`` documents
the full ``memory_manage`` surface; FastMCP's live schema generation reads the
``memory_manage`` async signature directly, so this class is here as the
canonical shape for tests and future refactors.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from . import _MEMORY_ACTIONS_MASTER


class MemArgs(BaseModel):
    action: str = Field(description="|".join(_MEMORY_ACTIONS_MASTER))
    pid: int = 0
    address: int | str = Field(default=0,
                               description="int, '0x...' hex, or "
                                           "'module+offset'")
    size: int = 0
    data_hex: str = Field(default="", description="write payload as hex")
    space: str = Field(default="user",
                       description="user|kernel|physical; kernel=true is "
                                   "a legacy alias")
    protect: int = 0
    kernel: bool = False
    pattern_hex: str = ""
    mask: str = ""
    pattern: str = Field(default="", description="IDA-style pattern "
                                                 "'4D 5A ?? 90'")
    base: int | str = Field(default=0,
                            description="pattern_scan start (alias for "
                                        "address)")
    max_results: int = 64
    want_names: bool = Field(default=False, description="handles: resolve "
                                                        "object names "
                                                        "(slow)")
    module: str = Field(default="", description="imports/exports: module "
                                                "basename or full path")
    sections: str = Field(default="",
                          description="pattern_scan/scan_start: PE "
                                      "section names to scan")
    filter: Any = Field(default="", description="row filter — name "
                                                "substring or "
                                                "{field: value} dict")
    name_regex: str = Field(default="",
                            description="modules: case-insensitive name "
                                        "regex")
    name_glob: str = Field(default="",
                           description="modules: case-insensitive name "
                                       "glob")
    path_contains: str = Field(default="",
                               description="modules: substring on the "
                                           "full path")
    compact: bool = Field(default=False,
                          description="modules: name/base/size only")
    summary: bool = Field(default=False,
                          description="list verbs: compact summary "
                                      "block")
    fields: list[str] = Field(default_factory=list,
                              description="server-side row projection")
    value: str = Field(default="", description="resolve: module+offset "
                                               "or absolute VA; dt: "
                                               "type name")
    # --- Phase 1 codegen: disasm / assemble ---
    bytes_hex: str = Field(default="",
                           description="disasm: raw hex buffer (no "
                                       "target contact)")
    arch: str = Field(default="x64",
                      description="disasm/assemble: x64|x86")
    syntax: str = Field(default="intel",
                        description="disasm: intel|att")
    count: int = Field(default=64,
                       description="disasm: max instructions")
    detail: bool = Field(default=False,
                         description="disasm: attach cs.detail (legacy "
                                     "bool); read/scan/inventory verbs: "
                                     "'complete' (default) or 'summary' "
                                     "evidence detail")
    resolve_symbols: bool = Field(default=False,
                                  description="disasm: annotate operands "
                                              "as module+offset")
    code: str = Field(default="",
                      description="assemble: source (labels allowed)")
    write_to: int | str = Field(default=0,
                                description="assemble: write bytes at "
                                            "this VA (needs "
                                            "dry_run=false)")
    dry_run: bool = Field(default=True,
                          description="assemble: refuse write unless "
                                      "false")
    want_blocks: bool = Field(default=False,
                              description="heaps: per-block detail")
    max_blocks: int = Field(default=0, description="heaps: per-heap block "
                                                   "cap")
    allow_fault: bool = Field(default=False,
                              description="kernel read: permit driver "
                                          "soft-fault of non-resident "
                                          "pages — keep OFF for blind "
                                          "probing")
    allow_map_write: bool = Field(default=False,
                                  description="physical write: opt into "
                                              "the MmMapIoSpaceEx path")
    allow_mmio: bool = Field(default=False,
                             description="physical read: opt into out-of-"
                                         "RAM reads (MMIO / firmware ROM). "
                                         "Default-deny — the driver "
                                         "refuses with kind='mmio_blocked'. "
                                         "WARNING: PCI device MMIO can "
                                         "wedge the box; prefer the hv "
                                         "UC-alias path for device "
                                         "inspection.")
    partial: bool = Field(default=False,
                          description="kernel read: per-4KB partial "
                                      "walk (stop at first hole)")
    timeout_s: float = Field(default=0.0,
                             description="per-call gRPC timeout (s)")
    scan_id: str = Field(default="",
                         description="scan job id from scan_start")
    verify: bool = Field(default=False,
                         description="write: atomic write-then-readback")
    decode: Any = Field(default=None,
                        description="read: typed decode — 'u64[4]' "
                                    "shorthand or {'type','module'}")
    reads: list[dict] | None = Field(default=None,
                                     description="read: batch "
                                                 "{va,size,decode?} "
                                                 "list")
    include_ascii: bool = Field(default=False,
                                description="read+decode: also emit the "
                                            "ASCII preview")
    from_va: int | str = Field(default=0,
                               description="read+space=physical: VA to "
                                           "translate first")
    resolve_physical: bool = Field(default=False,
                                   description="read: VA->PA->physical "
                                               "shortcut")
    name: str = Field(default="", description="target view: kernel|user "
                                              "(empty = your focused "
                                              "machine's kernel view; "
                                              "'<machine>.<kind>' for a "
                                              "specific view)")
    # --- follow_chain ---
    offsets: list[int] | None = Field(
        default=None,
        description="follow_chain: hop offsets added before each "
                    "deref (last hop stops before the final deref "
                    "and reads terminal_size bytes instead)")
    # --- leak_scan ---
    needles: list[str] | None = Field(
        default=None,
        description="leak_scan: byte needles — raw ASCII, or "
                    "'hex:4D5A...' prefix for binary strings")
    scopes: list[str] | None = Field(
        default=None,
        description="leak_scan: scopes to sweep. Any of "
                    "'kernel_pool', 'module_data', 'per_process'; "
                    "default = ['kernel_pool','module_data']")
    terminal_size: int = Field(
        default=0,
        description="follow_chain: bytes to read at the chain tail "
                    "(0 skips the terminal read)")
    expect_ascii: bool = Field(
        default=False,
        description="follow_chain: fail-fast if the terminal read is "
                    "not printable ASCII")
    expect_nonzero: bool = Field(
        default=False,
        description="follow_chain: fail-fast if any hop deref is 0")
    expect_module: str = Field(
        default="",
        description="follow_chain: fail-fast if the terminal pointer "
                    "falls outside this module's VA range")
    # --- signer / Authenticode column ---
    verify_signatures: bool = Field(
        default=False,
        description="modules: attach signer / signing_level / "
                    "is_signed / catalog / signer_cache_hit columns via "
                    "a batched WinVerifyTrust probe. Off by default — "
                    "the default modules response is bit-identical to "
                    "the original shape (do-not-break matrix §7).")
    force_recheck: bool = Field(
        default=False,
        description="modules + verify_signatures: bypass the agent's "
                    "signer LRU cache and run a fresh WinVerifyTrust "
                    "probe on every path.")
    # ---- HW-watch (append-only) ----
    mode: str = Field(
        default="poll",
        description="watch: 'poll' (orchestrator-side polling; default) "
                    "or 'hw' (driver-managed DR0..DR3 slot, DRIVER ABI v14+)")
    access: str = Field(
        default="write",
        description="watch(mode='hw'): DR access filter — "
                    "'write' | 'rw' (reads alone aren't observable on x86)")
    tid: int = Field(
        default=0,
        description="watch(mode='hw'): tid filter — 0 arms every thread "
                    "of the pid (incl. threads created later)")
    slot: int = Field(
        default=0xFF,
        description="watch(mode='hw'): DR slot 0..3; 0xFF (default) "
                    "lets the driver pick a free slot per (pid, tid)")
    preempt_ok: bool = Field(
        default=False,
        description="watch(mode='hw'): when every DR slot is in use, "
                    "preempt the oldest existing watch (never a plain "
                    "bp_manage breakpoint). Default = fail with "
                    "device-busy instead")
