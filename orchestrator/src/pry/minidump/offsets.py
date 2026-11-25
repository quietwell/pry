"""Dump-file layout constants — DUMP_HEADER64, TRIAGE_DUMP64, SUMMARY_DUMP64.

Header offsets were pinned against the WDK-internal ``Dump.h`` (Microsoft
Research Singularity tree mirror) and cross-checked against volatility's
``_DMP_HEADER64`` listing and a Windows-10 dump hexdump. The notable
trap: the 700-byte ``PhysicalMemoryBlockBuffer`` sits inside a union
with the 8-byte-aligned ``PHYSICAL_MEMORY_DESCRIPTOR64``, so the union
is 704 bytes — ``ContextRecord`` lands at 0x348 (not 0x344) and
``EXCEPTION_RECORD64`` at 0xF00.
"""

from __future__ import annotations

PAGE_SIG = b"PAGE"
VALID_64 = b"DU64"
VALID_32 = b"DUMP"
MDMP_SIG = b"MDMP"

HEADER_SIZE_64 = 0x2000
PAGE_SIZE = 0x1000

# DUMP_HEADER64 offsets (x64) — see module docstring for provenance.
_OFF_DTB = 0x10
_OFF_PFN_DB = 0x18
_OFF_PSLML = 0x20
_OFF_PSAPH = 0x28
_OFF_MACHINE = 0x30
_OFF_NUMPROC = 0x34
_OFF_BUGCHECK = 0x38
_OFF_PARAMS = 0x40
_OFF_VERSION_USER = 0x60
_OFF_KD_BLOCK = 0x80
_OFF_PHYS_MEM = 0x88          # PHYSICAL_MEMORY_DESCRIPTOR64
_OFF_CONTEXT = 0x348          # x64 CONTEXT inside a 3000-byte buffer
_OFF_EXCEPTION = 0xF00        # EXCEPTION_RECORD64 (152 bytes)
_OFF_DUMP_TYPE = 0xF98
_OFF_REQUIRED_SPACE = 0xFA0
_OFF_SYSTEM_TIME = 0xFA8
_OFF_COMMENT = 0xFB0
_OFF_SYSTEM_UPTIME = 0x1030

# EXCEPTION_RECORD64 field offsets (relative to the record).
_EXC_CODE = 0x00
_EXC_FLAGS = 0x04
_EXC_RECORD = 0x08
_EXC_ADDRESS = 0x10
_EXC_NUMPARAMS = 0x18
_EXC_INFO = 0x20               # 15 ULONG64 slots

# x64 CONTEXT field offsets (relative to ContextRecord start).
_CTX_P1 = 0x00                 # P1Home..P6Home
_CTX_FLAGS = 0x30
_CTX_MXCSR = 0x34
_CTX_SEGCS = 0x38              # segs: cs,ds,es,fs,gs,ss every 2 bytes
_CTX_EFLAGS = 0x44
_CTX_DR0 = 0x48                # dr0..dr3, then dr6, dr7 (8-byte slots)
_CTX_RAX = 0x78
_CTX_RIP = 0xF8

_CONTEXT_AMD64 = 0x00100000    # CONTEXT_AMD64 flag bit

# TRIAGE_DUMP64 offsets (relative to the structure at file 0x2000).
_TRI_SP_BUILD = 0x00
_TRI_SIZE_OF_DUMP = 0x04
_TRI_VALID_OFFSET = 0x08
_TRI_CONTEXT_OFFSET = 0x0C
_TRI_EXCEPTION_OFFSET = 0x10
_TRI_CALLSTACK_OFFSET = 0x28
_TRI_CALLSTACK_SIZE = 0x2C
_TRI_DRIVER_LIST_OFFSET = 0x30
_TRI_DRIVER_COUNT = 0x34
_TRI_STRING_POOL_OFFSET = 0x38
_TRI_STRING_POOL_SIZE = 0x3C
_TRI_BROKEN_DRIVER_OFFSET = 0x40
_TRI_TOP_OF_STACK = 0x48       # ULONG64 — highest VA of the saved stack
_TRI_DATA_PAGE_ADDRESS = 0x60  # ULONG64 VA the data page decodes at
_TRI_DATA_PAGE_OFFSET = 0x68
_TRI_DATA_PAGE_SIZE = 0x6C
_TRI_DEBUGGER_DATA_OFFSET = 0x70
_TRI_DEBUGGER_DATA_SIZE = 0x74
_TRI_DATA_BLOCKS_OFFSET = 0x78
_TRI_DATA_BLOCKS_COUNT = 0x7C

# KernBase sits at +0x18 inside the KDDEBUGGER_DATA64 block the triage
# dump embeds (verified against real minidumps: matches the ntoskrnl
# entry base in the embedded driver list).
_KD_DEBUGGER_KERNBASE = 0x18

# TRIAGE_DUMP64 embedded driver list: fixed 0x90-byte DUMP_DRIVER_ENTRY
# records (verified against real minidumps; name/base/size stable across
# the lab's builds — timestamp/checksum slots best-effort).
_TRI_DRIVER_ENTRY_SIZE = 0x90
_TRI_DRV_NAME_OFFSET = 0x00   # u64: absolute file offset of the name
_TRI_DRV_BASE = 0x38          # u64: DllBase
_TRI_DRV_SIZE = 0x48          # u64: SizeOfImage
_TRI_DRV_TIMESTAMP = 0x80     # u32: TimeDateStamp
_TRI_DRV_CHECKSUM = 0x88      # u32: CheckSum

# String pool: u32 char_count + UTF-16-LE chars + UTF-16 NUL, packed
# back-to-back (4-byte alignment between entries). Entry name offsets
# point at the u32 length field, as absolute dump file offsets.
_MAX_DRV_NAME_CHARS = 520

# SUMMARY_DUMP64 offsets (relative to the structure at file 0x2000).
_SUM_SIGNATURE = 0x00          # "SDMP" (summary/kernel) or "FDMP" (full)
_SUM_VALIDDUMP = 0x04          # "DUMP"
_SUM_DUMP_OPTIONS = 0x08
_SUM_HEADER_SIZE = 0x0C        # file offset where page data starts
_SUM_BITMAP_SIZE = 0x10        # bitmap length in bits (max PFN + 1)
_SUM_PAGES = 0x14              # bits actually set (= pages in file)
_SUM_BITMAP = 0x28             # bitmap bytes start here (after
                              # SizeOfBitMap u32 + ULONG64 reserved)

DUMP_TYPES = {
    0: "unknown",
    1: "full",
    2: "summary",
    3: "header",
    4: "triage",
    5: "bitmap_full",
    6: "bitmap_kernel",
}
_BITMAP_DUMP_TYPES = {2, 5, 6}
