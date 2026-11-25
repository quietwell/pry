/*
 * comm/abi/mem.h — Memory R/W (user/kernel/physical), user/kernel allocate/
 * free/protect, physical-ranges enumeration, pool scan, and VA translate.
 * Function codes 0x831-0x836, 0x840-0x844, 0x855-0x857.
 *
 * Part of the pry wire ABI; see comm/pry_abi.h.
 * Fixed-layout, no pointers, no C++. Any change here is a breaking ABI
 * change: bump PRY_ABI_VERSION and the driver epoch.
 */

#ifndef PRY_ABI_MEM_H
#define PRY_ABI_MEM_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PRY_FUNC_USER_MEM_READ 0x831
#define PRY_FUNC_USER_MEM_WRITE 0x832
#define PRY_FUNC_KERNEL_MEM_READ 0x833
#define PRY_FUNC_KERNEL_MEM_WRITE 0x834
#define PRY_FUNC_PHYS_MEM_READ 0x835
#define PRY_FUNC_PHYS_MEM_WRITE 0x836
#define PRY_FUNC_USER_ALLOC 0x840
#define PRY_FUNC_USER_FREE 0x841
#define PRY_FUNC_USER_PROTECT 0x842
#define PRY_FUNC_KMEM_ALLOC 0x843
#define PRY_FUNC_KMEM_FREE 0x844
#define PRY_FUNC_PHYS_RANGES 0x855 // v4: enumerate MmGetPhysicalMemoryRanges
#define PRY_FUNC_POOL_SCAN 0x856   // v4: SystemBigPoolInformation walk + filter
#define PRY_FUNC_VA_TRANSLATE 0x857 // v5: walk current CR3 page tables (Va -> Pa)

#define PRY_IOCTL_USER_MEM_READ PRY_IOCTL(PRY_FUNC_USER_MEM_READ, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define PRY_IOCTL_USER_MEM_WRITE PRY_IOCTL(PRY_FUNC_USER_MEM_WRITE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_KERNEL_MEM_READ PRY_IOCTL(PRY_FUNC_KERNEL_MEM_READ, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define PRY_IOCTL_KERNEL_MEM_WRITE PRY_IOCTL(PRY_FUNC_KERNEL_MEM_WRITE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_PHYS_MEM_READ PRY_IOCTL(PRY_FUNC_PHYS_MEM_READ, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define PRY_IOCTL_PHYS_MEM_WRITE PRY_IOCTL(PRY_FUNC_PHYS_MEM_WRITE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_USER_ALLOC PRY_IOCTL(PRY_FUNC_USER_ALLOC, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_USER_FREE PRY_IOCTL(PRY_FUNC_USER_FREE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_USER_PROTECT PRY_IOCTL(PRY_FUNC_USER_PROTECT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_KMEM_ALLOC PRY_IOCTL(PRY_FUNC_KMEM_ALLOC, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_KMEM_FREE PRY_IOCTL(PRY_FUNC_KMEM_FREE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_PHYS_RANGES PRY_IOCTL(PRY_FUNC_PHYS_RANGES, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_POOL_SCAN PRY_IOCTL(PRY_FUNC_POOL_SCAN, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_VA_TRANSLATE PRY_IOCTL(PRY_FUNC_VA_TRANSLATE, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PRY_MEM_FLAG_ALLOW_SOFTFAULT 0x1 // kernel read: soft-fault non-resident PAGEDATA
// v6, bit 1: kernel read walks the range per-4KB and returns whatever
// pages MmCopyMemory can serve. First failure stops the walk; caller
// gets STATUS_PARTIAL_COPY with *Done set to the valid prefix length.
// Fixes the "pool sweep fails atomically on an unmapped hole" workflow.
#define PRY_MEM_FLAG_PARTIAL 0x2
// v5, bit 2: physical write opts into the MmMapIoSpaceEx write path. Default
// OFF = clean refusal; when set, unmappable pages are skipped per-4KB and the
// caller sees STATUS_PARTIAL_COPY with Done < Size instead of a hard abort.
#define PRY_MEM_FLAG_ALLOW_MAP_WRITE 0x4
// vNEXT (T3.1 PR#5), bit 3: physical READ opt-in for out-of-RAM addresses.
// Default OFF = the driver refuses any physical address outside
// MmGetPhysicalMemoryRanges with STATUS_ACCESS_DENIED (never touches
// MmCopyMemory/MmMapIoSpaceEx), killing the "one MMIO read wedges the
// box" path. When set, behaviour is exactly as before the guard. Old
// agents that don't carry the proto field never set this bit, so the
// legacy IOCTL layout stays binary-compatible (the Flags slot already
// existed in v2+ and old senders write 0 there).
#define PRY_MEM_FLAG_ALLOW_OUT_OF_RAM 0x8

typedef struct _PRY_MEM_REQ {
    UINT64 Pid;
    UINT64 Address;
    UINT64 Size; // in: capacity, out: bytes transferred
    UINT32 Flags; // PRY_MEM_FLAG_* (appended in ABI v2; old drivers ignore)
    UINT32 Reserved;
} PRY_MEM_REQ, *PPRY_MEM_REQ;

// ------------------------------------------------------------------ v12 ----
// Extended write header. First 32 bytes are wire-identical to
// PRY_MEM_REQ; the old Reserved slot carries PRY_MEM_WRITE_EXT_MAGIC,
// which is how a v12 driver tells "[32B legacy hdr][payload]" apart from
// "[48B ext hdr][payload]" — an old sender writes Reserved=0 there, never
// the magic. When the marker is present the payload starts at offset 48
// and Cr3/Flags2 apply; otherwise payload starts at 32 and the write is
// legacy-shaped. Input stays METHOD_BUFFERED.
#define PRY_MEM_WRITE_EXT_MAGIC 0x33574D45u  // 'EMW3' little-endian

typedef struct _PRY_MEM_WRITE_IN {
    UINT64 Pid;
    UINT64 Address;
    UINT64 Size;      // declared payload size (wire payload may be shorter)
    UINT32 Flags;     // PRY_MEM_FLAG_* (same slot as PRY_MEM_REQ)
    UINT32 ExtLayout; // PRY_MEM_WRITE_EXT_MAGIC (was PRY_MEM_REQ.Reserved)
    UINT64 Cr3;       // foreign address space for KERNEL writes; 0 = current
    UINT32 Flags2;    // PRY_MEM_WRF_*
    UINT32 Reserved;
} PRY_MEM_WRITE_IN, *PPRY_MEM_WRITE_IN;   // 48 bytes

// Flags2 bits (the original Flags slot stays PRY_MEM_FLAG_* for
// read/phys-write semantics).
// STRICT_VA (kernel write): never fall back to the physical-remap path on
// a direct-VA fault — return STATUS_INVALID_ADDRESS instead. The fallback
// walks the page tables and writes through MmMapIoSpace, which bypasses
// the linear address entirely: DR watchpoints / EPT hooks on the target
// VA do not see the store. Callers that care about write observability
// opt out of the silent escape hatch.
#define PRY_MEM_WRF_STRICT_VA 0x1

// WritePath report (PRY_MEM_WRITE_OUT.WritePath; proto write_path).
#define PRY_MEM_WRITE_PATH_UNKNOWN     0 // pre-v12 peer, or no reply path
#define PRY_MEM_WRITE_PATH_DIRECT_VA   1 // RtlCopyMemory on the target VA
#define PRY_MEM_WRITE_PATH_PHYS_REMAP  2 // page-walk + physical map
#define PRY_MEM_WRITE_PATH_FOREIGN_CR3 3 // direct VA under request CR3

// Optional reply for the extended write. When the caller's DeviceIoControl
// carries an output buffer >= 16 bytes the driver always completes
// STATUS_SUCCESS and reports the op result here — even a failed write then
// returns Done/WritePath instead of collapsing to a bare NTSTATUS
// (a warning NTSTATUS breaks DeviceIoControl
// delivery). Callers without an output buffer keep the legacy contract
// (NTSTATUS + bytesReturned = Done).
typedef struct _PRY_MEM_WRITE_OUT {
    UINT32 Status;    // NTSTATUS of the write itself
    UINT8  WritePath; // PRY_MEM_WRITE_PATH_*
    UINT8  Reserved[3];
    UINT64 Done;      // bytes actually written
} PRY_MEM_WRITE_OUT, *PPRY_MEM_WRITE_OUT; // 16 bytes

typedef struct _PRY_USER_ALLOC_IN {
    UINT64 Pid;
    UINT64 Size;
    UINT32 Protect; // PAGE_*
    UINT32 Reserved;
} PRY_USER_ALLOC_IN, *PPRY_USER_ALLOC_IN;

typedef struct _PRY_USER_ALLOC_OUT {
    UINT32 Status; // NTSTATUS
    UINT32 Reserved;
    UINT64 Address;
} PRY_USER_ALLOC_OUT, *PPRY_USER_ALLOC_OUT;

typedef struct _PRY_USER_FREE_IN {
    UINT64 Pid;
    UINT64 Address; // region base as returned by USER_ALLOC
} PRY_USER_FREE_IN, *PPRY_USER_FREE_IN;

typedef struct _PRY_USER_FREE_OUT {
    UINT32 Status;
    UINT32 Reserved;
} PRY_USER_FREE_OUT, *PPRY_USER_FREE_OUT;

typedef struct _PRY_USER_PROTECT_IN {
    UINT64 Pid;
    UINT64 Address;
    UINT64 Size;
    UINT32 Protect;
    UINT32 Reserved;
} PRY_USER_PROTECT_IN, *PPRY_USER_PROTECT_IN;

typedef struct _PRY_USER_PROTECT_OUT {
    UINT32 Status;
    UINT32 OldProtect;
} PRY_USER_PROTECT_OUT, *PPRY_USER_PROTECT_OUT;

typedef struct _PRY_KMEM_ALLOC_IN {
    UINT64 Size;
} PRY_KMEM_ALLOC_IN, *PPRY_KMEM_ALLOC_IN;

typedef struct _PRY_KMEM_ALLOC_OUT {
    UINT32 Status;
    UINT32 Reserved;
    UINT64 Address;
} PRY_KMEM_ALLOC_OUT, *PPRY_KMEM_ALLOC_OUT;

typedef struct _PRY_KMEM_FREE_IN {
    UINT64 Address; // must come from KMEM_ALLOC
} PRY_KMEM_FREE_IN, *PPRY_KMEM_FREE_IN;

typedef struct _PRY_KMEM_FREE_OUT {
    UINT32 Status;
    UINT32 Reserved;
} PRY_KMEM_FREE_OUT, *PPRY_KMEM_FREE_OUT;

// v4: MmGetPhysicalMemoryRanges enumeration. Input is empty; output is a
// PRY_PHYS_RANGES_HDR followed by Count PRY_PHYS_RANGE_ENTRY entries.
// The driver re-queries per call so hotplug RAM (VM balloon, PCIe MMIO
// resize) is reflected. Total system-RAM = sum(Size for Kind=Ram).
#define PRY_MAX_PHYS_RANGES 128

#define PRY_PHYS_KIND_RAM 0

typedef struct _PRY_PHYS_RANGE_ENTRY {
    UINT64 Base; // physical byte address
    UINT64 Size; // bytes
    UINT32 Kind; // PRY_PHYS_KIND_* (currently only RAM; kept for MMIO/ROM later)
    UINT32 Reserved;
} PRY_PHYS_RANGE_ENTRY, *PPRY_PHYS_RANGE_ENTRY;

typedef struct _PRY_PHYS_RANGES_HDR {
    UINT32 Status;
    UINT32 Count;      // entries written after this header
    UINT32 Required;   // total ranges available (may exceed Count)
    UINT32 Reserved;
} PRY_PHYS_RANGES_HDR, *PPRY_PHYS_RANGES_HDR;

// v4: SystemBigPoolInformation walk + optional tag/content filter.
// The kernel's SystemBigPoolInformation only lists >4KB "big pool"
// allocations (single-page LFH lumps are opaque on modern builds); this
// is still exactly the surface interesting to driver RE (large device
// buffers, MDL-backed IO blocks, EDID caches etc.).
//
// Filter semantics: an entry is returned if
//   (TagFilter == 0 OR entry.Tag == TagFilter)
//   AND (PatternLen == 0
//        OR memmem(read(entry.VA + Offset, ContentSpan), Pattern) hits).
// PatternLen<=16, ContentSpan<=4096 (compute+alloc budget). If Pattern is
// set and the entry read fails, the entry is silently skipped (a hole is
// not evidence).

#define PRY_POOL_MAX_ENTRIES 4096
// pattern cap raised 16 -> 64 B, span cap 4 KiB -> 64 KiB.
// Older builds hit the smaller caps as STATUS_INVALID_PARAMETER; new ones
// still accept the smaller sizes.
#define PRY_POOL_PATTERN_MAX 64
#define PRY_POOL_CONTENT_SPAN_MAX (64u * 1024u)

#define PRY_POOL_FLAG_NONPAGED_ONLY 0x1
#define PRY_POOL_FLAG_PAGED_ONLY    0x2

typedef struct _PRY_POOL_SCAN_IN {
    UINT32 TagFilter;    // 4-char tag as UINT32, or 0 for any
    UINT32 Flags;        // PRY_POOL_FLAG_*
    UINT32 MaxResults;   // clamped to PRY_POOL_MAX_ENTRIES
    UINT32 PatternLen;   // 0 = no content filter
    UINT32 ContentSpan;  // bytes to read+scan starting at VA+Offset; 0 = whole
    UINT32 Offset;       // start of the content window inside the entry
    UCHAR  Pattern[PRY_POOL_PATTERN_MAX];
    UCHAR  Mask[PRY_POOL_PATTERN_MAX]; // 0 or '?' = wildcard byte
    // resume index. 0 = fresh scan; otherwise the driver
    // skips entries whose SystemBigPoolInformation index is below the
    // cursor and writes the next cursor into the HDR for the follow-up
    // call. The pool table isn't guaranteed stable across calls — treat
    // cursored scans as "snapshot-ish" and expect new allocations to
    // appear only on fresh calls.
    UINT32 Cursor;
} PRY_POOL_SCAN_IN, *PPRY_POOL_SCAN_IN;

typedef struct _PRY_POOL_ENTRY {
    UINT64 VirtualAddress;
    UINT64 SizeInBytes;
    UINT32 Tag;
    UINT32 NonPaged;      // 1 = non-paged pool, 0 = paged
    UINT64 MatchedOffset; // when PatternLen > 0, absolute VA of the match; else 0
} PRY_POOL_ENTRY, *PPRY_POOL_ENTRY;

typedef struct _PRY_POOL_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;    // total entries the walk saw before filter
    UINT32 Considered;  // total entries after tag/paged filter, before content
    // scan telemetry. `Holes` counts entries whose content
    // read failed (previously silently skipped), `SpanTruncated` counts
    // entries whose content span had to be clipped to the entry size,
    // `LastIndex` is the AllocatedInfo index the driver reached, and
    // `NextCursor` is 0 when the scan completed, else the cursor to pass
    // on the next call.
    UINT32 Holes;
    UINT32 SpanTruncated;
    UINT32 LastIndex;
    UINT32 NextCursor;
} PRY_POOL_HDR, *PPRY_POOL_HDR;

// v5: VA -> PA via the driver's page-table walk (PryTranslateVa, current
// CR3 context). Exposed so gates/tests can locate the physical backing of a
// kernel VA (e.g. a KMEM_ALLOC result) without poking at live RAM blindly.
// v12: IN grows Cr3 + Pid (walk under an explicit CR3, or a target
// process's tables via KeStackAttachProcess — the deferred v7 USER-space
// feature). OUT grows PageSizeShift + Cr3 (which CR3 the walk used).
// Both directions degrade cleanly: a v12 caller's 24-byte IN satisfies the
// v11 driver's 16-byte minimum (extra tail ignored -> legacy walk); a v12
// driver fills only the caller's OUT prefix (16-byte caller -> legacy
// reply, PageSizeShift/Cr3 stay zero client-side).
typedef struct _PRY_VA_TRANSLATE_IN {
    UINT64 Va;
    UINT64 Cr3;  // v12 (bytes 8..15 were Reserved[2] pre-v12, always 0 —
                 // a legacy request therefore reads as Cr3=0 = "current")
    UINT64 Pid;  // v12: process whose tables are walked (USER space);
                 // 0 = caller context / system for kernel VAs
} PRY_VA_TRANSLATE_IN, *PPRY_VA_TRANSLATE_IN;

typedef struct _PRY_VA_TRANSLATE_OUT {
    UINT32 Status;        // NTSTATUS of the walk (STATUS_INVALID_ADDRESS when unmapped)
    UINT32 PageSizeShift; // v12 (was Reserved): 12/21/30 for the leaf that
                          // mapped VA; 0 on failure or a v11 driver
    UINT64 PhysicalAddress;
    UINT64 Cr3;           // v12: CR3 the walk actually ran under
} PRY_VA_TRANSLATE_OUT, *PPRY_VA_TRANSLATE_OUT;

#ifdef __cplusplus
}
#endif

#endif // PRY_ABI_MEM_H
