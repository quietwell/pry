/*
 * comm/abi/notify.h — Kernel notification ring (PRY_EVT) plus the
 * SUBSCRIBE/READ/DISABLE/STATS IOCTLs that drain it. Function codes
 * 0x8A0-0x8A3.
 *
 * Part of the pry wire ABI; see comm/pry_abi.h.
 * Fixed-layout, no pointers, no C++. Any change here is a breaking ABI
 * change: bump PRY_ABI_VERSION and the driver epoch.
 */

#ifndef PRY_ABI_NOTIFY_H
#define PRY_ABI_NOTIFY_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// v10: notify event ring + kernel object/thread enumeration
#define PRY_FUNC_NOTIFY_SUBSCRIBE 0x8A0
#define PRY_FUNC_NOTIFY_READ      0x8A1
#define PRY_FUNC_NOTIFY_DISABLE   0x8A2
#define PRY_FUNC_NOTIFY_STATS     0x8A3

#define PRY_IOCTL_NOTIFY_SUBSCRIBE PRY_IOCTL(PRY_FUNC_NOTIFY_SUBSCRIBE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_NOTIFY_READ      PRY_IOCTL(PRY_FUNC_NOTIFY_READ,      METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define PRY_IOCTL_NOTIFY_DISABLE   PRY_IOCTL(PRY_FUNC_NOTIFY_DISABLE,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_NOTIFY_STATS     PRY_IOCTL(PRY_FUNC_NOTIFY_STATS,     METHOD_BUFFERED, FILE_ANY_ACCESS)

// ------------------------------------------------------------- Notify ring ----
// v10: the agent's "ears". The driver registers kernel notification
// callbacks (process create/exit, thread create/exit, image load — kernel
// images included, so driver loads fall out for free) and appends
// fixed-size records to a static overwrite-oldest ring. The ring lives in
// the driver image (nonpaged); callbacks only take a spinlock and copy, so
// process creation is never stalled. NOTIFY_READ drains oldest-first and
// returns the cumulative dropped counter — a reader that saw seq N and
// later sees LastSeq jump by more than the events delivered knows the ring
// overflowed in between (gap), and `dropped` increasing proves loss.
//
// Classes are subscribed via NOTIFY_SUBSCRIBE (bitmask; 0 = all three) and
// unregistered by NOTIFY_DISABLE and at unload. Registration is refcount-
// free by design: subscribe = kernel-visible state change, so the
// orchestrator gates it like driver_load.

#define PRY_EVT_KIND_PROC_CREATE  1
#define PRY_EVT_KIND_PROC_EXIT    2
#define PRY_EVT_KIND_IMAGE_LOAD   3
#define PRY_EVT_KIND_THREAD_CREATE 4
#define PRY_EVT_KIND_THREAD_EXIT  5
#define PRY_EVT_KIND_BP_HIT       6 // v11: armed HW bp fired (int1 hook)

#define PRY_EVT_CLASS_PROC   0x1
#define PRY_EVT_CLASS_IMAGE  0x2
#define PRY_EVT_CLASS_THREAD 0x4
// v11: DR0-3 breakpoint hits. Subscribing installs the driver's int1
// (IDT vector 1) hook on every CPU — kernel-visible and PatchGuard-
// sensitive, so the class is ignored unless the subscribe call also
// carries PRY_NOTIFY_FLAG_BP_HOOK_OK. Unsubscribed hits chain to the
// original KiTrap01 (unchanged pre-hook behaviour).
#define PRY_EVT_CLASS_BP     0x8
#define PRY_EVT_CLASS_ALL    (PRY_EVT_CLASS_PROC | PRY_EVT_CLASS_IMAGE | PRY_EVT_CLASS_THREAD | PRY_EVT_CLASS_BP)

#define PRY_EVT_RING 1024
#define PRY_EVT_IMAGE_CCH 128

typedef struct _PRY_EVT {
    UINT64 Seq;       // monotonic per-boot, starts at 1
    UINT64 TsMs;      // interrupt-time ms (uptime) when the event happened
    UINT32 Kind;      // PRY_EVT_KIND_*
    UINT32 Pid;
    UINT32 ParentPid; // proc-create only
    UINT32 Tid;       // thread events only
    UINT64 ImageBase; // image-load only
    UINT64 ImageSize; // image-load only
    WCHAR  Image[PRY_EVT_IMAGE_CCH]; // NT path, NUL-truncated
    // ---- v11 tail: BP_HIT payload (zero for other kinds) ----
    UINT64 Address;   // faulting RIP
    UINT64 Dr6;       // raw DR6 snapshot at trap entry
    UINT32 BpId;      // matched pry bp id (0 when the table lock wasn't taken)
    UINT32 Slot;      // DR slot that fired, 0-3 (0xFF = unresolved)
    UINT32 Access;    // matched bp's PRY_HW_* access (0 when unmatched)
    UINT32 Irql;      // KeGetCurrentIrql() at hit
    // ---- v14 tail (SI #25): watch demux cookie ----
    // Non-zero only when the ringed BP_HIT fires against a PRY_BP_REC
    // with IsWatch=1 (mirror of PRY_BP_ENTRY.WatchCookie). Agents
    // built against v13 see a short record and continue to parse the
    // v11 tail unchanged; agents built against v14 pick up the demux key.
    UINT32 WatchCookie;
    UINT32 Reserved;  // alignment/pad for future growth
} PRY_EVT, *PPRY_EVT;

// v11: subscribe Flags (field was Reserved; same wire layout)
#define PRY_NOTIFY_FLAG_BP_HOOK_OK 0x1 // consent for the IDT[1] hook

typedef struct _PRY_NOTIFY_SUBSCRIBE_IN {
    UINT32 Classes;   // PRY_EVT_CLASS_* bitmask; 0 = all
    UINT32 Flags;     // PRY_NOTIFY_FLAG_* (v11; was Reserved)
} PRY_NOTIFY_SUBSCRIBE_IN, *PPRY_NOTIFY_SUBSCRIBE_IN;

typedef struct _PRY_NOTIFY_SUBSCRIBE_OUT {
    UINT32 Status;
    UINT32 Registered; // classes actually registered
} PRY_NOTIFY_SUBSCRIBE_OUT, *PPRY_NOTIFY_SUBSCRIBE_OUT;

typedef struct _PRY_NOTIFY_READ_IN {
    UINT32 Max;       // events to drain (clamped to PRY_EVT_RING)
    UINT32 Reserved;
} PRY_NOTIFY_READ_IN, *PPRY_NOTIFY_READ_IN;

typedef struct _PRY_NOTIFY_READ_HDR {
    UINT32 Status;
    UINT32 Count;     // PRY_EVT records following the header
    UINT64 Dropped;   // overwrite-oldest counter, cumulative since load
    UINT64 LastSeq;   // highest seq in this batch
} PRY_NOTIFY_READ_HDR, *PPRY_NOTIFY_READ_HDR;

typedef struct _PRY_NOTIFY_STATS_OUT {
    UINT32 Status;
    UINT32 Registered;  // PRY_EVT_CLASS_* bitmask actually registered
    UINT32 ProcVariant; // 1 = Ex routine, 2 = classic, 0 = not registered
    UINT32 BpTrapMissed; // v11 (was Reserved): int1 hits consumed without a
                         // ring record (lock contention / teardown window)
    UINT64 Buffered;    // events currently in the ring
    UINT64 Dropped;     // cumulative overwrite-oldest count
    UINT64 Seq;         // highest seq issued
    UINT64 Total;       // cumulative events appended
} PRY_NOTIFY_STATS_OUT, *PPRY_NOTIFY_STATS_OUT;

#ifdef __cplusplus
}
#endif

#endif // PRY_ABI_NOTIFY_H
