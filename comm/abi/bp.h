/*
 * comm/abi/bp.h — Software + hardware breakpoint set/clear/list and the
 * CTX_GET/CTX_SET companion surface. Function codes 0x860-0x861 (CTX)
 * and 0x870-0x874 (BP).
 *
 * Part of the pry wire ABI; see comm/pry_abi.h.
 * Fixed-layout, no pointers, no C++. Any change here is a breaking ABI
 * change: bump PRY_ABI_VERSION and the driver epoch.
 */

#ifndef PRY_ABI_BP_H
#define PRY_ABI_BP_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PRY_FUNC_CTX_GET 0x860
#define PRY_FUNC_CTX_SET 0x861
#define PRY_FUNC_BP_SW_SET 0x870
#define PRY_FUNC_BP_SW_CLEAR 0x871
#define PRY_FUNC_BP_HW_SET 0x872
#define PRY_FUNC_BP_HW_CLEAR 0x873
#define PRY_FUNC_BP_LIST 0x874

#define PRY_IOCTL_CTX_GET PRY_IOCTL(PRY_FUNC_CTX_GET, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_CTX_SET PRY_IOCTL(PRY_FUNC_CTX_SET, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_BP_SW_SET PRY_IOCTL(PRY_FUNC_BP_SW_SET, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_BP_SW_CLEAR PRY_IOCTL(PRY_FUNC_BP_SW_CLEAR, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_BP_HW_SET PRY_IOCTL(PRY_FUNC_BP_HW_SET, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_BP_HW_CLEAR PRY_IOCTL(PRY_FUNC_BP_HW_CLEAR, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_BP_LIST PRY_IOCTL(PRY_FUNC_BP_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)

// x64 CONTEXT is 1232 bytes, 16-aligned; stored as raw bytes here so the ABI
// header stays OS-header-free. Both sides copy through a CONTEXT-aligned local.
#define PRY_CONTEXT_SIZE 1232

typedef struct _PRY_CTX_HDR_IN {
    UINT64 Tid;
    UINT32 Flags; // CONTEXT_* mask
    UINT32 Reserved;
} PRY_CTX_HDR_IN, *PPRY_CTX_HDR_IN;

// v2 CTX_SET combined input layout (METHOD_BUFFERED, like the mem writes):
//   input  = [PRY_CTX_HDR_IN][UCHAR Context[PRY_CONTEXT_SIZE]]
//   output = PRY_CTX_HDR_OUT (driver fills Status; Flags echoes in.Flags)
// v1 passed the CONTEXT through lpOutBuffer, which METHOD_BUFFERED never
// delivers to the driver, and took the flags from the wrong buffer offset â€”
// the operation silently applied nothing.
typedef struct _PRY_CTX_HDR_OUT {
    UINT32 Status;
    UINT32 Flags;
    UCHAR Context[PRY_CONTEXT_SIZE];
} PRY_CTX_HDR_OUT, *PPRY_CTX_HDR_OUT;

// breakpoints
#define PRY_BP_KIND_SW 0
#define PRY_BP_KIND_HW 1
#define PRY_HW_EXEC 0
#define PRY_HW_WRITE 1
#define PRY_HW_RW 2
#define PRY_MAX_BP 64

typedef struct _PRY_BP_SW_SET_IN {
    UINT64 Pid;
    UINT64 Address;
} PRY_BP_SW_SET_IN, *PPRY_BP_SW_SET_IN;

typedef struct _PRY_BP_SW_SET_OUT {
    UINT32 Status;
    UINT32 Id;
    UCHAR OrigByte;
    UCHAR Reserved[3];
} PRY_BP_SW_SET_OUT, *PPRY_BP_SW_SET_OUT;

typedef struct _PRY_BP_SW_CLEAR_IN {
    UINT64 Pid;
    UINT64 Address;
    UINT32 Id; // 0: match by pid+address, else by id
    UINT32 Reserved;
} PRY_BP_SW_CLEAR_IN, *PPRY_BP_SW_CLEAR_IN;

// v6 flag bits on PRY_BP_HW_SET_IN.Reserved (renamed Flags).
// GLOBAL: Pid=0 arms every thread of every process AND
// PsSetCreateThreadNotifyRoutine catches newborns regardless of parent
// pid. Two-slot cap enforced by the driver to prevent DR starvation.
// DANGEROUS_OK: skip the PatchGuard-expected refusal (kd/lab-only VMs).
#define PRY_BP_HW_FLAG_GLOBAL 0x1
#define PRY_BP_HW_FLAG_DANGEROUS_OK 0x2
// ---- SI #25 HW-watch (v14) ----
// IS_WATCH marks a BP_HW_SET entry as the backing arm for a mem_rw
// watch subscription. The driver stashes the record's own BpId as the
// WatchCookie, mirrors it into every PRY_EVT_KIND_BP_HIT record it
// rings, and surfaces IsWatch + WatchCookie through BP_LIST. Watch
// entries never fire PRY_HW_EXEC — the orchestrator rejects that at
// request time; the driver double-checks.
// PREEMPT_OK lets a watch arm succeed even when every per-(pid,tid) DR
// slot is spoken for IF the only occupants are other IS_WATCH entries:
// the oldest one is demoted. A plain bp_manage breakpoint is NEVER
// preempted. Mutually exclusive with GLOBAL (watches are per-pid/tid).
#define PRY_BPHW_FLAG_IS_WATCH 0x4
#define PRY_BPHW_FLAG_PREEMPT_OK 0x8
// Sentinel Slot value for "driver picks a free slot per (pid, tid)".
// Legal everywhere PRY_BP_HW_SET_IN.Slot is accepted; also valid for
// non-watch arms, but the preempt_ok fallback only kicks for IS_WATCH.
#define PRY_BP_HW_SLOT_AUTO 0xFF

typedef struct _PRY_BP_HW_SET_IN {
    UINT64 Pid;
    UINT64 Tid;     // 0 = all threads of Pid; Pid=0 + FLAG_GLOBAL = every thread system-wide
    UINT64 Address;
    UINT32 Slot;    // 0..3
    UINT32 Length;  // 1,2,4,8
    UINT32 Access;  // PRY_HW_*
    UINT32 Flags;   // PRY_BP_HW_FLAG_* (was Reserved pre-v6; old drivers ignored)
} PRY_BP_HW_SET_IN, *PPRY_BP_HW_SET_IN;

typedef struct _PRY_BP_HW_SET_OUT {
    UINT32 Status;
    UINT32 Id;
    UINT32 ThreadsPatched;
    UINT32 Reserved;
} PRY_BP_HW_SET_OUT, *PPRY_BP_HW_SET_OUT;

typedef struct _PRY_BP_HW_CLEAR_IN {
    UINT64 Pid;
    UINT64 Tid;
    UINT32 Slot;
    UINT32 Reserved;
} PRY_BP_HW_CLEAR_IN, *PPRY_BP_HW_CLEAR_IN;

typedef struct _PRY_BP_HW_CLEAR_OUT {
    UINT32 Status;
    UINT32 ThreadsPatched;
} PRY_BP_HW_CLEAR_OUT, *PPRY_BP_HW_CLEAR_OUT;

// v14 (SI #25): the 7 Reserved bytes carry IsWatch (0/1) and WatchCookie
// (BpId of the IS_WATCH table entry; 0 when not a watch). Layout stays
// the same total size, so pre-v14 BP_LIST readers that treat the tail
// as opaque are unaffected; v14+ readers decode the watch surface.
typedef struct _PRY_BP_ENTRY {
    UINT32 Id;
    UINT32 Kind;
    UINT32 Pid;
    UINT32 Tid;
    UINT32 Slot;
    UINT32 Length;
    UINT32 Access;
    UINT32 Enabled;
    UINT64 Address;
    UCHAR OrigByte;
    UCHAR IsWatch;        // v14 — 1 when this entry backs a mem_rw watch
    UCHAR Reserved[2];
    UINT32 WatchCookie;   // v14 — BpId mirror (demux key for BP_HIT events)
} PRY_BP_ENTRY, *PPRY_BP_ENTRY;

typedef struct _PRY_BP_LIST_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} PRY_BP_LIST_HDR, *PPRY_BP_LIST_HDR;

#ifdef __cplusplus
}
#endif

#endif // PRY_ABI_BP_H
