/*
 * comm/abi/watchdog.h — Driver-owned wedge-detector watchdog
 * (ARM/KICK/DISARM/LIST). Function codes 0x890-0x893.
 *
 * Part of the pry wire ABI; see comm/pry_abi.h.
 * Fixed-layout, no pointers, no C++. Any change here is a breaking ABI
 * change: bump PRY_ABI_VERSION and the driver epoch.
 */

#ifndef PRY_ABI_WATCHDOG_H
#define PRY_ABI_WATCHDOG_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// v8: wedge-detector watchdog. See "Watchdog" section below for struct
// layouts and the DriverEntry-spawned worker's contract.
#define PRY_FUNC_WATCHDOG_ARM    0x890
#define PRY_FUNC_WATCHDOG_KICK   0x891
#define PRY_FUNC_WATCHDOG_DISARM 0x892
#define PRY_FUNC_WATCHDOG_LIST   0x893

#define PRY_IOCTL_WATCHDOG_ARM    PRY_IOCTL(PRY_FUNC_WATCHDOG_ARM,    METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_WATCHDOG_KICK   PRY_IOCTL(PRY_FUNC_WATCHDOG_KICK,   METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_WATCHDOG_DISARM PRY_IOCTL(PRY_FUNC_WATCHDOG_DISARM, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_WATCHDOG_LIST   PRY_IOCTL(PRY_FUNC_WATCHDOG_LIST,   METHOD_BUFFERED, FILE_ANY_ACCESS)

// --------------------------------------------------------------- Watchdog ----
// Wedge-detector. A driver-owned 8-slot table holds absolute
// QPC-microsecond deadlines; on the first deadline that passes without a
// KICK, the driver calls
//   KeBugCheckEx(PRY_BUGCHECK_MANUALLY_INITIATED,
//                Id, DeadlineUs, LastKickUs, Cookie)
// so the resulting dump self-identifies as a watchdog fire under
// `!analyze -v` — Arg1..Arg4 carry the slot's provenance directly.
//
// Runner: a periodic KTIMER + KDPC at 100 ms (PRY_DRV_VERSION_MINOR
// = 1) so wedges that starve threads
// (dispatcher-lock spins, DPC storms pinning every CPU at DISPATCH+, scheduler
// bugs) still fire — a DPC runs off the per-CPU clock interrupt above the
// thread scheduler. Wire ABI is unchanged; the runner swap is opaque to
// user-mode callers.
//
// Contract:
//   * IDs are caller-chosen non-zero UINT32. ID collision on ARM without
//     PRY_WDG_FLAG_REPLACE returns STATUS_OBJECT_NAME_COLLISION.
//   * DeadlineMs upper-bound = 3_600_000 (1 h). Larger values are refused.
//   * KICK on an unarmed ID returns STATUS_NOT_FOUND — the caller learns
//     their Arm dropped without waiting for a bugcheck.
//   * On-wire evidence of a fire is the MEMORY DUMP: the four KeBugCheckEx
//     args (Id, DeadlineUs, LastKickUs, Cookie), plus a "PryDrv WDG FIRE"
//     line captured in the KdPrintCircularBuffer readable via `!dbgprint` in
//     windbg. The timer-DPC runner does NOT write "WDG FIRE …" to the on-disk kernel log at
//     fire time (ZwWriteFile is illegal at DISPATCH_LEVEL from the DPC path),
//     so Files.LogTail / target_manage(crash_state) kernel_log_tail no longer
//     carry a fire marker — read the dump instead. (v8 did write on disk from
//     the retired system thread; that path is gone. Arm/Kick/Disarm calls
//     still emit routine on-disk audit lines from PASSIVE_LEVEL.)

#define PRY_WATCHDOG_MAX 8
#define PRY_WDG_MAX_LABEL 32
#define PRY_WDG_MAX_DEADLINE_MS (60u * 60u * 1000u)  // 1 hour

#define PRY_WDG_FLAG_REPLACE 0x1  // overwrite an existing entry with same Id

// Bug-check code the worker uses when it fires. Documented as
// MANUALLY_INITIATED_CRASH (0xE2). Callers may override via BugcheckCode.
#define PRY_BUGCHECK_MANUALLY_INITIATED 0xE2u

typedef struct _PRY_WDG_ARM_IN {
    UINT32 Id;            // caller-chosen; nonzero
    UINT32 DeadlineMs;    // relative deadline from Arm
    UINT32 BugcheckCode;  // 0 = 0xE2 MANUALLY_INITIATED_CRASH
    UINT32 Flags;         // PRY_WDG_FLAG_*
    UINT64 Cookie;        // opaque; passed as the 4th bugcheck arg
    CHAR   Label[PRY_WDG_MAX_LABEL]; // NUL-terminated best-effort tag
} PRY_WDG_ARM_IN, *PPRY_WDG_ARM_IN;

typedef struct _PRY_WDG_ARM_OUT {
    UINT32 Status;
    UINT32 Reserved;
} PRY_WDG_ARM_OUT, *PPRY_WDG_ARM_OUT;

typedef struct _PRY_WDG_KICK_IN {
    UINT32 Id;
    UINT32 DeadlineMs;    // new relative deadline; 0 = keep existing
    UINT64 Cookie;        // new cookie; 0 = keep existing
} PRY_WDG_KICK_IN, *PPRY_WDG_KICK_IN;

typedef struct _PRY_WDG_KICK_OUT {
    UINT32 Status;
    UINT32 Reserved;
    UINT64 KickCount;
    UINT64 LastKickUs;
    UINT64 DeadlineUs;    // absolute QPC-us after this kick
} PRY_WDG_KICK_OUT, *PPRY_WDG_KICK_OUT;

typedef struct _PRY_WDG_DISARM_IN {
    UINT32 Id;
    UINT32 Reserved;
} PRY_WDG_DISARM_IN, *PPRY_WDG_DISARM_IN;

typedef struct _PRY_WDG_DISARM_OUT {
    UINT32 Status;
    UINT32 Reserved;
} PRY_WDG_DISARM_OUT, *PPRY_WDG_DISARM_OUT;

typedef struct _PRY_WDG_LIST_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
    UINT64 NowUs;         // driver's QPC-us at read time (compare to DeadlineUs)
} PRY_WDG_LIST_HDR, *PPRY_WDG_LIST_HDR;

typedef struct _PRY_WDG_ENTRY {
    UINT32 Id;
    UINT32 BugcheckCode;
    UINT64 DeadlineUs;
    UINT64 LastKickUs;
    UINT64 KickCount;
    UINT64 Cookie;
    UINT64 ArmedUs;       // when the slot was armed
    CHAR   Label[PRY_WDG_MAX_LABEL];
} PRY_WDG_ENTRY, *PPRY_WDG_ENTRY;

#ifdef __cplusplus
}
#endif

#endif // PRY_ABI_WATCHDOG_H
