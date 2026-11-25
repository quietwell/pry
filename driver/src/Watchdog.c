#include "PryDriver.h"

// wedge-detector. See pry_abi.h "Watchdog" for the caller contract.
//
// Design: one periodic KTIMER + KDPC ticking at 100 ms. The DPC callback
// scans the PRY_WATCHDOG_MAX-slot table under a spinlock (already at
// DISPATCH_LEVEL in a DPC — uses the AtDpcLevel acquire variant) and, on
// the first entry whose absolute QPC-microsecond deadline has passed,
// snapshots it, releases the lock, DbgPrintEx()s a "WDG FIRE" trailer, and
// calls KeBugCheckEx(0xE2, Id, DeadlineUs, LastKickUs, Cookie). Those
// four Args make `!analyze -v` self-identify the dump as ours.
//
// v8 predecessor used a HIGH_PRIORITY system thread. That worked for the
// ordinary "LLM stopped kicking" case, and had been fired in the field —
// but the wedge shape the harness has been chasing (three unresolved
// dumps) starves the scheduler itself. HIGH_PRIORITY is still a THREAD
// priority: the scheduler runs at IRQL 2 (DISPATCH_LEVEL) and depends on
// the dispatcher lock / ready-lists / KI_RUNNING flags being sane on every
// CPU. Wedges that hold the dispatcher lock indefinitely, or pin every
// CPU at DISPATCH_LEVEL or above, prevent HIGH_PRIORITY from running as
// surely as PASSIVE. Timer DPCs bypass thread scheduling entirely — they
// fire off the tail of the per-CPU clock interrupt, above the scheduler.
// A wedge that starves threads does not starve timer DPCs; a wedge that
// starves DPCs on one CPU still runs the DPC on any other CPU whose
// tick lands. This is the failure mode this file exists to close.
//
// Tradeoff we accept: pre-bugcheck ZwWriteFile is illegal at DISPATCH_LEVEL,
// so the on-disk `WDG FIRE` line the v8 thread wrote is gone. We emit
// DbgPrintEx at DPFLTR_ERROR_LEVEL, which lands in the KdPrintCircularBuffer
// and is captured in the crash dump — `!dbgprint` in windbg reads it back.
// The four bug-check args carry the essential provenance regardless. The
// orchestrator's target_manage(crash_state) becomes DPC-fire-blind on
// its kernel-log-tail path; the memory dump itself is the primary artifact
// and carries everything the analyst needs.

// ---- Table ----------------------------------------------------------------

typedef struct _PRY_WDG_REC {
    UINT32 Id;               // 0 = slot free
    UINT32 BugcheckCode;
    UINT32 Flags;
    UINT32 Reserved;
    UINT64 DeadlineUs;       // absolute QPC-us
    UINT64 LastKickUs;
    UINT64 KickCount;
    UINT64 Cookie;
    UINT64 ArmedUs;
    CHAR   Label[PRY_WDG_MAX_LABEL];
} PRY_WDG_REC, *PPRY_WDG_REC;

static PRY_WDG_REC PryWdgTable[PRY_WATCHDOG_MAX];
static KSPIN_LOCK    PryWdgLock;
static KTIMER        PryWdgTimer;
static KDPC          PryWdgDpc;
static volatile LONG PryWdgArmed = 0;   // 1 while the periodic timer is set

// QPC frequency captured once so the deadline check doesn't do a divide on
// every 100 ms tick.
static LARGE_INTEGER PryQpcFreq = {0};

// Timer period: 100 ms. Detection latency is [0, tick_period]; the minimum
// useful arm deadline is on the order of seconds, so 100 ms is negligible
// against the deadline horizon. Overhead is ~10 DPCs/s + one 8-entry loop
// under a spinlock — trivially cheap.
#define PRY_WDG_TICK_MS 100

// KeQueryPerformanceCounter is legal at any IRQL <= DISPATCH_LEVEL, so the
// same helper is safe from the DPC and from the PASSIVE-level IOCTL paths.
//
// The obvious `(ticks * 1_000_000) / freq` overflows uint64 once ticks
// crosses ~1.845e13 — roughly 21 days of uptime on the standard 10 MHz
// Windows QPC. That is squarely inside the target regime for a wedge-
// detector living on a lab VM chasing an intermittent scheduler bug: after
// the wrap, nowUs collapses to a small value while previously-armed
// DeadlineUs stays huge, and (a) the DPC's `nowUs >= r->DeadlineUs`
// compare never trips again — the watchdog dies silently, or (b) any slot
// whose deadline sat just above the wrapped nowUs fires with garbage
// KeBugCheckEx args, misidentifying the wedge in `!analyze -v`. The
// standard remedy is to split the divide before the multiply so the
// intermediate never leaves uint64: two divides on a 100 ms tick path
// is free.
static __forceinline UINT64 PryQpcMicroseconds(VOID)
{
    LARGE_INTEGER now = KeQueryPerformanceCounter(NULL);
    UINT64 f = (UINT64)PryQpcFreq.QuadPart;
    if (!f) return 0;
    UINT64 ticks = (UINT64)now.QuadPart;
    UINT64 sec = ticks / f;
    UINT64 rem = ticks % f;
    // sec*1e6 fits comfortably for centuries at any realistic freq; rem<f
    // by construction, so rem*1e6 < f*1e6 which is bounded by the QPC
    // frequency's own uint64 range on any hardware Windows supports.
    return sec * 1000000ULL + (rem * 1000000ULL) / f;
}

// ---- DPC callback ---------------------------------------------------------

static VOID PryWdgDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID DeferredContext,
                                _In_opt_ PVOID SystemArgument1,
                                _In_opt_ PVOID SystemArgument2)
{
    UINT64 nowUs;
    UINT32 i;
    PRY_WDG_REC fired;
    BOOLEAN fire = FALSE;
    UINT32 code;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Already at DISPATCH_LEVEL in a DPC; the AtDpcLevel acquire skips the
    // redundant IRQL raise. IOCTL callers (PASSIVE) still use
    // KeAcquireSpinLock which does raise — the two acquire variants cooperate
    // on the same lock.
    KeAcquireSpinLockAtDpcLevel(&PryWdgLock);
    nowUs = PryQpcMicroseconds();
    for (i = 0; i < PRY_WATCHDOG_MAX; i++) {
        PPRY_WDG_REC r = &PryWdgTable[i];
        if (!r->Id) continue;
        if (nowUs >= r->DeadlineUs) {
            fired = *r; // stack snapshot, then release the lock
            fire = TRUE;
            break;
        }
    }
    KeReleaseSpinLockFromDpcLevel(&PryWdgLock);

    if (!fire) return;

    // DbgPrint IS callable at DISPATCH_LEVEL. The KdPrintCircularBuffer is
    // captured in the crash dump (see !dbgprint in windbg) so this line
    // survives to the analyst even though ZwWriteFile is illegal here.
    // The leading "PryDrv WDG FIRE" is unique enough for a text search
    // through the buffered kd output.
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "PryDrv WDG FIRE (DPC) id=%u label='%s' code=0x%x "
               "cookie=0x%llx armed_us=%llu deadline_us=%llu "
               "last_kick_us=%llu kicks=%llu\n",
               fired.Id, fired.Label, fired.BugcheckCode, fired.Cookie,
               fired.ArmedUs, fired.DeadlineUs, fired.LastKickUs, fired.KickCount);

    code = fired.BugcheckCode ? fired.BugcheckCode : PRY_BUGCHECK_MANUALLY_INITIATED;
    KeBugCheckEx((ULONG)code,
                 (ULONG_PTR)fired.Id,
                 (ULONG_PTR)fired.DeadlineUs,
                 (ULONG_PTR)fired.LastKickUs,
                 (ULONG_PTR)fired.Cookie);
    // does not return — KeBugCheckEx freezes the system.
}

// ---- Init / Shutdown ------------------------------------------------------

NTSTATUS PryWatchdogInit(VOID)
{
    LARGE_INTEGER firstDue;

    RtlZeroMemory(PryWdgTable, sizeof(PryWdgTable));
    KeInitializeSpinLock(&PryWdgLock);
    KeQueryPerformanceCounter(&PryQpcFreq);
    if (PryQpcFreq.QuadPart == 0) {
        PryLog("WDG init: KeQueryPerformanceCounter freq == 0, skipping DPC");
        return STATUS_UNSUCCESSFUL;
    }

    KeInitializeTimer(&PryWdgTimer);
    KeInitializeDpc(&PryWdgDpc, PryWdgDpcRoutine, NULL);

    // Negative DueTime => relative; 100-ns units. First tick 100 ms out
    // (deliberately not 0 so an in-flight Arm has time to populate a slot;
    // the table is zeroed anyway, but a first-tick delay is free).
    firstDue.QuadPart = -((LONGLONG)PRY_WDG_TICK_MS * 10000LL);
    (void)KeSetTimerEx(&PryWdgTimer, firstDue, PRY_WDG_TICK_MS, &PryWdgDpc);
    InterlockedExchange(&PryWdgArmed, 1);

    PryLog("WDG init ok (DPC-based, %u ms tick, freq=%lld ticks/s)",
             (UINT32)PRY_WDG_TICK_MS, PryQpcFreq.QuadPart);
    return STATUS_SUCCESS;
}

VOID PryWatchdogShutdown(VOID)
{
    KIRQL irql;
    UINT32 i;

    // Cancel first so no new ticks queue. KeCancelTimer returns TRUE if the
    // timer was in the queue; either way, no further ticks will fire.
    if (InterlockedExchange(&PryWdgArmed, 0)) {
        (void)KeCancelTimer(&PryWdgTimer);
        // Drain any DPC that was in-flight when we cancelled. Legal at
        // PASSIVE_LEVEL (PryEvtDriverUnload calls us at PASSIVE). Unlike
        // the v8 thread wait, this is guaranteed to complete — a DPC can't
        // spin forever.
        KeFlushQueuedDpcs();
    }

    // Zero the table AFTER the flush. A straggler DPC that queued before
    // the cancel and won the race before the flush will have already fired
    // (its deadline was legitimate, so its bugcheck is a valid wedge report
    // even during unload). Zeroing here just guarantees no future recheck
    // ever bugchecks the already-shutting-down driver.
    KeAcquireSpinLock(&PryWdgLock, &irql);
    for (i = 0; i < PRY_WATCHDOG_MAX; i++) {
        PryWdgTable[i].Id = 0;
    }
    KeReleaseSpinLock(&PryWdgLock, irql);

    PryLog("WDG shutdown ok");
}

// ---- API called from the dispatcher --------------------------------------

static PPRY_WDG_REC PryWdgFindLocked(_In_ UINT32 Id)
{
    UINT32 i;
    for (i = 0; i < PRY_WATCHDOG_MAX; i++) {
        if (PryWdgTable[i].Id == Id) return &PryWdgTable[i];
    }
    return NULL;
}

static PPRY_WDG_REC PryWdgAllocLocked(VOID)
{
    UINT32 i;
    for (i = 0; i < PRY_WATCHDOG_MAX; i++) {
        if (!PryWdgTable[i].Id) return &PryWdgTable[i];
    }
    return NULL;
}

NTSTATUS PryWatchdogArm(_In_ UINT32 Id, _In_ UINT32 DeadlineMs,
                          _In_ UINT32 BugcheckCode, _In_ UINT32 Flags,
                          _In_ UINT64 Cookie, _In_ const CHAR* Label)
{
    KIRQL irql;
    PPRY_WDG_REC rec = NULL;
    UINT64 nowUs;

    if (!Id) return STATUS_INVALID_PARAMETER;
    if (!DeadlineMs) return STATUS_INVALID_PARAMETER;
    if (DeadlineMs > PRY_WDG_MAX_DEADLINE_MS) return STATUS_INVALID_PARAMETER;

    nowUs = PryQpcMicroseconds();

    KeAcquireSpinLock(&PryWdgLock, &irql);
    rec = PryWdgFindLocked(Id);
    if (rec && !(Flags & PRY_WDG_FLAG_REPLACE)) {
        KeReleaseSpinLock(&PryWdgLock, irql);
        return STATUS_OBJECT_NAME_COLLISION;
    }
    if (!rec) {
        rec = PryWdgAllocLocked();
        if (!rec) {
            KeReleaseSpinLock(&PryWdgLock, irql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    RtlZeroMemory(rec, sizeof(*rec));
    rec->Id = Id;
    rec->BugcheckCode = BugcheckCode ? BugcheckCode : PRY_BUGCHECK_MANUALLY_INITIATED;
    rec->Flags = Flags;
    rec->Cookie = Cookie;
    rec->ArmedUs = nowUs;
    rec->LastKickUs = nowUs;
    rec->KickCount = 0;
    rec->DeadlineUs = nowUs + (UINT64)DeadlineMs * 1000ULL;
    if (Label) {
        // Label may not be NUL-terminated in the IOCTL buffer; copy up to
        // PRY_WDG_MAX_LABEL-1 and always terminate.
        UINT32 j;
        for (j = 0; j + 1 < PRY_WDG_MAX_LABEL; j++) {
            CHAR c = Label[j];
            if (!c) break;
            rec->Label[j] = c;
        }
        rec->Label[j] = '\0';
    }
    KeReleaseSpinLock(&PryWdgLock, irql);

    // No wake needed: the DPC ticks unconditionally every PRY_WDG_TICK_MS.
    PryLog("WDG arm id=%u label='%s' deadline_ms=%u flags=0x%x cookie=0x%llx",
             Id, rec->Label, DeadlineMs, Flags, Cookie);
    return STATUS_SUCCESS;
}

NTSTATUS PryWatchdogKick(_In_ UINT32 Id, _In_ UINT32 DeadlineMs,
                           _In_ UINT64 Cookie,
                           _Out_ UINT64* KickCount, _Out_ UINT64* LastKickUs,
                           _Out_ UINT64* DeadlineUs)
{
    KIRQL irql;
    PPRY_WDG_REC rec;
    UINT64 nowUs;

    if (!Id) return STATUS_INVALID_PARAMETER;
    if (DeadlineMs > PRY_WDG_MAX_DEADLINE_MS) return STATUS_INVALID_PARAMETER;

    nowUs = PryQpcMicroseconds();

    KeAcquireSpinLock(&PryWdgLock, &irql);
    rec = PryWdgFindLocked(Id);
    if (!rec) {
        KeReleaseSpinLock(&PryWdgLock, irql);
        return STATUS_NOT_FOUND;
    }
    rec->LastKickUs = nowUs;
    rec->KickCount++;
    if (DeadlineMs) {
        rec->DeadlineUs = nowUs + (UINT64)DeadlineMs * 1000ULL;
    }
    if (Cookie) {
        rec->Cookie = Cookie;
    }
    if (KickCount)  *KickCount  = rec->KickCount;
    if (LastKickUs) *LastKickUs = rec->LastKickUs;
    if (DeadlineUs) *DeadlineUs = rec->DeadlineUs;
    KeReleaseSpinLock(&PryWdgLock, irql);

    return STATUS_SUCCESS;
}

NTSTATUS PryWatchdogDisarm(_In_ UINT32 Id)
{
    KIRQL irql;
    PPRY_WDG_REC rec;

    if (!Id) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&PryWdgLock, &irql);
    rec = PryWdgFindLocked(Id);
    if (!rec) {
        KeReleaseSpinLock(&PryWdgLock, irql);
        return STATUS_NOT_FOUND;
    }
    rec->Id = 0;
    KeReleaseSpinLock(&PryWdgLock, irql);

    PryLog("WDG disarm id=%u", Id);
    return STATUS_SUCCESS;
}

NTSTATUS PryWatchdogList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                           _In_ SIZE_T CapacityBytes,
                           _Out_ PUINT32 Count, _Out_ PUINT32 Required,
                           _Out_ PUINT64 NowUs)
{
    KIRQL irql;
    UINT32 i;
    UINT32 outIdx = 0;
    UINT32 required = 0;
    UINT32 cap = (UINT32)(CapacityBytes / sizeof(PRY_WDG_ENTRY));
    PPRY_WDG_ENTRY out = (PPRY_WDG_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    *NowUs = PryQpcMicroseconds();

    KeAcquireSpinLock(&PryWdgLock, &irql);
    for (i = 0; i < PRY_WATCHDOG_MAX; i++) {
        PPRY_WDG_REC r = &PryWdgTable[i];
        if (!r->Id) continue;
        required++;
        if (outIdx < cap && out) {
            RtlZeroMemory(&out[outIdx], sizeof(out[outIdx]));
            out[outIdx].Id = r->Id;
            out[outIdx].BugcheckCode = r->BugcheckCode;
            out[outIdx].DeadlineUs = r->DeadlineUs;
            out[outIdx].LastKickUs = r->LastKickUs;
            out[outIdx].KickCount = r->KickCount;
            out[outIdx].Cookie = r->Cookie;
            out[outIdx].ArmedUs = r->ArmedUs;
            RtlCopyMemory(out[outIdx].Label, r->Label, PRY_WDG_MAX_LABEL);
            outIdx++;
        }
    }
    KeReleaseSpinLock(&PryWdgLock, irql);

    *Count = outIdx;
    *Required = required;
    return required > outIdx ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}
