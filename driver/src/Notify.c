#include "PryDriver.h"

// Ps{Set,Remove}CreateProcessNotifyRoutine{,Ex}: the Set variants are in
// ntoskrnl.lib, but the Remove variants are missing from the WDK import
// lib in this configuration — resolve all four at runtime via
// MmGetSystemRoutineAddress (same pattern as PsGetProcessVadRoot in Vad.c).
typedef NTSTATUS (*PRY_PROC_NOTIFY_SET_FN)(PVOID NotifyRoutine, BOOLEAN Remove);
typedef NTSTATUS (*PRY_PROC_NOTIFY_RM_FN)(PVOID NotifyRoutine);
static PRY_PROC_NOTIFY_SET_FN PryProcSetEx;   // PsSetCreateProcessNotifyRoutineEx
static PRY_PROC_NOTIFY_RM_FN PryProcRemoveEx; // PsRemoveCreateProcessNotifyRoutineEx
static PRY_PROC_NOTIFY_SET_FN PryProcSet;     // PsSetCreateProcessNotifyRoutine
static PRY_PROC_NOTIFY_RM_FN PryProcRemove;   // PsRemoveCreateProcessNotifyRoutine
NTKERNELAPI NTSTATUS PsSetLoadImageNotifyRoutine(_In_ PVOID NotifyRoutine);
NTKERNELAPI NTSTATUS PsRemoveLoadImageNotifyRoutine(_In_ PVOID NotifyRoutine);

// v10 notify ring: the agent's "ears". PsSet{CreateProcess,CreateThread,
// LoadImage}NotifyRoutine callbacks append fixed-size records to a static
// overwrite-oldest ring; NOTIFY_READ drains oldest-first under the spinlock.
//
// Callback contract: they run at <=DISPATCH_LEVEL in an arbitrary process
// context while the process/thread/image machinery holds its own locks.
// The only legal work here is a bounded spinlock-guarded copy — no Zw*,
// no paging, no allocation, no logging. The ring never blocks the
// notifying thread: on overflow the oldest record is overwritten and
// PryEvtDropped counts the loss so readers can report the gap honestly.

static PRY_EVT PryEvtRing[PRY_EVT_RING];
static KSPIN_LOCK PryEvtLock;
static UINT32 PryEvtHead;         // next write slot
static UINT32 PryEvtBuffered;     // entries currently in the ring
static UINT64 PryEvtNextSeq = 1;  // next seq to issue
static UINT64 PryEvtDropped;      // overwrite-oldest counter
static UINT64 PryEvtTotal;        // cumulative events appended
static volatile UINT32 PryEvtSubscribed; // registered class bitmask
static volatile LONG PryEvtInFlight;     // callbacks executing

// registration state: 0 = not registered, 1 = Ex variant, 2 = classic
static volatile LONG PryRegProc;
static volatile LONG PryRegImage;
static volatile LONG PryRegThread;

VOID PryNotifyInit(VOID)
{
    KeInitializeSpinLock(&PryEvtLock);
    PryEvtHead = 0;
    PryEvtBuffered = 0;
    PryEvtNextSeq = 1;
    PryEvtDropped = 0;
    PryEvtTotal = 0;
    PryEvtSubscribed = 0;
    PryEvtInFlight = 0;
    PryRegProc = 0;
    PryRegImage = 0;
    PryRegThread = 0;

    // runtime-resolve the process-notify registry entry points (missing
    // from the WDK import lib; see the comment above)
    {
        UNICODE_STRING s;
        RtlInitUnicodeString(&s, L"PsSetCreateProcessNotifyRoutineEx");
        PryProcSetEx = (PRY_PROC_NOTIFY_SET_FN)MmGetSystemRoutineAddress(&s);
        RtlInitUnicodeString(&s, L"PsRemoveCreateProcessNotifyRoutineEx");
        PryProcRemoveEx = (PRY_PROC_NOTIFY_RM_FN)MmGetSystemRoutineAddress(&s);
        RtlInitUnicodeString(&s, L"PsSetCreateProcessNotifyRoutine");
        PryProcSet = (PRY_PROC_NOTIFY_SET_FN)MmGetSystemRoutineAddress(&s);
        RtlInitUnicodeString(&s, L"PsRemoveCreateProcessNotifyRoutine");
        PryProcRemove = (PRY_PROC_NOTIFY_RM_FN)MmGetSystemRoutineAddress(&s);
    }
}

// shared ring-write tail: caller holds PryEvtLock (at whatever IRQL it
// was acquired — the routine itself is IRQL-agnostic).
// v14 (SI #25): WatchCookie populated for BP_HIT records fired against
// an IS_WATCH entry (0 otherwise). Zero-init'd by the RtlZeroMemory
// below for non-BP kinds.
static VOID PryEvtAppendLocked(_In_ UINT64 TsMs, _In_ UINT32 Kind,
                                 _In_ UINT32 Pid, _In_ UINT32 ParentPid,
                                 _In_ UINT32 Tid, _In_ UINT64 ImageBase,
                                 _In_ UINT64 ImageSize, _In_ PCWSTR Image,
                                 _In_ UINT64 Address, _In_ UINT64 Dr6,
                                 _In_ UINT32 BpId, _In_ UINT32 Slot,
                                 _In_ UINT32 Access, _In_ UINT32 Irql,
                                 _In_ UINT32 WatchCookie)
{
    PRY_EVT* e;

    e = &PryEvtRing[PryEvtHead];
    RtlZeroMemory(e, sizeof(*e));
    e->Seq = PryEvtNextSeq++;
    // TsMs is interrupt-time milliseconds captured by the caller at event
    // entry, before waiting for the ring lock. The ABI field is unchanged.
    e->TsMs = TsMs;
    e->Kind = Kind;
    e->Pid = Pid;
    e->ParentPid = ParentPid;
    e->Tid = Tid;
    e->ImageBase = ImageBase;
    e->ImageSize = ImageSize;
    e->Address = Address;
    e->Dr6 = Dr6;
    e->BpId = BpId;
    e->Slot = Slot;
    e->Access = Access;
    e->Irql = Irql;
    e->WatchCookie = WatchCookie;
    if (Image) {
        SIZE_T cch = 0;
        while (cch < PRY_EVT_IMAGE_CCH - 1 && Image[cch]) {
            cch++;
        }
        RtlCopyMemory(e->Image, Image, cch * sizeof(WCHAR));
    }
    PryEvtHead = (PryEvtHead + 1) % PRY_EVT_RING;
    if (PryEvtBuffered < PRY_EVT_RING) {
        PryEvtBuffered++;
    } else {
        PryEvtDropped++; // head overwrote the oldest entry
    }
    PryEvtTotal++;
}

static VOID PryEvtAppend(UINT32 Kind, UINT32 Pid, UINT32 ParentPid, UINT32 Tid,
                           UINT64 ImageBase, UINT64 ImageSize, PCWSTR Image)
{
    KIRQL irql;
    UINT64 tsMs = KeQueryInterruptTime() / 10000;

    // kind -> owning class (the subscription bitmask is class-grained)
    switch (Kind) {
    case PRY_EVT_KIND_PROC_CREATE:
    case PRY_EVT_KIND_PROC_EXIT:
        if (!(PryEvtSubscribed & PRY_EVT_CLASS_PROC)) return;
        break;
    case PRY_EVT_KIND_IMAGE_LOAD:
        if (!(PryEvtSubscribed & PRY_EVT_CLASS_IMAGE)) return;
        break;
    case PRY_EVT_KIND_THREAD_CREATE:
    case PRY_EVT_KIND_THREAD_EXIT:
        if (!(PryEvtSubscribed & PRY_EVT_CLASS_THREAD)) return;
        break;
    default:
        return;
    }
    InterlockedIncrement(&PryEvtInFlight);

    KeAcquireSpinLock(&PryEvtLock, &irql);
    PryEvtAppendLocked(tsMs, Kind, Pid, ParentPid, Tid, ImageBase, ImageSize,
                         Image, 0, 0, 0, 0xFF, 0, 0, 0);
    KeReleaseSpinLock(&PryEvtLock, irql);
    InterlockedDecrement(&PryEvtInFlight);
}

// v11: BP_HIT append from the int1 trap path (BpTrap.c). Callable at any
// IRQL — the trap handler may run at DISPATCH or above, where a raising
// acquire would corrupt IRQL — so at DISPATCH+ the lock is try-acquired
// and a contention loss is counted via PryBpTrapMissed instead of
// spinning (the alternative is a deadlock when the lock holder lives on
// the same CPU).
VOID PryEvtAppendBpHit(_In_ UINT64 HitTsMs, _In_ UINT32 Pid, _In_ UINT32 Tid,
                         _In_ UINT64 Rip, _In_ UINT64 Dr6, _In_ UINT32 BpId, _In_ UINT32 Slot,
                         _In_ UINT32 Access, _In_ UINT32 Irql,
                         _In_ UINT32 WatchCookie)
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    BOOLEAN locked = FALSE;

    if (!(PryEvtSubscribed & PRY_EVT_CLASS_BP)) {
        return;
    }
    InterlockedIncrement(&PryEvtInFlight);
    if (Irql < DISPATCH_LEVEL) {
        KeAcquireSpinLock(&PryEvtLock, &oldIrql);
        locked = TRUE;
    } else {
        locked = KeTryToAcquireSpinLockAtDpcLevel(&PryEvtLock);
    }
    if (!locked) {
        InterlockedIncrement(&PryBpTrapMissed);
        InterlockedDecrement(&PryEvtInFlight);
        return;
    }
    PryEvtAppendLocked(HitTsMs, PRY_EVT_KIND_BP_HIT, Pid, 0, Tid,
                         0, 0, NULL, Rip, Dr6, BpId, Slot, Access, Irql,
                         WatchCookie);
    if (Irql < DISPATCH_LEVEL) {
        KeReleaseSpinLock(&PryEvtLock, oldIrql);
    } else {
        KeReleaseSpinLockFromDpcLevel(&PryEvtLock);
    }
    InterlockedDecrement(&PryEvtInFlight);
}

// --- process notify (Ex preferred: carries the image path; classic fallback)
// NOTE: the Ex callback signature is (PEPROCESS, HANDLE ProcessId,
// PS_CREATE_NOTIFY_INFO*) — three parameters. A two-parameter callback
// misreads ProcessId as CreateInfo and dereferences a HANDLE as a pointer
// on the first process event (bugcheck — learned the hard way).

static VOID PryOnEvtProcEx(_In_ PEPROCESS Process, _In_ HANDLE ProcessId,
                             _Inout_ PS_CREATE_NOTIFY_INFO* CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UINT32 pid = (UINT32)(ULONG_PTR)ProcessId;
    if (CreateInfo) {
        PCWSTR img = (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer)
                         ? CreateInfo->ImageFileName->Buffer : NULL;
        PryEvtAppend(PRY_EVT_KIND_PROC_CREATE, pid,
                       (UINT32)(ULONG_PTR)CreateInfo->ParentProcessId, 0,
                       0, 0, img);
    } else {
        PryEvtAppend(PRY_EVT_KIND_PROC_EXIT, pid, 0, 0, 0, 0, NULL);
    }
}

static VOID PryOnEvtProcClassic(_In_ HANDLE ParentId, _In_ HANDLE ProcessId,
                                  _In_ BOOLEAN Create)
{
    PryEvtAppend(Create ? PRY_EVT_KIND_PROC_CREATE : PRY_EVT_KIND_PROC_EXIT,
                   (UINT32)(ULONG_PTR)ProcessId, (UINT32)(ULONG_PTR)ParentId,
                   0, 0, 0, NULL);
}

// --- image load notify (fires for kernel images too, so driver loads
// surface as IMAGE_LOAD events with SystemModeImage set in the name path)

static VOID PryOnEvtImage(_In_opt_ PUNICODE_STRING FullImageName,
                            _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
    PryEvtAppend(PRY_EVT_KIND_IMAGE_LOAD,
                   (UINT32)(ULONG_PTR)ProcessId, 0, 0,
                   (UINT64)ImageInfo->ImageBase, ImageInfo->ImageSize,
                   FullImageName ? FullImageName->Buffer : NULL);
}

// --- thread notify (classic variant; coexists with the BP feature's own
// registration — the OS allows up to 64 notify callbacks)

static VOID PryOnEvtThread(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId,
                             _In_ BOOLEAN Create)
{
    PryEvtAppend(Create ? PRY_EVT_KIND_THREAD_CREATE : PRY_EVT_KIND_THREAD_EXIT,
                   (UINT32)(ULONG_PTR)ProcessId, 0, (UINT32)(ULONG_PTR)ThreadId,
                   0, 0, NULL);
}

NTSTATUS PryNotifySubscribe(_In_ UINT32 Classes, _In_ UINT32 Flags,
                              _Out_ UINT32* Registered)
{
    NTSTATUS st;
    // Classes=0 means "all" — but the BP class installs an IDT hook, so it
    // is excluded from the wildcard: callers must name CLASS_BP explicitly
    // AND pass FLAG_BP_HOOK_OK.
    UINT32 want = Classes ? Classes : (PRY_EVT_CLASS_ALL & ~PRY_EVT_CLASS_BP);
    UINT32 ok = 0;
    NTSTATUS bpSt = STATUS_SUCCESS;

    *Registered = 0;

    if (want & PRY_EVT_CLASS_PROC && !PryRegProc) {
        if (!PryProcSetEx || !PryProcSet) {
            PryLog("notify: proc routines unresolved (skipping proc class)");
        } else {
            st = PryProcSetEx(PryOnEvtProcEx, FALSE);
            if (NT_SUCCESS(st)) {
                PryRegProc = 1;
            } else {
                st = PryProcSet(PryOnEvtProcClassic, FALSE);
                if (!NT_SUCCESS(st)) {
                    PryLog("notify: proc register failed st=%x", st);
                    return st;
                }
                PryRegProc = 2;
                PryLog("notify: proc Ex refused, classic registered (no image path)");
            }
        }
    }
    if (want & PRY_EVT_CLASS_PROC) {
        ok |= PRY_EVT_CLASS_PROC;
    }

    if (want & PRY_EVT_CLASS_IMAGE && !PryRegImage) {
        st = PsSetLoadImageNotifyRoutine(PryOnEvtImage);
        if (!NT_SUCCESS(st)) {
            PryLog("notify: image register failed st=%x", st);
            return st;
        }
        PryRegImage = 1;
    }
    if (want & PRY_EVT_CLASS_IMAGE) {
        ok |= PRY_EVT_CLASS_IMAGE;
    }

    if (want & PRY_EVT_CLASS_THREAD && !PryRegThread) {
        st = PsSetCreateThreadNotifyRoutine(PryOnEvtThread);
        if (!NT_SUCCESS(st)) {
            PryLog("notify: thread register failed st=%x", st);
            return st;
        }
        PryRegThread = 1;
    }
    if (want & PRY_EVT_CLASS_THREAD) {
        ok |= PRY_EVT_CLASS_THREAD;
    }

    // v11: CLASS_BP = the int1 hook, not a Ps callback. Refused without
    // FLAG_BP_HOOK_OK (IDT patching is PG-sensitive) and under HVCI
    // (install itself fails there). A refused/failed BP class does not
    // sink the other classes — the bit's absence in *Registered is the
    // honest signal; bpSt propagates when BP was the sole request.
    if (want & PRY_EVT_CLASS_BP) {
        if (!(Flags & PRY_NOTIFY_FLAG_BP_HOOK_OK)) {
            PryLog("notify: CLASS_BP refused (no FLAG_BP_HOOK_OK)");
            bpSt = STATUS_ACCESS_DENIED;
        } else {
            bpSt = PryBpTrapInstall();
            if (NT_SUCCESS(bpSt)) {
                ok |= PRY_EVT_CLASS_BP;
            } else {
                PryLog("notify: CLASS_BP install failed st=%x", bpSt);
            }
        }
    }

    InterlockedOr((volatile LONG*)&PryEvtSubscribed, ok);
    PryLog("notify subscribe want=%x flags=%x ok=%x bpSt=%x", want, Flags,
             ok, bpSt);
    *Registered = ok;
    if (!NT_SUCCESS(bpSt) && !(ok & ~PRY_EVT_CLASS_BP)) {
        return bpSt; // BP was the only class asked for — surface it
    }
    return STATUS_SUCCESS;
}

NTSTATUS PryNotifyDisable(VOID)
{
    // a HW breakpoint's DR0-3 stay armed on their
    // owning thread(s) whether or not the int1 hook below is installed.
    // Pulling the hook (PryBpTrapUninstall) while any are still armed
    // turns their next #DB into an unhandled trap -- no subscriber, no
    // handler, bugcheck. Refuse outright instead of tearing anything
    // down; the caller must clear every HW bp first (BP_HW_CLEAR), or
    // let PryBpCleanup do it at unload, which zeroes PryBpHwArmed
    // before ever reaching this call.
    if (InterlockedCompareExchange(&PryBpHwArmed, 0, 0) != 0) {
        PryLog("NOTIFY_DISABLE refused: %ld HW breakpoint(s) still armed",
                 PryBpHwArmed);
        return STATUS_DEVICE_BUSY;
    }

    // Snapshot-then-clear: each registered callback is removed exactly once.
    // InterlockedExchange returns the previous value, so a concurrent
    // DISABLE cannot double-remove.
    LONG proc = InterlockedExchange(&PryRegProc, 0);
    LONG img = InterlockedExchange(&PryRegImage, 0);
    LONG thr = InterlockedExchange(&PryRegThread, 0);

    if (proc == 1) {
        if (PryProcRemoveEx) {
            PryProcRemoveEx(PryOnEvtProcEx);
        }
    } else if (proc == 2) {
        if (PryProcRemove) {
            PryProcRemove(PryOnEvtProcClassic);
        }
    }
    if (img) {
        PsRemoveLoadImageNotifyRoutine(PryOnEvtImage);
    }
    if (thr) {
        PsRemoveCreateThreadNotifyRoutine(PryOnEvtThread);
    }

    // bounded in-flight drain: callbacks may still run on other CPUs
    {
        LARGE_INTEGER interval;
        ULONG waitedMs = 0;
        while (PryEvtInFlight > 0 && waitedMs < 5000) {
            interval.QuadPart = -10 * 1000; // 1 ms
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
            waitedMs++;
        }
        if (PryEvtInFlight > 0) {
            PryLog("NOTIFY WARNING: %d callback(s) still in flight", PryEvtInFlight);
        }
    }
    // v11: drop the int1 hook before ungating the class bit — hits during
    // teardown chain to KiTrap01 rather than recording into a dead ring.
    InterlockedAnd((volatile LONG*)&PryEvtSubscribed, ~PRY_EVT_CLASS_BP);
    PryBpTrapUninstall();

    InterlockedExchange((volatile LONG*)&PryEvtSubscribed, 0);
    PryLog("notify disabled (buffered=%u dropped=%llu)",
             PryEvtBuffered, PryEvtDropped);
    return STATUS_SUCCESS;
}

NTSTATUS PryNotifyRead(_In_ UINT32 Max, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                         _Out_ PUINT64 Dropped, _Out_ PUINT64 LastSeq)
{
    KIRQL irql;
    PPRY_EVT out = (PPRY_EVT)Buffer;
    UINT32 cap, n = 0, tail;

    *Count = 0;
    *Dropped = 0;
    *LastSeq = 0;
    cap = (UINT32)(CapacityBytes / sizeof(PRY_EVT));
    if (cap > PRY_EVT_RING) {
        cap = PRY_EVT_RING;
    }
    if (Max && cap > Max) {
        cap = Max;
    }

    KeAcquireSpinLock(&PryEvtLock, &irql);
    tail = (PryEvtHead + PRY_EVT_RING - PryEvtBuffered) % PRY_EVT_RING;
    while (n < cap && PryEvtBuffered > 0) {
        RtlCopyMemory(&out[n], &PryEvtRing[tail], sizeof(PRY_EVT));
        tail = (tail + 1) % PRY_EVT_RING;
        PryEvtBuffered--;
        n++;
    }
    *Dropped = PryEvtDropped;
    if (n) {
        *LastSeq = out[n - 1].Seq;
    }
    KeReleaseSpinLock(&PryEvtLock, irql);
    *Count = n;
    return STATUS_SUCCESS;
}

NTSTATUS PryNotifyStats(_Out_ PRY_NOTIFY_STATS_OUT* Out)
{
    KIRQL irql;
    RtlZeroMemory(Out, sizeof(*Out));
    KeAcquireSpinLock(&PryEvtLock, &irql);
    Out->Buffered = PryEvtBuffered;
    Out->Dropped = PryEvtDropped;
    Out->Seq = PryEvtNextSeq - 1;
    Out->Total = PryEvtTotal;
    KeReleaseSpinLock(&PryEvtLock, irql);
    Out->Registered = PryEvtSubscribed;
    Out->ProcVariant = (UINT32)PryRegProc;
    Out->BpTrapMissed = (UINT32)InterlockedCompareExchange(&PryBpTrapMissed, 0, 0);
    return STATUS_SUCCESS;
}
