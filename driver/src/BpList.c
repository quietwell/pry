#include "PryDriver.h"

// Shared breakpoint-table storage plus init/list/cleanup entry points.
// SW set/clear + table alloc/find helpers live in BpSw.c; DR-based HW
// arming plus thread-create notification live in BpHw.c. Split is
// mechanical — logic and locking policy unchanged.

PRY_BP_REC PryBpTable[PRY_MAX_BP];
KSPIN_LOCK PryBpLock;
UINT32 PryBpNextId = 1;
volatile LONG PryBpThreadNotifyRegistered = 0;
volatile LONG PryThreadNotifyActive = 0;
// v11: live HW-bp record count. Read lock-free by the int1 dispatch path
// when the table spinlock is out of reach (>DISPATCH_LEVEL hits).
volatile LONG PryBpHwArmed = 0;

VOID PryBpInit(VOID)
{
    KeInitializeSpinLock(&PryBpLock);
}

NTSTATUS PryBpList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                     _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    KIRQL irql;
    UINT32 i, outIdx = 0;
    UINT32 cap = (UINT32)(CapacityBytes / sizeof(PRY_BP_ENTRY));
    PPRY_BP_ENTRY out = (PPRY_BP_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;

    KeAcquireSpinLock(&PryBpLock, &irql);
    for (i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        if (!r->Used || !r->Enabled) {
            continue;
        }
        if (outIdx < cap && out) {
            out[outIdx].Id = r->Id;
            out[outIdx].Kind = r->Kind;
            out[outIdx].Pid = r->Pid;
            out[outIdx].Tid = r->Tid;
            out[outIdx].Slot = r->Slot;
            out[outIdx].Length = r->Length;
            out[outIdx].Access = r->Access;
            out[outIdx].Enabled = r->Enabled;
            out[outIdx].Address = r->Address;
            out[outIdx].OrigByte = r->OrigByte;
            // v14 (SI #25): watch surface — IsWatch byte + WatchCookie u32
            // ride in the Reserved tail (same wire bytes, same layout size).
            out[outIdx].IsWatch = (UCHAR)(r->IsWatch ? 1u : 0u);
            RtlZeroMemory(out[outIdx].Reserved, sizeof(out[outIdx].Reserved));
            out[outIdx].WatchCookie = r->WatchCookie;
            outIdx++;
        }
        (*Required)++;
    }
    KeReleaseSpinLock(&PryBpLock, irql);
    *Count = outIdx;
    return *Required > outIdx ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

// direct best-effort restore used only from
// PryBpCleanup below. By the time it runs, the table slot is already
// freed (Used/Enabled cleared under the same lock that took this
// snapshot -- a racing armer must never observe a half-torn-down
// record), so PryBpSwClear's own lookup (PryBpFindSwLocked, which
// requires Used && Enabled) can never find the record: the original bug
// here left every live 0xCC breakpoint byte planted in the target
// forever. Restore straight from the snapshot instead -- same attach +
// verify-0xCC + write-back sequence, minus table bookkeeping (nothing to
// free: the slot is already free). Routes a kernel address through the
// guarded kernel write path for the same reason PryBpSwSet/Clear now
// do: a raw store under __try can bugcheck on a resident read-only
// kernel page, outside any __except.
static VOID PryBpCleanupRestoreSw(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UCHAR OrigByte)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;

    if (!PryUserRangeOk(Address, 1)) {
        UCHAR cur = 0;
        SIZE_T done = 0;
        UINT8 writePath = 0;
        st = PryKernelMemRead(Address, &cur, sizeof(cur), &done, 0);
        if (NT_SUCCESS(st) && done == sizeof(cur)) {
            if (cur == 0xCC) {
                PryKernelMemWrite(Address, &OrigByte, sizeof(OrigByte), &done, 0, 0, &writePath);
            } else {
                PryLog("BPCLEANUP sw mismatch(kernel) addr=%llx cur=%02x", Address, (UINT32)cur);
            }
        }
        return;
    }

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return; // process is gone: the 0xCC went with its address space
    }
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        volatile UCHAR* p = (volatile UCHAR*)(ULONG_PTR)Address;
        if (*p == 0xCC) {
            *p = OrigByte;
        } else {
            PryLog("BPCLEANUP sw mismatch addr=%llx cur=%02x", Address, (UINT32)*p);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        PryLog("BPCLEANUP sw except addr=%llx st=%x", Address, GetExceptionCode());
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
}

VOID PryBpCleanup(VOID)
{
    // Best-effort teardown of every live breakpoint before the caller
    // (PryEvtDriverUnload) pulls the int1 hook:
    //   - SW: restore the original byte straight from the snapshot taken
    //     below (see PryBpCleanupRestoreSw for why the lookup-based
    //     PryBpSwClear can't be used here).
    //   - HW: clear DR0-3/DR7 + the per-thread gate via the same remote-
    //     APC worker a live BP_HW_CLEAR uses (PryBpHwClearDr), then
    //     sweep every process's debug-active gate (PryBpHwClearAllGates
    //     -- covers a Global bp, whose touched-process set is never
    //     tracked). Both must finish, and every APC either one queues
    //     must drain, before the caller removes the int1 hook: a HW bp
    //     still live when that hook goes away turns its next #DB into an
    //     unhandled trap (bugcheck). The drain-wait below guarantees
    //     that ordering without DriverEntry.c having to know about it --
    //     by the time this function returns, PryApcOutstanding is 0 or
    //     the wait has already logged why it couldn't get there.
    UINT32 i;
    KIRQL irql;
    PRY_BP_REC snapshot[PRY_MAX_BP];
    UINT32 snapCount = 0;
    BOOLEAN anyHw = FALSE;
    ULONG waitedMs;
    LARGE_INTEGER interval;

    KeAcquireSpinLock(&PryBpLock, &irql);
    for (i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        if (r->Used && r->Enabled &&
            (r->Kind == PRY_BP_KIND_SW || r->Kind == PRY_BP_KIND_HW)) {
            snapshot[snapCount++] = *r;
        }
        r->Used = 0;
        r->Enabled = 0;
    }
    PryBpHwArmed = 0;
    KeReleaseSpinLock(&PryBpLock, irql);

    for (i = 0; i < snapCount; i++) {
        if (snapshot[i].Kind == PRY_BP_KIND_SW) {
            PryBpCleanupRestoreSw(snapshot[i].Pid, snapshot[i].Address, snapshot[i].OrigByte);
        } else {
            UINT32 applied = 0;
            PryBpHwClearDr(&snapshot[i], &applied);
            anyHw = TRUE;
        }
    }
    if (anyHw) {
        PryBpHwClearAllGates();
    }

    // Drain outstanding remote-call APCs (queued just above by
    // PryBpHwClearDr, or already in flight from a set/clear racing the
    // start of unload) before the caller removes int1 -- bounded the
    // same way every other unload drain in this driver is.
    waitedMs = 0;
    while (PryApcOutstanding > 0 && waitedMs < 5000) {
        interval.QuadPart = -10 * 1000; // 1 ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        waitedMs++;
    }
    if (PryApcOutstanding > 0) {
        PryLog("BPCLEANUP WARNING: %d APC(s) still queued - HW bp state may not be fully clear",
                 PryApcOutstanding);
    }
}
