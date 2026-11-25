#include "PryDriver.h"
#include <intrin.h>

// Hardware (DR0-3/DR7) breakpoints: DR7 bit layout, DebugActive gate,
// kernel-APC DR arming worker, per-thread apply/clear callbacks, plus
// the public PryBpHw{Set,Clear} entry points and the thread-create
// notification that reaches threads born after the bp was set.
//
// see the notes at each change:
//   * a record arms and clears only threads of its own live process
//     (PryBpRecOwnsThread);
//   * a set publishes its record before the first thread is armed;
//   * a clear keeps the record claimable until its DR clears have run
//     (PryBpHwClearTracked), and only then frees it;
//   * an explicit slot that a live record holds is refused, never overwritten;
//   * the DR slot's bits are read-modify-written, never replaced wholesale;
//   * records of an exiting process are reaped (PryBpOnProcessExitEx).

// Serializes record-scope arm/clear walks, including thread-create arming.
// This is a KMUTEX (not a fast mutex): normal APCs must remain deliverable
// while a set/clear aimed at the calling thread waits for completion.
static KMUTEX PryBpHwOpMutex;

VOID PryBpHwInit(VOID)
{
    KeInitializeMutex(&PryBpHwOpMutex, 0);
}

// Context op declared in Context.c: attaches to the target process and runs
// PsSet/GetContextThread(UserMode) through the user-APC machinery so the
// kernel's DR filter accepts the write. Seeding the per-thread saved DR
// context is what makes a live-register arm survive the next context switch
// on 26200.6965 -- the DebugActive gate alone is not enough there.
NTSTATUS PryThreadCtxOp(_In_ PETHREAD Thread, _Inout_ PCONTEXT Ctx, _In_ BOOLEAN Set);

#ifndef ThreadSuspendCount
#define ThreadSuspendCount 35
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif
NTKERNELAPI NTSTATUS ZwQueryInformationThread(_In_ HANDLE ThreadHandle,
                                              _In_ ULONG ThreadInformationClass,
                                              _Out_ PVOID ThreadInformation,
                                              _In_ ULONG ThreadInformationLength,
                                              _Out_opt_ PULONG ReturnLength);

// True when the thread has any outstanding suspend (NtSuspendProcess /
// NtSuspendThread) -- distinct from PsGetThreadFreezeCount, which only
// catches the debug-stop and fibre-freeze flavours. A suspended thread
// cannot deliver the user APC that PryThreadCtxOp waits on, so caller
// paths that would otherwise block need this signal.
static BOOLEAN PryThreadIsSuspended(_In_ PETHREAD Thread)
{
    HANDLE h = NULL;
    ULONG count = 0, ret = 0;
    NTSTATUS st;

    st = ObOpenObjectByPointer(Thread, OBJ_KERNEL_HANDLE, NULL,
                               THREAD_QUERY_INFORMATION, *PsThreadType, KernelMode, &h);
    if (!NT_SUCCESS(st)) {
        return FALSE; // can't tell -- let the caller try (it still has its own guards)
    }
    st = ZwQueryInformationThread(h, ThreadSuspendCount, &count, sizeof(count), &ret);
    ZwClose(h);
    return NT_SUCCESS(st) && count > 0;
}

static UINT64 PryDr7Bits(_In_ UINT32 Slot, _In_ UINT32 Len, _In_ UINT32 Access)
{
    UINT64 rw, ln;

    switch (Access) {
    case PRY_HW_WRITE: rw = 1; break;
    case PRY_HW_RW: rw = 3; break;
    case PRY_HW_EXEC:
    default: rw = 0; break;
    }
    switch (Len) {
    case 2: ln = 1; break;
    case 8: ln = 2; break;
    case 4: ln = 3; break;
    case 1:
    default: ln = 0; break;
    }
    // DR7 local-enable bits are L0..L3 = bits 0,2,4,6 (bit 2*slot) --
    // interleaved with the global-enable Gn bits at 2*slot+1, which this
    // driver never sets. RWn/LENn pairs start at bit 16 with 4 bits per
    // slot.
    return (1ull << (Slot * 2)) |
           (rw << (16 + Slot * 4)) |
           (ln << (18 + Slot * 4));
}

// every DR7 bit that belongs to one slot: its L bit plus RW and LEN.
static UINT64 PryDr7SlotMask(_In_ UINT32 Slot)
{
    return (1ull << (Slot * 2)) | (0xFull << (16 + Slot * 4));
}

// ---- kernel-APC DR arming ------------------------------------
// PsSetContextThread(CONTEXT_DEBUG_REGISTERS) does not stick on 26200.1
// (verified: read-back returns 0/0 after the set, 6x20ms retries). The
// reliable mechanism is a kernel normal APC that runs ON the target thread
// and writes the debug registers directly against the live CPU state.
// Reuses the PryRemoteCall APC machinery from RemoteCall.c: the "target"
// function is PryDrArmWorker below, executed on the target thread in
// kernel mode with (slot|clear, address, dr7bits) marshalled through the
// three remote-call arguments.

// ---- DebugActive gate -----------------------------------------
// Root cause of the non-persistence bug: on 26200.1 the kernel filters
// DR state for threads whose dispatcher-header DebugActive byte is clear
// (bit0 = ActiveDR7). PsSetContextThread drops the write (read-back 0/0),
// and a kernel-mode __writedr from the ARM APC is undone at the next
// context switch because the kernel restores the thread's saved (zeroed)
// DR state. Offsets from ntkrnlmp.pdb 72C69E72-6C64-8BC1-8257-AF38FA78A2F2
// age 1 (26200.1): _KTHREAD.Header.DebugActive = KTHREAD+0x03;
// _EPROCESS.Pcb shares the dispatcher header layout, EPROCESS+0x03.
// Setting bit0 marks the thread DR-active: the kernel then saves/restores
// live DRs across switches and the CONTEXT_DEBUG_REGISTERS path un-filters.
// the earlier "harmless for a lab" claim is wrong on Win11 25H2.
// Leaving _EPROCESS.Pcb.DebugActive set after the last HW BP is cleared
// has the kernel's process-teardown path (nt+0x48ef4d on 26200.6965)
// dereference the (null) debug port and bugcheck IRQL_NOT_LESS_OR_EQUAL
// at DISPATCH_LEVEL. We now clear the thread gate from the arm APC when
// its DR7 L0..L3 are all zero, and the process gate from PryBpHwClear
// once the last HW BP for the pid is gone (bp lock held).
#define PRY_DBGACTIVE_OFFSET 0x03
#define PRY_DBGACTIVE_ACTIVEDR7 0x01

static VOID PryDrGateEnable(_In_ PEPROCESS Proc, _In_ PETHREAD Thread)
{
    volatile UCHAR* tGate = (volatile UCHAR*)((ULONG_PTR)Thread + PRY_DBGACTIVE_OFFSET);
    volatile UCHAR* pGate = (volatile UCHAR*)((ULONG_PTR)Proc + PRY_DBGACTIVE_OFFSET);
    UCHAR before = *tGate;
    InterlockedOr8((volatile CHAR*)tGate, PRY_DBGACTIVE_ACTIVEDR7);
    InterlockedOr8((volatile CHAR*)pGate, PRY_DBGACTIVE_ACTIVEDR7);
    if (!(before & PRY_DBGACTIVE_ACTIVEDR7)) {
        PryLog("DRGATE tid=%llu Header.DebugActive 0->1 (process gate too)",
                 (UINT64)(ULONG_PTR)PsGetThreadId(Thread));
    }
}

static VOID PryDrGateDisableCurrentThread(VOID)
{
    volatile UCHAR* tGate = (volatile UCHAR*)((ULONG_PTR)PsGetCurrentThread() + PRY_DBGACTIVE_OFFSET);
    UCHAR before = *tGate;
    InterlockedAnd8((volatile CHAR*)tGate, (CHAR)~PRY_DBGACTIVE_ACTIVEDR7);
    if (before & PRY_DBGACTIVE_ACTIVEDR7) {
        PryLog("DRGATE tid=%llu Header.DebugActive 1->0 (last-slot clear)",
                 (UINT64)(ULONG_PTR)PsGetCurrentThreadId());
    }
}

static VOID PryDrGateDisableProcess(_In_ PEPROCESS Proc)
{
    volatile UCHAR* pGate = (volatile UCHAR*)((ULONG_PTR)Proc + PRY_DBGACTIVE_OFFSET);
    UCHAR before = *pGate;
    InterlockedAnd8((volatile CHAR*)pGate, (CHAR)~PRY_DBGACTIVE_ACTIVEDR7);
    if (before & PRY_DBGACTIVE_ACTIVEDR7) {
        PryLog("DRGATE pid=%llu Pcb.DebugActive 1->0 (no HW BPs remain)",
                 (UINT64)(ULONG_PTR)PsGetProcessId(Proc));
    }
}

// Runs on the target thread (kernel APC normal routine). a1 = slot | clear<<8,
// a2 = address (arm), a3 = the slot's DR7 bits: OR'd in to arm, cleared out
// to disarm. Only the slot's own L/RW/LEN fields are touched, so other
// slots armed on the thread keep their state.
VOID PryDrArmWorker(UINT64 a1, UINT64 a2, UINT64 a3)
{
    ULONG slot = (ULONG)(a1 & 0xFF);
    BOOLEAN clear = (a1 >> 8) & 1;
    UINT64 dr7Before;
    UINT64 dr7After;

    // This target-thread APC is deliberately the ONLY writer used by the HW
    // arm/clear paths. Ps{Get,Set}ContextThread supplies a saved snapshot;
    // writing that snapshot can restore an older DR7 after another slot has
    // already been armed. Read-modify-write the live registers instead.
    if (!clear) {
        // A previous last-record clear may have dropped either gate. Re-arm
        // both on every arm, before making the new DR state live.
        PryDrGateEnable(PsGetCurrentProcess(), PsGetCurrentThread());
    }
    dr7Before = __readdr(7);
    if (clear) {
        switch (slot) {
        case 0: __writedr(0, 0); break;
        case 1: __writedr(1, 0); break;
        case 2: __writedr(2, 0); break;
        case 3: __writedr(3, 0); break;
        }
        // Clear only this slot's L/RW/LEN fields. In particular slot 3 is
        // L3=bit 6 and RW3/LEN3=bits 28-31; no other slot is disturbed.
        dr7After = dr7Before & ~PryDr7SlotMask(slot);
        __writedr(7, dr7After);
        dr7After = __readdr(7);
    } else {
        switch (slot) {
        case 0: __writedr(0, a2); break;
        case 1: __writedr(1, a2); break;
        case 2: __writedr(2, a2); break;
        case 3: __writedr(3, a2); break;
        }
        dr7After = (dr7Before & ~PryDr7SlotMask(slot)) | a3;
        __writedr(7, dr7After);
        dr7After = __readdr(7);
    }
    PryLog("DRCTL %s pid=%llu tid=%llu slot=%u dr7_before=%llx dr7_after=%llx",
             clear ? "clear" : "arm",
             (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
             (UINT64)(ULONG_PTR)PsGetCurrentThreadId(), slot, dr7Before, dr7After);

    // Last-slot clear drops the thread gate only after the DR7 write and
    // read-back. Any still-enabled sibling slot keeps the gate set.
    if (clear && (dr7After & 0x55) == 0) {
        PryDrGateDisableCurrentThread();
    }
}

// a non-global record owns only threads of its own live process:
// the same PID and, when the record was pinned at set time, the very same
// EPROCESS -- so a PID recycled after an exit can never inherit a record.
// Global records own every thread, as before.
static BOOLEAN PryBpRecOwnsThread(_In_ const PRY_BP_REC* Rec, _In_ PETHREAD Thread)
{
    PEPROCESS proc;

    if (Rec->Global) {
        return TRUE;
    }
    if (!Rec->Pid) {
        return FALSE;
    }
    proc = IoThreadToProcess(Thread);
    if (!proc || (UINT32)(ULONG_PTR)PsGetProcessId(proc) != Rec->Pid) {
        return FALSE;
    }
    return Rec->ProcKey == 0 || Rec->ProcKey == (UINT64)(ULONG_PTR)proc;
}

// Completion tracking shared by arm and clear APCs. Refs holds the issuing
// call plus one reference per APC; a bounded wait can therefore time out
// without leaving a late APC pointing at freed stack. Error preserves a hard
// queue refusal that the thread-enumeration helper would otherwise hide when
// another thread succeeded.
typedef struct _PRY_BP_APC_TRACK {
    volatile LONG Refs;
    volatile LONG Pending;
    volatile LONG Error;
} PRY_BP_APC_TRACK;

typedef struct _PRY_BP_ARM_JOB {
    PRY_BP_REC Rec;
    PRY_BP_APC_TRACK* Track;
} PRY_BP_ARM_JOB;

#define PRY_BP_ARM_WAIT_MS 1000
#define PRY_BP_CLEAR_WAIT_MS 200

static VOID PryBpApcRelease(_In_ PRY_BP_APC_TRACK* Track)
{
    if (InterlockedDecrement(&Track->Refs) == 0) {
        PryFree(Track);
    }
}

static VOID PryBpApcDone(_In_ PVOID Ctx)
{
    PRY_BP_APC_TRACK* track = (PRY_BP_APC_TRACK*)Ctx;
    InterlockedDecrement(&track->Pending);
    PryBpApcRelease(track);
}

static VOID PryBpApcNoteError(_In_opt_ PRY_BP_APC_TRACK* Track, _In_ NTSTATUS St)
{
    if (!Track || NT_SUCCESS(St) || St == STATUS_NOT_FOUND ||
        St == STATUS_INVALID_CID || St == STATUS_THREAD_IS_TERMINATING) {
        return; // a thread that exited needs no arm or clear
    }
    InterlockedCompareExchange(&Track->Error, (LONG)St, 0);
}

// Returns TRUE only after every APC queued for this operation has run or been
// retired by thread rundown. Alertable so an operation aimed at the calling
// thread itself can make progress.
static BOOLEAN PryBpApcWait(_In_ PRY_BP_APC_TRACK* Track, _In_ UINT32 TimeoutMs)
{
    UINT32 waitedMs = 0;
    LARGE_INTEGER interval;

    while (InterlockedCompareExchange(&Track->Pending, 0, 0) > 0 && waitedMs < TimeoutMs) {
        interval.QuadPart = -10 * 1000; // 1 ms
        KeDelayExecutionThread(KernelMode, TRUE, &interval);
        waitedMs++;
    }
    return InterlockedCompareExchange(&Track->Pending, 0, 0) == 0;
}

static NTSTATUS PryHwApplyFn(_In_ PETHREAD Thread, _Inout_ PVOID Ctx)
{
    PRY_BP_ARM_JOB* job = (PRY_BP_ARM_JOB*)Ctx;
    PRY_BP_REC* rec = &job->Rec;
    PEPROCESS proc = IoThreadToProcess(Thread);
    NTSTATUS st;
    UINT64 tid = (UINT64)(ULONG_PTR)PsGetThreadId(Thread);
    UINT64 pid = proc ? (UINT64)(ULONG_PTR)PsGetProcessId(proc) : 0;
    UINT64 dr7bits = PryDr7Bits(rec->Slot, rec->Length, rec->Access);
    UINT32 queued = 0, alerted = 0;
    BOOLEAN frozen;
    BOOLEAN dying;

    // Nothing is written to a thread outside the record's own live process.
    if (!proc || !PryBpRecOwnsThread(rec, Thread)) {
        return STATUS_NOT_FOUND;
    }
    if (PsGetProcessDebugPort(proc) != NULL) {
        // The debugger owns these DRs. Most importantly, do not report an
        // applied thread when no arm APC was queued at all.
        PryBpApcNoteError(job->Track, STATUS_SHARING_VIOLATION);
        PryLog("BPHWSET apc refused pid=%llu tid=%llu slot=%u (debuggee owns DRs)",
                 pid, tid, rec->Slot);
        return STATUS_SHARING_VIOLATION;
    }

    // A frozen, suspended or terminating thread can't run the live-register
    // APC and can't deliver the user APC that seeds the saved DR context.
    // NtSuspendProcess (the orchestrator's `process_manage suspend`) raises
    // the suspend count, not the freeze count, so a plain
    // PsGetThreadFreezeCount check misses it and the ctx op below would
    // then block in PsSetContextThread for the full user-APC wait, once per
    // thread. Skip the thread entirely instead; when every thread of a
    // suspended process is skipped, Applied stays 0 and PryBpHwSet rolls
    // back with STATUS_UNSUCCESSFUL within milliseconds -- the secondary
    // "add hangs on a suspended process" bug.
    frozen = PsGetThreadFreezeCount(Thread) != 0;
    dying = PsIsThreadTerminating(Thread);
    if (frozen || dying || PryThreadIsSuspended(Thread)) {
        PryLog("BPHWSET apc skip pid=%llu tid=%llu slot=%u frozen=%d dying=%d suspended=%d",
                 pid, tid, rec->Slot, (int)frozen, (int)dying,
                 (int)(!frozen && !dying));
        return STATUS_NOT_FOUND;
    }

    // Set the DebugActive gate BEFORE the saved-context write, so the kernel
    // honors the CONTEXT_DEBUG_REGISTERS fields on 24H2+ (where it filters
    // them out when the gate is clear) and saves/restores the live DRs
    // across every subsequent context switch.
    PryDrGateEnable(proc, Thread);

    // Seed the per-thread saved DR context. On 26200.6965 a live
    // __writedr(7,...) from the arm APC alone is wiped at the next context
    // switch -- the kernel restores the saved context, which still has
    // zeroed DRs, and silently disarms every slot. 189752a's live-only
    // writer is the regression: 1e384ab's build fired because it also seeded
    // the saved context here. Keep 189752a's per-slot read-modify-write so a
    // stale snapshot can't replay an older DR state over another slot.
    {
        CONTEXT ctx;
        RtlZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        st = PryThreadCtxOp(Thread, &ctx, FALSE);
        if (NT_SUCCESS(st)) {
            (&ctx.Dr0)[rec->Slot] = rec->Address;
            ctx.Dr7 = (ctx.Dr7 & ~PryDr7SlotMask(rec->Slot)) | dr7bits;
            st = PryThreadCtxOp(Thread, &ctx, TRUE);
        }
        if (!NT_SUCCESS(st)) {
            // SUSPEND_COUNT_EXCEEDED can appear here if the thread was
            // frozen between the check above and the ctx op: harmless, the
            // thread is already excluded by the ioctl's intent. Other
            // failures let the live APC below still try to arm.
            PryLog("BPHWSET ctx write tid=%llu slot=%u st=%x (live APC will still arm)",
                     tid, rec->Slot, st);
        }
    }

    // Queue the live-register arm. A tracked set does not return success
    // until this APC has run (or its thread has exited); an untracked call is
    // used only by the void thread-create notification.
    if (job->Track) {
        InterlockedIncrement(&job->Track->Pending);
        InterlockedIncrement(&job->Track->Refs);
        st = PryRemoteCallEx(pid, tid, (UINT64)PryDrArmWorker,
                               (UINT64)(rec->Slot & 0xFF), rec->Address, dr7bits,
                               PRY_RC_FLAG_KERNEL, PryBpApcDone, job->Track,
                               &queued, &alerted);
    } else {
        st = PryRemoteCall(pid, tid, (UINT64)PryDrArmWorker,
                             (UINT64)(rec->Slot & 0xFF), rec->Address, dr7bits,
                             PRY_RC_FLAG_KERNEL, &queued, &alerted);
    }
    if (!NT_SUCCESS(st)) {
        PryBpApcNoteError(job->Track, st);
        PryLog("BPHWSET apc queue failed pid=%llu tid=%llu slot=%u st=%x",
                 pid, tid, rec->Slot, st);
    }
    return st;
}

static NTSTATUS PryBpHwArmTracked(_In_ const PRY_BP_REC* Rec, _Out_ PUINT32 Applied)
{
    PRY_BP_APC_TRACK* track;
    PRY_BP_ARM_JOB job;
    NTSTATUS st;

    *Applied = 0;
    track = (PRY_BP_APC_TRACK*)PryAlloc(sizeof(*track));
    if (!track) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    track->Refs = 1;
    track->Pending = 0;
    track->Error = 0;
    job.Rec = *Rec;
    job.Track = track;

    st = PryProcessThreadApply(Rec->Pid, Rec->Tid, PryHwApplyFn, &job, Applied);
    if (track->Error) {
        st = (NTSTATUS)track->Error;
    } else if (NT_SUCCESS(st) && *Applied && !PryBpApcWait(track, PRY_BP_ARM_WAIT_MS)) {
        // Never turn a merely queued or refused arm into a successful add.
        // Rollback queues clears behind any late arms on the same threads.
        PryLog("BPHWSET %ld arm APC(s) not retired after %u ms; add will fail",
                 InterlockedCompareExchange(&track->Pending, 0, 0), PRY_BP_ARM_WAIT_MS);
        st = STATUS_IO_TIMEOUT;
    }
    PryBpApcRelease(track);
    return st;
}

typedef struct _PRY_BP_CLEAR_JOB {
    PRY_BP_REC Rec;
    PRY_BP_APC_TRACK* Track;
} PRY_BP_CLEAR_JOB;

static NTSTATUS PryHwClearFn(_In_ PETHREAD Thread, _Inout_ PVOID Ctx)
{
    PRY_BP_CLEAR_JOB* job = (PRY_BP_CLEAR_JOB*)Ctx;
    PRY_BP_REC* rec = &job->Rec;
    PEPROCESS proc = IoThreadToProcess(Thread);
    NTSTATUS st;
    UINT64 tid = (UINT64)(ULONG_PTR)PsGetThreadId(Thread);
    UINT64 pid = proc ? (UINT64)(ULONG_PTR)PsGetProcessId(proc) : 0;
    UINT64 dr7bits = PryDr7Bits(rec->Slot, rec->Length, rec->Access);
    UINT64 pack = (rec->Slot & 0xFF) | (0x100); /* clear flag in bit 8 */
    UINT32 queued = 0, alerted = 0;

    if (!proc || !PryBpRecOwnsThread(rec, Thread)) {
        return STATUS_NOT_FOUND;
    }

    // A frozen / suspended / terminating thread cannot run the live clear
    // APC and cannot deliver the user APC that would rewrite the saved DR
    // context. Skip the thread completely so the caller's bounded wait
    // does not count APCs that will never retire; the DR that was never
    // armed (rollback) or whose record is already freed (unmatched hit in
    // BpTrap.c) cannot fire spurious user-mode hits when the thread later
    // resumes.
    if (PsGetThreadFreezeCount(Thread) || PsIsThreadTerminating(Thread) ||
        PryThreadIsSuspended(Thread)) {
        PryLog("BPHWCLR apc skip pid=%llu tid=%llu slot=%u (thread not runnable)",
                 pid, tid, rec->Slot);
        return STATUS_NOT_FOUND;
    }

    // Clear the slot's bits from the saved DR context so a subsequent
    // context-switch-in does not restore the armed state over the live
    // clear queued below. Read-modify-write only this slot's fields so
    // another slot armed on the same thread keeps its state.
    {
        CONTEXT ctx;
        RtlZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        st = PryThreadCtxOp(Thread, &ctx, FALSE);
        if (NT_SUCCESS(st)) {
            (&ctx.Dr0)[rec->Slot] = 0;
            ctx.Dr7 &= ~PryDr7SlotMask(rec->Slot);
            st = PryThreadCtxOp(Thread, &ctx, TRUE);
        }
        if (!NT_SUCCESS(st) && st != STATUS_SUSPEND_COUNT_EXCEEDED &&
            st != STATUS_INVALID_CID && st != STATUS_THREAD_IS_TERMINATING) {
            PryLog("BPHWCLR ctx write tid=%llu slot=%u st=%x (live APC will still clear)",
                     tid, rec->Slot, st);
        }
    }

    // As for arm, the target-thread APC is the sole live-register writer.
    // Track frozen and debugged threads too: excluding them used to let
    // their late clear race a later re-arm without appearing in Pending.
    InterlockedIncrement(&job->Track->Pending);
    InterlockedIncrement(&job->Track->Refs);
    st = PryRemoteCallEx(pid, tid, (UINT64)PryDrArmWorker,
                           pack, 0, dr7bits,
                           PRY_RC_FLAG_KERNEL, PryBpApcDone, job->Track,
                           &queued, &alerted);
    if (!NT_SUCCESS(st)) {
        PryBpApcNoteError(job->Track, st);
        PryLog("BPHWCLR apc queue failed pid=%llu tid=%llu slot=%u st=%x",
                 pid, tid, rec->Slot, st);
    }
    return st;
}

// clear one record's DR state over its own scope, then wait --
// bounded -- until every counted clear APC has run or been retired. The
// caller must not hold PryBpLock. The table entry is not touched here;
// callers free it once this returns.
static NTSTATUS PryBpHwClearTracked(_In_ const PRY_BP_REC* Rec, _Out_ PUINT32 Applied)
{
    PRY_BP_APC_TRACK* track;
    PRY_BP_CLEAR_JOB job;
    NTSTATUS st;
    BOOLEAN drained;

    *Applied = 0;
    track = (PRY_BP_APC_TRACK*)PryAlloc(sizeof(*track));
    if (!track) {
        // No tracker means no safe way to distinguish a completed clear from
        // a late one. Refuse before touching any thread instead.
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    track->Refs = 1;
    track->Pending = 0;
    track->Error = 0;
    job.Rec = *Rec;
    job.Track = track;
    st = PryProcessThreadApply(Rec->Pid, Rec->Tid, PryHwClearFn, &job, Applied);

    drained = PryBpApcWait(track, PRY_BP_CLEAR_WAIT_MS);
    if (track->Error) {
        // Do not free the owning record when a live thread could not be
        // cleared; its DR may still fire and must remain attributable.
        st = (NTSTATUS)track->Error;
    }
    if (!drained) {
        // A later arm is queued behind these clears on each target thread and
        // is itself completion-tracked, so even this bounded timeout cannot
        // leave a successful re-arm with an older final DR7 state.
        PryLog("BPHWCLR %ld clear APC(s) not retired after %u ms (threads blocked)",
                 InterlockedCompareExchange(&track->Pending, 0, 0), PRY_BP_CLEAR_WAIT_MS);
    }
    PryBpApcRelease(track);
    return st;
}

// public wrapper so callers outside this TU (BpList.c's
// PryBpCleanup at unload, and the preempted-watch path in PryBpHwSet
// below) can clear DR0-3/DR7 + the per-thread gate for a record whose
// table slot is ALREADY freed -- the normal PryBpHwClear takes an id/
// slot and does its own table lookup, which requires Used/Enabled and so
// can never find a record that is already gone. Rec is a snapshot taken
// before the free; its own (possibly disjoint) Pid/Tid scope is what gets
// walked, exactly as a live BP_HW_CLEAR on it would have.
// returns only after the clear APCs have retired (bounded).
NTSTATUS PryBpHwClearDr(_In_ const PRY_BP_REC* Rec, _Out_ PUINT32 Applied)
{
    return PryBpHwClearTracked(Rec, Applied);
}

// retire a record that a failed or rolled-back set had published:
// mark it claimable-but-not-armable, clear whatever did get armed, then free.
static VOID PryBpHwRollback(_In_ const PRY_BP_REC* Rec, _In_ PPRY_BP_REC Entry, _In_ UINT32 Id)
{
    KIRQL irql;
    UINT32 ignored = 0;
    BOOLEAN ours;

    KeAcquireSpinLock(&PryBpLock, &irql);
    ours = Entry->Used && Entry->Id == Id;
    if (ours) {
        Entry->Arming = 0;
        Entry->Retiring = 1; // no newborn is armed from it; its hits are still claimed
    }
    KeReleaseSpinLock(&PryBpLock, irql);
    if (!ours) {
        return; // already reaped (its process exited meanwhile)
    }
    {
        NTSTATUS clearSt = PryBpHwClearTracked(Rec, &ignored);
        KeAcquireSpinLock(&PryBpLock, &irql);
        if (Entry->Used && Entry->Id == Id) {
            if (NT_SUCCESS(clearSt)) {
                PryBpFreeLocked(Entry);
                InterlockedDecrement(&PryBpHwArmed);
            } else {
                // Safety over cosmetics: a failed add may leave a visible
                // record for manual retry, but never an unclaimed live DR.
                Entry->Retiring = 0;
            }
        }
        KeReleaseSpinLock(&PryBpLock, irql);
        if (!NT_SUCCESS(clearSt)) {
            PryLog("BPHWSET rollback clear failed id=%u st=%x; record retained if still live",
                     Id, clearSt);
        }
    }
}

// per-thread callback for PryBpHwClearAllGates.
static NTSTATUS PryGateClearFn(_In_ PETHREAD Thread, _Inout_ PVOID Ctx)
{
    PEPROCESS proc = IoThreadToProcess(Thread);
    UNREFERENCED_PARAMETER(Ctx);
    if (proc) {
        PryDrGateDisableProcess(proc);
    }
    return STATUS_SUCCESS;
}

// see the declaration in PryDriver.h. Reuses the
// same system-wide walk Global arming itself uses
// (PryProcessThreadApply(0,0,...) -> PryEnumProcessThreads), so the
// cost/scope of sweeping matches the cost/scope of having set the gates
// in the first place.
VOID PryBpHwClearAllGates(VOID)
{
    UINT32 applied = 0;
    PryProcessThreadApply(0, 0, PryGateClearFn, NULL, &applied);
    PryLog("BPHW gate-clear-all: swept %u thread(s)", applied);
}

// ---- SI #25 (v14): helpers for auto-slot allocation + preempt ----
//
// Both run with PryBpLock held. The scan is bounded by PRY_MAX_BP
// (currently 64) so the extra passes cost no more than the existing
// alloc helpers.
static UINT32 PryBpOccupancyLocked(_In_ UINT64 Pid, _In_ UINT64 Tid)
{
    UINT32 mask = 0;
    for (UINT32 i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        if (!(r->Used && r->Kind == PRY_BP_KIND_HW)) {
            continue;
        }
        // A per-pid/all-threads record (Tid==0) blocks a per-thread request,
        // and a per-thread record blocks only its own thread.
        // Pid==0 (Global) blocks every request for that slot.
        // a record still arming or retiring keeps its DR until its
        // clears run, so it occupies its slot in the meantime.
        if (r->Global) {
            mask |= (1u << r->Slot);
            continue;
        }
        if (r->Pid && (UINT32)Pid && r->Pid != (UINT32)Pid) {
            continue;
        }
        if (r->Tid && (UINT32)Tid && r->Tid != (UINT32)Tid) {
            continue;
        }
        mask |= (1u << r->Slot);
    }
    return mask & 0xF; // DR0..DR3
}

static PPRY_BP_REC PryBpWatchVictimLocked(_In_ UINT64 Pid, _In_ UINT64 Tid)
{
    // "Oldest watch" heuristic: lowest Id wins the Used sweep. Our
    // ids are allocated monotonically (BpSw.c PryBpAllocLocked), so
    // this gives insertion order. Never evicts a non-watch entry.
    PPRY_BP_REC victim = NULL;
    for (UINT32 i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        if (!(r->Used && r->Enabled && r->Kind == PRY_BP_KIND_HW && r->IsWatch)) {
            continue;
        }
        // a watch already being set up or torn down is not a victim.
        if (r->Arming || r->Retiring) {
            continue;
        }
        if (!r->Global) {
            if (r->Pid && (UINT32)Pid && r->Pid != (UINT32)Pid) {
                continue;
            }
            if (r->Tid && (UINT32)Tid && r->Tid != (UINT32)Tid) {
                continue;
            }
        }
        if (!victim || r->Id < victim->Id) {
            victim = r;
        }
    }
    return victim;
}

// Takes a table entry for Rec and publishes it: Used, Enabled (set in Rec),
// counted in PryBpHwArmed. Caller holds PryBpLock. NULL when the table is full.
static PPRY_BP_REC PryBpPublishLocked(_Inout_ PRY_BP_REC* Rec, _In_ BOOLEAN IsWatch,
                                           _Out_ PUINT32 Id)
{
    PPRY_BP_REC entry = PryBpAllocLocked(Id);
    if (entry) {
        if (IsWatch) {
            Rec->WatchCookie = *Id; // v14 (SI #25): mirror BpId as the demux key
        }
        *entry = *Rec;
        entry->Used = 1;
        entry->Id = *Id;
        InterlockedIncrement(&PryBpHwArmed);
    }
    return entry;
}

NTSTATUS PryBpHwSet(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Address, _In_ UINT32 Slot,
                      _In_ UINT32 Length, _In_ UINT32 Access, _In_ UINT32 Flags,
                      _Out_ PUINT32 Id, _Out_ PUINT32 Applied)
{
    NTSTATUS st;
    KIRQL irql;
    PRY_BP_REC rec;
    PRY_BP_REC victimSnapshot;
    PPRY_BP_REC victimLive = NULL;
    PPRY_BP_REC slotRec = NULL;
    PEPROCESS procRef = NULL;
    UINT32 newId = 0;
    UINT32 patched = 0;
    UINT32 occupied = 0;
    BOOLEAN opHeld = FALSE;
    const BOOLEAN Global = (Flags & PRY_BP_HW_FLAG_GLOBAL) != 0;
    const BOOLEAN DangerousOk = (Flags & PRY_BP_HW_FLAG_DANGEROUS_OK) != 0;
    // v14 (SI #25): watch-mode plumbing.
    const BOOLEAN IsWatch = (Flags & PRY_BPHW_FLAG_IS_WATCH) != 0;
    const BOOLEAN PreemptOk = (Flags & PRY_BPHW_FLAG_PREEMPT_OK) != 0;

    *Id = 0;
    *Applied = 0;
    // v6: Pid=0 legal ONLY with GLOBAL. Otherwise keep the historical
    // guard so a stray pid=0 request doesn't accidentally arm every
    // thread system-wide.
    if ((!Pid && !Global) || !Address) {
        return STATUS_INVALID_PARAMETER;
    }
    // v14 (SI #25): Slot==0xFF asks the driver for a free DR slot (auto-
    // allocate). Any other out-of-range value is still a hard reject.
    if (Slot > 3 && Slot != PRY_BP_HW_SLOT_AUTO) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Length != 1 && Length != 2 && Length != 4 && Length != 8) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Access != PRY_HW_EXEC && Access != PRY_HW_WRITE && Access != PRY_HW_RW) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Access == PRY_HW_EXEC && Length != 1) {
        return STATUS_INVALID_PARAMETER; // exec DRs are always length 1
    }
    // v14: watch entries never fire exec. The data-watchpoint model is
    // read/write only; an exec watch is a plain breakpoint, which the
    // caller gets through the ordinary (non-IS_WATCH) BP_HW_SET path.
    if (IsWatch && Access == PRY_HW_EXEC) {
        return STATUS_INVALID_PARAMETER;
    }
    // v14: watches are per-pid/tid. Combining IS_WATCH with GLOBAL
    // would arm every thread system-wide behind one WatchCookie — not
    // the subscription model the orchestrator expects, and it would
    // starve PID 4's own DRs. Reject outright.
    if (IsWatch && Global) {
        return STATUS_INVALID_PARAMETER;
    }

    // v6: global-BP safety gates.
    //   * Cap at 2 simultaneous global BPs — otherwise a runaway caller
    //     could pin every DR slot on every thread system-wide, DoS'ing
    //     the target's own debug DRs.
    //   * If PatchGuard is expected (PrySystemFlags surfaces it via
    //     ping.Flags) refuse without DangerousOk — DR writes shouldn't
    //     trip PG, but defensive when we're arming ntoskrnl threads.
    if (Global) {
        UINT32 globalCount = 0;
        KeAcquireSpinLock(&PryBpLock, &irql);
        for (UINT32 i = 0; i < PRY_MAX_BP; i++) {
            PPRY_BP_REC r = &PryBpTable[i];
            if (r->Used && r->Kind == PRY_BP_KIND_HW && r->Global) {
                globalCount++;
            }
        }
        KeReleaseSpinLock(&PryBpLock, irql);
        if (globalCount >= 2) {
            PryLog("BPHWSET refused global: 2-BP cap hit");
            return STATUS_QUOTA_EXCEEDED;
        }
        if (!DangerousOk && (PrySystemFlags() & 0) /* PG expected marker */) {
            // Placeholder — PrySystemFlags doesn't currently expose PG
            // separately; when it does, gate here. Leaving the branch
            // in place so the flag is honored the moment the marker
            // lands, without another Breakpoints.c edit.
            (void)0;
        }
        PryLog("BPHWSET global tid=%llu addr=%llx slot=%u", Tid, Address, Slot);
    } else {
        // a non-global record is pinned to its live EPROCESS, so
        // arm and clear can refuse threads of any other process, including
        // one that later reuses this PID. The reference is held until return.
        st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &procRef);
        if (!NT_SUCCESS(st)) {
            return st;
        }
        if (PsGetProcessDebugPort(procRef) != NULL) {
            // Never create a successful but deliberately unarmed record.
            st = STATUS_SHARING_VIOLATION;
            goto out_release;
        }
    }

    RtlZeroMemory(&rec, sizeof(rec));
    rec.Kind = PRY_BP_KIND_HW;
    rec.Pid = (UINT32)Pid;   // 0 when Global
    rec.Tid = (UINT32)Tid;
    rec.Slot = Slot;
    rec.Length = Length;
    rec.Access = Access;
    rec.Address = Address;
    rec.Enabled = 1;
    rec.Global = Global ? 1u : 0u;
    rec.IsWatch = IsWatch ? 1u : 0u; // v14 (SI #25)
    rec.ProcKey = procRef ? (UINT64)(ULONG_PTR)procRef : 0;
    rec.Arming = 1;

    // Keep the record published while its APCs run, but exclude a concurrent
    // clear or a create-notify arm until this operation reaches a final state.
    KeWaitForSingleObject(&PryBpHwOpMutex, Executive, KernelMode, FALSE, NULL);
    opHeld = TRUE;

    // v14 (SI #25): auto-slot + preempt resolution happens UNDER the
    // same lock as alloc, otherwise two watch arms racing against three
    // free slots could both pick slot 0 and leave slot 3 unused.
    // an explicit slot is taken only when no live record holds it
    // for an overlapping scope. Otherwise the request is refused; it is never
    // silently moved to another slot or allowed to overwrite a live DR.
    // the record is published (Enabled) BEFORE the first thread is
    // armed, so an int1 hit from an early-armed thread is claimed.
    KeAcquireSpinLock(&PryBpLock, &irql);
    occupied = PryBpOccupancyLocked(Pid, Tid);
    if (Slot == PRY_BP_HW_SLOT_AUTO) {
        UINT32 pick = 0xFFu;
        for (UINT32 s = 0; s < 4; s++) {
            if (!(occupied & (1u << s))) { pick = s; break; }
        }
        if (pick == 0xFFu && IsWatch && PreemptOk) {
            PPRY_BP_REC victim = PryBpWatchVictimLocked(Pid, Tid);
            if (victim) {
                pick = victim->Slot;
                PryLog("BPHWSET watch preempt pid=%llu tid=%llu slot=%u victim_id=%u",
                         Pid, Tid, pick, victim->Id);
                victimSnapshot = *victim; // keep its scope for the real DR clear below
                victimLive = victim;
                victim->Retiring = 1;     // stays claimable until its clears have run
            }
        }
        if (pick == 0xFFu) {
            KeReleaseSpinLock(&PryBpLock, irql);
            PryLog("BPHWSET auto-slot busy pid=%llu tid=%llu is_watch=%u preempt=%u",
                     Pid, Tid, (UINT32)IsWatch, (UINT32)PreemptOk);
            st = STATUS_DEVICE_BUSY;
            goto out_release;
        }
        Slot = pick;
        rec.Slot = pick;
    } else if (occupied & (1u << Slot)) {
        KeReleaseSpinLock(&PryBpLock, irql);
        PryLog("BPHWSET slot busy pid=%llu tid=%llu slot=%u (held by a live record)",
                 Pid, Tid, Slot);
        st = STATUS_DEVICE_BUSY;
        goto out_release;
    }
    if (!victimLive) {
        // No preemption: choosing the slot and taking its entry are one step.
        slotRec = PryBpPublishLocked(&rec, IsWatch, &newId);
    }
    KeReleaseSpinLock(&PryBpLock, irql);

    // a preempted watch keeps its table entry (Retiring)
    // until its DR clears have run; only then is it freed, and the new record
    // is published into the freed entry under the same lock. The new arm below
    // only touches the new scope, so a victim outside it would otherwise keep
    // a live DR that no record claims.
    if (victimLive) {
        UINT32 victimApplied = 0;
        st = PryBpHwClearDr(&victimSnapshot, &victimApplied);
        if (!NT_SUCCESS(st)) {
            KeAcquireSpinLock(&PryBpLock, &irql);
            if (victimLive->Used && victimLive->Id == victimSnapshot.Id) {
                victimLive->Retiring = 0; // retain ownership of any live DR
            }
            KeReleaseSpinLock(&PryBpLock, irql);
            goto out_release;
        }
        KeAcquireSpinLock(&PryBpLock, &irql);
        if (victimLive->Used && victimLive->Id == victimSnapshot.Id) {
            PryBpFreeLocked(victimLive);
            InterlockedDecrement(&PryBpHwArmed);
        }
        slotRec = PryBpPublishLocked(&rec, IsWatch, &newId);
        KeReleaseSpinLock(&PryBpLock, irql);
    }
    if (!slotRec) {
        st = STATUS_INSUFFICIENT_RESOURCES;
        goto out_release;
    }

    // PryProcessThreadApply handles Pid==0 as "walk every process"
    // when Tid==0 too. Tid!=0 with Pid==0 doesn't really make sense
    // (a tid uniquely identifies a thread already) but we let it through.
    st = PryBpHwArmTracked(&rec, &patched);
    if (!NT_SUCCESS(st)) {
        // A hard refusal, queue failure, or timeout is never converted into a
        // successful but partially/inertly armed record. Threads that simply
        // exited during the walk are ignored by PryBpApcNoteError.
        PryBpHwRollback(&rec, slotRec, newId);
        goto out_release;
    }
    // patched==0 for a non-global arm is now a hard failure.
    // Roll back so bp_manage add surfaces the reality directly.
    if (patched == 0) {
        PryBpHwRollback(&rec, slotRec, newId);
        PryLog("BPHWSET no thread armed pid=%llu tid=%llu slot=%u global=%u -> rollback",
                 Pid, Tid, Slot, Global);
        st = NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
        goto out_release;
    }

    KeAcquireSpinLock(&PryBpLock, &irql);
    if (slotRec->Used && slotRec->Id == newId) {
        slotRec->Arming = 0;
    }
    KeReleaseSpinLock(&PryBpLock, irql);

    *Id = newId;
    *Applied = patched;
    st = STATUS_SUCCESS;

out_release:
    if (opHeld) {
        KeReleaseMutex(&PryBpHwOpMutex, FALSE);
    }
    if (procRef) {
        ObDereferenceObject(procRef);
    }
    return st;
}

NTSTATUS PryBpHwClear(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT32 Slot, _Out_ PUINT32 Applied)
{
    NTSTATUS st;
    KIRQL irql;
    PRY_BP_REC rec;
    UINT32 patched = 0, i;
    BOOLEAN found = FALSE;
    BOOLEAN pidHasHw = FALSE;

    *Applied = 0;
    // v6: Pid==0 is valid — matches the global registry entry.
    if (Slot > 3) {
        return STATUS_INVALID_PARAMETER;
    }

    // Serialize against both a set and a create-notify snapshot/arm walk.
    KeWaitForSingleObject(&PryBpHwOpMutex, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&PryBpLock, &irql);
    for (i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        if (r->Kind == PRY_BP_KIND_HW && r->Used && r->Enabled && !r->Arming && !r->Retiring &&
            r->Pid == (UINT32)Pid && r->Slot == Slot && (!Tid || r->Tid == (UINT32)Tid)) {
            // mark it retiring: it keeps claiming hits, but no
            // newborn is armed from it, and no second clear may start on it.
            r->Retiring = 1;
            rec = *r;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&PryBpLock, irql);
    if (!found) {
        // idempotent clear. An entry that is already gone (a double-clear, or
        // a clear following the auto-prune on thread-exit) is not an
        // error. The correct end state (no bp) is already reached, so
        // return success with Applied=0.
        PryLog("BPHWCLR already-clean pid=%llu tid=%llu slot=%u", Pid, Tid, Slot);
        KeReleaseMutex(&PryBpHwOpMutex, FALSE);
        return STATUS_SUCCESS;
    }

    // clear first, and free the entry only after its clears have
    // run (bounded). Until then the record still claims any hit its DR fires.
    st = PryBpHwClearDr(&rec, &patched);
    if (!NT_SUCCESS(st)) {
        // A queue refusal can leave this record's DR armed. Keep ownership and
        // allow a retry instead of freeing the only record that can claim a
        // subsequent hit. Any already-queued clear still owns its tracker and
        // may finish asynchronously; the record remains table-visible.
        KeAcquireSpinLock(&PryBpLock, &irql);
        for (i = 0; i < PRY_MAX_BP; i++) {
            PPRY_BP_REC r = &PryBpTable[i];
            if (r->Used && r->Id == rec.Id) {
                r->Retiring = 0;
                break;
            }
        }
        KeReleaseSpinLock(&PryBpLock, irql);
        *Applied = patched;
        KeReleaseMutex(&PryBpHwOpMutex, FALSE);
        return st;
    }

    // scan under the same lock we free under so a concurrent
    // PryBpHwSet on this pid can't observe "no entries" between the
    // free below and a would-be gate-off. If this clear leaves zero HW
    // BPs on the pid, drop the process DebugActive gate — the earlier
    // "harmless for a lab" assumption bugchecks on Win11 25H2 when the
    // process later exits with DebugActive=1 and a null DebugPort.
    KeAcquireSpinLock(&PryBpLock, &irql);
    for (i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        if (r->Used && r->Id == rec.Id) {
            PryBpFreeLocked(r);
            InterlockedDecrement(&PryBpHwArmed);
            continue;
        }
        if (r->Used && r->Enabled && r->Kind == PRY_BP_KIND_HW &&
            (r->Global || r->Pid == (UINT32)Pid)) {
            pidHasHw = TRUE;
        }
    }
    KeReleaseSpinLock(&PryBpLock, irql);

    if (!pidHasHw && Pid) {
        PEPROCESS proc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc)) && proc) {
            PryDrGateDisableProcess(proc);
            ObDereferenceObject(proc);
        }
    } else if (!Pid) {
        // Global clear. Process gates were set on
        // every thread's own process by PryDrGateEnable; the set of
        // touched pids was never tracked, so a per-pid lookup can't do a
        // surgical cleanup here. Sweep every process's gate instead --
        // idempotent (an already-clear gate is a no-op) and the same
        // system-wide walk Global arming itself used to set them.
        PryBpHwClearAllGates();
        PryLog("BPHWCLR global: process gates cleared system-wide");
    }

    *Applied = patched;
    KeReleaseMutex(&PryBpHwOpMutex, FALSE);
    return st;
}

// all-thread HW breakpoints must also reach threads created after the bp was
// set; runs at PASSIVE_LEVEL from the thread-create notification
VOID PryOnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    UINT32 i;
    KIRQL irql;
    PETHREAD thread;
    PRY_BP_REC snap[PRY_MAX_BP];
    UINT32 snapCount = 0;
    UINT32 pruned = 0;

    if (!Create) {
        // auto-prune per-thread HW BPs when the armed thread
        // exits. Without this the registry accretes stale entries
        // that only surface as an error at the next bp_manage remove.
        // Global BPs (r->Global=1) are kept — they cover future
        // threads, and their per-thread arming is bookkept elsewhere.
        // Tid==0 (all-threads-of-pid) entries are also kept — the pid
        // may still have other live threads; the entry only stops
        // mattering when the process itself exits, and process-exit
        // notifications reap the whole pid (PryBpOnProcessExitEx).
        // the owning pid must match too; a TID is recycled, so a
        // thread exit of another process with the same TID must not prune.
        KeAcquireSpinLock(&PryBpLock, &irql);
        for (i = 0; i < PRY_MAX_BP; i++) {
            PPRY_BP_REC r = &PryBpTable[i];
            if (r->Used && r->Enabled && r->Kind == PRY_BP_KIND_HW &&
                !r->Global && r->Tid && r->Tid == (UINT32)(ULONG_PTR)ThreadId &&
                r->Pid == (UINT32)(ULONG_PTR)ProcessId) {
                PryBpFreeLocked(r);
                InterlockedDecrement(&PryBpHwArmed);
                pruned++;
            }
        }
        KeReleaseSpinLock(&PryBpLock, irql);
        if (pruned) {
            PryLog("BPHWPRN thread-exit pid=%llu tid=%llu -> pruned=%u",
                     (UINT64)(ULONG_PTR)ProcessId,
                     (UINT64)(ULONG_PTR)ThreadId, pruned);
        }
        return;
    }

    InterlockedIncrement(&PryThreadNotifyActive);
    KeWaitForSingleObject(&PryBpHwOpMutex, Executive, KernelMode, FALSE, NULL);
    __try {
        KeAcquireSpinLock(&PryBpLock, &irql);
        for (i = 0; i < PRY_MAX_BP; i++) {
            PPRY_BP_REC r = &PryBpTable[i];
            // a retiring record is on its way out; arming a newborn
            // from it could leave a DR behind that no record claims.
            if (!(r->Used && r->Enabled && r->Kind == PRY_BP_KIND_HW && r->Tid == 0 &&
                  !r->Retiring)) {
                continue;
            }
            // v6: Global BPs arm newborns regardless of parent pid;
            // per-pid BPs still only arm children of their pid.
            if (r->Global || r->Pid == (UINT32)(ULONG_PTR)ProcessId) {
                snap[snapCount++] = *r;
            }
        }
        KeReleaseSpinLock(&PryBpLock, irql);

        if (!snapCount) {
            return;
        }
        if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &thread))) {
            return;
        }
        for (i = 0; i < snapCount; i++) {
            PRY_BP_ARM_JOB job;
            job.Rec = snap[i];
            job.Track = NULL; // notification has no caller to wait; queueing is still checked/logged
            PryHwApplyFn(thread, &job); // refuses threads outside the record's process
        }
        ObDereferenceObject(thread);
    } __finally {
        KeReleaseMutex(&PryBpHwOpMutex, FALSE);
        InterlockedDecrement(&PryThreadNotifyActive);
    }
}

// classic (non-Ex) callback: receives the PEPROCESS instead of the pid — used
// as a fallback because PsSetCreateThreadNotifyRoutineEx demands /INTEGRITYCHECK
VOID PryOnThreadNotifyClassic(_In_ PEPROCESS Process, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    // forward BOTH create and exit notifications, so the auto-prune of
    // dead per-thread HW BPs also runs on classic-callback builds.
    if (!Process) {
        return;
    }
    PryOnThreadNotify(PsGetProcessId(Process), ThreadId, Create);
}

// ---- reap breakpoint records when their process exits ----------
// A per-pid HW record (and any SW int3 record) otherwise outlives its
// process: it keeps PryBpHwArmed above zero, so NOTIFY_DISABLE refuses
// forever, and a recycled PID can inherit it. Dropping the record also drops
// the EPROCESS DebugActive gate, which the exited process would otherwise
// carry into its teardown. Global records are
// kept: they are not owned by any one process.
static VOID PryBpOnProcessExitEx(_In_ PEPROCESS Process, _In_ HANDLE ProcessId,
                                   _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UINT32 pid = (UINT32)(ULONG_PTR)ProcessId;
    UINT32 droppedHw = 0;
    UINT32 droppedSw = 0;
    UINT32 i;
    KIRQL irql;

    if (CreateInfo) {
        return; // process creation: nothing to reap
    }
    KeAcquireSpinLock(&PryBpLock, &irql);
    for (i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        if (!(r->Used && r->Enabled) || r->Global || r->Pid != pid) {
            continue;
        }
        if (r->Kind == PRY_BP_KIND_HW) {
            droppedHw++;
            InterlockedDecrement(&PryBpHwArmed);
        } else if (r->Kind == PRY_BP_KIND_SW) {
            droppedSw++;
        }
        PryBpFreeLocked(r);
    }
    KeReleaseSpinLock(&PryBpLock, irql);

    if (droppedHw && Process) {
        PryDrGateDisableProcess(Process);
    }
    if (droppedHw || droppedSw) {
        PryLog("BPPROC exit pid=%u dropped hw=%u sw=%u", pid, droppedHw, droppedSw);
    }
}

static volatile LONG PryBpProcNotifyOn = 0;

NTSTATUS PryBpProcNotifyInit(VOID)
{
    NTSTATUS st = PsSetCreateProcessNotifyRoutineEx(PryBpOnProcessExitEx, FALSE);
    if (NT_SUCCESS(st)) {
        InterlockedExchange(&PryBpProcNotifyOn, 1);
    } else {
        PryLog("BP proc-exit notify register failed st=%x (records of exited pids will linger)", st);
    }
    return st;
}

VOID PryBpProcNotifyShutdown(VOID)
{
    if (InterlockedCompareExchange(&PryBpProcNotifyOn, 0, 1) == 1) {
        PsSetCreateProcessNotifyRoutineEx(PryBpOnProcessExitEx, TRUE);
    }
}
