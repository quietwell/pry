#include "PryDriver.h"

// Kernel-initiated user APC execution: the APC's normal routine is the user
// target itself, so ntdll's user-APC dispatcher calls Target(Arg1, Arg2, Arg3)
// inside the target process and restores the interrupted context via
// NtContinue afterwards. No stub shellcode is written into the target.
//
// for a KERNEL-mode remote call, Target is one of our
// OWN in-image routines (PryDrArmWorker, PryStackWalkWorker, ...),
// invoked as the KAPC's "normal routine" -- which the kernel calls
// directly and synchronously, right after the special kernel routine
// below returns (same kernel context, no usermode indirection, unlike the
// user-mode case described above). PryApcKernelRoutine used to
// decrement PryApcOutstanding and free the KAPC itself UNCONDITIONALLY,
// i.e. before that normal-routine call had even happened -- so
// PryEvtDriverUnload's drain-wait on PryApcOutstanding could see zero
// outstanding and let the image's pages go away while a normal routine
// was still queued (or mid-flight) to execute in them. Fix: for a
// kernel-mode call, the normal routine is redirected to a small wrapper
// (PryApcKernelTargetWrapper) that calls the REAL target first and only
// THEN decrements the counter and frees the block. The special kernel
// routine's own decrement+free now runs only for the user-mode path,
// where Target lives in the remote process (not our image) and there is
// no hook into "after ntdll's usermode dispatcher calls it" anyway.

// NT x64 KAPC layout (public ABI, minimal fields)
typedef struct _PRY_KAPC {
    UCHAR Type;
    UCHAR SpareByte0;
    UCHAR Size;
    UCHAR SpareByte1;
    ULONG SpareLong0;
    PVOID Thread;
    LIST_ENTRY ApcListEntry;
    PVOID KernelRoutine;
    PVOID RundownRoutine;
    PVOID NormalRoutine;
    PVOID NormalContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    CCHAR ApcStateIndex;
    CCHAR ApcMode;
    UCHAR NormalRoutineActive;
    UCHAR SpareByte2;
} PRY_KAPC, *PPRY_KAPC;

C_ASSERT(sizeof(PRY_KAPC) == 0x58);

typedef VOID (*PRY_KERNEL_ROUTINE)(_In_ PPRY_KAPC Apc, _Inout_ PVOID* NormalRoutine,
                                      _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1,
                                      _Inout_ PVOID* SystemArgument2);
typedef VOID (*PRY_RUNDOWN_ROUTINE)(_In_ PPRY_KAPC Apc);
typedef VOID (*PRY_RC_TARGET_FN)(UINT64, UINT64, UINT64);

NTKERNELAPI VOID KeInitializeApc(_Out_ PPRY_KAPC Apc, _In_ PVOID Thread,
                                 _In_ PRY_KAPC_ENVIRONMENT Environment,
                                 _In_ PRY_KERNEL_ROUTINE KernelRoutine,
                                 _In_opt_ PRY_RUNDOWN_ROUTINE RundownRoutine,
                                 _In_opt_ PVOID NormalRoutine,
                                 _In_ KPROCESSOR_MODE ApcMode,
                                 _In_opt_ PVOID NormalContext);
NTKERNELAPI BOOLEAN KeInsertQueueApc(_Inout_ PPRY_KAPC Apc, _In_opt_ PVOID SystemArgument1,
                                     _In_opt_ PVOID SystemArgument2, _In_ KPRIORITY Increment);

// Trailing allocation: PRY_KAPC must stay FIRST -- KeInitializeApc /
// KeInsertQueueApc address this block through a bare PPRY_KAPC cast,
// and only ever touch bytes within sizeof(PRY_KAPC). Anything placed
// after that is ours alone. RealTarget/RealArg1 are populated only for a
// kernel-mode call (see PryApcKernelTargetWrapper below); zero for the
// user-mode path, where Target is handed to the kernel directly instead.
// Done/DoneCtx (kernel-mode calls only) carry the PryRemoteCallEx
// completion hook; they are called from every path that retires the APC.
typedef struct _PRY_REMOTE_CALL_APC {
    PRY_KAPC Kapc;
    PRY_RC_TARGET_FN RealTarget;
    UINT64 RealArg1;
    PRY_RC_DONE_FN Done;
    PVOID DoneCtx;
} PRY_REMOTE_CALL_APC, *PPRY_REMOTE_CALL_APC;

static VOID PryApcKernelRoutine(_In_ PPRY_KAPC Apc, _Inout_ PVOID* NormalRoutine,
                                  _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1,
                                  _Inout_ PVOID* SystemArgument2)
{
    PPRY_REMOTE_CALL_APC rcApc = (PPRY_REMOTE_CALL_APC)Apc;
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    if (rcApc->RealTarget) {
        // Kernel-mode path: the normal routine is already redirected to
        // PryApcKernelTargetWrapper (set in PryRemoteCallEx), which owns
        // the decrement + free AFTER it calls the real in-image target.
        return;
    }
    // User-mode path: Target is not in this image, and nothing can hook
    // "after ntdll's dispatcher calls it" from kernel code -- this IS the
    // right (only) place to retire the count/memory for that case.
    InterlockedDecrement(&PryApcOutstanding);
    PryFree(Apc);
}

static VOID PryApcRundown(_In_ PPRY_KAPC Apc)
{
    PPRY_REMOTE_CALL_APC rcApc = (PPRY_REMOTE_CALL_APC)Apc;
    // Thread exited before the APC delivered: nothing will ever call the
    // normal routine, so this is the right place to retire the
    // count/memory regardless of kernel/user mode. A completion hook still
    // has to fire, or its owner would wait for an APC that never runs.
    if (rcApc->Done) {
        rcApc->Done(rcApc->DoneCtx);
    }
    InterlockedDecrement(&PryApcOutstanding);
    PryFree(Apc);
}

// Normal routine for a kernel-mode remote call: calls the real in-image
// target, THEN retires the APC. Runs at PASSIVE_LEVEL on the target
// thread, in this driver's own kernel context -- the only point from
// which "the in-image routine has finished" can actually be observed.
static VOID PryApcKernelTargetWrapper(_In_ PVOID NormalContext, _In_ PVOID SystemArgument1,
                                        _In_ PVOID SystemArgument2)
{
    PPRY_REMOTE_CALL_APC rcApc = (PPRY_REMOTE_CALL_APC)NormalContext;
    PRY_RC_TARGET_FN fn = rcApc->RealTarget;

    fn(rcApc->RealArg1, (UINT64)(ULONG_PTR)SystemArgument1, (UINT64)(ULONG_PTR)SystemArgument2);

    if (rcApc->Done) {
        rcApc->Done(rcApc->DoneCtx);
    }
    InterlockedDecrement(&PryApcOutstanding);
    PryFree(rcApc);
}

volatile LONG PryApcOutstanding = 0;

NTSTATUS PryRemoteCallEx(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Target,
                           _In_ UINT64 Arg1, _In_ UINT64 Arg2, _In_ UINT64 Arg3,
                           _In_ UINT32 Flags, _In_opt_ PRY_RC_DONE_FN Done,
                           _In_opt_ PVOID DoneCtx, _Out_ PUINT32 Queued, _Out_ PUINT32 Alerted)
{
    NTSTATUS st;
    PETHREAD thread;
    PPRY_REMOTE_CALL_APC apc;
    BOOLEAN queued;
    BOOLEAN kernelMode = (Flags & PRY_RC_FLAG_KERNEL) != 0;

    *Queued = 0;
    *Alerted = 0;
    // Done contract: invoked exactly once per call, from whichever
    // path retires it -- after the kernel target ran, at thread rundown, or
    // before returning here when nothing was queued. Kernel calls only.
    if (!Pid || !Tid || !Target || (Done && !kernelMode)) {
        st = STATUS_INVALID_PARAMETER;
        goto out_unqueued;
    }
    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &thread);
    if (!NT_SUCCESS(st)) {
        goto out_unqueued;
    }
    // TIDs are recycled. By now the TID may name a thread of
    // another process; never queue a call into a thread outside Pid.
    if ((UINT64)(ULONG_PTR)PsGetThreadProcessId(thread) != Pid) {
        ObDereferenceObject(thread);
        st = STATUS_NOT_FOUND;
        goto out_unqueued;
    }
    apc = (PPRY_REMOTE_CALL_APC)PryAlloc(sizeof(*apc));
    if (!apc) {
        ObDereferenceObject(thread);
        st = STATUS_INSUFFICIENT_RESOURCES;
        goto out_unqueued;
    }
    RtlZeroMemory(apc, sizeof(*apc));
    if (kernelMode) {
        apc->RealTarget = (PRY_RC_TARGET_FN)(ULONG_PTR)Target;
        apc->RealArg1 = Arg1;
        apc->Done = Done;
        apc->DoneCtx = DoneCtx;
    }

    KeInitializeApc(&apc->Kapc, thread, PryOriginalApcEnvironment,
                    PryApcKernelRoutine, PryApcRundown,
                    kernelMode ? (PVOID)PryApcKernelTargetWrapper : (PVOID)(ULONG_PTR)Target,
                    kernelMode ? KernelMode : UserMode,
                    kernelMode ? (PVOID)apc : (PVOID)(ULONG_PTR)Arg1);
    apc->Kapc.SystemArgument1 = (PVOID)(ULONG_PTR)Arg2;
    apc->Kapc.SystemArgument2 = (PVOID)(ULONG_PTR)Arg3;

    // account BEFORE inserting: the kernel routine can run the instant the
    // APC is queued, and PryEvtDriverUnload must never observe zero with
    // an APC still in flight (the routines live in this driver image).
    InterlockedIncrement(&PryApcOutstanding);
    queued = KeInsertQueueApc(&apc->Kapc, apc->Kapc.SystemArgument1, apc->Kapc.SystemArgument2, IO_NO_INCREMENT);
    if (!queued && !kernelMode) {
        // plain user APCs need an alertable thread: alert and retry once.
        // kernel APCs deliver on the next runnable moment, no alert needed.
        KeAlertThread(thread, UserMode);
        *Alerted = 1;
        KeInitializeApc(&apc->Kapc, thread, PryOriginalApcEnvironment,
                        PryApcKernelRoutine, PryApcRundown,
                        (PVOID)(ULONG_PTR)Target, UserMode, (PVOID)(ULONG_PTR)Arg1);
        apc->Kapc.SystemArgument1 = (PVOID)(ULONG_PTR)Arg2;
        apc->Kapc.SystemArgument2 = (PVOID)(ULONG_PTR)Arg3;
        queued = KeInsertQueueApc(&apc->Kapc, apc->Kapc.SystemArgument1, apc->Kapc.SystemArgument2, IO_NO_INCREMENT);
    }
    ObDereferenceObject(thread);
    if (!queued) {
        InterlockedDecrement(&PryApcOutstanding); // never entered the queue
        if (apc->Done) {
            apc->Done(apc->DoneCtx);
        }
        PryFree(apc);
        st = STATUS_UNSUCCESSFUL;
    } else {
        *Queued = 1;
        st = STATUS_SUCCESS;
    }
    return st;

out_unqueued:
    if (Done) {
        Done(DoneCtx);
    }
    return st;
}

NTSTATUS PryRemoteCall(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Target,
                         _In_ UINT64 Arg1, _In_ UINT64 Arg2, _In_ UINT64 Arg3,
                         _In_ UINT32 Flags, _Out_ PUINT32 Queued, _Out_ PUINT32 Alerted)
{
    return PryRemoteCallEx(Pid, Tid, Target, Arg1, Arg2, Arg3, Flags, NULL, NULL, Queued, Alerted);
}
