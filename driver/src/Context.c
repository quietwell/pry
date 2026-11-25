#include "PryDriver.h"

static NTSTATUS PryEnumProcessThreads(_In_ UINT64 Pid, _In_ NTSTATUS (*Fn)(_In_ PETHREAD, _Inout_ PVOID),
                                        _Inout_ PVOID Ctx, _Out_ PUINT32 Applied)
{
    // v6: Pid=0 == system-wide. Walk every process, call Fn on every
    // thread. Stops on first hard error (any single thread failure is
    // swallowed and skipped so a defunct thread doesn't abort the sweep).
    NTSTATUS st;
    PUCHAR buf = NULL;
    SIZE_T size = 1 << 20;
    UINT32 applied = 0;
    PETHREAD thread;

    *Applied = 0;
    for (;;) {
        PryFree(buf);
        buf = (PUCHAR)PryAlloc(size);
        if (!buf) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        st = ZwQuerySystemInformation(PRY_SYS_PROC_INFO_CLASS, buf, (ULONG)size, NULL);
        if (NT_SUCCESS(st)) {
            break;
        }
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            if (size > (64ull << 20)) {
                PryFree(buf);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            size *= 2;
            continue;
        }
        PryFree(buf);
        return st;
    }

    st = STATUS_NOT_FOUND;
    {
        PUCHAR cur = buf;
        BOOLEAN found = FALSE;
        while (cur) {
            PRY_SYS_PROC_INFO* p = (PRY_SYS_PROC_INFO*)cur;
            // Match: exact pid, or global sweep (Pid==0).
            if (Pid == 0 || (UINT64)(ULONG_PTR)p->UniqueProcessId == Pid) {
                found = TRUE;
                st = STATUS_SUCCESS;
                PRY_SYS_THREAD_INFO* threads = (PRY_SYS_THREAD_INFO*)(cur + sizeof(PRY_SYS_PROC_INFO));
                for (ULONG i = 0; i < p->NumberOfThreads; i++) {
                    if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)threads[i].UniqueThread, &thread))) {
                        continue;
                    }
                    // the snapshot holds TIDs, not thread objects. A
                    // thread that exited after the snapshot can leave its TID
                    // to a thread of another process, which the lookup above
                    // would then return. Only threads of the snapshot's own
                    // process are handed to Fn.
                    if ((UINT64)(ULONG_PTR)PsGetThreadProcessId(thread) != (UINT64)(ULONG_PTR)p->UniqueProcessId) {
                        ObDereferenceObject(thread);
                        continue;
                    }
                    if (NT_SUCCESS(Fn(thread, Ctx))) {
                        applied++;
                    }
                    ObDereferenceObject(thread);
                }
                if (Pid != 0) {
                    // Exact-pid match: only one process qualifies, stop early.
                    break;
                }
            }
            cur = p->NextEntryOffset ? cur + p->NextEntryOffset : NULL;
        }
        if (!found) {
            // Pid==0 with an empty list is impossible (system+idle at
            // minimum), so this branch is only reachable for exact-pid.
            (void)0;
        }
    }
    PryFree(buf);
    if (applied) {
        *Applied = applied;
        return STATUS_SUCCESS;
    }
    return st;
}

// Generic context op against a thread of ANY process. On 24H2+ the kernel
// rejects PsGet/SetContextThread(KernelMode) with CONTEXT_DEBUG_REGISTERS
// (0xC0000001 on other threads, 0xC0000005 on self), so we use the debugger
// path instead: allocate the CONTEXT in the TARGET's user space, attach, and
// issue the UserMode call - the probe passes and the kernel APC machinery
// applies/reads the full context (DRs included) on any build.
NTSTATUS PryThreadCtxOp(_In_ PETHREAD Thread, _Inout_ PCONTEXT Ctx, _In_ BOOLEAN Set)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    UINT64 buf = 0;

    proc = IoThreadToProcess(Thread);
    if (!proc) {
        return STATUS_INVALID_PARAMETER;
    }
    // Ps*ContextThread waits on a special APC delivered BY the target
    // thread. A frozen (debug stop / NtSuspendProcess) or terminating
    // thread never delivers — the call would block forever, and the
    // device queue is sequential so one blocked ioctl wedges them all.
    // Callers that may also face NtSuspendThread-style suspension (not
    // covered by FreezeCount) have to prefilter: see the PryThreadIsSuspended
    // helper in BpHw.c, which uses NtQueryInformationThread(ThreadSuspendCount).
    if (PsIsThreadTerminating(Thread) || PsGetThreadFreezeCount(Thread)) {
        return STATUS_SUSPEND_COUNT_EXCEEDED;
    }
    st = PryUserAlloc((UINT64)(ULONG_PTR)PsGetProcessId(proc), 0x1000, PAGE_READWRITE, &buf);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    KeStackAttachProcess((PRKPROCESS)proc, &apc);
    __try {
        if (Set) {
            RtlCopyMemory((PVOID)(ULONG_PTR)buf, Ctx, sizeof(CONTEXT));
            st = PsSetContextThread(Thread, (PCONTEXT)(ULONG_PTR)buf, UserMode);
        } else {
            st = PsGetContextThread(Thread, (PCONTEXT)(ULONG_PTR)buf, UserMode);
            if (NT_SUCCESS(st)) {
                RtlCopyMemory(Ctx, (PVOID)(ULONG_PTR)buf, sizeof(CONTEXT));
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    PryUserFree((UINT64)(ULONG_PTR)PsGetProcessId(proc), buf);
    return st;
}

NTSTATUS PryCtxGet(_In_ UINT64 Tid, _In_ ULONG Flags, _Out_ PVOID Context)
{
    NTSTATUS st;
    PETHREAD thread;
    CONTEXT ctx;

    if (!Tid || !Context) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &thread);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = Flags;
    st = PryThreadCtxOp(thread, &ctx, FALSE);
    if (NT_SUCCESS(st)) {
        RtlCopyMemory(Context, &ctx, sizeof(ctx));
    }
    ObDereferenceObject(thread);
    return st;
}

NTSTATUS PryCtxSet(_In_ UINT64 Tid, _In_ ULONG Flags, _In_ PVOID Context)
{
    NTSTATUS st;
    PETHREAD thread;
    CONTEXT ctx;

    if (!Tid || !Context) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &thread);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    RtlCopyMemory(&ctx, Context, sizeof(ctx));
    ctx.ContextFlags = Flags;
    st = PryThreadCtxOp(thread, &ctx, TRUE);
    ObDereferenceObject(thread);
    return st;
}

NTSTATUS PryProcessThreadApply(_In_ UINT64 Pid, _In_ UINT64 Tid,
                                 _In_ NTSTATUS (*Fn)(_In_ PETHREAD Thread, _Inout_ PVOID Ctx),
                                 _Inout_ PVOID Ctx, _Out_ PUINT32 Applied)
{
    NTSTATUS st = STATUS_SUCCESS;
    UINT32 applied = 0;

    *Applied = 0;
    // v6: Pid==0 && Tid==0 is now valid (system-wide sweep). The caller
    // (PryBpHwSet with FLAG_GLOBAL) is responsible for gating that
    // dangerous mode; here we just execute.
    if (Tid) {
        PETHREAD thread;
        st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &thread);
        if (!NT_SUCCESS(st)) {
            return st;
        }
        // a TID names whichever thread holds it now. Refuse a thread
        // outside the requested process rather than arm or clear it.
        if (Pid && (UINT64)(ULONG_PTR)PsGetThreadProcessId(thread) != Pid) {
            ObDereferenceObject(thread);
            return STATUS_NOT_FOUND;
        }
        st = Fn(thread, Ctx);
        if (NT_SUCCESS(st)) {
            applied = 1;
        }
        ObDereferenceObject(thread);
    } else {
        st = PryEnumProcessThreads(Pid, Fn, Ctx, &applied);
    }
    *Applied = applied;
    return st;
}
