#include "PryDriver.h"

// StackWalk.c — SI adoption feature #9: kernel-stack walk primitive.
//
// Walks the target thread's kernel/user stack via RtlWalkFrameChain. The
// walk is delivered through a kernel-mode APC on the target thread via the
// existing PryRemoteCall + PRY_RC_FLAG_KERNEL machinery; the APC runs
// at PASSIVE_LEVEL in the target context, which is the only legal place for
// RtlWalkFrameChain. Default timeout is bounded at 500 ms (plan README §6)
// so a frozen target cannot wedge the sequential IOCTL queue.
//
// Lifetime: each call allocates a work-block with a 2-reference count
// (worker + waiter) and a KEVENT. The worker drops its reference after it
// records frames and signals the event; the waiter drops its reference
// after it copies the result into the caller's output buffer. Whichever
// side hits refs==0 frees the block. On timeout with partial_ok=false the
// waiter still drops its reference — the APC may fire late and will free
// the block on its own.

NTKERNELAPI ULONG NTAPI RtlWalkFrameChain(_Out_writes_(FrameCount) PVOID* Frames,
                                          _In_ ULONG FrameCount,
                                          _In_ ULONG Flags);

#define PRY_RTL_WALK_FRAME_CHAIN_USER_MODE 0x1

typedef struct _PRY_STACKWALK_WB {
    KEVENT  Done;
    volatile LONG Refs;
    UINT32  Flags;      // snapshotted from IN.Flags
    UINT32  MaxFrames;  // clamped to PRY_STACKWALK_MAX_FRAMES
    volatile UINT32 KernelCount;
    volatile UINT32 UserCount;
    volatile UINT32 Status;
    volatile UINT64 Rip;
    volatile UINT64 Rsp;
    PVOID   KernelFrames[PRY_STACKWALK_MAX_FRAMES];
    PVOID   UserFrames[PRY_STACKWALK_MAX_FRAMES];
} PRY_STACKWALK_WB, *PPRY_STACKWALK_WB;

static VOID PryStackWalkDeref(_In_ PPRY_STACKWALK_WB Wb)
{
    if (InterlockedDecrement(&Wb->Refs) == 0) {
        PryFree(Wb);
    }
}

// Runs on the target thread at PASSIVE_LEVEL (kernel-mode normal APC). The
// PryRemoteCall KAPC decrements PryApcOutstanding and frees its own
// KAPC — we only own the workblock reference here.
static VOID PryStackWalkWorker(_In_ UINT64 Arg1, _In_ UINT64 Arg2,
                                 _In_ UINT64 Arg3)
{
    PPRY_STACKWALK_WB wb = (PPRY_STACKWALK_WB)(ULONG_PTR)Arg1;
    ULONG k = 0, u = 0;
    UNREFERENCED_PARAMETER(Arg2);
    UNREFERENCED_PARAMETER(Arg3);
    if (!wb) {
        return;
    }
    __try {
        if (wb->Flags & PRY_STACKWALK_FLAG_KERNEL) {
            k = RtlWalkFrameChain(wb->KernelFrames, wb->MaxFrames, 0);
        }
        if (wb->Flags & PRY_STACKWALK_FLAG_USER) {
            u = RtlWalkFrameChain(wb->UserFrames, wb->MaxFrames,
                                  PRY_RTL_WALK_FRAME_CHAIN_USER_MODE);
        }
        wb->KernelCount = (UINT32)k;
        wb->UserCount = (UINT32)u;
        if (k) {
            wb->Rip = (UINT64)(ULONG_PTR)wb->KernelFrames[0];
        } else if (u) {
            wb->Rip = (UINT64)(ULONG_PTR)wb->UserFrames[0];
        }
        wb->Status = (UINT32)STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        wb->Status = (UINT32)GetExceptionCode();
    }
    KeSetEvent(&wb->Done, IO_NO_INCREMENT, FALSE);
    PryStackWalkDeref(wb);
}

NTSTATUS PryThreadStackWalk(_In_ const PRY_STACKWALK_IN* In,
                              _Out_ PPRY_STACKWALK_HDR Hdr,
                              _Out_writes_bytes_(FramesBytes) PVOID FramesBuf,
                              _In_ SIZE_T FramesBytes)
{
    NTSTATUS st;
    PETHREAD thread = NULL;
    PPRY_STACKWALK_WB wb = NULL;
    UINT32 queued = 0, alerted = 0;
    UINT64 pid = 0;
    UINT32 maxFrames;
    LARGE_INTEGER to;
    PPRY_STACKWALK_FRAME frames = (PPRY_STACKWALK_FRAME)FramesBuf;
    SIZE_T frameCap = FramesBytes / sizeof(PRY_STACKWALK_FRAME);
    UINT32 flags = In->Flags;
    UINT32 timeoutMs = In->TimeoutMs ? In->TimeoutMs : PRY_STACKWALK_DEFAULT_TIMEOUT_MS;

    RtlZeroMemory(Hdr, sizeof(*Hdr));
    if ((flags & PRY_STACKWALK_FLAG_BOTH) == 0) {
        flags |= PRY_STACKWALK_FLAG_BOTH;
    }
    if (!In->Tid) {
        Hdr->Status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }
    maxFrames = In->MaxFrames ? In->MaxFrames : PRY_STACKWALK_MAX_FRAMES;
    if (maxFrames > PRY_STACKWALK_MAX_FRAMES) {
        maxFrames = PRY_STACKWALK_MAX_FRAMES;
    }

    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)In->Tid, &thread);
    if (!NT_SUCCESS(st)) {
        Hdr->Status = (UINT32)st;
        return st;
    }
    pid = (UINT64)(ULONG_PTR)PsGetThreadProcessId(thread);
    Hdr->Pid = (UINT32)pid;

    if (PsIsThreadTerminating(thread)) {
        ObDereferenceObject(thread);
        Hdr->Status = (UINT32)STATUS_SUSPEND_COUNT_EXCEEDED;
        return STATUS_SUSPEND_COUNT_EXCEEDED;
    }
    if (PsGetThreadFreezeCount(thread) &&
        !(flags & PRY_STACKWALK_FLAG_FORCE_APC)) {
        ObDereferenceObject(thread);
        Hdr->Status = (UINT32)STATUS_SUSPEND_COUNT_EXCEEDED;
        return STATUS_SUSPEND_COUNT_EXCEEDED;
    }

    wb = (PPRY_STACKWALK_WB)PryAlloc(sizeof(*wb));
    if (!wb) {
        ObDereferenceObject(thread);
        Hdr->Status = (UINT32)STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(wb, sizeof(*wb));
    KeInitializeEvent(&wb->Done, NotificationEvent, FALSE);
    wb->Refs = 2;
    wb->Flags = flags;
    wb->MaxFrames = maxFrames;

    st = PryRemoteCall(pid, In->Tid, (UINT64)(ULONG_PTR)PryStackWalkWorker,
                         (UINT64)(ULONG_PTR)wb, 0, 0,
                         PRY_RC_FLAG_KERNEL, &queued, &alerted);
    if (!NT_SUCCESS(st) || !queued) {
        PryFree(wb);
        ObDereferenceObject(thread);
        Hdr->Status = (UINT32)st;
        Hdr->Flags |= PRY_STACKWALK_HDR_APC_UNDELIVERABLE;
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }

    to.QuadPart = -(LONGLONG)timeoutMs * 10000LL;
    st = KeWaitForSingleObject(&wb->Done, Executive, KernelMode, FALSE, &to);
    if (st == STATUS_TIMEOUT) {
        Hdr->Flags |= PRY_STACKWALK_HDR_TIMED_OUT;
        if (!(flags & PRY_STACKWALK_FLAG_TIMEOUT_PARTIAL_OK)) {
            PryStackWalkDeref(wb);
            ObDereferenceObject(thread);
            Hdr->Status = (UINT32)STATUS_TIMEOUT;
            return STATUS_TIMEOUT;
        }
    }

    // Copy results while we still own the ref — worker frees on its own ref.
    {
        UINT32 k = wb->KernelCount;
        UINT32 u = wb->UserCount;
        UINT32 copied = 0;
        // track what was ACTUALLY written separately
        // from k/u (which are only clamped to maxFrames, the walk's own
        // cap) -- the copy loops below additionally stop at frameCap, the
        // caller's real output buffer capacity. Reporting k/u unclamped to
        // frameCap told a caller with a smaller buffer that more valid
        // frames existed than were ever written, and reading them past
        // frameCap is uninitialized/stale memory.
        UINT32 copiedK = 0, copiedU = 0;
        UINT32 i;
        if (k > maxFrames) k = maxFrames;
        if (u > maxFrames) u = maxFrames;
        for (i = 0; i < k && copied < frameCap; i++, copied++, copiedK++) {
            frames[copied].Rip = (UINT64)(ULONG_PTR)wb->KernelFrames[i];
            frames[copied].ModuleTag = PRY_STACKWALK_MOD_KERNEL;
            frames[copied].ModuleBase = 0;
            frames[copied].Reserved = 0;
        }
        for (i = 0; i < u && copied < frameCap; i++, copied++, copiedU++) {
            frames[copied].Rip = (UINT64)(ULONG_PTR)wb->UserFrames[i];
            frames[copied].ModuleTag = PRY_STACKWALK_MOD_USER;
            frames[copied].ModuleBase = 0;
            frames[copied].Reserved = 0;
        }
        Hdr->KernelFrameCount = copiedK;
        Hdr->UserFrameCount = copiedU;
        Hdr->Rip = wb->Rip;
        Hdr->Rsp = wb->Rsp;
        Hdr->Status = wb->Status;
        if ((Hdr->Flags & PRY_STACKWALK_HDR_TIMED_OUT) == 0) {
            if (flags & PRY_STACKWALK_FLAG_KERNEL) Hdr->Flags |= PRY_STACKWALK_HDR_KERNEL_DONE;
            if (flags & PRY_STACKWALK_FLAG_USER)   Hdr->Flags |= PRY_STACKWALK_HDR_USER_DONE;
        }
    }
    PryStackWalkDeref(wb);
    ObDereferenceObject(thread);
    PryLog("STACKWALK tid=%llu -> k=%u u=%u flags=%x st=%x",
             In->Tid, Hdr->KernelFrameCount, Hdr->UserFrameCount,
             Hdr->Flags, Hdr->Status);
    return Hdr->Status ? (NTSTATUS)Hdr->Status : STATUS_SUCCESS;
}
