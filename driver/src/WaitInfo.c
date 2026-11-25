#include "PryDriver.h"

// WaitInfo.c — SI adoption feature #3: analyze-wait on thread.
//
// Walks ETHREAD/KTHREAD under PsLookupThreadByThreadId's reference,
// reports the last_syscall + kernel_stack scalar fields plus the live
// wait state. Documented ObReference/Dereference pairing — no
// ETHREAD-offset reads happen until the Wave 3 dyn-data primitive
// (PryDyn.Valid) lands and surfaces the per-build offsets. Until then
// the handler returns STATUS_NOT_SUPPORTED after the ObReference round
// trip so Verifier's Object Reference Tracking sees a clean leave-with-no-
// leak path and the IOCTL slot stays live for callers to probe.
//
// See an internal plan
// Feature #1.

NTSTATUS PryThreadWaitInfo(_In_ UINT64 Tid,
                             _In_ const PRY_WAIT_INFO_IN* In,
                             _Out_writes_bytes_(CapacityBytes) PVOID Buf,
                             _In_ SIZE_T CapacityBytes,
                             _Out_ PUINT32 BytesWritten)
{
    PPRY_WAIT_INFO_HDR hdr;
    PETHREAD thread = NULL;
    NTSTATUS st;

    if (!Buf || CapacityBytes < sizeof(PRY_WAIT_INFO_HDR) || !BytesWritten) {
        if (BytesWritten) *BytesWritten = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }
    *BytesWritten = sizeof(PRY_WAIT_INFO_HDR);

    hdr = (PPRY_WAIT_INFO_HDR)Buf;
    RtlZeroMemory(hdr, sizeof(*hdr));

    if (!In || !Tid) {
        hdr->Status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS; // header carries the error — same pattern as other list IOCTLs
    }
    if (In->FrameCapture > PRY_WAIT_INFO_FRAME_MAX ||
        In->UserStackCapture > PRY_WAIT_INFO_USER_STACK_MAX) {
        hdr->Status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &thread);
    if (!NT_SUCCESS(st)) {
        hdr->Status = (UINT32)st; // STATUS_INVALID_CID surfaces here
        return STATUS_SUCCESS;
    }

    // Owning process pid is cheap and does not need dyn-data.
    hdr->Pid = (UINT32)(ULONG_PTR)PsGetThreadProcessId(thread);

    // All further ETHREAD/KTHREAD scalar reads sit behind the Wave 3
    // signed-offset blob. Dyn-data is empty (comm/abi/dyn.h is a landing
    // stub), so we surface STATUS_NOT_SUPPORTED after the
    // reference round-trip. The IOCTL slot stays live — callers can
    // probe for the feature by issuing the IOCTL and reading
    // hdr->Status; agents degrade to kind='agent_version' /
    // kind='not_supported' until dyn-data lands.
    //
    // When Wave 3 lands, replace this block with the ETHREAD/KTHREAD
    // walk per an internal plan
    // Feature #1 (dyn-data slot names already picked out in that doc).
    hdr->Status = (UINT32)STATUS_NOT_SUPPORTED;

    ObDereferenceObject(thread);
    return STATUS_SUCCESS;
}
