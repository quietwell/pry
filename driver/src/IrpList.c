#include "PryDriver.h"

// IrpList.c — SI slice 03 Feature 4: KTHREAD.IrpList walker.
//
// Walks the per-thread IRP list under PsLookupThreadByThreadId's
// reference. The walk itself happens inside IoCancelSpinLock (documented
// synchronization against IoCancelIrp) so we never race the kernel's
// own cancel path. Every ETHREAD/KTHREAD scalar offset we need —
// specifically the offset of the IrpList LIST_ENTRY, the offset of the
// Thread.IrpListEntry on each IRP, and the StackCount — rides on the
// Wave 3 dyn-data probe (PryDyn.Valid). Until Wave 3 ships we return
// STATUS_NOT_SUPPORTED after the Ob round trip so Verifier's Object
// Reference Tracking sees a clean leave-with-no-leak path and the IOCTL
// slot stays live for callers to probe.
//
// Mirrors the shape of WaitInfo.c (feature #3) exactly — Verifier
// matrix (special pool + IRQL + security + object tracking) is
// identical and the per-request lifecycle (ObReference / dispatch /
// ObDereference) never deviates on error.

NTSTATUS PryThreadIrpList(_In_ UINT64 Tid,
                            _In_ const PRY_IRP_LIST_IN* In,
                            _Out_writes_bytes_(CapacityBytes) PVOID Buf,
                            _In_ SIZE_T CapacityBytes,
                            _Out_ PUINT32 BytesWritten)
{
    PPRY_IRP_LIST_HDR hdr;
    PETHREAD thread = NULL;
    NTSTATUS st;

    if (!Buf || CapacityBytes < sizeof(PRY_IRP_LIST_HDR) || !BytesWritten) {
        if (BytesWritten) *BytesWritten = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }
    *BytesWritten = sizeof(PRY_IRP_LIST_HDR);

    hdr = (PPRY_IRP_LIST_HDR)Buf;
    RtlZeroMemory(hdr, sizeof(*hdr));

    if (!In || !Tid) {
        hdr->Status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    // ObReferenceObjectByHandle equivalent: PsLookupThreadByThreadId
    // bumps the KTHREAD refcount for us. We release it unconditionally
    // on every return path — Verifier Object Reference Tracking checks
    // this is paired.
    st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)Tid, &thread);
    if (!NT_SUCCESS(st)) {
        hdr->Status = (UINT32)st; // STATUS_INVALID_CID surfaces here
        return STATUS_SUCCESS;
    }

    // Owning pid is cheap and does not need dyn-data (PsGetThreadProcessId
    // is a documented export).
    hdr->Pid = (UINT32)(ULONG_PTR)PsGetThreadProcessId(thread);

    // Every field under KTHREAD.IrpList sits behind the Wave 3
    // signed-offset blob. comm/abi/dyn.h is still a landing stub, so
    // PryDyn.Valid is false and we surface
    // STATUS_NOT_SUPPORTED. When Wave 3 lands:
    //
    //   1. Read IrpListHead = PryReadKthreadIrpListHead(thread) under
    //      PryDyn.KthreadIrpList offset.
    //   2. KeAcquireSpinLock(&IoCancelSpinLock) — same discipline as
    //      IoCancelIrp uses to protect the list.
    //   3. Walk the LIST_ENTRY chain under PryDyn.IrpThreadListEntry
    //      offset per IRP; capture {IrpVa, DeviceObject,
    //      CancelRoutineVa, MajorFunction, MinorFunction, Flags} into
    //      PRY_IRP_LIST_ENTRY rows after the header.
    //   4. For each DeviceObject, probe ObGetObjectType->TypeName or
    //      the DRIVER_OBJECT->DriverName via a documented helper (we
    //      can skip resolving to a wide string in the driver — the
    //      agent-side can look up names from the module table).
    //   5. KeReleaseSpinLock(&IoCancelSpinLock) and ObDereferenceObject.
    //
    // Rows are PACKED after the header, Count rows written, Required
    // = total IRPs seen (may exceed Count on truncation).
    hdr->Status = (UINT32)STATUS_NOT_SUPPORTED;
    hdr->Count = 0;
    hdr->Required = 0;
    hdr->Truncated = 0;
    UNREFERENCED_PARAMETER(In); // MaxEntries unused until Wave 3

    ObDereferenceObject(thread);
    return STATUS_SUCCESS;
}
