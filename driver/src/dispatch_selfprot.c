#include "PryDriver.h"
#include "dispatch_internal.h"

// dispatch_selfprot.c — SI adoption feature #21: dispatcher glue for
// PRY_IOCTL_SELFPROT_CONFIG and PRY_IOCTL_SELFPROT_STATUS.
//
// Shape: METHOD_BUFFERED in/out, mirrors dispatch_watchdog.c's one-shot
// IOCTLs. The ObRegisterCallbacks state lives in SelfProt.c; this TU is
// pure request/response marshalling + logging.

SIZE_T PryHandleSelfProtConfig(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_SELFPROT_CONFIG_IN in;
    PVOID inBuf;
    PVOID outBuf;
    SIZE_T inLen;
    SIZE_T outLen;
    PPRY_SELFPROT_CONFIG_OUT out;
    NTSTATUS st;

    st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    st = PryOutput(Request, sizeof(PRY_SELFPROT_CONFIG_OUT),
                     &outBuf, &outLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));
    out = (PPRY_SELFPROT_CONFIG_OUT)outBuf;
    PrySelfProtApply(&in, out);
    PryLog("SELFPROT_CFG enable=%u flags=0x%x pids=%u -> st=%x inst=%u alt=%u",
             in.Enable, in.Flags, in.PidCount,
             out->Status, out->Installed, out->Altitude);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_SELFPROT_CONFIG_OUT);
}

SIZE_T PryHandleSelfProtStatus(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID outBuf;
    SIZE_T outLen;
    NTSTATUS st = PryOutput(Request, sizeof(PRY_SELFPROT_STATUS_OUT),
                              &outBuf, &outLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    PrySelfProtQuery((PPRY_SELFPROT_STATUS_OUT)outBuf);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_SELFPROT_STATUS_OUT);
}
