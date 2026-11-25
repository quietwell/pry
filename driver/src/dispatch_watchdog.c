#include "PryDriver.h"
#include "dispatch_internal.h"

// v8: watchdog. Arm/Kick/Disarm are point ops; List is variable-length. Every
// handler runs at PASSIVE_LEVEL and does not itself hold the watchdog table
// spinlock — PryWatchdogXxx does the locking.
SIZE_T PryHandleWatchdogArm(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_WDG_ARM_IN in;
    PVOID out;
    PRY_WDG_ARM_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    // guarantee label terminator inside the driver's copy; PryWatchdogArm
    // does the same but it never hurts to normalize at the ABI boundary.
    in.Label[PRY_WDG_MAX_LABEL - 1] = '\0';
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)PryWatchdogArm(in.Id, in.DeadlineMs, in.BugcheckCode,
                                             in.Flags, in.Cookie, in.Label);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("WDGARM id=%u deadline_ms=%u flags=0x%x -> st=%x",
             in.Id, in.DeadlineMs, in.Flags, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleWatchdogKick(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_WDG_KICK_IN in;
    PVOID out;
    PRY_WDG_KICK_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)PryWatchdogKick(in.Id, in.DeadlineMs, in.Cookie,
                                              &result.KickCount, &result.LastKickUs,
                                              &result.DeadlineUs);
    RtlCopyMemory(out, &result, sizeof(result));
    // Kick is high-cadence; log only on error to keep the log-file growth sane.
    if (result.Status != 0) {
        PryLog("WDGKICK id=%u deadline_ms=%u -> st=%x", in.Id, in.DeadlineMs, result.Status);
    }
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleWatchdogDisarm(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_WDG_DISARM_IN in;
    PVOID out;
    PRY_WDG_DISARM_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)PryWatchdogDisarm(in.Id);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("WDGDIS id=%u -> st=%x", in.Id, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleWatchdogList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID buf;
    SIZE_T len;
    PPRY_WDG_LIST_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    UINT64 nowUs = 0;
    NTSTATUS st;

    st = PryOutput(Request, sizeof(PRY_WDG_LIST_HDR), &buf, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PPRY_WDG_LIST_HDR)buf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = (UINT32)((len - sizeof(PRY_WDG_LIST_HDR)) / sizeof(PRY_WDG_ENTRY));

    st = PryWatchdogList((PUCHAR)buf + sizeof(PRY_WDG_LIST_HDR),
                            (SIZE_T)capacity * sizeof(PRY_WDG_ENTRY),
                            &count, &required, &nowUs);
    hdr->Status = (UINT32)st;
    hdr->Count = count;
    hdr->Required = required;
    hdr->NowUs = nowUs;
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_WDG_LIST_HDR) + (SIZE_T)count * sizeof(PRY_WDG_ENTRY);
}
