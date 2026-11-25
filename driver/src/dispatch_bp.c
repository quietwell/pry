#include "PryDriver.h"
#include "dispatch_internal.h"

SIZE_T PryHandleBpSwSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_BP_SW_SET_IN in;
    PVOID out;
    PRY_BP_SW_SET_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)PryBpSwSet(in.Pid, in.Address, &result.Id, &result.OrigByte);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("BPSWSET pid=%llu addr=%llx -> st=%x id=%u", in.Pid, in.Address, result.Status, result.Id);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleBpSwClear(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_BP_SW_CLEAR_IN in;
    PVOID out;
    PRY_USER_FREE_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)PryBpSwClear(in.Pid, in.Address, in.Id);
    result.Reserved = 0;
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("BPSWCLR pid=%llu addr=%llx id=%u -> st=%x", in.Pid, in.Address, in.Id, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleBpHwSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_BP_HW_SET_IN in;
    PVOID out;
    PRY_BP_HW_SET_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)PryBpHwSet(in.Pid, in.Tid, in.Address, in.Slot, in.Length, in.Access,
                                         in.Flags,
                                         &result.Id, &result.ThreadsPatched);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("BPHWSET pid=%llu tid=%llu addr=%llx slot=%u flags=%x -> st=%x patched=%u",
             in.Pid, in.Tid, in.Address, in.Slot, in.Flags, result.Status, result.ThreadsPatched);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleBpHwClear(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_BP_HW_CLEAR_IN in;
    PVOID out;
    PRY_BP_HW_CLEAR_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)PryBpHwClear(in.Pid, in.Tid, in.Slot, &result.ThreadsPatched);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("BPHWCLR pid=%llu tid=%llu slot=%u -> st=%x", in.Pid, in.Tid, in.Slot, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleBpList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID buf;
    SIZE_T len;
    PPRY_BP_LIST_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st;

    st = PryOutput(Request, sizeof(PRY_BP_LIST_HDR), &buf, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PPRY_BP_LIST_HDR)buf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = (UINT32)((len - sizeof(PRY_BP_LIST_HDR)) / sizeof(PRY_BP_ENTRY));

    st = PryBpList((PUCHAR)buf + sizeof(PRY_BP_LIST_HDR), (SIZE_T)capacity * sizeof(PRY_BP_ENTRY),
                     &count, &required);
    hdr->Status = (UINT32)st;
    hdr->Count = count;
    hdr->Required = required;
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_BP_LIST_HDR) + (SIZE_T)count * sizeof(PRY_BP_ENTRY);
}
