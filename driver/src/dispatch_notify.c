#include "PryDriver.h"
#include "dispatch_internal.h"

// v10 dispatch: notify ring (SUBSCRIBE/READ/DISABLE/STATS) + kernel
// enumeration (OBJ_ENUM, THREAD_LIST). Same two-phase header+entries
// output format as the process/VAD/handle lists.

SIZE_T PryHandleNotifySubscribe(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_NOTIFY_SUBSCRIBE_IN in;
    PVOID out;
    PPRY_NOTIFY_SUBSCRIBE_OUT res;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(PRY_NOTIFY_SUBSCRIBE_OUT), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    res = (PPRY_NOTIFY_SUBSCRIBE_OUT)out;
    RtlZeroMemory(res, sizeof(*res));
    // v11: in.Flags (was Reserved) — CLASS_BP needs FLAG_BP_HOOK_OK.
    res->Status = (UINT32)PryNotifySubscribe(in.Classes, in.Flags,
                                               &res->Registered);
    PryLog("NOTIFY_SUB classes=%x flags=%x -> st=%x ok=%x",
             in.Classes, in.Flags, res->Status, res->Registered);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_NOTIFY_SUBSCRIBE_OUT);
}

SIZE_T PryHandleNotifyRead(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_NOTIFY_READ_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    NTSTATUS st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));

    PVOID sys;
    SIZE_T len;
    st = PryOutMdl(Request, &sys, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    if (len < sizeof(PRY_NOTIFY_READ_HDR)) {
        *Status = STATUS_BUFFER_TOO_SMALL;
        return 0;
    }

    PPRY_NOTIFY_READ_HDR hdr = (PPRY_NOTIFY_READ_HDR)sys;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 count = 0;
    UINT64 dropped = 0, lastSeq = 0;
    hdr->Status = (UINT32)PryNotifyRead(in.Max, (PPRY_EVT)((PUCHAR)sys + sizeof(*hdr)),
                                          len - sizeof(*hdr), &count, &dropped, &lastSeq);
    hdr->Count = count;
    hdr->Dropped = dropped;
    hdr->LastSeq = lastSeq;
    PryLog("NOTIFY_READ max=%u -> n=%u dropped=%llu last=%llu",
             in.Max, count, dropped, lastSeq);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_NOTIFY_READ_HDR) + (SIZE_T)count * sizeof(PRY_EVT);
}

SIZE_T PryHandleNotifyDisable(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID out;
    SIZE_T len;
    NTSTATUS st = PryOutput(Request, sizeof(PRY_NOTIFY_STATS_OUT), &out, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    PPRY_NOTIFY_STATS_OUT res = (PPRY_NOTIFY_STATS_OUT)out;
    NTSTATUS disableSt = PryNotifyDisable();
    RtlZeroMemory(res, sizeof(*res));
    res->Status = (UINT32)disableSt;
    PryLog("NOTIFY_DISABLE -> st=%x", disableSt);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_NOTIFY_STATS_OUT);
}

SIZE_T PryHandleNotifyStats(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID out;
    SIZE_T len;
    NTSTATUS st = PryOutput(Request, sizeof(PRY_NOTIFY_STATS_OUT), &out, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    PryNotifyStats((PPRY_NOTIFY_STATS_OUT)out);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_NOTIFY_STATS_OUT);
}

SIZE_T PryHandleObjEnum(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_OBJ_ENUM_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    NTSTATUS st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));
    in.Path[PRY_OBJ_PATH_CCH - 1] = L'\0';

    PVOID sys;
    SIZE_T len;
    st = PryOutMdl(Request, &sys, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    if (len < sizeof(PRY_OBJ_HDR) || in.Path[0] != L'\\') {
        *Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
        return 0;
    }

    PPRY_OBJ_HDR hdr = (PPRY_OBJ_HDR)sys;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 count = 0, required = 0, truncated = 0;
    hdr->Status = (UINT32)PryObjEnum(in.Path, in.Depth, in.MaxEntries,
                                       (PUCHAR)sys + sizeof(*hdr),
                                       len - sizeof(*hdr),
                                       &count, &required, &truncated);
    hdr->Count = count;
    hdr->Required = required;
    hdr->Truncated = truncated;
    PryLog("OBJENUM path=%S depth=%u -> st=%x n=%u/%u trunc=%u",
             in.Path, in.Depth, hdr->Status, count, required, truncated);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_OBJ_HDR) + (SIZE_T)count * sizeof(PRY_OBJ_ENTRY);
}

SIZE_T PryHandleThreadList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_THREADLIST_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    NTSTATUS st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));

    PVOID sys;
    SIZE_T len;
    st = PryOutMdl(Request, &sys, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    if (len < sizeof(PRY_THREAD_HDR)) {
        *Status = STATUS_BUFFER_TOO_SMALL;
        return 0;
    }

    PPRY_THREAD_HDR hdr = (PPRY_THREAD_HDR)sys;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 count = 0, required = 0;
    hdr->Status = (UINT32)PryThreadList(in.Pid, (PUCHAR)sys + sizeof(*hdr),
                                          len - sizeof(*hdr), &count, &required);
    hdr->Count = count;
    hdr->Required = required;
    PryLog("THREADS pid=%u -> st=%x n=%u/%u", in.Pid, hdr->Status, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_THREAD_HDR) + (SIZE_T)count * sizeof(PRY_THREAD_ENTRY);
}
