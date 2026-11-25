#include "PryDriver.h"
#include "dispatch_internal.h"

SIZE_T PryHandlePhysRanges(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID buf;
    SIZE_T len;
    PPRY_PHYS_RANGES_HDR hdr;
    ULONG count = 0, total = 0, capacity;
    NTSTATUS st;

    st = PryOutput(Request, sizeof(PRY_PHYS_RANGES_HDR), &buf, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PPRY_PHYS_RANGES_HDR)buf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = (ULONG)((len - sizeof(PRY_PHYS_RANGES_HDR)) / sizeof(PRY_PHYS_RANGE_ENTRY));
    if (capacity > PRY_MAX_PHYS_RANGES) {
        capacity = PRY_MAX_PHYS_RANGES;
    }
    st = PryPhysRangesEnumerate((PRY_PHYS_RANGE_ENTRY*)((PUCHAR)buf + sizeof(*hdr)),
                                  capacity, &count, &total);
    hdr->Status = (UINT32)st;
    hdr->Count = count;
    hdr->Required = total;
    PryLog("PHYSRNG count=%u total=%u -> st=%x", count, total, hdr->Status);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_PHYS_RANGES_HDR) + (SIZE_T)count * sizeof(PRY_PHYS_RANGE_ENTRY);
}

SIZE_T PryHandlePoolScan(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID inbuf, outbuf;
    SIZE_T inlen, outlen;
    PPRY_POOL_HDR hdr;
    NTSTATUS st;
    PRY_POOL_SCAN_IN local;
    ULONG count = 0, required = 0, considered = 0, capacity;
    ULONG holes = 0, span_trunc = 0, last_idx = 0, next_cursor = 0;

    st = PryInput(Request, sizeof(PRY_POOL_SCAN_IN), &inbuf, &inlen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&local, inbuf, sizeof(local));

    st = PryOutput(Request, sizeof(PRY_POOL_HDR), &outbuf, &outlen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PPRY_POOL_HDR)outbuf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = (ULONG)((outlen - sizeof(PRY_POOL_HDR)) / sizeof(PRY_POOL_ENTRY));

    st = PryPoolScan(&local,
                       (PRY_POOL_ENTRY*)((PUCHAR)outbuf + sizeof(*hdr)),
                       capacity, &count, &required, &considered,
                       &holes, &span_trunc, &last_idx, &next_cursor);
    hdr->Status = (UINT32)st;
    hdr->Count = count;
    hdr->Required = required;
    hdr->Considered = considered;
    hdr->Holes = holes;
    hdr->SpanTruncated = span_trunc;
    hdr->LastIndex = last_idx;
    hdr->NextCursor = next_cursor;
    PryLog("POOLSCAN tag=%08x flags=%x span=%u cur=%u -> st=%x count=%u "
             "required=%u considered=%u holes=%u span_trunc=%u last=%u next=%u",
             local.TagFilter, local.Flags, local.ContentSpan, local.Cursor,
             hdr->Status, count, required, considered,
             holes, span_trunc, last_idx, next_cursor);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_POOL_HDR) + (SIZE_T)count * sizeof(PRY_POOL_ENTRY);
}

// v5: VA -> PA via the page-table walk. v12 grows it: Cr3 (foreign-space
// walk) and Pid (process tables via KeStackAttachProcess — the deferred
// USER-space feature from v7). Both directions are size-tolerant: a 16-byte
// legacy IN parses as Cr3=0/Pid=0; a 16-byte OUT gets only the legacy
// prefix back.
SIZE_T PryHandleVaTranslate(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_VA_TRANSLATE_IN in;
    PRY_VA_TRANSLATE_OUT result;
    PVOID inBuf, out;
    SIZE_T inLen = 0, outLen = 0, repLen;
    UINT64 pa = 0, usedCr3 = 0;
    UINT32 shift = 0;
    NTSTATUS st;

    // 16-byte minimum keeps v11 callers working; the v12 tail fields only
    // exist when the input is the full 24-byte struct.
    st = PryInput(Request, 16, &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&in, sizeof(in));
    RtlCopyMemory(&in, inBuf, inLen < sizeof(in) ? inLen : sizeof(in));

    st = PryOutput(Request, 16, &out, &outLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    repLen = outLen < sizeof(result) ? outLen : sizeof(result);

    RtlZeroMemory(&result, sizeof(result));
    st = PryTranslateVaEx(in.Va, in.Cr3, in.Pid, &pa, &shift, &usedCr3)
         ? STATUS_SUCCESS : STATUS_INVALID_ADDRESS;
    result.Status = (UINT32)st;
    result.PageSizeShift = shift;
    result.PhysicalAddress = pa;
    result.Cr3 = usedCr3;
    RtlCopyMemory(out, &result, repLen);
    PryLog("VATRAN va=%llx cr3=%llx pid=%llu -> st=%x pa=%llx shift=%u used=%llx",
             in.Va, in.Cr3, in.Pid, result.Status, pa, shift, usedCr3);
    *Status = STATUS_SUCCESS;
    return repLen;
}

// v12: per-CPU IDT enumeration — driver-side __sidt + KIDTENTRY64 decode
// (Idt.c). Same hdr+rows OUT_DIRECT shape as OBJ_ENUM/THREAD_LIST.
SIZE_T PryHandleIdtList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_IDT_LIST_IN in;
    PVOID inBuf, sys;
    SIZE_T inLen, len;
    NTSTATUS st;

    st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));

    st = PryOutMdl(Request, &sys, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    if (len < sizeof(PRY_IDT_LIST_HDR)) {
        *Status = STATUS_BUFFER_TOO_SMALL;
        return 0;
    }

    PPRY_IDT_LIST_HDR hdr = (PPRY_IDT_LIST_HDR)sys;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 count = 0, required = 0, firstLimit = 0;
    UINT64 firstBase = 0;
    hdr->Status = (UINT32)PryIdtList(in.AllCpus,
                                       (PUCHAR)sys + sizeof(*hdr),
                                       len - sizeof(*hdr),
                                       &count, &required,
                                       &firstBase, &firstLimit);
    hdr->Count = count;
    hdr->Required = required;
    hdr->IdtBase = firstBase;
    hdr->IdtLimit = firstLimit;
    PryLog("IDTLIST all=%u -> st=%x n=%u/%u base=%llx lim=%x",
             in.AllCpus, hdr->Status, count, required, firstBase, firstLimit);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_IDT_LIST_HDR) + (SIZE_T)count * sizeof(PRY_IDT_ENTRY_ROW);
}

SIZE_T PryHandleRemoteCall(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_REMOTE_CALL_IN in;
    PVOID out;
    PRY_REMOTE_CALL_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)PryRemoteCall(in.Pid, in.Tid, in.Target, in.Arg1, in.Arg2, in.Arg3,
                                            in.Flags, &result.Queued, &result.Alerted);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("RCALL pid=%llu tid=%llu target=%llx -> st=%x q=%u a=%u",
             in.Pid, in.Tid, in.Target, result.Status, result.Queued, result.Alerted);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}
