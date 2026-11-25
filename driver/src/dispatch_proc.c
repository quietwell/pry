#include "PryDriver.h"
#include "dispatch_internal.h"

SIZE_T PryHandleProcessList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PVOID buf;
    SIZE_T len;
    PPRY_PROC_LIST_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st, walk;

    st = PryOutput(Request, sizeof(PRY_PROC_LIST_HDR), &buf, &len);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PPRY_PROC_LIST_HDR)buf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = (UINT32)((len - sizeof(PRY_PROC_LIST_HDR)) / sizeof(PRY_PROC_ENTRY));

    walk = PryProcessList((PUCHAR)buf + sizeof(PRY_PROC_LIST_HDR),
                            (SIZE_T)capacity * sizeof(PRY_PROC_ENTRY), &count, &required);
    hdr->Status = (UINT32)walk;
    hdr->Count = count;
    hdr->Required = required;
    PryLog("PROCS -> st=%x n=%u/%u", walk, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_PROC_LIST_HDR) + (SIZE_T)count * sizeof(PRY_PROC_ENTRY);
}

SIZE_T PryHandleModules(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _Out_ NTSTATUS* Status)
{
    PRY_MODULES_IN in;
    PVOID out;
    PPRY_MODULES_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st, walk;

    st = PryInOut(Request, sizeof(in), sizeof(PRY_MODULES_HDR), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PPRY_MODULES_HDR)out;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = 0;

    {
        PVOID buf;
        SIZE_T len;
        if (NT_SUCCESS(WdfRequestRetrieveOutputBuffer(Request, sizeof(PRY_MODULES_HDR), &buf, &len))) {
            capacity = (UINT32)((len - sizeof(PRY_MODULES_HDR)) / sizeof(PRY_MODULE_ENTRY));
        }
    }

    walk = Kernel ? PryKernelModules((PUCHAR)out + sizeof(PRY_MODULES_HDR),
                                       (SIZE_T)capacity * sizeof(PRY_MODULE_ENTRY), &count, &required)
                  : PryUserModules(in.Pid, (in.Flags & PRY_MOD_FLAG_WOW64) != 0,
                                     (PUCHAR)out + sizeof(PRY_MODULES_HDR),
                                     (SIZE_T)capacity * sizeof(PRY_MODULE_ENTRY), &count, &required);
    hdr->Status = (UINT32)walk;
    hdr->Count = count;
    hdr->Required = required;
    PryLog("MODS k=%u wow64=%u pid=%llu -> st=%x n=%u/%u", Kernel,
             (in.Flags & PRY_MOD_FLAG_WOW64) != 0, in.Pid, walk, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_MODULES_HDR) + (SIZE_T)count * sizeof(PRY_MODULE_ENTRY);
}

SIZE_T PryHandleVadList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_VAD_IN in;
    PVOID out;
    PPRY_VAD_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st, walk;

    st = PryInOut(Request, sizeof(in), sizeof(PRY_VAD_HDR), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PPRY_VAD_HDR)out;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = 0;
    {
        PVOID buf;
        SIZE_T len;
        if (NT_SUCCESS(WdfRequestRetrieveOutputBuffer(Request, sizeof(PRY_VAD_HDR), &buf, &len))) {
            capacity = (UINT32)((len - sizeof(PRY_VAD_HDR)) / sizeof(PRY_VAD_ENTRY));
        }
    }
    walk = PryVadList(in.Pid, (PUCHAR)out + sizeof(PRY_VAD_HDR),
                        (SIZE_T)capacity * sizeof(PRY_VAD_ENTRY), &count, &required);
    hdr->Status = (UINT32)walk;
    hdr->Count = count;
    hdr->Required = required;
    PryLog("VAD pid=%llu -> st=%x n=%u/%u", in.Pid, walk, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_VAD_HDR) + (SIZE_T)count * sizeof(PRY_VAD_ENTRY);
}

SIZE_T PryHandleHandleList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_HANDLE_IN in;
    PVOID out;
    PPRY_HANDLE_HDR hdr;
    UINT32 count = 0, required = 0, capacity;
    NTSTATUS st, walk;

    st = PryInOut(Request, sizeof(in), sizeof(PRY_HANDLE_HDR), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    hdr = (PPRY_HANDLE_HDR)out;
    RtlZeroMemory(hdr, sizeof(*hdr));
    capacity = 0;
    {
        PVOID buf;
        SIZE_T len;
        if (NT_SUCCESS(WdfRequestRetrieveOutputBuffer(Request, sizeof(PRY_HANDLE_HDR), &buf, &len))) {
            capacity = (UINT32)((len - sizeof(PRY_HANDLE_HDR)) / sizeof(PRY_HANDLE_ENTRY));
        }
    }
    walk = PryHandleList(in.Pid, in.WantNames != 0, (PUCHAR)out + sizeof(PRY_HANDLE_HDR),
                           (SIZE_T)capacity * sizeof(PRY_HANDLE_ENTRY), &count, &required);
    hdr->Status = (UINT32)walk;
    hdr->Count = count;
    hdr->Required = required;
    PryLog("HANDLES pid=%llu names=%u -> st=%x n=%u/%u", in.Pid, in.WantNames, walk, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_HANDLE_HDR) + (SIZE_T)count * sizeof(PRY_HANDLE_ENTRY);
}

SIZE_T PryHandleCtxGet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_CTX_HDR_IN in;
    PVOID out;
    PPRY_CTX_HDR_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(PRY_CTX_HDR_OUT), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result = (PPRY_CTX_HDR_OUT)out;
    RtlZeroMemory(result, sizeof(*result));
    result->Status = (UINT32)PryCtxGet(in.Tid, in.Flags, result->Context);
    result->Flags = in.Flags;
    PryLog("CTXGET tid=%llu flags=%x -> st=%x", in.Tid, in.Flags, result->Status);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_CTX_HDR_OUT);
}

SIZE_T PryHandleCtxSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_CTX_HDR_IN in;
    PVOID inBuf, out;
    SIZE_T inLen;
    PPRY_CTX_HDR_OUT result;
    // v2 combined layout: [PRY_CTX_HDR_IN][CONTEXT] in the input buffer.
    // (v1 read the context from lpOutBuffer, which METHOD_BUFFERED never
    // delivers, and took Flags from the wrong offset â€” a silent no-op.)
    NTSTATUS st = PryInput(Request, sizeof(in) + PRY_CONTEXT_SIZE, &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    st = PryOutput(Request, sizeof(PRY_CTX_HDR_OUT), &out, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));
    result = (PPRY_CTX_HDR_OUT)out;
    {
        __declspec(align(16)) CONTEXT ctx;
        RtlCopyMemory(&ctx, (PUCHAR)inBuf + sizeof(in), sizeof(ctx));
        result->Status = (UINT32)PryCtxSet(in.Tid, in.Flags, &ctx);
        result->Flags = in.Flags;
        PryLog("CTXSET tid=%llu flags=%x -> st=%x", in.Tid, in.Flags, result->Status);
    }
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_CTX_HDR_OUT);
}

// ---- SI #6 handle ops dispatchers -----------------------------------------
// All three are METHOD_BUFFERED one-shots: fetch IN+OUT, delegate to the
// Handles.c helper, forward Status. SelfProtEnterCall in Dispatcher.c
// already brackets us so the ObCallback pre-op never strips our own opens.
SIZE_T PryHandleHandleDup(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_HANDLE_DUP_IN in;
    PVOID out;
    NTSTATUS st = PryInOut(Request, sizeof(in),
                             sizeof(PRY_HANDLE_DUP_OUT),
                             (PVOID*)&in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    (VOID)PryHandleDup(&in, (PPRY_HANDLE_DUP_OUT)out);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_HANDLE_DUP_OUT);
}

SIZE_T PryHandleHandleCloseRemote(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_HANDLE_CLOSE_IN in;
    PVOID out;
    NTSTATUS st = PryInOut(Request, sizeof(in),
                             sizeof(PRY_HANDLE_CLOSE_OUT),
                             (PVOID*)&in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    (VOID)PryHandleCloseRemote(&in, (PPRY_HANDLE_CLOSE_OUT)out);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_HANDLE_CLOSE_OUT);
}

SIZE_T PryHandleHandleCompare(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_HANDLE_CMP_IN in;
    PVOID out;
    NTSTATUS st = PryInOut(Request, sizeof(in),
                             sizeof(PRY_HANDLE_CMP_OUT),
                             (PVOID*)&in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    (VOID)PryHandleCompare(&in, (PPRY_HANDLE_CMP_OUT)out);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_HANDLE_CMP_OUT);
}

// ---- SI #9 stack-walk dispatcher ------------------------------------------
// METHOD_OUT_DIRECT since the frame array is variable-length; the IN block
// still travels in the ordinary system buffer.
SIZE_T PryHandleThreadStackWalk(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_STACKWALK_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    PVOID outBuf = NULL;
    SIZE_T outLen = 0;
    NTSTATUS st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));
    st = PryOutMdl(Request, &outBuf, &outLen);
    if (!NT_SUCCESS(st) || outLen < sizeof(PRY_STACKWALK_HDR)) {
        *Status = NT_SUCCESS(st) ? STATUS_BUFFER_TOO_SMALL : st;
        return 0;
    }
    {
        PPRY_STACKWALK_HDR hdr = (PPRY_STACKWALK_HDR)outBuf;
        PVOID frames = (PUCHAR)outBuf + sizeof(*hdr);
        SIZE_T framesBytes = outLen - sizeof(*hdr);
        (VOID)PryThreadStackWalk(&in, hdr, frames, framesBytes);
        *Status = STATUS_SUCCESS;
        return sizeof(PRY_STACKWALK_HDR)
             + ((SIZE_T)hdr->KernelFrameCount + hdr->UserFrameCount)
               * sizeof(PRY_STACKWALK_FRAME);
    }
}

// ---- SI #3 analyze-wait dispatcher --------------------------------
// METHOD_OUT_DIRECT: callers may ask the driver to copy a few KB of the
// saved arg frame and the user stack into the response trailer. The IN
// block travels in the system buffer; the HDR + trailers live in the
// MDL'd output. PryThreadWaitInfo owns the full fill (header + optional
// trailers) and reports total bytes written so the dispatcher can forward
// the right length to WdfRequestCompleteWithInformation.
SIZE_T PryHandleThreadWaitInfo(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_WAIT_INFO_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    PVOID outBuf = NULL;
    SIZE_T outLen = 0;
    UINT32 bytes = 0;
    NTSTATUS st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));
    st = PryOutMdl(Request, &outBuf, &outLen);
    if (!NT_SUCCESS(st) || outLen < sizeof(PRY_WAIT_INFO_HDR)) {
        *Status = NT_SUCCESS(st) ? STATUS_BUFFER_TOO_SMALL : st;
        return 0;
    }
    (VOID)PryThreadWaitInfo(in.Tid, &in, outBuf, outLen, &bytes);
    PryLog("WAITINFO tid=%llu flags=%x cap=%u/%u -> bytes=%u",
             in.Tid, in.Flags, in.FrameCapture, in.UserStackCapture, bytes);
    *Status = STATUS_SUCCESS;
    return (SIZE_T)bytes;
}

// ---- slice 03 Feature 4 IRP-list dispatcher ----------------------
// METHOD_OUT_DIRECT: rows are variable-length (0..PRY_IRP_LIST_MAX
// entries). IN block carries the TID + MaxEntries cap in the system
// buffer; the HDR + packed row trailer live in the MDL'd output.
SIZE_T PryHandleThreadIrpList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_IRP_LIST_IN in;
    PVOID inBuf;
    SIZE_T inLen;
    PVOID outBuf = NULL;
    SIZE_T outLen = 0;
    UINT32 bytes = 0;
    NTSTATUS st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));
    st = PryOutMdl(Request, &outBuf, &outLen);
    if (!NT_SUCCESS(st) || outLen < sizeof(PRY_IRP_LIST_HDR)) {
        *Status = NT_SUCCESS(st) ? STATUS_BUFFER_TOO_SMALL : st;
        return 0;
    }
    (VOID)PryThreadIrpList(in.Tid, &in, outBuf, outLen, &bytes);
    PryLog("IRP_LIST tid=%llu max=%u -> bytes=%u",
             in.Tid, in.MaxEntries, bytes);
    *Status = STATUS_SUCCESS;
    return (SIZE_T)bytes;
}
