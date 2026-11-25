#include "PryDriver.h"
#include "dispatch_internal.h"

#define PRY_MAX_TRANSFER_BYTES (64ull * 1024 * 1024)

NTSTATUS PryHandleMemRead(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _In_ BOOLEAN Physical, _Out_ SIZE_T* Info)
{
    NTSTATUS st;
    PRY_MEM_REQ req;
    PVOID in;
    SIZE_T inLen = 0, outLen = 0, size, done = 0;
    PVOID out;

    st = PryInput(Request, sizeof(req), &in, &inLen);
    if (!NT_SUCCESS(st)) {
        // Regression triage (v6): field report showed every MEM_READ
        // returning gle=87 while other IOCTLs worked. Log the failing
        // step + observed input length so the culprit is obvious in
        // the driver's own log.
        PryLog("MEMRD REJ k=%u p=%u PryInput st=%x inLen=%llx (want>=%llx)",
                 Kernel, Physical, st, (UINT64)inLen, (UINT64)sizeof(req));
        return st;
    }
    RtlCopyMemory(&req, in, sizeof(req));

    st = PryOutMdl(Request, &out, &outLen);
    if (!NT_SUCCESS(st)) {
        PryLog("MEMRD REJ k=%u p=%u PryOutMdl st=%x", Kernel, Physical, st);
        return st;
    }
    if (req.Size == 0 || req.Size > PRY_MAX_TRANSFER_BYTES) {
        PryLog("MEMRD REJ k=%u p=%u req.Size=%llx (outLen=%llx flags=%x addr=%llx)",
                 Kernel, Physical, req.Size, (UINT64)outLen, req.Flags, req.Address);
        return STATUS_INVALID_PARAMETER;
    }
    size = (SIZE_T)req.Size < outLen ? (SIZE_T)req.Size : outLen;

    if (Physical) {
        // vNEXT (T3.1 PR#5): forward the PRY_MEM_FLAG_ALLOW_OUT_OF_RAM
        // bit as a BOOLEAN into the physical read. Older callers that
        // don't carry the flag naturally get FALSE (default-deny), so one
        // mis-aimed MMIO BAR read can no longer wedge the box. The write
        // side keeps using req.Flags & PRY_MEM_FLAG_ALLOW_MAP_WRITE in
        // the write handler below — the guard is read-side only.
        BOOLEAN allowOutOfRam = (req.Flags & PRY_MEM_FLAG_ALLOW_OUT_OF_RAM) ? TRUE : FALSE;
        st = PryPhysMemRead(req.Address, out, size, allowOutOfRam, &done);
    } else if (Kernel) {
        // v6: pass Flags through raw — PryKernelMemRead now understands
        // both ALLOW_SOFTFAULT (v2) and PARTIAL (v6). Old-shape requests
        // (inLen < sizeof) get Flags=0, i.e. legacy strict semantics.
        UINT32 flags = 0;
        if (inLen >= sizeof(PRY_MEM_REQ)) {
            flags = req.Flags;
        }
        st = PryKernelMemRead(req.Address, out, size, &done, flags);
    } else {
        st = PryUserMemRead(req.Pid, req.Address, out, size, &done);
    }
    PryLog("MEMRD k=%u p=%u pid=%llu addr=%llx size=%llx flags=%x inLen=%llx outLen=%llx -> st=%x n=%llx",
             Kernel, Physical, req.Pid, req.Address, req.Size,
             req.Flags, (UINT64)inLen, (UINT64)outLen, st, (UINT64)done);
    // a partial read must complete STATUS_SUCCESS. Returning the
    // warning NTSTATUS STATUS_PARTIAL_COPY (0x8000000D) makes the I/O
    // manager fail the usermode DeviceIoControl (gle=299) and drop the
    // prefix entirely — callers saw a hard error instead of short data.
    // The valid-prefix signal survives in *Info (DeviceIoControl's
    // bytesReturned -> comm MemRead's got < len). Zero-byte results keep
    // propagating the real error (a SUCCESS with Info=0 would report a
    // bogus full read through comm's "ret ? ret : len").
    if (!NT_SUCCESS(st) && done > 0) {
        st = STATUS_SUCCESS;
    }
    *Info = done;
    return st;
}

NTSTATUS PryHandleMemWrite(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _In_ BOOLEAN Physical, _Out_ SIZE_T* Info)
{
    NTSTATUS st;
    PRY_MEM_REQ req;
    PRY_MEM_WRITE_IN ext;
    PVOID in, data, out = NULL;
    SIZE_T inLen, dataLen, size, done = 0, hdrLen, outLen = 0;
    UINT64 cr3 = 0;
    UINT32 flags2 = 0;
    UINT8 writePath = PRY_MEM_WRITE_PATH_UNKNOWN;

    // METHOD_BUFFERED combined layout: [PRY_MEM_REQ header][payload...]
    // v12: when the old Reserved slot carries PRY_MEM_WRITE_EXT_MAGIC and
    // the input is >= sizeof(PRY_MEM_WRITE_IN), the header is the 48-byte
    // ext form carrying Cr3+Flags2 and the payload sits at offset 48.
    st = PryInput(Request, sizeof(req), &in, &inLen);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    RtlCopyMemory(&req, in, sizeof(req));
    hdrLen = sizeof(req);
    if (inLen >= sizeof(ext)) {
        RtlCopyMemory(&ext, in, sizeof(ext));
        if (ext.ExtLayout == PRY_MEM_WRITE_EXT_MAGIC) {
            hdrLen = sizeof(ext);
            cr3 = ext.Cr3;
            flags2 = ext.Flags2;
        }
    }
    data = (PUCHAR)in + hdrLen;
    dataLen = inLen - hdrLen;
    if (req.Size == 0 || req.Size > PRY_MAX_TRANSFER_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    size = (SIZE_T)req.Size < dataLen ? (SIZE_T)req.Size : dataLen;

    // v12 reply channel: when the caller attached an output buffer the op
    // result goes out through PRY_MEM_WRITE_OUT and the request itself
    // completes STATUS_SUCCESS — Done/WritePath then survive even a failed
    // write (a warning NTSTATUS breaks DeviceIoControl).
    //
    // probe the TRUE output length first (Min=0 always
    // succeeds) instead of only trying the sizeof(PRY_MEM_WRITE_OUT)
    // retrieve — a caller that attached a small-but-nonzero buffer (1-15
    // bytes, short of the 16-byte reply struct) used to be silently
    // downgraded to the legacy (no-reply) path below instead of being told
    // its buffer doesn't fit.
    {
        SIZE_T rawOutLen = 0;
        PVOID rawOutBuf = NULL;
        NTSTATUS probeSt = PryOutput(Request, 0, &rawOutBuf, &rawOutLen);
        if (NT_SUCCESS(probeSt) && rawOutLen >= sizeof(PRY_MEM_WRITE_OUT)) {
            out = rawOutBuf;
            outLen = rawOutLen;
        } else if (NT_SUCCESS(probeSt) && rawOutLen > 0) {
            return STATUS_BUFFER_TOO_SMALL;
        } else {
            out = NULL;
        }
    }

    if (cr3 && (Physical || !Kernel)) {
        // foreign-CR3 write only makes sense through the kernel-write
        // IOCTL — the cr3 defines the address space; a user/phys request
        // with cr3 set is a caller bug, not a degraded op.
        st = STATUS_INVALID_PARAMETER;
    } else if (Physical) {
        // v5: map-based physical write is opt-in (ALLOW_MAP_WRITE); refused
        // cleanly when the flag is missing.
        st = PryPhysMemWrite(req.Address, data, size, &done,
                               (req.Flags & PRY_MEM_FLAG_ALLOW_MAP_WRITE) ? TRUE : FALSE);
        if (NT_SUCCESS(st)) {
            writePath = PRY_MEM_WRITE_PATH_PHYS_REMAP;
        }
    } else if (Kernel) {
        st = PryKernelMemWrite(req.Address, data, size, &done, flags2, cr3, &writePath);
    } else {
        // user write goes through the target process — inherently a
        // linear-VA store; STRICT_VA/CR3 have no meaning here and are
        // ignored (user writes never had a remap fallback to refuse).
        st = PryUserMemWrite(req.Pid, req.Address, data, size, &done);
        if (NT_SUCCESS(st)) {
            writePath = PRY_MEM_WRITE_PATH_DIRECT_VA;
        }
    }
    PryLog("MEMWR k=%u p=%u pid=%llu addr=%llx size=%llx cr3=%llx fl2=%x -> st=%x n=%llx path=%u",
             Kernel, Physical, req.Pid, req.Address, req.Size, cr3, flags2,
             st, (UINT64)done, writePath);

    if (out) {
        PPRY_MEM_WRITE_OUT rep = (PPRY_MEM_WRITE_OUT)out;
        rep->Status = (UINT32)st;
        rep->WritePath = writePath;
        rep->Reserved[0] = rep->Reserved[1] = rep->Reserved[2] = 0;
        rep->Done = (UINT64)done;
        *Info = sizeof(*rep);
        return STATUS_SUCCESS;
    }
    *Info = done;
    return st;
}

NTSTATUS PryInOut(_In_ WDFREQUEST Request, _In_ SIZE_T InSize, _In_ SIZE_T OutSize,
                    _Out_ PVOID* In, _Out_ PVOID* Out)
{
    NTSTATUS st;
    PVOID in, out;
    SIZE_T len;

    st = PryInput(Request, InSize, &in, &len);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = PryOutput(Request, OutSize, &out, &len);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    RtlCopyMemory(In, in, InSize);
    *Out = out;
    return STATUS_SUCCESS;
}

SIZE_T PryHandleAlloc(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_USER_ALLOC_IN in;
    PVOID out;
    PRY_USER_ALLOC_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)PryUserAlloc(in.Pid, in.Size, in.Protect, &result.Address);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("ALLOC pid=%llu size=%llx prot=%x -> st=%x addr=%llx",
             in.Pid, in.Size, in.Protect, result.Status, result.Address);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleFree(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_USER_FREE_IN in;
    PVOID out;
    PRY_USER_FREE_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)PryUserFree(in.Pid, in.Address);
    result.Reserved = 0;
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("FREE pid=%llu addr=%llx -> st=%x", in.Pid, in.Address, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleProtect(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_USER_PROTECT_IN in;
    PVOID out;
    PRY_USER_PROTECT_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)PryUserProtect(in.Pid, in.Address, in.Size, in.Protect, &result.OldProtect);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("PROT pid=%llu addr=%llx size=%llx -> st=%x old=%x",
             in.Pid, in.Address, in.Size, result.Status, result.OldProtect);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleKmemAlloc(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_KMEM_ALLOC_IN in;
    PVOID out;
    PRY_KMEM_ALLOC_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlZeroMemory(&result, sizeof(result));
    result.Status = (UINT32)PryKmemAlloc(in.Size, &result.Address);
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("KALLOC size=%llx -> st=%x addr=%llx", in.Size, result.Status, result.Address);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}

SIZE_T PryHandleKmemFree(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_KMEM_FREE_IN in;
    PVOID out;
    PRY_KMEM_FREE_OUT result;
    NTSTATUS st = PryInOut(Request, sizeof(in), sizeof(result), &in, &out);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    result.Status = (UINT32)PryKmemFree(in.Address);
    result.Reserved = 0;
    RtlCopyMemory(out, &result, sizeof(result));
    PryLog("KFREE addr=%llx -> st=%x", in.Address, result.Status);
    *Status = STATUS_SUCCESS;
    return sizeof(result);
}
