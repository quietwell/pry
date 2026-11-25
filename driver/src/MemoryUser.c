#include "PryDriver.h"

NTSTATUS PryUserMemRead(_In_ UINT64 Pid, _In_ UINT64 Address, _Out_ PVOID Dst,
                          _In_ SIZE_T Size, _Out_ PSIZE_T Done)
{
    NTSTATUS st;
    PEPROCESS proc;
    SIZE_T got = 0;

    *Done = 0;
    if (!Pid || !Dst || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    // MmCopyVirtualMemory with PreviousMode=KernelMode
    // skips the usual user/kernel boundary check on the SOURCE side, so a
    // "user memory read" request naming a kernel Address would silently
    // promote to an arbitrary kernel-memory read through what is supposed
    // to be the user-scoped path. Reject before ever calling it.
    if (!PryUserRangeOk(Address, Size)) {
        PryLog("UMRD refused: addr=%llx size=%llx is not user-mode (or wraps)", Address, (UINT64)Size);
        return STATUS_ACCESS_VIOLATION;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)Address, PsGetCurrentProcess(), Dst,
                             Size, KernelMode, &got);
    ObDereferenceObject(proc);
    *Done = got;
    return st;
}

NTSTATUS PryUserMemWrite(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ PVOID Src,
                           _In_ SIZE_T Size, _Out_ PSIZE_T Done)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;

    *Done = 0;
    if (!Pid || !Src || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    // PreviousMode stays KernelMode after attach, so
    // the __try guard below is the ONLY protection against a bad address
    // -- and it is not enough against a KERNEL one. A valid, resident
    // kernel page writes successfully with no exception at all (silent
    // corruption), and a resident READ-ONLY kernel page bugchecks
    // (PAGE_FAULT_IN_NONPAGED_AREA) OUTSIDE any __except. Reject before
    // ever attaching.
    if (!PryUserRangeOk(Address, Size)) {
        PryLog("UMWR refused: addr=%llx size=%llx is not user-mode (or wraps)", Address, (UINT64)Size);
        return STATUS_ACCESS_VIOLATION;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        // PreviousMode stays KernelMode after attach, so ProbeForWrite would be
        // a no-op here; the __try guard plus the user-range check above are
        // the actual protection.
        RtlCopyMemory((PVOID)(ULONG_PTR)Address, Src, Size);
        *Done = Size;
        st = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
        PryLog("UMWR except pid=%llu addr=%llx st=%x", Pid, Address, st);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return st;
}

NTSTATUS PryUserAlloc(_In_ UINT64 Pid, _In_ UINT64 Size, _In_ ULONG Protect, _Out_ UINT64* Address)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    PVOID base = NULL;
    SIZE_T sz;

    *Address = 0;
    if (!Pid || !Size || Size > (1ull << 32)) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    sz = (SIZE_T)Size;
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        st = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &sz,
                                     MEM_COMMIT | MEM_RESERVE, Protect);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    if (NT_SUCCESS(st)) {
        *Address = (UINT64)(ULONG_PTR)base;
    }
    return st;
}

NTSTATUS PryUserFree(_In_ UINT64 Pid, _In_ UINT64 Address)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    PVOID base;
    SIZE_T sz = 0;

    if (!Pid || !Address) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    base = (PVOID)(ULONG_PTR)Address;
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        st = ZwFreeVirtualMemory(NtCurrentProcess(), &base, &sz, MEM_RELEASE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return st;
}

NTSTATUS PryUserProtect(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT64 Size,
                          _In_ ULONG Protect, _Out_ ULONG* OldProtect)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    PVOID base;
    SIZE_T sz;

    *OldProtect = 0;
    if (!Pid || !Address || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    base = (PVOID)(ULONG_PTR)Address;
    sz = (SIZE_T)Size;
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        st = ZwProtectVirtualMemory(NtCurrentProcess(), &base, &sz, Protect, OldProtect);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return st;
}
