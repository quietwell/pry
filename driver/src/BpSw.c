#include "PryDriver.h"

// Software (int3) breakpoints plus the two table helpers (alloc/free)
// that BpHw.c also needs. Kernel .text int3 is PatchGuard-unsafe:
// lab-only, prefer HW breakpoints for kernel.

// find a free table slot under the lock; returns NULL when the table is full
PPRY_BP_REC PryBpAllocLocked(_Out_ PUINT32 Id)
{
    UINT32 i;
    for (i = 0; i < PRY_MAX_BP; i++) {
        if (!PryBpTable[i].Used) {
            RtlZeroMemory(&PryBpTable[i], sizeof(PryBpTable[i]));
            PryBpTable[i].Used = 1;
            PryBpTable[i].Id = PryBpNextId++;
            *Id = PryBpTable[i].Id;
            return &PryBpTable[i];
        }
    }
    return NULL;
}

VOID PryBpFreeLocked(_In_ PPRY_BP_REC Rec)
{
    Rec->Enabled = 0;
    Rec->Used = 0;
}

static PPRY_BP_REC PryBpFindSwLocked(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT32 Id)
{
    UINT32 i;
    for (i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        if (r->Kind != PRY_BP_KIND_SW || !r->Used || !r->Enabled) {
            continue;
        }
        if (Id && r->Id == Id) {
            return r;
        }
        if (!Id && Pid && r->Pid == (UINT32)Pid && r->Address == Address) {
            return r;
        }
    }
    return NULL;
}

NTSTATUS PryBpSwSet(_In_ UINT64 Pid, _In_ UINT64 Address, _Out_ PUINT32 Id, _Out_ PUCHAR OrigByte)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    UCHAR orig = 0;
    KIRQL irql;
    PPRY_BP_REC rec = NULL;
    UINT32 newId = 0;
    BOOLEAN kernelAddr;

    *Id = 0;
    *OrigByte = 0;
    if (!Pid || !Address) {
        return STATUS_INVALID_PARAMETER;
    }
    // the attach + raw-store __try path below is only
    // safe for a genuine user VA -- PreviousMode stays KernelMode after
    // attach, so a resident READ-ONLY KERNEL page bugchecks on the store
    // (PAGE_FAULT_IN_NONPAGED_AREA) outside any __except. Kernel .text
    // int3 is still a supported, if PatchGuard-risky, lab feature (see
    // this file's header comment), so a kernel address is routed through
    // the existing guarded kernel write path instead of being refused.
    kernelAddr = !PryUserRangeOk(Address, 1);

    KeAcquireSpinLock(&PryBpLock, &irql);
    rec = PryBpAllocLocked(&newId);
    KeReleaseSpinLock(&PryBpLock, irql);
    if (!rec) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    rec->Kind = PRY_BP_KIND_SW;
    rec->Pid = (UINT32)Pid;
    rec->Address = Address;
    rec->Enabled = 1;

    if (kernelAddr) {
        SIZE_T done = 0;
        UINT8 writePath = 0;
        UCHAR patch = 0xCC;
        st = PryKernelMemRead(Address, &orig, sizeof(orig), &done, 0);
        if (NT_SUCCESS(st) && done == sizeof(orig)) {
            st = PryKernelMemWrite(Address, &patch, sizeof(patch), &done, 0, 0, &writePath);
        }
    } else {
        st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
        if (!NT_SUCCESS(st)) {
            KeAcquireSpinLock(&PryBpLock, &irql);
            PryBpFreeLocked(rec);
            KeReleaseSpinLock(&PryBpLock, irql);
            return st;
        }

        KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
        __try {
            // probes are no-ops at PreviousMode==KernelMode; SEH is the guard
            orig = *(volatile UCHAR*)(ULONG_PTR)Address;
            *(volatile UCHAR*)(ULONG_PTR)Address = 0xCC;
            st = STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            st = GetExceptionCode();
        }
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
    }

    if (!NT_SUCCESS(st)) {
        KeAcquireSpinLock(&PryBpLock, &irql);
        PryBpFreeLocked(rec);
        KeReleaseSpinLock(&PryBpLock, irql);
        return st;
    }
    rec->OrigByte = orig;
    *Id = rec->Id;
    *OrigByte = orig;
    return STATUS_SUCCESS;
}

NTSTATUS PryBpSwClear(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT32 Id)
{
    NTSTATUS st;
    PEPROCESS proc;
    KAPC_STATE apc;
    KIRQL irql;
    PPRY_BP_REC rec = NULL;
    UCHAR orig = 0;
    BOOLEAN kernelAddr;

    KeAcquireSpinLock(&PryBpLock, &irql);
    rec = PryBpFindSwLocked(Pid, Address, Id);
    if (!rec) {
        KeReleaseSpinLock(&PryBpLock, irql);
        return STATUS_NOT_FOUND;
    }
    orig = rec->OrigByte;
    Pid = rec->Pid;
    Address = rec->Address;
    KeReleaseSpinLock(&PryBpLock, irql);

    // same kernel-vs-user routing as PryBpSwSet --
    // a raw attach+store under __try can bugcheck on a resident
    // read-only kernel page, outside any __except.
    kernelAddr = !PryUserRangeOk(Address, 1);
    if (kernelAddr) {
        UCHAR cur = 0;
        SIZE_T done = 0;
        UINT8 writePath = 0;
        st = PryKernelMemRead(Address, &cur, sizeof(cur), &done, 0);
        if (NT_SUCCESS(st) && done == sizeof(cur)) {
            if (cur == 0xCC) {
                st = PryKernelMemWrite(Address, &orig, sizeof(orig), &done, 0, 0, &writePath);
            } else {
                PryLog("BPSWCLR mismatch(kernel) addr=%llx cur=%02x", Address, (UINT32)cur);
                st = STATUS_DATA_ERROR;
            }
        }
    } else {
        st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
        if (!NT_SUCCESS(st)) {
            // process is gone: the 0CC went away with its address space — retire
            // the record instead of leaking the table slot forever
            PryLog("BPSWCLR process gone pid=%llu -> retired id", Pid);
            KeAcquireSpinLock(&PryBpLock, &irql);
            PryBpFreeLocked(rec);
            KeReleaseSpinLock(&PryBpLock, irql);
            return STATUS_NOT_FOUND;
        }
        KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
        __try {
            volatile UCHAR* p = (volatile UCHAR*)(ULONG_PTR)Address;
            if (*p == 0xCC) {
                *p = orig;
                st = STATUS_SUCCESS;
            } else {
                // patched by someone else: do not corrupt, surface mismatch
                PryLog("BPSWCLR mismatch addr=%llx cur=%02x", Address, (UINT32)*p);
                st = STATUS_DATA_ERROR;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            st = GetExceptionCode();
        }
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
    }

    KeAcquireSpinLock(&PryBpLock, &irql);
    if (NT_SUCCESS(st)) {
        PryBpFreeLocked(rec);
    }
    KeReleaseSpinLock(&PryBpLock, irql);
    return st;
}
