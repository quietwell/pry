#include "PryDriver.h"

// Kernel-side process iteration: one ZwQuerySystemInformation walk over
// SystemProcessInformation, copied out in the shared two-phase list format.

NTSTATUS PryProcessList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                          _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    NTSTATUS st;
    PUCHAR buf = NULL;
    SIZE_T size = 1 << 20;
    UINT32 cap, total = 0, written = 0;
    PPRY_PROC_ENTRY out = (PPRY_PROC_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(PRY_PROC_ENTRY));

    for (;;) {
        PryFree(buf);
        buf = (PUCHAR)PryAlloc(size);
        if (!buf) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        st = ZwQuerySystemInformation(PRY_SYS_PROC_INFO_CLASS, buf, (ULONG)size, NULL);
        if (NT_SUCCESS(st)) {
            break;
        }
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            if (size > (64ull << 20)) {
                PryFree(buf);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            size *= 2;
            continue;
        }
        PryFree(buf);
        return st;
    }

    PUCHAR cur = buf;
    while (cur) {
        PRY_SYS_PROC_INFO* p = (PRY_SYS_PROC_INFO*)cur;
        if (cap && written < cap && out) {
            PPRY_PROC_ENTRY e = &out[written];
            RtlZeroMemory(e, sizeof(*e));
            e->Pid = (UINT32)(ULONG_PTR)p->UniqueProcessId;
            e->ParentPid = (UINT32)(ULONG_PTR)p->InheritedFromProcessId;
            ULONG wch = p->ImageName.Length / sizeof(WCHAR);
            if (wch > PRY_PROC_NAME_CCH - 1) {
                wch = PRY_PROC_NAME_CCH - 1;
            }
            for (ULONG i = 0; i < wch; i++) {
                e->ImageName[i] = p->ImageName.Buffer[i];
            }
            written++;
        }
        total++;
        cur = p->NextEntryOffset ? cur + p->NextEntryOffset : NULL;
    }
    PryFree(buf);
    *Count = written;
    *Required = total;
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}
