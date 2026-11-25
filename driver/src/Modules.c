#include "PryDriver.h"

// Kernel modules: walk PsLoadedModuleList from our own DriverSection
// (KLDR_DATA_TABLE_ENTRY — same layout as the user-mode LDR entry).
// ZwQuerySystemInformation(SystemModuleInformation) is NOT used: recent
// builds zero ImageBase there and the entry layout drifted (path moved to
// +0x28), which yielded garbage names and useless bases.
// User modules: attached PEB->Ldr InLoadOrderModuleList walk under SEH
// (64-bit list, or the 32-bit PEB32 list for WoW64 targets when
// PRY_MOD_FLAG_WOW64 is set).

#pragma pack(push, 8)
typedef struct _PRY_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;           // 0x00
    LIST_ENTRY InMemoryOrderLinks;         // 0x10
    LIST_ENTRY InInitializationOrderLinks; // 0x20
    PVOID DllBase;                         // 0x30
    PVOID EntryPoint;                      // 0x38
    ULONG SizeOfImage;                     // 0x40
    UNICODE_STRING FullDllName;            // 0x48
    UNICODE_STRING BaseDllName;            // 0x58
} PRY_LDR_ENTRY, *PPRY_LDR_ENTRY;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(PRY_LDR_ENTRY, DllBase) == 0x30);
C_ASSERT(FIELD_OFFSET(PRY_LDR_ENTRY, SizeOfImage) == 0x40);
C_ASSERT(FIELD_OFFSET(PRY_LDR_ENTRY, FullDllName) == 0x48);
C_ASSERT(FIELD_OFFSET(PRY_LDR_ENTRY, BaseDllName) == 0x58);

// ---- x86 (32-bit) layouts for the WoW64 walk (offsets are target-side) ----
#define PRY_PEB32_LDR_OFF        0x0C
#define PRY_LDR32_LIST_HEAD_OFF  0x0C // PEB_LDR_DATA32.InLoadOrderModuleList
#define PRY_LDR32_DLLBASE_OFF    0x18
#define PRY_LDR32_SIZEIMAGE_OFF  0x20
#define PRY_LDR32_FULLNAME_OFF   0x24 // UNICODE_STRING32 {len,max,buf}
#define PRY_LDR32_BASENAME_OFF   0x2C

typedef struct _PRY_UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer; // 32-bit VA inside the WoW64 process
} PRY_UNICODE_STRING32;
C_ASSERT(sizeof(PRY_UNICODE_STRING32) == 8);

static VOID PryReadUserString(_In_ PCUNICODE_STRING Str, _Out_ WCHAR* Dst, _In_ ULONG DstCch)
{
    ULONG i, w;

    RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    if (!Str->Buffer || !Str->Length) {
        return;
    }
    w = Str->Length / sizeof(WCHAR);
    if (w > DstCch - 1) {
        w = DstCch - 1;
    }
    for (i = 0; i < w; i++) {
        Dst[i] = Str->Buffer[i]; // guarded by the caller's __try
    }
}

static VOID PryCopyKernelString(_In_ PCUNICODE_STRING Str, _Out_ WCHAR* Dst, _In_ ULONG DstCch)
{
    ULONG w;

    RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    if (!Str->Buffer || !Str->Length) {
        return;
    }
    w = Str->Length / sizeof(WCHAR);
    if (w > DstCch - 1) {
        w = DstCch - 1;
    }
    RtlCopyMemory(Dst, Str->Buffer, (SIZE_T)w * sizeof(WCHAR));
}

NTSTATUS PryKernelModules(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                            _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    PDRIVER_OBJECT drv = WdfDriverWdmGetDriverObject(WdfGetDriver());
    PPRY_LDR_ENTRY self;
    PLIST_ENTRY head;
    NTSTATUS st;
    UINT32 cap, total = 0, written = 0;
    PPRY_MODULE_ENTRY out = (PPRY_MODULE_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(PRY_MODULE_ENTRY));
    if (!drv || !drv->DriverSection) {
        return STATUS_INVALID_PARAMETER;
    }
    self = (PPRY_LDR_ENTRY)drv->DriverSection;
    head = &self->InLoadOrderLinks;

    // the loader mutates this list under its lock; walking unlocked can tear,
    // so every dereference is guarded and a fault yields partial data
    st = STATUS_SUCCESS;
    __try {
        for (PLIST_ENTRY cur = head->Flink; cur && cur != head && total < PRY_MAX_MODULES;
             cur = cur->Flink) {
            PPRY_LDR_ENTRY e = CONTAINING_RECORD(cur, PRY_LDR_ENTRY, InLoadOrderLinks);
            if (e->DllBase && e->BaseDllName.Buffer) {
                if (cap && written < cap && out) {
                    PPRY_MODULE_ENTRY o = &out[written];
                    o->Base = (UINT64)(ULONG_PTR)e->DllBase;
                    o->Size = e->SizeOfImage;
                    PryCopyKernelString(&e->BaseDllName, o->Name, PRY_MOD_NAME_CCH);
                    PryCopyKernelString(&e->FullDllName, o->Path, PRY_MOD_PATH_CCH);
                    written++;
                }
                total++;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_PARTIAL_COPY;
        PryLog("KERNMODS partial after n=%u st=%x", total, GetExceptionCode());
    }
    *Count = written;
    *Required = total;
    if (NT_SUCCESS(st) && total > written) {
        st = STATUS_BUFFER_OVERFLOW;
    }
    return st;
}

static NTSTATUS PryUserModulesNative(_In_ UINT64 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                                       _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                                       _Out_ PUINT32 Required, _In_ PEPROCESS proc)
{
    KAPC_STATE apc;
    PPEB peb;
    PVOID ldr;
    PLIST_ENTRY head;
    NTSTATUS st = STATUS_INVALID_PARAMETER;
    UINT32 cap, total = 0, written = 0;
    PPRY_MODULE_ENTRY out = (PPRY_MODULE_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(PRY_MODULE_ENTRY));

    peb = PsGetProcessPeb(proc);
    if (!peb) {
        return STATUS_INVALID_PARAMETER;
    }
    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        ldr = *(PVOID*)((PUCHAR)peb + 0x18); // PEB->Ldr
        if (!ldr) {
            st = STATUS_INVALID_PARAMETER;
            __leave;
        }
        head = (PLIST_ENTRY)((PUCHAR)ldr + 0x10); // Ldr->InLoadOrderModuleList
        for (PLIST_ENTRY cur = head->Flink; cur && cur != head && total < PRY_MAX_MODULES;
             cur = cur->Flink) {
            PPRY_LDR_ENTRY e = CONTAINING_RECORD(cur, PRY_LDR_ENTRY, InLoadOrderLinks);
            if (cap && written < cap && out) {
                PPRY_MODULE_ENTRY o = &out[written];
                o->Base = (UINT64)(ULONG_PTR)e->DllBase;
                o->Size = e->SizeOfImage;
                PryReadUserString(&e->FullDllName, o->Path, PRY_MOD_PATH_CCH);
                PryReadUserString(&e->BaseDllName, o->Name, PRY_MOD_NAME_CCH);
                written++;
            }
            total++;
            st = STATUS_SUCCESS;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_PARTIAL_COPY;
        PryLog("USERMODS partial pid=%llu after n=%u", Pid, total);
    }
    KeUnstackDetachProcess(&apc);

    *Count = written;
    *Required = total;
    if (st == STATUS_PARTIAL_COPY) {
        return st;
    }
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

static NTSTATUS PryUserModulesWow64(_In_ UINT64 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                                      _Out_ PUINT32 Required, _In_ PEPROCESS proc)
{
    KAPC_STATE apc;
    PVOID peb32;
    ULONG ldr32, flink;
    NTSTATUS st = STATUS_INVALID_PARAMETER;
    UINT32 cap, total = 0, written = 0;
    PPRY_MODULE_ENTRY out = (PPRY_MODULE_ENTRY)Buffer;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(PRY_MODULE_ENTRY));

    peb32 = PsGetProcessWow64Process(proc);
    if (!peb32) {
        return STATUS_NOT_SUPPORTED; // not a WoW64 process
    }

    KeStackAttachProcess((PRKPROCESS)proc, &apc); // EPROCESS begins with KPROCESS Pcb
    __try {
        ldr32 = *(ULONG*)((PUCHAR)peb32 + PRY_PEB32_LDR_OFF);
        if (!ldr32) {
            st = STATUS_INVALID_PARAMETER;
            __leave;
        }
        flink = *(ULONG*)((PUCHAR)(ULONG_PTR)ldr32 + PRY_LDR32_LIST_HEAD_OFF);
        while (flink && flink != ldr32 + PRY_LDR32_LIST_HEAD_OFF &&
               total < PRY_MAX_MODULES) {
            UCHAR* entry = (UCHAR*)(ULONG_PTR)flink;
            ULONG dllBase = *(ULONG*)(entry + PRY_LDR32_DLLBASE_OFF);
            if (dllBase && cap && written < cap && out) {
                PPRY_MODULE_ENTRY o = &out[written];
                PRY_UNICODE_STRING32 full, base;
                o->Base = (UINT64)dllBase;
                o->Size = *(ULONG*)(entry + PRY_LDR32_SIZEIMAGE_OFF);
                full = *(PRY_UNICODE_STRING32*)(entry + PRY_LDR32_FULLNAME_OFF);
                base = *(PRY_UNICODE_STRING32*)(entry + PRY_LDR32_BASENAME_OFF);
                if (base.Buffer && base.Length) {
                    ULONG w = base.Length / sizeof(WCHAR);
                    WCHAR* src = (WCHAR*)(ULONG_PTR)base.Buffer;
                    ULONG i, n = w > PRY_MOD_NAME_CCH - 1 ? PRY_MOD_NAME_CCH - 1 : w;
                    for (i = 0; i < n; i++) {
                        o->Name[i] = src[i];
                    }
                }
                if (full.Buffer && full.Length) {
                    ULONG w = full.Length / sizeof(WCHAR);
                    WCHAR* src = (WCHAR*)(ULONG_PTR)full.Buffer;
                    ULONG i, n = w > PRY_MOD_PATH_CCH - 1 ? PRY_MOD_PATH_CCH - 1 : w;
                    for (i = 0; i < n; i++) {
                        o->Path[i] = src[i];
                    }
                }
                written++;
            }
            total++;
            flink = *(ULONG*)entry; // InLoadOrderLinks.Flink
            st = STATUS_SUCCESS;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_PARTIAL_COPY;
        PryLog("USERMODS(wow64) partial pid=%llu after n=%u", Pid, total);
    }
    KeUnstackDetachProcess(&apc);

    *Count = written;
    *Required = total;
    if (st == STATUS_PARTIAL_COPY) {
        return st;
    }
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

NTSTATUS PryUserModules(_In_ UINT64 Pid, _In_ BOOLEAN Wow64,
                          _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                          _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    NTSTATUS st;
    PEPROCESS proc;

    if (!Pid) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = Wow64 ? PryUserModulesWow64(Pid, Buffer, CapacityBytes, Count, Required, proc)
               : PryUserModulesNative(Pid, Buffer, CapacityBytes, Count, Required, proc);
    ObDereferenceObject(proc);
    return st;
}
