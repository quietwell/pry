#include "PryDriver.h"

// Handle-table enumeration for one process: SystemExtendedHandleInformation
// (class 0x40) walk filtered by pid, two-phase like the module walks. Optional
// per-entry object names use attach + ObReferenceObjectByHandle +
// ObQueryNameString — best-effort under SEH; File objects are skipped when
// resolving names (documented deadlock risk inside IO completion paths).

#define PRY_SYS_HANDLE_INFO_EX_CLASS 0x40
#define PRY_HANDLE_MAX_TOTAL 4000000

#pragma pack(push, 8)
typedef struct _PRY_HANDLE_ENTRY_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectType;
    ULONG HandleAttributes;
    ULONG Reserved;
} PRY_HANDLE_ENTRY_EX, *PPRY_HANDLE_ENTRY_EX;
C_ASSERT(sizeof(PRY_HANDLE_ENTRY_EX) == 0x28);

typedef struct _PRY_HANDLE_INFO_EX {
    ULONG_PTR Count;
    ULONG_PTR Reserved;
    PRY_HANDLE_ENTRY_EX Handles[1];
} PRY_HANDLE_INFO_EX, *PPRY_HANDLE_INFO_EX;
#pragma pack(pop)

// _OBJECT_TYPE layout on Win10/11 (26200.xxxx inclusive) is
// {LIST_ENTRY TypeList @0x00, UNICODE_STRING Name @0x10, ...}. The old
// "TypeName is the first field" shape was wrong on every modern build
// and silently returned LIST_ENTRY pointer halves masquerading as
// WCHARs — the earlier UTF-8-truncation bug in services_memory
// then produced invalid UTF-8 that killed the HandleList proto on
// serialize. PRY_HANDLES_TYPELIST_OFFSET keeps the offset constant
// explicit so a future kernel-layout change is a one-line nudge.
#define PRY_HANDLES_TYPELIST_OFFSET 0x10
typedef struct _PRY_OBJECT_TYPE_MIN {
    LIST_ENTRY TypeList;     // +0x00 (two pointers)
    UNICODE_STRING TypeName; // +0x10
} PRY_OBJECT_TYPE_MIN, *PPRY_OBJECT_TYPE_MIN;
C_ASSERT(FIELD_OFFSET(PRY_OBJECT_TYPE_MIN, TypeName) == PRY_HANDLES_TYPELIST_OFFSET);

static VOID PryCopyHandleName(_In_ PCUNICODE_STRING Src, _Out_ WCHAR* Dst, _In_ ULONG DstCch)
{
    ULONG i, w;

    RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    if (!Src->Buffer || !Src->Length) {
        return;
    }
    w = Src->Length / sizeof(WCHAR);
    if (w > DstCch - 1) {
        w = DstCch - 1;
    }
    for (i = 0; i < w; i++) {
        Dst[i] = Src->Buffer[i];
    }
}

static VOID PryFillTypeName(_In_ PVOID Object, _Out_ WCHAR* Dst, _In_ ULONG DstCch,
                              _Out_ PBOOLEAN IsFile)
{
    *IsFile = FALSE;
    __try {
        PPRY_OBJECT_TYPE_MIN t = (PPRY_OBJECT_TYPE_MIN)ObGetObjectType(Object);
        if (t) {
            PryCopyHandleName(&t->TypeName, Dst, DstCch);
            if (t->TypeName.Length == sizeof(L"File") - sizeof(WCHAR) &&
                t->TypeName.Buffer && t->TypeName.Buffer[0] == L'F' &&
                t->TypeName.Buffer[1] == L'i' && t->TypeName.Buffer[2] == L'l' &&
                t->TypeName.Buffer[3] == L'e') {
                *IsFile = TRUE;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    }
}

static VOID PryFillObjectName(_In_opt_ PVOID Object, _In_ BOOLEAN IsFile, _Out_ WCHAR* Dst,
                                _In_ ULONG DstCch)
{
    UCHAR buf[512];
    ULONG retLen = 0;
    POBJECT_NAME_INFORMATION name = (POBJECT_NAME_INFORMATION)buf;

    RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    if (!Object || IsFile) {
        return; // File name queries can deadlock — deliberately skipped
    }
    __try {
        if (NT_SUCCESS(ObQueryNameString(Object, name, sizeof(buf), &retLen)) &&
            name->Name.Buffer && name->Name.Length) {
            PryCopyHandleName(&name->Name, Dst, DstCch);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(Dst, DstCch * sizeof(WCHAR));
    }
}

// ---- SI #6 handle ops -----------------------------------------------------
// Documented Ob*/Zw* under KernelMode PreviousMode so SeAccessCheck is
// bypassed (lab-tool contract). KeStackAttachProcess brackets each remote
// operation; nested attaches are illegal, so helpers below never cross.
// See an internal plan Feature 2.

NTKERNELAPI NTSTATUS ObOpenObjectByPointer(_In_ PVOID Object, _In_ ULONG HandleAttributes,
                                           _In_opt_ PACCESS_STATE AccessState,
                                           _In_ ACCESS_MASK DesiredAccess,
                                           _In_opt_ POBJECT_TYPE ObjectType,
                                           _In_ KPROCESSOR_MODE AccessMode,
                                           _Out_ PHANDLE Handle);
NTKERNELAPI NTSTATUS ObReferenceObjectByHandle(_In_ HANDLE Handle, _In_ ACCESS_MASK DesiredAccess,
                                                _In_opt_ POBJECT_TYPE ObjectType,
                                                _In_ KPROCESSOR_MODE AccessMode,
                                                _Out_ PVOID* Object,
                                                _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInfo);
NTKERNELAPI NTSTATUS ObCloseHandle(_In_ HANDLE Handle, _In_ KPROCESSOR_MODE AccessMode);

NTSTATUS PryHandleDup(_In_ const PRY_HANDLE_DUP_IN* In,
                        _Out_ PPRY_HANDLE_DUP_OUT Out)
{
    NTSTATUS st;
    PEPROCESS src = NULL;
    PVOID obj = NULL;
    HANDLE newH = NULL;
    KAPC_STATE apc;

    RtlZeroMemory(Out, sizeof(*Out));
    if (!In->SrcPid || !In->SrcHandle) {
        Out->Status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)In->SrcPid, &src);
    if (!NT_SUCCESS(st)) {
        Out->Status = (UINT32)st;
        return st;
    }
    KeStackAttachProcess((PRKPROCESS)src, &apc);
    __try {
        st = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)In->SrcHandle,
                                       0, NULL, KernelMode, &obj, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
        obj = NULL;
    }
    KeUnstackDetachProcess(&apc);
    if (!NT_SUCCESS(st) || !obj) {
        ObDereferenceObject(src);
        Out->Status = (UINT32)st;
        return st;
    }

    st = ObOpenObjectByPointer(obj,
                               (In->Options & PRY_HANDLE_DUP_FLAG_NO_INHERIT) ? 0 : OBJ_INHERIT,
                               NULL,
                               In->DesiredAccess,
                               NULL,                 // any object type
                               KernelMode,
                               &newH);
    if (NT_SUCCESS(st)) {
        BOOLEAN isFile = FALSE;
        Out->NewHandle = (UINT64)(ULONG_PTR)newH;
        Out->ObjectAddr = (UINT64)(ULONG_PTR)obj;
        Out->GrantedAccess = In->DesiredAccess;
        PryFillTypeName(obj, Out->TypeName, PRY_HANDLE_TYPE_CCH, &isFile);
    }
    ObDereferenceObject(obj);
    ObDereferenceObject(src);
    Out->Status = (UINT32)st;
    PryLog("HANDLE_DUP src_pid=%llu src_h=%llx -> st=%x new=%llx obj=%llx",
             In->SrcPid, In->SrcHandle, st, Out->NewHandle, Out->ObjectAddr);
    return st;
}

NTSTATUS PryHandleCloseRemote(_In_ const PRY_HANDLE_CLOSE_IN* In,
                                _Out_ PPRY_HANDLE_CLOSE_OUT Out)
{
    NTSTATUS st;
    PEPROCESS target = NULL;
    KAPC_STATE apc;

    RtlZeroMemory(Out, sizeof(*Out));
    if (!In->TargetPid || !In->TargetHandle) {
        Out->Status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }
    // a kernel handle (OBJ_KERNEL_HANDLE) sign-extends
    // to a negative 64-bit value and resolves against the system-wide
    // kernel handle table regardless of which process we attach to --
    // naming any TargetPid would still let a caller close a handle it
    // does not actually own (ours, or another component's). Reject it.
    if ((INT64)In->TargetHandle < 0) {
        PryLog("HANDLE_CLOSE_REMOTE refused: kernel handle value h=%llx", In->TargetHandle);
        Out->Status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)In->TargetPid, &target);
    if (!NT_SUCCESS(st)) {
        Out->Status = (UINT32)st;
        return st;
    }
    KeStackAttachProcess((PRKPROCESS)target, &apc);
    __try {
        st = ObCloseHandle((HANDLE)(ULONG_PTR)In->TargetHandle, KernelMode);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(target);
    Out->Status = (UINT32)st;
    PryLog("HANDLE_CLOSE_REMOTE pid=%llu h=%llx -> st=%x",
             In->TargetPid, In->TargetHandle, st);
    return st;
}

static NTSTATUS PryResolveHandleObj(_In_ UINT64 Pid, _In_ UINT64 HandleValue,
                                      _Out_ PVOID* Obj, _Out_opt_ PUINT32 TypeIdx)
{
    NTSTATUS st;
    PEPROCESS proc = NULL;
    KAPC_STATE apc;
    PVOID obj = NULL;

    *Obj = NULL;
    if (TypeIdx) *TypeIdx = 0;
    if (!Pid || !HandleValue) {
        return STATUS_INVALID_PARAMETER;
    }
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    KeStackAttachProcess((PRKPROCESS)proc, &apc);
    __try {
        st = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)HandleValue,
                                       0, NULL, KernelMode, &obj, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
        obj = NULL;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    if (NT_SUCCESS(st) && obj) {
        *Obj = obj;
        if (TypeIdx) {
            __try {
                PPRY_OBJECT_TYPE_MIN t =
                    (PPRY_OBJECT_TYPE_MIN)ObGetObjectType(obj);
                UNREFERENCED_PARAMETER(t);
                // Public ObGetObjectTypeIndex is unavailable from this WDK;
                // leave as 0 and let the orchestrator correlate type names.
                *TypeIdx = 0;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                *TypeIdx = 0;
            }
        }
    }
    return st;
}

NTSTATUS PryHandleCompare(_In_ const PRY_HANDLE_CMP_IN* In,
                            _Out_ PPRY_HANDLE_CMP_OUT Out)
{
    NTSTATUS stA, stB;
    PVOID objA = NULL;
    PVOID objB = NULL;

    RtlZeroMemory(Out, sizeof(*Out));
    stA = PryResolveHandleObj(In->PidA, In->HandleA, &objA, &Out->TypeIndexA);
    stB = PryResolveHandleObj(In->PidB, In->HandleB, &objB, &Out->TypeIndexB);
    if (NT_SUCCESS(stA) && NT_SUCCESS(stB)) {
        Out->Same = (objA == objB) ? 1u : 0u;
        Out->ObjectA = (UINT64)(ULONG_PTR)objA;
        Out->ObjectB = (UINT64)(ULONG_PTR)objB;
    }
    if (NT_SUCCESS(stA) && objA) ObDereferenceObject(objA);
    if (NT_SUCCESS(stB) && objB) ObDereferenceObject(objB);
    {
        NTSTATUS st = NT_SUCCESS(stA) ? stB : stA;
        Out->Status = (UINT32)st;
        PryLog("HANDLE_COMPARE (%llu,%llx) vs (%llu,%llx) -> st=%x same=%u",
                 In->PidA, In->HandleA, In->PidB, In->HandleB, st, Out->Same);
        return st;
    }
}

NTSTATUS PryHandleList(_In_ UINT64 Pid, _In_ BOOLEAN WantNames,
                         _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required)
{
    NTSTATUS st;
    PUCHAR buf = NULL;
    SIZE_T size = 1 << 20;
    UINT32 cap, total = 0, written = 0;
    PPRY_HANDLE_ENTRY out = (PPRY_HANDLE_ENTRY)Buffer;
    PPRY_HANDLE_INFO_EX info;
    PEPROCESS targetProc = NULL;
    KAPC_STATE apc;
    BOOLEAN attached = FALSE;

    *Count = 0;
    *Required = 0;
    cap = (UINT32)(CapacityBytes / sizeof(PRY_HANDLE_ENTRY));
    if (!Pid) {
        return STATUS_INVALID_PARAMETER;
    }

    for (;;) {
        PryFree(buf);
        buf = (PUCHAR)PryAlloc(size);
        if (!buf) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        st = ZwQuerySystemInformation(PRY_SYS_HANDLE_INFO_EX_CLASS, buf, (ULONG)size, NULL);
        if (NT_SUCCESS(st)) {
            break;
        }
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            if (size > (SIZE_T)PRY_HANDLE_MAX_TOTAL * sizeof(PRY_HANDLE_ENTRY_EX) + (1 << 20)) {
                PryFree(buf);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            size *= 2;
            continue;
        }
        PryFree(buf);
        return st;
    }

    info = (PPRY_HANDLE_INFO_EX)buf;
    if (info->Count > PRY_HANDLE_MAX_TOTAL) {
        PryFree(buf);
        return STATUS_INFO_LENGTH_MISMATCH; // absurd count: refuse
    }

    // the snapshot's Object pointer is a point-in-time
    // value we hold no reference to -- the handle can close and the
    // object can be freed (and its memory reused) between the snapshot
    // above and PryFillTypeName/PryFillObjectName below, which is a
    // use-after-free. Attach to the target once and re-resolve each
    // handle BY VALUE via ObReferenceObjectByHandle (the same pattern
    // PryResolveHandleObj already uses for HANDLE_COMPARE), so those
    // helpers only ever touch a live, referenced object.
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &targetProc);
    if (NT_SUCCESS(st)) {
        KeStackAttachProcess((PRKPROCESS)targetProc, &apc); // EPROCESS begins with KPROCESS Pcb
        attached = TRUE;
    }

    for (ULONG i = 0; i < info->Count && total < PRY_HANDLE_MAX_TOTAL; i++) {
        PPRY_HANDLE_ENTRY_EX e = &info->Handles[i];
        if ((UINT64)e->UniqueProcessId != Pid) {
            continue;
        }
        if (cap && written < cap && out) {
            PPRY_HANDLE_ENTRY o = &out[written];

            RtlZeroMemory(o, sizeof(*o));
            o->HandleValue = (UINT64)e->HandleValue;
            o->GrantedAccess = e->GrantedAccess;
            o->ObjectTypeIndex = e->ObjectType;

            if (attached && e->HandleValue) {
                PVOID obj = NULL;
                NTSTATUS rst;
                __try {
                    rst = ObReferenceObjectByHandle((HANDLE)e->HandleValue, 0, NULL,
                                                     KernelMode, &obj, NULL);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    rst = GetExceptionCode();
                    obj = NULL;
                }
                if (NT_SUCCESS(rst) && obj) {
                    BOOLEAN isFile = FALSE;
                    o->Object = (UINT64)(ULONG_PTR)obj;
                    PryFillTypeName(obj, o->TypeName, PRY_HANDLE_TYPE_CCH, &isFile);
                    if (WantNames) {
                        PryFillObjectName(obj, isFile, o->Name, PRY_HANDLE_NAME_CCH);
                    }
                    ObDereferenceObject(obj);
                }
            }
            written++;
        }
        total++;
    }

    if (attached) {
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(targetProc);
    }
    PryFree(buf);

    *Count = written;
    *Required = total;
    PryLog("HANDLES pid=%llu want_names=%u -> n=%u/%u", Pid, WantNames, written, total);
    return total > written ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}
