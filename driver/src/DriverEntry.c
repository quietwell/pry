#include "PryDriver.h"

// Kernel op log: append-only text file at PRY_KERNEL_LOG_PATH. All call
// sites run at PASSIVE_LEVEL (KMDF sequential queue), so direct ZwWriteFile is
// safe. Records raised above APC_LEVEL (defensive) go to a small pending ring
// flushed by the next passive call.

#define PRY_LOG_MAX 240
#define PRY_LOG_PENDING 16

typedef struct _PRY_LOG_CTX {
    HANDLE File;
    BOOLEAN Initialized;
    CHAR Pending[PRY_LOG_PENDING][PRY_LOG_MAX];
    volatile LONG PendingCount;
} PRY_LOG_CTX;

static PRY_LOG_CTX PryLogCtx;

NTSTATUS PryLogInit(VOID)
{
    NTSTATUS st;
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES attrs;
    IO_STATUS_BLOCK iosb;

    PryLogCtx.File = NULL;
    PryLogCtx.PendingCount = 0;

    RtlInitUnicodeString(&path, PRY_KERNEL_LOG_PATH);
    InitializeObjectAttributes(&attrs, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = ZwCreateFile(&PryLogCtx.File,
                      FILE_APPEND_DATA | SYNCHRONIZE,
                      &attrs,
                      &iosb,
                      NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OPEN_IF,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                      NULL,
                      0);
    if (!NT_SUCCESS(st)) {
        PryLogCtx.File = NULL;
        return st;
    }
    PryLogCtx.Initialized = TRUE;
    return STATUS_SUCCESS;
}

static VOID PryLogFlushPending(VOID)
{
    LONG idx;
    CHAR line[PRY_LOG_MAX];

    while (PryLogCtx.PendingCount > 0) {
        idx = InterlockedDecrement(&PryLogCtx.PendingCount);
        if (idx < 0) {
            InterlockedIncrement(&PryLogCtx.PendingCount);
            break;
        }
        if (idx >= PRY_LOG_PENDING) {
            continue;
        }
        RtlCopyMemory(line, PryLogCtx.Pending[idx], PRY_LOG_MAX);
        PryLog("%s", line);
    }
}

VOID PryLogCleanup(VOID)
{
    if (PryLogCtx.File) {
        ZwClose(PryLogCtx.File);
        PryLogCtx.File = NULL;
    }
    PryLogCtx.Initialized = FALSE;
}

VOID PryLog(_In_ PCSTR Format, ...)
{
    CHAR text[PRY_LOG_MAX];
    CHAR line[PRY_LOG_MAX + 64];
    va_list args;
    NTSTATUS st;
    IO_STATUS_BLOCK iosb;
    SIZE_T len;
    LARGE_INTEGER now;

    if (!PryLogCtx.File) {
        return;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        LONG idx = InterlockedIncrement(&PryLogCtx.PendingCount) - 1;
        if (idx < PRY_LOG_PENDING) {
            va_start(args, Format);
            RtlStringCbVPrintfA(PryLogCtx.Pending[idx], PRY_LOG_MAX, Format, args);
            va_end(args);
        } else {
            InterlockedDecrement(&PryLogCtx.PendingCount);
        }
        return;
    }

    PryLogFlushPending();

    va_start(args, Format);
    RtlStringCbVPrintfA(text, sizeof(text), Format, args);
    va_end(args);

    KeQuerySystemTime(&now);
    RtlStringCbPrintfA(line, sizeof(line), "[%I64u] [t%Iu] %s\r\n",
                       (UINT64)now.QuadPart, (UINT64)HandleToUlong(PsGetCurrentThreadId()), text);
    RtlStringCbLengthA(line, sizeof(line), &len);

    // single serialized caller (sequential queue); each append is one
    // synchronous ZwWriteFile issued at PASSIVE_LEVEL
    st = ZwWriteFile(PryLogCtx.File, NULL, NULL, NULL, &iosb, (PVOID)line, (ULONG)len, NULL, NULL);

    UNREFERENCED_PARAMETER(st);
}

ULONG PrySystemFlags(VOID)
{
    ULONG flags = 0;
    ULONG ret = 0;
    NTSTATUS st;
    PRY_CI_INFO ci;

#ifndef SystemCodeIntegrityInformation
#define SystemCodeIntegrityInformation 103
#endif
#ifndef CODEINTEGRITY_OPTION_TESTSIGNING
#define CODEINTEGRITY_OPTION_TESTSIGNING 0x2
#endif
#ifndef CODEINTEGRITY_OPTION_HVCI_KMCI_DISABLED
#define CODEINTEGRITY_OPTION_HVCI_KMCI_DISABLED 0x200
#endif
#ifndef CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#endif

    ci.Length = sizeof(ci);
    ci.CodeIntegrityOptions = 0;
    st = ZwQuerySystemInformation(SystemCodeIntegrityInformation,
                                  &ci, sizeof(ci), &ret);
    if (NT_SUCCESS(st)) {
        if (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGNING) {
            flags |= PRY_FLAG_TESTSIGNING;
        }
        if (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) {
            flags |= PRY_FLAG_HVCI;
            // v14 (SI #25): HVCI blocks the int1 trap hook that turns a
            // #DB into a ring record, but DR arming still works. Surface
            // the fallback bit so an ABI v14 agent can skip the hooked
            // path for mem_rw watch and poll from userland instead.
            flags |= PRY_FLAG_WATCH_HVCI_FALLBACK;
        }
    }
    return flags;
}

ULONG PryNtBuild = 0;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS st;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver = WDF_NO_HANDLE;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = PryEvtDriverUnload;
    config.DriverPoolTag = PRY_POOL_TAG;

    PryLogInit();
    PryLog("PryDrv %u.%u abi=%u DriverEntry",
             PRY_DRV_VERSION_MAJOR, PRY_DRV_VERSION_MINOR, PRY_ABI_VERSION);

    {
        // RtlGetVersion: reliable build capture (the NtBuildNumber import
        // reads garbage without dllimport on this toolchain)
        RTL_OSVERSIONINFOW vi;
        RtlZeroMemory(&vi, sizeof(vi));
        vi.dwOSVersionInfoSize = sizeof(vi);
        if (NT_SUCCESS(RtlGetVersion(&vi))) {
            PryNtBuild = vi.dwBuildNumber;
        }
        PryLog("build=%u", PryNtBuild);
    }

    PryKmemInit();
    PryBpInit();
    PryBpHwInit();
    PryNotifyInit();
    // SI #21: initialise the self-protection state (callback NOT registered
    // yet — the first SELFPROT_CONFIG(Enable=ON) installs it). Pure state
    // init: no pool, no sync primitives beyond an ERESOURCE.
    PrySelfProtInit();

    st = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(st)) {
        PryLog("WdfDriverCreate failed st=%x", st);
        // PrySelfProtInit() above already allocated
        // an ERESOURCE (PrySp.Lock) -- undo it here or it leaks for the
        // life of the (now-failed) load. Safe to call having done nothing
        // past Init: PrySelfProtShutdown no-ops the (never-installed)
        // callback unregister and just deletes the resource.
        PrySelfProtShutdown();
        PryLogCleanup();
        return st;
    }

    st = PryCreateControlDevice(driver);
    if (!NT_SUCCESS(st)) {
        PryLog("control device failed st=%x", st);
    }

    // all-thread HW breakpoints reach threads created later. The Ex variant
    // requires the image to be linked with /INTEGRITYCHECK (0xC0000022
    // otherwise); fall back to the classic routine when it is refused.
    st = PsSetCreateThreadNotifyRoutineEx(0, PryOnThreadNotify);
    if (NT_SUCCESS(st)) {
        PryBpThreadNotifyRegistered = 1;
    } else {
        PryLog("thread notify Ex failed st=%x (needs /INTEGRITYCHECK), trying classic", st);
        st = PsSetCreateThreadNotifyRoutine(PryOnThreadNotifyClassic);
        if (NT_SUCCESS(st)) {
            PryBpThreadNotifyRegistered = 2;
        } else {
            PryLog("thread notify register failed st=%x (hw bp on new threads disabled)", st);
        }
    }

    // reap breakpoint records (and their DebugActive gates) when
    // their process exits. Failure is logged inside; the rest of the driver
    // does not depend on it.
    (void)PryBpProcNotifyInit();

    st = PryPhysRangesInit();
    PryLog("phys ranges init st=%x", st);

    // v8: wedge-detector. Best-effort — a failure here does not abort load,
    // but the log line surfaces the state so target_manage(crash_state) has
    // a signal to render.
    {
        NTSTATUS wd = PryWatchdogInit();
        PryLog("watchdog init st=%x", wd);
    }
    return STATUS_SUCCESS;
}

VOID PryEvtDriverUnload(_In_ WDFDRIVER Driver)
{
    LARGE_INTEGER interval;
    ULONG waitedMs;

    UNREFERENCED_PARAMETER(Driver);

    // The APC kernel routine/rundown and the thread-notify callback live in
    // this image. Both must be drained before the code pages go away or a
    // queued APC fires into unmapped memory (BSOD). EvtDriverUnload cannot
    // fail, so we wait (bounded) and log loudly when busy.
    if (PryBpThreadNotifyRegistered == 1) {
        PsRemoveCreateThreadNotifyRoutine(PryOnThreadNotify);
    } else if (PryBpThreadNotifyRegistered == 2) {
        PsRemoveCreateThreadNotifyRoutine(PryOnThreadNotifyClassic);
    }
    if (PryBpThreadNotifyRegistered) {
        PryBpThreadNotifyRegistered = 0;
        waitedMs = 0;
        while (PryThreadNotifyActive > 0 && waitedMs < 5000) {
            interval.QuadPart = -10 * 1000; // 1 ms
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
            waitedMs++;
        }
        if (PryThreadNotifyActive > 0) {
            PryLog("UNLOAD WARNING: thread notify still active=%d", PryThreadNotifyActive);
        }
    }

    // the process-exit callback must be gone before the table is
    // torn down below (it would otherwise reap records mid-cleanup).
    PryBpProcNotifyShutdown();
    PryBpCleanup();
    PryWatchdogShutdown();
    // v10: notify callbacks must be unregistered before the image pages go
    // away, and in-flight callbacks drained (same discipline as the BP
    // thread-notify path above). PryBpCleanup just above clears every HW
    // breakpoint and zeroes PryBpHwArmed before draining its own APCs, so
    // this never gets refused by the "HW bp still armed" guard added there.
    {
        NTSTATUS ndSt = PryNotifyDisable();
        if (!NT_SUCCESS(ndSt)) {
            PryLog("UNLOAD WARNING: NotifyDisable refused st=%x (HW bp still armed?)", ndSt);
        }
    }
    // SI #21: ObUnRegisterCallbacks + drain of any pre-op still running.
    PrySelfProtShutdown();

    // v13: a queued/running kernel-call thunk lives in this image. Flush
    // waits for the worker (it always completes once started), so the
    // deleted work item can never fire into unmapped code.
    PryKcallShutdown();

    waitedMs = 0;
    while (PryApcOutstanding > 0 && waitedMs < 5000) {
        interval.QuadPart = -10 * 1000; // 1 ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        waitedMs++;
    }
    if (PryApcOutstanding > 0) {
        PryLog("UNLOAD WARNING: %d APC(s) still queued - mapped image may be running", PryApcOutstanding);
    }

    // actually free every still-tracked KMEM_ALLOC
    // block (and its bookkeeping record) instead of only counting and
    // logging them -- those blocks have outlived any caller that could
    // still reference them by the time EvtDriverUnload runs.
    PryLog("unload (kalloc blocks freed: %u)", PryKmemFreeAll());
    PryLogCleanup();
}
