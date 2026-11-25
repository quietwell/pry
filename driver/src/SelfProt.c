#include "PryDriver.h"

// SelfProt.c -- SI adoption feature #21: ObRegisterCallbacks-based driver
// self-protection. See an internal plan
// enumeration.md feature 21.
//
// Model: a pre-op callback on PsProcessType (and optionally PsThreadType)
// masks DesiredAccess down to a safe keep-mask whenever a non-trusted
// caller tries to open a protected PID. "Trusted" = kernel-mode opener,
// our own dispatcher thread (PrySelfProtEnterCall / LeaveCall bracket),
// or the target PID opening itself. The retroscan-over-existing-handles
// path is deferred (slice doc §Retroscan — needs undocumented
// ExEnumHandleTable); the first-cut strips at CREATE/DUPLICATE only.

#ifndef OB_FLT_REGISTRATION_VERSION
#define OB_FLT_REGISTRATION_VERSION 0x0100
#endif
#ifndef STATUS_FLT_INSTANCE_ALTITUDE_COLLISION
#define STATUS_FLT_INSTANCE_ALTITUDE_COLLISION ((NTSTATUS)0xC01C000AL)
#endif
// User-mode access constants not auto-defined in kernel-mode (ntddk/ntifs).
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION  0x0800
#endif

#define PRY_SELFPROT_PROC_KEEP_DEFAULT \
    (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
#define PRY_SELFPROT_THREAD_KEEP_DEFAULT \
    (THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
#define PRY_SELFPROT_ALTITUDE_BASE 389100u
#define PRY_SELFPROT_ALTITUDE_SPAN 10u   // 389100..389109
#define PRY_SELFPROT_ALT_BUFFER_CCH 16

typedef struct _PRY_SELFPROT_STATE {
    BOOLEAN       Initialized;
    BOOLEAN       Installed;
    UINT32        Altitude;        // in-use (389100..389109 or 0)
    UINT32        Flags;           // last applied Config.Flags
    UINT32        ProcKeep;
    UINT32        ThreadKeep;
    UINT32        PidCount;
    UINT32        Pids[PRY_SELFPROT_MAX_PIDS];
    PVOID         RegHandle;
    UINT64        DisableToken;    // cookie an operator must echo to turn off
    volatile LONG InFlight;        // outstanding pre-op calls
    volatile LONG State;           // PRY_SELFPROT_STATE_*
    volatile LONG64 Hits;
    volatile LONG64 Stripped;
    volatile LONG64 Bypassed;
    ERESOURCE     Lock;            // write-exclusive on config change
} PRY_SELFPROT_STATE;

static PRY_SELFPROT_STATE PrySp;

// Per-dispatcher-thread reentry guard. The sequential queue serialises
// IOCTLs; this depth lets a nested handle acquisition during one of our
// IOCTL handlers short-circuit the strip. It's a plain counter — the KMDF
// sequential queue guarantees one dispatcher thread at a time, so no
// per-thread TLS is required for the first cut.
static volatile LONG PrySpOwnDepth;

VOID PrySelfProtEnterCall(VOID)
{
    InterlockedIncrement(&PrySpOwnDepth);
}

VOID PrySelfProtLeaveCall(VOID)
{
    InterlockedDecrement(&PrySpOwnDepth);
}

static BOOLEAN PrySpSelfInCall(VOID)
{
    return (PrySpOwnDepth > 0);
}

static BOOLEAN PrySpIsProtectedPid(UINT32 pid)
{
    UINT32 i;
    if (!pid) return FALSE;
    for (i = 0; i < PrySp.PidCount; i++) {
        if (PrySp.Pids[i] == pid) return TRUE;
    }
    return FALSE;
}

static OB_PREOP_CALLBACK_STATUS PrySpPreOp(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    POBJECT_TYPE t;
    HANDLE targetPidH;
    UINT32 targetPid = 0;
    UINT32 callerPid;
    ACCESS_MASK keep;
    ACCESS_MASK orig;
    ACCESS_MASK next;

    UNREFERENCED_PARAMETER(RegistrationContext);

    InterlockedIncrement(&PrySp.InFlight);
    InterlockedIncrement64(&PrySp.Hits);

    // Kernel origin: never touch. KernelHandle==1 covers IoCreateFile-style
    // kernel opens plus every kernel-driven handle acquisition. ObCallback
    // itself fires at PASSIVE_LEVEL on the opener's thread.
    if (Info->KernelHandle) {
        InterlockedIncrement64(&PrySp.Bypassed);
        goto out;
    }

    // Our own dispatcher thread: never strip the opens our IOCTL handlers
    // perform (PryUserMemRead etc. ObOpenObjectByPointer the target
    // EPROCESS). Set/cleared in Dispatcher.c around the IOCTL switch.
    if (PrySpSelfInCall()) {
        InterlockedIncrement64(&PrySp.Bypassed);
        goto out;
    }

    t = Info->ObjectType;
    if (t == *PsProcessType) {
        targetPidH = PsGetProcessId((PEPROCESS)Info->Object);
        targetPid = (UINT32)(ULONG_PTR)targetPidH;
        keep = (ACCESS_MASK)PrySp.ProcKeep;
    } else if (t == *PsThreadType) {
        PEPROCESS targetProc = IoThreadToProcess((PETHREAD)Info->Object);
        targetPidH = targetProc ? PsGetProcessId(targetProc) : NULL;
        targetPid = (UINT32)(ULONG_PTR)targetPidH;
        keep = (ACCESS_MASK)PrySp.ThreadKeep;
    } else {
        goto out;
    }

    if (!PrySpIsProtectedPid(targetPid)) {
        goto out;
    }

    // Self-open is always allowed (an agent handling its own threads/VM
    // would otherwise deadlock itself).
    callerPid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    if (callerPid == targetPid) {
        InterlockedIncrement64(&PrySp.Bypassed);
        goto out;
    }

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        orig = Info->Parameters->CreateHandleInformation.DesiredAccess;
        next = orig & keep;
        if (next != orig) {
            Info->Parameters->CreateHandleInformation.DesiredAccess = next;
            InterlockedIncrement64(&PrySp.Stripped);
        }
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE &&
               !(PrySp.Flags & PRY_SELFPROT_FLAG_ALLOW_DUP)) {
        orig = Info->Parameters->DuplicateHandleInformation.DesiredAccess;
        next = orig & keep;
        if (next != orig) {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess = next;
            InterlockedIncrement64(&PrySp.Stripped);
        }
    }

out:
    InterlockedDecrement(&PrySp.InFlight);
    return OB_PREOP_SUCCESS;
}

VOID PrySelfProtInit(VOID)
{
    if (PrySp.Initialized) {
        return;
    }
    RtlZeroMemory(&PrySp, sizeof(PrySp));
    ExInitializeResourceLite(&PrySp.Lock);
    PrySp.ProcKeep = PRY_SELFPROT_PROC_KEEP_DEFAULT;
    PrySp.ThreadKeep = PRY_SELFPROT_THREAD_KEEP_DEFAULT;
    // DisableToken is seeded on first install (RtlRandomEx) and persists
    // across reconfig to let the orchestrator keep driving teardown with
    // the same cookie it logged.
    PrySp.Initialized = TRUE;
}

static VOID PrySpDrain(VOID)
{
    LARGE_INTEGER interval;
    ULONG waited = 0;
    while (PrySp.InFlight > 0 && waited < 5000) {
        interval.QuadPart = -10 * 1000;  // 1 ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        waited++;
    }
    if (PrySp.InFlight > 0) {
        PryLog("SELFPROT: drain timed out, in_flight=%d", PrySp.InFlight);
    }
}

static VOID PrySpUnregisterLocked(VOID)
{
    if (PrySp.RegHandle) {
        ObUnRegisterCallbacks(PrySp.RegHandle);
        PrySp.RegHandle = NULL;
    }
    PrySpDrain();
    PrySp.Installed = FALSE;
    PrySp.Altitude = 0;
    InterlockedExchange(&PrySp.State, 0);
}

VOID PrySelfProtShutdown(VOID)
{
    if (!PrySp.Initialized) {
        return;
    }
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&PrySp.Lock, TRUE);
    PrySpUnregisterLocked();
    ExReleaseResourceLite(&PrySp.Lock);
    KeLeaveCriticalRegion();
    ExDeleteResourceLite(&PrySp.Lock);
    PrySp.Initialized = FALSE;
    PryLog("SELFPROT: shutdown");
}

static NTSTATUS PrySpRegisterLocked(UINT32 flags, UINT32* altOut)
{
    OB_OPERATION_REGISTRATION ops[2];
    OB_CALLBACK_REGISTRATION reg;
    UNICODE_STRING alt;
    WCHAR altBuf[PRY_SELFPROT_ALT_BUFFER_CCH];
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    UINT32 attempt;
    UINT32 opsCount;
    ACCESS_MASK procOps;
    ACCESS_MASK threadOps;

    procOps = OB_OPERATION_HANDLE_CREATE;
    if (!(flags & PRY_SELFPROT_FLAG_ALLOW_DUP)) {
        procOps |= OB_OPERATION_HANDLE_DUPLICATE;
    }
    threadOps = procOps;

    RtlZeroMemory(ops, sizeof(ops));
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = procOps;
    ops[0].PreOperation = PrySpPreOp;
    opsCount = 1;
    if (flags & PRY_SELFPROT_FLAG_INCLUDE_THREADS) {
        ops[1].ObjectType = PsThreadType;
        ops[1].Operations = threadOps;
        ops[1].PreOperation = PrySpPreOp;
        opsCount = 2;
    }

    for (attempt = 0; attempt < PRY_SELFPROT_ALTITUDE_SPAN; attempt++) {
        UINT32 cand = PRY_SELFPROT_ALTITUDE_BASE + attempt;
        RtlStringCchPrintfW(altBuf, PRY_SELFPROT_ALT_BUFFER_CCH, L"%u", cand);
        RtlInitUnicodeString(&alt, altBuf);
        RtlZeroMemory(&reg, sizeof(reg));
        reg.Version = OB_FLT_REGISTRATION_VERSION;
        reg.OperationRegistrationCount = (USHORT)opsCount;
        reg.Altitude = alt;
        reg.RegistrationContext = NULL;
        reg.OperationRegistration = ops;

        st = ObRegisterCallbacks(&reg, &PrySp.RegHandle);
        if (NT_SUCCESS(st)) {
            if (altOut) *altOut = cand;
            if (attempt > 0) {
                InterlockedOr(&PrySp.State,
                              PRY_SELFPROT_STATE_ALTITUDE_RETRY);
                PryLog("SELFPROT: altitude retried to %u", cand);
            }
            return STATUS_SUCCESS;
        }
        if (st != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) {
            // Non-collision failure (invalid param, etc.) — give up.
            break;
        }
    }

    InterlockedOr(&PrySp.State, PRY_SELFPROT_STATE_ALTITUDE_FAIL);
    PryLog("SELFPROT: altitude install failed st=%x (collision across %u..%u)",
             st, PRY_SELFPROT_ALTITUDE_BASE,
             PRY_SELFPROT_ALTITUDE_BASE + PRY_SELFPROT_ALTITUDE_SPAN - 1);
    return st;
}

static VOID PrySpCopyPidsLocked(const PRY_SELFPROT_CONFIG_IN* in)
{
    UINT32 i;
    UINT32 n = in->PidCount;
    if (n > PRY_SELFPROT_MAX_PIDS) n = PRY_SELFPROT_MAX_PIDS;
    RtlZeroMemory(PrySp.Pids, sizeof(PrySp.Pids));
    PrySp.PidCount = 0;
    for (i = 0; i < n; i++) {
        if (in->ProtectedPids[i]) {
            PrySp.Pids[PrySp.PidCount++] = in->ProtectedPids[i];
        }
    }
}

static VOID PrySpSeedDisableTokenLocked(VOID)
{
    LARGE_INTEGER now;
    ULONG seed;
    if (PrySp.DisableToken) {
        return;
    }
    KeQueryTickCount(&now);
    seed = (ULONG)now.LowPart ^ (ULONG)now.HighPart ^ (ULONG)(ULONG_PTR)&PrySp;
    PrySp.DisableToken =
        ((UINT64)RtlRandomEx(&seed) << 32) | (UINT64)RtlRandomEx(&seed);
    if (!PrySp.DisableToken) {
        PrySp.DisableToken = 0xBEEFC0DEBAADF00DULL;
    }
    PryLog("SELFPROT: disable_token=0x%llx (echo via DISABLE_TOKEN_OK to turn off)",
             (unsigned long long)PrySp.DisableToken);
}

NTSTATUS PrySelfProtApply(_In_ const PRY_SELFPROT_CONFIG_IN* In,
                            _Out_ PRY_SELFPROT_CONFIG_OUT* Out)
{
    NTSTATUS st = STATUS_SUCCESS;
    UINT32 altitude = 0;
    BOOLEAN callerIsProtected;
    UINT32 callerPid;

    RtlZeroMemory(Out, sizeof(*Out));
    if (!PrySp.Initialized) {
        Out->Status = (UINT32)STATUS_DEVICE_NOT_READY;
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&PrySp.Lock, TRUE);

    callerPid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    callerIsProtected = PrySpIsProtectedPid(callerPid);

    if (In->Enable == PRY_SELFPROT_ENABLE_OFF) {
        BOOLEAN tokenOk =
            (In->Flags & PRY_SELFPROT_FLAG_DISABLE_TOKEN_OK) &&
            In->DisableToken != 0 &&
            In->DisableToken == PrySp.DisableToken;
        if (!callerIsProtected && !tokenOk) {
            st = STATUS_ACCESS_DENIED;
            PryLog("SELFPROT: Enable=0 refused (caller pid=%u not protected,"
                     " token mismatch)", callerPid);
            goto done;
        }
        PrySpUnregisterLocked();
        PrySp.PidCount = 0;
        RtlZeroMemory(PrySp.Pids, sizeof(PrySp.Pids));
        PryLog("SELFPROT: disabled by pid=%u", callerPid);
        st = STATUS_SUCCESS;
        goto done;
    }

    PrySpCopyPidsLocked(In);
    PrySp.ProcKeep = In->ProcessAccessKeep
        ? In->ProcessAccessKeep : PRY_SELFPROT_PROC_KEEP_DEFAULT;
    PrySp.ThreadKeep = In->ThreadAccessKeep
        ? In->ThreadAccessKeep : PRY_SELFPROT_THREAD_KEEP_DEFAULT;
    PrySp.Flags = In->Flags;

    if (In->Enable == PRY_SELFPROT_ENABLE_REFRESH) {
        if (!PrySp.Installed) {
            st = STATUS_INVALID_DEVICE_STATE;
            goto done;
        }
        altitude = PrySp.Altitude;
        st = STATUS_SUCCESS;
        PryLog("SELFPROT: refreshed pids=%u mask=0x%x/0x%x flags=0x%x",
                 PrySp.PidCount, PrySp.ProcKeep, PrySp.ThreadKeep,
                 PrySp.Flags);
    } else {
        // Enable == ON: full install (or re-install after flag changes).
        if (PrySp.Installed) {
            PrySpUnregisterLocked();
        }
        InterlockedAnd(&PrySp.State, 0);
        st = PrySpRegisterLocked(In->Flags, &altitude);
        if (NT_SUCCESS(st)) {
            PrySp.Installed = TRUE;
            PrySp.Altitude = altitude;
            InterlockedOr(&PrySp.State, PRY_SELFPROT_STATE_INSTALLED);
            PrySpSeedDisableTokenLocked();
            PryLog("SELFPROT: installed altitude=%u pids=%u flags=0x%x",
                     altitude, PrySp.PidCount, PrySp.Flags);
        }
    }

done:
    Out->Status = (UINT32)st;
    Out->Installed = PrySp.Installed ? 1u : 0u;
    Out->State = (UINT32)PrySp.State;
    Out->Altitude = PrySp.Altitude;
    Out->ProtectedPids = PrySp.PidCount;
    Out->DisableToken = PrySp.DisableToken;
    ExReleaseResourceLite(&PrySp.Lock);
    KeLeaveCriticalRegion();
    return st;
}

VOID PrySelfProtQuery(_Out_ PRY_SELFPROT_STATUS_OUT* Out)
{
    RtlZeroMemory(Out, sizeof(*Out));
    if (!PrySp.Initialized) {
        Out->Status = (UINT32)STATUS_DEVICE_NOT_READY;
        return;
    }
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PrySp.Lock, TRUE);
    Out->Status = (UINT32)STATUS_SUCCESS;
    Out->State = (UINT32)PrySp.State;
    Out->Installed = PrySp.Installed ? 1u : 0u;
    Out->Altitude = PrySp.Altitude;
    Out->ProtectedPids = PrySp.PidCount;
    Out->Flags = PrySp.Flags;
    Out->ProcessAccessKeep = PrySp.ProcKeep;
    Out->ThreadAccessKeep = PrySp.ThreadKeep;
    Out->PreOpHits = (UINT64)PrySp.Hits;
    Out->Stripped = (UINT64)PrySp.Stripped;
    Out->Bypassed = (UINT64)PrySp.Bypassed;
    ExReleaseResourceLite(&PrySp.Lock);
    KeLeaveCriticalRegion();
}
