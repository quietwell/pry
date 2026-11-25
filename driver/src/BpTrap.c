#include "PryDriver.h"
#include <intrin.h>

// BpTrap.c — v11 kernel HW-BP hit observability.
//
// Armed DR0-3 breakpoints raise #DB on the hitting CPU; without a kernel
// debugger that vector resolves to KiDispatchException and a bugcheck, so
// hits were invisible (the reviewer's "kd-only" gap). Subscribing the
// PRY_EVT_CLASS_BP notify class redirects every CPU's IDT[1] to
// PryBpTrapStub (BpTrapAsm.asm): hits whose DR6 B0-B3 bit resolves to an
// armed pry HW bp are recorded in the notify ring and resumed (RF set
// so exec bps don't re-fault); everything else chains to the saved
// KiTrap01 unchanged.
//
// The IDT entry itself is unwritable on modern builds — the page is RO
// even via a writable alias. Instead each CPU gets a full writable COPY
// of its IDT in our nonpaged pool with entry[1] retargeted, and the CPU
// is switched to it via lidt. Install first probes a no-op lidt of the
// unchanged IDTR: hypervisors with descriptor-table exiting (observed on
// a Hyper-V guest, build 26200 — IDT page EPT-RO, lidt/CR0.WP both
// intercepted) make the probe fault and install fails NOT_SUPPORTED
// instead of corrupting anything. Kernel vectored handlers don't exist
// in the kernel (no RtlAddVectoredExceptionHandler export), so this is
// the only kernel-side mechanism.
//
// Safety notes:
//   * IDT redirection is PatchGuard territory — install is gated on
//     PRY_NOTIFY_FLAG_BP_HOOK_OK and the lidt probe.
//   * The dispatch path never blocks and never allocates. Above
//     DISPATCH_LEVEL the bp-table/ring locks are skipped; a likely-ours
//     hit still consumes (counted) rather than chaining into a bugcheck.
//   * A per-CPU busy flag makes reentrant hits consume without
//     recording instead of recursing to a stack overflow.
//   * DR7.GD: a foreign "general detect" would fault on our own dr
//     reads; no in-kernel code keeps GD armed permanently, and the lab
//     gate documents the residual risk.

#pragma pack(push, 1)
typedef struct _PRY_IDT_ENTRY {
    UINT16 OffsetLow;
    UINT16 Selector;
    UINT16 IstIndex : 3;
    UINT16 Reserved0 : 5;
    UINT16 Type : 5;
    UINT16 Dpl : 2;
    UINT16 Present : 1;
    UINT16 OffsetMiddle;
    UINT32 OffsetHigh;
    UINT32 Reserved1;
} PRY_IDT_ENTRY, *PPRY_IDT_ENTRY;

// __sidt emits a 10-byte operand {limit:2, base:8} — must stay packed or
// Base reads at offset 8 instead of 2 (wild pointer -> AV on deref).
typedef struct _PRY_IDTR {
    UINT16 Limit;
    UINT64 Base;
} PRY_IDTR, *PPRY_IDTR;
#pragma pack(pop)

#define PRY_TRAP_MAX_CPUS 1024
#define EFLAGS_RF 0x10000

extern VOID PryBpTrapStub(VOID);

volatile LONG PryBpTrapOn = 0;          // 1 while the hook owns int1
volatile LONG PryBpTrapInStub = 0;      // in-flight stub executions
volatile LONG PryBpTrapMissed = 0;      // hits consumed but not recorded
volatile LONG PryBpTrapCpuBusy[PRY_TRAP_MAX_CPUS];
UINT64 PryBpTrapChainTarget = 0;        // asm jmp target (orig KiTrap01)

static UINT64 PryIdtTarget(_In_ const PRY_IDT_ENTRY* E)
{
    return (UINT64)E->OffsetLow
         | ((UINT64)E->OffsetMiddle << 16)
         | ((UINT64)E->OffsetHigh << 32);
}

static VOID PryIdtSetTarget(_Inout_ PRY_IDT_ENTRY* E, _In_ UINT64 Addr)
{
    E->OffsetLow = (UINT16)(Addr & 0xFFFF);
    E->OffsetMiddle = (UINT16)((Addr >> 16) & 0xFFFF);
    E->OffsetHigh = (UINT32)(Addr >> 32);
}

typedef struct _PRY_BP_TRAP_CTX {
    UINT64 StubAddr;
    BOOLEAN Uninstall;
    UINT32 Patched;
    UINT32 Restored;
    UINT32 Foreign;      // cpus whose IDTR was neither ours nor original
    UINT32 Unmapped;     // cpus without a writable IDT copy (skipped)
} PRY_BP_TRAP_CTX;

// per-CPU patch state: a writable copy of the cpu's own IDT with
// entry[1] -> our stub, plus the original IDTR for restore.
typedef struct _PRY_BP_TRAP_CPU {
    PRY_IDTR OrigIdtr;     // this cpu's original IDTR (restore target)
    PVOID      CopyBase;     // page-aligned writable IDT copy
} PRY_BP_TRAP_CPU;
static PRY_BP_TRAP_CPU* PryBpTrapCpus = NULL;
static ULONG PryBpTrapCpuCount = 0;

// KeGetCurrentProcessorIndexEx isn't exported by this WDK's ntoskrnl —
// ProcessorNumberEx + IndexFromNumber covers the same ground (Vista+).
static ULONG PryBpTrapCpuIndex(VOID)
{
    PROCESSOR_NUMBER pn;
    ULONG idx = KeGetCurrentProcessorNumberEx(&pn);
    UNREFERENCED_PARAMETER(idx);
    return KeGetProcessorIndexFromNumber(&pn);
}

// runs at IPI_LEVEL on every processor (KeIpiGenericCall). lidt is
// locally atomic here: an int1 can only fire from code executing on this
// CPU, and this CPU is inside the callback.
static ULONG_PTR PryBpTrapPatchCpu(_In_ ULONG_PTR Ctx)
{
    PRY_BP_TRAP_CTX* c = (PRY_BP_TRAP_CTX*)Ctx;
    PRY_IDTR idtr, next;
    ULONG cpu = PryBpTrapCpuIndex();

    if (cpu >= PryBpTrapCpuCount || !PryBpTrapCpus
        || !PryBpTrapCpus[cpu].CopyBase) {
        InterlockedIncrement((volatile LONG*)&c->Unmapped);
        return 0;
    }

    if (!c->Uninstall) {
        __sidt(&idtr);
        if (idtr.Base == (UINT64)(ULONG_PTR)PryBpTrapCpus[cpu].CopyBase) {
            return 0; // already ours (IPI may include the caller)
        }
        next = PryBpTrapCpus[cpu].OrigIdtr;
        next.Base = (UINT64)(ULONG_PTR)PryBpTrapCpus[cpu].CopyBase;
        __lidt(&next);
        InterlockedIncrement((volatile LONG*)&c->Patched);
        return 0;
    }

    // uninstall: restore this cpu's original IDTR.
    __sidt(&idtr);
    if (idtr.Base == (UINT64)(ULONG_PTR)PryBpTrapCpus[cpu].CopyBase) {
        __lidt(&PryBpTrapCpus[cpu].OrigIdtr);
        InterlockedIncrement((volatile LONG*)&c->Restored);
    } else {
        // someone re-hooked after us — leave their state, log-worthy
        InterlockedIncrement((volatile LONG*)&c->Foreign);
    }
    return 0;
}

// PASSIVE: park the caller on each cpu in turn, capture its IDTR, and
// build the writable copy with entry[1] -> PryBpTrapStub.
static NTSTATUS PryBpTrapMapIdts(_In_ ULONG Ncpu, _In_ UINT64 StubAddr)
{
    ULONG i;
    NTSTATUS st;
    PryBpTrapCpus = (PRY_BP_TRAP_CPU*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, Ncpu * sizeof(PRY_BP_TRAP_CPU), 'ByrP');
    if (!PryBpTrapCpus) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(PryBpTrapCpus, Ncpu * sizeof(PRY_BP_TRAP_CPU));
    PryBpTrapCpuCount = Ncpu;

    for (i = 0; i < Ncpu; i++) {
        PROCESSOR_NUMBER pn;
        GROUP_AFFINITY ga, old;
        PRY_IDTR idtr;
        SIZE_T copyLen;

        st = KeGetProcessorNumberFromIndex(i, &pn);
        if (!NT_SUCCESS(st)) {
            continue; // hole in the index space — leave unmapped
        }
        RtlZeroMemory(&ga, sizeof(ga));
        ga.Group = pn.Group;
        ga.Mask = (KAFFINITY)1 << pn.Number;
        KeSetSystemGroupAffinityThread(&ga, &old);
        __sidt(&idtr);
        KeRevertToUserGroupAffinityThread(&old);

        copyLen = (SIZE_T)idtr.Limit + 1;
        if (copyLen > PAGE_SIZE) {
            PryLog("BPTRAP map cpu%u: idt limit %x > page", i, idtr.Limit);
            continue;
        }
        PryBpTrapCpus[i].OrigIdtr = idtr;
        // PAGE_SIZE pool allocations come back page-aligned.
        PryBpTrapCpus[i].CopyBase = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, PAGE_SIZE, 'IyrP');
        if (!PryBpTrapCpus[i].CopyBase) {
            PryLog("BPTRAP map cpu%u: copy alloc failed", i);
            continue;
        }
        RtlCopyMemory(PryBpTrapCpus[i].CopyBase,
                      (PVOID)(ULONG_PTR)idtr.Base, copyLen);
        PryIdtSetTarget(
            &((PPRY_IDT_ENTRY)PryBpTrapCpus[i].CopyBase)[1], StubAddr);
    }
    return STATUS_SUCCESS;
}

static VOID PryBpTrapUnmapIdts(VOID)
{
    ULONG i;
    if (!PryBpTrapCpus) {
        return;
    }
    for (i = 0; i < PryBpTrapCpuCount; i++) {
        if (PryBpTrapCpus[i].CopyBase) {
            ExFreePoolWithTag(PryBpTrapCpus[i].CopyBase, 'IyrP');
        }
    }
    ExFreePoolWithTag(PryBpTrapCpus, 'ByrP');
    PryBpTrapCpus = NULL;
    PryBpTrapCpuCount = 0;
}

#ifndef SystemKernelVaShadowInformation
#define SystemKernelVaShadowInformation 196
#endif

// SYSTEM_KERNEL_VA_SHADOW_INFORMATION (undocumented but widely known;
// bit 0 is KvaShadowEnabled). Declared locally -- only this install gate
// needs it.
typedef struct _PRY_KVA_SHADOW_INFO {
    union {
        ULONG KvaShadowFlags;
        struct {
            ULONG KvaShadowEnabled : 1;
            ULONG KvaShadowUserGlobal : 1;
            ULONG KvaShadowPcid : 1;
            ULONG KvaShadowInvpcid : 1;
            ULONG KvaShadowRequired : 1;
            ULONG KvaShadowRequiredAvailable : 1;
            ULONG InvalidPteBit : 6;
            ULONG L1DataCacheFlushSupported : 1;
            ULONG L1TerminalFaultMitigationPresent : 1;
            ULONG Reserved : 18;
        };
    };
} PRY_KVA_SHADOW_INFO;

// KVA shadowing (the Meltdown mitigation) runs the kernel under a CR3
// separate from user mode, with only a minimal trampoline mapped into
// the user page tables. Our per-CPU IDT copy (nonpaged pool) is never in
// that trampoline. An int1 that enters while CR3 is still the user table
// (the common case -- #DB can fire from CPL3) would walk the IDT through
// an address that's unmapped under that CR3: a page fault with no IDT
// left to service it, i.e. a triple fault. Refuse the hook outright
// instead of gambling on it.
static BOOLEAN PryBpTrapKvaShadowOn(VOID)
{
    PRY_KVA_SHADOW_INFO info;
    ULONG ret = 0;
    NTSTATUS st;

    RtlZeroMemory(&info, sizeof(info));
    st = ZwQuerySystemInformation(SystemKernelVaShadowInformation, &info, sizeof(info), &ret);
    if (!NT_SUCCESS(st)) {
        // Class unsupported on this build: these are old enough WDK/OS
        // combinations that the mitigation doesn't exist at all, so
        // "off" is the correct answer here, not "unknown".
        return FALSE;
    }
    return info.KvaShadowEnabled != 0;
}

// capability probe: reloading the identical IDTR is architecturally a
// no-op. A fault means the hypervisor intercepts descriptor-table ops —
// the IDT-copy hook can't work, and neither could an in-place write
// (the page was already proven EPT-RO). Fail cleanly instead.
static BOOLEAN PryBpTrapLidtOk(VOID)
{
    BOOLEAN ok = TRUE;
    __try {
        PRY_IDTR cur;
        __sidt(&cur);
        __lidt(&cur);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    return ok;
}

NTSTATUS PryBpTrapInstall(VOID)
{
    PRY_BP_TRAP_CTX ctx;
    PRY_IDTR idtr;
    NTSTATUS st;
    ULONG ncpu;

    if (InterlockedCompareExchange(&PryBpTrapOn, 0, 0) == 1) {
        return STATUS_SUCCESS; // already installed
    }
    if (PrySystemFlags() & PRY_FLAG_HVCI) {
        PryLog("BPTRAP refused: HVCI on (IDT read-only)");
        return STATUS_NOT_SUPPORTED;
    }
    if (PryBpTrapKvaShadowOn()) {
        PryLog("BPTRAP refused: KVA shadowing enabled (IDT copy is not in the user-CR3 trampoline)");
        return STATUS_NOT_SUPPORTED;
    }
    if (!PryBpTrapLidtOk()) {
        PryLog("BPTRAP refused: descriptor-table exiting (hypervisor)");
        return STATUS_NOT_SUPPORTED;
    }

    ncpu = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (!ncpu || ncpu > PRY_TRAP_MAX_CPUS) {
        ncpu = PRY_TRAP_MAX_CPUS;
    }

    st = PryBpTrapMapIdts(ncpu, (UINT64)(ULONG_PTR)PryBpTrapStub);
    if (!NT_SUCCESS(st)) {
        goto fail;
    }

    // the chain target is whatever vector 1 resolves to right now on the
    // caller's CPU (KiTrap01 on a stock kernel). Every CPU's kernel IDT
    // entry points at the same handler on sane hosts; a mismatch still
    // chains correctly because it only affects the jmp target.
    __sidt(&idtr);
    PryBpTrapChainTarget = PryIdtTarget(&((PPRY_IDT_ENTRY)idtr.Base)[1]);

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.StubAddr = (UINT64)(ULONG_PTR)PryBpTrapStub;
    ctx.Uninstall = FALSE;
    PryBpTrapPatchCpu((ULONG_PTR)&ctx);   // caller's CPU first
    KeIpiGenericCall(PryBpTrapPatchCpu, (ULONG_PTR)&ctx);

    PryLog("BPTRAP installed: patched=%u unmapped=%u chain=%llx",
             ctx.Patched, ctx.Unmapped, PryBpTrapChainTarget);
    if (!ctx.Patched) {
        PryLog("BPTRAP install failed: 0/%u cpus patched", ncpu);
        st = STATUS_UNSUCCESSFUL;
        goto fail;
    }
    InterlockedExchange(&PryBpTrapOn, 1);
    return STATUS_SUCCESS;

fail:
    PryBpTrapUnmapIdts();
    return st;
}

VOID PryBpTrapUninstall(VOID)
{
    PRY_BP_TRAP_CTX ctx;
    LARGE_INTEGER interval;
    ULONG waitedMs = 0;

    if (InterlockedCompareExchange(&PryBpTrapOn, 0, 0) == 0) {
        return;
    }
    // stop consuming first: in-flight and future hits chain to KiTrap01.
    InterlockedExchange(&PryBpTrapOn, 0);

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.StubAddr = (UINT64)(ULONG_PTR)PryBpTrapStub;
    ctx.Uninstall = TRUE;
    PryBpTrapPatchCpu((ULONG_PTR)&ctx);
    KeIpiGenericCall(PryBpTrapPatchCpu, (ULONG_PTR)&ctx);

    // drain stubs still mid-dispatch on any CPU (bounded)
    while (InterlockedCompareExchange(&PryBpTrapInStub, 0, 0) != 0
           && waitedMs < 5000) {
        interval.QuadPart = -10 * 1000;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        waitedMs++;
    }
    PryLog("BPTRAP uninstalled: restored=%u foreign=%u inStub=%ld missed=%ld",
             ctx.Restored, ctx.Foreign,
             InterlockedCompareExchange(&PryBpTrapInStub, 0, 0),
             PryBpTrapMissed);

    PryBpTrapUnmapIdts();
}

BOOLEAN PryBpTrapInstalled(VOID)
{
    return InterlockedCompareExchange(&PryBpTrapOn, 0, 0) == 1;
}

// caller holds PryBpLock (acquired however is safe
// for its own IRQL -- see PryBpTrapDispatch below). Scans the armed-HW-
// bp table for a record matching the fired DR condition bits Bbits on
// this (Pid,Tid); fills *BpId/*Slot/*Access/*WatchCookie and returns TRUE
// on a match, FALSE otherwise (out params untouched on a miss).
static BOOLEAN PryBpTrapScanLocked(_In_ UINT32 Bbits, _In_ UINT32 Pid, _In_ UINT32 Tid,
                                     _Out_ UINT32* BpId, _Out_ UINT32* Slot,
                                     _Out_ UINT32* Access, _Out_ UINT32* WatchCookie)
{
    UINT32 i;
    for (i = 0; i < PRY_MAX_BP; i++) {
        PPRY_BP_REC r = &PryBpTable[i];
        UINT64 drn;
        if (!(r->Used && r->Enabled && r->Kind == PRY_BP_KIND_HW)) {
            continue;
        }
        if (!(Bbits & (1u << r->Slot))) {
            continue;
        }
        // scope: per-thread, per-process, all-of-pid, or global
        if (!r->Global && r->Pid && r->Pid != Pid) {
            continue;
        }
        // a record pinned to an EPROCESS does not claim a hit from
        // a process that later reused its PID.
        if (!r->Global && r->ProcKey && r->ProcKey != (UINT64)(ULONG_PTR)PsGetCurrentProcess()) {
            continue;
        }
        if (r->Tid && r->Tid != Tid) {
            continue;
        }
        switch (r->Slot) { // __readdr needs a constant index
        case 0: drn = __readdr(0); break;
        case 1: drn = __readdr(1); break;
        case 2: drn = __readdr(2); break;
        case 3: drn = __readdr(3); break;
        default: drn = ~0ull; break;
        }
        if (drn != r->Address) {
            continue; // stale/foreign DR contents
        }
        *BpId = r->Id;
        *Slot = r->Slot;
        *Access = r->Access;
        // v14 (SI #25): propagate the watch demux cookie. 0 for a plain
        // bp_manage HW breakpoint; echoes r->Id for an entry that was
        // armed through PRY_BPHW_FLAG_IS_WATCH.
        *WatchCookie = r->IsWatch ? r->WatchCookie : 0;
        return TRUE;
    }
    return FALSE;
}

// called by the asm stub with interrupts masked (vector gate semantics):
// return nonzero to consume (record queued + RF set) or 0 to chain.
UINT32 PryBpTrapDispatch(_In_ UINT64 Rip, _In_ UINT64 Cs,
                           _Inout_ UINT64* RflagsSlot)
{
    UINT64 dr6;
    UINT32 bbits;
    UINT32 cpu;
    UINT32 pid, tid;
    KIRQL irql;
    UINT32 i;
    UINT32 bpId = 0, slot = 0xFF, access = 0;
    UINT32 watchCookie = 0; // v14 (SI #25): mirrored from matching IS_WATCH record
    BOOLEAN tableScanned = FALSE;
    // Timestamp at trap entry, before either the bp-table or event-ring lock.
    // KeQueryInterruptTime returns 100 ns units; PRY_EVT.TsMs is uptime ms.
    UINT64 hitTsMs = KeQueryInterruptTime() / 10000;

    UNREFERENCED_PARAMETER(Cs);

    dr6 = __readdr(6);
    bbits = (UINT32)(dr6 & 0xF);            // B0-B3 = DR0-3 condition bits
    if (!bbits) {
        return 0;                           // BS/GD/BT — not a DR bp hit
    }

    cpu = PryBpTrapCpuIndex();
    if (cpu < PRY_TRAP_MAX_CPUS) {
        if (InterlockedCompareExchange(&PryBpTrapCpuBusy[cpu], 1, 0) != 0) {
            // reentrant hit on this CPU — consume without touching state
            // (records the loss via the missed counter below)
            InterlockedIncrement(&PryBpTrapMissed);
            *RflagsSlot |= EFLAGS_RF;
            return 1;
        }
    }

    irql = KeGetCurrentIrql();
    pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    tid = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();

    // Match the fired slot(s) against the armed bp table. Below
    // DISPATCH_LEVEL the lock is safe to block on: whoever holds it, if
    // anyone, is a different CPU and will release it in due course. At
    // or above DISPATCH_LEVEL -- the common case, since armed DRs mostly
    // fire from code already running at DISPATCH -- a blocking acquire
    // can self-deadlock: the holder may be THIS exact CPU, now spinning
    // here instead of returning to release it (the thread-create notify
    // path is one such holder). Try-acquire instead and fall back to the
    // lock-free "something's armed, record a minimal hit" path below on
    // contention, exactly as Notify.c's PryEvtAppendBpHit already does
    // for the identical hazard.
    if (irql < DISPATCH_LEVEL) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&PryBpLock, &oldIrql);
        tableScanned = TRUE;
        (VOID)PryBpTrapScanLocked((UINT32)bbits, pid, tid, &bpId, &slot, &access, &watchCookie);
        KeReleaseSpinLock(&PryBpLock, oldIrql);
    } else if (KeTryToAcquireSpinLockAtDpcLevel(&PryBpLock)) {
        tableScanned = TRUE;
        (VOID)PryBpTrapScanLocked((UINT32)bbits, pid, tid, &bpId, &slot, &access, &watchCookie);
        KeReleaseSpinLockFromDpcLevel(&PryBpLock);
    }

    if (!tableScanned) {
        // resolve the first set B-bit without the table
        for (i = 0; i < 4; i++) {
            if (bbits & (1u << i)) {
                slot = i;
                break;
            }
        }
    }

    if (!PryBpTrapOn) {
        // teardown window: hook still installed, subscription gone —
        // chaining armed bp hits here would bugcheck; consume silently.
        InterlockedIncrement(&PryBpTrapMissed);
        *RflagsSlot |= EFLAGS_RF;
        goto out_consumed;
    }
    if (tableScanned) {
        // definitive answer: no matching armed record -> not ours.
        if (!bpId) {
            goto out_foreign;
        }
    } else if (PryBpHwArmed <= 0) {
        // couldn't scan (>DISPATCH) and nothing armed — foreign hit.
        goto out_foreign;
    }

    PryEvtAppendBpHit(hitTsMs, pid, tid, Rip, dr6, bpId, slot, access,
                        (UINT32)irql, watchCookie);
    *RflagsSlot |= EFLAGS_RF; // skip the refire on exec bps

out_consumed:
    // DR6 B0-B3 are sticky. Clear the ones this hit reported so a later
    // #DB is not mistaken for a hit on a slot that has already fired.
    __writedr(6, dr6 & ~0xFull);
    if (cpu < PRY_TRAP_MAX_CPUS) {
        InterlockedExchange(&PryBpTrapCpuBusy[cpu], 0);
    }
    return 1;

out_foreign:
    // no armed record claims this hit. Chaining it to KiTrap01 is what
    // raises STATUS_SINGLE_STEP in the hitting process (or bugchecks in the
    // kernel), so for a process without a debugger the enable bits of the
    // fired slots are cleared on this thread -- we are running on it, so DR7
    // is written directly -- and the hit is consumed with RF set. A process
    // with a debug port keeps the chain: its debugger owns these DRs and must
    // see the hit.
    if (!PsGetProcessDebugPort(PsGetCurrentProcess())) {
        UINT64 dr7 = __readdr(7);
        UINT64 mask = 0;
        for (i = 0; i < 4; i++) {
            if (bbits & (1u << i)) {
                mask |= 1ull << (i * 2); // L0..L3
            }
        }
        __writedr(7, dr7 & ~mask);
        InterlockedIncrement(&PryBpTrapMissed);
        *RflagsSlot |= EFLAGS_RF;
        goto out_consumed;
    }
    if (cpu < PRY_TRAP_MAX_CPUS) {
        InterlockedExchange(&PryBpTrapCpuBusy[cpu], 0);
    }
    return 0;
}
