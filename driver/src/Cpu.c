#include "PryDriver.h"
#include <intrin.h>

// Cpu.c — PR#6 T3.2 (2026-10): MSR + CPUID reader.
//
// The driver pins the servicing thread to each requested logical processor
// via KeSetSystemGroupAffinityThread (ALL_PROCESSOR_GROUPS-aware, same
// pattern Idt.c and BpTrap.c use), then runs __readmsr / __cpuidex. The
// MSR instruction raises #GP on unimplemented MSRs — swallowed with
// __try/__except(EXCEPTION_EXECUTE_HANDLER) so the per-row NtStatus
// reports STATUS_UNSUCCESSFUL and the walk continues. CPUID never faults
// on a legal operand so the __try/__except is defensive only.
//
// Design notes:
//   * No input validation on the MSR number itself — a privileged caller
//     is free to probe any address; #GP catches the bad ones.
//   * CoreCount is clamped to PRY_CPU_MAX_CORES (also the output
//     capacity cap). AllCores expands against
//     KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS).
//   * Affinity is strictly restored on every per-core iteration via
//     KeRevertToUserGroupAffinityThread, including through __except.

static NTSTATUS PryCpuPinExec(_In_ UINT32 Core, _In_ VOID (*Fn)(PVOID Ctx),
                                _In_ PVOID Ctx)
{
    PROCESSOR_NUMBER pn;
    GROUP_AFFINITY ga, old;
    NTSTATUS st = KeGetProcessorNumberFromIndex(Core, &pn);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    RtlZeroMemory(&ga, sizeof(ga));
    ga.Group = pn.Group;
    ga.Mask = (KAFFINITY)1 << pn.Number;
    KeSetSystemGroupAffinityThread(&ga, &old);
    __try {
        Fn(Ctx);
    } __finally {
        KeRevertToUserGroupAffinityThread(&old);
    }
    return STATUS_SUCCESS;
}

typedef struct _PRY_MSR_CTX {
    UINT32 Msr;
    UINT64 Value;
    NTSTATUS Status;
} PRY_MSR_CTX;

static VOID PryMsrReadCore(PVOID Raw)
{
    PRY_MSR_CTX* c = (PRY_MSR_CTX*)Raw;
    __try {
        c->Value = __readmsr(c->Msr);
        c->Status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // #GP on unimplemented MSR — the whole point of per-row NtStatus.
        c->Value = 0;
        c->Status = STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS PryReadMsrOnCore(_In_ UINT32 Core, _In_ UINT32 Msr, _Out_ PUINT64 Value,
                            _Out_ PUINT32 NtStatus)
{
    PRY_MSR_CTX ctx;
    ctx.Msr = Msr;
    ctx.Value = 0;
    ctx.Status = STATUS_UNSUCCESSFUL;
    NTSTATUS pin = PryCpuPinExec(Core, PryMsrReadCore, &ctx);
    if (!NT_SUCCESS(pin)) {
        *Value = 0;
        *NtStatus = (UINT32)pin;
        return pin;
    }
    *Value = ctx.Value;
    *NtStatus = (UINT32)ctx.Status;
    return STATUS_SUCCESS;
}

typedef struct _PRY_CPUID_CTX {
    UINT32 Leaf;
    UINT32 Subleaf;
    int Regs[4];
} PRY_CPUID_CTX;

static VOID PryCpuidReadCore(PVOID Raw)
{
    PRY_CPUID_CTX* c = (PRY_CPUID_CTX*)Raw;
    __try {
        __cpuidex(c->Regs, (int)c->Leaf, (int)c->Subleaf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        c->Regs[0] = c->Regs[1] = c->Regs[2] = c->Regs[3] = 0;
    }
}

NTSTATUS PryCpuidOnCore(_In_ UINT32 Core, _In_ UINT32 Leaf, _In_ UINT32 Subleaf,
                          _Out_writes_(4) int OutRegs[4])
{
    PRY_CPUID_CTX ctx;
    ctx.Leaf = Leaf;
    ctx.Subleaf = Subleaf;
    ctx.Regs[0] = ctx.Regs[1] = ctx.Regs[2] = ctx.Regs[3] = 0;
    NTSTATUS pin = PryCpuPinExec(Core, PryCpuidReadCore, &ctx);
    if (!NT_SUCCESS(pin)) {
        OutRegs[0] = OutRegs[1] = OutRegs[2] = OutRegs[3] = 0;
        return pin;
    }
    OutRegs[0] = ctx.Regs[0];
    OutRegs[1] = ctx.Regs[1];
    OutRegs[2] = ctx.Regs[2];
    OutRegs[3] = ctx.Regs[3];
    return STATUS_SUCCESS;
}

static ULONG PryCpuMaxActive(VOID)
{
    ULONG n = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (!n) {
        n = 1;
    }
    if (n > PRY_CPU_MAX_CORES) {
        n = PRY_CPU_MAX_CORES;
    }
    return n;
}

static VOID PryExpandCores(_In_ const PRY_MSR_READ_IN* In,
                             _Out_writes_to_(PRY_CPU_MAX_CORES, *OutCount) UINT32* Out,
                             _Out_ PUINT32 OutCount)
{
    ULONG n = 0;
    if (In->AllCores) {
        ULONG max = PryCpuMaxActive();
        for (ULONG i = 0; i < max && n < PRY_CPU_MAX_CORES; i++) {
            Out[n++] = (UINT32)i;
        }
    } else {
        ULONG src = In->CoreCount;
        if (src > PRY_CPU_MAX_CORES) {
            src = PRY_CPU_MAX_CORES;
        }
        for (ULONG i = 0; i < src; i++) {
            Out[n++] = In->Cores[i];
        }
    }
    *OutCount = n;
}

static VOID PryExpandCoresCpuid(_In_ const PRY_CPUID_IN* In,
                                  _Out_writes_to_(PRY_CPU_MAX_CORES, *OutCount) UINT32* Out,
                                  _Out_ PUINT32 OutCount)
{
    // Same layout as the MSR expand — alias through a tiny shim so the
    // ABI structs stay distinct but the walker code is one path.
    PRY_MSR_READ_IN proxy;
    proxy.AllCores = In->AllCores;
    proxy.CoreCount = In->CoreCount;
    for (ULONG i = 0; i < PRY_CPU_MAX_CORES; i++) {
        proxy.Cores[i] = In->Cores[i];
    }
    PryExpandCores(&proxy, Out, OutCount);
}

NTSTATUS PryHandleMsrReadImpl(_In_ const PRY_MSR_READ_IN* In,
                                _Out_writes_(Capacity) PRY_MSR_VALUE* Out,
                                _In_ UINT32 Capacity, _Out_ PUINT32 Written,
                                _Out_ PUINT32 Required)
{
    UINT32 cores[PRY_CPU_MAX_CORES];
    UINT32 ncores = 0;
    UINT32 wrote = 0;

    PryExpandCores(In, cores, &ncores);
    *Required = ncores;

    for (UINT32 i = 0; i < ncores && wrote < Capacity; i++) {
        UINT64 v = 0;
        UINT32 nts = 0;
        (VOID)PryReadMsrOnCore(cores[i], In->Msr, &v, &nts);
        Out[wrote].Core = cores[i];
        Out[wrote].NtStatus = nts;
        Out[wrote].Value = v;
        wrote++;
    }

    *Written = wrote;
    if (!ncores) {
        return STATUS_INVALID_PARAMETER;
    }
    return (wrote < ncores) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

NTSTATUS PryHandleCpuidReadImpl(_In_ const PRY_CPUID_IN* In,
                                  _Out_writes_(Capacity) PRY_CPUID_VALUE* Out,
                                  _In_ UINT32 Capacity, _Out_ PUINT32 Written,
                                  _Out_ PUINT32 Required)
{
    UINT32 cores[PRY_CPU_MAX_CORES];
    UINT32 ncores = 0;
    UINT32 wrote = 0;

    PryExpandCoresCpuid(In, cores, &ncores);
    *Required = ncores;

    for (UINT32 i = 0; i < ncores && wrote < Capacity; i++) {
        int regs[4] = {0, 0, 0, 0};
        (VOID)PryCpuidOnCore(cores[i], In->Leaf, In->Subleaf, regs);
        Out[wrote].Core = cores[i];
        Out[wrote].Eax = (UINT32)regs[0];
        Out[wrote].Ebx = (UINT32)regs[1];
        Out[wrote].Ecx = (UINT32)regs[2];
        Out[wrote].Edx = (UINT32)regs[3];
        Out[wrote].Reserved = 0;
        wrote++;
    }

    *Written = wrote;
    if (!ncores) {
        return STATUS_INVALID_PARAMETER;
    }
    return (wrote < ncores) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

// --------------------------- WDF dispatch glue ---------------------------
// Returns bytes written to the output buffer. On input/output buffer
// failure, writes the NTSTATUS to *Status and returns 0.

SIZE_T PryHandleMsrRead(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_MSR_READ_IN in;
    PVOID inBuf, outBuf;
    SIZE_T inLen, outLen;
    NTSTATUS st;

    st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));

    st = PryOutput(Request, sizeof(PRY_MSR_READ_HDR), &outBuf, &outLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }

    PPRY_MSR_READ_HDR hdr = (PPRY_MSR_READ_HDR)outBuf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 capacity = (UINT32)((outLen - sizeof(*hdr)) / sizeof(PRY_MSR_VALUE));
    if (capacity > PRY_CPU_MAX_CORES) {
        capacity = PRY_CPU_MAX_CORES;
    }

    UINT32 count = 0, required = 0;
    hdr->Status = (UINT32)PryHandleMsrReadImpl(
        &in,
        (PPRY_MSR_VALUE)((PUCHAR)outBuf + sizeof(*hdr)),
        capacity, &count, &required);
    hdr->Count = count;
    hdr->Required = required;
    PryLog("MSRRD msr=%08x all=%u ncores=%u -> st=%x n=%u/%u",
             in.Msr, in.AllCores, in.CoreCount, hdr->Status, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_MSR_READ_HDR) + (SIZE_T)count * sizeof(PRY_MSR_VALUE);
}

SIZE_T PryHandleCpuidRead(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status)
{
    PRY_CPUID_IN in;
    PVOID inBuf, outBuf;
    SIZE_T inLen, outLen;
    NTSTATUS st;

    st = PryInput(Request, sizeof(in), &inBuf, &inLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }
    RtlCopyMemory(&in, inBuf, sizeof(in));

    st = PryOutput(Request, sizeof(PRY_CPUID_HDR), &outBuf, &outLen);
    if (!NT_SUCCESS(st)) {
        *Status = st;
        return 0;
    }

    PPRY_CPUID_HDR hdr = (PPRY_CPUID_HDR)outBuf;
    RtlZeroMemory(hdr, sizeof(*hdr));
    UINT32 capacity = (UINT32)((outLen - sizeof(*hdr)) / sizeof(PRY_CPUID_VALUE));
    if (capacity > PRY_CPU_MAX_CORES) {
        capacity = PRY_CPU_MAX_CORES;
    }

    UINT32 count = 0, required = 0;
    hdr->Status = (UINT32)PryHandleCpuidReadImpl(
        &in,
        (PPRY_CPUID_VALUE)((PUCHAR)outBuf + sizeof(*hdr)),
        capacity, &count, &required);
    hdr->Count = count;
    hdr->Required = required;
    PryLog("CPUID leaf=%08x sub=%08x all=%u -> st=%x n=%u/%u",
             in.Leaf, in.Subleaf, in.AllCores, hdr->Status, count, required);
    *Status = STATUS_SUCCESS;
    return sizeof(PRY_CPUID_HDR) + (SIZE_T)count * sizeof(PRY_CPUID_VALUE);
}
