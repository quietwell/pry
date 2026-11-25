#ifndef PRY_DRIVER_H
#define PRY_DRIVER_H

#include <ntifs.h> // full KAPC_STATE layout (48 bytes on x64); must precede ntddk/wdm
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include "../../comm/pry_abi.h"

// these structs are defined once in comm/pry_abi.h
// and compiled independently by two different toolchains/configs (this
// WDK kernel build vs. the usermode comm/agent build) -- comm/pry_comm.cpp
// already C_ASSERTs a handful of them, but not these, so a layout drift
// (a struct edit landing on only one side's expected literal, or the two
// builds quietly disagreeing on padding) would only break comm's build,
// never the driver's. Mirror the sizes here too.
C_ASSERT(sizeof(PRY_EVT) == 344);
C_ASSERT(sizeof(PRY_STACKWALK_IN) == 32);
C_ASSERT(sizeof(PRY_STACKWALK_FRAME) == 24);
C_ASSERT(sizeof(PRY_STACKWALK_HDR) == 40);
C_ASSERT(sizeof(PRY_SELFPROT_CONFIG_IN) == 160);
C_ASSERT(sizeof(PRY_SELFPROT_CONFIG_OUT) == 32);
C_ASSERT(sizeof(PRY_SELFPROT_STATUS_OUT) == 64);
C_ASSERT(sizeof(PRY_HANDLE_ENTRY) == 272);
C_ASSERT(sizeof(PRY_HANDLE_DUP_IN) == 40);
C_ASSERT(sizeof(PRY_HANDLE_DUP_OUT) == 80);
C_ASSERT(sizeof(PRY_HANDLE_CLOSE_IN) == 32);
C_ASSERT(sizeof(PRY_HANDLE_CLOSE_OUT) == 8);
C_ASSERT(sizeof(PRY_HANDLE_CMP_IN) == 48);
C_ASSERT(sizeof(PRY_HANDLE_CMP_OUT) == 32);
C_ASSERT(sizeof(PRY_MSR_READ_IN) == 272);
C_ASSERT(sizeof(PRY_MSR_VALUE) == 16);
C_ASSERT(sizeof(PRY_MSR_READ_HDR) == 16);

typedef struct _PRY_CI_INFO {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} PRY_CI_INFO;

// exported but undocumented / no-longer-declared NT APIs used intentionally (lab tooling)
// NOTE: `extern ULONG NtBuildNumber` without dllimport reads garbage on this
// toolchain — the OS build is captured once via RtlGetVersion into PryNtBuild
extern ULONG PryNtBuild;
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(_In_ PEPROCESS SourceProcess, _In_ PVOID SourceAddress,
                                         _In_ PEPROCESS TargetProcess, _Out_ PVOID TargetAddress,
                                         _In_ SIZE_T BufferSize, _In_ KPROCESSOR_MODE PreviousMode,
                                         _Out_ PSIZE_T ReturnSize);
NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process); // PEB32 on WoW64, NULL otherwise
// PsGetProcessVadRoot is exported by ntoskrnl but missing from the WDK import
// lib; Vad.c resolves it via MmGetSystemRoutineAddress at runtime.
NTKERNELAPI struct _OBJECT_TYPE* ObGetObjectType(_In_ PVOID Object);
NTKERNELAPI BOOLEAN KeAlertThread(_In_ PVOID Thread, _In_ KPROCESSOR_MODE AlertMode);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS* Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Out_ PETHREAD* Thread);
NTKERNELAPI NTSTATUS PsGetContextThread(_In_ PETHREAD Thread, _Inout_ PVOID ThreadContext, _In_ KPROCESSOR_MODE PreviousMode);
NTKERNELAPI NTSTATUS PsSetContextThread(_In_ PETHREAD Thread, _In_ PVOID ThreadContext, _In_ KPROCESSOR_MODE PreviousMode);
NTKERNELAPI PVOID PsGetProcessDebugPort(_In_ PEPROCESS Process);
NTKERNELAPI BOOLEAN PsIsThreadTerminating(_In_ PETHREAD Thread);
NTKERNELAPI ULONG PsGetThreadFreezeCount(_In_ PETHREAD Thread);
// undocumented but exported since NT 5.x, used by NtSuspendThread.
// Required to make Ps{Get,Set}ContextThread deliver synchronously against the
// target's trap frame � otherwise the pending set APC hasn't executed yet
// when our immediate readback runs, and the verify sees stale zeros in the
// DR area on a thread that was never previously DR-active.
NTKERNELAPI NTSTATUS ZwAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits,
                                             _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect);
NTKERNELAPI NTSTATUS ZwFreeVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG FreeType);
NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize,
                                            _In_ ULONG NewProtect, _Out_ PULONG OldProtect);
NTKERNELAPI NTSTATUS ZwQuerySystemInformation(_In_ ULONG SystemInformationClass,
                                              _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
                                              _In_ ULONG SystemInformationLength,
                                              _Out_opt_ PULONG ReturnLength);
NTKERNELAPI VOID KeStackAttachProcess(_In_ PRKPROCESS Process, _Out_ PVOID ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(_In_ PVOID ApcState);

// KAPC_STATE comes from ntifs.h (48 bytes on x64). The previous hand-rolled
// 32-byte PRY_KAPC_STATE was 16 bytes short: KeStackAttachProcess writes
// the full struct, silently corrupting the caller's stack.

typedef enum _PRY_KAPC_ENVIRONMENT {
    PryOriginalApcEnvironment = 0,
    PryAttachedApcEnvironment = 1,
    PryCurrentApcEnvironment = 2,
    PryInsertApcEnvironment = 3
} PRY_KAPC_ENVIRONMENT;

// SYSTEM_PROCESS_INFORMATION / SYSTEM_THREAD_INFORMATION (public x64 ABI,
// as consumed by ZwQuerySystemInformation(SystemProcessInformation))
#define PRY_SYS_PROC_INFO_CLASS 5

#pragma pack(push, 8)
typedef struct _PRY_SYS_THREAD_INFO {
    LARGE_INTEGER KernelTime;  // 0
    LARGE_INTEGER UserTime;    // 8
    LARGE_INTEGER CreateTime;  // 16
    ULONG WaitTime;            // 24
    ULONG Reserved0;           // 28
    PVOID StartAddress;        // 32
    PVOID UniqueProcess;       // 40 (CLIENT_ID.UniqueProcess)
    PVOID UniqueThread;        // 48 (CLIENT_ID.UniqueThread)
    KPRIORITY Priority;        // 56
    LONG BasePriority;         // 60
    ULONG ContextSwitches;     // 64
    ULONG ThreadState;         // 68
    ULONG WaitReason;          // 72
    ULONG Reserved1;           // 76
} PRY_SYS_THREAD_INFO;

typedef struct _PRY_SYS_PROC_INFO {
    ULONG NextEntryOffset;                   // 0
    ULONG NumberOfThreads;                   // 4
    LARGE_INTEGER WorkingSetPrivateSize;     // 8
    ULONG HardFaultCount;                    // 16
    ULONG NumberOfThreadsHighWatermark;      // 20
    ULONGLONG CycleTime;                     // 24
    LARGE_INTEGER CreateTime;                // 32
    LARGE_INTEGER UserTime;                  // 40
    LARGE_INTEGER KernelTime;                // 48
    UNICODE_STRING ImageName;                // 56
    KPRIORITY BasePriority;                  // 72
    HANDLE UniqueProcessId;                  // 80
    HANDLE InheritedFromProcessId;           // 88
    ULONG HandleCount;                       // 96
    ULONG SessionId;                         // 100
    ULONG_PTR UniqueProcessKey;              // 104
    SIZE_T PeakVirtualSize;                  // 112
    SIZE_T VirtualSize;                      // 120
    ULONG PageFaultCount;                    // 128
    SIZE_T PeakWorkingSetSize;               // 136
    SIZE_T WorkingSetSize;                   // 144
    SIZE_T QuotaPeakPagedPoolUsage;          // 152
    SIZE_T QuotaPagedPoolUsage;              // 160
    SIZE_T QuotaPeakNonPagedPoolUsage;       // 168
    SIZE_T QuotaNonPagedPoolUsage;           // 176
    SIZE_T PagefileUsage;                    // 184
    SIZE_T PeakPagefileUsage;                // 192
    SIZE_T PrivatePageCount;                 // 200
    LARGE_INTEGER ReadOperationCount;        // 208
    LARGE_INTEGER WriteOperationCount;       // 216
    LARGE_INTEGER OtherOperationCount;       // 224
    LARGE_INTEGER ReadTransferCount;         // 232
    LARGE_INTEGER WriteTransferCount;        // 240
    LARGE_INTEGER OtherTransferCount;        // 248
} PRY_SYS_PROC_INFO;
#pragma pack(pop)

C_ASSERT(sizeof(PRY_SYS_THREAD_INFO) == 80);
C_ASSERT(FIELD_OFFSET(PRY_SYS_PROC_INFO, UniqueProcessId) == 80);
C_ASSERT(sizeof(PRY_SYS_PROC_INFO) == 256);

#define PRY_POOL_TAG 'DyrP' // "PryD" in pool dump order
#define PRY_DEVICE_NAME L"\\Device\\PryDrv"
#define PRY_SYMLINK_NAME L"\\??\\PryDrv"
#define PRY_KERNEL_LOG_PATH L"\\??\\C:\\Users\\Public\\Desktop\\pry_kernel.log"

// DriverEntry.c
NTSTATUS PryLogInit(VOID);
VOID PryLogCleanup(VOID);
VOID PryLog(_In_ PCSTR Format, ...);
ULONG PrySystemFlags(VOID);

// Device.c
NTSTATUS PryCreateControlDevice(_In_ WDFDRIVER Driver);
VOID PryEvtDriverUnload(_In_ WDFDRIVER Driver);
// v13: control device handle — work-item parent for KernelCall.c.
extern WDFDEVICE PryDevice;

// Dispatcher.c
VOID PryEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                             _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength,
                             _In_ ULONG IoControlCode);

// dispatch_io.c — request buffer helpers shared across dispatch TUs
NTSTATUS PryInput(_In_ WDFREQUEST Request, _In_ SIZE_T Min, _Out_ PVOID* Buf, _Out_ SIZE_T* Len);
NTSTATUS PryOutput(_In_ WDFREQUEST Request, _In_ SIZE_T Min, _Out_ PVOID* Buf, _Out_ SIZE_T* Len);
NTSTATUS PryOutMdl(_In_ WDFREQUEST Request, _Out_ PVOID* Sys, _Out_ SIZE_T* Len);
NTSTATUS PryInMdl(_In_ WDFREQUEST Request, _Out_ PVOID* Sys, _Out_ SIZE_T* Len);

// dispatch_mem.c — combined in/out fetch used across dispatch TUs
NTSTATUS PryInOut(_In_ WDFREQUEST Request, _In_ SIZE_T InSize, _In_ SIZE_T OutSize,
                    _Out_ PVOID* In, _Out_ PVOID* Out);

// ---- User memory ops (MemoryUser.c) ----
NTSTATUS PryUserMemRead(_In_ UINT64 Pid, _In_ UINT64 Address, _Out_ PVOID Dst,
                          _In_ SIZE_T Size, _Out_ PSIZE_T Done);
NTSTATUS PryUserMemWrite(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ PVOID Src,
                           _In_ SIZE_T Size, _Out_ PSIZE_T Done);
NTSTATUS PryUserAlloc(_In_ UINT64 Pid, _In_ UINT64 Size, _In_ ULONG Protect, _Out_ UINT64* Address);
NTSTATUS PryUserFree(_In_ UINT64 Pid, _In_ UINT64 Address);
NTSTATUS PryUserProtect(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT64 Size,
                          _In_ ULONG Protect, _Out_ ULONG* OldProtect);

// ---- Kernel memory ops (MemoryKernel.c) ----
NTSTATUS PryKernelMemRead(_In_ UINT64 Address, _Out_ PVOID Dst, _In_ SIZE_T Size,
                            _Out_ PSIZE_T Done, _In_ UINT32 Flags);
// v12: Flags2 = PRY_MEM_WRF_* (STRICT_VA refuses the phys-remap fallback);
// Cr3 != 0 swaps the thread into that address space for the copy (foreign
// write — see PryKernelMemWriteCr3); WritePath reports the PRY_MEM_WRITE_PATH_*
// the store took.
NTSTATUS PryKernelMemWrite(_In_ UINT64 Address, _In_ PVOID Src, _In_ SIZE_T Size,
                             _Out_ PSIZE_T Done, _In_ UINT32 Flags2, _In_ UINT64 Cr3,
                             _Out_ PUINT8 WritePath);

// ---- Kmem tracking (KmemTrack.c) ----
VOID PryKmemInit(VOID);
NTSTATUS PryKmemAlloc(_In_ UINT64 Size, _Out_ UINT64* Address);
NTSTATUS PryKmemFree(_In_ UINT64 Address);
ULONG PryKmemLeakCount(VOID);
// unload-time teardown — frees every still-tracked
// KMEM_ALLOC block plus its bookkeeping record (previously only counted
// and logged, never freed) and refuses any further KMEM_ALLOC. Returns
// the number of blocks freed.
ULONG PryKmemFreeAll(VOID);

// Physical.c
BOOLEAN PryPhysRead64(_In_ UINT64 Pa, _Out_ UINT64* Value);
NTSTATUS PryPhysRangesInit(VOID);
// vNEXT (T3.1 PR#5): AllowOutOfRam gates reads whose range is not entirely
// inside MmGetPhysicalMemoryRanges — default (FALSE) refuses with
// STATUS_ACCESS_DENIED before touching MmCopyMemory / MmMapIoSpaceEx so
// one wayward MMIO BAR read can no longer wedge the box. TRUE restores
// the pre-guard behaviour for operators who have accepted the wedge risk.
NTSTATUS PryPhysMemRead(_In_ UINT64 PhysicalAddress, _Out_ PVOID Dst, _In_ SIZE_T Size,
                          _In_ BOOLEAN AllowOutOfRam, _Out_ PSIZE_T Done);
NTSTATUS PryPhysMemWrite(_In_ UINT64 PhysicalAddress, _In_ PVOID Src, _In_ SIZE_T Size,
                           _Out_ PSIZE_T Done, _In_ BOOLEAN AllowMapWrite);
BOOLEAN PryTranslateVa(_In_ UINT64 Va, _Out_ UINT64* PhysicalAddress);
// v12: walk under an explicit Cr3 (0 = resolve from context: Pid's process
// via KeStackAttachProcess for user VAs, system tables for kernel VAs).
// PageSizeShift = 12/21/30 for the leaf that mapped VA; UsedCr3 = the CR3
// the walk ran under.
BOOLEAN PryTranslateVaEx(_In_ UINT64 Va, _In_ UINT64 Cr3, _In_ UINT64 Pid,
                           _Out_ UINT64* PhysicalAddress,
                           _Out_opt_ UINT32* PageSizeShift,
                           _Out_opt_ UINT64* UsedCr3);
// v12: same walk but exposes the leaf descriptor itself so callers can
// inspect RW/NX/etc. (foreign-CR3 write pre-verifies dst pages writable).
BOOLEAN PryWalkVaEx(_In_ UINT64 Va, _In_ UINT64 Cr3,
                      _Out_ UINT64* PhysicalAddress, _Out_ UINT64* LeafEntry,
                      _Out_ UINT32* PageSizeShift);
NTSTATUS PryPhysWriteKernelVa(_In_ UINT64 Va, _In_ PVOID Src, _In_ SIZE_T Size);
NTSTATUS PryPhysRangesEnumerate(_Out_writes_to_(Capacity, *Written) PRY_PHYS_RANGE_ENTRY* Out,
                                  _In_ ULONG Capacity, _Out_ PULONG Written, _Out_ PULONG Total);

// Pool.c
NTSTATUS PryPoolScan(_In_ const PRY_POOL_SCAN_IN* In,
                       _Out_writes_to_(Capacity, *Written) PRY_POOL_ENTRY* Out,
                       _In_ ULONG Capacity, _Out_ PULONG Written, _Out_ PULONG Required,
                       _Out_ PULONG Considered,
                       _Out_opt_ PULONG Holes,
                       _Out_opt_ PULONG SpanTruncated,
                       _Out_opt_ PULONG LastIndex,
                       _Out_opt_ PULONG NextCursor);

// Context.c
NTSTATUS PryCtxGet(_In_ UINT64 Tid, _In_ ULONG Flags, _Out_ PVOID Context);
NTSTATUS PryCtxSet(_In_ UINT64 Tid, _In_ ULONG Flags, _In_ PVOID Context);
NTSTATUS PryProcessThreadApply(_In_ UINT64 Pid, _In_ UINT64 Tid,
                                 _In_ NTSTATUS (*Fn)(_In_ PETHREAD Thread, _Inout_ PVOID Ctx),
                                 _Inout_ PVOID Ctx, _Out_ PUINT32 Applied);

// Breakpoints — shared table record (defined in BpList.c, used by BpSw.c/BpHw.c)
typedef struct _PRY_BP_REC {
    UINT32 Id;
    UINT32 Kind;
    UINT32 Pid;   // HW: 0 (with Global=1) = system-wide
    UINT32 Tid;   // HW: 0 = all threads of Pid (incl. threads created later)
    UINT32 Slot;
    UINT32 Length;
    UINT32 Access;
    UINT32 Used;    // table slot occupied (Enabled may be 0 while winding down)
    UINT32 Enabled;
    UINT32 Global;  // v6: 1 = system-wide (Pid==0). Kept in-band so the
                    // thread-create notify can arm regardless of parent pid.
    UINT32 IsWatch; // v14 (SI #25): 1 when this entry backs a mem_rw watch —
                    // trap dispatch mirrors WatchCookie into the ringed EVT.
    UINT32 WatchCookie; // v14 (SI #25): BpId mirror; 0 for non-watch entries.
    UINT64 Address;
    UCHAR OrigByte;
    // HW set in progress -- table-visible so int1 hits are claimed
    // from the first armed thread, but not a clear/preempt target yet.
    UINT32 Arming;
    // HW clear/preempt in progress -- still claims hits until every
    // DR clear for it has run; excluded from clear/preempt/newborn arming.
    UINT32 Retiring;
    // EPROCESS a non-global HW record is pinned to (0 = unpinned).
    UINT64 ProcKey;
} PRY_BP_REC, *PPRY_BP_REC;

extern PRY_BP_REC PryBpTable[PRY_MAX_BP];
extern KSPIN_LOCK PryBpLock;
extern UINT32 PryBpNextId;

// BpList.c
VOID PryBpInit(VOID);
NTSTATUS PryBpList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                     _Out_ PUINT32 Count, _Out_ PUINT32 Required);
VOID PryBpCleanup(VOID);

// BpSw.c
PPRY_BP_REC PryBpAllocLocked(_Out_ PUINT32 Id);
VOID PryBpFreeLocked(_In_ PPRY_BP_REC Rec);
NTSTATUS PryBpSwSet(_In_ UINT64 Pid, _In_ UINT64 Address, _Out_ PUINT32 Id, _Out_ PUCHAR OrigByte);
NTSTATUS PryBpSwClear(_In_ UINT64 Pid, _In_ UINT64 Address, _In_ UINT32 Id);

// BpHw.c
VOID PryBpHwInit(VOID);
NTSTATUS PryBpHwSet(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Address, _In_ UINT32 Slot,
                      _In_ UINT32 Length, _In_ UINT32 Access, _In_ UINT32 Flags,
                      _Out_ PUINT32 Id, _Out_ PUINT32 Applied);
NTSTATUS PryBpHwClear(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT32 Slot, _Out_ PUINT32 Applied);
// clear DR0-3/DR7 + the per-thread gate for a record
// snapshotted BEFORE its table slot was freed (PryBpCleanup at unload;
// a preempted auto-slot watch in PryBpHwSet) -- PryBpHwClear's own
// table lookup can never find a record that is already gone.
NTSTATUS PryBpHwClearDr(_In_ const PRY_BP_REC* Rec, _Out_ PUINT32 Applied);
// clear EPROCESS.Pcb.DebugActive on every process in
// the system. The per-pid clear inside PryBpHwClear can't do this for a
// Global (Pid==0) bp -- PryDrGateEnable touched every process that had
// a thread while it was armed, and that set is never tracked. Safe to
// call any time (clearing an already-clear gate is a no-op); used after
// a global HW clear and from PryBpCleanup at unload.
VOID PryBpHwClearAllGates(VOID);
// process-exit reaping of breakpoint records. Init registers the
// Ex process-notify routine; Shutdown removes it and must run before
// PryBpCleanup at unload.
NTSTATUS PryBpProcNotifyInit(VOID);
VOID     PryBpProcNotifyShutdown(VOID);

// thread-create notification so all-thread HW breakpoints reach new threads
VOID PryOnThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
VOID PryOnThreadNotifyClassic(_In_ PEPROCESS Process, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
extern volatile LONG PryThreadNotifyActive;    // in-flight callback count for unload ordering
extern volatile LONG PryBpThreadNotifyRegistered; // 1 = Ex variant, 2 = classic variant

// RemoteCall.c
NTSTATUS PryRemoteCall(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Target,
                         _In_ UINT64 Arg1, _In_ UINT64 Arg2, _In_ UINT64 Arg3,
                         _In_ UINT32 Flags, _Out_ PUINT32 Queued, _Out_ PUINT32 Alerted);
extern volatile LONG PryApcOutstanding; // queued-but-undelivered APC count
// PryRemoteCallEx is PryRemoteCall plus a completion hook. Done is
// called exactly once per call: after a kernel-mode target has run, when the
// APC is retired unrun (thread rundown), or before returning when nothing was
// queued. Kernel-mode calls only.
typedef VOID (*PRY_RC_DONE_FN)(_In_ PVOID DoneCtx);
NTSTATUS PryRemoteCallEx(_In_ UINT64 Pid, _In_ UINT64 Tid, _In_ UINT64 Target,
                           _In_ UINT64 Arg1, _In_ UINT64 Arg2, _In_ UINT64 Arg3,
                           _In_ UINT32 Flags, _In_opt_ PRY_RC_DONE_FN Done,
                           _In_opt_ PVOID DoneCtx, _Out_ PUINT32 Queued, _Out_ PUINT32 Alerted);

// KernelCall.c — v13 synchronous kernel function call. Defined here with the
// other dispatch entrypoints (dispatch_internal.h); PryKcallShutdown is
// called from EvtDriverUnload before the image pages go away.
SIZE_T PryHandleKernelCall(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
VOID   PryKcallShutdown(VOID);

// Watchdog.c — v8 wedge-detector. See pry_abi.h and Watchdog.c header
// comment for the contract.
NTSTATUS PryWatchdogInit(VOID);
VOID     PryWatchdogShutdown(VOID);
NTSTATUS PryWatchdogArm(_In_ UINT32 Id, _In_ UINT32 DeadlineMs,
                          _In_ UINT32 BugcheckCode, _In_ UINT32 Flags,
                          _In_ UINT64 Cookie, _In_ const CHAR* Label);
NTSTATUS PryWatchdogKick(_In_ UINT32 Id, _In_ UINT32 DeadlineMs,
                           _In_ UINT64 Cookie,
                           _Out_ UINT64* KickCount, _Out_ UINT64* LastKickUs,
                           _Out_ UINT64* DeadlineUs);
NTSTATUS PryWatchdogDisarm(_In_ UINT32 Id);
NTSTATUS PryWatchdogList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                           _In_ SIZE_T CapacityBytes,
                           _Out_ PUINT32 Count, _Out_ PUINT32 Required,
                           _Out_ PUINT64 NowUs);

// Notify.c — v10 notify event ring (the agent's "ears"). See pry_abi.h
// "Notify ring" section for the contract. Registration is kernel-visible
// state; the orchestrator gates SUBSCRIBE like driver_load.
VOID     PryNotifyInit(VOID);
NTSTATUS PryNotifySubscribe(_In_ UINT32 Classes, _In_ UINT32 Flags,
                              _Out_ UINT32* Registered);
// now refuses (STATUS_DEVICE_BUSY, nothing torn down)
// while any HW breakpoint is still armed (PryBpHwArmed > 0) -- pulling
// the int1 hook out from under a live DR0-3 armed breakpoint turns its
// next #DB into an unhandled trap. PryBpCleanup clears every HW bp
// (and drains the APCs that does) before unload reaches this call, so it
// never blocks teardown.
NTSTATUS PryNotifyDisable(VOID);
// v11: BP_HIT append from the int1 trap path — callable at any IRQL;
// drops (and counts) when the ring lock cannot be taken above PASSIVE.
// v14 (SI #25): grew a trailing WatchCookie arg — 0 for non-watch hits,
// mirrors PRY_BP_REC.WatchCookie for IS_WATCH entries so the agent
// can demux back to the orchestrator subscription.
VOID     PryEvtAppendBpHit(_In_ UINT64 HitTsMs, _In_ UINT32 Pid, _In_ UINT32 Tid,
                             _In_ UINT64 Rip, _In_ UINT64 Dr6, _In_ UINT32 BpId, _In_ UINT32 Slot,
                             _In_ UINT32 Access, _In_ UINT32 Irql,
                             _In_ UINT32 WatchCookie);
NTSTATUS PryNotifyRead(_In_ UINT32 Max, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                         _Out_ PUINT64 Dropped, _Out_ PUINT64 LastSeq);
NTSTATUS PryNotifyStats(_Out_ PRY_NOTIFY_STATS_OUT* Out);

// BpTrap.c + BpTrapAsm.asm — v11 kernel HW-BP hit observability. The
// install path redirects every CPU's IDT[1] to PryBpTrapStub by lidt'ing
// a writable per-CPU COPY of its IDT (originals saved for restore); the
// stub calls PryBpTrapDispatch which consumes #DBs matching an armed HW
// bp (record + RF + resume) and chains everything else to the saved
// KiTrap01. PatchGuard-sensitive — gated by PRY_NOTIFY_FLAG_BP_HOOK_OK
// plus a no-op lidt probe that fails NOT_SUPPORTED when a hypervisor
// intercepts descriptor-table ops (IDT is EPT-RO there anyway).
NTSTATUS PryBpTrapInstall(VOID);
VOID     PryBpTrapUninstall(VOID);
BOOLEAN  PryBpTrapInstalled(VOID);
extern   volatile LONG PryBpTrapOn;        // 1 while the hook owns int1
extern   volatile LONG PryBpTrapMissed;    // hits consumed unrecorded
extern   volatile LONG PryBpHwArmed;       // armed HW-bp table count (BpHw.c)
extern UINT64 PryBpTrapChainTarget;        // asm reads: original KiTrap01

// ObjDir.c — v10 object-directory enumeration (ZwOpen/QueryDirectoryObject)
NTSTATUS PryObjEnum(_In_ PCWSTR Path, _In_ UINT32 Depth, _In_ UINT32 MaxEntries,
                      _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                      _Out_ PUINT32 Required, _Out_ PUINT32 Truncated);

// Threads.c — v10 kernel-side enriched thread list
NTSTATUS PryThreadList(_In_ UINT32 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                         _Out_ PUINT32 Required);

// Idt.c — v12 per-CPU IDT dump (__sidt + KIDTENTRY64 decode). Fills
// PRY_IDT_ENTRY_ROWs; FirstBase/FirstLimit get the first CPU's IDTR.
NTSTATUS PryIdtList(_In_ UINT32 AllCpus,
                      _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count,
                      _Out_ PUINT32 Required, _Out_ PUINT64 FirstBase,
                      _Out_ PUINT32 FirstLimit);

// Modules.c
NTSTATUS PryKernelModules(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                            _Out_ PUINT32 Count, _Out_ PUINT32 Required);
NTSTATUS PryUserModules(_In_ UINT64 Pid, _In_ BOOLEAN Wow64,
                          _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                          _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required);

// Vad.c
NTSTATUS PryVadList(_In_ UINT64 Pid, _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                      _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required);

// Handles.c
NTSTATUS PryHandleList(_In_ UINT64 Pid, _In_ BOOLEAN WantNames,
                         _Out_writes_bytes_(CapacityBytes) PVOID Buffer,
                         _In_ SIZE_T CapacityBytes, _Out_ PUINT32 Count, _Out_ PUINT32 Required);
// SI #6 handle ops. Documented Ob*/Zw* under KernelMode PreviousMode;
// no dyn-data dependency. See an internal plan
// 01-driver-primitives.md Feature 2 for the kernel pattern.
NTSTATUS PryHandleDup(_In_ const PRY_HANDLE_DUP_IN* In,
                        _Out_ PPRY_HANDLE_DUP_OUT Out);
NTSTATUS PryHandleCloseRemote(_In_ const PRY_HANDLE_CLOSE_IN* In,
                                _Out_ PPRY_HANDLE_CLOSE_OUT Out);
NTSTATUS PryHandleCompare(_In_ const PRY_HANDLE_CMP_IN* In,
                            _Out_ PPRY_HANDLE_CMP_OUT Out);

// StackWalk.c — SI #9 kernel-stack walk. APC-delivered walk via
// PryRemoteCall + RC_FLAG_KERNEL + RtlWalkFrameChain; default timeout
// 500 ms.
NTSTATUS PryThreadStackWalk(_In_ const PRY_STACKWALK_IN* In,
                              _Out_ PPRY_STACKWALK_HDR Hdr,
                              _Out_writes_bytes_(FramesBytes) PVOID FramesBuf,
                              _In_ SIZE_T FramesBytes);

// WaitInfo.c — SI #3 analyze-wait on thread. Walks ETHREAD/KTHREAD
// under PsLookupThreadByThreadId's reference, pulls last_syscall / wait /
// kernel-stack scalars, optionally copies the saved arg frame and user
// stack trailers via MmCopyVirtualMemory. The field reads sit behind the
// Wave 3 dyn-data probe (PryDyn.Valid) — until that lands the handler
// surfaces STATUS_NOT_SUPPORTED without touching any ETHREAD offset so
// the handler is Verifier-clean against every live ntoskrnl build.
NTSTATUS PryThreadWaitInfo(_In_ UINT64 Tid,
                             _In_ const PRY_WAIT_INFO_IN* In,
                             _Out_writes_bytes_(CapacityBytes) PVOID Buf,
                             _In_ SIZE_T CapacityBytes,
                             _Out_ PUINT32 BytesWritten);

// IrpList.c — slice 03 Feature 4: KTHREAD.IrpList walker. Walks
// the per-thread IRP list under PsLookupThreadByThreadId's reference +
// IoCancelSpinLock; row fields ride the Wave 3 dyn-data probe
// (PryDyn.Valid). Until that lands, surfaces STATUS_NOT_SUPPORTED in
// the response header after the Ob round trip — Verifier Object
// Reference Tracking stays clean (same contract as WaitInfo above).
NTSTATUS PryThreadIrpList(_In_ UINT64 Tid,
                            _In_ const PRY_IRP_LIST_IN* In,
                            _Out_writes_bytes_(CapacityBytes) PVOID Buf,
                            _In_ SIZE_T CapacityBytes,
                            _Out_ PUINT32 BytesWritten);

// Processes.c
NTSTATUS PryProcessList(_Out_writes_bytes_(CapacityBytes) PVOID Buffer, _In_ SIZE_T CapacityBytes,
                          _Out_ PUINT32 Count, _Out_ PUINT32 Required);

// SelfProt.c — SI adoption feature #21. ObRegisterCallbacks pre-op that
// strips rights from handles opened against protected PIDs. Init registers
// the (initially empty) PID table + locks; Shutdown drains in-flight
// callbacks and unregisters. Config/Status drive the active state.
VOID     PrySelfProtInit(VOID);
VOID     PrySelfProtShutdown(VOID);
NTSTATUS PrySelfProtApply(_In_ const PRY_SELFPROT_CONFIG_IN* In,
                            _Out_ PRY_SELFPROT_CONFIG_OUT* Out);
VOID     PrySelfProtQuery(_Out_ PRY_SELFPROT_STATUS_OUT* Out);
// Dispatcher reentry guard: Dispatcher.c sets this around the IOCTL switch
// so pre-ops skip the strip while our own code opens handles.
VOID     PrySelfProtEnterCall(VOID);
VOID     PrySelfProtLeaveCall(VOID);

// MmUserProbeAddress (ntddk.h) is the documented
// ProbeFor{Read,Write} boundary: any address at or above it is kernel
// space. A __try/__except around a user-space read/write is NOT a safety
// net for a kernel address slipped in as "the user address" -- a valid,
// resident kernel page is read or written with no exception at all
// (silent corruption on a write), and a write that lands on a resident
// READ-ONLY kernel page bugchecks OUTSIDE any __except
// (PAGE_FAULT_IN_NONPAGED_AREA; see MemoryKernel.c's PryKernelMemWrite
// comment). Checked for wraparound: a huge Size must not let
// Address+Size overflow back under the boundary and slip past the check.
__forceinline BOOLEAN PryUserRangeOk(_In_ UINT64 Address, _In_ UINT64 Size)
{
    UINT64 end = Address + Size;
    if (end < Address) {
        return FALSE; // wraparound
    }
    return Address < MmUserProbeAddress && end <= MmUserProbeAddress;
}

__forceinline PVOID PryAlloc(_In_ SIZE_T Size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, PRY_POOL_TAG);
}

__forceinline VOID PryFree(_In_ PVOID P)
{
    if (P) {
        ExFreePoolWithTag(P, PRY_POOL_TAG);
    }
}

#endif // PRY_DRIVER_H

