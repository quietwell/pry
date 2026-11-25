/*
 * comm/abi/proc.h — Process/thread/module/handle/object/IDT/MSR/CPUID
 * enumeration structures and IOCTLs. Function codes 0x850-0x854,
 * 0x8A4-0x8A6, 0x8C0-0x8C1.
 *
 * Part of the pry wire ABI; see comm/pry_abi.h.
 * Fixed-layout, no pointers, no C++. Any change here is a breaking ABI
 * change: bump PRY_ABI_VERSION and the driver epoch.
 */

#ifndef PRY_ABI_PROC_H
#define PRY_ABI_PROC_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PRY_FUNC_USER_MODULES 0x850
#define PRY_FUNC_KERNEL_MODULES 0x851
#define PRY_FUNC_PROCESS_LIST 0x852
#define PRY_FUNC_VAD_LIST 0x853
#define PRY_FUNC_HANDLE_LIST 0x854
#define PRY_FUNC_OBJ_ENUM         0x8A4
#define PRY_FUNC_THREAD_LIST      0x8A5
// v12: per-CPU IDT enumeration (driver decodes KIDTENTRY64 rows)
#define PRY_FUNC_IDT_LIST         0x8A6
// PR#6 T3.2 (2026-10): MSR / CPUID reader. Per-core affinity-pin walk
// (__readmsr / __cpuidex) with __try/__except on #GP.
#define PRY_FUNC_MSR_READ         0x8C0
#define PRY_FUNC_CPUID_READ       0x8C1

#define PRY_IOCTL_USER_MODULES PRY_IOCTL(PRY_FUNC_USER_MODULES, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_KERNEL_MODULES PRY_IOCTL(PRY_FUNC_KERNEL_MODULES, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_PROCESS_LIST PRY_IOCTL(PRY_FUNC_PROCESS_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_VAD_LIST PRY_IOCTL(PRY_FUNC_VAD_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_HANDLE_LIST PRY_IOCTL(PRY_FUNC_HANDLE_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_OBJ_ENUM         PRY_IOCTL(PRY_FUNC_OBJ_ENUM,         METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define PRY_IOCTL_THREAD_LIST      PRY_IOCTL(PRY_FUNC_THREAD_LIST,      METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define PRY_IOCTL_IDT_LIST         PRY_IOCTL(PRY_FUNC_IDT_LIST,         METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
// PR#6 T3.2: fixed-size per-core result arrays, METHOD_BUFFERED is enough.
#define PRY_IOCTL_MSR_READ         PRY_IOCTL(PRY_FUNC_MSR_READ,         METHOD_BUFFERED,  FILE_ANY_ACCESS)
#define PRY_IOCTL_CPUID_READ       PRY_IOCTL(PRY_FUNC_CPUID_READ,       METHOD_BUFFERED,  FILE_ANY_ACCESS)

#define PRY_MOD_NAME_CCH 96
#define PRY_MOD_PATH_CCH 192
#define PRY_MAX_MODULES 1024

typedef struct _PRY_MODULE_ENTRY {
    UINT64 Base;
    UINT64 Size;
    WCHAR Name[PRY_MOD_NAME_CCH];
    WCHAR Path[PRY_MOD_PATH_CCH];
} PRY_MODULE_ENTRY, *PPRY_MODULE_ENTRY;

#define PRY_MOD_FLAG_WOW64 0x1 // walk the 32-bit PEB Ldr list (WoW64 target)

typedef struct _PRY_MODULES_IN {
    UINT64 Pid;      // user-mode walk only
    UINT32 Capacity; // caller-provided entry capacity (informational)
    UINT32 Kernel;   // 1 = PsLoadedModuleList walk, Pid ignored
    UINT32 Flags;    // PRY_MOD_FLAG_* (WoW64 walk when set)
    UINT32 Reserved;
} PRY_MODULES_IN, *PPRY_MODULES_IN;

typedef struct _PRY_MODULES_HDR {
    UINT32 Status;     // NTSTATUS of the walk (partial data possible)
    UINT32 Count;      // entries written after this header
    UINT32 Required;   // total modules found
    UINT32 Reserved;
} PRY_MODULES_HDR, *PPRY_MODULES_HDR;

// process enumeration (kernel-side ZwQuerySystemInformation walk)
#define PRY_PROC_NAME_CCH 64

typedef struct _PRY_PROC_ENTRY {
    UINT32 Pid;
    UINT32 ParentPid;
    WCHAR ImageName[PRY_PROC_NAME_CCH];
} PRY_PROC_ENTRY, *PPRY_PROC_ENTRY;

typedef struct _PRY_PROC_LIST_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} PRY_PROC_LIST_HDR, *PPRY_PROC_LIST_HDR;

// VAD enumeration (driver walks EPROCESS->VadRoot; build-gated offsets)
#define PRY_VAD_TYPE_NONE 0
#define PRY_VAD_TYPE_MAPPED 1
#define PRY_VAD_TYPE_SECTION 2
#define PRY_VAD_TYPE_SUBSECTION 3
#define PRY_VAD_TYPE_LARGE_PAGES 4

typedef struct _PRY_VAD_ENTRY {
    UINT64 StartVA;   // inclusive
    UINT64 EndVA;     // exclusive
    UINT32 Protect;   // Win32 PAGE_* (guard/nocache variants included)
    UINT32 VadType;   // PRY_VAD_TYPE_*
    UINT64 CommitCharge;
    UINT64 Reserved;
} PRY_VAD_ENTRY, *PPRY_VAD_ENTRY;

typedef struct _PRY_VAD_IN {
    UINT64 Pid;
    UINT32 Flags; // reserved
    UINT32 Reserved;
} PRY_VAD_IN, *PPRY_VAD_IN;

typedef struct _PRY_VAD_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} PRY_VAD_HDR, *PPRY_VAD_HDR;

// handle-table enumeration (SystemExtendedHandleInformation walk filtered by pid)
#define PRY_HANDLE_TYPE_CCH 24
#define PRY_HANDLE_NAME_CCH 96

typedef struct _PRY_HANDLE_ENTRY {
    UINT64 Object;
    UINT64 HandleValue;
    UINT32 GrantedAccess;
    UINT32 ObjectTypeIndex;
    UINT32 Reserved;
    WCHAR TypeName[PRY_HANDLE_TYPE_CCH];
    WCHAR Name[PRY_HANDLE_NAME_CCH];
} PRY_HANDLE_ENTRY, *PPRY_HANDLE_ENTRY;

typedef struct _PRY_HANDLE_IN {
    UINT64 Pid;
    UINT32 WantNames; // 1 = resolve object names (slow; skips File objects)
    UINT32 Reserved;
} PRY_HANDLE_IN, *PPRY_HANDLE_IN;

typedef struct _PRY_HANDLE_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} PRY_HANDLE_HDR, *PPRY_HANDLE_HDR;

// ------------------------------------------------------------------ v12 ----
// Per-CPU IDT enumeration. The driver parks on each requested processor
// (GROUP_AFFINITY, the BpTrap.c pattern), __sidt's it, and decodes the
// KIDTENTRY64 gate descriptors itself — no agent-side kernel reads needed
// per entry. Output is [PRY_IDT_LIST_HDR][Count x PRY_IDT_ENTRY_ROW];
// Required is the total row count across all CPUs so a truncated caller
// can size the retry. Each row carries the IDTR.Base it was read from:
// KIDT is per-processor on x64, and a per-CPU base drift is a real detour
// signature worth keeping per-row.

#define PRY_IDT_VECTORS      256
#define PRY_IDT_MAX_CPUS     64
#define PRY_IDT_MAX_ENTRIES  (PRY_IDT_VECTORS * PRY_IDT_MAX_CPUS)

typedef struct _PRY_IDT_LIST_IN {
    UINT32 AllCpus;  // 0 = only the CPU servicing this request
    UINT32 Reserved;
} PRY_IDT_LIST_IN, *PPRY_IDT_LIST_IN;

typedef struct _PRY_IDT_ENTRY_ROW {
    UINT32 Cpu;       // processor index the row was read on
    UINT32 Vector;    // 0..255
    UINT64 HandlerVa; // decoded offset_lo|mid|hi
    UINT32 Selector;
    UINT32 Ist;
    UINT32 Dpl;
    UINT32 Type;      // 5-bit gate type field
    UINT32 Present;   // P bit
    UINT32 Reserved;  // alignment pad ahead of IdtBase
    UINT64 IdtBase;   // IDTR.Base of that CPU
} PRY_IDT_ENTRY_ROW, *PPRY_IDT_ENTRY_ROW; // 48 bytes

typedef struct _PRY_IDT_LIST_HDR {
    UINT32 Status;    // NTSTATUS of the walk
    UINT32 Count;     // rows written after this header
    UINT32 Required;  // total rows across all CPUs
    UINT32 IdtLimit;  // IDTR.Limit of the first CPU read
    UINT64 IdtBase;   // IDTR.Base of the first CPU read
} PRY_IDT_LIST_HDR, *PPRY_IDT_LIST_HDR;   // 24 bytes

// ------------------------------------------------------- object enumeration ----
// v10: \Device / \Driver / \FileSystem / \BaseNamedObjects / \Callback /
// \ObjectTypes walk via ZwOpenDirectoryObject + ZwQueryDirectoryObject.
// No _OBJECT_DIRECTORY layout assumptions. Depth is clamped to 2,
// MaxEntries to PRY_OBJ_MAX_ENTRIES; Truncated=1 means the namespace
// had more than the caller's budget (a fact, not an error).

#define PRY_OBJ_PATH_CCH 128
#define PRY_OBJ_NAME_CCH 64
#define PRY_OBJ_MAX_ENTRIES 4096
#define PRY_OBJ_MAX_DEPTH 2

typedef struct _PRY_OBJ_ENUM_IN {
    WCHAR Path[PRY_OBJ_PATH_CCH]; // e.g. L"\Device"; leading '\' required
    UINT32 Depth;                    // 1 = flat, 2 = one subdirectory level
    UINT32 MaxEntries;               // clamped to PRY_OBJ_MAX_ENTRIES
} PRY_OBJ_ENUM_IN, *PPRY_OBJ_ENUM_IN;

typedef struct _PRY_OBJ_ENTRY {
    WCHAR Name[PRY_OBJ_NAME_CCH];
    WCHAR TypeName[PRY_OBJ_NAME_CCH];
    UINT32 IsDirectory; // 1 = object directory (recursed when depth allows)
    // object body VA + type-index resolved via
    // ObpRootDirectoryObject hash-bucket walk (populated iff `Source == 1`;
    // zero on the ZwQueryDirectoryObject fallback path, `Source == 0`).
    UINT32 Reserved;
    UINT64 Address;
    UINT32 TypeIndex;
    UINT32 Source;      // 0 = zwquery, 1 = walk
} PRY_OBJ_ENTRY, *PPRY_OBJ_ENTRY;

typedef struct _PRY_OBJ_HDR {
    UINT32 Status;    // NTSTATUS of the walk (partial data possible)
    UINT32 Count;     // entries written after this header
    UINT32 Required;  // total entries seen (may exceed Count)
    UINT32 Truncated; // 1 = budget hit before the walk finished
} PRY_OBJ_HDR, *PPRY_OBJ_HDR;

// ---------------------------------------------------------- thread list ----
// v10: kernel-side SystemProcessInformation walk enriched per-thread with
// ZwQueryInformationThread(ThreadBasicInformation → TebBaseAddress) and
// (ThreadQuerySetWin32StartAddress → Win32StartAddress). Both documented
// info classes — no ETHREAD offsets. Flags bit0 = Win32Start valid,
// bit1 = Teb valid (system threads have no TEB; Win32Start may be 0 for
// system-created threads).

#define PRY_THREAD_FLAG_WIN32_START 0x1
#define PRY_THREAD_FLAG_TEB         0x2
#define PRY_THREADLIST_MAX          8192

typedef struct _PRY_THREADLIST_IN {
    UINT32 Pid;      // 0 = every process
    UINT32 Reserved;
} PRY_THREADLIST_IN, *PPRY_THREADLIST_IN;

typedef struct _PRY_THREAD_ENTRY {
    UINT32 Tid;
    UINT32 Pid;
    UINT32 State;       // KTHREAD_STATE
    UINT32 WaitReason;
    LONG   BasePriority;
    UINT32 Flags;       // PRY_THREAD_FLAG_*
    UINT64 StartVa;     // SystemThreadInformation.StartAddress
    UINT64 Win32StartVa;
    UINT64 Teb;
} PRY_THREAD_ENTRY, *PPRY_THREAD_ENTRY;

typedef struct _PRY_THREAD_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} PRY_THREAD_HDR, *PPRY_THREAD_HDR;

// ---------------------------------------------- SI #3 IRP list (v15) ----
// Pending-IRP walk for a thread. Driver traverses KTHREAD.IrpList under
// IoCancelSpinLock, copies the IRP header fields (DeviceObject name,
// MajorFunction / MinorFunction, CancelRoutine VA) out, and releases
// the lock before continuing. METHOD_OUT_DIRECT so the variable-length
// row array doesn't bounce through the system buffer. Each row is
// 128 bytes to leave room for the device-name trailer; the HDR tells
// the agent how many rows and (for a terminated thread between the
// outer PsLookupThreadByThreadId and the walk) which NTSTATUS to
// surface. Mirrors the shape of PRY_THREAD_HDR / _ENTRY.
//
// Function code lands at 0x8A7, the next free slot after the v14 OBJ_ENUM /
// THREAD_LIST / IDT_LIST block (0x8A4-0x8A6). SI #3 WAIT_INFO lives at
// 0x8A8 (added late v14 by P0a) and uses the same METHOD_OUT_DIRECT
// transport.
#define PRY_FUNC_THREAD_IRP_LIST  0x8A7

#define PRY_IOCTL_THREAD_IRP_LIST \
    PRY_IOCTL(PRY_FUNC_THREAD_IRP_LIST, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define PRY_IRP_DEVICE_NAME_CCH   48
#define PRY_IRP_LIST_MAX          64

typedef struct _PRY_IRP_LIST_IN {
    UINT64 Tid;
    UINT32 Reserved;
    UINT32 MaxEntries;    // 0 => PRY_IRP_LIST_MAX
} PRY_IRP_LIST_IN, *PPRY_IRP_LIST_IN;

typedef struct _PRY_IRP_LIST_ENTRY {
    UINT64 IrpVa;                           // IRP* in kernel VA
    UINT64 DeviceObjectVa;                  // _IRP->Tail.Overlay.CurrentStackLocation->DeviceObject
    UINT64 CancelRoutineVa;                 // _IRP->CancelRoutine
    UINT64 Reserved;                        // alignment pad / future PFN
    UINT32 MajorFunction;                   // CurrentStackLocation.MajorFunction
    UINT32 MinorFunction;                   // CurrentStackLocation.MinorFunction
    UINT32 Flags;                           // _IRP->Flags
    UINT32 Reserved2;
    WCHAR  DeviceName[PRY_IRP_DEVICE_NAME_CCH]; // best-effort "\Device\Afd"
} PRY_IRP_LIST_ENTRY, *PPRY_IRP_LIST_ENTRY;

typedef struct _PRY_IRP_LIST_HDR {
    UINT32 Status;         // NTSTATUS of the walk (STATUS_INVALID_CID when
                           // the thread died, STATUS_NOT_SUPPORTED on a
                           // pre-dyn-data build)
    UINT32 Pid;            // owning process pid (0 before success)
    UINT32 Count;          // rows written after this header
    UINT32 Required;       // total IRPs the walker saw (may exceed Count)
    UINT32 Truncated;      // 1 => Count < Required
    UINT32 Reserved;
} PRY_IRP_LIST_HDR, *PPRY_IRP_LIST_HDR;

// --------------------------------------------------- SI #3 wait info ----
// Analyze-wait on a thread: driver walks ETHREAD/KTHREAD under an
// ObReferenceObjectByHandle equivalent (PsLookupThreadByThreadId) and
// returns the last_syscall / wait reason / kernel-stack scalar fields.
// METHOD_OUT_DIRECT because callers may ask the driver to copy a few KB
// of the saved arg-frame and user-stack into the response trailer; the
// handler is PASSIVE_LEVEL (WDF default queue).
//
// Function code 0x8A8 lands next to the SI #3 IRP_LIST slot (0x8A7). The
// per-field reads are gated on the Wave 3 dyn-data probe (PryDyn.Valid)
// — until Wave 3 ships, PryThreadWaitInfo surfaces STATUS_NOT_SUPPORTED
// without touching ETHREAD offsets so the handler is Verifier-safe
// across every ntoskrnl build.
#define PRY_FUNC_THREAD_WAIT_INFO 0x8A8

#define PRY_IOCTL_THREAD_WAIT_INFO \
    PRY_IOCTL(PRY_FUNC_THREAD_WAIT_INFO, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define PRY_WAIT_INFO_FRAME_MAX         4096u
#define PRY_WAIT_INFO_USER_STACK_MAX    16384u
#define PRY_WAIT_INFO_FRAME_DEFAULT     256u

// PRY_WAIT_INFO_IN.Flags
#define PRY_WAITINFO_FLAG_PARTIAL_OK        0x1
#define PRY_WAITINFO_FLAG_NO_USER_READ      0x2
#define PRY_WAITINFO_FLAG_USE_DYNDATA_VERIFY 0x4

typedef struct _PRY_WAIT_INFO_IN {
    UINT64 Tid;
    UINT32 FrameCapture;      // 0..PRY_WAIT_INFO_FRAME_MAX
    UINT32 UserStackCapture;  // 0..PRY_WAIT_INFO_USER_STACK_MAX
    UINT32 Flags;             // PRY_WAITINFO_FLAG_*
    UINT32 Reserved;
} PRY_WAIT_INFO_IN, *PPRY_WAIT_INFO_IN;

typedef struct _PRY_WAIT_INFO_HDR {
    UINT32 Status;              // NTSTATUS of the walk (STATUS_NOT_SUPPORTED
                                // without dyn-data; STATUS_INVALID_CID for
                                // a vanished thread)
    UINT32 Pid;                 // owning process pid (0 before Status != success)
    UINT64 KernelStackTop;      // ETHREAD->Tcb.StackBase (dyn-data)
    UINT64 KernelStackLimit;    // ETHREAD->Tcb.StackLimit (dyn-data)
    UINT64 UserStackPointer;    // Tcb.TrapFrame->Rsp (dyn-data)
    UINT64 SystemCallNumber;    // ETHREAD.LastSystemCallNumber (dyn-data)
    UINT64 ArgFrameUserVa;      // ETHREAD.LastSystemCallArgsFramePointer
    UINT32 WaitReason;          // KTHREAD.WaitReason (dyn-data)
    UINT32 WaitMode;            // KTHREAD.WaitMode (0 kernel, 1 user)
    UINT32 WaitStatus;          // KTHREAD.WaitStatus
    UINT32 ThreadState;         // KTHREAD.State
    UINT32 FrameBytes;          // trailing arg-frame bytes written
    UINT32 UserStackBytes;      // trailing user-stack bytes written
    UINT32 WaitBlockCount;      // KTHREAD.WaitBlockCount (dyn-data)
    UINT32 Reserved;
} PRY_WAIT_INFO_HDR, *PPRY_WAIT_INFO_HDR;

// -------------------------------------------------------- MSR / CPUID ----
// PR#6 T3.2: driver-side per-core reader. Walk is driven by a packed
// (CoreCount, Cores[]) list — AllCores=1 asks the driver to expand to
// every active logical processor via KeQueryActiveProcessorCountEx. The
// driver pins to each core via KeSetSystemGroupAffinityThread + __readmsr
// / __cpuidex, inside __try/__except(EXCEPTION_EXECUTE_HANDLER) so a
// #GP on an unimplemented MSR surfaces as NtStatus=STATUS_UNSUCCESSFUL
// per row — never a bugcheck. Cap matches PRY_IDT_MAX_CPUS.
#define PRY_CPU_MAX_CORES 64

typedef struct _PRY_MSR_READ_IN {
    UINT32 Msr;                                 // MSR address (ECX for RDMSR)
    UINT32 AllCores;                            // 1 = walk every active LP
    UINT32 CoreCount;                           // 0..PRY_CPU_MAX_CORES
    UINT32 Reserved;
    UINT32 Cores[PRY_CPU_MAX_CORES];         // explicit set, honored iff
                                                 // AllCores==0 && CoreCount>0
} PRY_MSR_READ_IN, *PPRY_MSR_READ_IN;

typedef struct _PRY_MSR_VALUE {
    UINT32 Core;                                // logical processor index
    UINT32 NtStatus;                            // STATUS_SUCCESS or
                                                 // STATUS_UNSUCCESSFUL on #GP
    UINT64 Value;                               // combined EDX:EAX; 0 on error
} PRY_MSR_VALUE, *PPRY_MSR_VALUE;

typedef struct _PRY_MSR_READ_HDR {
    UINT32 Status;                              // NTSTATUS of the walk itself
    UINT32 Count;                               // rows written after this hdr
    UINT32 Required;                            // rows the driver would emit
    UINT32 Reserved;
} PRY_MSR_READ_HDR, *PPRY_MSR_READ_HDR;

typedef struct _PRY_CPUID_IN {
    UINT32 Leaf;                                // EAX input
    UINT32 Subleaf;                             // ECX input
    UINT32 AllCores;
    UINT32 CoreCount;
    UINT32 Cores[PRY_CPU_MAX_CORES];
} PRY_CPUID_IN, *PPRY_CPUID_IN;

typedef struct _PRY_CPUID_VALUE {
    UINT32 Core;
    UINT32 Eax;
    UINT32 Ebx;
    UINT32 Ecx;
    UINT32 Edx;
    UINT32 Reserved;                            // keep row size 8-aligned (24B)
} PRY_CPUID_VALUE, *PPRY_CPUID_VALUE;

typedef struct _PRY_CPUID_HDR {
    UINT32 Status;
    UINT32 Count;
    UINT32 Required;
    UINT32 Reserved;
} PRY_CPUID_HDR, *PPRY_CPUID_HDR;

// ---- SI #21 self-protection ----
// ObRegisterCallbacks-driven pre-op handle-rights stripper. Config installs
// (or tears down) PsProcessType / PsThreadType pre-op callbacks that mask
// DesiredAccess down to a safe keep-mask for a caller-provided PID set.
// Status reports counters + whether the altitude install actually took.
//
// Function codes 0x8E0/0x8E1 are the two free slots in the 0x8D0..0x8FF
// range reserved by an internal plan §4 for the SI
// adoption plan (0x8D0/0x8D1 are earmarked for callback enumeration (#5);
// the rest of the band is unused today).
#define PRY_FUNC_SELFPROT_CONFIG   0x8E0
#define PRY_FUNC_SELFPROT_STATUS   0x8E1

#define PRY_IOCTL_SELFPROT_CONFIG \
    PRY_IOCTL(PRY_FUNC_SELFPROT_CONFIG, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_SELFPROT_STATUS \
    PRY_IOCTL(PRY_FUNC_SELFPROT_STATUS, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PRY_SELFPROT_MAX_PIDS      32

// Config.Enable
#define PRY_SELFPROT_ENABLE_OFF    0u   // tear down callbacks (DisableToken-gated)
#define PRY_SELFPROT_ENABLE_ON     1u   // install (or re-install, replacing cfg)
#define PRY_SELFPROT_ENABLE_REFRESH 2u  // replace PID list / masks only

// Config.Flags
#define PRY_SELFPROT_FLAG_INCLUDE_THREADS 0x1
#define PRY_SELFPROT_FLAG_DISABLE_TOKEN_OK 0x2  // present DisableToken to turn off
#define PRY_SELFPROT_FLAG_ALLOW_DUP        0x4  // skip HANDLE_DUPLICATE strip
// Retroscan over existing handles is intentionally out of the first cut —
// closing it needs the undocumented ExEnumHandleTable + handle-table lock
// dance (slice doc §Retroscan). Flag bit reserved so later cuts don't
// churn the ABI.
#define PRY_SELFPROT_FLAG_RETROSCAN        0x8  // reserved; not implemented v13+

// Status.Flags echo
#define PRY_SELFPROT_STATE_INSTALLED       0x1
#define PRY_SELFPROT_STATE_ALTITUDE_RETRY  0x2  // installed on 389101..389109
#define PRY_SELFPROT_STATE_ALTITUDE_FAIL   0x4  // every attempt collided

typedef struct _PRY_SELFPROT_CONFIG_IN {
    UINT32 Enable;              // PRY_SELFPROT_ENABLE_*
    UINT32 Flags;               // PRY_SELFPROT_FLAG_*
    UINT32 ProcessAccessKeep;   // kept bits for process handles (0 = default)
    UINT32 ThreadAccessKeep;    // kept bits for thread handles (0 = default)
    UINT32 PidCount;            // 0..PRY_SELFPROT_MAX_PIDS
    UINT32 Reserved;
    UINT64 DisableToken;        // required to turn OFF without a protected caller
    UINT32 ProtectedPids[PRY_SELFPROT_MAX_PIDS]; // 0 slots ignored
} PRY_SELFPROT_CONFIG_IN, *PPRY_SELFPROT_CONFIG_IN;

typedef struct _PRY_SELFPROT_CONFIG_OUT {
    UINT32 Status;              // NTSTATUS of the install (0 on success)
    UINT32 State;               // PRY_SELFPROT_STATE_*
    UINT32 Installed;           // 1 while callbacks are registered
    UINT32 Altitude;            // 389100..389109 that stuck, 0 otherwise
    UINT32 ProtectedPids;       // PID count after apply
    UINT32 Reserved;
    UINT64 DisableToken;        // echoed on first install; keep for later OFF
} PRY_SELFPROT_CONFIG_OUT, *PPRY_SELFPROT_CONFIG_OUT;

typedef struct _PRY_SELFPROT_STATUS_OUT {
    UINT32 Status;              // 0 on success
    UINT32 State;               // PRY_SELFPROT_STATE_*
    UINT32 Installed;
    UINT32 Altitude;
    UINT32 ProtectedPids;
    UINT32 Flags;               // echo of last Config.Flags
    UINT32 ProcessAccessKeep;
    UINT32 ThreadAccessKeep;
    UINT64 PreOpHits;           // callback entries overall
    UINT64 Stripped;             // handles with DesiredAccess narrowed
    UINT64 Bypassed;             // kernel/self/own-PID opens allowed through
    UINT64 Reserved;
} PRY_SELFPROT_STATUS_OUT, *PPRY_SELFPROT_STATUS_OUT;

// ---- SI #6 handle ops ----
// Three primitives that generalize the handle-table listing into actuator
// surface: duplicate a remote handle into the caller process, close a
// remote handle, compare two handles for pointer identity. All three use
// documented ObReferenceObjectByHandle / ObOpenObjectByPointer / ObCloseHandle
// / NtClose with KernelMode PreviousMode so SeAccessCheck is bypassed
// (lab-tool contract — see an internal plan
// 01-driver-primitives.md Feature 2).
//
// 0x8E0 / 0x8E1 are the SI #21 self-protection pair above; 0x8E2..0x8E4
// are the three new handle-op codes. ABI stays at v14 (SI #25 bumped it).
#define PRY_FUNC_HANDLE_DUP          0x8E2
#define PRY_FUNC_HANDLE_CLOSE_REMOTE 0x8E3
#define PRY_FUNC_HANDLE_COMPARE      0x8E4

#define PRY_IOCTL_HANDLE_DUP \
    PRY_IOCTL(PRY_FUNC_HANDLE_DUP, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_HANDLE_CLOSE_REMOTE \
    PRY_IOCTL(PRY_FUNC_HANDLE_CLOSE_REMOTE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_HANDLE_COMPARE \
    PRY_IOCTL(PRY_FUNC_HANDLE_COMPARE, METHOD_BUFFERED, FILE_ANY_ACCESS)

// HANDLE_DUP options
#define PRY_HANDLE_DUP_FLAG_SAME_ACCESS 0x1   // ignore DesiredAccess, mirror source
#define PRY_HANDLE_DUP_FLAG_NO_INHERIT  0x2   // omit OBJ_INHERIT in new handle

typedef struct _PRY_HANDLE_DUP_IN {
    UINT64 SrcPid;              // source process (!=0)
    UINT64 SrcHandle;           // handle value in SrcPid's table
    UINT32 DesiredAccess;       // granted to the new handle (ignored under SAME_ACCESS)
    UINT32 Options;             // PRY_HANDLE_DUP_FLAG_*
    UINT64 PrivilegeCookie;     // #24 session-token slot (opaque; 0 under legacy auth)
    UINT64 Reserved;
} PRY_HANDLE_DUP_IN, *PPRY_HANDLE_DUP_IN;

typedef struct _PRY_HANDLE_DUP_OUT {
    UINT32 Status;              // NTSTATUS of the op
    UINT32 GrantedAccess;       // mirrors what Ob granted (SAME_ACCESS)
    UINT64 NewHandle;           // handle VA in caller process (closable via NtClose)
    UINT64 ObjectAddr;          // VA of the referenced object (kernel pointer)
    UINT32 TypeIndex;           // ObGetObjectType index
    UINT32 Reserved;
    WCHAR  TypeName[PRY_HANDLE_TYPE_CCH]; // best-effort TypeName copy
} PRY_HANDLE_DUP_OUT, *PPRY_HANDLE_DUP_OUT;

typedef struct _PRY_HANDLE_CLOSE_IN {
    UINT64 TargetPid;
    UINT64 TargetHandle;
    UINT64 PrivilegeCookie;
    UINT64 Reserved;
} PRY_HANDLE_CLOSE_IN, *PPRY_HANDLE_CLOSE_IN;

typedef struct _PRY_HANDLE_CLOSE_OUT {
    UINT32 Status;              // NTSTATUS of ObCloseHandle
    UINT32 Reserved;
} PRY_HANDLE_CLOSE_OUT, *PPRY_HANDLE_CLOSE_OUT;

typedef struct _PRY_HANDLE_CMP_IN {
    UINT64 PidA;
    UINT64 HandleA;
    UINT64 PidB;
    UINT64 HandleB;
    UINT64 PrivilegeCookie;
    UINT64 Reserved;
} PRY_HANDLE_CMP_IN, *PPRY_HANDLE_CMP_IN;

typedef struct _PRY_HANDLE_CMP_OUT {
    UINT32 Status;              // NTSTATUS of the dual lookup
    UINT32 Same;                // 1 = object pointers match, 0 = different
    UINT64 ObjectA;
    UINT64 ObjectB;
    UINT32 TypeIndexA;
    UINT32 TypeIndexB;
} PRY_HANDLE_CMP_OUT, *PPRY_HANDLE_CMP_OUT;

// ---- SI #9 kernel-stack walk ----
// Thread stack walk via RtlWalkFrameChain, delivered through a kernel-mode
// APC on the target thread (PryRemoteCall + PRY_RC_FLAG_KERNEL). The
// APC runs at PASSIVE_LEVEL in the target context, which is where
// RtlWalkFrameChain is legal. Default timeout is bounded at 500 ms so a
// frozen target can't wedge the sequential IOCTL queue (plan README §6).
//
// Function code 0x8E5 sits above the SI #21 (0x8E0/0x8E1) and SI #6
// (0x8E2..0x8E4) codes within the 0x8D0..0x8FF reserved band.
#define PRY_FUNC_STACKWALK           0x8E5

#define PRY_IOCTL_STACKWALK \
    PRY_IOCTL(PRY_FUNC_STACKWALK, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define PRY_STACKWALK_MAX_FRAMES     128u
#define PRY_STACKWALK_DEFAULT_TIMEOUT_MS 500u

// IN.Flags
#define PRY_STACKWALK_FLAG_KERNEL        0x1
#define PRY_STACKWALK_FLAG_USER          0x2
#define PRY_STACKWALK_FLAG_BOTH          (PRY_STACKWALK_FLAG_KERNEL | \
                                             PRY_STACKWALK_FLAG_USER)
#define PRY_STACKWALK_FLAG_FORCE_APC     0x4
#define PRY_STACKWALK_FLAG_TIMEOUT_PARTIAL_OK 0x8

// HDR.Flags
#define PRY_STACKWALK_HDR_KERNEL_DONE    0x1
#define PRY_STACKWALK_HDR_USER_DONE      0x2
#define PRY_STACKWALK_HDR_TIMED_OUT      0x4
#define PRY_STACKWALK_HDR_APC_UNDELIVERABLE 0x8

// FRAME.ModuleTag
#define PRY_STACKWALK_MOD_KERNEL         0u
#define PRY_STACKWALK_MOD_USER           1u
#define PRY_STACKWALK_MOD_UNKNOWN        2u

typedef struct _PRY_STACKWALK_IN {
    UINT64 Tid;                 // target thread (!=0)
    UINT32 MaxFrames;           // 0 defaults, clamped to PRY_STACKWALK_MAX_FRAMES
    UINT32 Flags;               // PRY_STACKWALK_FLAG_*
    UINT32 TimeoutMs;           // 0 => PRY_STACKWALK_DEFAULT_TIMEOUT_MS
    UINT32 Reserved;
    UINT64 PrivilegeCookie;     // #24 session-token slot (opaque)
} PRY_STACKWALK_IN, *PPRY_STACKWALK_IN;

typedef struct _PRY_STACKWALK_FRAME {
    UINT64 Rip;                 // frame return address
    UINT32 ModuleTag;           // PRY_STACKWALK_MOD_*
    UINT32 Reserved;
    UINT64 ModuleBase;          // caller-correlated via MODULES listing
} PRY_STACKWALK_FRAME, *PPRY_STACKWALK_FRAME;

typedef struct _PRY_STACKWALK_HDR {
    UINT32 Status;              // walk NTSTATUS (STATUS_TIMEOUT for frozen target)
    UINT32 KernelFrameCount;
    UINT32 UserFrameCount;
    UINT32 Flags;               // PRY_STACKWALK_HDR_*
    UINT64 Rip;                 // snapshot RIP at APC entry (0 if undelivered)
    UINT64 Rsp;                 // snapshot RSP at APC entry
    UINT32 Pid;                 // owning process pid
    UINT32 Reserved;
} PRY_STACKWALK_HDR, *PPRY_STACKWALK_HDR;

#ifdef __cplusplus
}
#endif

#endif // PRY_ABI_PROC_H
