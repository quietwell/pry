/*
 * comm/abi/call.h — Remote user-mode call (user APC thunk) and the v13
 * synchronous kernel function call. Function codes 0x880 (remote) and
 * 0x8B0 (kernel).
 *
 * Part of the pry wire ABI; see comm/pry_abi.h.
 * Fixed-layout, no pointers, no C++. Any change here is a breaking ABI
 * change: bump PRY_ABI_VERSION and the driver epoch.
 */

#ifndef PRY_ABI_CALL_H
#define PRY_ABI_CALL_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PRY_FUNC_REMOTE_CALL 0x880
// v13: synchronous kernel function call (WDF work item at PASSIVE_LEVEL)
#define PRY_FUNC_KERNEL_CALL      0x8B0

#define PRY_IOCTL_REMOTE_CALL PRY_IOCTL(PRY_FUNC_REMOTE_CALL, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRY_IOCTL_KERNEL_CALL      PRY_IOCTL(PRY_FUNC_KERNEL_CALL,      METHOD_BUFFERED,  FILE_ANY_ACCESS)

typedef struct _PRY_REMOTE_CALL_IN {
    UINT64 Pid;
    UINT64 Tid;
    UINT64 Target; // user-mode function address, or kernel address w/ PRY_RC_FLAG_KERNEL
    UINT64 Arg1;   // rcx (user) / NormalContext (kernel)
    UINT64 Arg2;   // rdx (user) / SystemArgument1 (kernel)
    UINT64 Arg3;   // r8  (user) / SystemArgument2 (kernel)
    UINT32 Flags;  // PRY_RC_FLAG_*
    UINT32 Reserved;
} PRY_REMOTE_CALL_IN, *PPRY_REMOTE_CALL_IN;

#define PRY_RC_FLAG_KERNEL 0x1 // kernel-mode APC: NormalRoutine = Target runs in kernel

typedef struct _PRY_REMOTE_CALL_OUT {
    UINT32 Status;
    UINT32 Queued;
    UINT32 Alerted;
    UINT32 Reserved;
} PRY_REMOTE_CALL_OUT, *PPRY_REMOTE_CALL_OUT;

// ------------------------------------------------------------ kernel call ----
// v13: synchronous kernel function call. The driver runs Target inside a
// WDF work item at PASSIVE_LEVEL in System context, guarded by __try/__except
// (rax + exception capture), and parks the IOCTL thread on a KEVENT until the
// thunk signals or the caller's timeout expires.
//
// Contract:
//   * Target must be a canonical kernel VA unless PRY_KC_FLAG_FORCE is set
//     (pool-resident / non-module code) — the driver refuses otherwise.
//   * Argc <= PRY_KC_MAX_ARGS; x64 fastcall ignores surplus register/stack
//     args, so thunking a fixed 16-arg signature covers Argc 0..16. Args[0..3]
//     go to rcx/rdx/r8/r9, Args[4..15] to the stack in ms64 order.
//   * Only rax (ReturnValue) is captured — rdx:rax/struct returns out of scope.
//   * Caller wait is TimeoutMs (0 = 30000). On timeout the call returns
//     STATUS_TIMEOUT and the target thread keeps running; the slot stays Busy
//     and later calls report STATUS_DEVICE_BUSY until the thunk finishes.
//   * PASSIVE_LEVEL, System context only — APC/DISPATCH-only target routines
//     are out of contract.

#define PRY_KC_MAX_ARGS 16
#define PRY_KC_FLAG_FORCE      0x1 // skip canonical-VA refusal (pool-resident code)
#define PRY_KC_FLAG_VALIDATED  0x2 // informational: agent pre-checked module range

typedef struct _PRY_KERNEL_CALL_IN {
    UINT64 Target;
    UINT32 Argc;                    // <= PRY_KC_MAX_ARGS
    UINT32 Flags;                   // PRY_KC_FLAG_*
    UINT64 Args[PRY_KC_MAX_ARGS];
    UINT32 TimeoutMs;               // 0 = 30000
    UINT32 Reserved[3];
} PRY_KERNEL_CALL_IN, *PPRY_KERNEL_CALL_IN;
C_ASSERT(sizeof(PRY_KERNEL_CALL_IN) == 8 + 4 + 4 + 128 + 4 + 12); // 160

typedef struct _PRY_KERNEL_CALL_OUT {
    UINT32 Status;                  // NTSTATUS of the call operation itself
    UINT32 Completed;               // 1 = target ran to return
    UINT32 Exception;               // 1 = SEH caught inside the call
    UINT32 ExceptionCode;           // GetExceptionCode() when Exception=1
    UINT64 ReturnValue;             // rax
} PRY_KERNEL_CALL_OUT, *PPRY_KERNEL_CALL_OUT;
C_ASSERT(sizeof(PRY_KERNEL_CALL_OUT) == 24);

#ifdef __cplusplus
}
#endif

#endif // PRY_ABI_CALL_H
