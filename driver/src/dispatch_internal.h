#ifndef PRY_DISPATCH_INTERNAL_H
#define PRY_DISPATCH_INTERNAL_H

#include "PryDriver.h"

// dispatch_mem.c
NTSTATUS PryHandleMemRead(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _In_ BOOLEAN Physical, _Out_ SIZE_T* Info);
NTSTATUS PryHandleMemWrite(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _In_ BOOLEAN Physical, _Out_ SIZE_T* Info);
SIZE_T PryHandleAlloc(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleFree(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleProtect(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleKmemAlloc(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleKmemFree(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_proc.c
SIZE_T PryHandleProcessList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleModules(_In_ WDFREQUEST Request, _In_ BOOLEAN Kernel, _Out_ NTSTATUS* Status);
SIZE_T PryHandleVadList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleHandleList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleCtxGet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleCtxSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
// SI #6 handle ops
SIZE_T PryHandleHandleDup(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleHandleCloseRemote(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleHandleCompare(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
// SI #9 kernel-stack walk — dispatch TU extends dispatch_proc.c
// per the R0 driver report (no new dispatch_stackwalk.c).
SIZE_T PryHandleThreadStackWalk(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
// SI #3 analyze-wait on thread — dispatch TU extends dispatch_proc.c
// per the combined plan (same convention as #9 stackwalk).
SIZE_T PryHandleThreadWaitInfo(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
// slice 03 Feature 4 — KTHREAD.IrpList walker. Same transport
// shape as WaitInfo (METHOD_OUT_DIRECT, HDR + packed rows); dispatch
// glue lives in dispatch_proc.c next to PryHandleThreadWaitInfo.
SIZE_T PryHandleThreadIrpList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_bp.c
SIZE_T PryHandleBpSwSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleBpSwClear(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleBpHwSet(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleBpHwClear(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleBpList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_kernel.c
SIZE_T PryHandlePhysRanges(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandlePoolScan(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleVaTranslate(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleIdtList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleRemoteCall(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleKernelCall(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_watchdog.c
SIZE_T PryHandleWatchdogArm(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleWatchdogKick(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleWatchdogDisarm(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleWatchdogList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_notify.c (v10)
SIZE_T PryHandleNotifySubscribe(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleNotifyRead(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleNotifyDisable(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleNotifyStats(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleObjEnum(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleThreadList(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// Cpu.c (PR#6 T3.2)
SIZE_T PryHandleMsrRead(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleCpuidRead(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

// dispatch_selfprot.c (SI #21)
SIZE_T PryHandleSelfProtConfig(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);
SIZE_T PryHandleSelfProtStatus(_In_ WDFREQUEST Request, _Out_ NTSTATUS* Status);

#endif // PRY_DISPATCH_INTERNAL_H
