#include "PryDriver.h"
#include "dispatch_internal.h"

static VOID PryHandlePing(_Out_ PRY_PING_OUT* Out)
{
    RtlZeroMemory(Out, sizeof(*Out));
    Out->VersionMajor = PRY_DRV_VERSION_MAJOR;
    Out->VersionMinor = PRY_DRV_VERSION_MINOR;
    Out->NtBuild = PryNtBuild;
    Out->Flags = PrySystemFlags();
    Out->AbiVersion = PRY_ABI_VERSION;
}

VOID PryEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request,
                             _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength,
                             _In_ ULONG IoControlCode)
{
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    SIZE_T info = 0;
    PVOID buf;
    SIZE_T len;
    NTSTATUS inner = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    // SI #21: tell SelfProt.c that this is our own thread opening handles,
    // so its ObCallback pre-op never strips rights off our own IOCTL work.
    // Paired with PrySelfProtLeaveCall below in the __finally.
    PrySelfProtEnterCall();

    __try {
        switch (IoControlCode) {
        case PRY_IOCTL_PING:
            st = PryOutput(Request, sizeof(PRY_PING_OUT), &buf, &len);
            if (NT_SUCCESS(st)) {
                PRY_PING_OUT ping;
                PryHandlePing(&ping);
                RtlCopyMemory(buf, &ping, sizeof(ping));
                info = sizeof(PRY_PING_OUT);
                st = STATUS_SUCCESS;
            }
            break;

        case PRY_IOCTL_USER_MEM_READ:
            st = PryHandleMemRead(Request, FALSE, FALSE, &info);
            break;
        case PRY_IOCTL_USER_MEM_WRITE:
            st = PryHandleMemWrite(Request, FALSE, FALSE, &info);
            break;
        case PRY_IOCTL_KERNEL_MEM_READ:
            st = PryHandleMemRead(Request, TRUE, FALSE, &info);
            break;
        case PRY_IOCTL_KERNEL_MEM_WRITE:
            st = PryHandleMemWrite(Request, TRUE, FALSE, &info);
            break;
        case PRY_IOCTL_PHYS_MEM_READ:
            st = PryHandleMemRead(Request, FALSE, TRUE, &info);
            break;
        case PRY_IOCTL_PHYS_MEM_WRITE:
            st = PryHandleMemWrite(Request, FALSE, TRUE, &info);
            break;

        case PRY_IOCTL_USER_ALLOC:
            info = PryHandleAlloc(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_USER_FREE:
            info = PryHandleFree(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_USER_PROTECT:
            info = PryHandleProtect(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_KMEM_ALLOC:
            info = PryHandleKmemAlloc(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_KMEM_FREE:
            info = PryHandleKmemFree(Request, &inner);
            st = inner;
            break;

        case PRY_IOCTL_USER_MODULES:
            info = PryHandleModules(Request, FALSE, &inner);
            st = inner;
            break;
        case PRY_IOCTL_KERNEL_MODULES:
            info = PryHandleModules(Request, TRUE, &inner);
            st = inner;
            break;
        case PRY_IOCTL_PROCESS_LIST:
            info = PryHandleProcessList(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_VAD_LIST:
            info = PryHandleVadList(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_HANDLE_LIST:
            info = PryHandleHandleList(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_PHYS_RANGES:
            info = PryHandlePhysRanges(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_POOL_SCAN:
            info = PryHandlePoolScan(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_VA_TRANSLATE:
            info = PryHandleVaTranslate(Request, &inner);
            st = inner;
            break;

        case PRY_IOCTL_CTX_GET:
            info = PryHandleCtxGet(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_CTX_SET:
            info = PryHandleCtxSet(Request, &inner);
            st = inner;
            break;

        case PRY_IOCTL_BP_SW_SET:
            info = PryHandleBpSwSet(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_BP_SW_CLEAR:
            info = PryHandleBpSwClear(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_BP_HW_SET:
            info = PryHandleBpHwSet(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_BP_HW_CLEAR:
            info = PryHandleBpHwClear(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_BP_LIST:
            info = PryHandleBpList(Request, &inner);
            st = inner;
            break;

        case PRY_IOCTL_REMOTE_CALL:
            info = PryHandleRemoteCall(Request, &inner);
            st = inner;
            break;

        case PRY_IOCTL_KERNEL_CALL:
            info = PryHandleKernelCall(Request, &inner);
            st = inner;
            break;

        case PRY_IOCTL_WATCHDOG_ARM:
            info = PryHandleWatchdogArm(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_WATCHDOG_KICK:
            info = PryHandleWatchdogKick(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_WATCHDOG_DISARM:
            info = PryHandleWatchdogDisarm(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_WATCHDOG_LIST:
            info = PryHandleWatchdogList(Request, &inner);
            st = inner;
            break;

        case PRY_IOCTL_NOTIFY_SUBSCRIBE:
            info = PryHandleNotifySubscribe(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_NOTIFY_READ:
            info = PryHandleNotifyRead(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_NOTIFY_DISABLE:
            info = PryHandleNotifyDisable(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_NOTIFY_STATS:
            info = PryHandleNotifyStats(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_OBJ_ENUM:
            info = PryHandleObjEnum(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_THREAD_LIST:
            info = PryHandleThreadList(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_IDT_LIST:
            info = PryHandleIdtList(Request, &inner);
            st = inner;
            break;

        case PRY_IOCTL_MSR_READ:
            info = PryHandleMsrRead(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_CPUID_READ:
            info = PryHandleCpuidRead(Request, &inner);
            st = inner;
            break;

        // SI adoption feature #21 — ObRegisterCallbacks self-protection.
        case PRY_IOCTL_SELFPROT_CONFIG:
            info = PryHandleSelfProtConfig(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_SELFPROT_STATUS:
            info = PryHandleSelfProtStatus(Request, &inner);
            st = inner;
            break;

        // SI adoption feature #6 — handle duplicate / close-remote / compare.
        case PRY_IOCTL_HANDLE_DUP:
            info = PryHandleHandleDup(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_HANDLE_CLOSE_REMOTE:
            info = PryHandleHandleCloseRemote(Request, &inner);
            st = inner;
            break;
        case PRY_IOCTL_HANDLE_COMPARE:
            info = PryHandleHandleCompare(Request, &inner);
            st = inner;
            break;

        // SI adoption feature #9 — kernel-stack walk primitive.
        case PRY_IOCTL_STACKWALK:
            info = PryHandleThreadStackWalk(Request, &inner);
            st = inner;
            break;

        // SI adoption feature #3 — analyze-wait on thread.
        case PRY_IOCTL_THREAD_WAIT_INFO:
            info = PryHandleThreadWaitInfo(Request, &inner);
            st = inner;
            break;

        // slice 03 Feature 4 — KTHREAD.IrpList walker.
        case PRY_IOCTL_THREAD_IRP_LIST:
            info = PryHandleThreadIrpList(Request, &inner);
            st = inner;
            break;

        default:
            PryLog("unknown ioctl %x", IoControlCode);
            st = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
        PryLog("EXCEPT ioctl=%x st=%x", IoControlCode, st);
    }

    PrySelfProtLeaveCall();

    WdfRequestCompleteWithInformation(Request, st, info);
}
