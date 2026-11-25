#include "PryDriver.h"

// v13: control device handle shared with KernelCall.c (work-item parent).
// Defined here, declared extern in PryDriver.h.
WDFDEVICE PryDevice = WDF_NO_HANDLE;

// admin/SYSTEM-only SDDL (kernel+system+admins full control, others denied)
static const WCHAR PrySddlString[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
static const UNICODE_STRING PrySddl = {
    sizeof(PrySddlString) - sizeof(WCHAR), sizeof(PrySddlString), (PWCH)PrySddlString
};

// Non-PnP control device: \\.\PryDrv with admin/SYSTEM-only SDDL and a
// sequential default queue (all IOCTL handlers therefore run at PASSIVE_LEVEL
// and are serialized, which the breakpoint/APC tables rely on).

NTSTATUS PryCreateControlDevice(_In_ WDFDRIVER Driver)
{
    NTSTATUS st;
    PWDFDEVICE_INIT init;
    WDF_IO_QUEUE_CONFIG queueCfg;
    UNICODE_STRING devName;
    UNICODE_STRING symName;
    WDF_OBJECT_ATTRIBUTES attrs;

    RtlInitUnicodeString(&devName, PRY_DEVICE_NAME);
    RtlInitUnicodeString(&symName, PRY_SYMLINK_NAME);

    init = WdfControlDeviceInitAllocate(Driver, &PrySddl);
    if (!init) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(init, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(init, FALSE);

    st = WdfDeviceInitAssignName(init, &devName);
    if (!NT_SUCCESS(st)) {
        WdfDeviceInitFree(init);
        return st;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    st = WdfDeviceCreate(&init, &attrs, &PryDevice);
    if (!NT_SUCCESS(st)) {
        WdfDeviceInitFree(init);
        return st;
    }

    st = WdfDeviceCreateSymbolicLink(PryDevice, &symName);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueCfg, WdfIoQueueDispatchSequential);
    queueCfg.EvtIoDeviceControl = PryEvtIoDeviceControl;
    // the kernel-read fallback faults pageable pages in — only legal at
    // PASSIVE_LEVEL, so pin all queue callbacks there
    WDF_OBJECT_ATTRIBUTES_INIT(&attrs);
    attrs.ExecutionLevel = WdfExecutionLevelPassive;
    st = WdfIoQueueCreate(PryDevice, &queueCfg, &attrs, WDF_NO_HANDLE);
    if (!NT_SUCCESS(st)) {
        PryLog("queue create failed st=%x", st);
        return st;
    }

    WdfControlFinishInitializing(PryDevice);
    PryLog("device ready abi=%u drv=%u.%u build=" __DATE__ " " __TIME__,
             PRY_ABI_VERSION, PRY_DRV_VERSION_MAJOR, PRY_DRV_VERSION_MINOR);
    return STATUS_SUCCESS;
}
