"""Bugcheck + NTSTATUS name tables, fault-parameter decoding map.

Static lookup data for crash-dump interpretation. Codes that matter in
the lab (watchdog fires, verifier hits, the usual suspects); unknown
codes fall back to a ``0x%x`` rendering so the envelope stays honest
rather than inventing a name.
"""

from __future__ import annotations

from .offsets import DUMP_TYPES

# Bugcheck-name table — the codes that matter in the lab (watchdog
# fires, verifier hits, the usual suspects). Unknown codes fall back to
# "0x%x" so the envelope stays honest rather than inventing a name.
BUGCHECK_NAMES = {
    0x0001: "APC_INDEX_MISMATCH",
    0x000A: "IRQL_NOT_LESS_OR_EQUAL",
    0x001E: "KMODE_EXCEPTION_NOT_HANDLED",
    0x0024: "NTFS_FILE_SYSTEM",
    0x0027: "RDR_FILE_SYSTEM",
    0x002E: "DATA_BUS_ERROR",
    0x0035: "NO_MORE_IRP_STACK_LOCATIONS",
    0x003B: "SYSTEM_SERVICE_EXCEPTION",
    0x0044: "MULTIPLE_IRP_COMPLETE_REQUESTS",
    0x004D: "NO_PAGES_AVAILABLE",
    0x0050: "PAGE_FAULT_IN_NONPAGED_AREA",
    0x0051: "REGISTRY_ERROR",
    0x005A: "CRITICAL_SERVICE_FAILED",
    0x0074: "BAD_SYSTEM_CONFIG_INFO",
    0x0076: "PROCESS_HAS_LOCKED_PAGES",
    0x0077: "KERNEL_STACK_INPAGE_ERROR",
    0x007A: "KERNEL_DATA_INPAGE_ERROR",
    0x007B: "INACCESSIBLE_BOOT_DEVICE",
    0x007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0x007F: "UNEXPECTED_KERNEL_MODE_TRAP",
    0x008E: "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
    0x009C: "MACHINE_CHECK_EXCEPTION",
    0x009F: "DRIVER_POWER_STATE_FAILURE",
    0x00A0: "INTERNAL_POWER_ERROR",
    0x00A2: "MEMORY_IMAGE_CORRUPT",
    0x00A5: "ACPI_BIOS_ERROR",
    0x00AB: "SESSION_HAS_VALID_POOL_ON_EXIT",
    0x00BE: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
    0x00C1: "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION",
    0x00C2: "BAD_POOL_CALLER",
    0x00C4: "DRIVER_VERIFIER_DETECTED_VIOLATION",
    0x00C5: "DRIVER_CORRUPTED_EXPOOL",
    0x00CA: "PNP_DETECTED_FATAL_ERROR",
    0x00CB: "DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS",
    0x00CE: "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS",
    0x00D1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    0x00D5: "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
    0x00D8: "DRIVER_USED_EXCESSIVE_PTES",
    0x00DE: "POOL_CORRUPTION_IN_FILE_AREA",
    0x00E1: "WORKER_THREAD_RETURNED_AT_BAD_IRQL",
    0x00E2: "MANUALLY_INITIATED_CRASH",
    0x00E3: "RESOURCE_NOT_OWNED",
    0x00EA: "THREAD_STUCK_IN_DEVICE_DRIVER",
    0x00ED: "UNMOUNTABLE_BOOT_VOLUME",
    0x00EF: "CRITICAL_PROCESS_DIED",
    0x00F4: "CRITICAL_OBJECT_TERMINATION",
    0x00FC: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
    0x00FE: "BUGCODE_USB_DRIVER",
    0x0101: "CLOCK_WATCHDOG_TIMEOUT",
    0x0109: "CRITICAL_STRUCTURE_CORRUPTION",
    0x010D: "WDF_VIOLATION",
    0x010E: "VIDEO_MEMORY_MANAGEMENT_INTERNAL",
    0x0116: "VIDEO_TDR_FAILURE",
    0x0117: "VIDEO_TDR_TIMEOUT_DETECTED",
    0x0119: "VIDEO_SCHEDULER_INTERNAL_ERROR",
    0x0124: "WHEA_UNCORRECTABLE_ERROR",
    0x012B: "FAULTY_HARDWARE_CORRUPTED_PAGE",
    0x0133: "DPC_WATCHDOG_VIOLATION",
    0x0138: "GPIO_CONTROLLER_DRIVER_ERROR",
    0x0139: "KERNEL_SECURITY_CHECK_FAILURE",
    0x013A: "KERNEL_MODE_HEAP_CORRUPTION",
    0x0141: "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE",
    0x0142: "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL",
    0x014F: "PDC_WATCHDOG_TIMEOUT",
    0x015E: "BUGCODE_NDIS_DRIVER_ERROR",
    0x018B: "SECURE_KERNEL_ERROR",
    0x0190: "WIN32K_CRITICAL_FAILURE",
    0x019C: "WIN32K_POWER_WATCHDOG_TIMEOUT",
    0x01A2: "WIN32K_CALLOUT_WATCHDOG_BUGCHECK",
    0x01C4: "DRIVER_VERIFIER_DETECTED_VIOLATION_LIVEDUMP",
    0x01C7: "STORE_DATA_STRUCTURE_CORRUPTION",
    0x01C8: "MANUALLY_INITIATED_POWER_BUTTON_HOLD",
    0x01CC: "INVALID_MDL_RANGE",
    0x1000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
    0x1000008E: "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M",
}

# NTSTATUS names for the MDMP "bugcheck-equivalent" exception code.
NTSTATUS_NAMES = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0x80000003: "STATUS_BREAKPOINT",
    0x80000004: "STATUS_SINGLE_STEP",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    0xC000008E: "STATUS_FLOAT_DIVIDE_BY_ZERO",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0xC0000095: "STATUS_INTEGER_OVERFLOW",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xE0434352: "CLR_EXCEPTION",
}

# Per-bugcheck-class param decoding: which params hold the faulting
# address (the memory operand) and the faulting PC, when the class has a
# documented layout. Anything not listed gets the generic
# exception.address -> context.rip fallback.
_FAULT_PARAM_MAP = {
    # {memory referenced, IRQL, access type, faulting instruction}
    0x000A: {"faulting_va": 0, "faulting_pc": 3},
    0x00D1: {"faulting_va": 0, "faulting_pc": 3},
    # {memory referenced, access type, faulting instruction, reserved}
    0x0050: {"faulting_va": 0, "faulting_pc": 2},
    0x00D5: {"faulting_va": 0, "faulting_pc": 2},
    # {exception code, address where exception occurred, exc record, ctx}
    0x001E: {"faulting_va": 1, "faulting_pc": 1},
    0x007E: {"faulting_va": 1, "faulting_pc": 1},
    0x008E: {"faulting_va": 1, "faulting_pc": 1},
    # {exception code, exception record addr, context addr, 0}
    0x003B: {"faulting_va": 1, "faulting_pc": 1},
    # {list/corruption type, related address, ...}
    0x0139: {"faulting_va": 1},
    # {failed object/process address, ...}
    0x00EF: {"faulting_va": 0},
    0x00F4: {"faulting_va": 1},
    # CLOCK_WATCHDOG: {PRCB addr of hung processor, ...} is the only
    # useful address; treat p1 as the interesting VA.
    0x0101: {"faulting_va": 1},
    # DPC_WATCHDOG: p4 is the hung DPC's stack/driver for type 0.
    0x0133: {"faulting_va": 3},
}

_PRY_WATCHDOG_CODE = 0xE2


def bugcheck_name(code: int) -> str:
    return BUGCHECK_NAMES.get(code, "0x%x" % code)


def dump_type_name(code: int) -> str:
    return DUMP_TYPES.get(code, "unknown_0x%x" % code)
