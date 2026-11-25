/*
 * comm/abi/version.h — ABI version macros, device-type, PRY_IOCTL
 * CTL_CODE wrapper, PING function code/IOCTL/flags and PRY_PING_OUT.
 *
 * Part of the pry wire ABI; see comm/pry_abi.h.
 * Fixed-layout, no pointers, no C++. Any change here is a breaking ABI
 * change: bump PRY_ABI_VERSION and the driver epoch.
 */

#ifndef PRY_ABI_VERSION_H
#define PRY_ABI_VERSION_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
// windows.h first: TUs may include this header before any OS header, and
// winioctl.h cannot be parsed without the winnt.h type definitions.
#include <windows.h>
#include <winioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ABI revisions. PRY_ABI_VERSION below is the current revision; the driver
// reports it via PING and agents / the orchestrator gate features on it.
// Unless a revision says otherwise it is additive: older agents keep working
// against a newer driver (they simply never send the new codes).
//
// 2:  CTX_SET moved to the combined input layout [hdr][CONTEXT];
//     PRY_MODULES_IN gained Flags (WoW64 walk); VAD + HANDLE_LIST IOCTLs added.
// 4:  PHYS_RANGES + POOL_SCAN IOCTLs; PhysMemRead reworked (MmCopyMemory first,
//     per-call MmGetPhysicalMemoryRanges re-query).
// 5:  PHYS_MEM_WRITE is opt-in via PRY_MEM_FLAG_ALLOW_MAP_WRITE and fault
//     tolerant (per-4KB skip + STATUS_PARTIAL_COPY instead of aborting on the
//     first unmappable page). No struct layout changes.
// 6:  PRY_MEM_FLAG_PARTIAL on kernel READ (per-4KB walk, stop at the first
//     hole, return the valid prefix as STATUS_PARTIAL_COPY). HW-BP SET honours
//     pid=0 as system-wide (arm every existing thread of every process;
//     PsSetCreateThreadNotifyRoutine catches newborns), gated by
//     PRY_BP_HW_FLAG_GLOBAL and a per-BP cap. No struct layout changes; old
//     drivers ignore the new flag bits.
// 7:  No driver-side struct changes. Gates agent/comm surfaces built on the
//     existing IOCTL set:
//       * VA_TRANSLATE (0x857) is first-class over gRPC (Memory.VaTranslate).
//       * Memory.Watch (agent-side polling, in-agent threads only) uses the
//         existing MEM_READ paths.
//       * Files.LogTail + kernel-log rotation live entirely in the agent
//         process (Win32 CreateFile/SetFilePointerEx), no driver IOCTL.
//       * StatusResponse.agent_uptime_ms + RunExeResponse.killed populated.
//     Older drivers still pair with a newer agent (the agent gates the new
//     surfaces on comm/proto only).
// 8:  Wedge-detector watchdog. Four IOCTLs (WATCHDOG_ARM/KICK/DISARM/LIST)
//     driven by a driver-side system thread at HIGH_PRIORITY that
//     KeBugCheckEx()'s the target when a caller-armed deadline passes without
//     a kick. Turns silent wedges into analyzable dumps + auto-reboots, with
//     no PatchGuard-sensitive kernel .text hooks. The Files.LogFollow
//     server-streaming RPC (agent-only, no driver call) rides along.
// 10: Agent "ears" + kernel eyes. Six additive IOCTLs:
//       NOTIFY_SUBSCRIBE/READ/DISABLE/STATS (0x8A0-0x8A3): the driver
//       registers PsSet{CreateProcess,CreateThread,LoadImage}NotifyRoutine
//       and rings fixed-size events into a bounded overwrite-oldest ring
//       (never blocks the notifying thread; overflow bumps a dropped counter
//       the reader surfaces as gap evidence).
//       OBJ_ENUM (0x8A4): kernel object-directory enumeration via
//       ZwOpenDirectoryObject + ZwQueryDirectoryObject - no
//       _OBJECT_DIRECTORY struct offsets. Depth cap 2, entry cap 4096.
//       THREAD_LIST (0x8A5): kernel SystemProcessInformation walk enriched
//       per-thread with ZwQueryInformationThread(ThreadBasicInformation ->
//       TebBaseAddress, ThreadQuerySetWin32StartAddress) - both documented
//       info classes, no ETHREAD offset drift.
// 11: Kernel HW-BP hit observability. Two additive changes (old agents just
//     never request the class):
//       * PRY_EVT grows a BP_HIT tail (Address/Dr6/BpId/Slot/Access/Irql)
//         and a new kind PRY_EVT_KIND_BP_HIT=6 under a new subscription
//         class PRY_EVT_CLASS_BP=0x8. The ring drains through the existing
//         NOTIFY_READ/STATS IOCTLs - no new function codes.
//       * NOTIFY_SUBSCRIBE_IN.Reserved -> Flags (same layout). CLASS_BP is
//         only honored when the caller passes PRY_NOTIFY_FLAG_BP_HOOK_OK:
//         subscribing it installs a per-CPU IDT[1] hook (BpTrap.c) that
//         consumes #DB hits matching the armed HW-BP table, records
//         DR6/RIP/tid into the ring, sets RF, and resumes - the "hits only
//         observable with an attached kd" gap. IDT patching is PatchGuard
//         territory and refused outright when HVCI is on; the flag is the
//         explicit lab consent bit, mirroring BP_HW_FLAG_DANGEROUS_OK.
// 12: Write-path visibility + foreign-CR3 ops + IDT dump.
//       * MEM_WRITE gains an optional extended header (PRY_MEM_WRITE_IN,
//         marker-gated via the old Reserved slot) carrying Cr3 + Flags2, and
//         an optional PRY_MEM_WRITE_OUT reply {Status, WritePath, Done}.
//         Kernel writes report which store ran: direct VA, phys-remap
//         fallback, or foreign-CR3 - the remap silently bypassed DR
//         watchpoints on the linear address, and callers had no way to know.
//         PRY_MEM_WRF_STRICT_VA refuses the fallback (fault ->
//         STATUS_INVALID_ADDRESS). Cr3 != 0 swaps the IOCTL thread into that
//         address space for the copy (kernel-write only; the driver verifies
//         the foreign tables share the kernel half and pre-faults every dst
//         page at DISPATCH first - rejected cr3 -> STATUS_INVALID_PARAMETER,
//         unmapped dst -> STATUS_INVALID_ADDRESS).
//       * VA_TRANSLATE_IN grows Cr3 + Pid; VA_TRANSLATE_OUT grows
//         PageSizeShift + Cr3 (the walk runs under an explicit CR3 or a
//         target process's tables via KeStackAttachProcess - USER-space
//         translation).
//       * IDT_LIST (0x8A6, OUT_DIRECT): driver-side per-CPU __sidt walk,
//         decoded KIDTENTRY64 rows + per-row IDTR base.
// 13: Synchronous kernel function call - WDF work-item thunk at PASSIVE_LEVEL
//     in System context; SEH-guarded rax + exception capture, KEVENT
//     completion with caller timeout. One in-flight call at a time (the
//     control queue is sequential).
// 14: HW-watchpoint-backed mem_rw watch. Additive on top of
//     PRY_FUNC_BP_HW_SET/BP_HW_CLEAR:
//       * PRY_BP_HW_SET_IN.Flags gains PRY_BPHW_FLAG_IS_WATCH / _PREEMPT_OK
//         (watch marker + optional eviction of an older IS_WATCH entry when
//         every DR slot is spoken for).
//       * PRY_BP_HW_SET_IN.Slot accepts PRY_BP_HW_SLOT_AUTO (0xFF) to let the
//         driver pick a free DR slot per (pid, tid).
//       * PRY_EVT grows a UINT32 WatchCookie tail - length-prefixed read:
//         agents built against 13 see a short record and still parse the
//         earlier fields correctly, agents at 14+ read the extra 4 bytes.
//       * PRY_BP_ENTRY repurposes its 7 Reserved tail bytes to carry
//         IsWatch + a UINT32 WatchCookie so bp_list surfaces watch rows.
//       * PING.Flags gains PRY_FLAG_WATCH_HVCI_FALLBACK - set when the
//         driver's int1 hook refuses install (HVCI on, hypervisor desc-table
//         exiting, ...). The DR slots still arm, but hits don't ring; the
//         orchestrator must fall back to its agent-side polling path.
// 15: Pending-IRP column + WAIT_INFO slot.
//       * PRY_FUNC_THREAD_IRP_LIST (0x8A7, METHOD_OUT_DIRECT) + the
//         PRY_IRP_LIST_HDR / PRY_IRP_LIST_ENTRY structs in comm/abi/proc.h.
//         The driver walks KTHREAD.IrpList under IoCancelSpinLock discipline;
//         the agent-side fan-out happens from
//         thread_manage(action='list', include_pending_irp=True).
//       * PRY_FUNC_THREAD_WAIT_INFO (0x8A8) + PRY_WAIT_INFO_IN /
//         PRY_WAIT_INFO_HDR - the IOCTL slot is live but the driver returns
//         STATUS_NOT_SUPPORTED until dyn-data offsets are available.
// 16: ScanService RPC family. No driver-side changes. Additive on top of the
//     existing Memory service:
//       * ScanService (Create/Refine/Undo/Fetch/Cancel/Destroy/List/Status) -
//         on-target typed-value scanner with snapshot + next_scan + disk spill
//         (<agent_dir>\scans\).
//       * StatusResponse.scan_service_version - the agent advertises
//         ScanService support (0 = not supported).
// 17: PointerMapService + DissectService. Pointer map snapshot + reverse scan +
//     diff; typed one-shot dissector. StatusResponse.pointer_map_version
//     advertises support (0 = not supported).
#define PRY_ABI_VERSION 17

#define PRY_DEVICE_TYPE 0x00008325
#define PRY_DRV_VERSION_MAJOR 1
// Driver revision reported by PING (MAJOR.MINOR). The minor distinguishes
// driver builds with an identical wire shape but different behaviour, so a
// field target's Ping() tells them apart without a wire probe:
//   * watchdog runner is a periodic timer DPC (it was a HIGH_PRIORITY thread);
//   * partial reads complete STATUS_SUCCESS + short *Done instead of
//     STATUS_PARTIAL_COPY (the warning NTSTATUS failed the usermode
//     DeviceIoControl and dropped the valid prefix);
//   * notify ring + obj_enum + thread_list IOCTLs;
//   * BP_HIT ring records + per-CPU int1 hook behind
//     NOTIFY_SUBSCRIBE(CLASS_BP, FLAG_BP_HOOK_OK);
//   * ext mem-write header (write_path + STRICT_VA + cr3), VA_TRANSLATE
//     pid/cr3 + USER walks, IDT_LIST;
//   * KERNEL_CALL - synchronous kernel function call;
//   * PRY_MEM_FLAG_ALLOW_OUT_OF_RAM gates physical reads against RAM ranges;
//     default-deny with STATUS_ACCESS_DENIED (flag bit only, no layout change);
//   * HW-watchpoint-backed watch (PRY_BP_REC IsWatch/WatchCookie, PRY_EVT
//     WatchCookie tail, PRY_FLAG_WATCH_HVCI_FALLBACK PING bit,
//     PRY_BP_HW_SLOT_AUTO auto-slot allocation).
#define PRY_DRV_VERSION_MINOR 8

// own function-code range, never borrowed from any third-party driver
#define PRY_FUNC_PING 0x830

#define PRY_IOCTL(func, method, access) CTL_CODE(PRY_DEVICE_TYPE, func, method, access)

#define PRY_IOCTL_PING PRY_IOCTL(PRY_FUNC_PING, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ping flags
#define PRY_FLAG_TESTSIGNING 0x1
#define PRY_FLAG_HVCI 0x2
#define PRY_FLAG_SECUREBOOT 0x4
#define PRY_FLAG_KERNEL_DEBUGGER 0x8
// The driver would honour PRY_BPHW_FLAG_IS_WATCH's DR arming, but the int1
// trap hook that turns #DB into a ring record cannot install under HVCI (IDT
// page is EPT-RO) or when a hypervisor intercepts descriptor-table ops. Agents
// must fall back to orchestrator-side polling (mem_rw watch's original
// behaviour) whenever this bit is set.
#define PRY_FLAG_WATCH_HVCI_FALLBACK 0x10

typedef struct _PRY_PING_OUT {
    UINT32 VersionMajor;
    UINT32 VersionMinor;
    UINT32 NtBuild;
    UINT32 Flags;
    UINT32 AbiVersion;
    UINT32 Reserved;
} PRY_PING_OUT, *PPRY_PING_OUT;

#ifdef __cplusplus
}
#endif

#endif // PRY_ABI_VERSION_H
