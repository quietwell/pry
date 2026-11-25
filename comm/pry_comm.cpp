// Facade TU for the split pry_comm library.
//
// Phase 7c of the modular-split plan moved every function out of this file
// into per-concern TUs (pry_comm_core / _mem / _ctx / _bp / _watchdog).
// What stays here is the ABI compile-time guards -- they belong to the
// library as a whole and this original path is the anchor callers see in
// build output. Callers keep including "pry_comm.h" (unchanged) and
// linking against the same pry_comm static target; no source-level or
// linker-visible name at the public boundary moved.
#include "pry_comm.h"

#include <cstddef>
#include <cstdint>

namespace pry {

// ABI guards: if any of these fire, pry_abi.h drifted between driver and
// user-mode builds and the IOCTL surface is incompatible.
static_assert(sizeof(PRY_PING_OUT) == 24, "ping out ABI");
static_assert(sizeof(PRY_MEM_REQ) == 32, "mem req ABI (v2: Flags)");
static_assert(sizeof(PRY_USER_ALLOC_IN) == 24, "alloc in ABI");
static_assert(sizeof(PRY_USER_ALLOC_OUT) == 16, "alloc out ABI");
static_assert(sizeof(PRY_MODULES_IN) == 24, "modules in ABI (v2: +Flags)");
static_assert(sizeof(PRY_MODULE_ENTRY) == 16 + PRY_MOD_NAME_CCH * 2 + PRY_MOD_PATH_CCH * 2,
              "module entry ABI");
static_assert(offsetof(PRY_MODULE_ENTRY, Name) == 16, "module entry layout");
static_assert(sizeof(PRY_CTX_HDR_OUT) == 8 + PRY_CONTEXT_SIZE, "ctx header ABI");
static_assert(sizeof(CONTEXT) == PRY_CONTEXT_SIZE, "CONTEXT size vs ABI");
static_assert(sizeof(PRY_BP_ENTRY) == 48, "bp entry ABI");
static_assert(offsetof(PRY_BP_ENTRY, Address) == 32, "bp entry layout");
static_assert(sizeof(PRY_REMOTE_CALL_IN) == 56, "remote call in ABI");
static_assert(sizeof(PRY_REMOTE_CALL_OUT) == 16, "remote call out ABI");
static_assert(sizeof(PRY_VAD_ENTRY) == 40, "vad entry ABI");
static_assert(sizeof(PRY_HANDLE_ENTRY) == 32 + PRY_HANDLE_TYPE_CCH * 2 + PRY_HANDLE_NAME_CCH * 2,
              "handle entry ABI");
// v4 (2026-09-06): PHYS_RANGES + POOL_SCAN wire structs. If any of these fire,
// pry_abi.h drifted after the v4 bump -- rebuild driver + comm + exerciser
// from the same pry_abi.h and bump PRY_ABI_VERSION if the layout was
// intentionally changed.
static_assert(sizeof(PRY_PHYS_RANGE_ENTRY) == 24,
              "ABI v4 phys-range entry size (expect Base+Size+Kind+Reserved = 24)");
static_assert(offsetof(PRY_PHYS_RANGE_ENTRY, Kind) == 16,
              "ABI v4 phys-range entry layout (Kind must follow Base+Size at offset 16)");
static_assert(sizeof(PRY_PHYS_RANGES_HDR) == 16,
              "ABI v4 phys-ranges header size (expect Status+Count+Required+Reserved = 16)");
// PRY_POOL_SCAN_IN gained a Cursor UINT32 (7 UINT32s
// total) and the pattern/mask arrays grew from 16 B to 64 B. HDR gained
// Holes/SpanTruncated/LastIndex/NextCursor (8 UINT32s total).
static_assert(sizeof(PRY_POOL_SCAN_IN) == 28 + PRY_POOL_PATTERN_MAX * 2,
              "ABI pool-scan input size (7*UINT32 + 2*Pattern[PRY_POOL_PATTERN_MAX])");
static_assert(offsetof(PRY_POOL_SCAN_IN, Pattern) == 24,
              "ABI pool-scan input layout (Pattern must follow the first six UINT32 fields at offset 24; Cursor sits after Mask)");
static_assert(sizeof(PRY_POOL_ENTRY) == 32,
              "ABI v4 pool entry size (expect VA+Size+Tag+NonPaged+MatchedOffset = 32)");
static_assert(offsetof(PRY_POOL_ENTRY, MatchedOffset) == 24,
              "ABI v4 pool entry layout (MatchedOffset must sit at offset 24)");
static_assert(sizeof(PRY_POOL_HDR) == 32,
              "ABI pool header size (Status+Count+Required+Considered+Holes+SpanTruncated+LastIndex+NextCursor = 32)");

// ABI v7 (2026-09-09): no driver-side struct changes - the bump gates the new
// agent/comm surfaces (gRPC VaTranslate/Watch/LogTail/detached, agent_uptime_ms,
// RunExe.killed). These pins stay so a header drift can't silently re-enable or
// renumber the flag bits.
// ABI v8 (2026-09-10): watchdog IOCTL set + Files.LogFollow. Struct guards
// pinned below. (A brief v9 added Windows Sandbox RPCs; withdrawn
// 2026-09-14 — version returns to 8.)
// ABI v10 (2026-09-20): notify event ring (NOTIFY_SUBSCRIBE/READ/DISABLE/
// STATS) + OBJ_ENUM + THREAD_LIST IOCTLs. No changes to existing structs;
// the bump gates the new agent surfaces.
// ABI v14 (2026-10-28): SI adoption Wave 1 — PRY_EVT grows WatchCookie,
// PRY_BP_HW_SET_IN.Flags gains PRY_BPHW_FLAG_IS_WATCH/_PREEMPT_OK,
// PRY_BP_HW_SLOT_AUTO sentinel, PING.Flags gains PRY_FLAG_WATCH_HVCI_FALLBACK,
// plus new IOCTL codes for SelfProt/HandleOps/StackWalk at 0x8E0-0x8E5.
// ABI v15 (2026-10-31): pending-IRP column —
// PRY_FUNC_THREAD_IRP_LIST (0x8A7) + PRY_IRP_LIST_HDR / _ENTRY.
// Carries SI #3 THREAD_WAIT_INFO (0x8A8) that landed late v14.
// ABI v16 (2026-11-12): Memory scanner wave 1 — new ScanService RPC
// family + StatusResponse.scan_service_version advert. No driver
// IOCTL / struct changes; the bump exists so the handshake gates
// orchestrator ⇄ agent compatibility cleanly.
// ABI v17 (2026-11-12): Memory scanner wave 2 — new PointerMapService
// + DissectService RPC families + StatusResponse.pointer_map_version
// advert. No driver IOCTL / struct changes; the bump exists so the
// handshake gates orchestrator ⇄ agent compatibility cleanly.
static_assert(PRY_ABI_VERSION == 17,
              "ABI v17 expected (Memory scanner wave 2 — PointerMapService + "
              "DissectService + StatusResponse.pointer_map_version)");
static_assert(sizeof(PRY_WDG_ARM_IN) == 24 + PRY_WDG_MAX_LABEL,
              "ABI v8 watchdog arm-in size (5 fields + Label[32])");
static_assert(offsetof(PRY_WDG_ARM_IN, Cookie) == 16,
              "ABI v8 watchdog arm-in layout (Cookie at offset 16)");
static_assert(offsetof(PRY_WDG_ARM_IN, Label) == 24,
              "ABI v8 watchdog arm-in layout (Label at offset 24)");
static_assert(sizeof(PRY_WDG_KICK_IN) == 16,
              "ABI v8 watchdog kick-in size (Id+DeadlineMs+Cookie)");
static_assert(sizeof(PRY_WDG_KICK_OUT) == 32,
              "ABI v8 watchdog kick-out size (Status+Reserved+KickCount+LastKickUs+DeadlineUs)");
static_assert(sizeof(PRY_WDG_LIST_HDR) == 24,
              "ABI v8 watchdog list header size (Status+Count+Required+Reserved+NowUs)");
static_assert(sizeof(PRY_WDG_ENTRY) == 48 + PRY_WDG_MAX_LABEL,
              "ABI v8 watchdog entry size (6 UINT64 + 2 UINT32 + Label[32])");
static_assert(PRY_MEM_FLAG_ALLOW_SOFTFAULT == 0x1,
              "ABI v7 ALLOW_SOFTFAULT must stay bit 0");
static_assert(PRY_MEM_FLAG_PARTIAL == 0x2,
              "ABI v7 PARTIAL must stay bit 1");
static_assert(PRY_MEM_FLAG_ALLOW_MAP_WRITE == 0x4,
              "ABI v7 ALLOW_MAP_WRITE must stay bit 2");
static_assert(sizeof(PRY_VA_TRANSLATE_IN) == 24,
              "ABI v12 va-translate input size (Va + Cr3 + Pid)");
static_assert(offsetof(PRY_VA_TRANSLATE_IN, Cr3) == 8,
              "ABI v12 va-translate layout (Cr3 occupies the old Reserved[2] slot)");
static_assert(sizeof(PRY_VA_TRANSLATE_OUT) == 24,
              "ABI v12 va-translate output size (Status+PageSizeShift+PhysicalAddress+Cr3)");
static_assert(offsetof(PRY_VA_TRANSLATE_OUT, PhysicalAddress) == 8,
              "ABI v12 va-translate layout (PhysicalAddress must stay at offset 8 for v11 callers)");
// ABI v12 (2026-09-25): extended mem-write header (marker in the old
// Reserved slot), write out-reply, per-CPU IDT enumeration structs.
static_assert(sizeof(PRY_MEM_WRITE_IN) == 48,
              "ABI v12 mem-write ext input (32B legacy prefix + Cr3 + Flags2 + Reserved)");
static_assert(offsetof(PRY_MEM_WRITE_IN, Cr3) == 32,
              "ABI v12 mem-write layout (Cr3 must tail the legacy 32-byte header)");
static_assert(offsetof(PRY_MEM_WRITE_IN, Flags) == 24,
              "ABI v12 mem-write layout (Flags must keep PRY_MEM_REQ's offset)");
static_assert(sizeof(PRY_MEM_WRITE_OUT) == 16,
              "ABI v12 mem-write output (Status + WritePath + Done)");
static_assert(sizeof(PRY_IDT_LIST_IN) == 8,
              "ABI v12 idt-list input (AllCpus + Reserved)");
static_assert(sizeof(PRY_IDT_ENTRY_ROW) == 48,
              "ABI v12 idt row (cpu/vector/handler/sel/ist/dpl/type/present/base)");
static_assert(sizeof(PRY_IDT_LIST_HDR) == 24,
              "ABI v12 idt-list header (Status/Count/Required/IdtLimit/IdtBase)");
// SI #3 analyze-wait on thread. Any change to these structs is
// a wire break — bump PRY_ABI_VERSION and the driver epoch.
static_assert(sizeof(PRY_WAIT_INFO_IN) == 24,
              "ABI wait-info input (Tid + FrameCapture + UserStackCapture + Flags + Reserved)");
static_assert(sizeof(PRY_WAIT_INFO_HDR) == 80,
              "ABI wait-info header (Status+Pid + 5*UINT64 + 4*UINT32 wait block + 4*UINT32 tail)");
static_assert(offsetof(PRY_WAIT_INFO_HDR, KernelStackTop) == 8,
              "ABI wait-info header layout (KernelStackTop must follow Status/Pid at offset 8)");
static_assert(offsetof(PRY_WAIT_INFO_HDR, WaitReason) == 48,
              "ABI wait-info header layout (WaitReason starts the wait block at offset 48)");
// v15 (SI #3 Feature 4): pending-IRP walk structs. Any layout change
// is a wire break — bump ABI and the driver epoch.
static_assert(sizeof(PRY_IRP_LIST_IN) == 16,
              "ABI v15 irp-list input (Tid + Reserved + MaxEntries = 16)");
static_assert(sizeof(PRY_IRP_LIST_HDR) == 24,
              "ABI v15 irp-list header (Status+Pid+Count+Required+Truncated+Reserved)");
static_assert(sizeof(PRY_IRP_LIST_ENTRY) == 48 + PRY_IRP_DEVICE_NAME_CCH * 2,
              "ABI v15 irp-list entry (4*UINT64 + 4*UINT32 + Wchar[48])");
static_assert(offsetof(PRY_IRP_LIST_ENTRY, DeviceName) == 48,
              "ABI v15 irp-list entry layout (DeviceName at offset 48)");

} // namespace pry
