#pragma once

// light on purpose: no generated gRPC headers here. They are included as the
// FIRST header of each translation unit in services*.cpp — generated grpcpp
// headers must be parsed before windows.h, whose macros otherwise leak into
// the generated declarations (WriteConsole/ReadConsole/...).

#include "../config.hpp"
#include "../driver_mgr.hpp"
#include "../exec.hpp"
#include "../events.hpp"
#include "../dbg/dbg_session.hpp"
#include "../host/net_pin.hpp"

#include <string>
#include <string_view>

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>

namespace google {
namespace protobuf {
class Message;
}
} // namespace google

namespace grpc {
class ServerBuilder;
class ServerContext;
}

namespace pry {

grpc::Status CheckAuth(grpc::ServerContext* ctx, const std::string& token);
void FillStatus(google::protobuf::Message* msg, const std::string& err);

// driver ABI gate. Server-wide hook run by
// the auth processor for every authenticated call: FAILED_PRECONDITION for
// driver-only methods (abi_gate.hpp) while the loaded driver's ABI differs
// from PRY_ABI_VERSION; OK otherwise (including "no driver yet").
grpc::Status DriverAbiGate(DriverMgr& drv, std::string_view method);

// T1.1d phone-home: stable identity shared between the Status RPC and the
// agent_endpoint.json / POST /api/agent_report thread. Collocating them in
// one translation unit (services_agent.cpp) keeps the first-call-wins
// statics consistent so both paths report the same instance id and boot
// epoch for the lifetime of the process.
uint64_t BootEpochMs();
const std::string& AgentInstanceId();

void RegisterCoreServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                          ExecMgr& exec, host::NetPinMgr& netPin);
void RegisterFileExecServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                              ExecMgr& exec);
void RegisterRegistryService(grpc::ServerBuilder& builder, const AgentConfig& cfg);
// v8: driver-backed wedge-detector; refuses cleanly when the driver is absent.
void RegisterWatchdogService(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                             DriverMgr& drv);
// v11: Device.Ioctl (usermode actuator) + Telemetry (ETW query-only).
void RegisterDeviceServices(grpc::ServerBuilder& builder, const AgentConfig& cfg);
// v11: driver-backed notify event ring (the agent's "ears"); refuses
// cleanly when the driver is absent.
void RegisterEventsService(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                           DriverMgr& drv);
// PR#6 T3.2 (2026-10): driver-backed MSR / CPUID reader; refuses cleanly
// when the driver is absent.
void RegisterCpuService(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                        DriverMgr& drv);
// SI Wave 1 feature #1: image coherency scoring. Driver-free
// surface — the agent view routes mem reads through the driver only
// for PP targets. See agent/src/host/img_coherency.hpp.
void RegisterImageCoherencyService(grpc::ServerBuilder& builder,
                                    const AgentConfig& cfg,
                                    DriverMgr& drv);
// SI #21: ObRegisterCallbacks-driven driver self-protection
// toggle. Driver-backed; refuses cleanly ("driver_absent") when the
// driver isn't loaded. See driver/src/SelfProt.c.
void RegisterSelfProtService(grpc::ServerBuilder& builder,
                             const AgentConfig& cfg, DriverMgr& drv);
// SI Wave 1 feature #8: signer + Authenticode column.
// Driver-free surface — the probe runs entirely in user space
// (WinVerifyTrust + crypt32). See agent/src/host/sig_verify.hpp.
void RegisterSignaturesService(grpc::ServerBuilder& builder,
                                const AgentConfig& cfg);
// SI Wave 1 feature #14: process-snapshot minidump.
// Driver-free surface — PssCaptureSnapshot + MiniDumpWriteDump with a
// stepped access-mask ladder. PP targets wait for feature #23 (Wave 3)
// and surface ``pp_target_requires_feature_23`` until then. See
// agent/src/dump/process_dump.hpp.
void RegisterProcessDumpService(grpc::ServerBuilder& builder,
                                 const AgentConfig& cfg);
// SI Wave 1 feature #10: private kernel ETW session. Driver-
// free — ETW is NtAPI-level. See agent/src/etw/etw_session.hpp.
void RegisterEtwTraceService(grpc::ServerBuilder& builder,
                              const AgentConfig& cfg);
// SI Wave 1 feature #2: hidden-process detection. Three Wave 1
// modes (brute / registry / ETW); CSRSS mode is Wave 2 and lives
// behind the slice-1 HANDLE_LIST enrichment. Driver-free surface —
// pure usermode scanners. See agent/src/host/hidden_proc.hpp.
void RegisterHiddenProcessService(grpc::ServerBuilder& builder,
                                   const AgentConfig& cfg,
                                   DriverMgr& drv);
// SI Wave 1 feature #6: handle_dup / handle_close_remote /
// handle_compare primitives. Driver-backed; refuses cleanly
// ("driver_absent") when the pry driver isn't loaded.
void RegisterHandleOpsService(grpc::ServerBuilder& builder,
                              const AgentConfig& cfg, DriverMgr& drv);
// SI Wave 1 feature #9: kernel-stack walk primitive. Driver-
// backed (RtlWalkFrameChain under a kernel-mode APC on the target
// thread via PryRemoteCall). Refuses cleanly when the driver is absent.
void RegisterStackWalkService(grpc::ServerBuilder& builder,
                              const AgentConfig& cfg, DriverMgr& drv);

// Token / privilege / SID viewer + mutator.
// Phase 0 shell — every RPC returns grpc::Status::UNIMPLEMENTED until
// the P2 identity-policy slice fills them in. Agent-side registration
// mirrors the umagent service in umagent/src/um_services.hpp so a
// caller with the agent view routes transparently.
void RegisterTokenService(grpc::ServerBuilder& builder,
                          const AgentConfig& cfg, DriverMgr& drv);
// process-mitigation policy readout.
void RegisterMitigationsService(grpc::ServerBuilder& builder,
                                const AgentConfig& cfg, DriverMgr& drv);
// enhanced thread columns.
void RegisterThreadInspectService(grpc::ServerBuilder& builder,
                                  const AgentConfig& cfg, DriverMgr& drv);

void RegisterScanServiceAgent(grpc::ServerBuilder& builder,
                              const AgentConfig& cfg, DriverMgr& drv);
// v17 (Memory scanner wave 2): on-target pointer map + reverse scan +
// diff. Adapts ListUserModules + the Wave 1 MemReaderCtx-backed
// reader to the pointer-map service's injected callbacks.
void RegisterPointerMapServiceAgent(grpc::ServerBuilder& builder,
                                    const AgentConfig& cfg, DriverMgr& drv);
// v17 (Memory scanner wave 2): one-shot per-slot typed decode. Shares
// the same reader + module enumerator wiring.
void RegisterDissectServiceAgent(grpc::ServerBuilder& builder,
                                 const AgentConfig& cfg, DriverMgr& drv);

inline void RegisterServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                             ExecMgr& exec, host::NetPinMgr& netPin)
{
    RegisterCoreServices(builder, cfg, drv, exec, netPin);
    RegisterFileExecServices(builder, cfg, drv, exec);
    RegisterRegistryService(builder, cfg);
    RegisterWatchdogService(builder, cfg, drv);
    RegisterDeviceServices(builder, cfg);
    RegisterEventsService(builder, cfg, drv);
    RegisterCpuService(builder, cfg, drv);
    RegisterImageCoherencyService(builder, cfg, drv);
    RegisterSelfProtService(builder, cfg, drv);
    RegisterSignaturesService(builder, cfg);
    RegisterProcessDumpService(builder, cfg);
    RegisterEtwTraceService(builder, cfg);
    RegisterHiddenProcessService(builder, cfg, drv);
    RegisterHandleOpsService(builder, cfg, drv);
    RegisterStackWalkService(builder, cfg, drv);
    // skeletons — services register with every RPC
    // returning UNIMPLEMENTED; slice branches wire the bodies.
    RegisterTokenService(builder, cfg, drv);
    RegisterMitigationsService(builder, cfg, drv);
    RegisterThreadInspectService(builder, cfg, drv);
    // v16 Memory scanner wave 1: typed-value ScanService (Create/Refine/
    // Undo/Fetch/Cancel/Destroy/List/Status). On-target snapshot + disk
    // spill under <agent_dir>\scans\<view>.
    RegisterScanServiceAgent(builder, cfg, drv);
    // v17 Memory scanner wave 2: PointerMapService (map create + status +
    // list + cancel + save + load + destroy + reverse scan + diff).
    // Shares <agent_dir>\pointer_maps\<view>\ for disk mirror.
    RegisterPointerMapServiceAgent(builder, cfg, drv);
    // v17 Memory scanner wave 2: DissectService (per-slot typed decode).
    RegisterDissectServiceAgent(builder, cfg, drv);
}

// shared user-memory read: driver first, ReadProcessMemory fallback
struct MemReaderCtx {
    DriverMgr* drv = nullptr;
};
bool UserMemReadFn(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len);
// shared kernel-memory read: driver only, pid ignored
bool KernelMemReadFn(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len);

// module enumeration with driver-then-toolhelp fallback
bool ListUserModules(DriverMgr* drv, UINT32 pid, std::vector<pry::ModuleEntry>* out);

// case-insensitive basename-or-full-path module lookup (see DumpModule in
// services2.cpp for the reference pattern); returns 0 when not found
// canonical UTF-16 -> UTF-8 for proto3 string fields. The old
// `std::string(w.begin(), w.end())` idiom dropped the high byte of each
// WCHAR; modern protobuf-cpp silently refuses to serialize a proto3
// string with invalid UTF-8, which drops the whole response and shows
// up on the Python side as resp=None with StatusCode.OK.
std::string WideToUtf8(const std::wstring& w);
std::string BasenameLower(const std::string& p);
UINT64 FindModuleBase(const std::vector<pry::ModuleEntry>& mods,
                      const std::string& want);
std::string FindOwningModule(const std::vector<pry::ModuleEntry>& mods, UINT64 addr);

} // namespace pry
