#pragma once

// light on purpose: no generated gRPC headers here (same rule as the agent's
// services.hpp — they are included as the FIRST headers of um_services.cpp).

#include <cstdint>
#include <string>

#include "build_version.h"

namespace google {
namespace protobuf {
class Message;
}
} // namespace google

namespace grpc {
class ServerBuilder;
class ServerContext;
class Status;
}

namespace um {

struct Config {
    std::string bind = "127.0.0.1"; // localhost-only by default: same-host parity view
    int port = 50075;
    std::string token;
    std::string version = "0.0.0+" PRY_GIT_SHA PRY_GIT_DIRTY;
    uint64_t maxReadBytes = 8ull << 20;
};

void FillStatus(google::protobuf::Message* msg, const std::string& err);

// SI #1 feature registered from services_coherency.cpp; the main
// RegisterServices() below pulls it in.
void RegisterImageCoherencyService(grpc::ServerBuilder& builder,
                                    const Config& cfg);

// SI #8 signer / Authenticode column registered from services_sig.cpp.
void RegisterSignaturesService(grpc::ServerBuilder& builder,
                                const Config& cfg);

// SI #10 private kernel ETW session registered from services_etw.cpp.
void RegisterEtwTraceService(grpc::ServerBuilder& builder,
                              const Config& cfg);

// SI #14 process-snapshot minidump registered from services_dump.cpp.
// Driver-free surface — PssCaptureSnapshot + MiniDumpWriteDump with a
// stepped access-mask ladder. PP targets wait for feature #23 (Wave 3).
void RegisterProcessDumpService(grpc::ServerBuilder& builder,
                                 const Config& cfg);

// SI #2 hidden-process detection registered from services_hidden.cpp
// (Wave 1 modes: brute / registry / ETW). Pure usermode scanners,
// shared TU with the agent-side service.
void RegisterHiddenProcessService(grpc::ServerBuilder& builder,
                                   const Config& cfg);

// skeletons. Each service registers with every RPC
// returning grpc::Status::UNIMPLEMENTED until its slice branch wires
// the implementation. Agent-side mirrors are declared in
// agent/src/grpc/services.hpp.
void RegisterTokenService(grpc::ServerBuilder& builder, const Config& cfg);
void RegisterMitigationsService(grpc::ServerBuilder& builder, const Config& cfg);
void RegisterNetworkService(grpc::ServerBuilder& builder, const Config& cfg);
void RegisterServicesService(grpc::ServerBuilder& builder, const Config& cfg);
void RegisterThreadInspectService(grpc::ServerBuilder& builder, const Config& cfg);

// desktop input injection (SendInput-backed Click / Type / Key).
// Session 1 only — the session-0 agent service cannot reach the user
// desktop. Actuator-trust gated on the orchestrator (capabilities
// registry entries carry gate='min_trust_actuator'); per-RPC bearer
// token is checked here.
void RegisterInputService(grpc::ServerBuilder& builder, const Config& cfg);

void RegisterServices(grpc::ServerBuilder& builder, const Config& cfg);

} // namespace um
