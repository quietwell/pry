#pragma once

// umagent/src/services_input.hpp — desktop input injection.
//
// SendInput-backed Click / Type / Key RPCs on the umagent view
// (session 1). The session-0 agent service cannot serve these — a
// SendInput call from the service session never reaches the user
// desktop.

namespace grpc { class ServerBuilder; }

namespace um {

struct Config;

// Register the gRPC Input service (Click / Type / Key) on `builder`.
// Wired from RegisterServices() in um_services.cpp.
void RegisterInputService(grpc::ServerBuilder& builder, const Config& cfg);

}  // namespace um
