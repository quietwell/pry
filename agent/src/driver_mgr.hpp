#pragma once

#include "../src/config.hpp"
#include "../../comm/pry_comm.h"

#include <memory>
#include <string>
#include <vector>

namespace pry {

// broker between gRPC services and the driver; also owns service-load and
// manual-map launch paths
class DriverMgr {
public:
    explicit DriverMgr(const AgentConfig& cfg) : cfg_(cfg) {}

    struct SysInfo {
        PingInfo ping{};
        bool loaded = false;
        bool service = false;
    };

    SysInfo Query();
    std::string LoadService();       // returns error or "" on success
    std::string UnloadService(bool delete_service = true);
    std::string ManualMap(UINT32 pid);

    Driver& Comm() { return drv_; }

private:
    std::string GateAfterLoad();

    const AgentConfig& cfg_;
    Driver drv_;
};

// executes the driver exerciser's selftest + ping matrix against the freshly
// loaded driver before the agent reports it ready
std::string RunDriverGate(DriverMgr& mgr);

} // namespace pry
