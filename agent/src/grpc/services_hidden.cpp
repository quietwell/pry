// SI Wave 1 feature #2: hidden-process detection gRPC surface.
//
// Standalone service that runs the three Wave 1 PID oracles
// (brute / registry / ETW) via the shared pry::host::ScanHiddenProcesses
// scanner. Driver-free: the modes are all usermode APIs so the agent
// view answers even when the driver is absent. CSRSS mode (Wave 2)
// lands later; the stub TU agent/src/host/csrss_scan.cpp is empty on
// purpose. See an internal plan
// 04-umagent-orchestrator.md §Feature 2.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include <algorithm>
#include <string>
#include <vector>

#include "services.hpp"
#include "../host/hidden_proc.hpp"

namespace pry {

namespace {

bool AnyMode(const HiddenProcessRequest& req, const char* name)
{
    for (int i = 0; i < req.modes_size(); ++i) {
        const std::string& m = req.modes(i);
        if (m.size() != std::strlen(name)) continue;
        bool eq = true;
        for (size_t j = 0; j < m.size(); ++j) {
            char a = (char)::tolower((unsigned char)m[j]);
            char b = (char)::tolower((unsigned char)name[j]);
            if (a != b) { eq = false; break; }
        }
        if (eq) return true;
    }
    return false;
}

}  // namespace

class HiddenProcessSvc final : public HiddenProcess::Service {
public:
    HiddenProcessSvc(const AgentConfig& cfg, DriverMgr& drv)
        : cfg_(cfg), drv_(drv) {}

    grpc::Status Scan(::grpc::ServerContext* ctx,
                      const HiddenProcessRequest* req,
                      HiddenProcessResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        host::HiddenScanRequest sreq;
        sreq.pid_max = req->pid_max();
        sreq.step = req->step();
        sreq.timeout_ms = req->timeout_ms();
        // Empty modes list means "run every Wave 1 mode"; otherwise
        // only the named ones.
        bool any_requested = req->modes_size() > 0;
        sreq.do_brute    = !any_requested || AnyMode(*req, "brute");
        sreq.do_registry = !any_requested || AnyMode(*req, "registry");
        sreq.do_etw      = !any_requested || AnyMode(*req, "etw");

        host::HiddenScanResult out;
        std::string err;
        if (!host::ScanHiddenProcesses(sreq, &out, &err)) {
            FillStatus(resp, err.empty()
                             ? std::string("hidden_proc: scan failed")
                             : err);
            return grpc::Status::OK;
        }

        resp->set_pid_max_used(out.pid_max_used);
        resp->set_step_used(out.step_used);
        for (const auto& m : out.modes_run) resp->add_modes_run(m);
        for (const auto& m : out.modes_failed) resp->add_modes_failed(m);
        for (const auto& r : out.rows) {
            auto* row = resp->add_rows();
            row->set_pid(r.pid);
            row->set_image(r.image);
            row->set_present_brute(r.present_brute);
            row->set_present_registry(r.present_registry);
            row->set_present_etw(r.present_etw);
            row->set_exit_time_100ns(r.exit_time_100ns);
            row->set_handle_count(r.handle_count);
            row->set_sources(r.sources);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterHiddenProcessService(grpc::ServerBuilder& builder,
                                   const AgentConfig& cfg,
                                   DriverMgr& drv)
{
    static HiddenProcessSvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

}  // namespace pry
