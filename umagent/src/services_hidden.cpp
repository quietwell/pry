// umagent/src/services_hidden.cpp — SI #2 hidden-process gRPC (umagent)
//
// Standalone umagent-side HiddenProcess.Scan service. Delegates to the
// shared pry::host::ScanHiddenProcesses scanner (brute / registry /
// ETW passes), identical to the agent view. The orchestrator picks
// which view answers via the usual ``name=`` kwarg — on an umagent-only
// box this makes hidden-process detection fully driver-free.
//
// Slice doc: an internal plan
// §Feature 2.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#include <cstring>
#include <string>

#include "um_services.hpp"
#include "hidden_proc.hpp"

namespace um {

namespace {

grpc::Status CheckAuthHidden(grpc::ServerContext* ctx,
                              const std::string& token)
{
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

bool AnyMode(const pry::HiddenProcessRequest& req, const char* name)
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

class UmHiddenProcessSvc final : public pry::HiddenProcess::Service {
public:
    explicit UmHiddenProcessSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Scan(grpc::ServerContext* ctx,
                      const pry::HiddenProcessRequest* req,
                      pry::HiddenProcessResponse* resp) override
    {
        auto auth = CheckAuthHidden(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        pry::host::HiddenScanRequest sreq;
        sreq.pid_max = req->pid_max();
        sreq.step = req->step();
        sreq.timeout_ms = req->timeout_ms();
        bool any_requested = req->modes_size() > 0;
        sreq.do_brute    = !any_requested || AnyMode(*req, "brute");
        sreq.do_registry = !any_requested || AnyMode(*req, "registry");
        sreq.do_etw      = !any_requested || AnyMode(*req, "etw");

        pry::host::HiddenScanResult out;
        std::string err;
        if (!um::ScanHiddenProcesses(sreq, &out, &err)) {
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
    const Config& cfg_;
};

void RegisterHiddenProcessService(grpc::ServerBuilder& builder,
                                   const Config& cfg)
{
    static UmHiddenProcessSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
