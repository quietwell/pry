// agent/src/grpc/services_dump.cpp — SI feature #14: ProcessDump gRPC service.
//
// Driver-free surface — PssCaptureSnapshot + MiniDumpWriteDump run
// entirely in user space, so the agent view answers without touching
// the pry driver for non-protected targets. PP (PP/PPL) targets
// surface a clean ``pp_target_requires_feature_23`` error until SI
// feature #23 (Wave 3) lands. The shared probe lives in
// agent/src/dump/process_dump.cpp (shared with the umagent-side
// service through a vendored CMake entry). See the slice plan at
// an internal plan
// §Feature 9 (README feature #14).

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include <windows.h>

#include <string>

#include "services.hpp"
#include "../dump/process_dump.hpp"

namespace pry {

class ProcessDumpSvc final : public ProcessDump::Service {
public:
    explicit ProcessDumpSvc(const AgentConfig& cfg) : cfg_(cfg) {}

    grpc::Status CreateDump(::grpc::ServerContext* ctx,
                            const ProcessDumpRequest* req,
                            ProcessDumpResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        pry::host::ProcessDumpRequest in{};
        in.pid = req->pid();
        in.flags = req->flags();
        in.output_path = req->output_path();
        in.use_snapshot = req->use_snapshot();

        pry::host::ProcessDumpResponse out{};
        pry::host::DumpProcess(in, &out);

        resp->set_path(out.path);
        resp->set_size(out.size);
        resp->set_sha256(out.sha256);
        resp->set_access_mask_used(out.access_mask_used);
        resp->set_snapshot_used(out.snapshot_used);
        resp->set_kind(out.kind);
        FillStatus(resp, out.ok ? "" : out.error);
        return grpc::Status::OK;
    }

    // live kernel dump. The agent view
    // never runs NtSystemDebugControl(SysDbgGetLiveKernelDump) because
    // the agent typically has the pry driver loaded and we'd rather
    // keep SysDbg off the driver's attack surface. Operators point the
    // call at the umagent view (name='user') where the call is
    // scoped. Clean 'not_supported' envelope keeps the fallback honest.
    grpc::Status CreateLiveKernelDump(::grpc::ServerContext* ctx,
                                      const CreateLiveKernelDumpRequest* /*req*/,
                                      CreateLiveKernelDumpResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        resp->set_kind("not_supported");
        resp->set_error_detail("agent-side CreateLiveKernelDump is "
                                "deferred; route via name='user'");
        FillStatus(resp, "live_kernel_dump: agent-side disabled — "
                          "use the umagent view (name='user')");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
};

void RegisterProcessDumpService(grpc::ServerBuilder& builder,
                                 const AgentConfig& cfg)
{
    static ProcessDumpSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace pry
