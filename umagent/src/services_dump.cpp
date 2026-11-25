// umagent/src/services_dump.cpp — SI #14: process-snapshot minidump gRPC
//
// Standalone umagent-side ProcessDump.CreateDump service. The probe is
// driver-free (PssCaptureSnapshot + MiniDumpWriteDump), so this
// surface answers identically to the agent-side service — only the
// hosting process differs. The shared implementation (and ladder)
// lives in agent/src/dump/process_dump.cpp, which umagent pulls in
// through its CMakeLists.txt. See the slice plan at
// §Feature 9 (README feature #14).
//
// PP (PP/PPL) targets are deferred to SI feature #23 (Wave 3) — the
// shared probe surfaces ``pp_target_requires_feature_23`` rather than
// reaching for undocumented tactics.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#include <windows.h>

#include <string>
#include <vector>

#include "um_services.hpp"
#include "dump/process_dump.hpp"
#include "dump/live_kernel_dump.hpp"

namespace um {

namespace {

grpc::Status CheckAuthDump(grpc::ServerContext* ctx,
                            const std::string& token)
{
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

}  // namespace

class UmProcessDumpSvc final : public pry::ProcessDump::Service {
public:
    explicit UmProcessDumpSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status CreateDump(grpc::ServerContext* ctx,
                            const pry::ProcessDumpRequest* req,
                            pry::ProcessDumpResponse* resp) override
    {
        auto auth = CheckAuthDump(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        um::ProcessDumpRequest in{};
        in.pid = req->pid();
        in.flags = req->flags();
        in.output_path = req->output_path();
        in.use_snapshot = req->use_snapshot();

        um::ProcessDumpResponse out{};
        um::DumpProcess(in, &out);

        resp->set_path(out.path);
        resp->set_size(out.size);
        resp->set_sha256(out.sha256);
        resp->set_access_mask_used(out.access_mask_used);
        resp->set_snapshot_used(out.snapshot_used);
        resp->set_kind(out.kind);
        FillStatus(resp, out.ok ? "" : out.error);
        return grpc::Status::OK;
    }

    // live kernel dump.
    //   NtSystemDebugControl(SysDbgGetLiveKernelDump) path lives in
    //   dump/live_kernel_dump.cpp (worker thread + cancel event +
    //   SeDebugPrivilege re-check per slice doc). The service entry
    //   just translates the proto <-> plain-C++ shape and reports.
    grpc::Status CreateLiveKernelDump(grpc::ServerContext* ctx,
                                      const pry::CreateLiveKernelDumpRequest* req,
                                      pry::CreateLiveKernelDumpResponse* resp) override
    {
        auto auth = CheckAuthDump(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        um::LiveKernelDumpRequest in{};
        in.output_path = req->output_path();
        in.compression = req->compression();
        in.allow_cancel = req->allow_cancel();
        in.flags.reserve((size_t)req->flags_size());
        for (int i = 0; i < req->flags_size(); ++i) {
            in.flags.emplace_back(req->flags(i));
        }

        um::LiveKernelDumpResponse out{};
        um::CreateLiveKernelDump(in, &out);

        resp->set_path(out.path);
        resp->set_size(out.size);
        resp->set_sha256(out.sha256);
        resp->set_flags_used_mask(out.flags_used_mask);
        for (const auto& u : out.flags_unknown) {
            resp->add_flags_unknown(u);
        }
        resp->set_kind(out.kind);
        resp->set_error_detail(out.error_detail);
        FillStatus(resp, out.ok ? "" : out.error);
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

void RegisterProcessDumpService(grpc::ServerBuilder& builder,
                                 const Config& cfg)
{
    static UmProcessDumpSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
