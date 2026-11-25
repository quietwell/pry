// SI adoption feature #21 — SelfProt gRPC surface. Forwards to the driver
// via DriverMgr::Comm() (Driver::SelfProtConfig/Status). Agent-side state
// is zero: the driver's ERESOURCE-guarded config block is the source of
// truth. Shape mirrors services_watchdog.cpp.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include "services.hpp"

#include <string>

namespace pry {

static bool ProbeDriver(DriverMgr& drv, std::string* err)
{
    if (drv.Comm().IsOpen()) return true;
    if (!drv.Comm().Open()) {
        *err = "driver_absent: " + drv.Comm().LastError();
        return false;
    }
    return true;
}

class SelfProtSvc final : public SelfProt::Service {
public:
    SelfProtSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Config(::grpc::ServerContext* ctx,
                        const SelfProtConfigRequest* req,
                        SelfProtConfigResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }

        PRY_SELFPROT_CONFIG_IN in{};
        in.Enable = req->enable();
        in.Flags = req->flags();
        in.ProcessAccessKeep = req->process_access_keep();
        in.ThreadAccessKeep = req->thread_access_keep();
        in.DisableToken = req->disable_token();
        UINT32 n = 0;
        for (int i = 0; i < req->protected_pids_size() &&
                        n < PRY_SELFPROT_MAX_PIDS; i++) {
            UINT32 pid = req->protected_pids(i);
            if (pid) in.ProtectedPids[n++] = pid;
        }
        in.PidCount = n;

        PRY_SELFPROT_CONFIG_OUT out{};
        bool ok = drv_.Comm().SelfProtConfig(in, &out);
        resp->set_state(out.State);
        resp->set_installed(out.Installed != 0);
        resp->set_altitude(out.Altitude);
        resp->set_protected_pids(out.ProtectedPids);
        resp->set_disable_token(out.DisableToken);
        if (!ok) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Status(::grpc::ServerContext* ctx,
                        const SelfProtStatusRequest* /*req*/,
                        SelfProtStatusResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        PRY_SELFPROT_STATUS_OUT out{};
        if (!drv_.Comm().SelfProtStatus(&out)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_state(out.State);
        resp->set_installed(out.Installed != 0);
        resp->set_altitude(out.Altitude);
        resp->set_protected_pids(out.ProtectedPids);
        resp->set_flags(out.Flags);
        resp->set_process_access_keep(out.ProcessAccessKeep);
        resp->set_thread_access_keep(out.ThreadAccessKeep);
        resp->set_preop_hits(out.PreOpHits);
        resp->set_stripped(out.Stripped);
        resp->set_bypassed(out.Bypassed);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterSelfProtService(grpc::ServerBuilder& builder,
                             const AgentConfig& cfg, DriverMgr& drv)
{
    static SelfProtSvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

} // namespace pry
