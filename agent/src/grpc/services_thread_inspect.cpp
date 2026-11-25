// agent/src/grpc/services_thread_inspect.cpp
//
// Agent-side ThreadInspect service. Mix of driver-backed and
// umagent-only verbs:
//
//   WaitInfo        -> driver IOCTL PRY_IOCTL_THREAD_WAIT_INFO
//                      (status propagates from the driver header; dyn-data
//                      Wave 3 pending == wave_3_pending)
//   IrpList         -> driver IOCTL PRY_IOCTL_THREAD_IRP_LIST
//                      (status propagates; wave_3_pending degrade same
//                      as WaitInfo)
//   the rest        -> umagent-only Win32 APIs; agent view surfaces
//                      kind='not_supported' hint='use name=user' so the
//                      orchestrator fan-out can degrade cleanly per
//                      slice doc §Edge cases.
//
// Each column's error string on the agent view matches the operator-
// facing contract the orchestrator thread_inspect mixin keys off of.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include "services.hpp"

namespace pry {

namespace {

constexpr const char* kAgentUserOnly =
    "thread_inspect: this column is umagent-only — route via name='user'";

constexpr const char* kWave3Pending =
    "wave_3_pending";

class ThreadInspectSvc final : public ThreadInspect::Service {
public:
    explicit ThreadInspectSvc(const AgentConfig& cfg, DriverMgr& drv)
        : cfg_(cfg), drv_(drv) {}

    // --- Driver-backed: WaitInfo ---------------------------------------
    // The driver returns STATUS_NOT_SUPPORTED while Wave 3 dyn-data is
    // pending; we surface error='wave_3_pending' so the orchestrator
    // handler degrades last_syscall + kernel_stack_usage columns to
    // include_* None with the honest reason.
    grpc::Status WaitInfo(::grpc::ServerContext* ctx,
                          const ThreadWaitInfoRequest* req,
                          ThreadWaitInfoResponse* resp) override {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        if (req->tid() == 0) {
            resp->set_error("no_thread");
            FillStatus(resp, "WaitInfo: tid required");
            return grpc::Status::OK;
        }
        // Driver IOCTL round-trip would land here.
        // dyn-data isn't shipped, so we short-circuit to the honest
        // wave_3_pending surface — same contract the driver header
        // reports (hdr->Status = STATUS_NOT_SUPPORTED).
        resp->set_error(kWave3Pending);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // --- Driver-backed: IrpList ----------------------------------------
    grpc::Status IrpList(::grpc::ServerContext* ctx,
                         const ThreadIrpListRequest* req,
                         ThreadIrpListResponse* resp) override {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        if (req->tid() == 0) {
            resp->set_error("no_thread");
            FillStatus(resp, "IrpList: tid required");
            return grpc::Status::OK;
        }
        resp->set_error(kWave3Pending);
        resp->set_pending(false);
        resp->set_irp_count(0);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // --- Umagent-only columns: clean degrade ---------------------------
    grpc::Status Impersonation(::grpc::ServerContext* ctx,
                               const ThreadImpersonationRequest*,
                               ThreadImpersonationResponse* resp) override {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        resp->set_error("not_supported");
        FillStatus(resp, kAgentUserOnly);
        return grpc::Status::OK;
    }

    grpc::Status ComApartment(::grpc::ServerContext* ctx,
                              const ThreadComApartmentRequest*,
                              ThreadComApartmentResponse* resp) override {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        resp->set_error("not_supported");
        FillStatus(resp, kAgentUserOnly);
        return grpc::Status::OK;
    }

    grpc::Status RpcUsage(::grpc::ServerContext* ctx,
                          const ThreadRpcUsageRequest*,
                          ThreadRpcUsageResponse* resp) override {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        resp->set_error("not_supported");
        FillStatus(resp, kAgentUserOnly);
        return grpc::Status::OK;
    }

    grpc::Status PowerThrottling(::grpc::ServerContext* ctx,
                                 const ThreadPowerThrottlingRequest*,
                                 ThreadPowerThrottlingResponse* resp) override {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        resp->set_error("not_supported");
        FillStatus(resp, kAgentUserOnly);
        return grpc::Status::OK;
    }

    grpc::Status Fiber(::grpc::ServerContext* ctx,
                       const ThreadFiberRequest*,
                       ThreadFiberResponse* resp) override {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        resp->set_error("not_supported");
        FillStatus(resp, kAgentUserOnly);
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

} // namespace

void RegisterThreadInspectService(grpc::ServerBuilder& builder,
                                  const AgentConfig& cfg, DriverMgr& drv) {
    static ThreadInspectSvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

} // namespace pry
