// SI adoption feature #9 — StackWalk gRPC surface. Thin façade over
// Driver::StackWalk (comm/pry_comm). The driver IOCTL delivers the
// walk via a kernel-mode APC on the target thread (PryRemoteCall +
// PRY_RC_FLAG_KERNEL); default timeout 500 ms.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include "services.hpp"

#include <string>
#include <vector>

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

class StackWalkSvc final : public StackWalk::Service {
public:
    StackWalkSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Walk(::grpc::ServerContext* ctx,
                      const StackWalkRequest* req,
                      StackWalkResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }

        PRY_STACKWALK_IN in{};
        in.Tid = req->tid();
        in.MaxFrames = req->max_frames();
        in.Flags = req->flags();
        in.TimeoutMs = req->timeout_ms();
        in.PrivilegeCookie = req->privilege_cookie();

        PRY_STACKWALK_HDR hdr{};
        std::vector<PRY_STACKWALK_FRAME> frames(
            PRY_STACKWALK_MAX_FRAMES * 2);
        SIZE_T bytesReturned = 0;
        bool ok = drv_.Comm().StackWalk(in, &hdr,
                                        frames.data(),
                                        frames.size() * sizeof(frames[0]),
                                        &bytesReturned);
        resp->set_pid(hdr.Pid);
        resp->set_flags(hdr.Flags);
        resp->set_rip(hdr.Rip);
        resp->set_rsp(hdr.Rsp);
        for (UINT32 i = 0; i < hdr.KernelFrameCount && i < frames.size(); i++) {
            auto* f = resp->add_kernel_frames();
            f->set_rip(frames[i].Rip);
            f->set_module_tag(frames[i].ModuleTag);
            f->set_module_base(frames[i].ModuleBase);
        }
        UINT32 off = hdr.KernelFrameCount;
        for (UINT32 i = 0;
             i < hdr.UserFrameCount && (off + i) < frames.size(); i++) {
            auto* f = resp->add_user_frames();
            f->set_rip(frames[off + i].Rip);
            f->set_module_tag(frames[off + i].ModuleTag);
            f->set_module_base(frames[off + i].ModuleBase);
        }
        if (!ok) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterStackWalkService(grpc::ServerBuilder& builder,
                              const AgentConfig& cfg, DriverMgr& drv)
{
    static StackWalkSvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

} // namespace pry
