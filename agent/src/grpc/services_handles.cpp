// SI adoption feature #6 — HandleOps gRPC surface. Thin façade over the
// three driver IOCTLs (HANDLE_DUP / HANDLE_CLOSE_REMOTE / HANDLE_COMPARE)
// surfaced through comm/pry_comm's Driver::Handle* wrappers.
//
// Agent-side state is zero — the kernel is the source of truth. Shape
// mirrors services_selfprot.cpp (SI #21 landed first).

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

static std::string TypeNameUtf8(const WCHAR* wname)
{
    std::wstring w(wname);
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) {
        out.push_back(c > 0x7E || c < 0x20 ? '?' : (char)c);
    }
    return out;
}

class HandleOpsSvc final : public HandleOps::Service {
public:
    HandleOpsSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Duplicate(::grpc::ServerContext* ctx,
                           const HandleDupRequest* req,
                           HandleDupResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        PRY_HANDLE_DUP_IN in{};
        in.SrcPid = req->src_pid();
        in.SrcHandle = req->src_handle();
        in.DesiredAccess = req->desired_access();
        in.Options = req->options();
        in.PrivilegeCookie = req->privilege_cookie();
        PRY_HANDLE_DUP_OUT out{};
        bool ok = drv_.Comm().HandleDup(in, &out);
        resp->set_new_handle(out.NewHandle);
        resp->set_object_addr(out.ObjectAddr);
        resp->set_granted_access(out.GrantedAccess);
        resp->set_type_index(out.TypeIndex);
        resp->set_type_name(TypeNameUtf8(out.TypeName));
        if (!ok) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status CloseRemote(::grpc::ServerContext* ctx,
                             const HandleCloseRemoteRequest* req,
                             HandleCloseRemoteResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        PRY_HANDLE_CLOSE_IN in{};
        in.TargetPid = req->target_pid();
        in.TargetHandle = req->target_handle();
        in.PrivilegeCookie = req->privilege_cookie();
        PRY_HANDLE_CLOSE_OUT out{};
        if (!drv_.Comm().HandleCloseRemote(in, &out)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Compare(::grpc::ServerContext* ctx,
                         const HandleCompareRequest* req,
                         HandleCompareResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        PRY_HANDLE_CMP_IN in{};
        in.PidA = req->pid_a();
        in.HandleA = req->handle_a();
        in.PidB = req->pid_b();
        in.HandleB = req->handle_b();
        in.PrivilegeCookie = req->privilege_cookie();
        PRY_HANDLE_CMP_OUT out{};
        bool ok = drv_.Comm().HandleCompare(in, &out);
        resp->set_same(out.Same != 0);
        resp->set_object_a(out.ObjectA);
        resp->set_object_b(out.ObjectB);
        resp->set_type_index_a(out.TypeIndexA);
        resp->set_type_index_b(out.TypeIndexB);
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

void RegisterHandleOpsService(grpc::ServerBuilder& builder,
                              const AgentConfig& cfg, DriverMgr& drv)
{
    static HandleOpsSvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

} // namespace pry
