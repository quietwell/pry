// PR#6 T3.2 (2026-10): MSR / CPUID gRPC surface. Forwards to the driver
// via DriverMgr::Comm().MsrRead / CpuidRead. Same shape as
// services_watchdog.cpp — ProbeDriver first so a driver-absent state
// surfaces as a clean error instead of a raw IOCTL failure.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include "services.hpp"

#include <string>
#include <vector>

namespace pry {

static bool ProbeDriverCpu(DriverMgr& drv, std::string* err)
{
    if (drv.Comm().IsOpen()) return true;
    if (!drv.Comm().Open()) {
        *err = "driver_absent: " + drv.Comm().LastError();
        return false;
    }
    return true;
}

class CpuSvc final : public Cpu::Service {
public:
    CpuSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status MsrRead(::grpc::ServerContext* ctx, const MsrReadRequest* req,
                         MsrReadResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriverCpu(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        std::vector<UINT32> cores;
        cores.reserve(req->cores_size());
        for (int i = 0; i < req->cores_size(); i++) {
            cores.push_back(req->cores(i));
        }
        std::vector<Driver::MsrRow> rows;
        if (!drv_.Comm().MsrRead(req->msr(), cores, req->all_cores(), rows)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        for (auto& r : rows) {
            auto* v = resp->add_values();
            v->set_core(r.Core);
            v->set_value(r.Value);
            v->set_nt_status(r.NtStatus);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status CpuidRead(::grpc::ServerContext* ctx, const CpuidRequest* req,
                           CpuidResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriverCpu(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        std::vector<UINT32> cores;
        cores.reserve(req->cores_size());
        for (int i = 0; i < req->cores_size(); i++) {
            cores.push_back(req->cores(i));
        }
        std::vector<Driver::CpuidRow> rows;
        if (!drv_.Comm().CpuidRead(req->leaf(), req->subleaf(), cores,
                                    req->all_cores(), rows)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        for (auto& r : rows) {
            auto* v = resp->add_values();
            v->set_core(r.Core);
            v->set_eax(r.Eax);
            v->set_ebx(r.Ebx);
            v->set_ecx(r.Ecx);
            v->set_edx(r.Edx);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterCpuService(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                        DriverMgr& drv)
{
    static CpuSvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

} // namespace pry
