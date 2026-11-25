// agent/src/grpc/services_etw.cpp — SI #10 EtwTrace gRPC service.
//
// Driver-free surface — ETW is a user-mode API, so this service
// answers identically on the agent and the umagent. The underlying
// session + SPSC-ring + ProcessTrace machinery lives in
// agent/src/etw/{etw_session,etw_consumer,etw_registry}.cpp; the
// umagent builds the same files via CMake (see umagent/CMakeLists.txt).
// See an internal plan
// §Feature 8.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include <windows.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "services.hpp"
#include "../etw/etw_consumer.hpp"
#include "../etw/etw_registry.hpp"
#include "../etw/etw_session.hpp"

namespace pry {

namespace {

void FillEventRow(EtwEventRow* dst, const pry::etw::EtwEvent& e)
{
    dst->set_seq(e.seq);
    dst->set_ts_100ns(e.ts_100ns);
    dst->set_provider_guid(e.provider_guid);
    dst->set_event_id(e.event_id);
    dst->set_pid(e.pid);
    dst->set_tid(e.tid);
    dst->set_opcode(e.opcode);
    dst->set_version(e.version);
    dst->set_level(e.level);
    dst->set_keywords(e.keywords);
    dst->set_kind(e.kind);
    auto* f = dst->mutable_fields();
    for (const auto& kv : e.fields) (*f)[kv.first] = kv.second;
}

pry::etw::StartParams ToStartParams(const EtwStartRequest* req)
{
    pry::etw::StartParams p;
    p.session_name = req->session_name();
    p.buffer_size_kb = req->buffer_size_kb();
    p.min_buffers = req->min_buffers();
    p.max_buffers = req->max_buffers();
    p.ring_capacity = req->ring_capacity();
    for (const std::string& prov : req->providers()) {
        pry::etw::ProviderSpec ps;
        if (!pry::etw::ResolveProvider(prov, &ps.guid)) {
            // Unknown name / malformed GUID — queue it as failed by
            // leaving the GUID empty so the session's EnableProvider
            // call rejects it.
            ps.guid = prov;
        }
        ps.keywords_any = req->keywords_any();
        ps.keywords_all = req->keywords_all();
        ps.level = req->level();
        p.providers.push_back(std::move(ps));
    }
    return p;
}

}  // namespace

class EtwTraceSvc final : public EtwTrace::Service {
public:
    explicit EtwTraceSvc(const AgentConfig& cfg) : cfg_(cfg) {}

    grpc::Status Start(::grpc::ServerContext* ctx,
                        const EtwStartRequest* req,
                        EtwStartResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto p = ToStartParams(req);
        pry::etw::StartResult sr;
        std::string err;
        bool ok = pry::etw::SessionRegistry::Instance().Start(p, &sr, &err);
        resp->set_session_name(p.session_name);
        resp->set_session_handle(sr.session_handle);
        resp->set_ring_capacity(sr.ring_capacity);
        for (const auto& g : sr.started) resp->add_started_providers(g);
        for (const auto& g : sr.failed)  resp->add_failed_providers(g);
        FillStatus(resp, ok ? "" : err);
        return grpc::Status::OK;
    }

    grpc::Status Stop(::grpc::ServerContext* ctx,
                       const EtwStopRequest* req,
                       EtwStopResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        uint64_t total = 0, dropped = 0;
        std::string err;
        bool ok = pry::etw::SessionRegistry::Instance().Stop(
            req->session_name(), &total, &dropped, &err);
        resp->set_events_total(total);
        resp->set_events_dropped(dropped);
        FillStatus(resp, ok ? "" : err);
        return grpc::Status::OK;
    }

    grpc::Status Sessions(::grpc::ServerContext* ctx,
                           const EtwTraceSessionsRequest* /*req*/,
                           EtwTraceSessionsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto& reg = pry::etw::SessionRegistry::Instance();
        for (const std::string& name : reg.Names()) {
            auto* s = reg.Get(name);
            if (!s) continue;
            auto* row = resp->add_sessions();
            row->set_session_name(name);
            row->set_providers(s->providers_count());
            row->set_running(s->running());
            if (s->consumer()) {
                row->set_events_total(s->consumer()->ring().total());
                row->set_events_dropped(s->consumer()->ring().dropped());
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Tail(::grpc::ServerContext* ctx,
                       const EtwTailRequest* req,
                       EtwTailResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto* s = pry::etw::SessionRegistry::Instance().Get(
            req->session_name());
        if (!s || !s->consumer()) {
            FillStatus(resp, "etw: unknown session '"
                             + req->session_name() + "'");
            return grpc::Status::OK;
        }
        uint64_t last = 0;
        auto evts = s->consumer()->ring().Drain(req->limit(),
                                                  req->since_seq(), &last);
        for (const auto& e : evts) FillEventRow(resp->add_events(), e);
        resp->set_last_seq(last);
        resp->set_dropped(s->consumer()->ring().dropped());
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Events(::grpc::ServerContext* ctx,
                         const EtwEventsRequest* req,
                         EtwEventsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto* s = pry::etw::SessionRegistry::Instance().Get(
            req->session_name());
        if (!s || !s->consumer()) {
            FillStatus(resp, "etw: unknown session '"
                             + req->session_name() + "'");
            return grpc::Status::OK;
        }
        uint32_t budget = req->max_events() ? req->max_events() : 256;
        uint32_t timeout = req->timeout_ms();
        uint64_t deadline = (uint64_t)GetTickCount64() + timeout;
        uint64_t last = 0;
        auto& ring = s->consumer()->ring();
        auto evts = ring.Drain(budget, 0, &last);
        while (evts.empty() && timeout > 0
               && (uint64_t)GetTickCount64() < deadline
               && !ctx->IsCancelled()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            evts = ring.Drain(budget, 0, &last);
        }
        for (const auto& e : evts) FillEventRow(resp->add_events(), e);
        resp->set_last_seq(last);
        resp->set_dropped(ring.dropped());
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Stats(::grpc::ServerContext* ctx,
                        const EtwStatsRequest* req,
                        EtwStatsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto* s = pry::etw::SessionRegistry::Instance().Get(
            req->session_name());
        if (!s || !s->consumer()) {
            FillStatus(resp, "etw: unknown session '"
                             + req->session_name() + "'");
            return grpc::Status::OK;
        }
        resp->set_session_name(req->session_name());
        resp->set_events_total(s->consumer()->ring().total());
        resp->set_events_dropped(s->consumer()->ring().dropped());
        resp->set_events_lost(s->consumer()->events_lost());
        resp->set_buffers_written(s->consumer()->buffers_written());
        resp->set_buffers_lost(s->consumer()->buffers_lost());
        resp->set_ring_capacity(s->consumer()->ring().capacity());
        resp->set_ring_used(s->consumer()->ring().used());
        resp->set_running(s->running());
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
};

void RegisterEtwTraceService(grpc::ServerBuilder& builder,
                              const AgentConfig& cfg)
{
    static EtwTraceSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace pry
