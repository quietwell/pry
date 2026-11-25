#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "pry.grpc.pb.h"
#include "pry_abi.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include "services.hpp"
#include "services_internal.hpp"
#include "../breadcrumb.hpp"
#include "../common.h"
#include "../dump/dumper.hpp"
#include "../files.hpp"
#include "../host/host_info.hpp"
#include "../pe/pe_reader.hpp"
#include "../pe/heap_walker.hpp"
#include "../watch.hpp"

#include <tlhelp32.h>
#include <fstream>
#include <cctype>

namespace pry {

// ------------------------------------------------------------- Debug svc ----
//
// state-loop surface. Every mutating RPC carries a StopInfo echo
// built from DbgSession::StopInfoRec via FillPbStopInfo (proto class
// `pry::StopInfo` and the C++ `StopInfoRec` live in the same namespace
// — the proto owns the plain `StopInfo` name).

static void FillPbStopInfo(const StopInfoRec& r, ::pry::StopInfo* pb)
{
    if (!pb) {
        return;
    }
    pb->set_active(r.active);
    pb->set_stopped(r.stopped);
    pb->set_timed_out(r.timed_out);
    pb->set_pid(r.pid);
    pb->set_tid(r.tid);
    pb->set_rip(r.rip);
    pb->set_symbol(r.symbol);
    pb->set_stop_reason(r.stop_reason);
    pb->set_seq(r.seq);
    pb->set_arch(r.arch);
    pb->set_exception_code(r.exception_code);
    pb->set_first_chance(r.first_chance);
    pb->set_bp_id(r.bp_id);
    // crash-context mirror. Empty on StopInfoRecs that weren't
    // enriched (non-exception stops without include_context).
    for (const auto& kv : r.regs) {
        auto* rg = pb->add_regs();
        rg->set_name(kv.first);
        rg->set_value(kv.second);
    }
    pb->set_bytes_at_rip_hex(r.bytes_at_rip_hex);
}

class DebugSvc final : public Debug::Service {
public:
    DebugSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Launch(::grpc::ServerContext* ctx, const LaunchRequest* req, LaunchResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        UINT32 pid = 0, tid = 0;
        // 6-arg Launch carries the `monitor` flag (symmetric with
        // AttachRequest.monitor). The legacy 5-arg forwarder still exists for
        // source-compat callers but gRPC always goes straight to the full form.
        std::string err = DbgSession::Instance().Launch(req->cmdline(), req->working_dir(),
                                                        req->break_on_entry(), req->monitor(),
                                                        &pid, &tid);
        FillStatus(resp, err);
        resp->set_pid(pid);
        resp->set_initial_tid(tid);
        return grpc::Status::OK;
    }

    // Attach returns AttachResponse (OpStatus + StopInfo). The state
    // echo comes from a post-Attach Status() snapshot since Attach itself has
    // no state-aware overload.
    grpc::Status Attach(::grpc::ServerContext* ctx, const AttachRequest* req, AttachResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err = DbgSession::Instance().Attach(req->pid(), req->monitor());
        FillStatus(resp, err);
        StopInfoRec rec;
        DbgSession::Instance().Status(&rec);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    // Detach returns DetachResponse (OpStatus + StopInfo). Status()
    // after a clean detach reports active=false so the caller sees the state
    // transition without a second round-trip.
    grpc::Status Detach(::grpc::ServerContext* ctx, const DetachRequest* req, DetachResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err = DbgSession::Instance().Detach(req->kill());
        FillStatus(resp, err);
        StopInfoRec rec;
        DbgSession::Instance().Status(&rec);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    // Continue returns ContinueResponse (OpStatus + StopInfo). The
    // engine's Continue(&rec) overload fills the snapshot in the same call so
    // clients see where the 50 ms pump left them (stopped on hit vs. still
    // running).
    grpc::Status Continue(::grpc::ServerContext* ctx, const ContinueRequest* req, ContinueResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().Continue(&rec, req->include_context());
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    grpc::Status Step(::grpc::ServerContext* ctx, const StepRequest* req, StepResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().Step(req->kind() == StepRequest::STEP_OVER,
                                                      req->count() ? req->count() : 1, &rec,
                                                      req->include_context());
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    grpc::Status GetRegs(::grpc::ServerContext* ctx, const GetRegsRequest* req, GetRegsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        RegsRec r{};
        std::vector<std::string> warn;
        std::string err = DbgSession::Instance().GetRegs(&r, req->tid(), &warn);
        if (err.empty()) {
            auto* rg = resp->mutable_regs();
            rg->set_rax(r.rax);
            rg->set_rcx(r.rcx);
            rg->set_rdx(r.rdx);
            rg->set_rbx(r.rbx);
            rg->set_rsp(r.rsp);
            rg->set_rbp(r.rbp);
            rg->set_rsi(r.rsi);
            rg->set_rdi(r.rdi);
            rg->set_r8(r.r8);
            rg->set_r9(r.r9);
            rg->set_r10(r.r10);
            rg->set_r11(r.r11);
            rg->set_r12(r.r12);
            rg->set_r13(r.r13);
            rg->set_r14(r.r14);
            rg->set_r15(r.r15);
            rg->set_rip(r.rip);
            rg->set_rflags(r.rflags);
            // DRx are uint64 on the wire — no truncation.
            rg->set_dr0(r.dr0);
            rg->set_dr1(r.dr1);
            rg->set_dr2(r.dr2);
            rg->set_dr3(r.dr3);
            rg->set_dr6(r.dr6);
            rg->set_dr7(r.dr7);
        }
        // surface per-register failures as warnings.
        for (auto& w : warn) {
            resp->add_warnings(w);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status SetRegs(::grpc::ServerContext* ctx, const SetRegsRequest* req, SetRegsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        RegsRec r{};
        const auto& rg = req->regs();
        r.rax = rg.rax(); r.rcx = rg.rcx(); r.rdx = rg.rdx(); r.rbx = rg.rbx();
        r.rsp = rg.rsp(); r.rbp = rg.rbp(); r.rsi = rg.rsi(); r.rdi = rg.rdi();
        r.r8 = rg.r8(); r.r9 = rg.r9(); r.r10 = rg.r10(); r.r11 = rg.r11();
        r.r12 = rg.r12(); r.r13 = rg.r13(); r.r14 = rg.r14(); r.r15 = rg.r15();
        r.rip = rg.rip();
        r.rflags = rg.rflags();
        // DRx are uint64 — generated getters return uint64_t.
        r.dr0 = rg.dr0(); r.dr1 = rg.dr1(); r.dr2 = rg.dr2(); r.dr3 = rg.dr3();
        r.dr6 = rg.dr6(); r.dr7 = rg.dr7();
        std::vector<std::string> warn;
        std::string err = DbgSession::Instance().SetRegs(r, req->apply_gprs(), req->apply_rip(),
                                                         req->apply_rflags(), req->apply_dr(),
                                                         req->tid(), &warn);
        for (auto& w : warn) {
            resp->add_warnings(w);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status GetThreads(::grpc::ServerContext* ctx, const GetThreadsRequest*, GetThreadsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<ThreadRec> threads;
        UINT32 cur = 0;
        std::string err = DbgSession::Instance().GetThreads(&threads, &cur);
        for (auto& t : threads) {
            auto* ti = resp->add_threads();
            ti->set_tid(t.tid);
            ti->set_teb(t.teb);
            // suspend_count filled by GetThreads (per-thread
            // GetCurrentThreadSuspendCount sweep).
            ti->set_suspend_count(t.suspend_count);
            ti->set_start_address(t.start);
        }
        resp->set_current_tid(cur);
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status Stacktrace(::grpc::ServerContext* ctx, const StacktraceRequest* req, StacktraceResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<StackFrameRec> frames;
        std::string err = DbgSession::Instance().Stacktrace(req->max_frames() ? req->max_frames() : 32,
                                                            req->tid(), &frames);
        for (auto& f : frames) {
            auto* sf = resp->add_frames();
            sf->set_frame(f.frame);
            sf->set_return_address(f.ret);
            sf->set_symbol(f.symbol);
            sf->set_displacement(f.displacement);
            // module filled by Stacktrace via GetModuleByOffset.
            sf->set_module(f.module);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status ReadMemory(::grpc::ServerContext* ctx, const DebugReadRequest* req, DebugReadResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        // Mechanics audit P2: same ceiling as Memory.Read (--max-read-mb,
        // 8 MiB default). An unbounded size made the engine thread
        // allocate whatever the caller asked for (and ReadVirtual takes a
        // ULONG length, so > 4 GiB silently wrapped).
        if (req->size() > cfg_.maxMemReadBytes) {
            FillStatus(resp, "read exceeds max_mem_read_mb (" +
                                 std::to_string(cfg_.maxMemReadBytes) + " bytes)");
            return grpc::Status::OK;
        }
        std::vector<BYTE> data;
        std::string err = DbgSession::Instance().ReadMem(req->address(), req->size(), &data);
        if (err.empty()) {
            resp->set_data(data.data(), data.size());
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status WriteMemory(::grpc::ServerContext* ctx, const DebugWriteRequest* req, DebugWriteResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err = DbgSession::Instance().WriteMem(req->address(), req->data().data(),
                                                          req->data().size());
        FillStatus(resp, err);
        // echo current state so the MCP state loop sees `state` on
        // every mutating response (WriteMem itself doesn't change execution
        // state, so Status() mirrors lastStop_ as-is).
        StopInfoRec rec;
        DbgSession::Instance().Status(&rec);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    grpc::Status Regions(::grpc::ServerContext* ctx, const MemoryRegionsRequest* req, MemoryRegionsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<RegionRec> regions;
        std::string err = DbgSession::Instance().Regions(&regions);
        // L5 pagination: soft slice after driver fill. limit==0 means no cap.
        const int32_t offset = req->offset() > 0 ? req->offset() : 0;
        const int32_t limit  = req->limit()  > 0 ? req->limit()  : 0;
        const size_t start = static_cast<size_t>(offset);
        const size_t stop  = limit > 0
            ? std::min(regions.size(), start + static_cast<size_t>(limit))
            : regions.size();
        for (size_t i = start; i < stop; ++i) {
            const auto& r = regions[i];
            auto* rr = resp->add_regions();
            rr->set_base(r.base);
            rr->set_size(r.size);
            rr->set_state(r.state);
            rr->set_protect(r.protect);
            rr->set_type(r.type);
            rr->set_module(r.module);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status ExecuteCommand(::grpc::ServerContext* ctx, const ExecuteCommandRequest* req,
                                ExecuteCommandResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string output;
        StopInfoRec rec;
        // the 3-arg Execute re-reads GetExecutionStatus post-call
        // so `g`/`q`/`.detach` land in `state.stopped` / `state.active` instead
        // of silently drifting.
        std::string err = DbgSession::Instance().Execute(req->command(), &output, &rec);
        resp->set_output(output);
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    grpc::Status StreamEvents(::grpc::ServerContext* ctx, const StreamDebugEventsRequest* req,
                              grpc::ServerWriter<DebugEvent>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        auto& events = DbgSession::Instance().Events();
        UINT64 lastSent = req->from_seq() ? req->from_seq() - 1 : 0;
        if (req->from_seq()) {
            // replay buffered history first (dedupe against live pops below)
            std::deque<DebugEventRec> replay;
            events.SnapshotIf([&](const DebugEventRec& r) { return r.seq >= req->from_seq(); },
                              &replay);
            for (auto& rec : replay) {
                if (!WriteDebugEvent(writer, rec)) {
                    return grpc::Status::OK;
                }
                lastSent = rec.seq;
            }
        }
        DebugEventRec rec;
        while (!ctx->IsCancelled()) {
            if (events.Pop(&rec, std::chrono::seconds(1))) {
                if (rec.seq <= lastSent) {
                    continue; // already replayed from history
                }
                if (!WriteDebugEvent(writer, rec)) {
                    return grpc::Status::OK;
                }
                lastSent = rec.seq;
            }
        }
        return grpc::Status::OK;
    }

    // snapshot the engine's current parking state
    // without touching it. Safe to call on an inactive or monitor-mode
    // session; always returns the live lastStop_ snapshot.
    grpc::Status Status(::grpc::ServerContext* ctx, const DebugStatusRequest* req,
                        DebugStatusResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().Status(&rec, req->include_context());
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    // DebugBreakProcess + wait for the injected int3, capped
    // server-side at 30 s. Timeout returns ok=true, state.timed_out=true.
    grpc::Status Pause(::grpc::ServerContext* ctx, const PauseRequest* req, DebugOpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().Pause(req->timeout_ms(), &rec,
                                                       req->include_context());
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    // block until the next stop event or timeout.
    grpc::Status Wait(::grpc::ServerContext* ctx, const WaitRequest* req, DebugOpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().Wait(req->timeout_ms(), &rec,
                                                      req->include_context());
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    // Continue + WaitForStop under a single timeout budget. See
    // dbg_process.cpp for the 50 ms pump.
    grpc::Status Run(::grpc::ServerContext* ctx, const RunRequest* req, DebugOpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().Run(req->timeout_ms(), &rec,
                                                     req->include_context());
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    // arm a one-shot bp at `address`, resume, wait for the stop.
    grpc::Status RunTo(::grpc::ServerContext* ctx, const RunToRequest* req, DebugOpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().RunTo(req->address(), req->timeout_ms(), &rec,
                                                       req->include_context());
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    grpc::Status StepOut(::grpc::ServerContext* ctx, const StepOutRequest* req, DebugOpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().StepOut(req->timeout_ms(), &rec,
                                                         req->include_context());
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    // SetInterrupt-backed abort for a wedged engine op. See
    // dbg_engine.cpp::Cancel for the threading contract (called directly
    // from this gRPC thread, not via RunOnEngine — the engine thread is
    // precisely what we're trying to unblock). pid=0 targets the current
    // session; a non-zero pid is validated against the engine's attached
    // pid so a stale caller doesn't blind-fire into an unrelated session.
    grpc::Status Cancel(::grpc::ServerContext* ctx, const CancelRequest* req, CancelResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->pid() != 0) {
            UINT32 current = DbgSession::Instance().CurrentPid();
            if (current != 0 && current != req->pid()) {
                // Reject without touching the engine thread — Status() goes
                // through RunOnEngine and would hang if the engine is
                // already wedged (which is precisely when Cancel is most
                // likely called). Leave the state field zeroed.
                FillStatus(resp, "cancel: pid mismatch (session pid=" +
                           std::to_string(current) + ", requested=" +
                           std::to_string(req->pid()) + ")");
                return grpc::Status::OK;
            }
        }
        StopInfoRec rec;
        std::string err = DbgSession::Instance().Cancel(&rec);
        FillStatus(resp, err);
        FillPbStopInfo(rec, resp->mutable_state());
        return grpc::Status::OK;
    }

    grpc::Status Disasm(::grpc::ServerContext* ctx, const DisasmRequest* req, DisasmResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<DisasmLineRec> lines;
        std::string err = DbgSession::Instance().Disasm(req->address(),
                                                        req->count() ? req->count() : 16,
                                                        &lines);
        for (auto& ln : lines) {
            auto* pb = resp->add_lines();
            pb->set_address(ln.address);
            pb->set_bytes_hex(ln.bytes_hex);
            pb->set_text(ln.text);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status Resolve(::grpc::ServerContext* ctx, const ResolveRequest* req, ResolveResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        UINT64 addr = 0;
        std::string canonical;
        std::string err = DbgSession::Instance().Resolve(req->symbol(), &addr, &canonical);
        resp->set_address(addr);
        resp->set_canonical(canonical);
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status DebugDump(::grpc::ServerContext* ctx, const DebugDumpRequest* req,
                            DebugDumpResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        UINT64 bytes = 0;
        std::string err = DbgSession::Instance().DumpTo(req->path(), req->kind(), &bytes);
        resp->set_path(req->path());
        resp->set_bytes(bytes);
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status Modules(::grpc::ServerContext* ctx, const DebugModulesRequest*,
                         DebugModulesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<ModuleInfoRec> mods;
        std::string err = DbgSession::Instance().Modules(&mods);
        for (auto& m : mods) {
            auto* pb = resp->add_modules();
            pb->set_base(m.base);
            pb->set_size(m.size);
            pb->set_name(m.name);
            pb->set_path(m.path);
            pb->set_timestamp(m.timestamp);
            pb->set_loaded(m.loaded);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status ExceptionFilter(::grpc::ServerContext* ctx, const ExceptionFilterRequest* req,
                                 ExceptionFilterResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err = DbgSession::Instance().SetExceptionFilter(req->code(), req->action());
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

private:
    static bool WriteDebugEvent(grpc::ServerWriter<DebugEvent>* writer, const DebugEventRec& rec)
    {
        DebugEvent ev;
        ev.set_seq(rec.seq);
        ev.set_tid(rec.tid);
        ev.set_pid(rec.pid);
        ev.set_address(rec.address);
        ev.set_exception_code(rec.code);
        ev.set_description(rec.desc);
        ev.set_timestamp_unix(rec.ts);
        // typed enrichment. bp_id is non-zero on bp_sw/bp_hw;
        // first_chance only meaningful on exceptions; module_base mirrors
        // `address` for module_load / module_unload.
        ev.set_bp_id(rec.bp_id);
        ev.set_first_chance(rec.first_chance);
        ev.set_module_base(rec.module_base);
        if (rec.kind == "bp_sw") {
            ev.set_kind(DebugEvent::BREAKPOINT_SW);
        } else if (rec.kind == "bp_hw") {
            ev.set_kind(DebugEvent::BREAKPOINT_HW);
        } else if (rec.kind == "exception") {
            ev.set_kind(DebugEvent::EXCEPTION);
        } else if (rec.kind == "process_exit") {
            ev.set_kind(DebugEvent::PROCESS_EXIT);
        } else if (rec.kind == "thread_create") {
            ev.set_kind(DebugEvent::THREAD_CREATE);
        } else if (rec.kind == "thread_exit") {
            ev.set_kind(DebugEvent::THREAD_EXIT);
        } else if (rec.kind == "module_load") {
            ev.set_kind(DebugEvent::MODULE_LOAD);
        } else if (rec.kind == "module_unload") {
            // symmetric module-unload event.
            ev.set_kind(DebugEvent::MODULE_UNLOAD);
        } else {
            ev.set_kind(DebugEvent::SESSION_STATUS);
        }
        return writer->Write(ev);
    }

    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterDebugSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv)
{
    static DebugSvc debugSvc(cfg, drv);
    builder.RegisterService(&debugSvc);
}

} // namespace pry
