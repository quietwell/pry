#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "pry.grpc.pb.h"
#include "pry_abi.h"

#include <algorithm>
#include <atomic>
#include <chrono>
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

// -------------------------------------------------------- Breakpoints svc ----

class BpSvc final : public Breakpoints::Service {
public:
    BpSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Add(::grpc::ServerContext* ctx, const BpAddRequest* req, BpAddResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        // HW BPs are ALWAYS driver-backed (kernel_target is a
        // display hint from here on). Rationale: DbgEng's hw-BP surface
        // silently drops when the sub-session expires — you get
        // "no active session" hours after the last debug_manage call
        // even though target_manage stays connected. The driver's
        // BpHwSet uses KeStackAttachProcess + per-thread DR context
        // writes and works on any pid (user or kernel), so folding
        // both paths onto it removes the failure class entirely.
        // SW BPs still need DbgEng (int3 patch + exception routing),
        // so those keep the DbgSession path — with an auto-attach on
        // demand and a one-shot rebind on stale-session errors below.
        // via_debugger overrides the driver routing for HW bps: the
        // bp-events debug-port fallback mirrors driver bps as dbgeng
        // data breakpoints so hits surface through the debug port on
        // targets where the kernel int1 hook can't install (hypervisor
        // descriptor-table exiting). AddBreakpoint2 doesn't need a
        // stopped target — safe while a monitor session runs.
        // Mechanics audit P3: an unknown access string used to become an
        // EXECUTE breakpoint silently (a typo'd "wirte" watch never fired).
        if (req->kind() == BpAddRequest::HW) {
            const std::string& a = req->access();
            const bool known = a.empty() || a == "exec" || a == "write" || a == "rw" ||
                               (a == "read" && req->via_debugger());
            if (!known) {
                FillStatus(resp, a == "read"
                                     ? "bp_add: access='read' needs via_debugger=true (x86 debug "
                                       "registers cannot trap reads only; use rw)"
                                     : "bp_add: access must be exec|write|rw (got '" + a + "')");
                return grpc::Status::OK;
            }
        }
        if (req->kind() == BpAddRequest::HW && !req->via_debugger()) {
            UINT32 access = PRY_HW_EXEC;
            if (req->access() == "write") {
                access = PRY_HW_WRITE;
            } else if (req->access() == "rw") {
                access = PRY_HW_RW;
            }
            // v6: global + dangerous_ok pack into the driver's Flags byte.
            UINT32 flags = 0;
            if (req->global()) flags |= PRY_BP_HW_FLAG_GLOBAL;
            if (req->dangerous_ok()) flags |= PRY_BP_HW_FLAG_DANGEROUS_OK;
            // Global mode ignores pid — pass 0 to the driver even if the
            // caller happened to set one.
            UINT32 pid = req->global() ? 0u : req->pid();
            UINT32 bpId = 0, patched = 0;
            if (!drv_.Comm().BpHwSet(pid, req->tid(), req->address(), req->slot(),
                                     req->size() ? req->size() : 1, access,
                                     &bpId, &patched, flags)) {
                err = "driver: " + drv_.Comm().LastError();
            } else {
                resp->set_bp_id(bpId + 1000000);
            }
        } else {
            // SW BP path — auto-attach + rebind protects against the
            // stale-dbgeng-session failure mode. IsActive() is stale-safe:
            // a session that DbgEng dropped internally still shows active_
            // = true on our side, so the first BpAdd may still fail with
            // a dbgeng error; we retry once after a fresh Attach.
            auto& dbg = DbgSession::Instance();
            UINT32 target_pid = req->pid();
            if (!dbg.IsActive() && target_pid != 0) {
                std::string att = dbg.Attach(target_pid);
                if (!att.empty()) {
                    FillStatus(resp, "auto-attach pid=" + std::to_string(target_pid)
                                     + " failed: " + att);
                    return grpc::Status::OK;
                }
                OutputDebugStringA(("[dbg] auto-attached pid="
                                    + std::to_string(target_pid) + "\n").c_str());
            } else if (dbg.IsActive() && target_pid != 0
                       && dbg.CurrentPid() != target_pid) {
                // dbgeng single-session can only be attached to one pid at
                // a time; adding a bp with a different pid= would silently
                // register it against the ATTACHED pid's address space and
                // never fire against the caller's target. Fail loudly.
                FillStatus(resp, "dbgeng session attached to pid "
                                 + std::to_string(dbg.CurrentPid())
                                 + " but bp_add pid=" + std::to_string(target_pid)
                                 + " — detach first (debug_manage(action='detach'))"
                                 + " or omit pid= to use the attached pid");
                return grpc::Status::OK;
            }
            // BpAdd now takes a params struct so SW/dbgeng-DATA
            // bps can carry condition / commands / pass_count / one_shot /
            // match_tid. Plumb every new BpAddRequest field through — the
            // engine composes the dbgeng command string in dbg_bp.cpp.
            BpAddParams params;
            params.hw         = (req->kind() == BpAddRequest::HW);
            params.address    = req->address();
            params.size       = req->size();
            params.access     = req->access();
            params.condition  = req->condition();
            params.commands   = req->commands();
            params.pass_count = req->pass_count();
            params.one_shot   = req->one_shot();
            params.match_tid  = req->match_tid();
            UINT32 bpId = 0;
            err = dbg.BpAdd(params, &bpId);
            const bool stale = err.find("no active session") != std::string::npos
                               || err.find("E_UNEXPECTED") != std::string::npos
                               || err.find("RPC_S_SERVER") != std::string::npos;
            if (stale && target_pid != 0) {
                std::string att = dbg.Attach(target_pid);
                if (att.empty()) {
                    OutputDebugStringA(("[dbg] rebind pid="
                                        + std::to_string(target_pid) + "\n").c_str());
                    err = dbg.BpAdd(params, &bpId);
                }
            }
            if (err.empty()) {
                resp->set_bp_id(bpId);
            }
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status Remove(::grpc::ServerContext* ctx, const BpRemoveRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        if (req->bp_id() >= 1000000) {
            std::vector<BpRecord> bps;
            if (drv_.Comm().BpList(bps)) {
                UINT32 want = req->bp_id() - 1000000;
                bool found = false;
                for (auto& b : bps) {
                    if (b.Id == want) {
                        found = true;
                        UINT32 patched = 0;
                        if (!drv_.Comm().BpHwClear(b.Pid, b.Tid, b.Slot, &patched)) {
                            // BpHwClear returns STATUS_NOT_FOUND
                            // (0xc0000225) when the owning pid is gone —
                            // threads died with the process, so the per-
                            // thread DR state is already cleared, but
                            // the top-level BpRecord lingers in the
                            // driver's registry. From the caller's
                            // perspective there's nothing more to tear
                            // down; treat it as the same idempotent-
                            // remove path we already use when the id
                            // isn't in the registry at all (errno_code=2).
                            // PryBpHwClear soft-succeeds on registry
                            // misses but a dead owner is a different
                            // kernel path — this merges them.
                            std::string last = drv_.Comm().LastError();
                            if (last.find("c0000225") != std::string::npos
                                || last.find("STATUS_NOT_FOUND") != std::string::npos) {
                                resp->set_errno_code(2);
                            } else {
                                err = "driver: " + last;
                            }
                        }
                        break;
                    }
                }
                // idempotent remove. A registry miss is not an error
                // because the registry may no longer hold the id: with
                // PryOnThreadNotify auto-pruning per-thread entries
                // on thread-exit AND PryBpHwClear soft-
                // succeeding on registry misses, the id is expected
                // to be gone by the time a caller retries after an
                // MCP deadline. Match the driver's idempotence: leave
                // err empty so ok=true, and stash a hint in errno_code
                // (=2 == already_removed; FillStatus uses =1 for the
                // generic-error case) so a retrying caller can still
                // tell "we cleared it just now" apart from "it was
                // already gone."
                if (!found) {
                    resp->set_errno_code(2);
                }
            } else {
                err = "driver: " + drv_.Comm().LastError();
            }
        } else {
            err = DbgSession::Instance().BpRemove(req->bp_id());
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status List(::grpc::ServerContext* ctx, const BpListRequest*, BpListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<BpInfoRec> bps;
        std::string err = DbgSession::Instance().BpList(&bps);
        // the dbgeng session is optional — SW BPs and HW BPs both
        // route through the driver, so a bp_manage list must
        // still succeed after a debug_manage detach or a reconnect that
        // hasn't re-attached the debugger. Swallow the specific "no
        // active session" reply here so the driver-side enumeration
        // below is authoritative; any other DbgSession err still
        // propagates as an error.
        if (err == "no active session") {
            err.clear();
        }
        for (auto& b : bps) {
            auto* e = resp->add_breakpoints();
            e->set_bp_id(b.id);
            e->set_kind(b.kind);
            e->set_address(b.address);
            e->set_access(b.access);
            e->set_enabled(b.enabled);
            // dbgeng is single-session, so pid is the attached pid (0
            // if no session is active) — matches the driver-bp rows
            // below so bp_manage(list) carries pid for every row.
            e->set_pid(b.pid);
        }
        if (drv_.Comm().Open()) {
            std::vector<BpRecord> dbps;
            if (drv_.Comm().BpList(dbps)) {
                for (auto& b : dbps) {
                    auto* e = resp->add_breakpoints();
                    e->set_bp_id(b.Id + 1000000);
                    e->set_kind(b.Kind == PRY_BP_KIND_HW ? "hw" : "sw");
                    e->set_address(b.Address);
                    e->set_access(b.Access == PRY_HW_WRITE ? "write"
                                  : b.Access == PRY_HW_RW  ? "rw"
                                                              : "exec");
                    e->set_enabled(b.Enabled != 0);
                    // v12: scope fields — the bp_events debug-port
                    // fallback needs to know which process owns the bp.
                    e->set_pid(b.Pid);
                    e->set_tid(b.Tid);
                    e->set_size(b.Length);
                    // the DR slot (0-3) the driver actually took; without
                    // it every hw row read as slot 0 (proto3 default)
                    if (b.Kind == PRY_BP_KIND_HW) {
                        e->set_slot(b.Slot);
                    }
                }
            }
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status SetEnabled(::grpc::ServerContext* ctx, const BpSetEnabledRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        if (req->bp_id() >= 1000000) {
            err = "driver breakpoints are enabled/cleared via remove";
        } else {
            err = DbgSession::Instance().BpSetEnabled(req->bp_id(), req->enabled());
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterBpSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv)
{
    static BpSvc bpSvc(cfg, drv);
    builder.RegisterService(&bpSvc);
}

// -------------------------------------------------- SI #25 HW-watch (v14) --
// WatchHw service — thin facade over Driver::BpHwSet with
// PRY_BPHW_FLAG_IS_WATCH (and optional PREEMPT_OK) packed into Flags.
// The driver's PRY_BP_HW_SLOT_AUTO (0xFF) sentinel passes through
// untouched; the response carries the DR slot the driver actually armed
// plus the WatchCookie orchestrators use to demux BP_HIT ring records.

class WatchHwSvc final : public WatchHw::Service {
public:
    WatchHwSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Add(::grpc::ServerContext* ctx, const WatchHwAddRequest* req,
                     WatchHwAddResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        UINT32 access = PRY_HW_WRITE;
        const std::string a = req->access();
        if (a == "rw" || a == "read" /*promoted — DRs can't observe reads alone*/) {
            access = PRY_HW_RW;
        } else if (a == "write" || a.empty()) {
            access = PRY_HW_WRITE;
        } else {
            FillStatus(resp, "watch_hw: access must be write|rw (got " + a + ")");
            return grpc::Status::OK;
        }
        UINT32 size = req->size() ? req->size() : 1;
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            FillStatus(resp, "watch_hw: size must be 1|2|4|8");
            return grpc::Status::OK;
        }
        UINT32 flags = PRY_BPHW_FLAG_IS_WATCH;
        if (req->preempt_ok()) {
            flags |= PRY_BPHW_FLAG_PREEMPT_OK;
        }
        UINT32 slot = req->slot();
        if (slot == 0) {
            // Default to auto-slot when caller didn't pick one — matches
            // the orchestrator's slot=0xFF convention. Explicit slot=0
            // is still reachable via the Breakpoints service.
            slot = PRY_BP_HW_SLOT_AUTO;
        }
        UINT32 bpId = 0, patched = 0;
        if (!drv_.Comm().BpHwSet(req->pid(), req->tid(), req->address(),
                                 slot, size, access,
                                 &bpId, &patched, flags)) {
            err = "driver: " + drv_.Comm().LastError();
        } else {
            resp->set_watch_cookie(bpId);
            resp->set_slot(slot == PRY_BP_HW_SLOT_AUTO
                               ? 0xFF // orchestrator will read the real slot via BpList
                               : slot);
            resp->set_threads_patched(patched);
            PingInfo p{};
            if (drv_.Comm().Ping(&p)) {
                resp->set_hvci_fallback(
                    (p.Flags & PRY_FLAG_WATCH_HVCI_FALLBACK) != 0);
            }
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status Remove(::grpc::ServerContext* ctx, const WatchHwRemoveRequest* req,
                        OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        std::vector<BpRecord> bps;
        if (!drv_.Comm().BpList(bps)) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        bool found = false;
        for (auto& b : bps) {
            if (b.Id == req->watch_cookie()) {
                found = true;
                UINT32 patched = 0;
                if (!drv_.Comm().BpHwClear(b.Pid, b.Tid, b.Slot, &patched)) {
                    err = "driver: " + drv_.Comm().LastError();
                }
                break;
            }
        }
        if (!found) {
            resp->set_errno_code(2); // already_removed — matches BpSvc idempotence
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterWatchHwSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv)
{
    static WatchHwSvc watchHwSvc(cfg, drv);
    builder.RegisterService(&watchHwSvc);
}

} // namespace pry
