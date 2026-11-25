#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#include "um_services.hpp"
#include "umem.hpp"
#include "pe_reader.hpp"
#include "../agent/src/exec/call_user.hpp"
#include "../agent/src/scan/scan_service.hpp"
#include "../agent/src/scan/pointer_map_service.hpp"
#include "../agent/src/scan/dissect_service.hpp"
#include "pattern_scan.hpp"

#include <tlhelp32.h>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <map>
#include <vector>

namespace um {

void FillStatus(google::protobuf::Message* msg, const std::string& err)
{
    // every response message has an OpStatus status field at field 1
    auto* status = msg->GetReflection()->MutableMessage(msg, msg->GetDescriptor()->field(0));
    auto* st = static_cast<pry::OpStatus*>(status);
    st->set_ok(err.empty());
    if (!err.empty()) {
        st->set_error(err);
        st->set_errno_code(1);
    }
}

namespace {

grpc::Status CheckAuth(grpc::ServerContext* ctx, const std::string& token)
{
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

UINT32 PidOrSelf(UINT32 pid)
{
    return pid ? pid : GetCurrentProcessId();
}

// v14: same boot/instance identity the agent reports — the orchestrator's
// boot-detection works identically against both views.
static uint64_t UmBootEpochMs()
{
    struct TimeOfDay {
        LARGE_INTEGER BootTime, CurrentTime, TimeZoneBias;
        ULONG TimeZoneId, Reserved;
        ULONGLONG BootTimeBias, SleepTimeBias;
    } ti{};
    using NtQSIFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    static NtQSIFn ntqsi = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (NtQSIFn)GetProcAddress(ntdll, "NtQuerySystemInformation") : nullptr;
    }();
    if (ntqsi && ntqsi(3 /*SystemTimeOfDayInformation*/, &ti, sizeof(ti), nullptr) == 0) {
        return (uint64_t)(ti.BootTime.QuadPart / 10000ULL - 11644473600000ULL);
    }
    auto now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return now_ms - GetTickCount64();
}

static uint64_t UmAgentUptimeMs()
{
    static std::atomic<uint64_t> start{0};
    auto now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t s = start.load(std::memory_order_relaxed);
    if (s == 0) {
        start.compare_exchange_strong(s, now_ms);
        s = start.load(std::memory_order_relaxed);
    }
    return now_ms - s;
}

static const std::string& UmInstanceId()
{
    static const std::string id = [] {
        char buf[64];
        auto now = (unsigned long long)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        snprintf(buf, sizeof(buf), "%lu-%llu", (unsigned long)GetCurrentProcessId(), now);
        return std::string(buf);
    }();
    return id;
}

// v14: lightweight register snapshot (same shape as the agent's
// SnapThreadContext) — the umagent is the driver-free view, and "regs on a
// wedged user process" is exactly what it's for.
static void UmSnapThreadContext(uint32_t pid, uint32_t tid,
                                pry::SysThreadInfo* row,
                                std::map<DWORD, int>* wow64_cache)
{
    if (pid == GetCurrentProcessId() || tid == GetCurrentThreadId()) return;
    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                           THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!th) return;
    int wow64 = -1;
    auto it = wow64_cache->find(pid);
    if (it != wow64_cache->end()) {
        wow64 = it->second;
    } else {
        BOOL w = FALSE;
        HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (ph) {
            IsWow64Process(ph, &w);
            CloseHandle(ph);
        }
        wow64 = w ? 1 : 0;
        (*wow64_cache)[pid] = wow64;
    }
    if (SuspendThread(th) != (DWORD)-1) {
        auto* m = row->mutable_context_regs();
        if (wow64 == 1) {
            WOW64_CONTEXT c{};
            c.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER |
                             WOW64_CONTEXT_SEGMENTS;
            if (Wow64GetThreadContext(th, &c)) {
                (*m)["eip"] = c.Eip;  (*m)["esp"] = c.Esp;  (*m)["ebp"] = c.Ebp;
                (*m)["eax"] = c.Eax;  (*m)["ebx"] = c.Ebx;  (*m)["ecx"] = c.Ecx;
                (*m)["edx"] = c.Edx;  (*m)["esi"] = c.Esi;  (*m)["edi"] = c.Edi;
                (*m)["eflags"] = c.EFlags;
                (*m)["segcs"] = c.SegCs; (*m)["segss"] = c.SegSs;
            }
        } else {
            CONTEXT c{};
            c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
            if (GetThreadContext(th, &c)) {
                (*m)["rip"] = c.Rip;  (*m)["rsp"] = c.Rsp;  (*m)["rbp"] = c.Rbp;
                (*m)["rax"] = c.Rax;  (*m)["rbx"] = c.Rbx;  (*m)["rcx"] = c.Rcx;
                (*m)["rdx"] = c.Rdx;  (*m)["rsi"] = c.Rsi;  (*m)["rdi"] = c.Rdi;
                (*m)["r8"] = c.R8;    (*m)["r9"] = c.R9;    (*m)["r10"] = c.R10;
                (*m)["r11"] = c.R11;  (*m)["r12"] = c.R12;  (*m)["r13"] = c.R13;
                (*m)["r14"] = c.R14;  (*m)["r15"] = c.R15;
                (*m)["eflags"] = c.EFlags;
                (*m)["segcs"] = c.SegCs; (*m)["segss"] = c.SegSs;
            }
        }
        ResumeThread(th);
    }
    CloseHandle(th);
}

// case-insensitive basename-or-full-path module lookup over the um::Module
// list (mirror of the agent's FindModuleBase in grpc/services.cpp)
static std::string BasenameLower(const std::string& p)
{
    size_t slash = p.find_last_of("\\/");
    std::string b = slash == std::string::npos ? p : p.substr(slash + 1);
    for (auto& ch : b) {
        ch = (char)std::tolower((unsigned char)ch);
    }
    return b;
}

static uint64_t FindModuleBase(const std::vector<um::Module>& mods, const std::string& want)
{
    std::string want_lower = BasenameLower(want);
    for (const auto& m : mods) {
        if (_stricmp(m.name.c_str(), want.c_str()) == 0 ||
            _stricmp(m.path.c_str(), want.c_str()) == 0 ||
            BasenameLower(m.name) == want_lower ||
            BasenameLower(m.path) == want_lower) {
            return m.base;
        }
    }
    return 0;
}

static std::string FindOwningModule(const std::vector<um::Module>& mods, uint64_t addr)
{
    for (const auto& m : mods) {
        if (m.size == 0) {
            continue;
        }
        if (addr >= m.base && addr < m.base + m.size) {
            return m.name;
        }
    }
    return {};
}

// ------------------------------------------------------------- Agent svc ----

class UmAgentSvc final : public pry::Agent::Service {
public:
    explicit UmAgentSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Status(grpc::ServerContext* ctx, const pry::StatusRequest*,
                        pry::StatusResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        resp->set_agent_version("umagent/" + cfg_.version);
        OSVERSIONINFOEXW os{};
        os.dwOSVersionInfoSize = sizeof(os);
        using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOEXW*);
        auto rtl = (RtlGetVersionFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
        if (rtl && rtl(&os) == 0) {
            resp->set_os_version("Windows " + std::to_string(os.dwMajorVersion) + "." +
                                 std::to_string(os.dwMinorVersion));
            resp->set_os_build(os.dwBuildNumber);
        }
        resp->set_driver_state(pry::DRIVER_ABSENT);
        resp->set_agent_uptime_ms(UmAgentUptimeMs());
        resp->set_boot_epoch_ms(UmBootEpochMs());
        resp->set_agent_instance_id(UmInstanceId());
        // v16 (Memory scanner wave 1): same Phase-C advert as the kernel
        // agent — umagent also links scan_service.cpp (shared TU).
        resp->set_scan_service_version(1);
        // v17 (Memory scanner wave 2 Phase L): umagent carries the same
        // pointer_map + dissect service vendors; advertise.
        resp->set_pointer_map_version(1);
        // dedicated DissectService
        // advert; see agent/src/grpc/services_agent.cpp for rationale.
        // bumped to 2 once
        // Dissect.Compare landed.
        resp->set_dissect_version(2);
        // ABI report: umagent has no driver (proto: 0/0/false).
        resp->set_driver_abi_version(0);
        resp->set_agent_abi_version(0);
        resp->set_driver_abi_ok(false);
        resp->mutable_status()->set_ok(true);
        return grpc::Status::OK;
    }

    // unauthenticated identity probe (exempt in the auth
    // processor). No secrets — lets the orchestrator confirm which machine
    // and process own this endpoint before it sends the token.
    grpc::Status Identify(grpc::ServerContext*, const pry::IdentifyRequest*,
                          pry::IdentifyResponse* resp) override
    {
        wchar_t cn[MAX_COMPUTERNAME_LENGTH + 1]{};
        DWORD n = (DWORD)(sizeof(cn) / sizeof(cn[0]));
        if (GetComputerNameW(cn, &n) && n > 0) {
            int u = WideCharToMultiByte(CP_UTF8, 0, cn, (int)n, nullptr, 0, nullptr, nullptr);
            if (u > 0) {
                std::string s((size_t)u, '\0');
                WideCharToMultiByte(CP_UTF8, 0, cn, (int)n, s.data(), u, nullptr, nullptr);
                resp->set_computer_name(s);
            }
        }
        resp->set_boot_epoch_ms(UmBootEpochMs());
        resp->set_agent_instance_id(UmInstanceId());
        resp->set_agent_version("umagent/" + cfg_.version);
        resp->set_view_kind("user");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

// ------------------------------------------------------------ Memory svc ----

class UmMemorySvc final : public pry::Memory::Service {
public:
    explicit UmMemorySvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Read(grpc::ServerContext* ctx, const pry::MemoryReadRequest* req,
                      pry::MemoryReadResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->space() != pry::USER) {
            FillStatus(resp, "umagent: only USER space is served (kernel/physical need the agent+driver view)");
            return grpc::Status::OK;
        }
        if (req->size() > cfg_.maxReadBytes) {
            FillStatus(resp, "read exceeds max_read_mb");
            return grpc::Status::OK;
        }
        resp->mutable_data()->resize(static_cast<size_t>(req->size()));
        size_t got = 0;
        std::string err;
        if (!um::MemRead(PidOrSelf(req->pid()), req->address(), resp->mutable_data()->data(),
                         static_cast<size_t>(req->size()), &got, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->mutable_data()->resize(got);
        resp->set_read_bytes(got);
        FillStatus(resp, got == req->size() ? "" : "partial read: " + std::to_string(got) + "/" +
                                                              std::to_string(req->size()));
        return grpc::Status::OK;
    }

    grpc::Status Write(grpc::ServerContext* ctx, const pry::MemoryWriteRequest* req,
                       pry::MemoryWriteResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->space() != pry::USER) {
            FillStatus(resp, "umagent: only USER space is served");
            return grpc::Status::OK;
        }
        size_t written = 0;
        std::string err;
        if (!um::MemWrite(PidOrSelf(req->pid()), req->address(), req->data().data(),
                          req->data().size(), &written, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->set_written_bytes(written);
        // v12 write_path: a usermode WriteProcessMemory store is always the
        // linear-VA path — there is no phys-remap fallback to report.
        // (1 = PRY_MEM_WRITE_PATH_DIRECT_VA; umagent doesn't pull the
        // driver ABI header.)
        resp->set_write_path(1);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Alloc(grpc::ServerContext* ctx, const pry::MemoryAllocRequest* req,
                       pry::MemoryAllocResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel alloc unsupported");
            return grpc::Status::OK;
        }
        UINT64 addr = 0;
        std::string err;
        if (!um::MemAlloc(PidOrSelf(req->pid()), req->size(), req->protect(), &addr, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->set_address(addr);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Free(grpc::ServerContext* ctx, const pry::MemoryFreeRequest* req,
                      pry::MemoryFreeResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel free unsupported");
            return grpc::Status::OK;
        }
        std::string err;
        if (!um::MemFree(PidOrSelf(req->pid()), req->address(), &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Protect(grpc::ServerContext* ctx, const pry::MemoryProtectRequest* req,
                         pry::MemoryProtectResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        UINT32 old = 0;
        std::string err;
        if (!um::MemProtect(PidOrSelf(req->pid()), req->address(), req->size(), req->protect(), &old,
                            &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->set_old_protect(old);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Modules(grpc::ServerContext* ctx, const pry::ModulesRequest* req,
                         pry::ModulesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel module list unsupported (use the agent+driver view)");
            return grpc::Status::OK;
        }
        std::vector<um::Module> mods;
        std::string err;
        if (!um::Modules(req->pid(), &mods, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        for (const auto& m : mods) {
            auto* mi = resp->add_modules();
            mi->set_name(m.name);
            mi->set_path(m.path);
            mi->set_base(m.base);
            mi->set_size(m.size);
            mi->set_kernel(false);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ListProcesses(grpc::ServerContext* ctx, const pry::ListProcessesRequest* req,
                               pry::ListProcessesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<um::Process> procs;
        std::string err;
        if (!um::ProcessList(&procs, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        // v14: honor limit/offset like the agent view (was silently ignored)
        const size_t off = req ? static_cast<size_t>(req->offset() > 0 ? req->offset() : 0) : 0;
        const size_t lim = req ? static_cast<size_t>(req->limit()  > 0 ? req->limit()  : 0) : 0;
        size_t emitted = 0;
        for (size_t i = 0; i < procs.size(); ++i) {
            if (i < off) {
                continue;
            }
            if (lim && emitted >= lim) {
                break;
            }
            const auto& p = procs[i];
            auto* pi = resp->add_processes();
            pi->set_pid(p.pid);
            pi->set_parent_pid(p.parentPid);
            pi->set_image_name(p.image);
            pi->set_session_id(p.sessionId);
            pi->set_create_time_100ns(p.createTime100ns);
            if (req && req->with_cmdline()) {
                pi->set_cmdline(um::ProcCmdline(p.pid));
            }
            ++emitted;
        }
        resp->set_source("umagent");
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v14: parity with the agent view — NtQSI thread inventory, optional
    // register snapshot via with_context. kernel=true stays unsupported.
    grpc::Status ThreadList(grpc::ServerContext* ctx,
                            const pry::ThreadListRequest* req,
                            pry::ThreadListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel thread list unsupported (agent+driver view)");
            return grpc::Status::OK;
        }
        std::vector<um::ThreadRowLite> rows;
        std::string err;
        if (!um::ThreadRows(req->pid(), &rows, &err)) {
            FillStatus(resp, "thread list failed: " + err);
            return grpc::Status::OK;
        }
        for (const auto& t : rows) {
            auto* row = resp->add_threads();
            row->set_tid(t.tid);
            row->set_pid(t.pid);
            row->set_start_va(t.startVa);
            row->set_state(t.state);
            row->set_wait_reason(t.waitReason);
            row->set_base_priority(t.basePriority);
        }
        resp->set_count(static_cast<uint32_t>(rows.size()));
        resp->set_source("umagent");
        if (req->with_context()) {
            std::map<DWORD, int> wow;
            for (int i = 0; i < resp->threads_size(); ++i) {
                auto* t = resp->mutable_threads(i);
                UmSnapThreadContext(t->pid(), t->tid(), t, &wow);
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Scan(grpc::ServerContext* ctx, const pry::PatternScanRequest* req,
                      pry::PatternScanResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->space() != pry::USER) {
            FillStatus(resp, "umagent: only USER space is served");
            return grpc::Status::OK;
        }
        const std::string& pat = req->pattern();
        const std::string& mask = req->mask();
        if (!pry::patscan::ValidPattern(pat, mask)) {
            FillStatus(resp, "invalid pattern/mask");
            return grpc::Status::OK;
        }
        UINT32 pid = PidOrSelf(req->pid());

        // Shared loop + window planning (comm/pattern_scan.hpp), identical
        // to the agent view: base==0 walks all committed readable space;
        // base!=0 with size==0 runs from base to the end of the region
        // chain; else the explicit [base, base+size) window.
        std::vector<pry::patscan::Region> regions;
        if (req->base() == 0 || req->size() == 0) {
            std::vector<um::Region> ur;
            std::string err;
            if (!um::Regions(pid, &ur, &err)) {
                FillStatus(resp, err);
                return grpc::Status::OK;
            }
            regions.reserve(ur.size());
            for (const auto& r : ur) {
                regions.push_back({r.base, r.size, r.protect});
            }
        }
        auto ranges = pry::patscan::PlanRanges(req->base(), req->size(), regions);
        pry::patscan::ReadFn read = [pid](std::uint64_t va, std::uint8_t* dst,
                                             std::size_t want) -> std::size_t {
            size_t got = 0;
            std::string rerr;
            if (!um::MemRead(pid, va, dst, want, &got, &rerr)) {
                return 0;
            }
            return got;
        };
        std::vector<std::uint64_t> hits;
        auto st = pry::patscan::ScanRanges(
            ranges, pat, mask, req->max_results(), read, &hits,
            [ctx](std::uint64_t, std::uint64_t) { return !ctx->IsCancelled(); });
        if (st.cancelled) {
            return grpc::Status::CANCELLED;
        }
        for (auto va : hits) {
            resp->add_addresses(va);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // User-mode IAT walk: same PE parser + response shape as the agent path,
    // backed by um::MemRead instead of the driver.
    grpc::Status ModuleImports(grpc::ServerContext* ctx, const pry::ModuleImportsRequest* req,
                               pry::ModuleImportsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel imports unsupported (use the agent+driver view)");
            return grpc::Status::OK;
        }
        std::vector<um::Module> mods;
        std::string err;
        if (!um::Modules(req->pid(), &mods, &err)) {
            FillStatus(resp, "module list failed: " + err);
            return grpc::Status::OK;
        }
        uint64_t base = FindModuleBase(mods, req->module());
        if (!base) {
            FillStatus(resp, "module not found: " + req->module());
            return grpc::Status::OK;
        }
        uint32_t pid = PidOrSelf(req->pid());
        pry::pe::ReadFn read = [pid](uint64_t addr, void* dst, size_t len) -> bool {
            size_t got = 0;
            std::string rerr;
            return um::MemRead(pid, addr, dst, len, &got, &rerr) && got == len;
        };
        std::vector<pry::pe::IatRow> rows;
        if (!pry::pe::ParseImports(base, read, rows, &err)) {
            FillStatus(resp, "parse imports failed: " + (err.empty() ? "unknown" : err));
            return grpc::Status::OK;
        }
        for (const auto& r : rows) {
            auto* ie = resp->add_entries();
            ie->set_dll(r.dll);
            ie->set_name(r.name);
            ie->set_ordinal(r.ordinal);
            ie->set_iat_slot(r.iat_slot);
            ie->set_resolved(r.resolved);
            std::string owning = FindOwningModule(mods, r.resolved);
            ie->set_resolved_module(owning);
            // owning empty (pointer outside every loaded module) is almost
            // always a trampoline — flag it. Otherwise compare basenames.
            bool hooked = owning.empty() ||
                          BasenameLower(owning) != BasenameLower(r.dll);
            ie->set_hooked(hooked);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ModuleExports(grpc::ServerContext* ctx, const pry::ModuleExportsRequest* req,
                               pry::ModuleExportsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->kernel()) {
            FillStatus(resp, "umagent: kernel exports unsupported (use the agent+driver view)");
            return grpc::Status::OK;
        }
        std::vector<um::Module> mods;
        std::string err;
        if (!um::Modules(req->pid(), &mods, &err)) {
            FillStatus(resp, "module list failed: " + err);
            return grpc::Status::OK;
        }
        uint64_t base = FindModuleBase(mods, req->module());
        if (!base) {
            FillStatus(resp, "module not found: " + req->module());
            return grpc::Status::OK;
        }
        uint32_t pid = PidOrSelf(req->pid());
        pry::pe::ReadFn read = [pid](uint64_t addr, void* dst, size_t len) -> bool {
            size_t got = 0;
            std::string rerr;
            return um::MemRead(pid, addr, dst, len, &got, &rerr) && got == len;
        };
        std::vector<pry::pe::ExpRow> rows;
        if (!pry::pe::ParseExports(base, read, rows, &err)) {
            FillStatus(resp, "parse exports failed: " + (err.empty() ? "unknown" : err));
            return grpc::Status::OK;
        }
        for (const auto& r : rows) {
            auto* ee = resp->add_entries();
            ee->set_name(r.name);
            ee->set_ordinal(r.ordinal);
            ee->set_rva(r.rva);
            ee->set_address(base + r.rva);
            ee->set_forwarder(r.forwarder);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // segment-heap decode. Umagent view
    // reads the heap internals via ReadProcessMemory under the usermode
    // mem reader; PPL targets return access_denied (coverage flips to
    // partial + ppl_fallback). The full decoder (SegContexts walk +
    // _HEAP_PAGE_RANGE_DESCRIPTOR classification + LFH bucket
    // enumeration) rides on Wave 3 dyn-data; this build ships the honest
    // scaffold with ``coverage='partial'`` + ``warnings=
    // 'dyn_data_wave_3_pending'`` so the capability surface lives at
    // the right verb.
    grpc::Status HeapInfo(grpc::ServerContext* ctx,
                           const pry::HeapInfoRequest* req,
                           pry::HeapInfoResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->pid() == 0) {
            FillStatus(resp,
                        "heap_info: pid > 0 required (segment-heap "
                        "decode is per-process)");
            resp->set_coverage("partial");
            resp->set_hint("bad_arg");
            return grpc::Status::OK;
        }
        resp->set_coverage("partial");
        resp->set_hint("dyn_data_wave_3_pending");
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

// ------------------------------------------------------------- Debug svc ----
// Regions only: VirtualQueryEx walk of the target pid. Every other Debug RPC
// keeps the generated UNIMPLEMENTED default — debugging stays an agent/dbgeng
// concern.

class UmDebugSvc final : public pry::Debug::Service {
public:
    explicit UmDebugSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Regions(grpc::ServerContext* ctx, const pry::MemoryRegionsRequest* req,
                         pry::MemoryRegionsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<um::Region> regions;
        std::string err;
        if (!um::Regions(req->pid(), &regions, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        for (const auto& r : regions) {
            auto* rr = resp->add_regions();
            rr->set_base(r.base);
            rr->set_size(r.size);
            rr->set_state(r.state);
            rr->set_protect(r.protect);
            rr->set_type(r.type);
            rr->set_module(r.module);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

// ------------------------------------------------------------- Exec svc ----
// CallFunction only (user space): the param-block trampoline rides the same
// shared call_user.cpp the agent compiles. Kernel calls need the driver —
// answered as a clean space error, not UNIMPLEMENTED.

class UmExecSvc final : public pry::Exec::Service {
public:
    explicit UmExecSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status CallFunction(grpc::ServerContext* ctx, const pry::CallFunctionRequest* req,
                              pry::CallFunctionResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->space() == pry::CALL_KERNEL) {
            FillStatus(resp, "call: kernel calls require the agent view (driver)");
            return grpc::Status::OK;
        }
        if (req->target_va() == 0) {
            FillStatus(resp, "call: target_va required");
            return grpc::Status::OK;
        }
        if (req->args_size() > 16) {
            FillStatus(resp, "call: argc>16");
            return grpc::Status::OK;
        }
        if (!req->pid()) {
            FillStatus(resp, "call: pid required for CALL_USER");
            return grpc::Status::OK;
        }
        std::vector<uint64_t> args;
        args.reserve((size_t)req->args_size());
        for (uint64_t a : req->args()) {
            args.push_back(a);
        }
        pry::CallUserResult r = pry::CallUser(
            (uint32_t)req->pid(), req->target_va(), args, req->timeout_ms(),
            (req->flags() & 0x1) != 0);
        resp->set_return_value(r.ret);
        resp->set_last_error(r.last_error);
        resp->set_exit_code(r.exit_code);
        resp->set_timed_out(r.timed_out);
        resp->set_exception(r.exception);
        if (r.exception) {
            resp->set_exception_code(r.exit_code);
        }
        resp->set_thread_tid(r.tid);
        resp->set_stub_va(r.stub_va);
        if (r.timed_out) {
            std::string msg = "call: timed out - thread left running";
            if (r.killed) {
                msg = "call: timed out and killed (kill_on_timeout)";
            } else if (r.stub_va) {
                char b[64];
                snprintf(b, sizeof(b), " (tid=%lu, stub_va=0x%llx; free via Memory.Free)",
                         (unsigned long)r.tid, (unsigned long long)r.stub_va);
                msg += b;
            }
            FillStatus(resp, msg);
            return grpc::Status::OK;
        }
        if (!r.ok) {
            FillStatus(resp, r.error.empty() ? "call: failed" : r.error);
            return grpc::Status::OK;
        }
        FillStatus(resp, r.done == 1 ? "" : "call: thread exited before stub completion");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

} // namespace

// v16 Memory scanner wave 1: umagent reader — ReadProcessMemory only.
// Kernel / physical space fail at the reader so the handler surfaces
// reads_failed cleanly (the orchestrator-side router sends kernel
// scans to the kernel view, not the umagent view).
static bool UmScanReader(std::uint32_t pid, std::uint64_t va,
                         void* buf, std::size_t size,
                         pry::MemSpace space,
                         std::size_t* out_read)
{
    if (space != pry::USER) {
        if (out_read) *out_read = 0;
        return false;
    }
    HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        if (out_read) *out_read = 0;
        return false;
    }
    SIZE_T got = 0;
    BOOL ok = ReadProcessMemory(h, (LPCVOID)(uintptr_t)va, buf, size, &got);
    CloseHandle(h);
    if (out_read) *out_read = (std::size_t)got;
    return ok && got == size;
}

// v17 Memory scanner wave 2: umagent module enumerator — plain
// CreateToolhelp32Snapshot walk since umagent has no DriverMgr.
// Returns false when snapshot is unavailable (process gone, access
// denied) so PointerMapRegistry falls back to classifying every anchor
// as image_unknown / "" rather than crashing.
static bool UmPointerMapEnumerate(std::uint32_t pid,
                                   std::vector<pry::scan::ModuleInfo>* out)
{
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool any = false;
    if (Module32FirstW(snap, &me)) {
        do {
            pry::scan::ModuleInfo mi;
            auto to_utf8 = [](const wchar_t* w) -> std::string {
                if (!w || !*w) return {};
                int n = WideCharToMultiByte(CP_UTF8, 0, w, -1,
                                             nullptr, 0, nullptr, nullptr);
                if (n <= 1) return {};
                std::string s((std::size_t)(n - 1), '\0');
                WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n,
                                     nullptr, nullptr);
                return s;
            };
            mi.name = to_utf8(me.szModule);
            mi.path = to_utf8(me.szExePath);
            mi.base = (std::uint64_t)(uintptr_t)me.modBaseAddr;
            mi.size = me.modBaseSize;
            mi.timestamp_ms = 0;
            out->push_back(std::move(mi));
            any = true;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return any;
}

void RegisterServices(grpc::ServerBuilder& builder, const Config& cfg)
{
    static UmAgentSvc agentSvc(cfg);
    static UmMemorySvc memorySvc(cfg);
    static UmDebugSvc debugSvc(cfg);
    static UmExecSvc execSvc(cfg);
    builder.RegisterService(&agentSvc);
    builder.RegisterService(&memorySvc);
    builder.RegisterService(&debugSvc);
    builder.RegisterService(&execSvc);
    // v16 Memory scanner wave 1: typed-value ScanService.
    pry::scan::RegisterScanService(builder, "user", &UmScanReader);
    // v17 Memory scanner wave 2: PointerMapService (user space only;
    // kernel-space pointer maps live on the agent view).
    pry::scan::RegisterPointerMapService(
        builder, "user", &UmScanReader, &UmPointerMapEnumerate);
    // v17 Memory scanner wave 2: DissectService.
    pry::scan::RegisterDissectService(
        builder, "user", &UmScanReader, &UmPointerMapEnumerate);
    // SI Wave 1 feature #1: image coherency scoring.
    RegisterImageCoherencyService(builder, cfg);
    // SI Wave 1 feature #8: signer / Authenticode column.
    RegisterSignaturesService(builder, cfg);
    // SI Wave 1 feature #10: private kernel ETW session.
    RegisterEtwTraceService(builder, cfg);
    // SI Wave 1 feature #14: process-snapshot minidump.
    RegisterProcessDumpService(builder, cfg);
    // SI Wave 1 feature #2: hidden-process detection
    // (brute / registry / ETW).
    RegisterHiddenProcessService(builder, cfg);
    // skeletons — each service registers with every
    // RPC returning grpc::Status::UNIMPLEMENTED; the P2/P3/P4 slice
    // branches wire the bodies in-place.
    RegisterTokenService(builder, cfg);
    RegisterMitigationsService(builder, cfg);
    RegisterNetworkService(builder, cfg);
    RegisterServicesService(builder, cfg);
    RegisterThreadInspectService(builder, cfg);
    // desktop input injection (SendInput-backed Click / Type / Key).
    RegisterInputService(builder, cfg);
}

} // namespace um
