// umagent/src/services_thread_inspect.cpp
//
// Umagent-side ThreadInspect service. Fills the five umagent-only
// columns (impersonation / COM apartment / RPC usage / power throttling
// / fiber) directly via documented Win32 APIs. The two driver-backed
// columns (wait_info / irp_list) return error='no_driver' so the
// orchestrator fan-out routes them to the agent view.
//
// Slice doc §Edge cases: a 2s timeout wraps GetThreadWaitChain (the worker
// thread is detached when it expires) so a DC-latency WCT API call never
// blocks the RPC. COM apartment + fiber both ReadProcessMemory the TEB
// fields at documented x64 offsets (ReservedForOle=0x1758; SameTebFlags=
// 0x17EE, a 16-bit field whose bit 2 is HasFiberData).

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <wct.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "um_services.hpp"
#include "umem.hpp"

#pragma comment(lib, "advapi32.lib")

namespace um {

namespace {

constexpr const char* kNoDriver =
    "no_driver: route via name='' (agent/driver view) for driver-backed "
    "columns";

constexpr uint64_t kTebReservedForOleOffset = 0x1758;
// TEB.SameTebFlags is a 16-bit bitfield word (SafeThunkCall:0, InDebugPrint:1,
// HasFiberData:2, SkipThreadAttach:3, WerInShipAssertCode:4, RanProcessInit:5,
// ClonedThread:6, ..., InitialThread:10, SessionAware:11, ...). HasFiberData
// is bit 2 only — read the whole word and mask, never test the byte: the
// initial thread's RanProcessInit (bit 5) would read as "has fiber data".
// Verified on Windows 11 26100: a fresh thread reads 0x0000, the initial
// thread 0x0420, and ConvertThreadToFiber turns a thread's word into 0x0004.
constexpr uint64_t kTebSameTebFlagsOffset   = 0x17EE;
constexpr uint16_t kTebHasFiberDataMask     = 0x0004;

// NtQueryInformationThread class 49 — ThreadPowerThrottlingState. Not
// exported through <winternl.h>; redeclare the function pointer and
// struct locally.
constexpr ULONG kThreadPowerThrottlingState = 49;
struct POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
};

using NtQueryInformationThread_t = NTSTATUS (NTAPI*)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength);

static NtQueryInformationThread_t ResolveNtQueryThread()
{
    static std::once_flag once;
    static NtQueryInformationThread_t fn = nullptr;
    std::call_once(once, []() {
        HMODULE h = GetModuleHandleW(L"ntdll.dll");
        if (h) fn = reinterpret_cast<NtQueryInformationThread_t>(
            GetProcAddress(h, "NtQueryInformationThread"));
    });
    return fn;
}

// NtQueryInformationThread(ThreadBasicInformation=0): THREAD_BASIC_INFORMATION
// -> TebBaseAddress. Used by COM apartment + fiber probes.
static uint64_t ReadTebBase(HANDLE hThread)
{
    auto fn = ResolveNtQueryThread();
    if (!fn) return 0;
    struct TBI {
        NTSTATUS ExitStatus;
        PVOID TebBaseAddress;
        CLIENT_ID ClientId;
        KAFFINITY AffinityMask;
        LONG Priority;
        LONG BasePriority;
    } tbi{};
    ULONG rl = 0;
    NTSTATUS st = fn(hThread, 0, &tbi, sizeof(tbi), &rl);
    if (!NT_SUCCESS(st)) return 0;
    return reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
}

static std::string NtStatusHex(NTSTATUS st)
{
    char buf[16]{};
    _snprintf_s(buf, _TRUNCATE, "0x%08X", (unsigned)st);
    return buf;
}

// Failed NtQueryInformationThread -> error text. The hex status leads (the
// orchestrator keys 0xC0000022 -> access_denied off it), then the symbolic
// name when it is one we expect, then which query failed.
static std::string NtStatusText(NTSTATUS st, const char* what)
{
    const char* name = nullptr;
    switch (static_cast<ULONG>(st)) {
    case 0xC0000003: name = "STATUS_INVALID_INFO_CLASS"; break;
    case 0xC0000004: name = "STATUS_INFO_LENGTH_MISMATCH"; break;
    case 0xC0000008: name = "STATUS_INVALID_HANDLE"; break;
    case 0xC000000D: name = "STATUS_INVALID_PARAMETER"; break;
    case 0xC0000022: name = "STATUS_ACCESS_DENIED"; break;
    case 0xC000004B: name = "STATUS_THREAD_IS_TERMINATING"; break;
    default: break;
    }
    std::string s = NtStatusHex(st);
    if (name) {
        s += ' ';
        s += name;
    }
    s += " (";
    s += what;
    s += ')';
    return s;
}

// OpenThread failure -> error text. Same split Impersonation uses (thread
// gone / access refused / anything else); the failing right, tid and Win32
// code are kept so the refusal is attributable.
static std::string OpenThreadFailureText(DWORD gle, const char* right, uint32_t tid)
{
    if (gle == ERROR_INVALID_PARAMETER || gle == ERROR_NOT_FOUND) {
        return "no_thread";
    }
    std::string what = "OpenThread(";
    what += right;
    what += ") tid=" + std::to_string(tid);
    return std::string(gle == ERROR_ACCESS_DENIED ? "access_denied: "
                                                  : "open_thread_failed: ") +
           um::WinError(what.c_str(), gle);
}

static std::string WideToUtf8(const wchar_t* w, size_t maxLen)
{
    const size_t len = wcsnlen(w, maxLen);
    if (!len) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len), out.data(), n,
                        nullptr, nullptr);
    return out;
}

// ---- Wait Chain Traversal (RpcUsage) ---------------------------------------

// One WCT pass for a tid, run on a worker thread (see RpcUsage). Plain data
// only: the worker never touches the gRPC response.
struct WctOutcome {
    bool ok = false;
    const char* api = "";   // failing API when !ok
    DWORD gle = 0;          // its GetLastError()
    DWORD count = 0;        // chain length WCT reported (may exceed `kept`)
    DWORD kept = 0;         // valid entries in nodes[]
    WAITCHAIN_NODE_INFO nodes[WCT_MAX_NODE_COUNT]{};
};

static WctOutcome RunWaitChain(DWORD tid)
{
    WctOutcome o;
    // Synchronous session (Flags=0, no callback): GetThreadWaitChain hands
    // the chain back directly instead of through the async callback.
    HWCT ses = OpenThreadWaitChainSession(0, nullptr);
    if (!ses) {
        o.api = "OpenThreadWaitChainSession";
        o.gle = GetLastError();
        return o;
    }
    // NodeCount may not exceed WCT_MAX_NODE_COUNT (16): a larger array makes
    // GetThreadWaitChain fail with ERROR_INVALID_PARAMETER for every thread
    // — which is what the old 32-entry buffer did (the generic wct_failed).
    DWORD count = WCT_MAX_NODE_COUNT;
    BOOL cycle = FALSE;
    SetLastError(ERROR_SUCCESS);
    // 2nd arg is a DWORD_PTR Context (opaque pass-through to the async
    // callback — the session is synchronous so it is 0). Flags: the explicit
    // "all out-of-proc" combo (WCT_DEFAULT_FLAGS isn't in every SDK).
    const BOOL ok = GetThreadWaitChain(ses, 0, WCTP_GETINFO_ALL_FLAGS, tid,
                                       &count, o.nodes, &cycle);
    const DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
    CloseThreadWaitChainSession(ses);
    // ERROR_MORE_DATA: the chain has more nodes than the array holds and
    // `count` carries the true length — report that, scan what fit.
    if (!ok && gle != ERROR_MORE_DATA) {
        o.api = "GetThreadWaitChain";
        o.gle = gle;
        return o;
    }
    o.ok = true;
    o.count = count;
    o.kept = std::min<DWORD>(count, WCT_MAX_NODE_COUNT);
    return o;
}

// Chain-node types that mean the thread is blocked in an RPC / COM call
// (RPC runs over ALPC; COM adds its own call/activation nodes).
static bool IsRpcFlavoured(WCT_OBJECT_TYPE t)
{
    return t == WctAlpcType || t == WctComType || t == WctComActivationType;
}

// WCT names an ALPC node after its port, and RPC's local transport lives under
// "\RPC Control\<endpoint>" (seen live: a client blocked in an ncalrpc call
// has Alpc node '\RPC Control\<endpoint>'). Report that the way an RPC string
// binding reads — "lrpc:[epmapper]" — and pass any other node name through.
static std::string RpcServerLabel(const std::string& nodeName)
{
    static const char kPrefix[] = "\\RPC Control\\";
    constexpr size_t kLen = sizeof(kPrefix) - 1;
    if (nodeName.size() > kLen && _strnicmp(nodeName.c_str(), kPrefix, kLen) == 0) {
        return "lrpc:[" + nodeName.substr(kLen) + "]";
    }
    return nodeName;
}

// RpcUsage failure text. Known tokens lead (the orchestrator maps those to
// kinds and hints); the API, tid, Win32 code and system message follow, so
// a failure names its cause instead of a bare "wct_failed".
static std::string WctFailureText(const WctOutcome& o, uint32_t tid)
{
    const char* token = "";
    if (o.gle == ERROR_ACCESS_DENIED) {
        token = "access_denied: ";
    } else if (o.gle == ERROR_INVALID_PARAMETER &&
               std::strcmp(o.api, "GetThreadWaitChain") == 0) {
        // NodeCount is inside WCT_MAX_NODE_COUNT, so what is left of
        // ERROR_INVALID_PARAMETER is a thread id that does not exist.
        token = "no_thread: ";
    }
    std::string what = o.api;
    what += " tid=" + std::to_string(tid);
    return token + um::WinError(what.c_str(), o.gle);
}

static DWORD TidToPid(uint32_t tid)
{
    HANDLE t = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!t) return 0;
    DWORD pid = GetProcessIdOfThread(t);
    CloseHandle(t);
    return pid;
}

static std::string LookupSid(PSID sid, bool* is_self)
{
    if (is_self) *is_self = false;
    if (!sid) return {};
    wchar_t name[256]{};
    wchar_t domain[256]{};
    DWORD cName = _countof(name);
    DWORD cDomain = _countof(domain);
    SID_NAME_USE use{};
    if (!LookupAccountSidW(nullptr, sid, name, &cName,
                            domain, &cDomain, &use)) {
        return {};
    }
    std::wstring w;
    w.reserve(cDomain + 1 + cName);
    w.assign(domain, cDomain);
    if (cDomain) w += L"\\";
    w.append(name, cName);
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                 nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                         out.data(), n, nullptr, nullptr);
    if (is_self) {
        // compare against current-process primary token user
        HANDLE me = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &me)) {
            DWORD need = 0;
            GetTokenInformation(me, TokenUser, nullptr, 0, &need);
            std::vector<BYTE> buf(need);
            if (need && GetTokenInformation(me, TokenUser, buf.data(),
                                              need, &need)) {
                auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
                *is_self = EqualSid(tu->User.Sid, sid) == TRUE;
            }
            CloseHandle(me);
        }
    }
    return out;
}

static std::string SidToStringUtf8(PSID sid)
{
    if (!sid) return {};
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sid, &s)) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0,
                                 nullptr, nullptr);
    std::string out(n ? n - 1 : 0, '\0');
    if (n) WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n,
                                 nullptr, nullptr);
    LocalFree(s);
    return out;
}

static const char* ImpLevelName(SECURITY_IMPERSONATION_LEVEL lvl)
{
    switch (lvl) {
    case SecurityAnonymous:       return "Anonymous";
    case SecurityIdentification:  return "Identification";
    case SecurityImpersonation:   return "Impersonation";
    case SecurityDelegation:      return "Delegation";
    default: return "Unknown";
    }
}

class ThreadInspectSvc final : public pry::ThreadInspect::Service {
public:
    explicit ThreadInspectSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status WaitInfo(::grpc::ServerContext*,
                          const pry::ThreadWaitInfoRequest*,
                          pry::ThreadWaitInfoResponse* resp) override {
        resp->set_error("no_driver");
        FillStatus(resp, kNoDriver);
        return grpc::Status::OK;
    }

    grpc::Status IrpList(::grpc::ServerContext*,
                         const pry::ThreadIrpListRequest*,
                         pry::ThreadIrpListResponse* resp) override {
        resp->set_error("no_driver");
        resp->set_pending(false);
        resp->set_irp_count(0);
        FillStatus(resp, kNoDriver);
        return grpc::Status::OK;
    }

    grpc::Status Impersonation(::grpc::ServerContext*,
                               const pry::ThreadImpersonationRequest* req,
                               pry::ThreadImpersonationResponse* resp) override {
        if (req->tid() == 0) {
            resp->set_error("no_thread");
            FillStatus(resp, "Impersonation: tid required");
            return grpc::Status::OK;
        }
        HANDLE t = OpenThread(THREAD_QUERY_INFORMATION, FALSE,
                               (DWORD)req->tid());
        if (!t) {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER || err == ERROR_NOT_FOUND) {
                resp->set_error("no_thread");
            } else if (err == ERROR_ACCESS_DENIED) {
                resp->set_error("access_denied");
            } else {
                resp->set_error("open_thread_failed");
            }
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        HANDLE tok = nullptr;
        BOOL opened = OpenThreadToken(t, TOKEN_QUERY, TRUE, &tok);
        if (!opened) {
            CloseHandle(t);
            DWORD err = GetLastError();
            resp->set_present(false);
            if (err == ERROR_NO_TOKEN) {
                // Thread runs under its process primary token — this
                // is the no-impersonation case; present=false is the
                // honest answer with no error.
                FillStatus(resp, "");
                return grpc::Status::OK;
            }
            resp->set_error(err == ERROR_ACCESS_DENIED
                             ? "access_denied" : "open_thread_token_failed");
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        resp->set_present(true);
        // Impersonation level.
        SECURITY_IMPERSONATION_LEVEL lvl = SecurityAnonymous;
        DWORD rl = 0;
        if (GetTokenInformation(tok, TokenImpersonationLevel,
                                 &lvl, sizeof(lvl), &rl)) {
            resp->set_level(ImpLevelName(lvl));
        }
        DWORD need = 0;
        GetTokenInformation(tok, TokenUser, nullptr, 0, &need);
        std::vector<BYTE> buf(need);
        if (need && GetTokenInformation(tok, TokenUser, buf.data(),
                                          need, &need)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
            bool is_self = false;
            resp->set_user(LookupSid(tu->User.Sid, &is_self));
            resp->set_sid(SidToStringUtf8(tu->User.Sid));
            resp->set_is_self(is_self);
        }
        CloseHandle(tok);
        CloseHandle(t);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ComApartment(::grpc::ServerContext*,
                              const pry::ThreadComApartmentRequest* req,
                              pry::ThreadComApartmentResponse* resp) override {
        if (req->tid() == 0) {
            resp->set_error("no_thread");
            FillStatus(resp, "ComApartment: tid required");
            return grpc::Status::OK;
        }
        HANDLE t = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE,
                               (DWORD)req->tid());
        if (!t) {
            resp->set_error("no_thread");
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        uint64_t teb = ReadTebBase(t);
        DWORD pid = GetProcessIdOfThread(t);
        CloseHandle(t);
        if (!teb) {
            resp->set_error("no_teb");
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        uint64_t rfo = 0;
        size_t got = 0;
        std::string err;
        if (!um::MemRead(pid, teb + kTebReservedForOleOffset, &rfo,
                          sizeof(rfo), &got, &err) || got != sizeof(rfo)) {
            resp->set_error(err.empty() ? "read_teb_failed" : err);
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        resp->set_teb_rfo(rfo);
        // TEB.ReservedForOle=NULL means "no COM for this thread yet".
        // When present, it's a pointer to the SOleTlsData struct; we
        // report the apartment classification from the low bits of its
        // dwFlags field (word @ +0xC) when readable — but reading it
        // crosses a documented hazardous boundary (COM runtime
        // internals), so this build ships the ReservedForOle VA as the
        // honest observation, apartment type unknown-until-wave-3.
        resp->set_type(rfo ? "oletls" : "none");
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status RpcUsage(::grpc::ServerContext*,
                          const pry::ThreadRpcUsageRequest* req,
                          pry::ThreadRpcUsageResponse* resp) override {
        if (req->tid() == 0) {
            resp->set_error("no_thread");
            FillStatus(resp, "RpcUsage: tid required");
            return grpc::Status::OK;
        }
        // Dedicated worker + 2s timeout per slice doc §Edge cases:
        // GetThreadWaitChain can block for minutes against a slow DC. The
        // worker is detached and owns its state through the shared promise,
        // so giving up on it neither blocks this RPC nor leaves it writing
        // into a dead frame (a std::async future would block in its
        // destructor until the stuck WCT call returned — no timeout at all).
        auto job = std::make_shared<std::promise<WctOutcome>>();
        std::future<WctOutcome> fut = job->get_future();
        try {
            std::thread([job, tid = static_cast<DWORD>(req->tid())]() {
                job->set_value(RunWaitChain(tid));
            }).detach();
        } catch (const std::system_error& e) {
            resp->set_error(std::string("wct worker thread could not start: ") +
                            e.what());
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        if (fut.wait_for(std::chrono::seconds(2)) != std::future_status::ready) {
            resp->set_error("wct_timeout");
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        const WctOutcome o = fut.get();
        if (!o.ok) {
            resp->set_error(WctFailureText(o, req->tid()));
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        resp->set_chain_length(o.count);
        // in_rpc_call: the chain passes through an ALPC / COM node, i.e. the
        // thread is parked in an RPC or COM call. `server` is that node's
        // object name (the RPC endpoint) when WCT supplies one.
        bool in_rpc = false;
        std::string server;
        for (DWORD i = 0; i < o.kept; ++i) {
            const WAITCHAIN_NODE_INFO& n = o.nodes[i];
            if (!IsRpcFlavoured(n.ObjectType)) continue;
            in_rpc = true;
            if (server.empty()) {
                server = RpcServerLabel(WideToUtf8(n.LockObject.ObjectName,
                                                   WCT_OBJNAME_LENGTH));
            }
        }
        resp->set_in_rpc_call(in_rpc);
        if (!server.empty()) resp->set_server(server);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status PowerThrottling(::grpc::ServerContext*,
                                 const pry::ThreadPowerThrottlingRequest* req,
                                 pry::ThreadPowerThrottlingResponse* resp) override {
        if (req->tid() == 0) {
            resp->set_error("no_thread");
            FillStatus(resp, "PowerThrottling: tid required");
            return grpc::Status::OK;
        }
        // NtQueryInformationThread(ThreadPowerThrottlingState) checks the
        // handle for THREAD_QUERY_INFORMATION: with the limited right it
        // returns STATUS_ACCESS_DENIED for every thread, our own included.
        HANDLE t = OpenThread(THREAD_QUERY_INFORMATION, FALSE,
                               (DWORD)req->tid());
        if (!t) {
            resp->set_error(OpenThreadFailureText(
                GetLastError(), "THREAD_QUERY_INFORMATION", req->tid()));
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        auto fn = ResolveNtQueryThread();
        if (!fn) {
            CloseHandle(t);
            resp->set_error("not_supported");
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        POWER_THROTTLING_STATE pts{};
        pts.Version = 1;  // THREAD_POWER_THROTTLING_CURRENT_VERSION
        ULONG rl = 0;
        NTSTATUS st = fn(t, kThreadPowerThrottlingState,
                          &pts, sizeof(pts), &rl);
        CloseHandle(t);
        if (!NT_SUCCESS(st)) {
            resp->set_error(NtStatusText(
                st, "NtQueryInformationThread class 49 "
                    "ThreadPowerThrottlingState"));
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        resp->set_control_mask(pts.ControlMask);
        resp->set_state_mask(pts.StateMask);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Fiber(::grpc::ServerContext*,
                       const pry::ThreadFiberRequest* req,
                       pry::ThreadFiberResponse* resp) override {
        if (req->tid() == 0) {
            resp->set_error("no_thread");
            FillStatus(resp, "Fiber: tid required");
            return grpc::Status::OK;
        }
        HANDLE t = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE,
                               (DWORD)req->tid());
        if (!t) {
            resp->set_error("no_thread");
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        uint64_t teb = ReadTebBase(t);
        DWORD pid = GetProcessIdOfThread(t);
        CloseHandle(t);
        if (!teb) {
            resp->set_error("no_teb");
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        // Whole 16-bit SameTebFlags word, then the HasFiberData bit — a
        // one-byte read tested "!= 0" reports any other flag in the low byte
        // (the initial thread's RanProcessInit) as a fiber.
        uint16_t flags = 0;
        size_t got = 0;
        std::string err;
        if (!um::MemRead(pid, teb + kTebSameTebFlagsOffset, &flags,
                          sizeof(flags), &got, &err) || got != sizeof(flags)) {
            resp->set_error(err.empty() ? "read_teb_failed" : err);
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        resp->set_has_fiber_data((flags & kTebHasFiberDataMask) != 0);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

}  // namespace

void RegisterThreadInspectService(grpc::ServerBuilder& builder, const Config& cfg) {
    static ThreadInspectSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
