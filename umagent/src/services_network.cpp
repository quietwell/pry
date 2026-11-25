// umagent/src/services_network.cpp
//
// umagent-only Network service: TCP+UDP (v4+v6) IPHLPAPI snapshot,
// reverse-DNS LRU cache, Service-Tag resolution for svchost rows via
// I_QueryTagInformation, and SetTcpEntry(MIB_TCP_STATE_DELETE_TCB) kill
// (double-gated: orchestrator checks security.allow_kill_connection,
// the Kill RPC refuses regardless if the local/remote inputs are
// malformed). No driver dependency; agent-side mirror is intentionally
// absent (the kernel view returns kind='bad_arg' at the MCP layer).

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "um_services.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace um {

namespace {

// ----- auth -----------------------------------------------------------------

grpc::Status CheckAuthNet(grpc::ServerContext* ctx,
                           const std::string& token)
{
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

// ----- helpers --------------------------------------------------------------

static std::string FormatV4(uint32_t be_addr, uint16_t be_port)
{
    in_addr a;
    a.S_un.S_addr = be_addr;
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    char out[INET_ADDRSTRLEN + 8];
    snprintf(out, sizeof(out), "%s:%u", buf, ntohs(be_port));
    return out;
}

static std::string FormatV6(const uint8_t addr[16], uint32_t scope_id,
                             uint16_t be_port)
{
    in6_addr a{};
    memcpy(&a, addr, 16);
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    char out[INET6_ADDRSTRLEN + 32];
    if (scope_id) {
        snprintf(out, sizeof(out), "[%s%%%u]:%u", buf, scope_id,
                 ntohs(be_port));
    } else {
        snprintf(out, sizeof(out), "[%s]:%u", buf, ntohs(be_port));
    }
    return out;
}

static const char* TcpStateName(DWORD s)
{
    switch (s) {
        case MIB_TCP_STATE_CLOSED:      return "CLOSED";
        case MIB_TCP_STATE_LISTEN:      return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:     return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
        default:                        return "";
    }
}

static DWORD TcpStateFromName(const std::string& name)
{
    if (name == "ESTABLISHED") return MIB_TCP_STATE_ESTAB;
    if (name == "LISTEN" || name == "LISTENING") return MIB_TCP_STATE_LISTEN;
    if (name == "CLOSED") return MIB_TCP_STATE_CLOSED;
    if (name == "SYN_SENT") return MIB_TCP_STATE_SYN_SENT;
    if (name == "SYN_RCVD") return MIB_TCP_STATE_SYN_RCVD;
    if (name == "FIN_WAIT_1") return MIB_TCP_STATE_FIN_WAIT1;
    if (name == "FIN_WAIT_2") return MIB_TCP_STATE_FIN_WAIT2;
    if (name == "CLOSE_WAIT") return MIB_TCP_STATE_CLOSE_WAIT;
    if (name == "CLOSING") return MIB_TCP_STATE_CLOSING;
    if (name == "LAST_ACK") return MIB_TCP_STATE_LAST_ACK;
    if (name == "TIME_WAIT") return MIB_TCP_STATE_TIME_WAIT;
    return MIB_TCP_STATE_ESTAB;
}

static bool IsLoopbackV4(uint32_t be_addr)
{
    // 127.0.0.0/8
    return (ntohl(be_addr) >> 24) == 127;
}

static bool IsLoopbackV6(const uint8_t a[16])
{
    for (int i = 0; i < 15; ++i) if (a[i] != 0) return false;
    return a[15] == 1;
}

// Case-insensitive compare of two std::strings in ASCII.
static bool IEqualAscii(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = (char)::tolower((unsigned char)a[i]);
        char cb = (char)::tolower((unsigned char)b[i]);
        if (ca != cb) return false;
    }
    return true;
}

static bool ContainsCI(const std::vector<std::string>& v,
                        const std::string& s)
{
    if (v.empty()) return true;  // empty filter == match everything
    for (const auto& e : v) if (IEqualAscii(e, s)) return true;
    return false;
}

// ----- process-name cache ---------------------------------------------------

static std::string PidImageBase(DWORD pid)
{
    if (pid == 0) return "System Idle";
    if (pid == 4) return "System";
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    wchar_t buf[MAX_PATH]{};
    DWORD n = (DWORD)std::size(buf);
    std::string out;
    if (::QueryFullProcessImageNameW(h, 0, buf, &n) && n > 0) {
        const wchar_t* slash = wcsrchr(buf, L'\\');
        const wchar_t* name = slash ? slash + 1 : buf;
        int ulen = ::WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0,
                                          nullptr, nullptr);
        if (ulen > 0) {
            out.resize((size_t)ulen - 1);
            ::WideCharToMultiByte(CP_UTF8, 0, name, -1, out.data(), ulen,
                                   nullptr, nullptr);
        }
    }
    ::CloseHandle(h);
    return out;
}

class PidCache {
public:
    std::string get(DWORD pid)
    {
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = m_.find(pid);
            if (it != m_.end()) return it->second;
        }
        // Touch the kernel outside the lock so a slow OpenProcess
        // doesn't serialize every row.
        std::string name = PidImageBase(pid);
        std::lock_guard<std::mutex> lk(mu_);
        m_[pid] = name;
        return name;
    }
private:
    std::mutex mu_;
    std::unordered_map<DWORD, std::string> m_;
};

// ----- Service-Tag resolver -------------------------------------------------
// I_QueryTagInformation is an undocumented ntdll+advapi32 symbol. Resolve
// lazily; graceful degrade if the loader can't find it.

// Mirror of the undocumented TAG_INFO_NAME_FROM_TAG name_from_tag[0] = 1.
struct SCM_TAG_INFO {
    DWORD InClass;
    DWORD InTagHandle;
    DWORD OutServiceTag;
    DWORD OutServiceNameLen;
    PWSTR OutServiceName;
    DWORD OutClassOffset;
};

using PfnQueryTagInformation = DWORD (WINAPI*)(PCWSTR, DWORD, SCM_TAG_INFO*);

static PfnQueryTagInformation GetQueryTag()
{
    static std::atomic<PfnQueryTagInformation> cached{nullptr};
    static std::atomic<bool> probed{false};
    if (!probed.load(std::memory_order_acquire)) {
        HMODULE adv = ::GetModuleHandleW(L"advapi32.dll");
        PfnQueryTagInformation fn = nullptr;
        if (adv) {
            fn = (PfnQueryTagInformation)::GetProcAddress(
                adv, "I_QueryTagInformation");
        }
        cached.store(fn, std::memory_order_release);
        probed.store(true, std::memory_order_release);
    }
    return cached.load(std::memory_order_acquire);
}

static std::string ResolveServiceTag(DWORD pid, DWORD tag)
{
    if (tag == 0) return "";
    PfnQueryTagInformation fn = GetQueryTag();
    if (!fn) return "";
    SCM_TAG_INFO info{};
    info.InClass = 1;        // eTagInfoLevelNameFromTag
    info.InTagHandle = tag;
    // Signature wants a module name; passing the current host DLL name is
    // what SI uses. Null here reads the per-service-group table.
    DWORD rc = fn(nullptr, pid, &info);
    if (rc != ERROR_SUCCESS || info.OutServiceName == nullptr) return "";
    int ulen = ::WideCharToMultiByte(CP_UTF8, 0, info.OutServiceName, -1,
                                      nullptr, 0, nullptr, nullptr);
    std::string out;
    if (ulen > 0) {
        out.resize((size_t)ulen - 1);
        ::WideCharToMultiByte(CP_UTF8, 0, info.OutServiceName, -1,
                               out.data(), ulen, nullptr, nullptr);
    }
    ::LocalFree(info.OutServiceName);
    return out;
}

// ----- reverse-DNS LRU cache -----------------------------------------------
// Bounded (256 entries), background worker fills via GetNameInfoW. Reads
// are strict cache lookups; a miss enqueues a resolution and returns "".

struct DnsKey {
    int family;        // AF_INET / AF_INET6
    uint8_t raw[16];   // v4 uses raw[0..3], big-endian

    bool operator==(const DnsKey& o) const noexcept {
        return family == o.family &&
               memcmp(raw, o.raw, 16) == 0;
    }
};
struct DnsKeyHash {
    size_t operator()(const DnsKey& k) const noexcept {
        // FNV-1a on raw bytes.
        uint64_t h = 1469598103934665603ULL;
        for (int i = 0; i < 16; ++i) {
            h ^= k.raw[i];
            h *= 1099511628211ULL;
        }
        h ^= (uint64_t)k.family * 0x9E3779B97F4A7C15ULL;
        return (size_t)h;
    }
};

struct DnsEntry {
    std::string host;
    std::chrono::steady_clock::time_point stored;
    bool negative;
};

class DnsCache {
public:
    DnsCache() : stop_(false), hits_(0), misses_(0)
    {
        worker_ = std::thread([this]{ Worker(); });
    }
    ~DnsCache() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    // Read: cache hit returns the string; miss enqueues a job and
    // returns "". ``ttl`` is 60s for live rows, 60s for negatives.
    std::string lookup(int family, const uint8_t raw[16])
    {
        DnsKey k{};
        k.family = family;
        memcpy(k.raw, raw, 16);
        std::unique_lock<std::mutex> lk(mu_);
        auto it = map_.find(k);
        if (it != map_.end()) {
            auto now = std::chrono::steady_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                           now - it->second.stored).count();
            auto ttl = it->second.negative ? 60 : 60;
            if (age < ttl) {
                hits_.fetch_add(1, std::memory_order_relaxed);
                // Touch LRU: move to front.
                lru_.erase(it->second.lru_it);
                lru_.push_front(k);
                it->second.lru_it = lru_.begin();
                return it->second.entry.host;
            }
            // Stale — drop + fall through to enqueue.
            lru_.erase(it->second.lru_it);
            map_.erase(it);
        }
        misses_.fetch_add(1, std::memory_order_relaxed);
        // Enqueue, de-dup by presence in pending_.
        if (pending_.insert(k).second) {
            queue_.push_back(k);
            cv_.notify_one();
        }
        return "";
    }

    void snapshot(uint32_t* hits, uint32_t* misses, uint32_t* size) const
    {
        if (hits)   *hits   = (uint32_t)hits_.load(std::memory_order_relaxed);
        if (misses) *misses = (uint32_t)misses_.load(std::memory_order_relaxed);
        std::lock_guard<std::mutex> lk(mu_);
        if (size)   *size   = (uint32_t)map_.size();
    }

    static DnsCache& instance() {
        static DnsCache c;
        return c;
    }

private:
    struct Record {
        DnsEntry entry;
        std::list<DnsKey>::iterator lru_it;
        bool negative;
        std::chrono::steady_clock::time_point stored;
    };

    static constexpr size_t kMaxEntries = 256;
    static constexpr size_t kMaxQueue  = 1024;

    void Worker()
    {
        // One WSAStartup pair for the resolver's lifetime.
        WSADATA wsd{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsd) != 0) return;

        while (true) {
            DnsKey k{};
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [this]{
                    return stop_ || !queue_.empty();
                });
                if (stop_) break;
                k = queue_.front();
                queue_.pop_front();
                pending_.erase(k);
            }
            std::string host;
            bool negative = false;
            if (k.family == AF_INET) {
                sockaddr_in sa{};
                sa.sin_family = AF_INET;
                memcpy(&sa.sin_addr, k.raw, 4);
                wchar_t wbuf[NI_MAXHOST]{};
                int rc = ::GetNameInfoW((sockaddr*)&sa, sizeof(sa),
                                         wbuf, (DWORD)std::size(wbuf),
                                         nullptr, 0, NI_NAMEREQD);
                if (rc == 0) {
                    char ubuf[NI_MAXHOST]{};
                    int ulen = ::WideCharToMultiByte(CP_UTF8, 0, wbuf, -1,
                                                      ubuf, sizeof(ubuf),
                                                      nullptr, nullptr);
                    if (ulen > 0) host.assign(ubuf, (size_t)ulen - 1);
                } else {
                    negative = true;
                }
            } else {
                sockaddr_in6 sa{};
                sa.sin6_family = AF_INET6;
                memcpy(&sa.sin6_addr, k.raw, 16);
                wchar_t wbuf[NI_MAXHOST]{};
                int rc = ::GetNameInfoW((sockaddr*)&sa, sizeof(sa),
                                         wbuf, (DWORD)std::size(wbuf),
                                         nullptr, 0, NI_NAMEREQD);
                if (rc == 0) {
                    char ubuf[NI_MAXHOST]{};
                    int ulen = ::WideCharToMultiByte(CP_UTF8, 0, wbuf, -1,
                                                      ubuf, sizeof(ubuf),
                                                      nullptr, nullptr);
                    if (ulen > 0) host.assign(ubuf, (size_t)ulen - 1);
                } else {
                    negative = true;
                }
            }
            Store(k, host, negative);
        }

        ::WSACleanup();
    }

    void Store(const DnsKey& k, const std::string& host, bool negative)
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(k);
        if (it != map_.end()) {
            lru_.erase(it->second.lru_it);
            map_.erase(it);
        }
        while (map_.size() >= kMaxEntries) {
            if (lru_.empty()) break;
            DnsKey old = lru_.back();
            lru_.pop_back();
            map_.erase(old);
        }
        lru_.push_front(k);
        Record rec;
        rec.entry.host = host;
        rec.entry.negative = negative;
        rec.entry.stored = std::chrono::steady_clock::now();
        rec.lru_it = lru_.begin();
        rec.negative = negative;
        rec.stored = rec.entry.stored;
        map_.emplace(k, std::move(rec));
    }

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::thread worker_;
    bool stop_;
    std::atomic<uint64_t> hits_;
    std::atomic<uint64_t> misses_;
    std::list<DnsKey> lru_;
    std::deque<DnsKey> queue_;
    struct DnsKeyEq {
        bool operator()(const DnsKey& a, const DnsKey& b) const noexcept {
            return a == b;
        }
    };
    std::unordered_map<DnsKey, Record, DnsKeyHash, DnsKeyEq> map_;
    std::unordered_set<DnsKey, DnsKeyHash, DnsKeyEq> pending_;
};

// ----- extended TCP/UDP enumerator ------------------------------------------

// On Windows SDKs the OWNER_MODULE variants return a flat table whose row
// struct carries OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE] (uint64 words).
// We only project the first slot's module name — the rest is reserved.

template <typename Row>
static void ProjectModuleNames(const Row& r, pry::NetConnEntry* out)
{
    // Not every SDK exposes a free-standing GetOwnerModuleFromTcpEntry
    // signature we can forward through. The row's OwningModuleInfo[0]
    // is normally a module-info pointer index — surfacing it as a hex
    // tag gives orchestrator-side callers something to key on without
    // us guessing a struct layout per SDK rev.
    (void)r;
    (void)out;
}

static void FillTcpV4Row(const MIB_TCPROW_OWNER_MODULE& r,
                          pry::NetConnEntry* row)
{
    row->set_proto("tcp");
    row->set_family("v4");
    row->set_pid(r.dwOwningPid);
    row->set_state(TcpStateName(r.dwState));
    row->set_local(FormatV4(r.dwLocalAddr, (uint16_t)r.dwLocalPort));
    // Remote is only meaningful when connected / closing-ish.
    bool has_remote = r.dwState != MIB_TCP_STATE_LISTEN;
    row->set_remote(has_remote
        ? FormatV4(r.dwRemoteAddr, (uint16_t)r.dwRemotePort)
        : std::string(""));
    row->set_create_time_ms(
        (uint64_t)(r.liCreateTimestamp.QuadPart / 10000ULL));
    ProjectModuleNames(r, row);
}

static void FillTcpV6Row(const MIB_TCP6ROW_OWNER_MODULE& r,
                          pry::NetConnEntry* row)
{
    row->set_proto("tcp");
    row->set_family("v6");
    row->set_pid(r.dwOwningPid);
    row->set_state(TcpStateName(r.dwState));
    row->set_scope_id_local(r.dwLocalScopeId);
    row->set_scope_id_remote(r.dwRemoteScopeId);
    row->set_local(FormatV6(r.ucLocalAddr, r.dwLocalScopeId,
                             (uint16_t)r.dwLocalPort));
    bool has_remote = r.dwState != MIB_TCP_STATE_LISTEN;
    row->set_remote(has_remote
        ? FormatV6(r.ucRemoteAddr, r.dwRemoteScopeId,
                   (uint16_t)r.dwRemotePort)
        : std::string(""));
    row->set_create_time_ms(
        (uint64_t)(r.liCreateTimestamp.QuadPart / 10000ULL));
    ProjectModuleNames(r, row);
}

static void FillUdpV4Row(const MIB_UDPROW_OWNER_MODULE& r,
                          pry::NetConnEntry* row)
{
    row->set_proto("udp");
    row->set_family("v4");
    row->set_pid(r.dwOwningPid);
    row->set_local(FormatV4(r.dwLocalAddr, (uint16_t)r.dwLocalPort));
    row->set_create_time_ms(
        (uint64_t)(r.liCreateTimestamp.QuadPart / 10000ULL));
}

static void FillUdpV6Row(const MIB_UDP6ROW_OWNER_MODULE& r,
                          pry::NetConnEntry* row)
{
    row->set_proto("udp");
    row->set_family("v6");
    row->set_pid(r.dwOwningPid);
    row->set_scope_id_local(r.dwLocalScopeId);
    row->set_local(FormatV6(r.ucLocalAddr, r.dwLocalScopeId,
                             (uint16_t)r.dwLocalPort));
    row->set_create_time_ms(
        (uint64_t)(r.liCreateTimestamp.QuadPart / 10000ULL));
}

// NetListRequest.module_resolve (was parsed by nobody): owning module via
// GetOwnerModuleFrom{Tcp,Tcp6,Udp,Udp6}Entry, the documented iphlpapi
// resolver for OWNER_MODULE rows. Best effort per row — a row whose owner
// cannot be resolved (process gone, access denied, kernel-owned socket)
// simply carries no owning_module_names.
template <typename Row, typename Fn>
static void ResolveOwnerModule(Fn fn, const Row& r, pry::NetConnEntry* out)
{
    DWORD sz = 0;
    DWORD rc = fn(const_cast<Row*>(&r), TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &sz);
    if (rc != ERROR_INSUFFICIENT_BUFFER || sz == 0 || sz > 64 * 1024) {
        return;
    }
    std::vector<BYTE> buf(sz);
    if (fn(const_cast<Row*>(&r), TCPIP_OWNER_MODULE_INFO_BASIC, buf.data(), &sz) != NO_ERROR) {
        return;
    }
    auto* info = reinterpret_cast<const TCPIP_OWNER_MODULE_BASIC_INFO*>(buf.data());
    if (!info->pModuleName || !*info->pModuleName) {
        return;
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, info->pModuleName, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) {
        return;
    }
    std::string name((size_t)(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, info->pModuleName, -1, name.data(), n, nullptr, nullptr);
    out->add_owning_module_names(name);
}

// Owning service tag lives in SpecificPortBind member? No — this SDK
// uses dwOwningPid + the thread's service-tag at the time of creation.
// `GetOwnedTag` wraps a per-row probe that only succeeds for svchost
// children; everything else returns 0.
static DWORD GetRowServiceTag(DWORD pid, const BYTE* row_raw, size_t sz)
{
    // The OWNER_MODULE rows carry OwningModuleInfo[0] which, on current
    // Windows SDKs, is the DWORD service tag used by svchost.exe. SDK
    // headers inconsistently expose this through u.ServiceTag — read
    // the first qword and mask the low 32 bits as a conservative fallback
    // the way SI does.
    if (sz < sizeof(uint64_t)) return 0;
    (void)pid;
    uint64_t slot0 = *reinterpret_cast<const uint64_t*>(row_raw);
    return (DWORD)(slot0 & 0xFFFFFFFFu);
}

// ----- parse "ip:port" ------------------------------------------------------

static bool ParseEndpoint(const std::string& s, int& family,
                           uint8_t raw[16], uint32_t& scope_id,
                           uint16_t& port)
{
    // Accept "a.b.c.d:p" and "[addr%scope]:p".
    if (s.empty()) return false;
    scope_id = 0;
    if (s.front() == '[') {
        size_t rb = s.find(']');
        if (rb == std::string::npos) return false;
        std::string inside = s.substr(1, rb - 1);
        if (rb + 2 >= s.size() || s[rb + 1] != ':') return false;
        std::string pstr = s.substr(rb + 2);
        size_t pct = inside.find('%');
        std::string addr = pct == std::string::npos
                            ? inside : inside.substr(0, pct);
        if (pct != std::string::npos) {
            scope_id = (uint32_t)std::strtoul(inside.c_str() + pct + 1,
                                              nullptr, 10);
        }
        in6_addr a6{};
        if (inet_pton(AF_INET6, addr.c_str(), &a6) != 1) return false;
        memcpy(raw, &a6, 16);
        family = AF_INET6;
        port = (uint16_t)std::strtoul(pstr.c_str(), nullptr, 10);
        return port != 0;
    }
    size_t colon = s.rfind(':');
    if (colon == std::string::npos) return false;
    std::string addr = s.substr(0, colon);
    std::string pstr = s.substr(colon + 1);
    in_addr a4{};
    if (inet_pton(AF_INET, addr.c_str(), &a4) != 1) return false;
    memset(raw, 0, 16);
    memcpy(raw, &a4, 4);
    family = AF_INET;
    port = (uint16_t)std::strtoul(pstr.c_str(), nullptr, 10);
    return port != 0;
}

// ----- Network service ------------------------------------------------------

class UmNetworkSvc final : public pry::Network::Service {
public:
    explicit UmNetworkSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status List(grpc::ServerContext* ctx,
                       const pry::NetListRequest* req,
                       pry::NetListResponse* resp) override
    {
        auto auth = CheckAuthNet(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        std::vector<std::string> families, protos, states;
        for (int i = 0; i < req->families_size(); ++i)
            families.push_back(req->families(i));
        for (int i = 0; i < req->protos_size(); ++i)
            protos.push_back(req->protos(i));
        for (int i = 0; i < req->states_size(); ++i)
            states.push_back(req->states(i));
        const uint32_t pid_filter = req->pid();
        const bool include_lb = req->include_loopback();
        const bool include_services = req->include_services();
        const bool resolve_hostnames = req->resolve_hostnames();
        const bool module_resolve = req->module_resolve();
        const uint32_t limit = req->limit() ? req->limit() : 64;

        auto want_proto = [&](const char* p){ return ContainsCI(protos, p); };
        auto want_family = [&](const char* f){ return ContainsCI(families, f); };
        auto want_state = [&](const std::string& s){
            if (states.empty()) return true;
            if (s.empty()) return true;  // udp has no state
            return ContainsCI(states, s);
        };

        PidCache pids;
        uint32_t total = 0;
        bool truncated = false;

        auto push_row_common = [&](DWORD pid, pry::NetConnEntry* row,
                                    DWORD svc_tag) {
            row->set_process(pids.get(pid));
            if (include_services) {
                std::string tag = ResolveServiceTag(pid, svc_tag);
                if (!tag.empty()) row->set_service_tag(tag);
            }
        };

        auto maybe_resolve_dns = [&](int fam, const uint8_t raw[16],
                                      pry::NetConnEntry* row) {
            if (!resolve_hostnames) return;
            auto& cache = DnsCache::instance();
            std::string h = cache.lookup(fam, raw);
            if (!h.empty()) row->set_remote_host(h);
        };

        // ---- TCPv4 ---------------------------------------------------------
        if (want_proto("tcp") && want_family("v4")) {
            DWORD sz = 0;
            ::GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET,
                                   TCP_TABLE_OWNER_MODULE_ALL, 0);
            std::vector<BYTE> buf(sz);
            if (sz && ::GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET,
                                             TCP_TABLE_OWNER_MODULE_ALL, 0)
                == NO_ERROR) {
                const MIB_TCPTABLE_OWNER_MODULE* t =
                    reinterpret_cast<const MIB_TCPTABLE_OWNER_MODULE*>(buf.data());
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto& r = t->table[i];
                    if (pid_filter && r.dwOwningPid != pid_filter) continue;
                    if (!include_lb && IsLoopbackV4(r.dwLocalAddr)) continue;
                    std::string sn = TcpStateName(r.dwState);
                    if (!want_state(sn)) continue;
                    ++total;
                    if (resp->items_size() >= (int)limit) {
                        truncated = true;
                        continue;
                    }
                    auto* row = resp->add_items();
                    FillTcpV4Row(r, row);
                    if (module_resolve) ResolveOwnerModule(&::GetOwnerModuleFromTcpEntry, r, row);
                    push_row_common(r.dwOwningPid, row,
                                     GetRowServiceTag(
                                         r.dwOwningPid,
                                         reinterpret_cast<const BYTE*>(
                                             r.OwningModuleInfo),
                                         sizeof(r.OwningModuleInfo)));
                    uint8_t raw[16]{};
                    memcpy(raw, &r.dwRemoteAddr, 4);
                    maybe_resolve_dns(AF_INET, raw, row);
                }
            }
        }

        // ---- TCPv6 ---------------------------------------------------------
        if (want_proto("tcp") && want_family("v6")) {
            DWORD sz = 0;
            ::GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET6,
                                   TCP_TABLE_OWNER_MODULE_ALL, 0);
            std::vector<BYTE> buf(sz);
            if (sz && ::GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET6,
                                             TCP_TABLE_OWNER_MODULE_ALL, 0)
                == NO_ERROR) {
                const MIB_TCP6TABLE_OWNER_MODULE* t =
                    reinterpret_cast<const MIB_TCP6TABLE_OWNER_MODULE*>(buf.data());
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto& r = t->table[i];
                    if (pid_filter && r.dwOwningPid != pid_filter) continue;
                    if (!include_lb && IsLoopbackV6(r.ucLocalAddr)) continue;
                    std::string sn = TcpStateName(r.dwState);
                    if (!want_state(sn)) continue;
                    ++total;
                    if (resp->items_size() >= (int)limit) {
                        truncated = true;
                        continue;
                    }
                    auto* row = resp->add_items();
                    FillTcpV6Row(r, row);
                    if (module_resolve) ResolveOwnerModule(&::GetOwnerModuleFromTcp6Entry, r, row);
                    push_row_common(r.dwOwningPid, row,
                                     GetRowServiceTag(
                                         r.dwOwningPid,
                                         reinterpret_cast<const BYTE*>(
                                             r.OwningModuleInfo),
                                         sizeof(r.OwningModuleInfo)));
                    maybe_resolve_dns(AF_INET6, r.ucRemoteAddr, row);
                }
            }
        }

        // ---- UDPv4 ---------------------------------------------------------
        if (want_proto("udp") && want_family("v4") && states.empty()) {
            DWORD sz = 0;
            ::GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET,
                                   UDP_TABLE_OWNER_MODULE, 0);
            std::vector<BYTE> buf(sz);
            if (sz && ::GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET,
                                             UDP_TABLE_OWNER_MODULE, 0)
                == NO_ERROR) {
                const MIB_UDPTABLE_OWNER_MODULE* t =
                    reinterpret_cast<const MIB_UDPTABLE_OWNER_MODULE*>(buf.data());
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto& r = t->table[i];
                    if (pid_filter && r.dwOwningPid != pid_filter) continue;
                    if (!include_lb && IsLoopbackV4(r.dwLocalAddr)) continue;
                    ++total;
                    if (resp->items_size() >= (int)limit) {
                        truncated = true;
                        continue;
                    }
                    auto* row = resp->add_items();
                    FillUdpV4Row(r, row);
                    if (module_resolve) ResolveOwnerModule(&::GetOwnerModuleFromUdpEntry, r, row);
                    push_row_common(r.dwOwningPid, row,
                                     GetRowServiceTag(
                                         r.dwOwningPid,
                                         reinterpret_cast<const BYTE*>(
                                             r.OwningModuleInfo),
                                         sizeof(r.OwningModuleInfo)));
                }
            }
        }

        // ---- UDPv6 ---------------------------------------------------------
        if (want_proto("udp") && want_family("v6") && states.empty()) {
            DWORD sz = 0;
            ::GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET6,
                                   UDP_TABLE_OWNER_MODULE, 0);
            std::vector<BYTE> buf(sz);
            if (sz && ::GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET6,
                                             UDP_TABLE_OWNER_MODULE, 0)
                == NO_ERROR) {
                const MIB_UDP6TABLE_OWNER_MODULE* t =
                    reinterpret_cast<const MIB_UDP6TABLE_OWNER_MODULE*>(buf.data());
                for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                    const auto& r = t->table[i];
                    if (pid_filter && r.dwOwningPid != pid_filter) continue;
                    if (!include_lb && IsLoopbackV6(r.ucLocalAddr)) continue;
                    ++total;
                    if (resp->items_size() >= (int)limit) {
                        truncated = true;
                        continue;
                    }
                    auto* row = resp->add_items();
                    FillUdpV6Row(r, row);
                    if (module_resolve) ResolveOwnerModule(&::GetOwnerModuleFromUdp6Entry, r, row);
                    push_row_common(r.dwOwningPid, row,
                                     GetRowServiceTag(
                                         r.dwOwningPid,
                                         reinterpret_cast<const BYTE*>(
                                             r.OwningModuleInfo),
                                         sizeof(r.OwningModuleInfo)));
                }
            }
        }

        resp->set_total(total);
        resp->set_truncated(truncated);
        uint32_t hits = 0, misses = 0, size = 0;
        DnsCache::instance().snapshot(&hits, &misses, &size);
        resp->set_dns_cache_hits(hits);
        resp->set_dns_cache_misses(misses);
        resp->set_dns_cache_size(size);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Interfaces(grpc::ServerContext* ctx,
                             const pry::NetInterfacesRequest* req,
                             pry::NetInterfacesResponse* resp) override
    {
        auto auth = CheckAuthNet(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        ULONG flags = GAA_FLAG_INCLUDE_PREFIX |
                      GAA_FLAG_INCLUDE_GATEWAYS |
                      GAA_FLAG_SKIP_MULTICAST |
                      GAA_FLAG_SKIP_ANYCAST;
        ULONG sz = 15 * 1024;
        std::vector<BYTE> buf(sz);
        DWORD rc = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
                                            &sz);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            buf.resize(sz);
            rc = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                         reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
                                         &sz);
        }
        if (rc != NO_ERROR) {
            FillStatus(resp, "GetAdaptersAddresses failed: " + std::to_string(rc));
            return grpc::Status::OK;
        }

        auto fmt_addr = [](sockaddr* sa, int prefix) -> std::string {
            char tmp[INET6_ADDRSTRLEN]{};
            if (sa->sa_family == AF_INET) {
                sockaddr_in* a = reinterpret_cast<sockaddr_in*>(sa);
                inet_ntop(AF_INET, &a->sin_addr, tmp, sizeof(tmp));
            } else {
                sockaddr_in6* a = reinterpret_cast<sockaddr_in6*>(sa);
                inet_ntop(AF_INET6, &a->sin6_addr, tmp, sizeof(tmp));
            }
            char out[INET6_ADDRSTRLEN + 8];
            snprintf(out, sizeof(out), "%s/%d", tmp, prefix);
            return out;
        };

        for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
             a != nullptr; a = a->Next) {
            if (!req->include_down() && a->OperStatus != IfOperStatusUp)
                continue;
            auto* row = resp->add_items();
            row->set_name(a->AdapterName ? a->AdapterName : "");
            char fname[256]{};
            if (a->FriendlyName) {
                ::WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
                                       fname, sizeof(fname), nullptr, nullptr);
                row->set_friendly_name(fname);
            }
            char descr[256]{};
            if (a->Description) {
                ::WideCharToMultiByte(CP_UTF8, 0, a->Description, -1,
                                       descr, sizeof(descr), nullptr, nullptr);
                row->set_description(descr);
            }
            row->set_if_index(a->IfIndex);
            row->set_if_type(a->IfType);
            switch (a->OperStatus) {
                case IfOperStatusUp:       row->set_oper_status("up"); break;
                case IfOperStatusDown:     row->set_oper_status("down"); break;
                case IfOperStatusTesting:  row->set_oper_status("testing"); break;
                default:                    row->set_oper_status("other"); break;
            }
            row->set_speed_bps(a->TransmitLinkSpeed);
            for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
                row->add_unicast(fmt_addr(u->Address.lpSockaddr,
                                           u->OnLinkPrefixLength));
            }
            for (auto* g = a->FirstGatewayAddress; g; g = g->Next) {
                char tmp[INET6_ADDRSTRLEN]{};
                if (g->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* s = reinterpret_cast<sockaddr_in*>(g->Address.lpSockaddr);
                    inet_ntop(AF_INET, &s->sin_addr, tmp, sizeof(tmp));
                } else {
                    sockaddr_in6* s = reinterpret_cast<sockaddr_in6*>(g->Address.lpSockaddr);
                    inet_ntop(AF_INET6, &s->sin6_addr, tmp, sizeof(tmp));
                }
                row->add_gateways(tmp);
            }
            for (auto* d = a->FirstDnsServerAddress; d; d = d->Next) {
                char tmp[INET6_ADDRSTRLEN]{};
                if (d->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* s = reinterpret_cast<sockaddr_in*>(d->Address.lpSockaddr);
                    inet_ntop(AF_INET, &s->sin_addr, tmp, sizeof(tmp));
                } else {
                    sockaddr_in6* s = reinterpret_cast<sockaddr_in6*>(d->Address.lpSockaddr);
                    inet_ntop(AF_INET6, &s->sin6_addr, tmp, sizeof(tmp));
                }
                row->add_dns_servers(tmp);
            }
            if (a->PhysicalAddressLength) {
                char mac[32];
                int n = 0;
                for (DWORD i = 0; i < a->PhysicalAddressLength && n < 29; ++i) {
                    n += snprintf(mac + n, sizeof(mac) - n, "%s%02X",
                                    i == 0 ? "" : ":",
                                    a->PhysicalAddress[i]);
                }
                row->set_mac(mac);
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Stats(grpc::ServerContext* ctx,
                        const pry::NetStatsRequest* req,
                        pry::NetStatsResponse* resp) override
    {
        auto auth = CheckAuthNet(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        std::vector<std::string> families, protos;
        for (int i = 0; i < req->families_size(); ++i)
            families.push_back(req->families(i));
        for (int i = 0; i < req->protos_size(); ++i)
            protos.push_back(req->protos(i));

        auto want = [&](const char* f, const char* p) {
            return ContainsCI(families, f) && ContainsCI(protos, p);
        };
        auto push = [&](const std::string& family,
                         const std::string& proto,
                         const std::string& key, uint64_t v) {
            auto* c = resp->add_counters();
            c->set_name(family + "/" + proto + "/" + key);
            c->set_value(v);
        };

        if (want("v4", "tcp")) {
            MIB_TCPSTATS st{};
            if (::GetTcpStatisticsEx(&st, AF_INET) == NO_ERROR) {
                push("v4", "tcp", "InSegs",   st.dwInSegs);
                push("v4", "tcp", "OutSegs",  st.dwOutSegs);
                push("v4", "tcp", "ActiveOpens",  st.dwActiveOpens);
                push("v4", "tcp", "PassiveOpens", st.dwPassiveOpens);
                push("v4", "tcp", "AttemptFails", st.dwAttemptFails);
                push("v4", "tcp", "EstabResets",  st.dwEstabResets);
                push("v4", "tcp", "CurrEstab",    st.dwCurrEstab);
                push("v4", "tcp", "RetransSegs",  st.dwRetransSegs);
            }
        }
        if (want("v6", "tcp")) {
            MIB_TCPSTATS st{};
            if (::GetTcpStatisticsEx(&st, AF_INET6) == NO_ERROR) {
                push("v6", "tcp", "InSegs",      st.dwInSegs);
                push("v6", "tcp", "OutSegs",     st.dwOutSegs);
                push("v6", "tcp", "CurrEstab",   st.dwCurrEstab);
                push("v6", "tcp", "RetransSegs", st.dwRetransSegs);
            }
        }
        if (want("v4", "udp")) {
            MIB_UDPSTATS st{};
            if (::GetUdpStatisticsEx(&st, AF_INET) == NO_ERROR) {
                push("v4", "udp", "InDatagrams",  st.dwInDatagrams);
                push("v4", "udp", "OutDatagrams", st.dwOutDatagrams);
                push("v4", "udp", "NoPorts",      st.dwNoPorts);
                push("v4", "udp", "InErrors",     st.dwInErrors);
            }
        }
        if (want("v6", "udp")) {
            MIB_UDPSTATS st{};
            if (::GetUdpStatisticsEx(&st, AF_INET6) == NO_ERROR) {
                push("v6", "udp", "InDatagrams",  st.dwInDatagrams);
                push("v6", "udp", "OutDatagrams", st.dwOutDatagrams);
                push("v6", "udp", "NoPorts",      st.dwNoPorts);
                push("v6", "udp", "InErrors",     st.dwInErrors);
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Kill(grpc::ServerContext* ctx,
                       const pry::NetKillRequest* req,
                       pry::NetKillResponse* resp) override
    {
        auto auth = CheckAuthNet(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        int fam_l = 0, fam_r = 0;
        uint8_t raw_l[16]{}, raw_r[16]{};
        uint32_t scope_l = 0, scope_r = 0;
        uint16_t port_l = 0, port_r = 0;
        if (!ParseEndpoint(req->local(), fam_l, raw_l, scope_l, port_l) ||
            !ParseEndpoint(req->remote(), fam_r, raw_r, scope_r, port_r) ||
            fam_l != fam_r) {
            FillStatus(resp, "kill: bad local/remote endpoint "
                              "('ip:port' each; v4/v6 must match)");
            return grpc::Status::OK;
        }
        if (fam_l != AF_INET) {
            // SetTcpEntry is IPv4-only in the Win32 headers; v6 teardown
            // routes through SetPerTcp6ConnectionEStats in later SDKs,
            // which is out of scope for this slice.
            FillStatus(resp, "kill: v6 teardown unsupported "
                              "(SetTcpEntry is v4-only)");
            return grpc::Status::OK;
        }
        MIB_TCPROW row{};
        row.dwState = MIB_TCP_STATE_DELETE_TCB;
        memcpy(&row.dwLocalAddr, raw_l, 4);
        row.dwLocalPort = htons(port_l);
        memcpy(&row.dwRemoteAddr, raw_r, 4);
        row.dwRemotePort = htons(port_r);
        DWORD rc = ::SetTcpEntry(&row);
        if (rc == NO_ERROR) {
            resp->set_killed(true);
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        resp->set_killed(false);
        std::string err;
        switch (rc) {
            case ERROR_ACCESS_DENIED:
                err = "kill: ERROR_ACCESS_DENIED — SeDebugPrivilege or SYSTEM required";
                break;
            case ERROR_INVALID_PARAMETER:
                err = "kill: ERROR_INVALID_PARAMETER — connection may have closed";
                break;
            case ERROR_MR_MID_NOT_FOUND:
                err = "kill: ERROR_MR_MID_NOT_FOUND — connection no longer exists";
                break;
            default:
                err = "kill: SetTcpEntry failed rc=" + std::to_string(rc);
                break;
        }
        FillStatus(resp, err);
        (void)req->state_hint();  // informational only
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

}  // namespace

void RegisterNetworkService(grpc::ServerBuilder& builder, const Config& cfg)
{
    static UmNetworkSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
