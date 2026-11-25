// agent/src/host/token_mutate.cpp
//
// Mutators: AdjustTokenPrivileges / SetTokenInformation / Impersonate /
// ModifyDefaultDacl + impersonation lifecycle (dedicated worker thread,
// tombstone timer, destructor sweep).

#include "token_mutate.hpp"
#include "token_view.hpp"
#include "token_lsa.hpp"

#include <windows.h>
#include <sddl.h>
#include <processthreadsapi.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace pry::host {

namespace {

std::wstring Utf8ToW(const std::string& s) {
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                     nullptr, 0);
    if (n <= 0) return {};
    std::wstring out((size_t)n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                             out.data(), n);
    return out;
}


std::string PrivStateName(DWORD attrs) {
    if (attrs & SE_PRIVILEGE_ENABLED) return "enabled";
    if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT) return "default";
    return "disabled";
}


HANDLE OpenTargetTokenMutate(uint32_t pid, uint32_t tid, DWORD mask,
                              std::string* err) {
    HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                   (DWORD)pid);
    if (!hProc) {
        if (err) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "OpenProcess failed err=0x%08lx",
                          (unsigned long)::GetLastError());
            *err = buf;
        }
        return nullptr;
    }
    HANDLE hTok = nullptr;
    if (tid != 0) {
        HANDLE hThr = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION |
                                      THREAD_SET_LIMITED_INFORMATION,
                                      FALSE, (DWORD)tid);
        if (hThr) {
            if (::OpenThreadToken(hThr, mask, TRUE, &hTok)) {
                ::CloseHandle(hThr);
                ::CloseHandle(hProc);
                return hTok;
            }
            ::CloseHandle(hThr);
        }
    }
    if (!::OpenProcessToken(hProc, mask, &hTok)) {
        if (err) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "OpenProcessToken failed err=0x%08lx",
                          (unsigned long)::GetLastError());
            *err = buf;
        }
        hTok = nullptr;
    }
    ::CloseHandle(hProc);
    return hTok;
}

}  // namespace


AdjustPrivilegeResult AdjustPrivilege(
    uint32_t pid, uint32_t tid, const std::string& privilege_name,
    uint32_t luid_low, uint32_t luid_high, const std::string& action) {
    AdjustPrivilegeResult r;
    HANDLE tok = OpenTargetTokenMutate(pid, tid, TOKEN_ADJUST_PRIVILEGES |
                                                   TOKEN_QUERY,
                                         &r.err);
    if (!tok) return r;
    LUID luid{};
    if (luid_low == 0 && luid_high == 0) {
        std::wstring w = Utf8ToW(privilege_name);
        if (w.empty() ||
            !::LookupPrivilegeValueW(nullptr, w.c_str(), &luid)) {
            r.err = "LookupPrivilegeValueW failed";
            ::CloseHandle(tok);
            return r;
        }
    } else {
        luid.LowPart = luid_low;
        luid.HighPart = (LONG)luid_high;
    }
    r.luid_low = luid.LowPart;
    r.luid_high = (uint32_t)luid.HighPart;
    // Determine current attrs by scanning TokenPrivileges.
    DWORD sz = 0;
    ::GetTokenInformation(tok, TokenPrivileges, nullptr, 0, &sz);
    std::vector<unsigned char> buf(sz ? sz : 1);
    if (sz == 0 || !::GetTokenInformation(tok, TokenPrivileges,
                                             buf.data(), sz, &sz)) {
        r.err = "GetTokenInformation(TokenPrivileges) failed";
        ::CloseHandle(tok);
        return r;
    }
    auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
    DWORD existing_attrs = 0;
    bool present = false;
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
        if (tp->Privileges[i].Luid.LowPart == luid.LowPart &&
            tp->Privileges[i].Luid.HighPart == luid.HighPart) {
            existing_attrs = tp->Privileges[i].Attributes;
            present = true;
            break;
        }
    }
    r.previous_state = present ? PrivStateName(existing_attrs) : "absent";
    DWORD new_attrs = 0;
    if (action == "enable") new_attrs = SE_PRIVILEGE_ENABLED;
    else if (action == "disable") new_attrs = 0;
    else if (action == "remove") new_attrs = SE_PRIVILEGE_REMOVED;
    else {
        r.err = "unknown action";
        ::CloseHandle(tok);
        return r;
    }
    TOKEN_PRIVILEGES ntp{};
    ntp.PrivilegeCount = 1;
    ntp.Privileges[0].Luid = luid;
    ntp.Privileges[0].Attributes = new_attrs;
    if (!::AdjustTokenPrivileges(tok, FALSE, &ntp, sizeof(ntp), nullptr,
                                   nullptr)) {
        char buf2[96];
        std::snprintf(buf2, sizeof(buf2),
                      "AdjustTokenPrivileges failed err=0x%08lx",
                      (unsigned long)::GetLastError());
        r.err = buf2;
        ::CloseHandle(tok);
        return r;
    }
    DWORD last = ::GetLastError();
    if (last == ERROR_NOT_ALL_ASSIGNED) {
        // Soft error: slice 01 §Edge cases — fold into ok=true, state=absent.
        r.ok = true;
        r.previous_state = "absent";
        r.new_state = "absent";
        r.err = "ERROR_NOT_ALL_ASSIGNED";
        ::CloseHandle(tok);
        return r;
    }
    r.ok = true;
    if (action == "remove") r.new_state = "absent";
    else r.new_state = PrivStateName(new_attrs);
    ::CloseHandle(tok);
    return r;
}


SetIntegrityResult SetIntegrityLevel(uint32_t pid, uint32_t tid,
                                      uint32_t rid,
                                      const std::string& name) {
    SetIntegrityResult r;
    if (rid == 0 && !name.empty()) {
        if      (name == "untrusted")   rid = 0x0000;
        else if (name == "low")         rid = 0x1000;
        else if (name == "medium")      rid = 0x2000;
        else if (name == "medium_plus") rid = 0x2100;
        else if (name == "high")        rid = 0x3000;
        else if (name == "system")      rid = 0x4000;
        else { r.err = "unknown integrity name"; return r; }
    }
    if (rid == 0) { r.err = "integrity_rid required"; return r; }
    HANDLE tok = OpenTargetTokenMutate(
        pid, tid, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &r.err);
    if (!tok) return r;
    DWORD sz = 0;
    ::GetTokenInformation(tok, TokenIntegrityLevel, nullptr, 0, &sz);
    std::vector<unsigned char> cur(sz ? sz : 1);
    if (sz && ::GetTokenInformation(tok, TokenIntegrityLevel,
                                       cur.data(), sz, &sz)) {
        auto* ml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(cur.data());
        if (ml->Label.Sid) {
            UCHAR* cnt = ::GetSidSubAuthorityCount(ml->Label.Sid);
            if (cnt && *cnt > 0) {
                DWORD* prev = ::GetSidSubAuthority(ml->Label.Sid,
                                                     (DWORD)(*cnt - 1));
                if (prev) r.previous_rid = *prev;
            }
        }
    }
    char sidbuf[64];
    std::snprintf(sidbuf, sizeof(sidbuf), "S-1-16-%u", (unsigned)rid);
    PSID sid = nullptr;
    std::wstring w = Utf8ToW(sidbuf);
    if (!::ConvertStringSidToSidW(w.c_str(), &sid)) {
        r.err = "ConvertStringSidToSidW failed";
        ::CloseHandle(tok);
        return r;
    }
    TOKEN_MANDATORY_LABEL ml{};
    ml.Label.Attributes = SE_GROUP_INTEGRITY;
    ml.Label.Sid = sid;
    DWORD need = sizeof(TOKEN_MANDATORY_LABEL) + ::GetLengthSid(sid);
    if (!::SetTokenInformation(tok, TokenIntegrityLevel, &ml, need)) {
        char buf2[96];
        std::snprintf(buf2, sizeof(buf2),
                      "SetTokenInformation(IL) failed err=0x%08lx",
                      (unsigned long)::GetLastError());
        r.err = buf2;
        ::LocalFree(sid);
        ::CloseHandle(tok);
        return r;
    }
    r.ok = true;
    r.new_rid = rid;
    ::LocalFree(sid);
    ::CloseHandle(tok);
    return r;
}


SetVirtualizationResult SetVirtualization(uint32_t pid, uint32_t tid,
                                           bool enable) {
    SetVirtualizationResult r;
    HANDLE tok = OpenTargetTokenMutate(
        pid, tid, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &r.err);
    if (!tok) return r;
    DWORD prev = 0, got = 0;
    if (::GetTokenInformation(tok, TokenVirtualizationEnabled, &prev,
                                sizeof(prev), &got)) {
        r.previous = (prev != 0);
    }
    DWORD newv = enable ? 1 : 0;
    if (!::SetTokenInformation(tok, TokenVirtualizationEnabled, &newv,
                                 sizeof(newv))) {
        char buf2[96];
        std::snprintf(buf2, sizeof(buf2),
                      "SetTokenInformation(Virt) failed err=0x%08lx",
                      (unsigned long)::GetLastError());
        r.err = buf2;
        ::CloseHandle(tok);
        return r;
    }
    r.ok = true;
    r.new_value = enable;
    ::CloseHandle(tok);
    return r;
}


ModifyDaclResult ModifyDefaultDacl(uint32_t pid, uint32_t tid,
                                    const std::vector<DaclAceRow>& aces,
                                    bool replace) {
    ModifyDaclResult r;
    HANDLE tok = OpenTargetTokenMutate(
        pid, tid, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &r.err);
    if (!tok) return r;
    // Current default DACL (kept when merging).
    DWORD sz = 0;
    ::GetTokenInformation(tok, TokenDefaultDacl, nullptr, 0, &sz);
    std::vector<unsigned char> cur(sz ? sz : 1);
    PACL oldDacl = nullptr;
    if (sz && ::GetTokenInformation(tok, TokenDefaultDacl, cur.data(),
                                       sz, &sz)) {
        auto* d = reinterpret_cast<TOKEN_DEFAULT_DACL*>(cur.data());
        oldDacl = d->DefaultDacl;
        if (oldDacl) {
            r.ace_count_before = oldDacl->AceCount;
        }
    }
    // Mechanics audit P1: replace=false (the proto default) MERGES — the
    // existing ACEs are kept and the new ones added. It used to always
    // wipe-and-set (`(void)replace;`).
    const bool merge = !replace && oldDacl != nullptr;
    DWORD daclSize = sizeof(ACL);
    BYTE revision = ACL_REVISION;
    if (merge) {
        ACL_SIZE_INFORMATION si{};
        if (!::GetAclInformation(oldDacl, &si, sizeof(si), AclSizeInformation)) {
            r.err = "GetAclInformation(current default DACL) failed";
            ::CloseHandle(tok);
            return r;
        }
        daclSize = si.AclBytesInUse;
        if (oldDacl->AclRevision > revision) revision = oldDacl->AclRevision;
    }
    std::vector<PSID> psids;
    psids.reserve(aces.size());
    auto freeSids = [&] { for (auto p : psids) ::LocalFree(p); };
    for (const auto& a : aces) {
        PSID sid = nullptr;
        std::wstring sw = Utf8ToW(a.sid);
        if (!::ConvertStringSidToSidW(sw.c_str(), &sid)) {
            r.err = "ConvertStringSidToSidW failed";
            freeSids();
            ::CloseHandle(tok);
            return r;
        }
        if (a.type != "allow" && a.type != "deny" && !a.type.empty()) {
            ::LocalFree(sid);
            r.err = "ace type must be allow|deny (got " + a.type + ")";
            freeSids();
            ::CloseHandle(tok);
            return r;
        }
        psids.push_back(sid);
        daclSize += sizeof(ACCESS_ALLOWED_ACE) + ::GetLengthSid(sid)
                    - sizeof(DWORD);
    }
    daclSize = (daclSize + 3) & ~3u; // DWORD-aligned ACL size
    std::vector<unsigned char> daclbuf(daclSize ? daclSize : 1);
    auto* dacl = reinterpret_cast<PACL>(daclbuf.data());
    if (!::InitializeAcl(dacl, daclSize, revision)) {
        r.err = "InitializeAcl failed";
        freeSids();
        ::CloseHandle(tok);
        return r;
    }
    // Canonical order: new deny ACEs, then the existing ACEs (already
    // canonical), then new allow ACEs.
    auto addNew = [&](bool deny) -> bool {
        for (size_t i = 0; i < aces.size(); ++i) {
            const auto& a = aces[i];
            if ((a.type == "deny") != deny) continue;
            BOOL ok = deny
                ? ::AddAccessDeniedAceEx(dacl, revision, a.flags, a.access_mask, psids[i])
                : ::AddAccessAllowedAceEx(dacl, revision, a.flags, a.access_mask, psids[i]);
            if (!ok) return false;
        }
        return true;
    };
    bool built = addNew(true);
    if (built && merge) {
        for (DWORD i = 0; i < oldDacl->AceCount && built; ++i) {
            LPVOID ace = nullptr;
            if (!::GetAce(oldDacl, i, &ace)) { built = false; break; }
            auto* hdr = reinterpret_cast<ACE_HEADER*>(ace);
            built = ::AddAce(dacl, revision, MAXDWORD, ace, hdr->AceSize) != FALSE;
        }
    }
    if (built) built = addNew(false);
    if (!built) {
        char buf2[96];
        std::snprintf(buf2, sizeof(buf2), "building DACL failed err=0x%08lx",
                      (unsigned long)::GetLastError());
        r.err = buf2;
        freeSids();
        ::CloseHandle(tok);
        return r;
    }
    TOKEN_DEFAULT_DACL td{};
    td.DefaultDacl = dacl;
    if (!::SetTokenInformation(tok, TokenDefaultDacl, &td, sizeof(td))) {
        char buf2[96];
        std::snprintf(buf2, sizeof(buf2),
                      "SetTokenInformation(DefaultDacl) failed err=0x%08lx",
                      (unsigned long)::GetLastError());
        r.err = buf2;
        freeSids();
        ::CloseHandle(tok);
        return r;
    }
    r.ok = true;
    r.ace_count_after = dacl->AceCount;
    freeSids();
    ::CloseHandle(tok);
    return r;
}


// ------------------------------------------------- Impersonation ----

static std::string MakeImpersonationId() {
    char buf[48];
    std::snprintf(buf, sizeof(buf), "imp-%08lx-%08lx",
                  (unsigned long)::GetCurrentProcessId(),
                  (unsigned long)::GetTickCount());
    return std::string(buf);
}


struct ImpersonationWorker {
    HANDLE dup = nullptr;
    bool persist = false;
    std::mutex mu;
    std::condition_variable cv;
    bool stop = false;
    HANDLE started = nullptr;  // set once SetThreadToken ran
    bool token_set = false;
    DWORD set_err = 0;
    ~ImpersonationWorker() {
        if (dup) ::CloseHandle(dup);
        if (started) ::CloseHandle(started);
    }
    void Stop() {
        {
            std::lock_guard<std::mutex> lk(mu);
            stop = true;
        }
        cv.notify_all();
    }
};

static DWORD WINAPI ImpersonationThread(LPVOID p) {
    // Own a reference for the thread's lifetime; the registry holds another.
    std::unique_ptr<std::shared_ptr<ImpersonationWorker>> hold(
        static_cast<std::shared_ptr<ImpersonationWorker>*>(p));
    ImpersonationWorker& w = **hold;
    w.token_set = ::SetThreadToken(nullptr, w.dup) != FALSE;
    w.set_err = w.token_set ? 0 : ::GetLastError();
    ::SetEvent(w.started);
    if (w.token_set) {
        std::unique_lock<std::mutex> lk(w.mu);
        auto deadline = std::chrono::steady_clock::now() +
            (w.persist ? std::chrono::seconds(300) : std::chrono::seconds(30));
        w.cv.wait_until(lk, deadline, [&] { return w.stop; });
    }
    ::SetThreadToken(nullptr, nullptr);  // revert
    return 0;
}

static std::string LevelName(SECURITY_IMPERSONATION_LEVEL l) {
    switch (l) {
    case SecurityAnonymous:      return "anonymous";
    case SecurityIdentification: return "identification";
    case SecurityImpersonation:  return "impersonation";
    case SecurityDelegation:     return "delegation";
    default:                     return "unknown";
    }
}

// Signal the worker and wait for it; never TerminateThread. A worker that
// does not exit in time (it only waits on its CV) leaks its thread handle
// rather than being killed mid-revert.
static void StopWorker(ImpersonationRegistry::Entry& e) {
    if (e.worker) e.worker->Stop();
    HANDLE th = (HANDLE)e.worker_thread;
    if (th) {
        if (::WaitForSingleObject(th, 5000) == WAIT_OBJECT_0) {
            ::CloseHandle(th);
        }
        e.worker_thread = nullptr;
    }
}


ImpersonateResult StartImpersonation(uint32_t source_pid, uint32_t source_tid,
                                      bool persist,
                                      const std::string& impersonation_level) {
    ImpersonateResult r;
    SECURITY_IMPERSONATION_LEVEL lvl = SecurityImpersonation;
    if      (impersonation_level == "anonymous")      lvl = SecurityAnonymous;
    else if (impersonation_level == "identification") lvl = SecurityIdentification;
    else if (impersonation_level == "impersonation" ||
             impersonation_level.empty())             lvl = SecurityImpersonation;
    else if (impersonation_level == "delegation")     lvl = SecurityDelegation;
    else {
        r.err = "impersonation_level must be anonymous|identification|"
                "impersonation|delegation";
        return r;
    }
    HANDLE src_tok = OpenTargetTokenMutate(source_pid, source_tid,
                                             TOKEN_DUPLICATE | TOKEN_QUERY,
                                             &r.err);
    if (!src_tok) return r;
    HANDLE dup = nullptr;
    if (!::DuplicateTokenEx(src_tok, TOKEN_QUERY | TOKEN_IMPERSONATE |
                                       TOKEN_DUPLICATE,
                              nullptr, lvl, TokenImpersonation, &dup)) {
        char buf[96];
        std::snprintf(buf, sizeof(buf),
                      "DuplicateTokenEx failed err=0x%08lx",
                      (unsigned long)::GetLastError());
        r.err = buf;
        ::CloseHandle(src_tok);
        return r;
    }
    ::CloseHandle(src_tok);
    // Report the level the duplicate actually carries, not the request.
    SECURITY_IMPERSONATION_LEVEL got = lvl;
    DWORD gl = 0;
    ::GetTokenInformation(dup, TokenImpersonationLevel, &got, sizeof(got), &gl);

    // A dedicated agent worker thread holds the impersonation (proto:
    // target_tid == 0) until StopImpersonate or the tombstone
    // (30 s / 300 s persist).
    auto w = std::make_shared<ImpersonationWorker>();
    w->dup = dup;
    w->persist = persist;
    w->started = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!w->started) {
        r.err = "CreateEvent failed";
        return r;  // ~ImpersonationWorker closes dup
    }
    auto* hold = new std::shared_ptr<ImpersonationWorker>(w);
    DWORD tid = 0;
    HANDLE th = ::CreateThread(nullptr, 0, &ImpersonationThread, hold, 0, &tid);
    if (!th) {
        delete hold;
        r.err = "CreateThread failed";
        return r;
    }
    if (::WaitForSingleObject(w->started, 5000) != WAIT_OBJECT_0 || !w->token_set) {
        char buf[96];
        std::snprintf(buf, sizeof(buf), "SetThreadToken failed err=0x%08lx",
                      (unsigned long)w->set_err);
        r.err = buf;
        w->Stop();
        if (::WaitForSingleObject(th, 5000) == WAIT_OBJECT_0) ::CloseHandle(th);
        return r;
    }
    r.ok = true;
    r.impersonation_id =
        GlobalImpersonationRegistry().Register(dup, th, tid, persist, w);
    r.agent_thread_id = (uint32_t)tid;
    r.level_granted = LevelName(got);
    return r;
}


bool StopImpersonation(const std::string& impersonation_id,
                       std::string* err) {
    return GlobalImpersonationRegistry().Clear(impersonation_id, err);
}


// Registry
std::string ImpersonationRegistry::Register(void* dup_token,
                                             void* worker_thread,
                                             uint32_t agent_tid,
                                             bool persist,
                                             std::shared_ptr<ImpersonationWorker> worker) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string id = MakeImpersonationId();
    // Collision guard: tick-based ids on fast platforms can collide.
    for (int bump = 1; live_.count(id); ++bump) {
        char suf[8];
        std::snprintf(suf, sizeof(suf), "-%d", bump);
        id = MakeImpersonationId() + suf;
    }
    Entry e;
    e.dup_token = dup_token;
    e.worker_thread = worker_thread;
    e.agent_tid = agent_tid;
    e.persist = persist;
    e.worker = std::move(worker);
    e.tombstone_at = std::chrono::steady_clock::now() +
        (persist ? std::chrono::seconds(300) : std::chrono::seconds(30));
    live_[id] = e;
    return id;
}


bool ImpersonationRegistry::Clear(const std::string& id, std::string* err) {
    Entry e;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = live_.find(id);
        if (it == live_.end()) {
            if (err) *err = "impersonation_id not found";
            return false;
        }
        e = std::move(it->second);
        live_.erase(it);
    }
    StopWorker(e);  // outside mu_: waits up to 5 s for the worker to revert
    return true;
}


size_t ImpersonationRegistry::SweepExpired() {
    auto now = std::chrono::steady_clock::now();
    std::vector<Entry> expired;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = live_.begin(); it != live_.end();) {
            if (now >= it->second.tombstone_at) {
                expired.push_back(std::move(it->second));
                it = live_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& e : expired) StopWorker(e);
    return expired.size();
}


void ImpersonationRegistry::ClearAll() {
    std::vector<Entry> all;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [id, e] : live_) all.push_back(std::move(e));
        live_.clear();
    }
    for (auto& e : all) StopWorker(e);
}


size_t ImpersonationRegistry::Size() {
    std::lock_guard<std::mutex> lk(mu_);
    return live_.size();
}


bool ImpersonationRegistry::HasId(const std::string& id) {
    std::lock_guard<std::mutex> lk(mu_);
    return live_.count(id) != 0;
}


bool ImpersonationRegistry::Peek(const std::string& id, Entry* out) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = live_.find(id);
    if (it == live_.end()) return false;
    if (out) *out = it->second;
    return true;
}


ImpersonationRegistry& GlobalImpersonationRegistry() {
    static ImpersonationRegistry g;
    return g;
}

}  // namespace pry::host
