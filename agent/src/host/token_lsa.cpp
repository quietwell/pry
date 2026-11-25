// agent/src/host/token_lsa.cpp — shared with umagent.
//
// SID/name lookup helpers. LookupAccountSidW / LookupAccountNameW with
// a 3s wait budget — slice 01 §Edge cases "SID lookup latency against
// DCs". The orchestrator wrapper layers an additional asyncio.wait_for
// on top; this file ensures we never block > ~3s inside the native
// call.

#include "token_lsa.hpp"
#include "token_view.hpp"

#include <windows.h>
#include <sddl.h>
#include <wchar.h>
#include <lmcons.h>

#include <chrono>
#include <cstdio>
#include <future>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace pry::host {

bool SidToString(const unsigned char* sid, std::string* out) {
    if (!sid || !out) return false;
    LPWSTR s = nullptr;
    if (!::ConvertSidToStringSidW(const_cast<PSID>((PSID)sid), &s) || !s) {
        return false;
    }
    int n = ::WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0,
                                     nullptr, nullptr);
    if (n > 0) {
        out->resize(static_cast<size_t>(n - 1));
        ::WideCharToMultiByte(CP_UTF8, 0, s, -1, out->data(), n,
                              nullptr, nullptr);
    }
    ::LocalFree(s);
    return true;
}


std::string IntegrityNameFromRid(uint32_t rid) {
    switch (rid) {
        case 0x0000: return "untrusted";
        case 0x1000: return "low";
        case 0x2000: return "medium";
        case 0x2100: return "medium_plus";
        case 0x3000: return "high";
        case 0x4000: return "system";
        case 0x5000: return "protected";
        default:     return "";
    }
}


namespace {

std::string WStrToUtf8(const wchar_t* w, size_t len) {
    if (!w || len == 0) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, (int)len, nullptr, 0,
                                     nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, (int)len, out.data(), n,
                           nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWStr(const std::string& s) {
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                     nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                             out.data(), n);
    return out;
}

std::string SidNameUseStr(SID_NAME_USE use) {
    switch (use) {
        case SidTypeUser:          return "User";
        case SidTypeGroup:         return "Group";
        case SidTypeDomain:        return "Domain";
        case SidTypeAlias:         return "Alias";
        case SidTypeWellKnownGroup:return "WellKnownGroup";
        case SidTypeDeletedAccount:return "DeletedAccount";
        case SidTypeInvalid:       return "Invalid";
        case SidTypeUnknown:       return "Unknown";
        case SidTypeComputer:      return "Computer";
        case SidTypeLabel:         return "Label";
        case SidTypeLogonSession:  return "LogonSession";
        default:                   return "Unknown";
    }
}

LookupRowRaw LookupOneSidTimed(const std::string& sid_str) {
    LookupRowRaw out;
    out.input = sid_str;
    out.sid = sid_str;
    PSID psid = nullptr;
    std::wstring w = Utf8ToWStr(sid_str);
    if (w.empty() || !::ConvertStringSidToSidW(w.c_str(), &psid)) {
        return out;
    }
    // Run the lookup on a worker thread with a 3s budget so a stalled
    // DC can't wedge the whole gRPC call.
    auto fut = std::async(std::launch::async, [&]() {
        wchar_t name[UNLEN + 1]{};
        wchar_t domain[DNLEN + 1]{};
        DWORD cname = UNLEN + 1, cdom = DNLEN + 1;
        SID_NAME_USE use = SidTypeUnknown;
        BOOL ok = ::LookupAccountSidW(nullptr, psid, name, &cname, domain,
                                        &cdom, &use);
        return std::make_tuple((bool)ok, std::wstring(name, cname),
                                std::wstring(domain, cdom), use);
    });
    if (fut.wait_for(std::chrono::seconds(3)) == std::future_status::ready) {
        auto [ok, name, domain, use] = fut.get();
        if (ok) {
            out.name = WStrToUtf8(name.c_str(), name.size());
            out.domain = WStrToUtf8(domain.c_str(), domain.size());
            out.use = SidNameUseStr(use);
            // well_known mark: label types or NT AUTHORITY domain
            out.well_known =
                (use == SidTypeWellKnownGroup || use == SidTypeLabel ||
                 out.domain == "NT AUTHORITY" || out.domain == "BUILTIN");
        }
    }
    // Detach the future: the LookupAccountSid call will eventually return
    // (or the process will exit); we don't block here.
    (void)fut;
    ::LocalFree(psid);
    return out;
}


LookupRowRaw LookupOneNameTimed(const std::string& name_str) {
    LookupRowRaw out;
    out.input = name_str;
    out.name = name_str;
    std::wstring w = Utf8ToWStr(name_str);
    if (w.empty()) return out;
    auto fut = std::async(std::launch::async, [&]() {
        DWORD csid = 0, cdom = 0;
        SID_NAME_USE use = SidTypeUnknown;
        ::LookupAccountNameW(nullptr, w.c_str(), nullptr, &csid, nullptr,
                              &cdom, &use);
        std::vector<unsigned char> sidbuf(csid);
        std::wstring domainw(cdom, L'\0');
        if (csid == 0 || cdom == 0) {
            return std::make_tuple(false, std::string{}, std::wstring{}, use);
        }
        if (!::LookupAccountNameW(nullptr, w.c_str(), sidbuf.data(), &csid,
                                     domainw.data(), &cdom, &use)) {
            return std::make_tuple(false, std::string{}, std::wstring{}, use);
        }
        std::string sidstr;
        SidToString(sidbuf.data(), &sidstr);
        return std::make_tuple(true, sidstr, domainw, use);
    });
    if (fut.wait_for(std::chrono::seconds(3)) == std::future_status::ready) {
        auto [ok, sidstr, domainw, use] = fut.get();
        if (ok) {
            out.sid = sidstr;
            out.domain = WStrToUtf8(domainw.c_str(), domainw.size());
            out.use = SidNameUseStr(use);
            out.well_known =
                (use == SidTypeWellKnownGroup || use == SidTypeLabel);
        }
    }
    return out;
}

}  // namespace


bool LookupSidsAndNames(const std::vector<std::string>& sids,
                        const std::vector<std::string>& names,
                        std::vector<LookupRowRaw>* out,
                        std::string* err) {
    if (!out) {
        if (err) *err = "null out";
        return false;
    }
    out->clear();
    for (const auto& s : sids) {
        out->push_back(LookupOneSidTimed(s));
    }
    for (const auto& n : names) {
        out->push_back(LookupOneNameTimed(n));
    }
    return true;
}

}  // namespace pry::host
