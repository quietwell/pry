// agent/src/host/token_view.cpp — shared with umagent.
//
// Token read-only probe. Opens the target with
// PROCESS_QUERY_LIMITED_INFORMATION + OpenProcessToken(TOKEN_QUERY), or
// OpenThreadToken when `tid` is non-zero. Caller may supply a pre-dup'd
// process handle (agent-side PPL route via Wave-1 HANDLE_DUP IOCTL —
// umagent passes 0 and lets OpenProcess fail with denied_ppl).
//
// Partial-failure strategy: every sub-fetch is wrapped so a single
// GetTokenInformation class failing records into `partial_classes` and
// leaves its fields zero rather than failing the whole call.

#include "token_view.hpp"
#include "token_lsa.hpp"

#include <windows.h>
#include <sddl.h>
#include <processthreadsapi.h>
// ntsecapi.h brings in STRING / UNICODE_STRING / PSTRING; winternl.h in
// older SDKs doesn't ifndef-guard the same typedefs so the two can't
// coexist. token_view only needs the LSA + token APIs, not winternl's
// NtQuery* surface, so drop winternl here.
#include <ntsecapi.h>
#include <lmcons.h>

// Some Windows SDK revisions ship this typedef, others don't. Define it
// locally when absent so a build against an older SDK still links.
#ifndef PRY_HAVE_TOKEN_PROCESS_TRUST_LEVEL
#define PRY_HAVE_TOKEN_PROCESS_TRUST_LEVEL 1
typedef struct _PRY_TOKEN_PROCESS_TRUST_LEVEL {
    PSID TrustLevelSid;
} PRY_TOKEN_PROCESS_TRUST_LEVEL;
#define TOKEN_PROCESS_TRUST_LEVEL PRY_TOKEN_PROCESS_TRUST_LEVEL
#endif

#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace pry::host {

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

std::string WStrToUtf8(const std::wstring& w) {
    return WStrToUtf8(w.data(), w.size());
}


void NotePartial(TokenSnapshot* out, const char* cls, DWORD err) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s:0x%08lx", cls,
                  (unsigned long)err);
    if (!out->partial_classes.empty()) out->partial_classes += ";";
    out->partial_classes += buf;
}


// Return a heap-free buffer of the specified TOKEN_INFORMATION_CLASS.
// Caller frees via `free`. On failure returns nullptr and sets err.
void* GetTokenInfoBuf(HANDLE tok, TOKEN_INFORMATION_CLASS cls,
                     DWORD* sz_out, DWORD* err_out) {
    DWORD sz = 0;
    ::GetTokenInformation(tok, cls, nullptr, 0, &sz);
    DWORD last = ::GetLastError();
    if (last != ERROR_INSUFFICIENT_BUFFER || sz == 0) {
        // Some classes return success with sz=0 — still allocate to be safe.
        if (last != 0 && last != ERROR_INSUFFICIENT_BUFFER) {
            if (err_out) *err_out = last;
            return nullptr;
        }
        if (sz == 0) sz = 1;
    }
    void* buf = ::malloc(sz);
    if (!buf) {
        if (err_out) *err_out = ERROR_OUTOFMEMORY;
        return nullptr;
    }
    std::memset(buf, 0, sz);
    if (!::GetTokenInformation(tok, cls, buf, sz, &sz)) {
        if (err_out) *err_out = ::GetLastError();
        ::free(buf);
        return nullptr;
    }
    if (sz_out) *sz_out = sz;
    if (err_out) *err_out = 0;
    return buf;
}


std::string ElevationTypeName(TOKEN_ELEVATION_TYPE t) {
    switch (t) {
        case TokenElevationTypeDefault: return "default";
        case TokenElevationTypeFull:    return "full";
        case TokenElevationTypeLimited: return "limited";
        default:                        return "unknown";
    }
}


// Reads TokenUser, resolves SID + name/domain via Lsa.
void ReadUser(HANDLE tok, TokenSnapshot* out) {
    DWORD sz = 0, err = 0;
    auto* u = (TOKEN_USER*)GetTokenInfoBuf(tok, TokenUser, &sz, &err);
    if (!u) {
        NotePartial(out, "user", err);
        return;
    }
    std::string sid_str;
    if (SidToString(reinterpret_cast<const unsigned char*>(u->User.Sid),
                    &sid_str)) {
        out->user_sid = sid_str;
    }
    // name resolution — single-SID LookupAccountSidW. LSA batching
    // lives in token_lsa.cpp; this hot path uses the simpler API.
    wchar_t name[UNLEN + 1]{};
    wchar_t domain[DNLEN + 1]{};
    DWORD cname = UNLEN + 1, cdom = DNLEN + 1;
    SID_NAME_USE use;
    if (::LookupAccountSidW(nullptr, u->User.Sid, name, &cname, domain,
                              &cdom, &use)) {
        out->user_name = WStrToUtf8(name, cname);
        out->user_domain = WStrToUtf8(domain, cdom);
    }
    ::free(u);
}


void ReadIntegrity(HANDLE tok, TokenSnapshot* out) {
    DWORD sz = 0, err = 0;
    auto* ml = (TOKEN_MANDATORY_LABEL*)GetTokenInfoBuf(
        tok, TokenIntegrityLevel, &sz, &err);
    if (!ml || !ml->Label.Sid) {
        if (ml) ::free(ml);
        if (err && err != ERROR_INVALID_PARAMETER) NotePartial(out, "integrity", err);
        return;
    }
    UCHAR* cnt = ::GetSidSubAuthorityCount(ml->Label.Sid);
    if (cnt && *cnt > 0) {
        DWORD* rid = ::GetSidSubAuthority(
            ml->Label.Sid, (DWORD)(*cnt - 1));
        if (rid) {
            out->integrity_rid = *rid;
            out->integrity_name = IntegrityNameFromRid(out->integrity_rid);
        }
    }
    ::free(ml);
}


void ReadElevation(HANDLE tok, TokenSnapshot* out) {
    DWORD sz = 0, err = 0;
    auto* et = (TOKEN_ELEVATION_TYPE*)GetTokenInfoBuf(
        tok, TokenElevationType, &sz, &err);
    if (et) {
        out->elevation_type = ElevationTypeName(*et);
        ::free(et);
    } else if (err) {
        NotePartial(out, "elevation_type", err);
    }
    TOKEN_ELEVATION e{};
    DWORD got = 0;
    if (::GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &got)) {
        out->is_elevated = (e.TokenIsElevated != 0);
    }
    // linked token: present/absent only; resolve user_sid when caller wants it
    DWORD sz2 = 0, err2 = 0;
    auto* lt = (TOKEN_LINKED_TOKEN*)GetTokenInfoBuf(
        tok, TokenLinkedToken, &sz2, &err2);
    if (lt && lt->LinkedToken) {
        out->linked_token_present = true;
        ::CloseHandle(lt->LinkedToken);
        ::free(lt);
    } else if (lt) {
        ::free(lt);
    } else if (err2 && err2 != ERROR_NO_SUCH_LOGON_SESSION) {
        NotePartial(out, "linked_token", err2);
    }
}


void ReadMandatoryPolicy(HANDLE tok, TokenSnapshot* out) {
    TOKEN_MANDATORY_POLICY mp{};
    DWORD got = 0;
    if (::GetTokenInformation(tok, TokenMandatoryPolicy, &mp, sizeof(mp),
                                &got)) {
        out->mandatory_policy = mp.Policy;
    } else {
        DWORD err = ::GetLastError();
        if (err != ERROR_INVALID_PARAMETER) {
            NotePartial(out, "mandatory_policy", err);
        }
    }
}


void ReadVirtualization(HANDLE tok, TokenSnapshot* out) {
    DWORD got = 0;
    DWORD enabled = 0, allowed = 0;
    if (::GetTokenInformation(tok, TokenVirtualizationEnabled, &enabled,
                                sizeof(enabled), &got)) {
        out->uac_virtualization_enabled = (enabled != 0);
    }
    if (::GetTokenInformation(tok, TokenVirtualizationAllowed, &allowed,
                                sizeof(allowed), &got)) {
        out->uac_virtualization_allowed = (allowed != 0);
    }
}


void ReadSession(HANDLE tok, TokenSnapshot* out) {
    DWORD sid = 0, got = 0;
    if (::GetTokenInformation(tok, TokenSessionId, &sid, sizeof(sid),
                                &got)) {
        out->session_id = sid;
    }
    DWORD sz = 0, err = 0;
    auto* ts = (TOKEN_STATISTICS*)GetTokenInfoBuf(
        tok, TokenStatistics, &sz, &err);
    if (ts) {
        out->logon_id_low = ts->AuthenticationId.LowPart;
        out->logon_id_high = (uint32_t)ts->AuthenticationId.HighPart;
        ::free(ts);
    } else if (err) {
        NotePartial(out, "statistics", err);
    }
}


void ReadAppContainer(HANDLE tok, TokenSnapshot* out) {
    DWORD got = 0;
    DWORD is_ac = 0;
    if (!::GetTokenInformation(tok, TokenIsAppContainer, &is_ac,
                                 sizeof(is_ac), &got)) {
        return;  // not an AC token
    }
    out->is_app_container = (is_ac != 0);
    if (!is_ac) return;
    DWORD sz = 0, err = 0;
    auto* ac_sid = (TOKEN_APPCONTAINER_INFORMATION*)GetTokenInfoBuf(
        tok, TokenAppContainerSid, &sz, &err);
    if (ac_sid && ac_sid->TokenAppContainer) {
        std::string s;
        if (SidToString(
                reinterpret_cast<const unsigned char*>(ac_sid->TokenAppContainer),
                &s)) {
            out->app_container_sid = s;
        }
        ::free(ac_sid);
    }
    DWORD num = 0;
    if (::GetTokenInformation(tok, TokenAppContainerNumber, &num,
                                sizeof(num), &got)) {
        out->app_container_number = num;
    }
}


void ReadTrustLabel(HANDLE tok, TokenSnapshot* out) {
    DWORD sz = 0, err = 0;
    auto* tl = (TOKEN_PROCESS_TRUST_LEVEL*)GetTokenInfoBuf(
        tok, TokenProcessTrustLevel, &sz, &err);
    if (tl && tl->TrustLevelSid) {
        std::string s;
        if (SidToString(
                reinterpret_cast<const unsigned char*>(tl->TrustLevelSid),
                &s)) {
            out->trust_label_sid = s;
        }
        ::free(tl);
    } else if (tl) {
        ::free(tl);
    }
    // trust_label_name resolution left to the LSA batcher.
}


void ReadGroups(HANDLE tok, TokenSnapshot* out) {
    DWORD sz = 0, err = 0;
    auto* tg = (TOKEN_GROUPS*)GetTokenInfoBuf(tok, TokenGroups, &sz, &err);
    if (!tg) {
        if (err) NotePartial(out, "groups", err);
        return;
    }
    for (DWORD i = 0; i < tg->GroupCount; ++i) {
        const auto& g = tg->Groups[i];
        TokenGroupRow row;
        std::string s;
        if (SidToString(
                reinterpret_cast<const unsigned char*>(g.Sid), &s)) {
            row.sid = s;
        }
        row.attributes = g.Attributes;
        row.is_deny = (g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0;
        row.is_mandatory = (g.Attributes & SE_GROUP_MANDATORY) != 0;
        row.is_integrity = (g.Attributes & SE_GROUP_INTEGRITY) != 0;
        row.is_logon_id = (g.Attributes & SE_GROUP_LOGON_ID) != 0;
        row.is_enabled = (g.Attributes & SE_GROUP_ENABLED) != 0;
        row.is_enabled_by_default =
            (g.Attributes & SE_GROUP_ENABLED_BY_DEFAULT) != 0;
        row.is_use_for_deny_only =
            (g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0;
        row.is_owner = (g.Attributes & SE_GROUP_OWNER) != 0;
        row.is_resource = (g.Attributes & SE_GROUP_RESOURCE) != 0;
        row.use = "Group";
        out->groups.push_back(std::move(row));
    }
    ::free(tg);
}


std::string PrivStateName(DWORD attrs) {
    if (attrs & SE_PRIVILEGE_ENABLED) return "enabled";
    if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT) return "default";
    return "disabled";
}


void ReadPrivileges(HANDLE tok, TokenSnapshot* out) {
    DWORD sz = 0, err = 0;
    auto* tp = (TOKEN_PRIVILEGES*)GetTokenInfoBuf(
        tok, TokenPrivileges, &sz, &err);
    if (!tp) {
        if (err) NotePartial(out, "privileges", err);
        return;
    }
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
        const auto& p = tp->Privileges[i];
        TokenPrivilegeRow row;
        row.luid_low = p.Luid.LowPart;
        row.luid_high = (uint32_t)p.Luid.HighPart;
        row.attributes = p.Attributes;
        row.state = PrivStateName(p.Attributes);
        row.enabled_by_default =
            (p.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
        // name + display name
        wchar_t namew[128]{};
        DWORD cname = 128;
        if (::LookupPrivilegeNameW(nullptr,
                                     const_cast<PLUID>(&p.Luid), namew,
                                     &cname)) {
            row.name = WStrToUtf8(namew, cname);
            wchar_t dispw[256]{};
            DWORD cdisp = 256;
            DWORD lang_id = 0;
            if (::LookupPrivilegeDisplayNameW(
                    nullptr, namew, dispw, &cdisp, &lang_id)) {
                row.display_name = WStrToUtf8(dispw, cdisp);
            }
        }
        out->privileges.push_back(std::move(row));
    }
    ::free(tp);
}


void ReadSecurityAttributes(HANDLE tok, TokenSnapshot* out) {
    DWORD sz = 0, err = 0;
    void* buf = GetTokenInfoBuf(tok, (TOKEN_INFORMATION_CLASS)31,  // TokenSecurityAttributes
                                 &sz, &err);
    if (buf && sz) {
        out->security_attributes_raw.assign(
            reinterpret_cast<const char*>(buf), sz);
    }
    if (buf) ::free(buf);
}


// Opens the token for `pid`/`tid`. tid>0 tries OpenThreadToken first
// (impersonation token); on NO_TOKEN it falls back to the process
// primary token.
HANDLE OpenTargetToken(uint32_t pid, uint32_t tid,
                       void* process_handle_override,
                       bool want_adjust_privileges,
                       bool want_adjust_default,
                       TokenSnapshot* snap,
                       std::string* err) {
    DWORD mask = TOKEN_QUERY;
    if (want_adjust_privileges) mask |= TOKEN_ADJUST_PRIVILEGES;
    if (want_adjust_default)    mask |= TOKEN_ADJUST_DEFAULT;
    HANDLE hProc = (HANDLE)process_handle_override;
    bool owned_proc = false;
    if (!hProc) {
        hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                (DWORD)pid);
        owned_proc = true;
    }
    if (!hProc) {
        if (err) {
            DWORD e = ::GetLastError();
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "OpenProcess failed err=0x%08lx "
                          "(ppl path requires HANDLE_DUP on agent view)",
                          (unsigned long)e);
            *err = buf;
        }
        return nullptr;
    }
    HANDLE hTok = nullptr;
    if (tid != 0) {
        HANDLE hThr = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION,
                                     FALSE, (DWORD)tid);
        if (hThr) {
            if (::OpenThreadToken(hThr, mask, TRUE, &hTok)) {
                if (snap) snap->token_source = "impersonation";
                if (snap) snap->thread_impersonating = true;
                ::CloseHandle(hThr);
                if (owned_proc) ::CloseHandle(hProc);
                return hTok;
            }
            DWORD e = ::GetLastError();
            if (e != ERROR_NO_TOKEN) {
                if (err) {
                    char buf[96];
                    std::snprintf(buf, sizeof(buf),
                                  "OpenThreadToken failed err=0x%08lx",
                                  (unsigned long)e);
                    *err = buf;
                }
                ::CloseHandle(hThr);
                if (owned_proc) ::CloseHandle(hProc);
                return nullptr;
            }
            ::CloseHandle(hThr);
        }
    }
    if (!::OpenProcessToken(hProc, mask, &hTok)) {
        if (err) {
            DWORD e = ::GetLastError();
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "OpenProcessToken failed err=0x%08lx",
                          (unsigned long)e);
            *err = buf;
        }
        if (owned_proc) ::CloseHandle(hProc);
        return nullptr;
    }
    if (snap) snap->token_source = "primary";
    if (owned_proc) ::CloseHandle(hProc);
    return hTok;
}

}  // namespace


bool CollectToken(uint32_t pid, uint32_t tid, const CollectOpts& opts,
                  void* process_handle_override,
                  TokenSnapshot* out, std::string* err) {
    if (!out) {
        if (err) *err = "null TokenSnapshot";
        return false;
    }
    *out = TokenSnapshot{};
    HANDLE tok = OpenTargetToken(pid, tid, process_handle_override,
                                   /*adjust_priv=*/false,
                                   /*adjust_default=*/false, out, err);
    if (!tok) return false;

    ReadUser(tok, out);
    ReadIntegrity(tok, out);
    ReadElevation(tok, out);
    ReadMandatoryPolicy(tok, out);
    ReadVirtualization(tok, out);
    ReadSession(tok, out);
    ReadAppContainer(tok, out);
    ReadTrustLabel(tok, out);
    if (opts.include_groups) ReadGroups(tok, out);
    if (opts.include_privileges) ReadPrivileges(tok, out);
    if (opts.include_security_attributes) ReadSecurityAttributes(tok, out);
    if (opts.include_logon_session) {
        // best-effort — a disconnected DC gives us empty name/domain
        std::vector<LogonSessionRow> all;
        std::string lerr;
        if (EnumLogonSessions(false, &all, &lerr)) {
            for (const auto& ls : all) {
                if (ls.logon_id_low == out->logon_id_low &&
                    ls.logon_id_high == out->logon_id_high) {
                    out->logon_session = ls;
                    out->have_logon_session = true;
                    break;
                }
            }
        }
    }
    ::CloseHandle(tok);
    if (err && !out->partial_classes.empty()) {
        *err = out->partial_classes;
    }
    return true;
}


// ---------------------------------------------------- logon sessions ----

bool EnumLogonSessions(bool include_dns_names,
                       std::vector<LogonSessionRow>* out,
                       std::string* err) {
    (void)include_dns_names;
    if (!out) {
        if (err) *err = "null out";
        return false;
    }
    out->clear();
    // LsaEnumerateLogonSessions / LsaGetLogonSessionData are in secur32.lib.
    // Loaded dynamically so pre-SP builds without secur32 still link.
    HMODULE secur32 = ::LoadLibraryA("secur32.dll");
    if (!secur32) {
        if (err) *err = "secur32.dll missing";
        return false;
    }
    using LsaEnum_t = NTSTATUS(NTAPI*)(PULONG, PLUID*);
    using LsaGetData_t = NTSTATUS(NTAPI*)(PLUID, PSECURITY_LOGON_SESSION_DATA*);
    using LsaFree_t = NTSTATUS(NTAPI*)(PVOID);
    auto enum_fn =
        (LsaEnum_t)::GetProcAddress(secur32, "LsaEnumerateLogonSessions");
    auto data_fn =
        (LsaGetData_t)::GetProcAddress(secur32, "LsaGetLogonSessionData");
    auto free_fn =
        (LsaFree_t)::GetProcAddress(secur32, "LsaFreeReturnBuffer");
    if (!enum_fn || !data_fn || !free_fn) {
        if (err) *err = "secur32 missing LsaEnumerate*";
        ::FreeLibrary(secur32);
        return false;
    }
    ULONG count = 0;
    PLUID luids = nullptr;
    if (enum_fn(&count, &luids) != 0 || !luids) {
        if (err) *err = "LsaEnumerateLogonSessions failed";
        ::FreeLibrary(secur32);
        return false;
    }
    for (ULONG i = 0; i < count; ++i) {
        PSECURITY_LOGON_SESSION_DATA d = nullptr;
        if (data_fn(&luids[i], &d) != 0 || !d) continue;
        LogonSessionRow row;
        row.logon_id_low = d->LogonId.LowPart;
        row.logon_id_high = (uint32_t)d->LogonId.HighPart;
        if (d->UserName.Buffer && d->UserName.Length) {
            row.user_name = WStrToUtf8(
                d->UserName.Buffer,
                d->UserName.Length / sizeof(wchar_t));
        }
        if (d->AuthenticationPackage.Buffer &&
            d->AuthenticationPackage.Length) {
            row.auth_domain = WStrToUtf8(
                d->AuthenticationPackage.Buffer,
                d->AuthenticationPackage.Length / sizeof(wchar_t));
        }
        row.logon_type = d->LogonType;
        row.session_id = d->Session;
        row.logon_time_100ns = d->LogonTime.QuadPart;
        if (d->LogonServer.Buffer && d->LogonServer.Length) {
            row.logon_server = WStrToUtf8(
                d->LogonServer.Buffer,
                d->LogonServer.Length / sizeof(wchar_t));
        }
        if (d->DnsDomainName.Buffer && d->DnsDomainName.Length) {
            row.dns_domain_name = WStrToUtf8(
                d->DnsDomainName.Buffer,
                d->DnsDomainName.Length / sizeof(wchar_t));
        }
        if (d->Upn.Buffer && d->Upn.Length) {
            row.upn = WStrToUtf8(d->Upn.Buffer,
                                   d->Upn.Length / sizeof(wchar_t));
        }
        row.user_flags = d->UserFlags;
        // logon_type_name
        switch (d->LogonType) {
            case 2:  row.logon_type_name = "Interactive"; break;
            case 3:  row.logon_type_name = "Network"; break;
            case 4:  row.logon_type_name = "Batch"; break;
            case 5:  row.logon_type_name = "Service"; break;
            case 7:  row.logon_type_name = "Unlock"; break;
            case 8:  row.logon_type_name = "NetworkCleartext"; break;
            case 9:  row.logon_type_name = "NewCredentials"; break;
            case 10: row.logon_type_name = "RemoteInteractive"; break;
            case 11: row.logon_type_name = "CachedInteractive"; break;
            default: row.logon_type_name = "Unknown"; break;
        }
        out->push_back(std::move(row));
        free_fn(d);
    }
    free_fn(luids);
    ::FreeLibrary(secur32);
    return true;
}

}  // namespace pry::host
