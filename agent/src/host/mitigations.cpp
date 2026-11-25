// agent/src/host/mitigations.cpp
//
// GetProcessMitigationPolicy readout, shared between the agent and
// umagent via the vendored CMake entry (umagent/CMakeLists.txt pulls
// this file directly; agent/CMakeLists.txt lists it under
// PRY_AGENT_SOURCES).
//
// The decoder opens the target with PROCESS_QUERY_INFORMATION (falls
// back to PROCESS_QUERY_LIMITED_INFORMATION when the full mask is
// refused — modern GetProcessMitigationPolicy classes mostly accept
// the limited mask). On ERROR_INVALID_PARAMETER we retry with the
// pre-known smaller struct size; on ERROR_NOT_SUPPORTED the fields
// stay false and no error row is recorded (API honestly reported n/a).
//
// Agent-side PPL route: when `is_agent_view` is true and the full open
// fails, the caller is expected to supply a dup'd process handle (see
// services_mitigations.cpp on the agent side). Umagent sets
// `is_agent_view=false` and surfaces 'denied' per README §7.

#include "mitigations.hpp"

#include <windows.h>
#include <processthreadsapi.h>
#include <processenv.h>
#include <psapi.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace pry::host {

namespace {

// Record `err_text` into the aggregator, marking the row ``partial``.
void NotePartial(MitigationSet* out, const char* cls, DWORD err) {
    out->partial = true;
    if (!out->err.empty()) {
        out->err += ";";
    }
    char buf[96];
    std::snprintf(buf, sizeof(buf), "%s:0x%08lx", cls, (unsigned long)err);
    out->err += buf;
}

template <typename T, typename ProcPolicy>
bool TryGet(HANDLE hProc, ProcPolicy policy, T* dst) {
    std::memset(dst, 0, sizeof(T));
    SIZE_T sz = sizeof(T);
    BOOL ok = ::GetProcessMitigationPolicy(hProc, policy, dst, sz);
    return ok != FALSE;
}


// Open the target with the needed query mask. Falls back from
// PROCESS_QUERY_INFORMATION to PROCESS_QUERY_LIMITED_INFORMATION — most
// mitigation classes accept the limited mask on modern builds.
HANDLE OpenForQuery(uint32_t pid, bool* limited_only) {
    *limited_only = false;
    HANDLE h = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (h) {
        return h;
    }
    h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (h) {
        *limited_only = true;
    }
    return h;
}


uint64_t ProcessCreateTime100ns(HANDLE hProc) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!::GetProcessTimes(hProc, &created, &exited, &kernel, &user)) {
        return 0;
    }
    ULARGE_INTEGER li{};
    li.LowPart = created.dwLowDateTime;
    li.HighPart = created.dwHighDateTime;
    return li.QuadPart;
}


void DecodeDep(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_DEP_POLICY d{};
    if (TryGet(hProc, ProcessDEPPolicy, &d)) {
        out->dep_enable = d.Enable;
        out->dep_atl_thunk_emulation_disable = d.DisableAtlThunkEmulation;
        out->dep_permanent = d.Permanent;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "dep", e);
    }
}

void DecodeAslr(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_ASLR_POLICY a{};
    if (TryGet(hProc, ProcessASLRPolicy, &a)) {
        out->aslr_bottom_up = a.EnableBottomUpRandomization;
        out->aslr_force_relocate = a.EnableForceRelocateImages;
        out->aslr_high_entropy = a.EnableHighEntropy;
        out->aslr_disallow_stripped_images = a.DisallowStrippedImages;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "aslr", e);
    }
}

void DecodeCfg(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY c{};
    if (TryGet(hProc, ProcessControlFlowGuardPolicy, &c)) {
        out->cfg_enable = c.EnableControlFlowGuard;
        out->cfg_strict_mode = c.StrictMode;
        out->cfg_export_dynamic_invalidation =
            c.EnableExportSuppression;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "cfg", e);
    }
}

void DecodeStrictHandle(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY s{};
    if (TryGet(hProc, ProcessStrictHandleCheckPolicy, &s)) {
        out->strict_handle_check =
            s.RaiseExceptionOnInvalidHandleReference;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "strict_handle", e);
    }
}

void DecodeSysCall(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY sc{};
    if (TryGet(hProc, ProcessSystemCallDisablePolicy, &sc)) {
        out->syscall_disable = sc.DisallowWin32kSystemCalls;
        out->syscall_allow_win32k = sc.AuditDisallowWin32kSystemCalls;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "syscall", e);
    }
}

void DecodeExtPoints(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY e{};
    if (TryGet(hProc, ProcessExtensionPointDisablePolicy, &e)) {
        out->extension_points_disabled = e.DisableExtensionPoints;
    } else {
        DWORD err = ::GetLastError();
        if (err != ERROR_NOT_SUPPORTED) NotePartial(out, "ext_points", err);
    }
}

void DecodeDynCode(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY d{};
    if (TryGet(hProc, ProcessDynamicCodePolicy, &d)) {
        out->dyn_prohibit = d.ProhibitDynamicCode;
        out->dyn_allow_thread_opt_out = d.AllowThreadOptOut;
        out->dyn_allow_remote_downgrade = d.AllowRemoteDowngrade;
        out->dyn_audit = d.AuditProhibitDynamicCode;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "dyn_code", e);
    }
}

void DecodeBinSig(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY b{};
    if (TryGet(hProc, ProcessSignaturePolicy, &b)) {
        out->bs_micro_signed_only = b.MicrosoftSignedOnly;
        out->bs_store_signed_only = b.StoreSignedOnly;
        out->bs_mitigation_opt_in = b.MitigationOptIn;
        out->bs_mitigation_audit_mask =
            (uint32_t)b.AuditMicrosoftSignedOnly |
            ((uint32_t)b.AuditStoreSignedOnly << 1);
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "bin_sig", e);
    }
}

void DecodeFont(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_FONT_DISABLE_POLICY f{};
    if (TryGet(hProc, ProcessFontDisablePolicy, &f)) {
        out->font_disable_non_system = f.DisableNonSystemFonts;
        out->font_audit = f.AuditNonSystemFontLoading;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "font", e);
    }
}

void DecodeImageLoad(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY i{};
    if (TryGet(hProc, ProcessImageLoadPolicy, &i)) {
        out->image_no_remote = i.NoRemoteImages;
        out->image_no_low_mandatory = i.NoLowMandatoryLabelImages;
        out->image_prefer_system32 = i.PreferSystem32Images;
        out->image_audit_no_remote = i.AuditNoRemoteImages;
        out->image_audit_no_low_mandatory = i.AuditNoLowMandatoryLabelImages;
        // AuditPreferSystem32Images was added to the SDK union late; older
        // WDK/SDK revisions on build hosts without it fall back to zero.
        __if_exists(PROCESS_MITIGATION_IMAGE_LOAD_POLICY::AuditPreferSystem32Images) {
            out->image_audit_prefer_system32 = i.AuditPreferSystem32Images;
        }
        __if_not_exists(PROCESS_MITIGATION_IMAGE_LOAD_POLICY::AuditPreferSystem32Images) {
            out->image_audit_prefer_system32 = 0;
        }
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "image_load", e);
    }
}

void DecodeShadowStack(HANDLE hProc, MitigationSet* out) {
#ifdef ProcessUserShadowStackPolicy
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY u{};
    if (TryGet(hProc, ProcessUserShadowStackPolicy, &u)) {
        out->ush_enabled = u.EnableUserShadowStack;
        out->ush_audit = u.AuditUserShadowStack;
        out->ush_strict_mode = u.EnableUserShadowStackStrictMode;
        out->ush_set_context_ip_validation = u.SetContextIpValidation;
        out->ush_set_context_ip_validation_relaxed =
            u.SetContextIpValidationRelaxedMode;
        out->ush_block_non_cet_binaries = u.BlockNonCetBinaries;
        out->ush_block_non_cet_binaries_non_ehcont =
            u.BlockNonCetBinariesNonEhcont;
        out->ush_cet_dynamic_apis_out_of_proc_only =
            u.CetDynamicApisOutOfProcOnly;
        out->ush_audit_set_context_ip_validation =
            u.AuditSetContextIpValidation;
        out->ush_audit_block_non_cet_binaries = u.AuditBlockNonCetBinaries;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "shadow_stack", e);
    }
#else
    (void)hProc; (void)out;
#endif
}

void DecodePayload(HANDLE hProc, MitigationSet* out) {
    PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY p{};
    if (TryGet(hProc, ProcessPayloadRestrictionPolicy, &p)) {
        out->payload_enable_eaf = p.EnableExportAddressFilter;
        out->payload_enable_eaf_plus = p.EnableExportAddressFilterPlus;
        out->payload_audit_eaf = p.AuditExportAddressFilter;
        out->payload_audit_eaf_plus = p.AuditExportAddressFilterPlus;
        out->payload_enable_iaf = p.EnableImportAddressFilter;
        out->payload_audit_iaf = p.AuditImportAddressFilter;
        out->payload_enable_rop_stack_pivot = p.EnableRopStackPivot;
        out->payload_audit_rop_stack_pivot = p.AuditRopStackPivot;
        out->payload_enable_rop_caller_check = p.EnableRopCallerCheck;
        out->payload_audit_rop_caller_check = p.AuditRopCallerCheck;
        out->payload_enable_rop_sim_exec = p.EnableRopSimExec;
        out->payload_audit_rop_sim_exec = p.AuditRopSimExec;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "payload", e);
    }
}

void DecodeSideChannel(HANDLE hProc, MitigationSet* out) {
#ifdef ProcessSideChannelIsolationPolicy
    PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY s{};
    if (TryGet(hProc, ProcessSideChannelIsolationPolicy, &s)) {
        out->sci_smt_branch_target_isolation = s.SmtBranchTargetIsolation;
        out->sci_isolate_security_domain = s.IsolateSecurityDomain;
        out->sci_disable_page_combine = s.DisablePageCombine;
        out->sci_speculative_store_bypass_disable =
            s.SpeculativeStoreBypassDisable;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "side_channel", e);
    }
#else
    (void)hProc; (void)out;
#endif
}

void DecodeRedirectionTrust(HANDLE hProc, MitigationSet* out) {
#ifdef ProcessRedirectionTrustPolicy
    PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY r{};
    if (TryGet(hProc, ProcessRedirectionTrustPolicy, &r)) {
        out->redirection_trust_enforce = r.EnforceRedirectionTrust;
        out->redirection_trust_audit = r.AuditRedirectionTrust;
    } else {
        DWORD e = ::GetLastError();
        if (e != ERROR_NOT_SUPPORTED) NotePartial(out, "redirection_trust", e);
    }
#else
    (void)hProc; (void)out;
#endif
}

}  // namespace


bool CollectMitigations(uint32_t pid, bool is_agent_view,
                        MitigationSet* out, std::string* err) {
    (void)is_agent_view;  // caller side manages the PPL dup path.
    if (!out) {
        if (err) *err = "null MitigationSet out";
        return false;
    }
    *out = MitigationSet{};
    if (pid == 0) {
        if (err) *err = "pid=0";
        return false;
    }

    bool limited = false;
    HANDLE hProc = OpenForQuery(pid, &limited);
    if (!hProc) {
        if (err) {
            DWORD e = ::GetLastError();
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "OpenProcess failed err=0x%08lx",
                          (unsigned long)e);
            *err = buf;
        }
        return false;
    }

    out->create_time_100ns = ProcessCreateTime100ns(hProc);

    DecodeDep(hProc, out);
    DecodeAslr(hProc, out);
    DecodeCfg(hProc, out);
    DecodeStrictHandle(hProc, out);
    DecodeSysCall(hProc, out);
    DecodeExtPoints(hProc, out);
    DecodeDynCode(hProc, out);
    DecodeBinSig(hProc, out);
    DecodeFont(hProc, out);
    DecodeImageLoad(hProc, out);
    DecodeShadowStack(hProc, out);
    DecodePayload(hProc, out);
    DecodeSideChannel(hProc, out);
    DecodeRedirectionTrust(hProc, out);

    ::CloseHandle(hProc);
    if (err) *err = out->err;
    return true;
}


// ---------------------------------------------------------------- cache ----

static uint64_t MakeKey(uint32_t pid, uint64_t create_time) {
    return ((uint64_t)pid << 32) | (uint32_t)(create_time & 0xFFFFFFFF);
}

bool MitigationsCache::Get(uint32_t pid, uint64_t create_time,
                           MitigationSet* out) {
    if (!out) return false;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = rows_.find(MakeKey(pid, create_time));
    if (it == rows_.end()) return false;
    if (std::chrono::steady_clock::now() - it->second.stamped > kTtl) {
        rows_.erase(it);
        return false;
    }
    *out = it->second.row;
    return true;
}

void MitigationsCache::Put(uint32_t pid, uint64_t create_time,
                           const MitigationSet& row) {
    std::lock_guard<std::mutex> lk(mu_);
    rows_[MakeKey(pid, create_time)] = {row, std::chrono::steady_clock::now()};
    if (rows_.size() > kCap) {
        // Drop the stalest entry (O(n) but kCap=2048 is small enough).
        auto oldest = rows_.begin();
        for (auto it = rows_.begin(); it != rows_.end(); ++it) {
            if (it->second.stamped < oldest->second.stamped) {
                oldest = it;
            }
        }
        if (oldest != rows_.end()) rows_.erase(oldest);
    }
}

void MitigationsCache::Invalidate(uint32_t pid) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = rows_.begin(); it != rows_.end();) {
        if ((uint32_t)(it->first >> 32) == pid) {
            it = rows_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t MitigationsCache::Size() {
    std::lock_guard<std::mutex> lk(mu_);
    return rows_.size();
}

MitigationsCache& GlobalMitigationsCache() {
    static MitigationsCache g;
    return g;
}

}  // namespace pry::host
