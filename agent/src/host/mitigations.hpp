// agent/src/host/mitigations.hpp
//
// Shared process-mitigation-policy readout. Built into both agent and
// umagent through the vendored CMake entry (same pattern as
// agent/src/host/sig_verify.cpp + umagent/src/sig_verify.cpp). The
// agent-side TU adds a Wave-1 HANDLE_DUP fallback for PPL targets;
// umagent uses OpenProcess + ACCESS_DENIED surface so the view
// asymmetry is
// honored.

#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace pry::host {

// Flattened per-policy decode. Fields mirror the proto MitigationRow
// one-for-one so the services_mitigations.cpp translation is a straight
// field-set.
struct MitigationSet {
    bool dep_enable = false;
    bool dep_atl_thunk_emulation_disable = false;
    bool dep_permanent = false;

    bool aslr_bottom_up = false;
    bool aslr_force_relocate = false;
    bool aslr_high_entropy = false;
    bool aslr_disallow_stripped_images = false;
    bool aslr_bottom_up_high_entropy = false;
    bool aslr_high_address_space_override = false;

    bool cfg_enable = false;
    bool cfg_strict_mode = false;
    bool cfg_suppress_exports = false;
    bool cfg_export_dynamic_invalidation = false;

    bool strict_handle_check = false;

    bool syscall_disable = false;
    bool syscall_allow_win32k = false;

    bool extension_points_disabled = false;

    bool dyn_prohibit = false;
    bool dyn_allow_thread_opt_out = false;
    bool dyn_allow_remote_downgrade = false;
    bool dyn_audit = false;
    bool dyn_audit_allow_thread_opt_out = false;
    bool dyn_audit_allow_remote_downgrade = false;

    bool bs_micro_signed_only = false;
    bool bs_store_signed_only = false;
    bool bs_mitigation_opt_in = false;
    uint32_t bs_mitigation_audit_mask = 0;
    bool bs_oem_signed_loosened_to_wintcb = false;

    bool font_disable_non_system = false;
    bool font_audit = false;

    bool image_no_remote = false;
    bool image_no_low_mandatory = false;
    bool image_prefer_system32 = false;
    bool image_audit_no_remote = false;
    bool image_audit_no_low_mandatory = false;
    bool image_audit_prefer_system32 = false;

    bool ush_enabled = false;
    bool ush_audit = false;
    bool ush_strict_mode = false;
    bool ush_set_context_ip_validation = false;
    bool ush_set_context_ip_validation_relaxed = false;
    bool ush_block_non_cet_binaries = false;
    bool ush_block_non_cet_binaries_non_ehcont = false;
    bool ush_cet_dynamic_apis_out_of_proc_only = false;
    bool ush_audit_set_context_ip_validation = false;
    bool ush_audit_block_non_cet_binaries = false;

    bool payload_enable_eaf = false;
    bool payload_enable_eaf_plus = false;
    bool payload_audit_eaf = false;
    bool payload_audit_eaf_plus = false;
    bool payload_enable_iaf = false;
    bool payload_audit_iaf = false;
    bool payload_enable_rop_stack_pivot = false;
    bool payload_audit_rop_stack_pivot = false;
    bool payload_enable_rop_caller_check = false;
    bool payload_audit_rop_caller_check = false;
    bool payload_enable_rop_sim_exec = false;
    bool payload_audit_rop_sim_exec = false;

    bool sci_smt_branch_target_isolation = false;
    bool sci_isolate_security_domain = false;
    bool sci_disable_page_combine = false;
    bool sci_speculative_store_bypass_disable = false;

    bool redirection_trust_enforce = false;
    bool redirection_trust_audit = false;

    uint64_t create_time_100ns = 0;
    std::string err;   // empty on full success; populated when a class fails
    bool partial = false;
};


// Collect every policy class for `pid`. Returns true on partial success
// (any class decoded); only returns false when the process could not be
// opened at all. ``partial=true`` + a non-empty ``err`` names the
// problem class(es) that fell back.
//
// `is_agent_view` picks the PPL route: when true and OpenProcess fails
// with access-denied, retry via the pry driver's HANDLE_DUP IOCTL
// (agent-side; umagent sets false and surfaces 'denied').
bool CollectMitigations(uint32_t pid, bool is_agent_view,
                        MitigationSet* out, std::string* err);


// Thread-safe LRU keyed by (pid, create_time_100ns). TTL = 60s, cap 2048.
class MitigationsCache {
public:
    struct Entry {
        MitigationSet row;
        std::chrono::steady_clock::time_point stamped;
    };

    // Returns true + populates `out` on hit; false on miss or TTL expiry.
    bool Get(uint32_t pid, uint64_t create_time, MitigationSet* out);
    void Put(uint32_t pid, uint64_t create_time, const MitigationSet& row);
    void Invalidate(uint32_t pid);
    size_t Size();

private:
    std::mutex mu_;
    std::unordered_map<uint64_t, Entry> rows_;  // key = pid<<32 | lo(create_time)
    static constexpr size_t kCap = 2048;
    static constexpr std::chrono::seconds kTtl{60};
};

MitigationsCache& GlobalMitigationsCache();

}  // namespace pry::host
