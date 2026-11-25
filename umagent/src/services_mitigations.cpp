// umagent/src/services_mitigations.cpp
//
// Umagent-side Mitigations.GetMitigationPolicy. Uses the shared
// agent/src/host/mitigations.cpp decoder (vendored into the umagent
// build via CMakeLists.txt). PPL coverage asymmetry: umagent lacks the
// driver's HANDLE_DUP fallback, so PPL opens surface
// ``mitigations_source='denied'`` here (README §7).

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#include <cstring>
#include <string>

#include "um_services.hpp"
#include "../../agent/src/host/mitigations.hpp"

namespace um {

namespace {

grpc::Status CheckAuthMit(grpc::ServerContext* ctx, const std::string& token) {
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

// Local marshaller — same shape as agent/src/grpc/services_mitigations.cpp
// Marshal(); kept here as a free function so the agent/umagent builds
// don't collide on symbol linkage.
void Marshal(const pry::host::MitigationSet& m, uint32_t pid,
             bool cache_hit, pry::MitigationRow* row) {
    row->set_pid(pid);
    row->set_create_time_100ns(m.create_time_100ns);
    row->set_error(m.err);
    row->set_cache_hit(cache_hit);

    row->mutable_dep()->set_enable(m.dep_enable);
    row->mutable_dep()->set_atl_thunk_emulation_disable(
        m.dep_atl_thunk_emulation_disable);
    row->mutable_dep()->set_permanent(m.dep_permanent);

    row->mutable_aslr()->set_bottom_up(m.aslr_bottom_up);
    row->mutable_aslr()->set_force_relocate(m.aslr_force_relocate);
    row->mutable_aslr()->set_high_entropy(m.aslr_high_entropy);
    row->mutable_aslr()->set_disallow_stripped_images(
        m.aslr_disallow_stripped_images);
    row->mutable_aslr()->set_bottom_up_high_entropy(
        m.aslr_bottom_up_high_entropy);
    row->mutable_aslr()->set_high_address_space_override(
        m.aslr_high_address_space_override);

    row->mutable_cfg()->set_enable(m.cfg_enable);
    row->mutable_cfg()->set_strict_mode(m.cfg_strict_mode);
    row->mutable_cfg()->set_suppress_exports(m.cfg_suppress_exports);
    row->mutable_cfg()->set_export_dynamic_invalidation(
        m.cfg_export_dynamic_invalidation);

    row->set_strict_handle_check(m.strict_handle_check);

    row->mutable_syscall()->set_disable(m.syscall_disable);
    row->mutable_syscall()->set_allow_win32k_system_calls(
        m.syscall_allow_win32k);

    row->set_extension_points_disabled(m.extension_points_disabled);

    auto* dc = row->mutable_dynamic_code();
    dc->set_prohibit(m.dyn_prohibit);
    dc->set_allow_thread_opt_out(m.dyn_allow_thread_opt_out);
    dc->set_allow_remote_downgrade(m.dyn_allow_remote_downgrade);
    dc->set_audit(m.dyn_audit);
    dc->set_audit_allow_thread_opt_out(m.dyn_audit_allow_thread_opt_out);
    dc->set_audit_allow_remote_downgrade(m.dyn_audit_allow_remote_downgrade);

    auto* bs = row->mutable_binary_signature();
    bs->set_micro_signed_only(m.bs_micro_signed_only);
    bs->set_store_signed_only(m.bs_store_signed_only);
    bs->set_mitigation_opt_in(m.bs_mitigation_opt_in);
    bs->set_mitigation_audit_mask(m.bs_mitigation_audit_mask);
    bs->set_oem_signed_loosened_to_wintcb(m.bs_oem_signed_loosened_to_wintcb);

    row->mutable_font_disable()->set_disable_non_system_fonts(
        m.font_disable_non_system);
    row->mutable_font_disable()->set_audit(m.font_audit);

    auto* il = row->mutable_image_load();
    il->set_no_remote_images(m.image_no_remote);
    il->set_no_low_mandatory_label_images(m.image_no_low_mandatory);
    il->set_prefer_system32(m.image_prefer_system32);
    il->set_audit_no_remote_images(m.image_audit_no_remote);
    il->set_audit_no_low_mandatory_label_images(
        m.image_audit_no_low_mandatory);
    il->set_audit_prefer_system32(m.image_audit_prefer_system32);

    auto* us = row->mutable_user_shadow_stack();
    us->set_enabled(m.ush_enabled);
    us->set_audit(m.ush_audit);
    us->set_strict_mode(m.ush_strict_mode);
    us->set_set_context_ip_validation(m.ush_set_context_ip_validation);
    us->set_set_context_ip_validation_relaxed_mode(
        m.ush_set_context_ip_validation_relaxed);
    us->set_block_non_cet_binaries(m.ush_block_non_cet_binaries);
    us->set_block_non_cet_binaries_non_ehcont(
        m.ush_block_non_cet_binaries_non_ehcont);
    us->set_cet_dynamic_apis_out_of_proc_only(
        m.ush_cet_dynamic_apis_out_of_proc_only);
    us->set_audit_set_context_ip_validation(
        m.ush_audit_set_context_ip_validation);
    us->set_audit_block_non_cet_binaries(
        m.ush_audit_block_non_cet_binaries);

    auto* p = row->mutable_payload_restriction();
    p->set_enable_export_address_filter(m.payload_enable_eaf);
    p->set_enable_export_address_filter_plus(m.payload_enable_eaf_plus);
    p->set_audit_export_address_filter(m.payload_audit_eaf);
    p->set_audit_export_address_filter_plus(m.payload_audit_eaf_plus);
    p->set_enable_import_address_filter(m.payload_enable_iaf);
    p->set_audit_import_address_filter(m.payload_audit_iaf);
    p->set_enable_rop_stack_pivot(m.payload_enable_rop_stack_pivot);
    p->set_audit_rop_stack_pivot(m.payload_audit_rop_stack_pivot);
    p->set_enable_rop_caller_check(m.payload_enable_rop_caller_check);
    p->set_audit_rop_caller_check(m.payload_audit_rop_caller_check);
    p->set_enable_rop_sim_exec(m.payload_enable_rop_sim_exec);
    p->set_audit_rop_sim_exec(m.payload_audit_rop_sim_exec);

    auto* sc = row->mutable_side_channel();
    sc->set_smt_branch_target_isolation(m.sci_smt_branch_target_isolation);
    sc->set_isolate_security_domain(m.sci_isolate_security_domain);
    sc->set_disable_page_combine(m.sci_disable_page_combine);
    sc->set_speculative_store_bypass_disable(
        m.sci_speculative_store_bypass_disable);

    row->mutable_redirection_trust()->set_enforce(m.redirection_trust_enforce);
    row->mutable_redirection_trust()->set_audit(m.redirection_trust_audit);
}


class UmMitigationsSvc final : public pry::Mitigations::Service {
public:
    explicit UmMitigationsSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status GetMitigationPolicy(
        ::grpc::ServerContext* ctx,
        const pry::GetMitigationPolicyRequest* req,
        pry::GetMitigationPolicyResponse* resp) override {
        auto auth = CheckAuthMit(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        uint32_t hits = 0, probed = 0;
        for (uint32_t pid : req->pids()) {
            if (pid == 0) continue;
            pry::host::MitigationSet m;
            bool cache_hit = false;
            if (!req->force_recheck() &&
                pry::host::GlobalMitigationsCache().Get(pid, 0, &m)) {
                cache_hit = true;
                ++hits;
            } else {
                std::string err;
                if (!pry::host::CollectMitigations(
                        pid, /*is_agent_view=*/false, &m, &err)) {
                    auto* row = resp->add_rows();
                    row->set_pid(pid);
                    // README §7: umagent on PPL surfaces 'denied'.
                    row->set_error(err.empty()
                                   ? std::string("denied_ppl: open failed")
                                   : err);
                    continue;
                }
                pry::host::GlobalMitigationsCache().Put(pid, 0, m);
                ++probed;
            }
            auto* row = resp->add_rows();
            Marshal(m, pid, cache_hit, row);
        }
        resp->set_cache_hits(hits);
        resp->set_probed(probed);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

}  // namespace

void RegisterMitigationsService(grpc::ServerBuilder& builder,
                                const Config& cfg) {
    static UmMitigationsSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
