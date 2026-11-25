// umagent/src/services_token.cpp — umagent view.
//
// Mirror of agent/src/grpc/services_token.cpp wired for the umagent
// (driver-free) view. Shared TUs vendored from agent/src/host via
// CMake. PPL coverage: this view fails on PPL opens; the agent view
// routes through Wave-1 HANDLE_DUP for reads (README §7).

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#include <cstring>
#include <string>
#include <vector>

#include "um_services.hpp"
#include "../../agent/src/host/token_view.hpp"
#include "../../agent/src/host/token_mutate.hpp"
#include "../../agent/src/host/token_lsa.hpp"

namespace um {

namespace {

grpc::Status CheckAuthTok(grpc::ServerContext* ctx, const std::string& token) {
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

void MarshalCore(const pry::host::TokenSnapshot& snap,
                 pry::TokenCore* core) {
    core->set_user_sid(snap.user_sid);
    core->set_user_name(snap.user_name);
    core->set_user_domain(snap.user_domain);
    core->set_logon_sid(snap.logon_sid);
    core->set_integrity_rid(snap.integrity_rid);
    core->set_integrity_name(snap.integrity_name);
    core->set_elevation_type(snap.elevation_type);
    core->set_is_elevated(snap.is_elevated);
    core->set_linked_token_present(snap.linked_token_present);
    core->set_uac_virtualization_enabled(snap.uac_virtualization_enabled);
    core->set_uac_virtualization_allowed(snap.uac_virtualization_allowed);
    core->set_mandatory_policy(snap.mandatory_policy);
    core->set_session_id(snap.session_id);
    core->set_logon_id_low(snap.logon_id_low);
    core->set_logon_id_high(snap.logon_id_high);
    core->set_is_app_container(snap.is_app_container);
    core->set_app_container_sid(snap.app_container_sid);
    core->set_app_container_name(snap.app_container_name);
    core->set_app_container_number(snap.app_container_number);
    core->set_trust_label_sid(snap.trust_label_sid);
    core->set_trust_label_name(snap.trust_label_name);
}

void MarshalLogon(const pry::host::LogonSessionRow& r,
                   pry::LogonSessionInfo* out) {
    out->set_logon_id_low(r.logon_id_low);
    out->set_logon_id_high(r.logon_id_high);
    out->set_user_name(r.user_name);
    out->set_auth_domain(r.auth_domain);
    out->set_logon_type(r.logon_type);
    out->set_logon_type_name(r.logon_type_name);
    out->set_session_id(r.session_id);
    out->set_logon_time_100ns(r.logon_time_100ns);
    out->set_logoff_time_100ns(r.logoff_time_100ns);
    out->set_logon_server(r.logon_server);
    out->set_dns_domain_name(r.dns_domain_name);
    out->set_upn(r.upn);
    out->set_user_flags(r.user_flags);
}


class UmTokenSvc final : public pry::Token::Service {
public:
    explicit UmTokenSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status View(::grpc::ServerContext* ctx,
                      const pry::TokenViewRequest* req,
                      pry::TokenViewResponse* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        pry::host::CollectOpts opts;
        opts.include_groups = req->include_groups();
        opts.include_privileges = req->include_privileges();
        opts.include_security_attributes = req->include_security_attributes();
        opts.include_logon_session = req->include_logon_session();
        pry::host::TokenSnapshot snap;
        std::string err;
        bool ok = pry::host::CollectToken(
            req->pid(), req->tid(), opts, nullptr, &snap, &err);
        if (!ok) {
            FillStatus(resp, err.empty()
                             ? std::string("denied_ppl: open failed")
                             : err);
            return grpc::Status::OK;
        }
        MarshalCore(snap, resp->mutable_core());
        for (const auto& g : snap.groups) {
            auto* o = resp->add_groups();
            o->set_sid(g.sid);
            o->set_name(g.name);
            o->set_domain(g.domain);
            o->set_attributes(g.attributes);
            o->set_is_deny(g.is_deny);
            o->set_is_mandatory(g.is_mandatory);
            o->set_is_integrity(g.is_integrity);
            o->set_is_logon_id(g.is_logon_id);
            o->set_is_enabled(g.is_enabled);
            o->set_is_enabled_by_default(g.is_enabled_by_default);
            o->set_is_use_for_deny_only(g.is_use_for_deny_only);
            o->set_is_owner(g.is_owner);
            o->set_is_resource(g.is_resource);
            o->set_use(g.use);
        }
        for (const auto& p : snap.privileges) {
            auto* o = resp->add_privileges();
            o->set_luid_low(p.luid_low);
            o->set_luid_high(p.luid_high);
            o->set_name(p.name);
            o->set_display_name(p.display_name);
            o->set_attributes(p.attributes);
            o->set_state(p.state);
            o->set_enabled_by_default(p.enabled_by_default);
        }
        for (const auto& c : snap.capabilities) {
            auto* o = resp->add_capabilities();
            o->set_sid(c.sid);
            o->set_name(c.name);
        }
        if (opts.include_security_attributes) {
            resp->set_security_attributes_raw(snap.security_attributes_raw);
        }
        if (opts.include_logon_session && snap.have_logon_session) {
            MarshalLogon(snap.logon_session, resp->mutable_logon_session());
        }
        resp->set_token_source(snap.token_source);
        resp->set_thread_impersonating(snap.thread_impersonating);
        FillStatus(resp, snap.partial_classes);
        return grpc::Status::OK;
    }

    grpc::Status AdjustPrivilege(::grpc::ServerContext* ctx,
                                 const pry::AdjustPrivilegeRequest* req,
                                 pry::AdjustPrivilegeResponse* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto r = pry::host::AdjustPrivilege(
            req->pid(), req->tid(), req->privilege_name(),
            req->luid_low(), req->luid_high(), req->action());
        resp->set_previous_state(r.previous_state);
        resp->set_new_state(r.new_state);
        resp->set_luid_low(r.luid_low);
        resp->set_luid_high(r.luid_high);
        FillStatus(resp, r.ok ? std::string("") : r.err);
        return grpc::Status::OK;
    }

    grpc::Status SetIntegrityLevel(::grpc::ServerContext* ctx,
                                   const pry::SetIntegrityLevelRequest* req,
                                   pry::SetIntegrityLevelResponse* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto r = pry::host::SetIntegrityLevel(
            req->pid(), req->tid(), req->integrity_rid(),
            req->integrity_name());
        resp->set_previous_rid(r.previous_rid);
        resp->set_new_rid(r.new_rid);
        FillStatus(resp, r.ok ? std::string("") : r.err);
        return grpc::Status::OK;
    }

    grpc::Status SetVirtualization(::grpc::ServerContext* ctx,
                                   const pry::SetVirtualizationRequest* req,
                                   pry::SetVirtualizationResponse* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto r = pry::host::SetVirtualization(
            req->pid(), req->tid(), req->enable());
        resp->set_previous(r.previous);
        resp->set_new_value(r.new_value);
        FillStatus(resp, r.ok ? std::string("") : r.err);
        return grpc::Status::OK;
    }

    grpc::Status Impersonate(::grpc::ServerContext* ctx,
                             const pry::ImpersonateRequest* req,
                             pry::ImpersonateResponse* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        // target_tid != 0 (impersonate on an EXISTING thread) is not
        // implemented; it used to be silently ignored. 0 = the dedicated
        // agent worker thread, which is what StartImpersonation does.
        if (req->target_tid() != 0) {
            resp->mutable_status()->set_ok(false);
            resp->mutable_status()->set_error(
                "not_supported: target_tid impersonation is not implemented; omit it "
                "(0) to hold the impersonation on a dedicated agent worker thread");
            resp->mutable_status()->set_kind("not_supported");
            return grpc::Status::OK;
        }
        auto r = pry::host::StartImpersonation(
            req->source_pid(), req->source_tid(),
            req->persist(), req->impersonation_level());
        resp->set_impersonation_id(r.impersonation_id);
        resp->set_agent_thread_id(r.agent_thread_id);
        resp->set_level_granted(r.level_granted);
        FillStatus(resp, r.ok ? std::string("") : r.err);
        return grpc::Status::OK;
    }

    grpc::Status StopImpersonate(::grpc::ServerContext* ctx,
                                 const pry::StopImpersonateRequest* req,
                                 pry::OpStatus* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        bool ok = pry::host::StopImpersonation(
            req->impersonation_id(), &err);
        resp->set_ok(ok);
        if (!ok) resp->set_error(err);
        return grpc::Status::OK;
    }

    grpc::Status ModifyDefaultDacl(::grpc::ServerContext* ctx,
                                   const pry::ModifyDefaultDaclRequest* req,
                                   pry::ModifyDefaultDaclResponse* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::vector<pry::host::DaclAceRow> aces;
        aces.reserve(req->aces_size());
        for (const auto& a : req->aces()) {
            pry::host::DaclAceRow row;
            row.sid = a.sid();
            row.access_mask = a.access_mask();
            row.type = a.type();
            row.flags = a.flags();
            aces.push_back(std::move(row));
        }
        auto r = pry::host::ModifyDefaultDacl(
            req->pid(), req->tid(), aces, req->replace());
        resp->set_ace_count_before(r.ace_count_before);
        resp->set_ace_count_after(r.ace_count_after);
        FillStatus(resp, r.ok ? std::string("") : r.err);
        return grpc::Status::OK;
    }

    grpc::Status LookupSid(::grpc::ServerContext* ctx,
                           const pry::LookupSidRequest* req,
                           pry::LookupSidResponse* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::vector<std::string> sids(req->sids().begin(), req->sids().end());
        std::vector<std::string> names(req->names().begin(), req->names().end());
        std::vector<pry::host::LookupRowRaw> rows;
        std::string err;
        pry::host::LookupSidsAndNames(sids, names, &rows, &err);
        for (const auto& r : rows) {
            auto* o = resp->add_rows();
            o->set_input(r.input);
            o->set_sid(r.sid);
            o->set_name(r.name);
            o->set_domain(r.domain);
            o->set_use(r.use);
            o->set_well_known(r.well_known);
        }
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status LogonSessions(::grpc::ServerContext* ctx,
                               const pry::LogonSessionsRequest* req,
                               pry::LogonSessionsResponse* resp) override {
        auto auth = CheckAuthTok(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::vector<pry::host::LogonSessionRow> sessions;
        std::string err;
        if (!pry::host::EnumLogonSessions(req->include_dns_names(),
                                                &sessions, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        for (const auto& s : sessions) {
            MarshalLogon(s, resp->add_sessions());
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

}  // namespace

void RegisterTokenService(grpc::ServerBuilder& builder, const Config& cfg) {
    static UmTokenSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
