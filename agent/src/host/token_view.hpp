// agent/src/host/token_view.hpp — shared with umagent.
//
// Token read-only probe. Shared between agent and umagent via the
// vendored CMake entry. Agent-side callers can pass a dup'd process
// handle for PPL coverage; umagent passes 0 and surfaces 'denied_ppl'
// on open failure (README §7).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pry::host {

struct TokenGroupRow {
    std::string sid;
    std::string name;
    std::string domain;
    uint32_t attributes = 0;
    bool is_deny = false;
    bool is_mandatory = false;
    bool is_integrity = false;
    bool is_logon_id = false;
    bool is_enabled = false;
    bool is_enabled_by_default = false;
    bool is_use_for_deny_only = false;
    bool is_owner = false;
    bool is_resource = false;
    std::string use;  // SID_NAME_USE string
};

struct TokenPrivilegeRow {
    uint32_t luid_low = 0;
    uint32_t luid_high = 0;
    std::string name;
    std::string display_name;
    uint32_t attributes = 0;
    std::string state;   // "enabled" / "disabled" / "default"
    bool enabled_by_default = false;
};

struct TokenCapRow {
    std::string sid;
    std::string name;
};

struct LogonSessionRow {
    uint32_t logon_id_low = 0;
    uint32_t logon_id_high = 0;
    std::string user_name;
    std::string auth_domain;
    uint32_t logon_type = 0;
    std::string logon_type_name;
    uint32_t session_id = 0;
    uint64_t logon_time_100ns = 0;
    uint64_t logoff_time_100ns = 0;
    std::string logon_server;
    std::string dns_domain_name;
    std::string upn;
    uint32_t user_flags = 0;
};

struct TokenSnapshot {
    std::string user_sid, user_name, user_domain;
    std::string logon_sid;
    uint32_t integrity_rid = 0;
    std::string integrity_name;
    std::string elevation_type;   // "default" | "full" | "limited"
    bool is_elevated = false;
    bool linked_token_present = false;
    bool uac_virtualization_enabled = false;
    bool uac_virtualization_allowed = false;
    uint32_t mandatory_policy = 0;
    uint32_t session_id = 0;
    uint32_t logon_id_low = 0;
    uint32_t logon_id_high = 0;
    bool is_app_container = false;
    std::string app_container_sid;
    std::string app_container_name;
    uint32_t app_container_number = 0;
    std::string trust_label_sid;
    std::string trust_label_name;

    std::vector<TokenGroupRow> groups;
    std::vector<TokenPrivilegeRow> privileges;
    std::vector<TokenCapRow> capabilities;
    std::string security_attributes_raw;
    LogonSessionRow logon_session;
    bool have_logon_session = false;

    std::string token_source;      // "primary" | "impersonation"
    bool thread_impersonating = false;
    std::string partial_classes;   // ';'-separated list on partial fail
};

struct CollectOpts {
    bool include_groups = false;
    bool include_privileges = false;
    bool include_security_attributes = false;
    bool include_logon_session = false;
};

// `process_handle_override` (optional) is the agent-side PPL dup; when
// 0 the function opens via OpenProcess + OpenProcessToken. Returns
// true on success / partial-success (``partial_classes`` names which
// classes fell back). Returns false only when no token could be read.
bool CollectToken(uint32_t pid, uint32_t tid, const CollectOpts& opts,
                  void* process_handle_override,
                  TokenSnapshot* out, std::string* err);


// Logon-session enumeration (LsaEnumerateLogonSessions +
// LsaGetLogonSessionData). Shared helper so the ``logon_sessions`` verb
// has the same decoder as the single-row ``include_logon_session`` path.
bool EnumLogonSessions(bool include_dns_names,
                       std::vector<LogonSessionRow>* out,
                       std::string* err);

}  // namespace pry::host
