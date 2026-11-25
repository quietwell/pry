// comm/grpc_auth.hpp — the ONE bearer-token check for the agent and umagent
// gRPC servers.
//
// Two layers share this file:
//
//   * A server-wide auth processor installed on the listening port's
//     credentials (MakeServerCredentials). gRPC core runs it in the server
//     auth filter BEFORE any handler is dispatched, for every method of
//     every registered service, so a service that forgets to call
//     CheckAuth (the memory scanner services did) is still covered. This is the
//     authoritative check. It also hosts an optional per-call `gate` (the
//     agent's driver ABI gate) that can refuse a call with any status.
//   * CheckAuth — the per-handler helper the existing services call. Kept
//     as defence in depth; it uses the same constant-time compare.
//
// Why a custom ServerCredentials: grpc++ 1.76's
// InsecureServerCredentials()->SetAuthMetadataProcessor() is
// grpc_core::Crash("Not Supported"). The core C API
// (grpc_server_credentials_set_auth_metadata_processor) works on insecure
// credentials just fine — the chttp2 server always adds the credentials to
// the channel args, so the ServerAuthFilter runs and hands us the full
// client metadata including the ":path" pseudo-header. Pinned by
// agent/tests/unit_tests.cpp against a real in-process server.
//
// Header-only on purpose: pry_comm is a plain static lib that does not
// link gRPC, and umagent does not link pry_comm at all. Include it only
// from TUs that already pull <grpcpp/grpcpp.h> (before windows.h — see the
// note in agent/src/grpc/services.hpp).
//
// Semantics (unchanged from the old per-file helpers): an empty configured
// token disables the bearer check entirely; callers log that loudly at
// startup.
#pragma once

#include <grpc/credentials.h>
#include <grpc/grpc_security.h>
#include <grpc/slice.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pry::auth {

// Compare without an early exit on the first differing byte. Length is not
// hidden (the token length is not the secret), but the content is.
inline bool ConstantTimeEquals(std::string_view a, std::string_view b)
{
    const std::size_t n = a.size() > b.size() ? a.size() : b.size();
    volatile unsigned char diff = (unsigned char)(a.size() != b.size());
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char x = i < a.size() ? (unsigned char)a[i] : 0;
        const unsigned char y = i < b.size() ? (unsigned char)b[i] : 0;
        diff = (unsigned char)(diff | (x ^ y));
    }
    return diff == 0;
}

// `header` is the raw `authorization` metadata value; the accepted form is
// exactly "Bearer <token>".
inline bool BearerMatches(std::string_view header, std::string_view token)
{
    constexpr std::string_view kPrefix = "Bearer ";
    if (header.size() < kPrefix.size() || header.substr(0, kPrefix.size()) != kPrefix) {
        (void)ConstantTimeEquals(header, token);
        return false;
    }
    return ConstantTimeEquals(header.substr(kPrefix.size()), token);
}

inline grpc::Status Unauthenticated()
{
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "missing or invalid bearer token");
}

// Per-handler check (defence in depth; the processor below is authoritative).
inline grpc::Status CheckAuth(const grpc::ServerContext* ctx, const std::string& token)
{
    if (token.empty()) {
        return grpc::Status::OK; // auth disabled (logged loudly at startup)
    }
    const auto& md = ctx->client_metadata();
    auto it = md.find("authorization");
    if (it == md.end() ||
        !BearerMatches(std::string_view(it->second.data(), it->second.size()), token)) {
        return Unauthenticated();
    }
    return grpc::Status::OK;
}

// Methods reachable without a token. Identify returns only non-secret
// identity (computer name, boot epoch, instance id, version, view kind) so
// the orchestrator can verify WHO it is talking to before it sends the
// token anywhere.
inline const std::vector<std::string>& DefaultExemptMethods()
{
    static const std::vector<std::string> v{"/pry.Agent/Identify"};
    return v;
}

struct ServerAuthPolicy {
    std::string token;                       // empty => bearer check disabled
    std::vector<std::string> exempt_methods; // full ":path" values
    // Optional server-wide refusal hook, run after auth for non-exempt
    // methods (the agent's driver ABI gate). Return non-OK to abort the
    // call with that status before the handler runs. Must be cheap and
    // thread-safe: it runs inline on gRPC transport threads.
    std::function<grpc::Status(std::string_view method)> gate;
};

// The decision, separated from the gRPC plumbing so it is unit-testable.
// `path` empty means the pseudo-header was absent: treated as non-exempt
// (fail closed). `authorization` is nullptr when the header was absent.
inline grpc::Status Decide(const ServerAuthPolicy& p, std::string_view path,
                           const std::string_view* authorization)
{
    if (!path.empty()) {
        for (const auto& m : p.exempt_methods) {
            if (path == m) {
                return grpc::Status::OK;
            }
        }
    }
    if (!p.token.empty() && (!authorization || !BearerMatches(*authorization, p.token))) {
        return Unauthenticated();
    }
    if (p.gate) {
        return p.gate(path);
    }
    return grpc::Status::OK;
}

namespace detail {

inline std::string_view SliceView(const grpc_slice& s)
{
    return std::string_view(reinterpret_cast<const char*>(GRPC_SLICE_START_PTR(s)),
                            GRPC_SLICE_LENGTH(s));
}

// Plaintext listener credentials with a core-level auth metadata processor.
// `authorization` is deliberately NOT reported as consumed: the per-handler
// CheckAuth calls still read it.
class InsecureAuthServerCredentials final : public grpc::ServerCredentials {
public:
    explicit InsecureAuthServerCredentials(std::shared_ptr<const ServerAuthPolicy> policy)
        : grpc::ServerCredentials(grpc_insecure_server_credentials_create())
    {
        auto* holder = new std::shared_ptr<const ServerAuthPolicy>(std::move(policy));
        grpc_auth_metadata_processor proc{};
        proc.process = &InsecureAuthServerCredentials::Process;
        proc.destroy = &InsecureAuthServerCredentials::Destroy;
        proc.state = holder;
        grpc_server_credentials_set_auth_metadata_processor(c_creds(), proc);
    }

    // The policy is fixed at construction; grpc++'s base implementation
    // would crash on insecure credentials, so never forward to it.
    void SetAuthMetadataProcessor(const std::shared_ptr<grpc::AuthMetadataProcessor>&) override {}

private:
    static void Destroy(void* state)
    {
        delete static_cast<std::shared_ptr<const ServerAuthPolicy>*>(state);
    }

    // Non-blocking: constant-time compare + an atomic read in the gate, so
    // it runs (and completes) inline, exactly like grpc++'s own wrapper
    // does for a non-blocking processor.
    static void Process(void* state, grpc_auth_context*, const grpc_metadata* md, size_t num_md,
                        grpc_process_auth_metadata_done_cb cb, void* user_data)
    {
        const auto& policy = **static_cast<std::shared_ptr<const ServerAuthPolicy>*>(state);
        std::string_view path;
        std::string_view auth;
        bool have_auth = false;
        for (size_t i = 0; i < num_md; ++i) {
            std::string_view k = SliceView(md[i].key);
            if (k == ":path") {
                path = SliceView(md[i].value);
            } else if (k == "authorization" && !have_auth) {
                auth = SliceView(md[i].value);
                have_auth = true;
            }
        }
        grpc::Status st = Decide(policy, path, have_auth ? &auth : nullptr);
        const std::string msg = st.error_message();
        cb(user_data, nullptr, 0, nullptr, 0, static_cast<grpc_status_code>(st.error_code()),
           st.ok() ? nullptr : msg.c_str());
    }
};

} // namespace detail

// Every AddListeningPort of the agent / umagent server must use these.
inline std::shared_ptr<grpc::ServerCredentials> MakeServerCredentials(ServerAuthPolicy policy)
{
    return std::make_shared<detail::InsecureAuthServerCredentials>(
        std::make_shared<const ServerAuthPolicy>(std::move(policy)));
}

inline bool IsLoopbackBind(std::string_view host)
{
    return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
}

} // namespace pry::auth
