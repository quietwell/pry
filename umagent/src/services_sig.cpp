// umagent/src/services_sig.cpp — SI #8 signer / Authenticode gRPC
//
// Standalone umagent-side Signatures.Verify service. The probe is
// driver-free (WinVerifyTrust + crypt32), so this surface answers
// identically to the agent-side service — only the hosting process
// differs. The shared implementation (and cache) live in
// agent/src/host/sig_verify.cpp + agent/src/host/sig_cache.cpp, which
// umagent pulls in through its CMakeLists.txt. See the slice plan at
// §Feature 6.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#include <windows.h>

#include <string>

#include "um_services.hpp"
#include "sig_cache.hpp"
#include "sig_verify.hpp"

namespace um {

namespace {

grpc::Status CheckAuthSig(grpc::ServerContext* ctx,
                            const std::string& token)
{
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

std::wstring Utf8ToWideSig(const std::string& s)
{
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                   nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

}  // namespace

class UmSignaturesSvc final : public pry::Signatures::Service {
public:
    explicit UmSignaturesSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Verify(grpc::ServerContext* ctx,
                         const pry::VerifySignaturesRequest* req,
                         pry::VerifySignaturesResponse* resp) override
    {
        auto auth = CheckAuthSig(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        auto& cache = GlobalSignerCache();
        uint32_t hits = 0, probed = 0;
        for (const std::string& p : req->paths()) {
            if (p.empty()) continue;
            if (ctx->IsCancelled()) break;
            auto* row = resp->add_rows();
            std::wstring wp = Utf8ToWideSig(p);
            SignerInfo info{};
            bool cached = false;
            std::string err;
            cache.VerifyCached(wp, req->force_recheck(), &info, &cached, &err);
            if (cached) ++hits; else ++probed;
            row->set_path(p);
            row->set_signer(info.signer);
            row->set_issuer(info.issuer);
            row->set_signing_level(info.signing_level);
            row->set_is_signed(info.is_signed);
            row->set_catalog(info.catalog);
            row->set_cache_timestamp_100ns(info.cache_timestamp_100ns);
            row->set_cache_hit(cached);
            row->set_error(info.error);
        }
        resp->set_cache_hits(hits);
        resp->set_probed(probed);
        if (probed > 0) cache.SaveToDisk();
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

void RegisterSignaturesService(grpc::ServerBuilder& builder, const Config& cfg)
{
    static UmSignaturesSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
