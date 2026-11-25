// SI Wave 1 feature #8: signer / Authenticode column gRPC surface.
//
// Driver-free surface — WinVerifyTrust runs entirely in user space, so
// the agent view answers without touching the pry driver. The
// shared probe (agent/src/host/sig_verify.cpp) is also the one the
// umagent-side service calls; the orchestrator picks the view with the
// usual ``name=`` kwarg. Backing cache: pry::host::GlobalSignerCache().
// See the slice plan at an internal plan
// 04-umagent-orchestrator.md §Feature 6.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include <windows.h>

#include <string>

#include "services.hpp"
#include "../host/sig_cache.hpp"
#include "../host/sig_verify.hpp"

namespace pry {

namespace {

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

void FillRow(SignerRow* row, const std::string& path,
              const pry::host::SignerInfo& info, bool cache_hit)
{
    row->set_path(path);
    row->set_signer(info.signer);
    row->set_issuer(info.issuer);
    row->set_signing_level(info.signing_level);
    row->set_is_signed(info.is_signed);
    row->set_catalog(info.catalog);
    row->set_cache_timestamp_100ns(info.cache_timestamp_100ns);
    row->set_cache_hit(cache_hit);
    row->set_error(info.error);
}

}  // namespace

class SignaturesSvc final : public Signatures::Service {
public:
    explicit SignaturesSvc(const AgentConfig& cfg) : cfg_(cfg) {}

    grpc::Status Verify(::grpc::ServerContext* ctx,
                         const VerifySignaturesRequest* req,
                         VerifySignaturesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        auto& cache = pry::host::GlobalSignerCache();
        uint32_t hits = 0, probed = 0;
        for (const std::string& p : req->paths()) {
            if (p.empty()) continue;
            if (ctx->IsCancelled()) break;
            auto* row = resp->add_rows();
            std::wstring wp = Utf8ToWideSig(p);
            pry::host::SignerInfo info{};
            bool cached = false;
            std::string err;
            cache.VerifyCached(wp, req->force_recheck(), &info, &cached, &err);
            if (cached) ++hits; else ++probed;
            FillRow(row, p, info, cached);
        }
        resp->set_cache_hits(hits);
        resp->set_probed(probed);
        // Opportunistic persistence so a restart doesn't lose the hot
        // set; best-effort — ignore errors.
        if (probed > 0) cache.SaveToDisk();
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
};

void RegisterSignaturesService(grpc::ServerBuilder& builder,
                                 const AgentConfig& cfg)
{
    static SignaturesSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace pry
