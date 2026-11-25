// umagent/src/services_coherency.cpp — SI #1 image coherency gRPC
//
// Standalone umagent-side ImageCoherency.Score service. Delegates to
// um::ComputeCoherency (umagent/src/img_coherency.cpp), which wraps the
// shared pry::host scorer with usermode readers (CreateFileMapping
// for disk + um::MemRead for the live image). See the slice plan at
// §Feature 1.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#include <string>

#include "um_services.hpp"
#include "img_coherency.hpp"

namespace um {

namespace {

grpc::Status CheckAuthCoherency(grpc::ServerContext* ctx,
                                 const std::string& token)
{
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

}  // namespace

class UmImageCoherencySvc final : public pry::ImageCoherency::Service {
public:
    explicit UmImageCoherencySvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Score(grpc::ServerContext* ctx,
                       const pry::ImageCoherencyRequest* req,
                       pry::ImageCoherencyResponse* resp) override
    {
        auto auth = CheckAuthCoherency(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        pry::host::Request creq;
        creq.pid = req->pid();
        creq.module_base = req->module_base();
        creq.module_name = req->module_name();
        switch (req->mode()) {
            case pry::ImageCoherencyRequest::QUICK:
                creq.mode = pry::host::CoherencyMode::kQuick; break;
            case pry::ImageCoherencyRequest::FULL:
                creq.mode = pry::host::CoherencyMode::kFull; break;
            default:
                creq.mode = pry::host::CoherencyMode::kNormal; break;
        }
        creq.max_mismatch_ranges = req->max_mismatch_ranges();
        creq.include_mismatch_hex = req->include_mismatch_hex();

        pry::host::Result out;
        std::string err;
        if (!um::ComputeCoherency(creq, &out, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }

        resp->set_module_basename(out.module_basename);
        resp->set_module_path_disk(out.module_path_disk);
        resp->set_size_of_image(out.size_of_image);
        resp->set_bytes_compared(out.bytes_compared);
        resp->set_bytes_mismatched(out.bytes_mismatched);
        resp->set_coherency(out.coherency);
        resp->set_sections_total(out.sections_total);
        resp->set_sections_skipped_relocatable(out.sections_skipped_relocatable);
        resp->set_truncated(out.truncated);
        resp->set_reloc_dir_rva(out.reloc_dir_rva);
        resp->set_reloc_dir_size(out.reloc_dir_size);
        for (const auto& s : out.sections) {
            auto* sp = resp->add_sections();
            sp->set_name(s.name);
            sp->set_va(s.va);
            sp->set_size(s.size);
            sp->set_characteristics(s.characteristics);
        }
        for (const auto& m : out.mismatches) {
            auto* r = resp->add_ranges();
            r->set_rva(m.rva);
            r->set_length(m.length);
            r->set_section(m.section);
            r->set_hint(m.hint);
            r->set_in_memory_sample(m.in_memory_sample);
            r->set_on_disk_sample(m.on_disk_sample);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

void RegisterImageCoherencyService(grpc::ServerBuilder& builder,
                                    const Config& cfg)
{
    static UmImageCoherencySvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
