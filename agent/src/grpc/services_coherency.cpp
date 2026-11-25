// SI Wave 1 feature #1: image coherency scoring gRPC surface.
//
// Pure usermode compare — the mapped image is read via UserMemReadFn
// (which already routes through the driver when it is loaded and
// falls back to ReadProcessMemory), the on-disk image is memory-mapped
// via CreateFileW + CreateFileMappingW. The shared scorer lives in
// agent/src/host/img_coherency.cpp. See the slice plan at
// an internal plan
// §Feature 1 for the response contract.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "services.hpp"
#include "../host/img_coherency.hpp"

namespace pry {

namespace {

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                   nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

std::string ToLower(const std::string& s)
{
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}

std::string WideToUtf8Local(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                           s.data(), n, nullptr, nullptr);
    return s;
}

bool ResolveModuleAgent(DriverMgr& drv, UINT32 pid,
                        const std::string& module_name,
                        uint64_t base_hint, std::string* out_path,
                        uint64_t* out_base, uint64_t* out_size,
                        std::string* err)
{
    std::vector<ModuleEntry> mods;
    if (!ListUserModules(&drv, pid, &mods)) {
        if (err) *err = "coherency: failed to enumerate modules for pid "
                        + std::to_string(pid);
        return false;
    }
    std::string want = ToLower(module_name);
    for (const auto& m : mods) {
        std::string mpath = WideToUtf8Local(m.Path);
        std::string mname = WideToUtf8Local(m.Name);
        if (base_hint && m.Base == base_hint) {
            *out_path = mpath;
            *out_base = m.Base;
            *out_size = m.Size;
            return true;
        }
        std::string ln = ToLower(mname);
        std::string lp = ToLower(mpath);
        if (!want.empty() && (ln == want || lp == want)) {
            *out_path = mpath;
            *out_base = m.Base;
            *out_size = m.Size;
            return true;
        }
    }
    if (err) *err = "coherency: module not found in pid "
                     + std::to_string(pid) + " (" + module_name + ")";
    return false;
}

// On-disk mapped-file wrapper (same shape as the umagent counterpart).
class MappedFile {
public:
    ~MappedFile() { close(); }

    bool open(const std::wstring& path, std::string* err)
    {
        file_ = ::CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE
                                  | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) {
            if (err) *err = "coherency: CreateFileW failed, gle="
                            + std::to_string(::GetLastError());
            return false;
        }
        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(file_, &sz)) {
            if (err) *err = "coherency: GetFileSizeEx failed";
            return false;
        }
        size_ = static_cast<size_t>(sz.QuadPart);
        mapping_ = ::CreateFileMappingW(file_, nullptr, PAGE_READONLY,
                                         0, 0, nullptr);
        if (!mapping_) {
            if (err) *err = "coherency: CreateFileMappingW failed, gle="
                            + std::to_string(::GetLastError());
            return false;
        }
        view_ = ::MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!view_) {
            if (err) *err = "coherency: MapViewOfFile failed";
            return false;
        }
        return true;
    }

    void close()
    {
        if (view_) { ::UnmapViewOfFile(view_); view_ = nullptr; }
        if (mapping_) { ::CloseHandle(mapping_); mapping_ = nullptr; }
        if (file_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file_);
            file_ = INVALID_HANDLE_VALUE;
        }
    }

    const uint8_t* data() const { return static_cast<const uint8_t*>(view_); }
    size_t size() const { return size_; }

private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
    LPVOID view_ = nullptr;
    size_t size_ = 0;
};

int64_t RvaToFileOffset(const uint8_t* file_data, size_t file_size,
                        uint32_t rva)
{
    if (file_size < 0x40) return -1;
    if (file_data[0] != 'M' || file_data[1] != 'Z') return -1;
    uint32_t e_lfanew;
    std::memcpy(&e_lfanew, file_data + 0x3C, 4);
    if (e_lfanew + 24 > file_size) return -1;
    if (std::memcmp(file_data + e_lfanew, "PE\0\0", 4) != 0) return -1;
    uint32_t coff = e_lfanew + 4;
    uint16_t nsec, opt_size;
    std::memcpy(&nsec, file_data + coff + 2, 2);
    std::memcpy(&opt_size, file_data + coff + 16, 2);
    uint32_t sec_off = coff + 20 + opt_size;
    uint32_t first_sec_va = 0;
    if (nsec && sec_off + 40 <= file_size) {
        std::memcpy(&first_sec_va, file_data + sec_off + 12, 4);
    }
    if (!nsec || rva < first_sec_va) {
        return rva < file_size ? static_cast<int64_t>(rva) : -1;
    }
    for (uint16_t i = 0; i < nsec; ++i) {
        uint32_t off = sec_off + i * 40;
        if (off + 40 > file_size) break;
        uint32_t vsize, va, raw_size, raw_off;
        std::memcpy(&vsize, file_data + off + 8, 4);
        std::memcpy(&va, file_data + off + 12, 4);
        std::memcpy(&raw_size, file_data + off + 16, 4);
        std::memcpy(&raw_off, file_data + off + 20, 4);
        uint32_t span = std::max(vsize, raw_size);
        if (va <= rva && rva < va + span) {
            uint32_t delta = rva - va;
            if (delta >= raw_size) return -1;
            uint32_t out = raw_off + delta;
            return (out < file_size) ? static_cast<int64_t>(out) : -1;
        }
    }
    return -1;
}

}  // namespace

class ImageCoherencySvc final : public ImageCoherency::Service {
public:
    ImageCoherencySvc(const AgentConfig& cfg, DriverMgr& drv)
        : cfg_(cfg), drv_(drv) {}

    grpc::Status Score(::grpc::ServerContext* ctx,
                       const ImageCoherencyRequest* req,
                       ImageCoherencyResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        UINT32 pid = req->pid() ? req->pid() : ::GetCurrentProcessId();
        std::string err;
        std::string path;
        uint64_t base = 0;
        uint64_t size = 0;
        if (!ResolveModuleAgent(drv_, pid, req->module_name(),
                                 req->module_base(), &path, &base, &size,
                                 &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        resp->set_module_path_disk(path);
        size_t slash = path.find_last_of("\\/");
        resp->set_module_basename(slash == std::string::npos
                                       ? path
                                       : path.substr(slash + 1));

        MappedFile disk;
        if (!disk.open(Utf8ToWide(path), &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        if (disk.size() < 0x40) {
            FillStatus(resp, "coherency: on-disk file too small");
            return grpc::Status::OK;
        }
        const uint8_t* file_data = disk.data();
        size_t file_size = disk.size();
        std::vector<uint8_t> headers;
        headers.resize(std::min<size_t>(file_size, 0x10000));
        std::memcpy(headers.data(), file_data, headers.size());

        MemReaderCtx mctx;
        mctx.drv = &drv_;

        auto disk_reader = [file_data, file_size](uint32_t rva, size_t len,
                                                    uint8_t* dst) -> size_t {
            int64_t off = RvaToFileOffset(file_data, file_size, rva);
            if (off < 0) return 0;
            size_t avail = file_size - static_cast<size_t>(off);
            size_t take = std::min(len, avail);
            std::memcpy(dst, file_data + off, take);
            return take;
        };

        auto mem_reader = [&mctx, pid, base](uint32_t rva, size_t len,
                                               uint8_t* dst) -> size_t {
            if (!UserMemReadFn(&mctx, pid, base + rva, dst, len)) return 0;
            return len;
        };

        pry::host::Request creq;
        creq.pid = pid;
        creq.module_base = base;
        creq.module_name = req->module_name();
        switch (req->mode()) {
            case ImageCoherencyRequest::QUICK:
                creq.mode = pry::host::CoherencyMode::kQuick; break;
            case ImageCoherencyRequest::FULL:
                creq.mode = pry::host::CoherencyMode::kFull; break;
            default:
                creq.mode = pry::host::CoherencyMode::kNormal; break;
        }
        creq.max_mismatch_ranges = req->max_mismatch_ranges();
        creq.include_mismatch_hex = req->include_mismatch_hex();

        pry::host::Result out;
        if (!pry::host::ComputeCoherency(creq, mem_reader, disk_reader,
                                              headers, &out, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }

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
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterImageCoherencyService(grpc::ServerBuilder& builder,
                                    const AgentConfig& cfg,
                                    DriverMgr& drv)
{
    static ImageCoherencySvc svc(cfg, drv);
    builder.RegisterService(&svc);
}

}  // namespace pry
