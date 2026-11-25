// umagent/src/img_coherency.cpp — SI feature #1: image coherency (umagent side)
//
// Opens the module's on-disk image, maps it, reads the mapped headers,
// and runs the shared pry::host::ComputeCoherency scorer against two
// readers — one over the file mapping, one through um::MemRead. See the
// slice plan at an internal plan
// 04-umagent-orchestrator.md §Feature 1 for the overall contract.

#include "img_coherency.hpp"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "umem.hpp"

namespace um {

namespace {

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                          out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                   nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                          out.data(), n);
    return out;
}

// RAII wrapper over CreateFileW + CreateFileMappingW + MapViewOfFile.
class MappedFile {
public:
    MappedFile() = default;
    ~MappedFile() { close(); }

    bool open(const std::wstring& path, std::string* err) {
        file_ = ::CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE
                                  | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) {
            if (err) *err = WinError("CreateFileW (coherency disk)",
                                     ::GetLastError());
            return false;
        }
        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(file_, &sz)) {
            if (err) *err = WinError("GetFileSizeEx", ::GetLastError());
            return false;
        }
        size_ = static_cast<size_t>(sz.QuadPart);
        mapping_ = ::CreateFileMappingW(file_, nullptr, PAGE_READONLY,
                                         0, 0, nullptr);
        if (!mapping_) {
            if (err) *err = WinError("CreateFileMappingW",
                                     ::GetLastError());
            return false;
        }
        view_ = ::MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!view_) {
            if (err) *err = WinError("MapViewOfFile", ::GetLastError());
            return false;
        }
        return true;
    }

    void close() {
        if (view_) {
            ::UnmapViewOfFile(view_);
            view_ = nullptr;
        }
        if (mapping_) {
            ::CloseHandle(mapping_);
            mapping_ = nullptr;
        }
        if (file_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file_);
            file_ = INVALID_HANDLE_VALUE;
        }
    }

    const uint8_t* data() const {
        return static_cast<const uint8_t*>(view_);
    }
    size_t size() const { return size_; }

private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
    LPVOID view_ = nullptr;
    size_t size_ = 0;
};

// For a file-layout buffer, resolve an RVA to a file offset via the
// section table so disk reads correspond to the same mapped-image RVA.
int64_t RvaToFileOffset(const uint8_t* file_data, size_t file_size,
                        uint32_t rva) {
    if (file_size < 0x40) return -1;
    if (file_data[0] != 'M' || file_data[1] != 'Z') return -1;
    uint32_t e_lfanew;
    std::memcpy(&e_lfanew, file_data + 0x3C, 4);
    if (e_lfanew + 24 > file_size) return -1;
    if (std::memcmp(file_data + e_lfanew, "PE\0\0", 4) != 0) return -1;
    uint32_t coff = e_lfanew + 4;
    uint16_t nsec;
    uint16_t opt_size;
    std::memcpy(&nsec, file_data + coff + 2, 2);
    std::memcpy(&opt_size, file_data + coff + 16, 2);
    uint32_t sec_off = coff + 20 + opt_size;
    // Headers mapped at offset 0 on both sides.
    uint32_t hdr_end = sec_off + nsec * 40;
    uint32_t first_sec_va = 0;
    if (nsec && sec_off + 40 <= file_size) {
        std::memcpy(&first_sec_va, file_data + sec_off + 12, 4);
    }
    if (rva < first_sec_va || !nsec) {
        return rva < file_size ? static_cast<int64_t>(rva) : -1;
    }
    (void)hdr_end;
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

bool ResolveModuleForCoherency(uint32_t pid,
                               const std::string& module_name,
                               uint64_t module_base_hint,
                               std::string* out_path,
                               uint64_t* out_base,
                               uint64_t* out_size,
                               std::string* err) {
    std::vector<um::Module> mods;
    std::string merr;
    if (!um::Modules(pid, &mods, &merr)) {
        if (err) *err = merr;
        return false;
    }
    const Module* found = nullptr;
    std::string want = module_name;
    std::transform(want.begin(), want.end(), want.begin(), ::tolower);
    for (const auto& m : mods) {
        if (module_base_hint && m.base == module_base_hint) {
            found = &m;
            break;
        }
        std::string lo_name = m.name;
        std::string lo_path = m.path;
        std::transform(lo_name.begin(), lo_name.end(), lo_name.begin(),
                       ::tolower);
        std::transform(lo_path.begin(), lo_path.end(), lo_path.begin(),
                       ::tolower);
        if (!want.empty() && (lo_name == want || lo_path == want)) {
            found = &m;
            break;
        }
    }
    if (!found) {
        if (err) *err = "coherency: module not found in pid " +
                        std::to_string(pid) + " (" + module_name + ")";
        return false;
    }
    if (out_path) *out_path = found->path;
    if (out_base) *out_base = found->base;
    if (out_size) *out_size = found->size;
    return true;
}

bool ComputeCoherency(const pry::host::Request& req,
                      pry::host::Result* out,
                      std::string* err) {
    uint32_t pid = req.pid ? req.pid : ::GetCurrentProcessId();
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0;
    if (!ResolveModuleForCoherency(pid, req.module_name, req.module_base,
                                    &path, &base, &size, err)) {
        return false;
    }
    out->module_path_disk = path;
    // basename extraction
    size_t slash = path.find_last_of("\\/");
    out->module_basename = (slash == std::string::npos)
                                ? path
                                : path.substr(slash + 1);

    MappedFile disk;
    if (!disk.open(Utf8ToWide(path), err)) return false;
    if (disk.size() < 0x40) {
        if (err) *err = "coherency: on-disk file too small";
        return false;
    }

    // Headers — pull enough to resolve directories + section table.
    const uint8_t* file_data = disk.data();
    size_t file_size = disk.size();

    std::vector<uint8_t> headers;
    headers.resize(std::min<size_t>(file_size, 0x10000));
    std::memcpy(headers.data(), file_data, headers.size());

    auto disk_reader = [file_data, file_size](uint32_t rva, size_t len,
                                               uint8_t* dst) -> size_t {
        int64_t off = RvaToFileOffset(file_data, file_size, rva);
        if (off < 0) return 0;
        size_t avail = file_size - static_cast<size_t>(off);
        size_t take = std::min(len, avail);
        std::memcpy(dst, file_data + off, take);
        return take;
    };

    auto mem_reader = [pid, base](uint32_t rva, size_t len,
                                   uint8_t* dst) -> size_t {
        size_t got = 0;
        std::string merr;
        if (!um::MemRead(pid, base + rva, dst, len, &got, &merr)) {
            return 0;
        }
        return got;
    };

    return pry::host::ComputeCoherency(req, mem_reader, disk_reader,
                                           headers, out, err);
}

}  // namespace um
