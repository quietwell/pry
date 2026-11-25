// agent/src/host/sig_cache.cpp — SI feature #8: signer LRU cache impl.
//
// Shared implementation (compiled into both agent and umagent). The
// cache lives behind a mutex; LRU order is a vector that we rotate on
// hit and pop_back on eviction. The index map stores slot indices into
// the order vector and is rebuilt on structural changes (eviction or
// move-to-front) — on the hot path, the common case (hit near the
// front) only touches O(move_distance) index entries. This is the
// standard "small LRU: avoid std::list splice overhead" shape.

#include "sig_cache.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

namespace pry::host {

namespace {

constexpr uint32_t kDiskMagic = 0x53494743;   // 'SIGC' little-endian
constexpr uint32_t kDiskVersion = 1;

std::string Lower(std::string s)
{
    for (auto& c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s;
}

std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), out.data(),
                          n, nullptr, nullptr);
    return out;
}

bool ProbeKey(const std::wstring& path, SignerCacheKey* out)
{
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        return false;
    }
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    out->path_lower = Lower(WideToUtf8(path));
    out->size = (uint64_t(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
    out->mtime_100ns = (uint64_t(fad.ftLastWriteTime.dwHighDateTime) << 32)
                       | fad.ftLastWriteTime.dwLowDateTime;
    return true;
}

std::wstring CachePath()
{
    wchar_t buf[MAX_PATH]{};
    DWORD n = ::GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    std::wstring dir;
    if (n > 0 && n < MAX_PATH) dir.assign(buf, n);
    else dir = L"C:\\ProgramData";
    dir += L"\\pry";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir + L"\\sig_cache.bin";
}

template <typename T>
void WriteBytes(std::ofstream& out, const T& v)
{
    out.write(reinterpret_cast<const char*>(&v), sizeof(v));
}

void WriteString(std::ofstream& out, const std::string& s)
{
    uint32_t n = static_cast<uint32_t>(s.size());
    WriteBytes(out, n);
    out.write(s.data(), s.size());
}

template <typename T>
bool ReadBytes(std::ifstream& in, T* v)
{
    in.read(reinterpret_cast<char*>(v), sizeof(T));
    return in.gcount() == static_cast<std::streamsize>(sizeof(T));
}

bool ReadString(std::ifstream& in, std::string* s, uint32_t max_len)
{
    uint32_t n = 0;
    if (!ReadBytes(in, &n)) return false;
    if (n > max_len) return false;
    s->assign(n, '\0');
    if (n) in.read(s->data(), n);
    return in.gcount() == static_cast<std::streamsize>(n);
}

}  // namespace

size_t SignerCacheKeyHash::operator()(const SignerCacheKey& k) const noexcept
{
    size_t h = std::hash<std::string>{}(k.path_lower);
    h ^= std::hash<uint64_t>{}(k.size) + 0x9E3779B97F4A7C15ULL + (h << 6)
         + (h >> 2);
    h ^= std::hash<uint64_t>{}(k.mtime_100ns) + 0x9E3779B97F4A7C15ULL
         + (h << 6) + (h >> 2);
    return h;
}

SignerCache::SignerCache(size_t capacity)
    : capacity_(capacity ? capacity : kDefaultCapacity)
{
    order_.reserve(capacity_);
    idx_.reserve(capacity_);
}

void SignerCache::RebuildIndex()
{
    idx_.clear();
    for (size_t i = 0; i < order_.size(); ++i) idx_.emplace(order_[i].key, i);
}

std::optional<SignerInfo> SignerCache::Lookup(const std::wstring& path)
{
    SignerCacheKey k;
    if (!ProbeKey(path, &k)) return std::nullopt;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = idx_.find(k);
    if (it == idx_.end()) return std::nullopt;
    // Move-to-front rotation.
    size_t pos = it->second;
    if (pos != 0) {
        Entry hit = std::move(order_[pos]);
        order_.erase(order_.begin() + pos);
        order_.insert(order_.begin(), std::move(hit));
        RebuildIndex();
    }
    return order_.front().info;
}

void SignerCache::Store(const std::wstring& path, const SignerInfo& info)
{
    SignerCacheKey k;
    if (!ProbeKey(path, &k)) return;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = idx_.find(k);
    if (it != idx_.end()) {
        size_t pos = it->second;
        order_[pos].info = info;
        if (pos != 0) {
            Entry hit = std::move(order_[pos]);
            order_.erase(order_.begin() + pos);
            order_.insert(order_.begin(), std::move(hit));
            RebuildIndex();
        }
        return;
    }
    Entry e{};
    e.key = std::move(k);
    e.info = info;
    order_.insert(order_.begin(), std::move(e));
    while (order_.size() > capacity_) order_.pop_back();
    RebuildIndex();
}

bool SignerCache::VerifyCached(const std::wstring& path, bool force_recheck,
                                 SignerInfo* out, bool* out_cached,
                                 std::string* err)
{
    if (out_cached) *out_cached = false;
    if (!force_recheck) {
        if (auto hit = Lookup(path)) {
            if (out) *out = *hit;
            if (out_cached) *out_cached = true;
            return true;
        }
    }
    SignerInfo info{};
    bool ok = VerifySigner(path, &info, err);
    if (ok) {
        FILETIME ft{};
        ::GetSystemTimeAsFileTime(&ft);
        info.cache_timestamp_100ns = (uint64_t(ft.dwHighDateTime) << 32)
                                      | ft.dwLowDateTime;
        Store(path, info);
    }
    if (out) *out = info;
    return ok;
}

size_t SignerCache::size() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return order_.size();
}

bool SignerCache::LoadFromDisk()
{
    std::ifstream in(CachePath(), std::ios::binary);
    if (!in) return false;
    uint32_t magic = 0, version = 0, count = 0;
    if (!ReadBytes(in, &magic) || magic != kDiskMagic) return false;
    if (!ReadBytes(in, &version) || version != kDiskVersion) return false;
    if (!ReadBytes(in, &count)) return false;
    if (count > capacity_ * 2) return false;
    std::lock_guard<std::mutex> lk(mu_);
    order_.clear();
    for (uint32_t i = 0; i < count; ++i) {
        Entry e{};
        if (!ReadString(in, &e.key.path_lower, 32768)) break;
        if (!ReadBytes(in, &e.key.size)) break;
        if (!ReadBytes(in, &e.key.mtime_100ns)) break;
        uint8_t is_signed = 0, catalog = 0;
        if (!ReadBytes(in, &is_signed)) break;
        if (!ReadBytes(in, &catalog)) break;
        if (!ReadBytes(in, &e.info.cache_timestamp_100ns)) break;
        if (!ReadString(in, &e.info.signer, 2048)) break;
        if (!ReadString(in, &e.info.issuer, 2048)) break;
        if (!ReadString(in, &e.info.signing_level, 64)) break;
        e.info.is_signed = (is_signed != 0);
        e.info.catalog = (catalog != 0);
        if (order_.size() < capacity_) order_.push_back(std::move(e));
    }
    RebuildIndex();
    return true;
}

bool SignerCache::SaveToDisk()
{
    std::ofstream out(CachePath(),
                       std::ios::binary | std::ios::trunc);
    if (!out) return false;
    std::lock_guard<std::mutex> lk(mu_);
    uint32_t magic = kDiskMagic, version = kDiskVersion;
    uint32_t count = static_cast<uint32_t>(order_.size());
    WriteBytes(out, magic);
    WriteBytes(out, version);
    WriteBytes(out, count);
    for (const auto& e : order_) {
        WriteString(out, e.key.path_lower);
        WriteBytes(out, e.key.size);
        WriteBytes(out, e.key.mtime_100ns);
        uint8_t is_signed = e.info.is_signed ? 1 : 0;
        uint8_t catalog = e.info.catalog ? 1 : 0;
        WriteBytes(out, is_signed);
        WriteBytes(out, catalog);
        WriteBytes(out, e.info.cache_timestamp_100ns);
        WriteString(out, e.info.signer);
        WriteString(out, e.info.issuer);
        WriteString(out, e.info.signing_level);
    }
    return static_cast<bool>(out);
}

SignerCache& GlobalSignerCache()
{
    static SignerCache cache(SignerCache::kDefaultCapacity);
    static std::once_flag once;
    std::call_once(once, [&] { cache.LoadFromDisk(); });
    return cache;
}

}  // namespace pry::host
