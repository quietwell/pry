#pragma once

// agent/src/host/sig_cache.hpp — SI feature #8: signer LRU cache.
//
// Shared implementation (built into both agent and umagent via vendored
// CMake source list). In-memory LRU keyed by
// (path_lower, file_size_bytes, mtime_100ns); eviction at 4096 entries,
// FIFO-of-least-recently-used order. Disk persistence to
// %ProgramData%\pry\sig_cache.bin is best-effort — load on first
// touch, save on `Flush()`. See the slice plan at
// an internal plan
// §Feature 6 for the response contract.

#include "sig_verify.hpp"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace pry::host {

struct SignerCacheKey {
    std::string path_lower;
    uint64_t size = 0;
    uint64_t mtime_100ns = 0;

    bool operator==(const SignerCacheKey& o) const noexcept {
        return size == o.size && mtime_100ns == o.mtime_100ns
            && path_lower == o.path_lower;
    }
};

struct SignerCacheKeyHash {
    size_t operator()(const SignerCacheKey& k) const noexcept;
};

class SignerCache {
public:
    static constexpr size_t kDefaultCapacity = 4096;

    explicit SignerCache(size_t capacity = kDefaultCapacity);

    // Lookup. Returns the cached SignerInfo if present and still fresh
    // (size + mtime match the current on-disk file); otherwise empty.
    // Thread-safe.
    std::optional<SignerInfo> Lookup(const std::wstring& path);

    // Store the row for *path*; evicts the LRU entry when the cache is
    // full. Thread-safe.
    void Store(const std::wstring& path, const SignerInfo& info);

    // Verify + cache in one call. If *force_recheck* is true, bypasses
    // the cache (and overwrites the slot on success). The *out_cached*
    // out-param is set to the cache-hit flag.
    bool VerifyCached(const std::wstring& path, bool force_recheck,
                       SignerInfo* out, bool* out_cached,
                       std::string* err);

    size_t size() const;
    size_t capacity() const { return capacity_; }

    // Best-effort load/save to %ProgramData%\pry\sig_cache.bin. On
    // parse/version mismatch the cache stays empty.
    bool LoadFromDisk();
    bool SaveToDisk();

private:
    struct Entry {
        SignerCacheKey key;
        SignerInfo info;
    };

    mutable std::mutex mu_;
    size_t capacity_;
    // Order list: front = MRU, back = LRU candidate for eviction.
    std::vector<Entry> order_;
    // Map from key -> index into order_. Rebuilt on eviction / rotate.
    std::unordered_map<SignerCacheKey, size_t, SignerCacheKeyHash> idx_;

    void RebuildIndex();
};

// Process-global cache (used by the gRPC services).
SignerCache& GlobalSignerCache();

}  // namespace pry::host
