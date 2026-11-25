// comm/pattern_scan.hpp — the ONE byte-pattern scan loop shared by the
// agent (Memory.Scan / Memory.ScanStream, driver-backed reads) and the
// umagent (Memory.Scan, ReadProcessMemory reads).
//
// Before this there were three drifted copies. The agent's had three bugs
// (mechanics audit P1): size=0 (the orchestrator's whole-space scan)
// returned 0 hits; `limit = got - pat.size()` skipped the last start
// position of every chunk; and the overlap bookkeeping advanced the cursor
// by got-(p-1) but decremented the remaining count by got, so a scan
// stopped (chunks-1)*(p-1) bytes short of its window.
//
// Contract:
//   * PlanRanges() turns (base, size) into scan ranges with the proto
//     semantics: base==0 -> every readable region; base!=0 && size==0 ->
//     readable regions from base onward ("till end of region chain");
//     otherwise the explicit [base, base+size) window.
//   * ScanRange() reads a range in `chunk`-byte windows that overlap by
//     pat.size()-1 bytes, so a match straddling a window boundary is found
//     exactly once and every start position in the range is tested.
//     A read that returns 0 bytes, or a short read before the end of the
//     range, stops that range (the next byte is unreadable) after the bytes
//     that DID arrive were scanned.
//
// Header-only, no gRPC / Windows dependency: unit-tested in
// agent/tests/unit_tests.cpp.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pry::patscan {

struct Range {
    std::uint64_t start = 0;
    std::uint64_t size = 0;
};

struct Region {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint32_t protect = 0; // Win32 PAGE_*
};

// Same predicate umagent always used: committed, not NOACCESS, not GUARD.
inline bool IsReadableProtect(std::uint32_t protect)
{
    constexpr std::uint32_t kNoAccess = 0x01; // PAGE_NOACCESS
    constexpr std::uint32_t kGuard = 0x100;   // PAGE_GUARD
    return protect != 0 && protect != kNoAccess && (protect & kGuard) == 0;
}

inline bool ValidPattern(const std::string& pat, const std::string& mask)
{
    return !pat.empty() && (mask.empty() || mask.size() == pat.size());
}

// Saturating end of [start, start+size).
inline std::uint64_t RangeEnd(std::uint64_t start, std::uint64_t size)
{
    return size > UINT64_MAX - start ? UINT64_MAX : start + size;
}

inline std::vector<Range> PlanRanges(std::uint64_t base, std::uint64_t size,
                                     const std::vector<Region>& regions)
{
    std::vector<Range> out;
    if (base != 0 && size != 0) {
        out.push_back({base, size});
        return out;
    }
    for (const auto& r : regions) {
        if (!IsReadableProtect(r.protect) || r.size == 0) {
            continue;
        }
        const std::uint64_t end = RangeEnd(r.base, r.size);
        const std::uint64_t start = std::max(r.base, base);
        if (start < end) {
            out.push_back({start, end - start});
        }
    }
    return out;
}

// True when `pat` matches at `p` ('?' in `mask` = wildcard byte).
inline bool MatchAt(const std::uint8_t* p, const std::string& pat, const std::string& mask)
{
    for (std::size_t j = 0; j < pat.size(); ++j) {
        if (!mask.empty() && mask[j] == '?') {
            continue;
        }
        if (p[j] != static_cast<std::uint8_t>(pat[j])) {
            return false;
        }
    }
    return true;
}

// read(va, dst, want) -> bytes actually read (0 = unreadable).
using ReadFn = std::function<std::size_t(std::uint64_t va, std::uint8_t* dst, std::size_t want)>;
// hit(va) -> false to stop the whole scan (result cap reached).
using HitFn = std::function<bool(std::uint64_t va)>;
// chunk_done(cursor, bytes_scanned_total) after every window -> false to
// cancel (client went away). Optional.
using ChunkFn = std::function<bool(std::uint64_t cursor, std::uint64_t bytes_scanned)>;

struct ScanStats {
    std::uint64_t bytes_scanned = 0; // distinct bytes of the range(s) covered
    std::uint64_t cursor = 0;        // first VA NOT yet covered when stopped
    bool read_stopped = false;       // a range ended early on an unreadable byte
    bool cap_hit = false;            // hit() returned false
    bool cancelled = false;          // chunk_done() returned false
};

inline constexpr std::size_t kDefaultChunk = 0x100000; // 1 MiB

// Scans one range; accumulates into *stats (so several ranges can share
// one stats object). Returns false when the WHOLE scan must stop
// (cap_hit / cancelled), true to continue with the next range.
inline bool ScanRange(const Range& r, const std::string& pat, const std::string& mask,
                      std::size_t chunk, const ReadFn& read, const HitFn& hit,
                      const ChunkFn& chunk_done, std::vector<std::uint8_t>& buf,
                      ScanStats* stats)
{
    const std::size_t p = pat.size();
    if (p == 0 || r.size == 0) {
        return true;
    }
    // A window must hold at least one full pattern plus progress.
    chunk = std::max<std::size_t>(chunk, 2 * p);
    if (buf.size() < chunk) {
        buf.resize(chunk);
    }
    const std::uint64_t end = RangeEnd(r.start, r.size);
    std::uint64_t pos = r.start; // first start position not yet tested
    while (pos < end) {
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(chunk, end - pos));
        std::size_t got = read(pos, buf.data(), want);
        if (got > want) {
            got = want; // defensive: never trust a reader past `want`
        }
        if (got == 0) {
            stats->read_stopped = true;
            break;
        }
        // start positions 0 .. got-p (inclusive) have p bytes available
        const std::size_t limit = got >= p ? got - p + 1 : 0;
        for (std::size_t i = 0; i < limit; ++i) {
            if (MatchAt(buf.data() + i, pat, mask)) {
                if (!hit(pos + i)) {
                    stats->bytes_scanned += i + p; // bytes the hit consumed
                    stats->cursor = pos + i + 1;
                    stats->cap_hit = true;
                    return false;
                }
            }
        }
        std::uint64_t next;
        bool stop_range = false;
        if (pos + got >= end) {
            next = end; // window reached the end of the range
        } else if (got < want) {
            next = pos + got; // short read: the byte after is unreadable
            stop_range = true;
            stats->read_stopped = true;
        } else {
            next = pos + limit; // full window: overlap the last p-1 bytes
        }
        stats->bytes_scanned += next - pos;
        pos = next;
        stats->cursor = pos;
        if (chunk_done && !chunk_done(pos, stats->bytes_scanned)) {
            stats->cancelled = true;
            return false;
        }
        if (stop_range) {
            break;
        }
    }
    stats->cursor = pos;
    return true;
}

// Convenience: scan every range, stop at max_results hits.
inline ScanStats ScanRanges(const std::vector<Range>& ranges, const std::string& pat,
                            const std::string& mask, std::uint32_t max_results,
                            const ReadFn& read, std::vector<std::uint64_t>* hits,
                            const ChunkFn& chunk_done = {}, std::size_t chunk = kDefaultChunk)
{
    ScanStats st;
    std::vector<std::uint8_t> buf;
    const std::uint32_t cap = max_results ? max_results : 64;
    HitFn on_hit = [&](std::uint64_t va) {
        hits->push_back(va);
        return hits->size() < cap;
    };
    for (const auto& r : ranges) {
        if (hits->size() >= cap) {
            st.cap_hit = true;
            break;
        }
        if (!ScanRange(r, pat, mask, chunk, read, on_hit, chunk_done, buf, &st)) {
            break;
        }
    }
    return st;
}

} // namespace pry::patscan
