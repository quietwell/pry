#pragma once

// Cross-process heap enumeration via ntdll's RtlQueryProcessDebugInformation
// (the same undocumented-but-stable path !heap uses). Falls back to a
// PEB->ProcessHeaps walk (heap-level only, no blocks) via a caller-supplied
// user-mode reader when the debug-info API refuses (some system pids do).

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pry::pe {

using UserReadFn = std::function<bool(uint32_t pid, uint64_t addr, void* dst, size_t len)>;

struct HeapBlockRow {
    uint64_t address;
    uint64_t size;
    uint32_t flags;
};

struct HeapRow {
    uint64_t handle;      // HEAP* (target VA); equal to base for user heaps
    uint32_t flags;
    uint64_t base;
    uint64_t committed;
    uint64_t reserved;
    std::vector<HeapBlockRow> blocks;   // empty unless want_blocks
};

// pid == GetCurrentProcessId() is fine; caller must pass a valid user_read
// only when the debug-info fallback is needed. When want_blocks is false,
// no target-thread injection happens (PDI_HEAPS only). max_blocks caps the
// per-heap block count; 0 means "default 4096"; hard cap 65535.
bool WalkHeaps(uint32_t pid, bool want_blocks, uint32_t max_blocks,
               UserReadFn user_read, std::vector<HeapRow>& out, std::string& err);

// ---- VA -> allocation reverse index ----
//
// See an internal plan §7. The index is a
// sorted-interval vector over every block in every heap of a pid. Lookup
// is O(log n) via std::upper_bound + a single bounds check. BlockIval
// carries the originating row/block index so the caller can recover
// heap_handle, segment base, and flags without a parallel lookup.

constexpr uint32_t HEAPATTRIB_MAX_VAS      = 4096;
constexpr uint64_t HEAPATTRIB_TTL_MS       = 2000;
constexpr uint64_t HEAPATTRIB_DELTA_BYTES  = 1ull * 1024ull * 1024ull;  // 1 MiB
constexpr uint32_t HEAPATTRIB_LRU_CAP      = 4;

struct BlockIval {
    uint64_t lo;           // chunk base VA
    uint64_t hi;           // lo + chunk_size (exclusive)
    uint32_t row_idx;      // index into HeapIndex::rows
    uint32_t block_idx;    // index into HeapIndex::rows[row_idx].blocks
};

struct HeapIndex {
    uint32_t pid = 0;
    uint32_t epoch = 0;                // bumps on every rebuild
    uint64_t built_ms = 0;             // monotonic ms at build time
    uint64_t committed_sum = 0;        // sum of row.committed at build time
    std::vector<HeapRow> rows;         // cached snapshot
    std::vector<BlockIval> ivals;      // sorted by lo
};

// Build (or rebuild) the index for the given pid. On success, `out` is
// fully populated and ready for LookupByVA. Reuses WalkHeaps internally
// so the fallback heap-level-only path (system pids) still populates
// rows; `ivals` is empty in that case and LookupByVA returns nullptr.
bool BuildHeapIndex(uint32_t pid, UserReadFn user_read,
                    HeapIndex& out, std::string& err);

// Returns the covering block when `va` lies in some [lo, hi) interval.
// Out params (any may be nullptr) carry the owning segment / heap /
// flags for the caller to copy into the response record.
const HeapBlockRow* LookupByVA(const HeapIndex& idx, uint64_t va,
                               uint64_t* seg_out, uint64_t* heap_out,
                               uint32_t* flags_out);

} // namespace pry::pe
