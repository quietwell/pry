#pragma once

// agent/src/host/img_coherency.hpp — SI feature #1: image coherency scoring.
//
// Shared implementation vendored by both the agent-side gRPC service
// (services_memory.cpp) and the umagent-side service. The scorer takes
// two byte readers (one for the mapped image, one for the on-disk file)
// plus a PE header buffer, builds an exclusion bitmap over the regions
// that are legitimately divergent between disk and memory (relocs,
// IAT thunks, LoadConfig override tables, CFG function/call-check
// tables, ARM64X dynamic relocs, the ImageBase field in the optional
// header), then compares bytes section-by-section. See the plan at
// an internal plan
// §Feature 1 for the response contract.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pry::host {

// Mode selector mirrors the proto enum (QUICK/NORMAL/FULL). QUICK caps
// at ~192 KiB total; NORMAL at 40 MiB; FULL walks SizeOfImage.
enum class CoherencyMode : int { kQuick = 0, kNormal = 1, kFull = 2 };

// Mismatch range coalesced across skipped (exclusion-bitmap) bits.
struct MismatchRange {
    uint32_t rva = 0;
    uint32_t length = 0;
    std::string in_memory_sample;   // raw bytes; <= 64 B capture
    std::string on_disk_sample;
    std::string section;            // ".text" / ".idata" / "" when outside sections
    std::string hint;               // "iat_slot" | "reloc" | "section_hole" | ""
};

// One section's layout as the scorer uses it (and as it is echoed back
// in the response for the orchestrator's classifier).
struct SectionSpan {
    std::string name;
    uint32_t va = 0;              // RVA of section start
    uint32_t size = 0;            // virtual size
    uint32_t characteristics = 0;
    bool executable = false;
};

struct Request {
    uint32_t pid = 0;             // informational only; the readers already bound to it
    uint64_t module_base = 0;
    std::string module_name;
    CoherencyMode mode = CoherencyMode::kNormal;
    uint32_t max_mismatch_ranges = 128;
    bool include_mismatch_hex = false;
};

// Reader callback: fill *dst* with *len* bytes from image offset *rva*
// (zero-based inside the mapped image / on-disk file). Returns the
// number of bytes actually read (0 on failure). The scorer tolerates
// short reads and marks the hole as a section_hole mismatch.
using Reader = std::function<size_t(uint32_t rva, size_t len, uint8_t* dst)>;

struct Result {
    std::string module_basename;
    std::string module_path_disk;
    uint64_t size_of_image = 0;
    uint64_t bytes_compared = 0;
    uint64_t bytes_mismatched = 0;
    float coherency = 1.0f;
    uint64_t sections_total = 0;
    uint64_t sections_skipped_relocatable = 0;
    bool truncated = false;
    uint32_t reloc_dir_rva = 0;
    uint32_t reloc_dir_size = 0;
    std::vector<SectionSpan> sections;
    std::vector<MismatchRange> mismatches;
};

// Core entry point. ``mapped_reader`` reads from the in-memory image;
// ``disk_reader`` from the mapped file on disk; ``headers`` is the
// (already-mapped) view used to parse the PE directories. Returns true
// on structural success; on failure sets *err* with a diagnostic and
// leaves *out* with whatever partial info has been accumulated.
bool ComputeCoherency(const Request& req,
                      const Reader& mapped_reader,
                      const Reader& disk_reader,
                      const std::vector<uint8_t>& headers,
                      Result* out,
                      std::string* err);

}  // namespace pry::host
