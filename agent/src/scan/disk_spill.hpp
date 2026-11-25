// agent/src/scan/disk_spill.hpp
//
// v17 (Memory scanner wave 2 Phase B): shared disk-spill helpers for the
// agent's on-target scan stores — Wave 1's ScanService (raw.bin +
// vas.bin per generation) and Wave 2's PointerMapService (map.bin +
// by_target.idx + modules.json + meta.json). Factored out of
// scan_service.cpp so both services share one atomic-rename
// discipline: .tmp sibling, close (flush), rename into place. On
// crash between write and rename the .tmp may remain; GC in each
// registry sweeps stale ones.
//
// Header-only; included by scan_service.cpp + pointer_map_service.cpp.
// Keep the surface tiny — no allocation beyond std::ofstream, no
// dependency on the generated proto headers.

#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace pry::scan {

// Writes `size` bytes to `out_path` atomically via a .tmp sibling.
// Returns false on any OS failure. Creates missing parent directories.
// `size == 0` writes an empty file (rare: a valid empty vas.bin for a
// never-hit snapshot).
inline bool WriteAtomic(const std::filesystem::path& out_path,
                        const void* data, std::size_t size)
{
    std::error_code ec;
    auto parent = out_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) return false;
    }
    auto tmp = out_path;
    tmp += ".tmp";
    {
        std::ofstream os(tmp, std::ios::binary | std::ios::trunc);
        if (!os) return false;
        if (size > 0) {
            os.write(reinterpret_cast<const char*>(data),
                     static_cast<std::streamsize>(size));
            if (!os) return false;
        }
    }
    // Rename over any existing file (atomic on Windows/NTFS when target
    // isn't a locked file). On failure clean up the .tmp.
    std::filesystem::rename(tmp, out_path, ec);
    if (ec) {
        std::error_code rm;
        std::filesystem::remove(tmp, rm);
        return false;
    }
    return true;
}

// Writes a scan snapshot (packed vas + raw buffer) as
// vas.genNN.bin + raw.genNN.bin into `dir`. The pair is the on-disk
// mirror ScanEntry falls back to when snapshot RAM crosses
// SCAN_RAM_BUDGET. Two sequential WriteAtomic calls: the pair is NOT
// atomic as a unit — a crash between the two leaves vas without a
// matching raw. ScanRegistry GC drops dirs whose vas/raw pair fails
// its sanity check.
inline bool WriteRawToDisk(const std::filesystem::path& dir,
                           const std::vector<std::uint64_t>& vas,
                           const std::vector<std::uint8_t>& raw,
                           std::uint32_t generation)
{
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;
    char suffix[32];
    std::snprintf(suffix, sizeof(suffix), ".gen%02u.bin", generation);
    auto vas_path = dir / (std::string("vas") + suffix);
    auto raw_path = dir / (std::string("raw") + suffix);
    if (!WriteAtomic(vas_path, vas.data(),
                     vas.size() * sizeof(std::uint64_t))) {
        return false;
    }
    if (!WriteAtomic(raw_path, raw.data(), raw.size())) {
        return false;
    }
    return true;
}

}  // namespace pry::scan
