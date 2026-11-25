// agent/src/scan/scan_ids.hpp — client-supplied scan / pointer-map ids
// become directory names under the scan root, and the services run as
// SYSTEM. Mechanics audit P0 #2: `scan_root_/view_/req.scan_id()` with an
// absolute id REPLACED the whole path (std::filesystem operator/), and
// Destroy then ran remove_all() on it; a Loaded map's spill_dir was the
// caller's own remote_path, so Load + Destroy (keep_disk defaults false)
// deleted the user's saved map folder.
//
// Rules enforced through these helpers:
//   * ids match ^[A-Za-z0-9_-]{1,64}$ (no separators, dots, drive letters);
//   * remove_all only ever runs on a path that canonicalizes to a strict
//     descendant of the registry's own spill root.
//
// Header-only, no gRPC: unit-tested in agent/tests/unit_tests.cpp.
#pragma once

#include <cstddef>
#include <filesystem>
#include <string_view>
#include <system_error>

namespace pry::scan {

inline constexpr std::size_t kMaxIdLen = 64;

inline bool ValidId(std::string_view id)
{
    if (id.empty() || id.size() > kMaxIdLen) {
        return false;
    }
    for (char c : id) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

// True when `p` canonicalizes to a STRICT descendant of `root` (never root
// itself). weakly_canonical resolves "..", symlinks/junctions of the
// existing prefix, and case is compared as the filesystem returns it after
// canonicalization (lower-cased on Windows to be safe).
inline bool PathStrictlyUnder(const std::filesystem::path& root, const std::filesystem::path& p)
{
    if (root.empty() || p.empty() || !root.is_absolute() || !p.is_absolute()) {
        return false;
    }
    std::error_code ec;
    auto r = std::filesystem::weakly_canonical(root, ec);
    if (ec) {
        return false;
    }
    auto c = std::filesystem::weakly_canonical(p, ec);
    if (ec) {
        return false;
    }
    auto lower = [](std::wstring s) {
        for (auto& ch : s) {
            if (ch >= L'A' && ch <= L'Z') {
                ch = (wchar_t)(ch - L'A' + L'a');
            }
        }
        return s;
    };
    std::wstring rs = lower(r.wstring());
    std::wstring cs = lower(c.wstring());
    while (!rs.empty() && (rs.back() == L'\\' || rs.back() == L'/')) {
        rs.pop_back();
    }
    if (cs.size() <= rs.size() + 1 || cs.compare(0, rs.size(), rs) != 0) {
        return false;
    }
    const wchar_t sep = cs[rs.size()];
    return sep == L'\\' || sep == L'/';
}

// remove_all, but only inside `root`. Returns false (and touches nothing)
// for anything else.
inline bool RemoveAllUnder(const std::filesystem::path& root, const std::filesystem::path& p,
                           std::error_code& ec)
{
    if (!PathStrictlyUnder(root, p)) {
        return false;
    }
    std::filesystem::remove_all(p, ec);
    return !ec;
}

} // namespace pry::scan
