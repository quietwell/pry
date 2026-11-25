#pragma once
// umagent/src/syscall_table.hpp — SI feature #3 syscall-number calibration.
//
// Builds a bidirectional nt-syscall ↔ number table by scanning the stub
// bytes of every ntdll.dll export whose name starts with "Nt". The stubs
// on x64 follow a stable prologue since Win7 — `mov eax, imm32; …; syscall`
// — so the imm32 at offset +4 of the stub gives the syscall number. One
// singleton per umagent process (keyed by ntdll build + bitness; keyed is
// a future-proofing scaffold — same umagent process always sees the same
// ntdll).
//
// This file is the Wave-1 landing scaffold; the ThreadInspect / WaitInfo
// handlers wire it into their response decoders. The
// table is cheap to build (~30 ms) and inert without a caller — safe to
// construct lazily.
//
// See an internal plan #3.

#include <cstdint>
#include <string>
#include <unordered_map>

namespace um {

struct SyscallNameTable {
    std::unordered_map<std::uint32_t, std::string> name_by_nr;
    std::unordered_map<std::string, std::uint32_t> nr_by_name;
    std::uint64_t ntdll_base = 0;
    std::string   ntdll_version;    // "10.0.26100.xxxx" when resolvable
    std::uint32_t ntdll_build = 0;  // just the "26100" / "26200" slot
    bool          calibrated = false;
};

// Build the table from the current process's ntdll image. Safe to call
// from any thread. Returns a reference to the singleton (first call
// populates it under a std::call_once). Repeat callers get the cached
// copy; `recalibrate=true` forces a rebuild and swaps the cache. Table
// is empty+calibrated=false if ntdll isn't resolvable (e.g. test harness
// without loaded ntdll).
const SyscallNameTable& GetSyscallTable(bool recalibrate = false);

// Convenience: syscall name for a decoded number, or empty when the
// number isn't in the table (unknown stub bytes, uncalibrated).
std::string LookupSyscallName(std::uint32_t number);

// Convenience: syscall number for a canonical ntdll export name
// ("NtWaitForSingleObject"); returns UINT32_MAX when not found.
std::uint32_t LookupSyscallNumber(const std::string& name);

}  // namespace um
