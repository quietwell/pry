#pragma once

// agent/src/dump/process_dump.hpp — SI feature #14: process-snapshot minidump.
//
// Shared implementation used by both the agent-side ProcessDump service
// (agent/src/grpc/services_dump.cpp) and the umagent-side service
// (umagent/src/services_dump.cpp, via vendored CMake entry). Wraps
// PssCaptureSnapshot + MiniDumpWriteDump behind a stepped access-mask
// ladder: PROCESS_ALL_ACCESS → VM_READ|QUERY_INFORMATION|DUP_HANDLE →
// VM_READ|QUERY_INFORMATION → QUERY_LIMITED_INFORMATION. The first mask
// whose OpenProcess call succeeds AND for which MiniDumpWriteDump returns
// is the one echoed back in access_mask_used.
//
// PP (Protected Process / PPL) targets are out of scope for Wave 1 — the
// driver's PRY_FUNC_OPEN_PROCESS_KM primitive (SI feature #23) lands
// in Wave 3. Until then, a dump request against a PP target surfaces a
// clean ``pp_target_requires_feature_23`` error from Dump() and never
// falls back to any undocumented tactic. See the slice plan at
// an internal plan
// §Feature 9 (feature numbering in that doc: §9 == feature #14).

#include <cstdint>
#include <string>

namespace pry::host {

struct ProcessDumpRequest {
    uint32_t pid = 0;              // target pid; must not be 0 or self
    uint64_t flags = 0;            // MINIDUMP_TYPE bitmask (see below)
    std::string output_path;       // absolute Win32 path; "" → auto under %TEMP%\pry\dumps
    bool use_snapshot = true;      // false → direct MiniDumpWriteDump on the open handle
};

struct ProcessDumpResponse {
    bool ok = false;
    std::string error;             // non-empty on failure (named kinds below)
    std::string kind;              // "bad_arg" | "self_pid" | "no_process" |
                                   // "pp_target_requires_feature_23" |
                                   // "access_denied" | "snapshot_failed" |
                                   // "dump_failed" | "io_failed"
    std::string path;              // absolute output path on success
    uint64_t size = 0;             // dump file size in bytes
    std::string sha256;            // lowercase hex, 64 chars
    uint32_t access_mask_used = 0; // which rung of the ladder succeeded
    bool snapshot_used = false;    // true when PssCaptureSnapshot path was taken
};

// Perform a process-snapshot minidump. Returns a filled response (never
// throws). ``use_snapshot=true`` runs the PSS path (PssCaptureSnapshot →
// MiniDumpWriteDump via the snapshot handle); ``use_snapshot=false`` is
// the direct-process path (same output, no snapshot). Both honor the
// stepped-access-mask ladder.
void DumpProcess(const ProcessDumpRequest& req, ProcessDumpResponse* out);

// Default MINIDUMP_TYPE used when ProcessDumpRequest.flags == 0:
// MiniDumpWithFullMemory | MiniDumpWithThreadInfo | MiniDumpWithHandleData |
// MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo | MiniDumpWithTokenInformation
constexpr uint64_t kDefaultDumpFlags =
    0x00000002ULL | 0x00001000ULL | 0x00000004ULL |
    0x00000020ULL | 0x00000800ULL | 0x00040000ULL;

}  // namespace pry::host
