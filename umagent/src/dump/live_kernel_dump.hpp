#pragma once

// umagent/src/dump/live_kernel_dump.hpp
//
// Live kernel dump via NtSystemDebugControl(SysDbgGetLiveKernelDump).
// Pure umagent — no driver dependency. The call writes the dump to a
// target-side path (orchestrator sees {path, size, sha256} only — see
// slice doc §Feature 5).

#include <cstdint>
#include <string>
#include <vector>

namespace um {

struct LiveKernelDumpRequest {
    std::string output_path;      // "" => default under %SystemRoot%\\LiveKernelDumps
    std::vector<std::string> flags;  // slice doc names (hypervisor_pages / usermode / stack_only / compression / page_table_only)
    bool compression = false;     // ORs in the compression bit
    bool allow_cancel = false;    // register a cancel event with SysDbg
};

struct LiveKernelDumpResponse {
    bool ok = false;
    std::string error;
    std::string kind;             // "" | "not_allowed" | "access_denied" | "not_supported" | "io_failed" | "sysdbg_failed"
    std::string error_detail;     // free-form, usually win32-err or NTSTATUS hex
    std::string path;             // absolute path to the written dump
    uint64_t size = 0;            // bytes written
    std::string sha256;           // lowercase hex of the dump bytes
    uint32_t flags_used_mask = 0; // SYSDBG_LIVEDUMP_FLAG_* bits applied
    std::vector<std::string> flags_unknown;  // names we didn't recognize
};

// Thread-safe entry point. Dispatches to the SysDbg path, writes the
// output file on the target, and fills ``out``. Idempotent per invocation.
void CreateLiveKernelDump(const LiveKernelDumpRequest& req,
                          LiveKernelDumpResponse* out);

}  // namespace um
