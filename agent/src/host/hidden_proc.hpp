#pragma once

// agent/src/host/hidden_proc.hpp — SI feature 2 (Wave 1): hidden-process
// detection.
//
// Three usermode PID oracles whose results cross-reference against the
// NtQuerySystemInformation(SystemProcessInformation) inventory:
//
//   brute   — step PIDs with OpenProcess; a PID that opens (or that
//             returns ACCESS_DENIED) exists even if NtQSI unlinked it
//             from ActiveProcessLinks.
//   registry— HKLM PerfLib\009\Counter + Services\*\ImagePath scrape,
//             joined to EnumProcesses for mapping image→PID.
//   etw     — EnumerateTraceGuidsEx(TraceGuidQueryInfo) returns the
//             pid that owns each registered provider.
//
// CSRSS mode (handle-table deref via the driver) is Wave 2 — stub in
// agent/src/host/csrss_scan.cpp is intentionally empty. See the plan
// at an internal plan
// §Feature 2 and §3 (Wave 1).
//
// Shared source: the agent (services_hidden.cpp) and the umagent
// (services_hidden.cpp counterpart) both compile this translation
// unit — the scanners are pure usermode and have no driver dependency.

#include <cstdint>
#include <string>
#include <vector>

namespace pry::host {

struct HiddenPidRow {
    uint32_t pid = 0;
    std::string image;             // best-effort basename, "" when denied
    bool present_brute = false;
    bool present_registry = false;
    bool present_etw = false;
    uint64_t exit_time_100ns = 0;  // non-zero + handle-live => zombie
    uint32_t handle_count = 0;
    std::string sources;           // comma-sep list of modes that saw it
};

struct HiddenScanRequest {
    uint32_t pid_max = 100000;     // scanner default when caller passes 0
    uint32_t step = 4;             // scanner default when caller passes 0
    uint32_t timeout_ms = 0;       // 0 => no per-mode soft cap
    bool do_brute = false;
    bool do_registry = false;
    bool do_etw = false;
};

struct HiddenScanResult {
    std::vector<HiddenPidRow> rows;
    std::vector<std::string> modes_run;
    std::vector<std::string> modes_failed;
    uint32_t pid_max_used = 0;
    uint32_t step_used = 0;
};

// Entry point. Runs each enabled scanner in turn, merges rows by PID,
// and never throws. A mode that bails lands in ``modes_failed``; its
// row.present_<mode> stays false and other modes still contribute.
// *err* carries the first structural error encountered when every
// enabled mode failed; the function returns false in that case. On
// partial success returns true and leaves *err* empty.
bool ScanHiddenProcesses(const HiddenScanRequest& req,
                         HiddenScanResult* out,
                         std::string* err);

// Mode-pass helpers exposed for testing / targeted re-runs. Each one
// returns true on success and merges into *rows* (adding new PIDs or
// toggling the present_<mode> flag on existing rows).
bool BruteScan(uint32_t pid_max, uint32_t step,
               std::vector<HiddenPidRow>* rows, std::string* err);
bool RegistryScan(std::vector<HiddenPidRow>* rows, std::string* err);
bool EtwScan(std::vector<HiddenPidRow>* rows, std::string* err);

}  // namespace pry::host
