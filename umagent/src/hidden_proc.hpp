#pragma once
// umagent/src/hidden_proc.hpp — SI feature #2 (Wave 1): hidden-process
// detection (umagent side).
//
// Thin umagent facade over the shared pry::host::ScanHiddenProcesses
// scorer in agent/src/host/hidden_proc.cpp. The scanners are pure
// usermode so the agent and umagent run the identical code; the facade
// exists so the umagent TU keeps the ``um::`` namespace shape every
// other umagent translation unit uses.
//
// Slice doc: an internal plan
// §Feature 2.

#include <string>

#include "../../agent/src/host/hidden_proc.hpp"

namespace um {

// Entry point. Delegates to pry::host::ScanHiddenProcesses — the
// shared scanner does not touch any umagent-only state so the facade
// is a pass-through today. Kept as a named entry so service-level
// code can declare the usermode entry alongside the other um:: verbs.
bool ScanHiddenProcesses(const pry::host::HiddenScanRequest& req,
                         pry::host::HiddenScanResult* out,
                         std::string* err);

}  // namespace um
