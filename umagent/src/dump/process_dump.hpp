#pragma once

// umagent/src/dump/process_dump.hpp — SI feature #14 (umagent-side facade).
//
// Thin wrapper over pry::host::DumpProcess so umagent translation
// units can call it under the ``um::`` namespace they already live in.
// The real implementation is in agent/src/dump/process_dump.cpp, which
// umagent pulls into its build via a vendored CMake entry (so both
// agent and umagent share one PssCaptureSnapshot + MiniDumpWriteDump
// probe). See the slice plan at an internal plan
// 04-umagent-orchestrator.md §Feature 9.

#include "../../../agent/src/dump/process_dump.hpp"

namespace um {

using ProcessDumpRequest = pry::host::ProcessDumpRequest;
using ProcessDumpResponse = pry::host::ProcessDumpResponse;

inline void DumpProcess(const ProcessDumpRequest& req,
                         ProcessDumpResponse* out)
{
    pry::host::DumpProcess(req, out);
}

}  // namespace um
