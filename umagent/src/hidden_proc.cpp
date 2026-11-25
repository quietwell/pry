// umagent/src/hidden_proc.cpp — SI feature #2 (Wave 1): hidden-process
// detection (umagent side).
//
// Pass-through facade: the shared scanner lives in
// agent/src/host/hidden_proc.cpp (brute / registry / ETW passes) and is
// also vendored into the umagent CMake target. See the slice plan at
// an internal plan
// §Feature 2.

#include "hidden_proc.hpp"

namespace um {

bool ScanHiddenProcesses(const pry::host::HiddenScanRequest& req,
                         pry::host::HiddenScanResult* out,
                         std::string* err)
{
    return pry::host::ScanHiddenProcesses(req, out, err);
}

}  // namespace um
