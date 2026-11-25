#pragma once

// umagent/src/sig_verify.hpp — SI feature #8 (umagent-side facade).
//
// Thin wrapper over pry::host::VerifySigner so umagent translation
// units can call it under the ``um::`` namespace they already live in.
// The real implementation is in agent/src/host/sig_verify.cpp, which
// umagent pulls into its build via a vendored CMake entry (so both
// agent and umagent share one WinVerifyTrust probe). See the slice
// plan at an internal plan
// 04-umagent-orchestrator.md §Feature 6.

#include "../../agent/src/host/sig_verify.hpp"

namespace um {

// SignerInfo and VerifySigner alias into the shared pry::host
// namespace so umagent-local service code can keep its ``um::`` prefix
// (same pattern as um::ComputeCoherency wrapping pry::host::).
using SignerInfo = pry::host::SignerInfo;

inline bool VerifySigner(const std::wstring& path, SignerInfo* out,
                           std::string* err)
{
    return pry::host::VerifySigner(path, out, err);
}

}  // namespace um
