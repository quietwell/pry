// umagent/src/sig_verify.cpp — SI feature #8 (umagent-side facade TU).
//
// The implementation is header-only in sig_verify.hpp (an inline wrapper
// over pry::host::VerifySigner). This TU exists so umagent's
// CMakeLists.txt source list continues to list the file — the shared
// WinVerifyTrust probe lives in agent/src/host/sig_verify.cpp, which
// umagent compiles via a vendored CMake source entry. See the slice
// plan at an internal plan
// 04-umagent-orchestrator.md §Feature 6.

#include "sig_verify.hpp"

namespace um {
// All public API is inline in the header; this TU is intentionally empty.
}  // namespace um
