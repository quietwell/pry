// umagent/src/etw/etw_consumer.cpp — SI #10 ETW consumer (umagent facade TU).
//
// Facade — the real implementation lives at
// agent/src/etw/etw_consumer.cpp, which umagent compiles via a
// vendored CMake entry (same pattern as img_coherency / sig_verify).
// Keeping an empty TU under this path leaves the umagent CMakeLists
// source list stable.

#include "etw_consumer.hpp"

namespace um {
// Shared types live in pry::etw.
}  // namespace um
