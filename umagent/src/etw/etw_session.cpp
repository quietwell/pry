// umagent/src/etw/etw_session.cpp — SI #10 ETW session (umagent facade TU).
//
// Implementation is shared with the agent: the real .cpp lives at
// agent/src/etw/etw_session.cpp and umagent compiles it via a vendored
// CMake entry (same pattern as img_coherency / sig_verify). This file
// is intentionally empty so the umagent CMakeLists source list keeps
// a stable path. See an internal plan
// 04-umagent-orchestrator.md §Feature 8.

#include "etw_session.hpp"

namespace um {
// All ETW types live in the shared pry::etw namespace; umagent code
// reaches them directly. Nothing to define here.
}  // namespace um
