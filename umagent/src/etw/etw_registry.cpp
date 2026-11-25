// umagent/src/etw/etw_registry.cpp — SI #10 ETW provider registry (facade).
//
// Facade — the kernel-provider GUID table + resolver live at
// agent/src/etw/etw_registry.cpp, which umagent compiles via a
// vendored CMake entry. This TU exists so umagent's source list stays
// stable; the shared implementation serves both views.

namespace um {
// Shared types live in pry::etw.
}  // namespace um
