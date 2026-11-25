// umagent/src/sig_cache.cpp — SI feature #8 (umagent-side facade TU).
//
// Public interface is header-only in sig_cache.hpp (aliases into
// pry::host). The actual LRU + disk persistence lives in
// agent/src/host/sig_cache.cpp, which umagent compiles via a vendored
// CMake entry. See the slice plan at
// an internal plan
// §Feature 6.

#include "sig_cache.hpp"

namespace um {
// All public API is inline in the header; this TU is intentionally empty.
}  // namespace um
