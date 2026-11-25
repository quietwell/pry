#pragma once

// umagent/src/sig_cache.hpp — SI feature #8 (umagent-side facade).
//
// Thin wrapper exposing the shared pry::host::SignerCache under the
// ``um::`` prefix. The real implementation lives in
// agent/src/host/sig_cache.cpp; umagent's CMakeLists.txt pulls the
// shared TU in via a vendored source entry, so one cache implementation
// serves both the agent and umagent gRPC services. See the slice plan
// at an internal plan
// §Feature 6.

#include "../../agent/src/host/sig_cache.hpp"

namespace um {

using SignerCache = pry::host::SignerCache;

inline SignerCache& GlobalSignerCache()
{
    return pry::host::GlobalSignerCache();
}

}  // namespace um
