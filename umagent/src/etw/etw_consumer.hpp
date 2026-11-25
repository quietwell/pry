#pragma once
// umagent/src/etw/etw_consumer.hpp — SI #10 ETW consumer (umagent view).
//
// Facade for the shared agent-side implementation (see
// agent/src/etw/etw_consumer.hpp). The umagent CMakeLists.txt pulls
// in the agent-side .cpp so the SPSC ring + decoder behave
// identically across views.
#include "../../../agent/src/etw/etw_consumer.hpp"
