#pragma once
// umagent/src/etw/etw_session.hpp — SI #10 ETW session (umagent view).
//
// Thin facade header: the shared implementation lives at
// agent/src/etw/etw_session.hpp and the umagent builds the same .cpp
// through its CMakeLists.txt (same pattern as img_coherency /
// sig_verify). This header exists so umagent translation units can
// include a local path without diving into the agent tree.
#include "../../../agent/src/etw/etw_session.hpp"
