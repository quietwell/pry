#pragma once

// agent/src/host/user_stackwalk.hpp — SI feature 7: user-space stack walk.
//
// Landing spot for System Informer adoption feature 7's user-mode half,
// see an internal plan and
// an internal plan Phase R0 scaffolding. The kernel
// half rides the slice-1 PRY_FUNC_THREAD_STACKWALK driver primitive;
// this TU owns the Suspend+GetThreadContext+StackWalk64 walker that both
// the agent (when the driver path is unavailable) and umagent consume.
// Public API is populated by the SI Wave 1 PR.
