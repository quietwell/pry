// umagent/src/user_stackwalk.cpp — SI feature #7: user-space stack walk (umagent-side)
//
// Landing spot for System Informer adoption feature #7
// (an internal plan).
// Will use SuspendThread + GetThreadContext + StackWalk64 / RtlLookupFunctionEntry +
// RtlVirtualUnwind on x64 (and matching WoW64 variants). Symbol lookup is orchestrator-side.
// Shared with the agent via a vendored path per 02-cpp-side.md.
//
// This file is intentionally empty — populated by the SI Wave 1 PR.

namespace um {
// empty — populated by SI feature #7
}  // namespace um
