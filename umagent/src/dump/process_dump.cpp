// umagent/src/dump/process_dump.cpp — SI feature #14 (umagent-side facade TU).
//
// The implementation is header-only in process_dump.hpp (an inline
// wrapper over pry::host::DumpProcess). This TU exists so umagent's
// CMakeLists.txt source list continues to list the file — the real
// PssCaptureSnapshot + MiniDumpWriteDump probe lives in
// agent/src/dump/process_dump.cpp, which umagent compiles via a vendored
// CMake source entry.

#include "process_dump.hpp"

namespace um {
// All public API is inline in the header; this TU is intentionally empty.
}  // namespace um
