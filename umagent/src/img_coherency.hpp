#pragma once
// umagent/src/img_coherency.hpp — SI feature #1: image coherency (umagent side)
//
// Thin umagent facade around the shared pry::host::ComputeCoherency
// scorer (agent/src/host/img_coherency.hpp). Opens the on-disk module
// image via CreateFileW + CreateFileMappingW (full share mode, as SI's
// imgcoherency.c does), wires an in-memory reader through um::MemRead,
// and returns a filled pry::host::Result. See the slice plan at
// an internal plan
// §Feature 1 for the response contract and classifier labels.

#include <cstdint>
#include <string>

#include "../../agent/src/host/img_coherency.hpp"

namespace um {

// Resolve a module (basename or path) in *pid* to its on-disk full
// path and runtime base/size. Empty return + non-empty *err* on
// failure. module_name may be empty when module_base is given.
bool ResolveModuleForCoherency(uint32_t pid,
                               const std::string& module_name,
                               uint64_t module_base_hint,
                               std::string* out_path,
                               uint64_t* out_base,
                               uint64_t* out_size,
                               std::string* err);

// End-to-end entry — opens the on-disk file, invokes the shared scorer
// against both the mapped file and the live process memory, and fills
// *out*. Returns false on structural failure (no module, bad PE,
// VM_READ denied), with *err* describing the first thing that failed.
bool ComputeCoherency(const pry::host::Request& req,
                      pry::host::Result* out,
                      std::string* err);

}  // namespace um
