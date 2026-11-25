// agent/src/host/token_lsa.hpp — shared with umagent.
//
// SID / name / logon-session helpers. LsaLookupSids2 + LsaLookupNames2
// with a 3s per-call timeout to survive an unreachable DC (slice 01
// §Edge cases — DC-latency surfaces coverage.partial.lsa_timeout).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pry::host {

struct LookupRowRaw {
    std::string input;
    std::string sid;
    std::string name;
    std::string domain;
    std::string use;         // SID_NAME_USE string
    bool well_known = false;
};

bool LookupSidsAndNames(const std::vector<std::string>& sids,
                        const std::vector<std::string>& names,
                        std::vector<LookupRowRaw>* out,
                        std::string* err);

// String conversion helpers (SID <-> string).
bool SidToString(const unsigned char* sid, std::string* out);
std::string IntegrityNameFromRid(uint32_t rid);

}  // namespace pry::host
