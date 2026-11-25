// agent/src/etw/etw_registry.cpp — SI #10 kernel-provider GUID table.
//
// Friendly-name → GUID resolver for the ETW RPC surface. The names are
// the short labels the orchestrator sends; a caller is also free to
// pass a raw GUID string (with or without braces, any case). The
// GUIDs below are the published kernel provider identifiers from
// MSDN:
//
//   Image       — 15A2B423-635B-4b7f-B8CF-1BAB9F9AD5C7
//   Process     — 22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716
//   Thread      — 3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C
//   DiskIO      — 3D6FA8D4-FE05-11D0-9DDA-00C04FD7BA7C
//   FileIO      — EDD08927-9CC4-4E65-B970-C2560FB5C289
//   TcpIp       — 9A280AC0-C8E0-11D1-84E2-00C04FB998A2
//   UdpIp       — BF3A50C5-A9C9-4988-A005-2DF0B7C80F80

#include "etw_registry.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <utility>

namespace pry::etw {

namespace {

struct Entry {
    const char* name;
    const char* guid;  // uppercase, no braces, 36 chars
};

constexpr std::array<Entry, 7> kKernelProviders{{
    {"image",   "15A2B423-635B-4B7F-B8CF-1BAB9F9AD5C7"},
    {"process", "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"},
    {"thread",  "3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C"},
    {"diskio",  "3D6FA8D4-FE05-11D0-9DDA-00C04FD7BA7C"},
    {"fileio",  "EDD08927-9CC4-4E65-B970-C2560FB5C289"},
    {"tcpip",   "9A280AC0-C8E0-11D1-84E2-00C04FB998A2"},
    {"udpip",   "BF3A50C5-A9C9-4988-A005-2DF0B7C80F80"},
}};

std::string ToUpper(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)std::toupper(c); });
    return s;
}

std::string NormalizeGuid(const std::string& in)
{
    std::string s = in;
    if (!s.empty() && s.front() == '{') s.erase(s.begin());
    if (!s.empty() && s.back() == '}') s.pop_back();
    s = ToUpper(std::move(s));
    // Expect 36 chars with dashes at 8/13/18/23.
    if (s.size() == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-'
        && s[23] == '-') {
        return s;
    }
    return {};
}

}  // namespace

bool ResolveProvider(const std::string& name, std::string* out_guid)
{
    if (!out_guid) return false;
    out_guid->clear();
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    for (const auto& e : kKernelProviders) {
        if (lower == e.name) {
            *out_guid = e.guid;
            return true;
        }
    }
    std::string g = NormalizeGuid(name);
    if (!g.empty()) {
        *out_guid = std::move(g);
        return true;
    }
    return false;
}

std::string ProviderKind(const std::string& guid)
{
    std::string g = NormalizeGuid(guid);
    if (g.empty()) return {};
    for (const auto& e : kKernelProviders) {
        if (g == e.guid) return e.name;
    }
    return {};
}

}  // namespace pry::etw
