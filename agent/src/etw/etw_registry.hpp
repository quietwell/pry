#pragma once
// agent/src/etw/etw_registry.hpp — SI #10 kernel-provider GUID table.
//
// Small, static map from short friendly names ("image", "process",
// "thread", "diskio", "fileio", "tcpip", "udpip") onto the kernel's
// well-known provider GUIDs so the orchestrator can ask for "image"
// without carrying GUID strings around. Also resolves a GUID back to
// its friendly name for the response path (so the orchestrator sees
// kind='image' rather than a bare GUID). Unknown GUIDs round-trip as
// their string form with kind="".

#include <string>

namespace pry::etw {

// Returns true + fills `out_guid` (uppercase 36-char no braces) when
// `name` matches a registered friendly name or already is a GUID.
bool ResolveProvider(const std::string& name, std::string* out_guid);

// Reverse lookup for the response path.
std::string ProviderKind(const std::string& guid);

}  // namespace pry::etw
