#pragma once

// agent/src/host/sig_verify.hpp — SI feature #8: Authenticode signer lookup.
//
// Shared implementation vendored by both the agent-side service
// (agent/src/grpc/services_sig.cpp) and the umagent-side service
// (umagent/src/services_sig.cpp). The entry wraps
// WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2) and extracts the
// first signer certificate's subject + issuer common names via
// WTHelperProvDataFromStateData + WTHelperGetProvSignerFromChain.
// Thread-safe (every call uses process-local WVT state that is opened
// and closed in-call); the backing cache is in sig_cache.hpp. See the
// slice plan at an internal plan
// 04-umagent-orchestrator.md §Feature 6 for the response contract.

#include <cstdint>
#include <string>

namespace pry::host {

// Signer tier derived from the issuer CN (not from WVT's trust decision,
// which is a boolean). Values match the slice doc's enum.
//   "microsoft"   — Microsoft Code Signing PCA family
//   "windows"     — Microsoft Windows Production PCA family
//   "antimalware" — Microsoft Windows Early Launch AM PCA
//   "3rd_party"   — any other issuer that chained successfully
//   "unsigned"    — WinVerifyTrust refused (file is not signed)
//   "unknown"     — probe failed before we could tell either way
struct SignerInfo {
    std::string signer;         // subject CN of the leaf cert (or "")
    std::string issuer;         // issuer CN of the leaf cert (or "")
    std::string signing_level;  // one of the strings above
    bool is_signed = false;     // WinVerifyTrust returned ERROR_SUCCESS
    bool catalog = false;       // signature came from a system catalog
    uint64_t cache_timestamp_100ns = 0;  // populated by the cache layer
    std::string error;          // last probe error (empty on success)
};

// Verify *path* via WinVerifyTrust and populate *out*. Returns true on
// a structural success (even for an unsigned file — out.is_signed==false,
// out.signing_level="unsigned"); false only if the file could not be
// opened. On failure *err* carries a diagnostic.
bool VerifySigner(const std::wstring& path, SignerInfo* out,
                   std::string* err);

}  // namespace pry::host
