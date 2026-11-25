// agent/src/host/sig_verify.cpp — SI feature #8: Authenticode signer lookup.
//
// Shared implementation (compiled into both agent and umagent via
// vendored CMake source list). WinVerifyTrust performs the trust
// decision; WTHelperProvDataFromStateData + WTHelperGetProvSignerFromChain
// extract the first signer's leaf certificate so we can report subject
// CN + issuer CN. Signing-level classification is a pure issuer-CN
// substring match — the slice doc §Feature 6 is explicit that the level
// is a heuristic hint, not a trust decision.

#include "sig_verify.hpp"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>

#include <algorithm>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace pry::host {

namespace {

// WinVerifyTrust is documented thread-safe but takes a non-const GUID
// pointer; keep a function-local copy per call.
GUID WvtActionV2() { return WINTRUST_ACTION_GENERIC_VERIFY_V2; }

std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), out.data(),
                          n, nullptr, nullptr);
    return out;
}

std::string CnFromCert(PCCERT_CONTEXT cert, DWORD flags)
{
    if (!cert) return {};
    DWORD n = ::CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                     flags, nullptr, nullptr, 0);
    if (n <= 1) return {};
    std::wstring buf(n, L'\0');
    DWORD written = ::CertGetNameStringW(
        cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, buf.data(), n);
    if (written == 0) return {};
    // CertGetNameStringW writes a null terminator inside the buffer; trim it.
    if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
    return WideToUtf8(buf);
}

std::string ClassifyIssuer(const std::string& issuer)
{
    if (issuer.empty()) return "unknown";
    auto has = [&](const char* needle) {
        return issuer.find(needle) != std::string::npos;
    };
    if (has("Early Launch Anti") || has("Early Launch Antimalware")) {
        return "antimalware";
    }
    if (has("Windows Production PCA") || has("Windows PCA 20")
        || has("Windows Verification")) {
        return "windows";
    }
    if (has("Microsoft Code Signing") || has("Microsoft Windows Signing")
        || has("Microsoft Development") || has("Microsoft Root")
        || has("Microsoft Code Verification")) {
        return "microsoft";
    }
    return "3rd_party";
}

// Catalog-first probe (so system-signed binaries don't fall through to
// the embedded path and report unsigned). WTD_CHOICE_CATALOG points at a
// WINTRUST_CATALOG_INFO; we feed it the file's cat-hash via
// CryptCATAdminCalcHashFromFileHandle. On catalog miss, fall back to
// WTD_CHOICE_FILE (embedded Authenticode).

bool TryCatalog(const std::wstring& path, SignerInfo* out, std::string* err)
{
    HANDLE fh = ::CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE
                                   | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING,
                               FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (fh == INVALID_HANDLE_VALUE) {
        if (err) *err = "sig: open file failed, gle="
                        + std::to_string(::GetLastError());
        return false;
    }
    HCATADMIN hAdmin = nullptr;
    using CryptCATAdminAcquireContext2Fn = BOOL(WINAPI*)(
        HCATADMIN*, const GUID*, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
    static auto pAcquire2 = reinterpret_cast<CryptCATAdminAcquireContext2Fn>(
        ::GetProcAddress(::GetModuleHandleW(L"wintrust.dll"),
                         "CryptCATAdminAcquireContext2"));
    BOOL okAcq = FALSE;
    if (pAcquire2) {
        okAcq = pAcquire2(&hAdmin, nullptr, BCRYPT_SHA256_ALGORITHM,
                           nullptr, 0);
    }
    if (!okAcq && !::CryptCATAdminAcquireContext(&hAdmin, nullptr, 0)) {
        ::CloseHandle(fh);
        return false;
    }
    DWORD cbHash = 0;
    ::CryptCATAdminCalcHashFromFileHandle(fh, &cbHash, nullptr, 0);
    std::vector<BYTE> hash(cbHash);
    BOOL hashOk = ::CryptCATAdminCalcHashFromFileHandle(fh, &cbHash,
                                                         hash.data(), 0);
    ::CloseHandle(fh);
    if (!hashOk) {
        ::CryptCATAdminReleaseContext(hAdmin, 0);
        return false;
    }
    HCATINFO hCat = ::CryptCATAdminEnumCatalogFromHash(hAdmin, hash.data(),
                                                        cbHash, 0, nullptr);
    if (!hCat) {
        ::CryptCATAdminReleaseContext(hAdmin, 0);
        return false;
    }
    CATALOG_INFO ci{};
    ci.cbStruct = sizeof(ci);
    if (!::CryptCATCatalogInfoFromContext(hCat, &ci, 0)) {
        ::CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
        ::CryptCATAdminReleaseContext(hAdmin, 0);
        return false;
    }
    // Hex-encode the hash for WINTRUST_CATALOG_INFO.pcwszMemberTag.
    std::wstring memberTag(cbHash * 2, L'\0');
    static const wchar_t kHex[] = L"0123456789ABCDEF";
    for (DWORD i = 0; i < cbHash; ++i) {
        memberTag[i * 2]     = kHex[(hash[i] >> 4) & 0xF];
        memberTag[i * 2 + 1] = kHex[hash[i] & 0xF];
    }

    WINTRUST_CATALOG_INFO wci{};
    wci.cbStruct = sizeof(wci);
    wci.pcwszCatalogFilePath = ci.wszCatalogFile;
    wci.pcwszMemberTag = memberTag.c_str();
    wci.pcwszMemberFilePath = path.c_str();
    wci.pbCalculatedFileHash = hash.data();
    wci.cbCalculatedFileHash = cbHash;
    wci.hCatAdmin = hAdmin;

    WINTRUST_DATA wtd{};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wtd.pCatalog = &wci;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID g = WvtActionV2();
    LONG rc = ::WinVerifyTrust(nullptr, &g, &wtd);
    bool ok = (rc == ERROR_SUCCESS);
    if (ok) {
        out->is_signed = true;
        out->catalog = true;
        CRYPT_PROVIDER_DATA* pd =
            ::WTHelperProvDataFromStateData(wtd.hWVTStateData);
        if (pd) {
            CRYPT_PROVIDER_SGNR* sgnr =
                ::WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);
            if (sgnr && sgnr->csCertChain) {
                CRYPT_PROVIDER_CERT* pc =
                    ::WTHelperGetProvCertFromChain(sgnr, 0);
                if (pc && pc->pCert) {
                    out->signer = CnFromCert(pc->pCert, 0);
                    out->issuer = CnFromCert(pc->pCert,
                                              CERT_NAME_ISSUER_FLAG);
                }
            }
        }
    }
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &g, &wtd);
    ::CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
    ::CryptCATAdminReleaseContext(hAdmin, 0);
    return ok;
}

bool TryEmbedded(const std::wstring& path, SignerInfo* out,
                  std::string* err)
{
    WINTRUST_FILE_INFO wfi{};
    wfi.cbStruct = sizeof(wfi);
    wfi.pcwszFilePath = path.c_str();

    WINTRUST_DATA wtd{};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &wfi;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID g = WvtActionV2();
    LONG rc = ::WinVerifyTrust(nullptr, &g, &wtd);
    bool ok = (rc == ERROR_SUCCESS);
    if (ok) {
        out->is_signed = true;
        out->catalog = false;
        CRYPT_PROVIDER_DATA* pd =
            ::WTHelperProvDataFromStateData(wtd.hWVTStateData);
        if (pd) {
            CRYPT_PROVIDER_SGNR* sgnr =
                ::WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);
            if (sgnr && sgnr->csCertChain) {
                CRYPT_PROVIDER_CERT* pc =
                    ::WTHelperGetProvCertFromChain(sgnr, 0);
                if (pc && pc->pCert) {
                    out->signer = CnFromCert(pc->pCert, 0);
                    out->issuer = CnFromCert(pc->pCert,
                                              CERT_NAME_ISSUER_FLAG);
                }
            }
        }
    } else if (rc == TRUST_E_NOSIGNATURE) {
        // honest "unsigned"; distinct from a probe failure.
        if (err) *err = "unsigned";
    } else {
        if (err) *err = "WinVerifyTrust rc=0x"
                         + std::to_string(static_cast<unsigned long>(rc));
    }
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &g, &wtd);
    return ok;
}

}  // namespace

bool VerifySigner(const std::wstring& path, SignerInfo* out,
                   std::string* err)
{
    if (!out) return false;
    *out = SignerInfo{};
    if (path.empty()) {
        if (err) *err = "sig: empty path";
        out->signing_level = "unknown";
        return false;
    }
    DWORD attrs = ::GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES
        || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        if (err) *err = "sig: file not found or is a directory";
        out->signing_level = "unknown";
        return false;
    }
    std::string catErr;
    if (TryCatalog(path, out, &catErr)) {
        out->signing_level = ClassifyIssuer(out->issuer);
        if (err) *err = "";
        return true;
    }
    std::string embErr;
    if (TryEmbedded(path, out, &embErr)) {
        out->signing_level = ClassifyIssuer(out->issuer);
        if (err) *err = "";
        return true;
    }
    // Neither path succeeded. If WVT said TRUST_E_NOSIGNATURE on the
    // embedded probe we return structurally-ok "unsigned"; otherwise
    // "unknown" plus the probe diagnostic.
    out->is_signed = false;
    if (embErr == "unsigned") {
        out->signing_level = "unsigned";
        if (err) *err = "";
        return true;
    }
    out->signing_level = "unknown";
    out->error = embErr.empty() ? catErr : embErr;
    if (err) *err = out->error;
    return true;  // probe is a soft error; the row still answers.
}

}  // namespace pry::host
