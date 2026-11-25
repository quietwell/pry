// agent/src/dump/process_dump.cpp — SI feature #14: process-snapshot minidump.
//
// Shared implementation vendored by both the agent-side service
// (agent/src/grpc/services_dump.cpp) and the umagent-side service
// (umagent/src/services_dump.cpp, through a vendored CMake entry in
// umagent/CMakeLists.txt). Wraps PssCaptureSnapshot + MiniDumpWriteDump
// behind the stepped access-mask ladder documented in
// agent/src/dump/process_dump.hpp. See the slice plan at
// an internal plan
// §Feature 9 (README feature #14).
//
// PP target handling is EXPLICITLY DEFERRED to SI feature #23 (Wave 3).
// When every rung of the ladder returns ACCESS_DENIED and the process
// exists, Dump() surfaces ``pp_target_requires_feature_23`` rather than
// reaching for undocumented tactics.

#include "process_dump.hpp"

#include <windows.h>
#include <dbghelp.h>
#include <processsnapshot.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")

namespace pry::host {

namespace {

// Stepped access-mask ladder — maximum access first, dropping to the
// minimum. The last rung (QUERY_LIMITED_INFORMATION) can't drive
// MiniDumpWriteDump by itself but is retained so a dump failure at that
// rung yields an honest "access_denied: minimum level" diagnostic
// instead of an ambiguous "no process". The dump call attempts proceed
// top-down and stop at the first full success.
constexpr std::array<DWORD, 4> kAccessLadder = {
    PROCESS_ALL_ACCESS,
    // PssCaptureSnapshot's documented minimum: VM_READ+VM_OPERATION+
    // DUP_HANDLE+QUERY_INFORMATION+SUSPEND_RESUME.
    PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION |
        PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME,
    PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

// PSS flags for the snapshot — mirrors SI's `imgcoherency` and
// `procdump`-style capture: VA clone, handles with names/types/trace,
// thread contexts (extended). The breakaway flags are left off: on
// Win11 25H2 service-silo jobs reject them with ACCESS_DENIED even
// with SeTcbPrivilege, and procdump itself doesn't use them.
constexpr DWORD kPssFlags =
    PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES |
    PSS_CAPTURE_HANDLE_NAME_INFORMATION |
    PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
    PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
    PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS |
    PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED;

std::string FormatLastErr(const char* ctx)
{
    DWORD e = GetLastError();
    char buf[128];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s: GetLastError=0x%lx",
                ctx, (unsigned long)e);
    return std::string(buf);
}

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                   (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                           out.data(), n);
    return out;
}

std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                           out.data(), n, nullptr, nullptr);
    return out;
}

// Default output path when the caller leaves output_path empty:
// %TEMP%\pry\dumps\pid_<pid>_<unix-ms>.dmp. Creates the dirs when
// missing. Returned path is wide so CreateFileW / MiniDumpWriteDump
// take it directly.
std::wstring DefaultOutputPath(uint32_t pid)
{
    wchar_t tmp[MAX_PATH + 1]{};
    DWORD n = ::GetTempPathW(MAX_PATH, tmp);
    std::wstring base = (n && n <= MAX_PATH) ? std::wstring(tmp)
                                              : L"C:\\Windows\\Temp\\";
    std::wstring dir1 = base + L"pry";
    std::wstring dir2 = dir1 + L"\\dumps";
    ::CreateDirectoryW(dir1.c_str(), nullptr);
    ::CreateDirectoryW(dir2.c_str(), nullptr);
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    uint64_t t100 = (uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime;
    uint64_t ms = (t100 / 10000ULL) - 11644473600000ULL;
    wchar_t name[96];
    _snwprintf_s(name, 96, _TRUNCATE, L"\\pid_%u_%llu.dmp",
                 (unsigned)pid, (unsigned long long)ms);
    return dir2 + name;
}

// Try to detect PP / PPL via GetProcessInformation(ProcessProtectionLevelInfo).
// Needs a handle with PROCESS_QUERY_LIMITED_INFORMATION — we probe at that
// mask when the stepped ladder failed everywhere else. Returns true when
// the target is confirmed PP/PPL. The documented "unprotected" sentinel
// is PROTECTION_LEVEL_NONE (0xFFFFFFFF), but Win11 25H2 also returns
// 0xFFFFFFFE for non-protected processes (the newer "same as caller"
// sentinel). The named protected levels are the small set 0x0..0x8
// (WINTCB_LIGHT..PPL_APP); anything outside that is treated as
// unprotected.
bool IsProtectedProcess(uint32_t pid)
{
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    PROCESS_PROTECTION_LEVEL_INFORMATION info{};
    BOOL ok = ::GetProcessInformation(h, ProcessProtectionLevelInfo,
                                       &info, sizeof(info));
    ::CloseHandle(h);
    if (!ok) return false;
    constexpr DWORD kMaxKnownProtected = 0x08u;  // PROTECTION_LEVEL_PPL_APP
    return info.ProtectionLevel <= kMaxKnownProtected;
}

// Does the pid exist at all? OpenProcess(QUERY_LIMITED_INFO) succeeding
// is a stronger existence proof than NtQuerySystemInformation on a very
// recent fork — but PP processes also return ACCESS_DENIED there, so we
// cross-check: a failure with ERROR_INVALID_PARAMETER means "no such pid";
// an ACCESS_DENIED means "exists but is locked down".
bool ProcessExists(uint32_t pid, bool* out_denied)
{
    *out_denied = false;
    if (pid == 0) return false;
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        ::CloseHandle(h);
        return true;
    }
    DWORD e = GetLastError();
    if (e == ERROR_ACCESS_DENIED) {
        *out_denied = true;
        return true;
    }
    return false;
}

std::string Sha256File(HANDLE hFile, uint64_t* size_out)
{
    LARGE_INTEGER sz{};
    if (!::GetFileSizeEx(hFile, &sz)) return {};
    *size_out = (uint64_t)sz.QuadPart;
    LARGE_INTEGER zero{};
    ::SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN);

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                     nullptr, 0) != 0) {
        return {};
    }
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    constexpr size_t CHUNK = 1 << 16;
    std::vector<BYTE> buf(CHUNK);
    for (;;) {
        DWORD got = 0;
        if (!::ReadFile(hFile, buf.data(), (DWORD)CHUNK, &got, nullptr)) {
            BCryptDestroyHash(hh);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        if (got == 0) break;
        if (BCryptHashData(hh, buf.data(), got, 0) != 0) {
            BCryptDestroyHash(hh);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
    }
    BYTE digest[32]{};
    BCryptFinishHash(hh, digest, sizeof(digest), 0);
    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(alg, 0);
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (int i = 0; i < 32; ++i) {
        out[i * 2 + 0] = kHex[(digest[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[digest[i] & 0xF];
    }
    ::SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN);
    return out;
}

// One ladder rung: open process, run the (optional) snapshot, call
// MiniDumpWriteDump. Returns true on full success.
bool TryDumpAtMask(uint32_t pid, DWORD mask, uint64_t flags,
                   HANDLE out_file, bool use_snapshot,
                   bool* snapshot_was_used, std::string* err)
{
    *snapshot_was_used = false;
    HANDLE hProc = ::OpenProcess(mask, FALSE, pid);
    if (!hProc) {
        *err = FormatLastErr("OpenProcess");
        return false;
    }
    HPSS snap = nullptr;
    MINIDUMP_CALLBACK_INFORMATION* cbp = nullptr;
    MINIDUMP_CALLBACK_INFORMATION cb_pss{};
    HANDLE dumpProc = hProc;
    DWORD dumpPid = pid;
    if (use_snapshot) {
        DWORD st = ::PssCaptureSnapshot(hProc,
                                         static_cast<PSS_CAPTURE_FLAGS>(kPssFlags),
                                         CONTEXT_ALL, &snap);
        if (st != ERROR_SUCCESS) {
            ::CloseHandle(hProc);
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "PssCaptureSnapshot: 0x%lx",
                        (unsigned long)st);
            *err = buf;
            return false;
        }
        // dbghelp's PssSnapshotHelpers hand MiniDumpWriteDump the snapshot
        // transparently via the MiniDumpWithoutOptionalData path. The
        // supported way is through the MINIDUMP_CALLBACK_INFORMATION that
        // reroutes read/write requests to the snapshot handle — but on
        // modern dbghelp (Win10 1703+) MiniDumpWriteDump accepts an HPSS
        // directly through the process_handle parameter. We follow the
        // latter: pass the snapshot handle to MiniDumpWriteDump and let
        // dbghelp speak to it as if it were a process handle.
        dumpProc = (HANDLE)snap;
        *snapshot_was_used = true;
    }
    MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(flags != 0
        ? (DWORD)flags
        : (DWORD)kDefaultDumpFlags);
    BOOL ok = ::MiniDumpWriteDump(dumpProc, dumpPid, out_file, dumpType,
                                   nullptr, nullptr, cbp);
    DWORD gle = GetLastError();
    if (use_snapshot && snap) {
        ::PssFreeSnapshot(hProc, snap);
    }
    ::CloseHandle(hProc);
    if (!ok) {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "MiniDumpWriteDump: GetLastError=0x%lx",
                    (unsigned long)gle);
        *err = buf;
        return false;
    }
    return true;
}

}  // namespace

void DumpProcess(const ProcessDumpRequest& req, ProcessDumpResponse* out)
{
    *out = {};
    if (req.pid == 0) {
        out->kind = "bad_arg";
        out->error = "pid must be > 0";
        return;
    }
    if (req.pid == ::GetCurrentProcessId()) {
        out->kind = "self_pid";
        out->error = "refusing to dump the agent/umagent process itself";
        return;
    }
    bool was_denied = false;
    if (!ProcessExists(req.pid, &was_denied)) {
        out->kind = "no_process";
        out->error = "pid not found (or exited before dump start)";
        return;
    }
    if (was_denied && IsProtectedProcess(req.pid)) {
        out->kind = "pp_target_requires_feature_23";
        out->error = "target is protected (PP/PPL); requires PP open "
                     "(feature #23, Wave 3)";
        return;
    }

    // Resolve output path.
    std::wstring wpath = Utf8ToWide(req.output_path);
    if (wpath.empty()) {
        wpath = DefaultOutputPath(req.pid);
    } else {
        // Ensure parent directory exists best-effort — no deep recursion.
        auto slash = wpath.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            std::wstring parent = wpath.substr(0, slash);
            ::CreateDirectoryW(parent.c_str(), nullptr);
        }
    }
    HANDLE hFile = ::CreateFileW(
        wpath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        out->kind = "io_failed";
        out->error = FormatLastErr("CreateFileW(output)");
        return;
    }

    std::string last_err = "no ladder rung attempted";
    bool success = false;
    bool snap_used = false;
    DWORD mask_used = 0;
    bool want_snapshot = req.use_snapshot;
    for (DWORD mask : kAccessLadder) {
        std::string err;
        bool used = false;
        if (TryDumpAtMask(req.pid, mask, req.flags, hFile,
                          want_snapshot, &used, &err)) {
            success = true;
            snap_used = used;
            mask_used = mask;
            break;
        }
        last_err = std::move(err);
        // Rewind to overwrite from the top on the next attempt.
        LARGE_INTEGER zero{};
        ::SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN);
        ::SetEndOfFile(hFile);
        // Win11 25H2 refuses PssCaptureSnapshot with ACCESS_DENIED when
        // the caller lives in a service silo (SI's workaround path). The
        // direct MiniDumpWriteDump still works, so drop the snapshot and
        // retry the SAME rung — if that succeeds, snapshot_used=false
        // tells the caller we fell back.
        if (want_snapshot &&
            last_err.compare(0, 20, "PssCaptureSnapshot: ") == 0) {
            want_snapshot = false;
            if (TryDumpAtMask(req.pid, mask, req.flags, hFile,
                              false, &used, &err)) {
                success = true;
                snap_used = false;
                mask_used = mask;
                break;
            }
            last_err = std::move(err);
            ::SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN);
            ::SetEndOfFile(hFile);
        }
    }
    if (!success) {
        ::CloseHandle(hFile);
        ::DeleteFileW(wpath.c_str());
        // Distinguish PP-denied-everywhere from a generic failure. The
        // ladder's last_err carries "GetLastError=0xN" (exact — see
        // FormatLastErr). ACCESS_DENIED is 0x5 and that is the only
        // suffix we treat as such — 0x15 / 0x50 / 0x53 etc must NOT
        // masquerade as access denied.
        bool access_denied = last_err.size() >= 4 &&
            last_err.compare(last_err.size() - 4, 4, "=0x5") == 0;
        if (access_denied) {
            if (IsProtectedProcess(req.pid)) {
                out->kind = "pp_target_requires_feature_23";
                out->error = "target denied every ladder rung — PP/PPL; "
                             "requires PP open (feature #23, Wave 3)";
                return;
            }
            out->kind = "access_denied";
            out->error = "access denied at every ladder rung: " + last_err;
            return;
        }
        out->kind = req.use_snapshot ? "snapshot_failed" : "dump_failed";
        out->error = last_err;
        return;
    }

    uint64_t sz = 0;
    std::string sha = Sha256File(hFile, &sz);
    ::CloseHandle(hFile);
    if (sha.empty()) {
        out->kind = "io_failed";
        out->error = "sha256 compute failed";
        return;
    }

    out->ok = true;
    out->path = WideToUtf8(wpath);
    out->size = sz;
    out->sha256 = std::move(sha);
    out->access_mask_used = (uint32_t)mask_used;
    out->snapshot_used = snap_used;
}

}  // namespace pry::host
