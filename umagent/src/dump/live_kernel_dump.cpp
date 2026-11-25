// umagent/src/dump/live_kernel_dump.cpp
//
// NtSystemDebugControl(SysDbgGetLiveKernelDump) wrapper.
//
// Design notes (slice doc §Feature 5):
//   * SeDebugPrivilege is re-enabled on the calling thread per
//     NtSystemDebugControl call — the umagent service token may have
//     lost it to a token sweep between calls.
//   * SysDbgGetLiveKernelDump writes directly to our output HANDLE —
//     the orchestrator never buffers the dump bytes. The handle is a
//     plain CreateFileW on the target.
//   * ``flags`` are translated from slice names to
//     SYSDBG_LIVEDUMP_FLAG_* bits. Unknown names echo in flags_unknown.
//   * On older Windows that doesn't carry the SysDbg class 37
//     SysDbgGetLiveKernelDump (<=1803), the call returns
//     STATUS_INVALID_PARAMETER / STATUS_NOT_IMPLEMENTED — we classify
//     either as kind='not_supported' and keep the output file empty.
//
// This TU keeps the public entry point tiny. Everything else is static
// so the symbol table doesn't leak NtSystemDebugControl internals into
// other translation units.

#include "live_kernel_dump.hpp"

#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <shlwapi.h>  // PathFileExistsW

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace um {

namespace {

// SYSDBG_LIVEDUMP_* flags live in the undocumented ntddk/ntddbg
// headers; redefine the ones we need here.
constexpr uint32_t SYSDBG_LIVEDUMP_FLAG_SELECTIVE_DUMP            = 0x00000001;
constexpr uint32_t SYSDBG_LIVEDUMP_FLAG_USE_DUMP_STORAGE_STACK    = 0x00000002;
constexpr uint32_t SYSDBG_LIVEDUMP_FLAG_COMPRESS_MEMORY_PAGES_DATA = 0x00000010;
constexpr uint32_t SYSDBG_LIVEDUMP_FLAG_INCLUDE_USERSPACE_MEMORY_PAGES = 0x00000020;

// SYSDBG_COMMAND values
constexpr ULONG kSysDbgGetLiveKernelDump = 37;

#pragma pack(push, 1)
struct SYSDBG_LIVEDUMP_CONTROL_V1 {
    ULONG Version;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    HANDLE DumpFileHandle;
    HANDLE CancelEventHandle;
    ULONG Flags;
    ULONG AddPagesControl;
};
#pragma pack(pop)

using NtSystemDebugControl_t = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);

static NtSystemDebugControl_t ResolveNtSystemDebugControl()
{
    static std::once_flag once;
    static NtSystemDebugControl_t fn = nullptr;
    std::call_once(once, []() {
        HMODULE h = GetModuleHandleW(L"ntdll.dll");
        if (!h) return;
        fn = reinterpret_cast<NtSystemDebugControl_t>(
            GetProcAddress(h, "NtSystemDebugControl"));
    });
    return fn;
}

static bool EnableSeDebugPrivilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME,
                                &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp),
                                     nullptr, nullptr);
    DWORD last = GetLastError();
    CloseHandle(token);
    return ok && last == ERROR_SUCCESS;
}

// Compute SHA-256 of a file on disk. 64 KiB window, no mapping — the
// dump can land north of 1 GiB and we don't want a reserved VA
// footprint for it.
static std::string FileSha256(const std::wstring& path, uint64_t* size_out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string out;
    uint64_t total = 0;
    DWORD hashLen = 0;
    DWORD cb = 0;
    DWORD propLen = sizeof(hashLen);

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                                          (PUCHAR)&hashLen, propLen,
                                          &cb, 0))) goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0,
                                          nullptr, 0, 0))) goto cleanup;
    {
        std::vector<uint8_t> buf(64 * 1024);
        for (;;) {
            DWORD rd = 0;
            if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr)) break;
            if (rd == 0) break;
            BCryptHashData(hash, buf.data(), rd, 0);
            total += rd;
        }
        std::vector<uint8_t> digest(hashLen);
        if (BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(),
                                             hashLen, 0))) {
            static const char kHex[] = "0123456789abcdef";
            out.resize((size_t)hashLen * 2);
            for (DWORD i = 0; i < hashLen; ++i) {
                out[i * 2]     = kHex[(digest[i] >> 4) & 0xF];
                out[i * 2 + 1] = kHex[digest[i] & 0xF];
            }
        }
    }

cleanup:
    if (hash) BCryptDestroyHash(hash);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(h);
    if (size_out) *size_out = total;
    return out;
}

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                 nullptr, 0);
    if (n <= 0) return {};
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                         out.data(), n);
    return out;
}

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                 nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                         out.data(), n, nullptr, nullptr);
    return out;
}

static std::wstring DefaultOutputPath()
{
    wchar_t sysroot[MAX_PATH]{};
    DWORD n = GetEnvironmentVariableW(L"SystemRoot", sysroot, MAX_PATH);
    if (!n || n >= MAX_PATH) {
        wcscpy_s(sysroot, L"C:\\Windows");
    }
    std::wstring base = std::wstring(sysroot) + L"\\LiveKernelDumps";
    CreateDirectoryW(base.c_str(), nullptr);
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    uint64_t unix_ms = (u.QuadPart - 116444736000000000ULL) / 10000ULL;
    wchar_t name[64]{};
    swprintf_s(name, L"\\pry_%llu.dmp",
                (unsigned long long)unix_ms);
    std::wstring full = base + name;

    DWORD attrs = GetFileAttributesW(base.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        // SystemRoot path isn't writable — fall back to %TEMP%\\pry\\dumps
        wchar_t temp[MAX_PATH]{};
        DWORD t = GetTempPathW(MAX_PATH, temp);
        if (t && t < MAX_PATH) {
            std::wstring fallback = std::wstring(temp) + L"pry\\dumps";
            CreateDirectoryW((std::wstring(temp) + L"pry").c_str(),
                              nullptr);
            CreateDirectoryW(fallback.c_str(), nullptr);
            full = fallback + name;
        }
    }
    return full;
}

struct FlagResolution {
    uint32_t sysdbg_flags = 0;
    uint32_t add_pages = 0;
    std::vector<std::string> unknown;
    bool stack_only = false;
};

static FlagResolution ResolveFlags(const LiveKernelDumpRequest& req)
{
    FlagResolution out{};
    for (const auto& fRaw : req.flags) {
        std::string f;
        f.reserve(fRaw.size());
        for (char c : fRaw) f.push_back((char)tolower((unsigned char)c));
        if (f == "compression") {
            out.sysdbg_flags |= SYSDBG_LIVEDUMP_FLAG_COMPRESS_MEMORY_PAGES_DATA;
        } else if (f == "usermode") {
            out.sysdbg_flags |= SYSDBG_LIVEDUMP_FLAG_USE_DUMP_STORAGE_STACK;
            out.add_pages |= SYSDBG_LIVEDUMP_FLAG_INCLUDE_USERSPACE_MEMORY_PAGES;
        } else if (f == "stack_only") {
            out.sysdbg_flags |= SYSDBG_LIVEDUMP_FLAG_SELECTIVE_DUMP;
            out.stack_only = true;
        } else if (f == "page_table_only") {
            out.sysdbg_flags |= SYSDBG_LIVEDUMP_FLAG_SELECTIVE_DUMP;
        } else if (f == "hypervisor_pages") {
            out.sysdbg_flags |= SYSDBG_LIVEDUMP_FLAG_SELECTIVE_DUMP;
        } else {
            out.unknown.push_back(fRaw);
        }
    }
    if (req.compression) {
        out.sysdbg_flags |= SYSDBG_LIVEDUMP_FLAG_COMPRESS_MEMORY_PAGES_DATA;
    }
    return out;
}

}  // namespace

void CreateLiveKernelDump(const LiveKernelDumpRequest& req,
                           LiveKernelDumpResponse* out)
{
    if (!out) return;
    *out = LiveKernelDumpResponse{};

    FlagResolution fl = ResolveFlags(req);
    out->flags_used_mask = fl.sysdbg_flags;
    out->flags_unknown = fl.unknown;

    NtSystemDebugControl_t fn = ResolveNtSystemDebugControl();
    if (!fn) {
        out->kind = "not_supported";
        out->error = "NtSystemDebugControl unresolved — pre-NT6 build?";
        out->error_detail = "ntdll!NtSystemDebugControl = nullptr";
        return;
    }

    if (!EnableSeDebugPrivilege()) {
        out->kind = "access_denied";
        out->error = "SeDebugPrivilege could not be enabled on the "
                      "umagent service token";
        out->error_detail = "AdjustTokenPrivileges(SE_DEBUG_NAME) failed";
        return;
    }

    std::wstring wpath = Utf8ToWide(req.output_path);
    if (wpath.empty()) {
        wpath = DefaultOutputPath();
    }
    out->path = WideToUtf8(wpath);

    HANDLE hFile = CreateFileW(wpath.c_str(),
                                GENERIC_WRITE,
                                FILE_SHARE_READ,
                                nullptr,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        out->kind = "io_failed";
        out->error = "CreateFileW failed";
        char buf[64]{};
        _snprintf_s(buf, _TRUNCATE, "GetLastError=%lu", err);
        out->error_detail = buf;
        return;
    }

    HANDLE hCancel = nullptr;
    if (req.allow_cancel) {
        hCancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }

    SYSDBG_LIVEDUMP_CONTROL_V1 ctrl{};
    ctrl.Version = 1;
    ctrl.DumpFileHandle = hFile;
    ctrl.CancelEventHandle = hCancel;
    ctrl.Flags = fl.sysdbg_flags;
    ctrl.AddPagesControl = fl.add_pages;

    ULONG returnLength = 0;
    NTSTATUS st = fn(kSysDbgGetLiveKernelDump,
                      &ctrl, sizeof(ctrl),
                      nullptr, 0, &returnLength);

    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    if (hCancel) CloseHandle(hCancel);

    if (!NT_SUCCESS(st)) {
        char buf[64]{};
        _snprintf_s(buf, _TRUNCATE, "0x%08X", (unsigned)st);
        out->error_detail = buf;
        if (st == (NTSTATUS)0xC0000022L /* STATUS_ACCESS_DENIED */
                || st == (NTSTATUS)0xC0000061L /* STATUS_PRIVILEGE_NOT_HELD */) {
            out->kind = "access_denied";
            out->error = "SysDbgGetLiveKernelDump refused: "
                          "SeDebugPrivilege / HVCI policy";
        } else if (st == (NTSTATUS)0xC00000BBL /* STATUS_NOT_SUPPORTED */
                     || st == (NTSTATUS)0xC000000DL /* STATUS_INVALID_PARAMETER */) {
            out->kind = "not_supported";
            out->error = "SysDbgGetLiveKernelDump not supported on this "
                          "build";
        } else {
            out->kind = "sysdbg_failed";
            out->error = "NtSystemDebugControl failed";
        }
        // Best-effort cleanup of the empty / partial file.
        DeleteFileW(wpath.c_str());
        out->path.clear();
        return;
    }

    uint64_t total = 0;
    out->sha256 = FileSha256(wpath, &total);
    out->size = total;
    out->ok = true;
}

}  // namespace um
