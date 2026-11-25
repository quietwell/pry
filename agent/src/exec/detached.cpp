#include "detached.hpp"

#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <map>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

namespace pry {

static std::wstring MakeHexId()
{
    UCHAR buf[12] = {};
    BCryptGenRandom(nullptr, buf, sizeof(buf),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wchar_t hex[25] = {};
    for (int i = 0; i < 12; ++i) {
        static const wchar_t* nib = L"0123456789abcdef";
        hex[i * 2] = nib[(buf[i] >> 4) & 0xF];
        hex[i * 2 + 1] = nib[buf[i] & 0xF];
    }
    hex[24] = 0;
    return std::wstring(hex);
}

static uint64_t NowMs()
{
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

static std::wstring ProgramDataDir()
{
    wchar_t buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr,
                                    SHGFP_TYPE_CURRENT, buf))) {
        return std::wstring(buf) + L"\\pry\\detached";
    }
    return std::wstring(L"C:\\ProgramData\\pry\\detached");
}

static bool EnsureDir(const std::wstring& p)
{
    if (CreateDirectoryW(p.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool EnsureDirRecursive(const std::wstring& p)
{
    for (size_t i = 0; i < p.size(); ++i) {
        if (p[i] == L'\\' && i > 3) {
            std::wstring parent = p.substr(0, i);
            EnsureDir(parent);
        }
    }
    return EnsureDir(p);
}

// build a double-null-terminated wide env block from the agent's
// own environment merged with `extras`. Returns an empty vector when
// `extras` is empty (caller then passes nullptr, which inherits unchanged).
// Case-insensitive on the variable name per Win32 convention, so a caller
// setting PYTHONUNBUFFERED replaces the inherited value rather than
// producing two entries.
static std::vector<wchar_t> BuildEnvBlock(
    const std::map<std::wstring, std::wstring>& extras)
{
    std::vector<wchar_t> out;
    if (extras.empty()) return out;

    auto ieq = [](wchar_t a, wchar_t b) {
        return std::towupper(a) == std::towupper(b);
    };
    std::map<std::wstring, std::wstring> extras_u;
    for (auto& kv : extras) {
        std::wstring up;
        up.reserve(kv.first.size());
        for (wchar_t c : kv.first) up.push_back(std::towupper(c));
        extras_u[up] = kv.second;
    }

    LPWCH envs = GetEnvironmentStringsW();
    if (envs) {
        for (LPWCH p = envs; *p; p += wcslen(p) + 1) {
            std::wstring entry = p;
            auto eq = entry.find(L'=');
            if (eq == std::wstring::npos) {
                for (wchar_t c : entry) out.push_back(c);
                out.push_back(L'\0');
                continue;
            }
            std::wstring name = entry.substr(0, eq);
            std::wstring up;
            up.reserve(name.size());
            for (wchar_t c : name) up.push_back(std::towupper(c));
            if (extras_u.count(up)) continue; // caller overrides
            for (wchar_t c : entry) out.push_back(c);
            out.push_back(L'\0');
        }
        FreeEnvironmentStringsW(envs);
    }
    for (auto& kv : extras) {
        for (wchar_t c : kv.first) out.push_back(c);
        out.push_back(L'=');
        for (wchar_t c : kv.second) out.push_back(c);
        out.push_back(L'\0');
    }
    out.push_back(L'\0');
    (void)ieq; // reserved for a stricter dedup if we ever drop the uppercase map
    return out;
}

std::shared_ptr<DetachedHandle> DetachedRegistry::Spawn(
    const std::wstring& cmdline, const std::wstring& workdir,
    const std::wstring& stdout_path, const std::wstring& stderr_path,
    bool hidden_window, std::string* err)
{
    return Spawn(cmdline, workdir, stdout_path, stderr_path, hidden_window,
                 std::map<std::wstring, std::wstring>{}, err);
}

std::shared_ptr<DetachedHandle> DetachedRegistry::Spawn(
    const std::wstring& cmdline, const std::wstring& workdir,
    const std::wstring& stdout_path, const std::wstring& stderr_path,
    bool hidden_window,
    const std::map<std::wstring, std::wstring>& extra_env,
    std::string* err)
{
    auto h = std::make_shared<DetachedHandle>();
    std::wstring wid = MakeHexId();
    h->id.reserve(wid.size());
    for (wchar_t c : wid) {
        h->id.push_back(static_cast<char>(c)); // hex id, ASCII-only by construction
    }

    std::wstring root = ProgramDataDir();
    EnsureDirRecursive(root);
    std::wstring instance_dir = root + L"\\" + wid;
    EnsureDirRecursive(instance_dir);

    h->stdout_path = stdout_path.empty() ? (instance_dir + L"\\stdout.log")
                                          : stdout_path;
    h->stderr_path = stderr_path.empty() ? (instance_dir + L"\\stderr.log")
                                          : stderr_path;

    // Open logs with FILE_SHARE_READ|WRITE|DELETE so LogTail can read
    // them concurrently. Truncate to prevent stale content bleeding into
    // a re-used path.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hout = CreateFileW(h->stdout_path.c_str(), GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    HANDLE herr = CreateFileW(h->stderr_path.c_str(), GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hout == INVALID_HANDLE_VALUE || herr == INVALID_HANDLE_VALUE) {
        if (err) {
            char msg[128];
            _snprintf_s(msg, _TRUNCATE,
                        "CreateFileW logs failed gle=%lu", GetLastError());
            *err = msg;
        }
        if (hout != INVALID_HANDLE_VALUE) CloseHandle(hout);
        if (herr != INVALID_HANDLE_VALUE) CloseHandle(herr);
        return nullptr;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hout;
    si.hStdError = herr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = hidden_window ? SW_HIDE : SW_SHOWDEFAULT;

    PROCESS_INFORMATION pi{};
    // Mutable command line buffer for CreateProcessW.
    std::wstring cmd_mut = cmdline;
    DWORD flags = CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT;
    if (hidden_window) flags |= CREATE_NO_WINDOW;

    // merge agent env with caller extras when provided; nullptr
    // inherits the agent's own environment as before.
    std::vector<wchar_t> env_block = BuildEnvBlock(extra_env);
    LPVOID env_ptr = env_block.empty() ? nullptr : env_block.data();

    BOOL ok = CreateProcessW(nullptr, cmd_mut.data(), nullptr, nullptr,
                              TRUE, flags, env_ptr,
                              workdir.empty() ? nullptr : workdir.c_str(),
                              &si, &pi);
    CloseHandle(hout);
    CloseHandle(herr);
    if (!ok) {
        if (err) {
            char msg[128];
            _snprintf_s(msg, _TRUNCATE,
                        "CreateProcessW failed gle=%lu", GetLastError());
            *err = msg;
        }
        return nullptr;
    }
    h->pid = pi.dwProcessId;
    h->process = pi.hProcess;
    h->thread = pi.hThread;
    h->started_ts = NowMs();

    {
        std::lock_guard<std::mutex> lock(m_);
        map_[h->id] = h;
    }
    return h;
}

std::shared_ptr<DetachedHandle> DetachedRegistry::Get(const std::string& id)
{
    std::lock_guard<std::mutex> lock(m_);
    auto it = map_.find(id);
    return it == map_.end() ? nullptr : it->second;
}

bool DetachedRegistry::Kill(const std::string& id, std::string* err)
{
    std::shared_ptr<DetachedHandle> h;
    {
        std::lock_guard<std::mutex> lock(m_);
        auto it = map_.find(id);
        if (it == map_.end()) {
            if (err) *err = "detached: unknown handle_id";
            return false;
        }
        h = it->second;
    }
    if (!h->running) return true;
    // CTRL_BREAK first — reaches only our new process group — then a hard
    // kill after a short grace period.
    GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, h->pid);
    if (WaitForSingleObject(h->process, 250) != WAIT_OBJECT_0) {
        TerminateProcess(h->process, 0xDEADBEEF);
        WaitForSingleObject(h->process, 500);
    }
    Poll(h);
    return true;
}

void DetachedRegistry::Poll(const std::shared_ptr<DetachedHandle>& h)
{
    if (!h || !h->running) return;
    DWORD code = 0;
    if (GetExitCodeProcess(h->process, &code) && code != STILL_ACTIVE) {
        h->exit_code = code;
        h->exited_ts = NowMs();
        h->running = false;
    }
}

} // namespace pry
