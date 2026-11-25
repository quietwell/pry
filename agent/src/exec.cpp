#include "exec.hpp"
#include "common.h"
#include "exec/cmdline_quote.hpp"

#include <array>
#include <atomic>
#include <cstring>
#include <thread>

namespace pry {

static std::wstring Quote(const std::wstring& s)
{
    std::wstring q = L"\"";
    q += s;
    q += L"\"";
    return q;
}

static bool Pipe(HANDLE* read, HANDLE* write)
{
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    return CreatePipe(read, write, &sa, 0) != 0;
}

// Per-stream capture cap. Beyond it the pipe keeps being drained (so the
// child never blocks on a full pipe) but the bytes are dropped and a
// marker is appended — a chatty child can no longer balloon agent memory
// or blow the 128 MiB gRPC message cap.
constexpr size_t kMaxCaptureBytes = 16u * 1024 * 1024;

static void AppendCapped(std::vector<BYTE>& out, const CHAR* buf, DWORD n, bool* truncated)
{
    if (out.size() >= kMaxCaptureBytes) {
        *truncated = true;
        return;
    }
    size_t room = kMaxCaptureBytes - out.size();
    size_t take = n < room ? (size_t)n : room;
    out.insert(out.end(), buf, buf + take);
    if (take < n) {
        *truncated = true;
    }
}

// Polls one pipe until the child exits (final drain), the deadline passes
// or the caller cancels; then kills the whole process tree via `kill`.
// stdout and stderr are drained concurrently (one thread each), so a child
// that fills one pipe while we wait on the other cannot deadlock.
static void Drain(HANDLE pipe, std::vector<BYTE>& out, HANDLE proc, DWORD timeoutMs,
                  std::atomic<bool>* timedOut, const std::function<void()>& kill,
                  const ExecMgr::CancelledFn& cancelled)
{
    ULONGLONG deadline = GetTickCount64() + (timeoutMs ? timeoutMs : 30000);
    CHAR buf[8192];
    DWORD n = 0;
    bool truncated = false;
    auto kill_child = [&]() {
        timedOut->store(true);
        kill();
        WaitForSingleObject(proc, 5000);
    };
    for (;;) {
        // v14: the orchestrator's wire deadline fires before our side's
        // timeout — without this the poller keeps burning until timeoutMs
        // even though the caller is gone.
        if ((cancelled && cancelled()) || timedOut->load()) {
            kill_child();
            break;
        }
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &n, nullptr)) {
            break;
        }
        if (n > 0) {
            if (ReadFile(pipe, buf, sizeof(buf), &n, nullptr) && n) {
                AppendCapped(out, buf, n, &truncated);
            } else {
                break;
            }
        } else {
            if (WaitForSingleObject(proc, 50) == WAIT_OBJECT_0) {
                // final drain
                while (PeekNamedPipe(pipe, nullptr, 0, nullptr, &n, nullptr) && n) {
                    if (ReadFile(pipe, buf, sizeof(buf), &n, nullptr) && n) {
                        AppendCapped(out, buf, n, &truncated);
                    } else {
                        break;
                    }
                }
                break;
            }
            if (GetTickCount64() > deadline) {
                kill_child();
                break;
            }
        }
    }
    if (truncated) {
        static const char kNote[] = "\n[pry: output truncated at 16 MiB]\n";
        out.insert(out.end(), kNote, kNote + sizeof(kNote) - 1);
    }
}

// T2.2 (PR#1): strip the trailing `#< CLIXML\n<Objs ...>...</Objs>` block
// that PowerShell appends to stderr (and to stdout under
// -OutputFormat Text) when the host isn't a PS host. The block is the
// outermost `<Objs` element serialized as PSObjects; even an empty one is
// a 150-byte constant that noises every exec call. We scan from the end
// of the buffer for the `#< CLIXML` sentinel and trim from there — safer
// than regex, cheap, no third-party deps.
static void StripTrailingClixml(std::vector<BYTE>& buf)
{
    if (buf.size() < 10) return;
    static const unsigned char kMark[] = "#< CLIXML";
    constexpr size_t kMarkLen = sizeof(kMark) - 1;
    // Scan the last 32 KiB for the marker — CLIXML is ALWAYS at the tail
    // for native-shell callers; bounding the search keeps giant stdout
    // sweeps cheap.
    size_t search_floor = buf.size() > (32 * 1024)
        ? (buf.size() - (32 * 1024)) : 0;
    for (size_t i = buf.size() - kMarkLen; i + kMarkLen <= buf.size();
         --i) {
        if (buf[i] == kMark[0] &&
            std::memcmp(&buf[i], kMark, kMarkLen) == 0) {
            // Trim from the newline that precedes `#< CLIXML` (if any)
            // so an upstream caller doesn't see a dangling blank line.
            size_t cut = i;
            while (cut > 0 &&
                   (buf[cut - 1] == '\r' || buf[cut - 1] == '\n')) {
                --cut;
            }
            buf.resize(cut);
            return;
        }
        if (i == search_floor) break;
    }
}

RunResult RunCommandLine(const std::wstring& cmdLine, const std::wstring& workDir,
                         DWORD timeoutMs, const ExecMgr::CancelledFn& cancelled)
{
    RunResult res;
    HANDLE outR = nullptr, outW = nullptr, errR = nullptr, errW = nullptr;
    if (!Pipe(&outR, &outW) || !Pipe(&errR, &errW)) {
        res.error = Win32ErrorString("CreatePipe", GetLastError());
        if (outR) CloseHandle(outR);
        if (outW) CloseHandle(outW);
        return res;
    }
    // Keep the parent's read ends out of the child.
    SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errR, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = outW;
    si.hStdError = errW;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmd(cmdLine.begin(), cmdLine.end());
    cmd.push_back(L'\0');
    // Job object so a timeout/cancel kills the whole tree (a `cmd /c` or
    // installer child used to survive its parent's TerminateProcess and
    // keep the pipes open). No KILL_ON_JOB_CLOSE: descendants of a run
    // that completes normally keep running exactly as before.
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi)) {
        res.error = Win32ErrorString("CreateProcess", GetLastError());
        CloseHandle(outR);
        CloseHandle(outW);
        CloseHandle(errR);
        CloseHandle(errW);
        if (job) CloseHandle(job);
        return res;
    }
    const bool inJob = job && AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(outW);
    CloseHandle(errW);
    std::atomic<bool> timedOut{false};
    std::function<void()> kill = [&]() {
        if (inJob) {
            TerminateJobObject(job, 1);
        } else {
            TerminateProcess(pi.hProcess, 1);
        }
    };
    std::thread drainOut(Drain, outR, std::ref(res.out), pi.hProcess, timeoutMs, &timedOut,
                         std::cref(kill), std::cref(cancelled));
    Drain(errR, res.err, pi.hProcess, timeoutMs, &timedOut, kill, cancelled);
    drainOut.join();
    if (timedOut.load()) {
        res.timedOut = true;
    }
    GetExitCodeProcess(pi.hProcess, &res.exitCode);
    CloseHandle(outR);
    CloseHandle(errR);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (job) CloseHandle(job);
    return res;
}

static RunResult RunProcess(const std::wstring& cmdLine, const std::wstring& workDir,
                            DWORD timeoutMs, const ExecMgr::CancelledFn& cancelled)
{
    return RunCommandLine(cmdLine, workDir, timeoutMs, cancelled);
}

RunResult ExecMgr::RunExe(const std::wstring& exe, const std::vector<std::wstring>& args,
                       const std::wstring& workDir, DWORD timeoutMs,
                       const CancelledFn& cancelled)
{
    // argv[0] only wraps (no escape processing applies to it); every other
    // argument follows the CommandLineToArgvW rules so embedded quotes and
    // trailing backslashes survive (`"C:\dir\"` used to swallow the quote).
    std::wstring cmd = QuoteExe(exe);
    for (auto& a : args) {
        cmd += L" ";
        cmd += QuoteArg(a);
    }
    return RunProcess(cmd, workDir, timeoutMs, cancelled);
}

RunResult ExecMgr::RunShell(bool powershell, const std::string& command,
                         const std::wstring& workDir, DWORD timeoutMs,
                         const CancelledFn& cancelled)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
    std::wstring cmd(n ? n - 1 : 0, L'\0');
    if (n) {
        MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, cmd.data(), n);
    }
    std::wstring full;
    if (powershell) {
        // force UTF-8 output encoding before the user's
        // command so stdout survives the Windows codepage ride without
        // becoming `â†’` noise. Separator is `;` so the user's command
        // text is appended verbatim.
        // T2.2 (PR#1): also silence the progress stream (which spills
        // to stderr as CLIXML) and keep -ErrorActionPreference=Continue
        // so a broken sub-call doesn't tear down the whole script.
        std::wstring body =
            L"$ProgressPreference='SilentlyContinue'; "
            L"$ErrorActionPreference='Continue'; "
            L"[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd;
        full = L"powershell.exe -NoProfile -NonInteractive -Command " + Quote(body);
    } else {
        full = L"cmd.exe /c " + Quote(cmd);
    }
    RunResult res = RunProcess(full, workDir, timeoutMs, cancelled);
    if (powershell) {
        // T2.2: strip the trailing `#< CLIXML\n<Objs ...>...</Objs>` block
        // from stderr (and, with -OutputFormat Text, from stdout). Only
        // trims if the marker is actually present — never corrupts output.
        StripTrailingClixml(res.err);
        StripTrailingClixml(res.out);
    }
    return res;
}

// PowerShell -EncodedCommand path.
RunResult ExecMgr::RunShellEncoded(const std::string& encoded_b64,
                                   const std::wstring& workDir,
                                   DWORD timeoutMs,
                                   const CancelledFn& cancelled)
{
    // base64 is pure ASCII, so a plain narrow→wide copy is enough.
    std::wstring w;
    w.reserve(encoded_b64.size());
    for (char c : encoded_b64) {
        w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    std::wstring full = L"powershell.exe -NoProfile -NonInteractive "
                        L"-OutputFormat Text -EncodedCommand " + w;
    RunResult res = RunProcess(full, workDir, timeoutMs, cancelled);
    // T2.2 (PR#1): the orchestrator-side agent_client/exec.py inlines a
    // SilentlyContinue preamble into the base64 payload itself; this
    // call still trims the CLIXML sentinel in case the body itself emits
    // one (progress preferences inside a sub-shell, legacy orchestrators
    // that pre-date the inlined preamble, etc.).
    StripTrailingClixml(res.err);
    StripTrailingClixml(res.out);
    return res;
}

uint32_t ExecMgr::StartShell(bool powershell, const std::wstring& workDir, std::string* err)
{
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE inR = nullptr, inW = nullptr, outR = nullptr, outW = nullptr;
    if (!Pipe(&inR, &inW) || !Pipe(&outR, &outW)) {
        *err = Win32ErrorString("CreatePipe", GetLastError());
        return 0;
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = inR;
    si.hStdOutput = outW;
    si.hStdError = outW;
    PROCESS_INFORMATION pi{};
    std::wstring cmd = powershell ? L"powershell.exe -NoProfile -NoLogo" : L"cmd.exe";
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi)) {
        *err = Win32ErrorString("CreateProcess(shell)", GetLastError());
        CloseHandle(inR);
        CloseHandle(inW);
        CloseHandle(outR);
        CloseHandle(outW);
        return 0;
    }
    CloseHandle(inR);
    CloseHandle(outW);

    auto sh = std::make_shared<Shell>();
    sh->proc = pi.hProcess;
    sh->inWrite = inW;
    sh->outRead = outR;
    sh->queue = std::make_shared<EventQueue<std::vector<BYTE>>>();
    CloseHandle(pi.hThread);

    std::lock_guard<std::mutex> lk(m_);
    uint32_t id = nextShellId_++;
    shells_[id] = sh;
    std::thread(ShellReaderThread, sh, id).detach();
    return id;
}

void ShellReaderThread(std::shared_ptr<ExecMgr::Shell> shell, uint32_t id)
{
    CHAR buf[8192];
    DWORD n = 0;
    for (;;) {
        if (!PeekNamedPipe(shell->outRead, nullptr, 0, nullptr, &n, nullptr)) {
            break;
        }
        if (n == 0) {
            if (WaitForSingleObject(shell->proc, 100) == WAIT_OBJECT_0) {
                break;
            }
            continue;
        }
        if (!ReadFile(shell->outRead, buf, sizeof(buf), &n, nullptr) || !n) {
            break;
        }
        shell->queue->Push(std::vector<BYTE>(buf, buf + n));
    }
    shell->queue->Push({}); // eof marker
}

bool ExecMgr::WriteShell(uint32_t id, const std::string& data, std::string* err)
{
    std::shared_ptr<Shell> sh;
    {
        std::lock_guard<std::mutex> lk(m_);
        auto it = shells_.find(id);
        if (it == shells_.end()) {
            *err = "no such shell session";
            return false;
        }
        sh = it->second;
    }
    DWORD w = 0;
    if (!WriteFile(sh->inWrite, data.data(), (DWORD)data.size(), &w, nullptr)) {
        *err = Win32ErrorString("WriteFile(shell)", GetLastError());
        return false;
    }
    return true;
}

bool ExecMgr::StopShell(uint32_t id, std::string* err)
{
    std::shared_ptr<Shell> sh;
    {
        std::lock_guard<std::mutex> lk(m_);
        auto it = shells_.find(id);
        if (it == shells_.end()) {
            *err = "no such shell session";
            return false;
        }
        sh = it->second;
        shells_.erase(it);
    }
    // handles close when the last shared_ptr (ours + reader thread) drops;
    // terminating first makes the reader thread exit its pipe loop
    TerminateProcess(sh->proc, 1);
    return true;
}

std::shared_ptr<ExecMgr::Shell> ExecMgr::GetShell(uint32_t id)
{
    std::lock_guard<std::mutex> lk(m_);
    auto it = shells_.find(id);
    return it == shells_.end() ? nullptr : it->second;
}

std::vector<uint32_t> ExecMgr::ShellIds()
{
    std::vector<uint32_t> ids;
    std::lock_guard<std::mutex> lk(m_);
    ids.reserve(shells_.size());
    for (auto& kv : shells_) {
        ids.push_back(kv.first);
    }
    return ids;
}

// ---- process suspend/resume (NtSuspendProcess / NtResumeProcess) ----

using NtSuspendResumeFn = LONG(WINAPI*)(HANDLE);

std::string ExecMgr::Suspend(uint32_t pid)
{
    if (pid == GetCurrentProcessId()) {
        return "refusing to suspend the agent itself";
    }
    static NtSuspendResumeFn ntSuspend = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (NtSuspendResumeFn)GetProcAddress(ntdll, "NtSuspendProcess") : nullptr;
    }();
    if (!ntSuspend) {
        return "NtSuspendProcess unavailable";
    }
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) {
        return Win32ErrorString("OpenProcess(PROCESS_SUSPEND_RESUME)", GetLastError());
    }
    LONG st = ntSuspend(h);
    CloseHandle(h);
    return st == 0 ? "" : ("NtSuspendProcess failed nt=0x" + std::to_string((UINT32)st));
}

std::string ExecMgr::Resume(uint32_t pid)
{
    if (pid == GetCurrentProcessId()) {
        return "refusing to resume the agent itself (it is not suspended)";
    }
    static NtSuspendResumeFn ntResume = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (NtSuspendResumeFn)GetProcAddress(ntdll, "NtResumeProcess") : nullptr;
    }();
    if (!ntResume) {
        return "NtResumeProcess unavailable";
    }
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) {
        return Win32ErrorString("OpenProcess(PROCESS_SUSPEND_RESUME)", GetLastError());
    }
    LONG st = ntResume(h);
    CloseHandle(h);
    return st == 0 ? "" : ("NtResumeProcess failed nt=0x" + std::to_string((UINT32)st));
}

} // namespace pry
