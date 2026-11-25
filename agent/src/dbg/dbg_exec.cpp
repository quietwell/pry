#include "dbg_session.hpp"
#include "../common.h"

#include <dbgeng.h>
#include <objbase.h>

#include <sys/stat.h>

namespace pry {

template <typename T>
static T* As(void** pp)
{
    return reinterpret_cast<T*>(*pp);
}

// raw dbgeng command passthrough: captures engine output through an
// IDebugOutputCallbacksWide sink while the command executes
class DbgOutputSink : public IDebugOutputCallbacksWide {
public:
    STDMETHODIMP QueryInterface(REFIID riid, PVOID* obj) override
    {
        if (!obj) {
            return E_INVALIDARG;
        }
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IDebugOutputCallbacksWide)) {
            *obj = this;
            AddRef();
            return S_OK;
        }
        *obj = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refs_); }
    STDMETHODIMP_(ULONG) Release() override { return InterlockedDecrement(&refs_); }
    STDMETHODIMP Output(ULONG mask, PCWSTR text) override
    {
        UNREFERENCED_PARAMETER(mask);
        std::lock_guard<std::mutex> lk(bufM_);
        if (text) {
            buf_ += text;
            if (buf_.size() > 4 * 1024 * 1024) { // 8MB of UTF-16 max
                buf_.resize(4 * 1024 * 1024);
            }
        }
        return S_OK;
    }
    std::wstring Take()
    {
        std::lock_guard<std::mutex> lk(bufM_);
        return std::move(buf_);
    }

private:
    LONG refs_ = 1;
    std::mutex bufM_;
    std::wstring buf_;
};

// legacy forwarder. New callers pass a StopInfoRec* and get the
// post-command state echo; old callers get the plain output-only shape.
std::string DbgSession::Execute(const std::string& command, std::string* output)
{
    return Execute(command, output, nullptr);
}

std::string DbgSession::Execute(const std::string& command, std::string* output, StopInfoRec* state)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        if (state) {
            FillStopInfoLocked(state, "process_exit");
        }
        return "no active session";
    }
    // dbgeng's IDebugControl::Execute() silently accepts commands
    // while the target is running but produces no output through the
    // registered callbacks — the caller sees ok=true with an empty
    // buffer and no way to tell the command actually ran or was
    // discarded. Reject the call explicitly so the caller knows to
    // break first (or Continue only when done with commands).
    auto client = As<IDebugClient5>(&client5_);
    auto control = As<IDebugControl3>(&control3_);
    bool interruptedForCmd = false;
    if (!stopped_) {
        if (!monitor_) {
            if (state) {
                FillStopInfoLocked(state, lastStop_.stop_reason.empty() ? "none"
                                                                        : lastStop_.stop_reason);
            }
            return "target is running (dbgeng discards output on running "
                   "targets; break the target first or issue commands "
                   "between stops)";
        }
        // monitor mode: the debugee runs continuously, so commands that
        // need a stopped state (ba, etc.) do an interrupt → cmd → resume
        // cycle — passive observation must never park the target.
        if (std::string err = EnsureStopped(5000); !err.empty()) {
            if (state) {
                FillStopInfoLocked(state, "none");
            }
            return err;
        }
        interruptedForCmd = true;
    }
    if (command.empty()) {
        if (state) {
            *state = lastStop_;
        }
        return "empty command";
    }
    // IDebugControl3::Execute takes an ANSI command string
    std::string narrow = command;

    static DbgOutputSink sink; // shared: only one command executes at a time (m_)
    sink.Take(); // clear previous output
    if (FAILED(client->SetOutputCallbacksWide(&sink))) {
        if (state) {
            FillStopInfoLocked(state, "none");
        }
        return "SetOutputCallbacksWide failed";
    }
    // capture the pre-call execution status so we can tell
    // state-mutating commands (`g`, `gh`, `t`, `p`, `.detach`, `q`) apart
    // from informational ones (`r`, `k`, `bl`). dbgeng updates the status
    // asynchronously inside Execute; a post-call query reflects whatever
    // the command drove the engine to.
    ULONG preStatus = 0;
    control->GetExecutionStatus(&preStatus);

    // IDebugControl::Execute(OutputControl, Command, Flags) — the first
    // slot is the OutCtl mask that steers output to our sink, not a
    // DEBUG_EXECUTE_* flag. DEBUG_EXECUTE_NOT_LOGGED (0x2) happens to
    // alias DEBUG_OUTCTL_ALL_OTHER_CLIENTS, so a swap routed every byte
    // of dbgeng output to the (nonexistent) "all other clients" sink
    // and ours captured nothing. Hence `bp`/`bl`/`r` returning empty
    // strings and `t` tripping an engine-state HRESULT. Keep output on
    // THIS_CLIENT and move the no-log flag to its real slot.
    HRESULT hr = control->Execute(DEBUG_OUTCTL_THIS_CLIENT, narrow.c_str(),
                                  DEBUG_EXECUTE_NOT_LOGGED);
    client->SetOutputCallbacksWide(nullptr); // restore before touching sink

    // B8: re-read the engine status and reconcile flags. The command may
    // have:
    //   - parked at a break      → newStatus == DEBUG_STATUS_BREAK, stopped_=true
    //   - requested a go         → stopped_=false (dbgeng hasn't resumed
    //                              yet; the engine loop's idle pump picks
    //                              it up)
    //   - ended the session      → .detach / q / qd set newStatus to one of
    //                              DEBUG_STATUS_*_SESSION; Active=false and
    //                              the engine thread's next pass EndSessions.
    // A command that's "state-changing" surfaces through lastStop_ via a
    // FillStopInfoLocked below so the gRPC echo carries an honest snapshot.
    ULONG newStatus = 0;
    control->GetExecutionStatus(&newStatus);
    const bool preRunning = (preStatus == DEBUG_STATUS_GO
                             || preStatus == DEBUG_STATUS_GO_HANDLED
                             || preStatus == DEBUG_STATUS_GO_NOT_HANDLED
                             || preStatus == DEBUG_STATUS_STEP_OVER
                             || preStatus == DEBUG_STATUS_STEP_INTO
                             || preStatus == DEBUG_STATUS_STEP_BRANCH);
    const bool nowBreak = (newStatus == DEBUG_STATUS_BREAK);
    const bool nowDead = (newStatus == DEBUG_STATUS_NO_DEBUGGEE);
    const bool stateChanged = (nowBreak != stopped_) || (nowDead && active_);
    if (nowBreak) {
        stopped_ = true;
    } else {
        // !BREAK: either running (the pump will observe the stop event) or
        // session ended. Either way, we're not currently parked.
        stopped_ = false;
    }
    if (nowDead) {
        active_ = false;
    }
    if (stateChanged && active_) {
        // "cmd" synthesises a lastStop_ snapshot so Status/Wait callers
        // observe the transition even without an event landing.
        StopInfoRec cmdStop;
        FillStopInfoLocked(&cmdStop, "cmd");
        PublishStop(std::move(cmdStop));
    } else if (nowDead) {
        // session ended by the command — reflect that in the cached snapshot
        // (preserve the pre-exit rip/symbol; just mark active=false).
        StopInfoRec dead = lastStop_; // engine thread: lock-free read is ok
        dead.active = false;
        dead.stopped = false;
        dead.stop_reason = "process_exit";
        PublishStop(std::move(dead));
    }
    (void)preRunning; // retained for future heuristics; keeps the lint quiet

    if (FAILED(hr)) {
        if (state) {
            if (active_) {
                *state = lastStop_;
            } else {
                FillStopInfoLocked(state, "process_exit");
            }
        }
        return "Execute failed hr=" + std::to_string(hr);
    }
    std::wstring out = sink.Take();
    int n = WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), nullptr, 0, nullptr, nullptr);
    output->assign(n ? n : 0, '\0');
    if (n) {
        WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), output->data(), n, nullptr, nullptr);
    }
    if (interruptedForCmd) {
        ResumeAfterInterrupt(); // resume the target we broke for the command
    }
    if (state) {
        if (!active_) {
            FillStopInfoLocked(state, "process_exit");
        } else if (stopped_) {
            *state = lastStop_;
        } else {
            FillStopInfoLocked(state, "none");
        }
    }
    return "";
    });
}

// DumpTo — write a user-mode dump of the attached target via
// IDebugClient5::WriteDumpFileWide. `kind` picks the dump profile:
//   "mini" (default) → DEBUG_DUMP_SMALL
//   "full"           → DEBUG_DUMP_DEFAULT (full mini-dump with memory)
// On success stats the output path for `*bytes` so the caller doesn't have
// to round-trip for size. A pre-existing file at `path` is overwritten by
// dbgeng per its documented behaviour.
std::string DbgSession::DumpTo(const std::string& path, const std::string& kind, UINT64* bytes)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            return "no active session";
        }
        if (path.empty()) {
            return "empty path";
        }
        auto client = As<IDebugClient5>(&client5_);
        ULONG qualifier = DEBUG_DUMP_SMALL;
        if (kind == "full") {
            qualifier = DEBUG_DUMP_DEFAULT;
        } else if (!kind.empty() && kind != "mini") {
            return "unknown dump kind (use \"mini\" or \"full\")";
        }
        // Convert path to wide; dbgeng's narrow variant is lossy for non-
        // ASCII paths and 24H2+ writes it anyway.
        int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), nullptr, 0);
        if (wlen <= 0) {
            return "invalid path encoding";
        }
        std::wstring wpath((size_t)wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), (int)path.size(), wpath.data(), wlen);
        HRESULT hr = client->WriteDumpFileWide(wpath.c_str(), 0, qualifier,
                                               DEBUG_FORMAT_DEFAULT, nullptr);
        if (FAILED(hr)) {
            return "WriteDumpFileWide failed hr=" + std::to_string(hr);
        }
        if (bytes) {
            struct __stat64 st{};
            if (_wstat64(wpath.c_str(), &st) == 0) {
                *bytes = (UINT64)st.st_size;
            }
        }
        return "";
    });
}

// SetExceptionFilter — program the dbgeng exception filter table
// for `code` (NTSTATUS) with the caller's chosen policy. Mapping:
//   "break"          → first-chance break, go-handled on continue
//   "ignore"         → neither break; go-handled on continue (debugger
//                      swallows; app's SEH never sees it)
//   "second_chance"  → do not break first chance, but break on second
//                      chance; go-not-handled on continue so the OS
//                      re-dispatches through SEH
// Any other value returns "unknown action". The entry's TextSize/Command
// fields are left at engine defaults.
std::string DbgSession::SetExceptionFilter(UINT32 code, const std::string& action)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            return "no active session";
        }
        auto control = As<IDebugControl3>(&control3_);
        DEBUG_EXCEPTION_FILTER_PARAMETERS param{};
        param.ExceptionCode = code;
        if (action == "break") {
            param.ExecutionOption = DEBUG_FILTER_BREAK;
            param.ContinueOption = DEBUG_FILTER_GO_HANDLED;
        } else if (action == "ignore") {
            param.ExecutionOption = DEBUG_FILTER_IGNORE;
            param.ContinueOption = DEBUG_FILTER_GO_HANDLED;
        } else if (action == "second_chance") {
            param.ExecutionOption = DEBUG_FILTER_SECOND_CHANCE_BREAK;
            param.ContinueOption = DEBUG_FILTER_GO_NOT_HANDLED;
        } else {
            return "unknown action (use \"break\" | \"ignore\" | \"second_chance\")";
        }
        HRESULT hr = control->SetExceptionFilterParameters(1, &param);
        if (FAILED(hr)) {
            return "SetExceptionFilterParameters failed hr=" + std::to_string(hr);
        }
        return "";
    });
}

} // namespace pry
