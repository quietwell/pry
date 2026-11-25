#include "dbg_session.hpp"
#include "../common.h"

#include <dbgeng.h>
#include <objbase.h>

#include <chrono>

namespace pry {

template <typename T>
static T* As(void** pp)
{
    return reinterpret_cast<T*>(*pp);
}

// 5-arg forwarder for source compat (existing services_debug.cpp
// still calls this shape). monitor=false mirrors the earlier default.
std::string DbgSession::Launch(const std::string& cmdline, const std::string& workDir,
                               bool breakOnEntry, UINT32* pid, UINT32* tid)
{
    return Launch(cmdline, workDir, breakOnEntry, false, pid, tid);
}

std::string DbgSession::Launch(const std::string& cmdline, const std::string& workDir,
                               bool breakOnEntry, bool monitor, UINT32* pid, UINT32* tid)
{
    return RunOnEngine([&]() -> std::string {
        std::string err = InitEngine();
        if (!err.empty()) {
            return err;
        }
        auto client = As<IDebugClient5>(&client5_);
        auto control = As<IDebugControl3>(&control3_);
        auto sys = As<IDebugSystemObjects4>(&sysObj4_);
        if (active_) {
            return "debug session already active; detach first";
        }
        // B6 fix: break_on_entry leaked across launches. AddEngineOptions is
        // additive — once set, DEBUG_ENGOPT_INITIAL_BREAK stayed on for every
        // subsequent Launch unless something explicitly cleared it. Use an
        // explicit get/mask/set pair so break_on_entry=false actually clears
        // the option.
        ULONG opts = 0;
        control->GetEngineOptions(&opts);
        if (breakOnEntry) opts |= DEBUG_ENGOPT_INITIAL_BREAK;
        else              opts &= ~DEBUG_ENGOPT_INITIAL_BREAK;
        control->SetEngineOptions(opts);
        std::vector<char> mutableCmd(cmdline.begin(), cmdline.end());
        mutableCmd.push_back('\0');
        DEBUG_CREATE_PROCESS_OPTIONS copts{};
        copts.CreateFlags = DEBUG_ONLY_THIS_PROCESS;
        HRESULT hr = client->CreateProcess2(0, mutableCmd.data(), &copts, sizeof(copts),
                                            workDir.empty() ? nullptr : workDir.c_str(), nullptr);
        if (FAILED(hr)) {
            return "CreateProcess2 failed hr=" + std::to_string(hr) + " (cmd: " + cmdline + ")";
        }
        hr = control->WaitForEvent(0, 15000);
        if (hr != S_OK) {
            client->EndSession(DEBUG_SESSION_END);
            return "no initial debug event hr=" + std::to_string(hr);
        }
        ULONG sysPid = 0, sysTid = 0;
        sys->GetCurrentProcessSystemId(&sysPid);
        sys->GetCurrentThreadSystemId(&sysTid);
        pid_ = sysPid;
        active_ = true;
        stopped_ = true;
        monitor_ = monitor;
        *pid = sysPid;
        *tid = sysTid;
        seq_++;
        events_.Push({++seq_, "session_status", pid_, sysTid, 0, 0, "launched: " + cmdline,
                      NowUnix(), false, 0, 0});
        // seed lastStop_ so Status() answers meaningfully before any
        // subsequent event lands. "launch" is the canonical initial reason.
        { StopInfoRec s0; FillStopInfoLocked(&s0, "launch"); PublishStop(std::move(s0)); }
        if (monitor_) {
            // monitor-mode launch: do not park at the initial-break int3 —
            // auto-resume so the event ring starts streaming right away.
            // The initial event is dbgeng's INITIAL_BREAK int3; it MUST be
            // resumed with GO_HANDLED (same reason Continue uses it: a plain
            // GO re-dispatches the int3 exception into the target's SEH
            // chain and the target never actually leaves the break, so no
            // later EXIT_PROCESS event ever reaches WaitForEvent). Attach's
            // monitor path at line ~147 already does this directly; mirror
            // that here instead of going through ResumeMonitorEventLocked
            // (which defaults to plain GO when lastEvKind_ is empty).
            As<IDebugControl3>(&control3_)->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
            stopped_ = false;
            { StopInfoRec s0; FillStopInfoLocked(&s0, "none"); PublishStop(std::move(s0)); }
        }
        return "";
    });
}

std::string DbgSession::Attach(UINT32 pid, bool monitor)
{
    return RunOnEngine([&]() -> std::string {
        std::string err = InitEngine();
        if (!err.empty()) {
            return err;
        }
        auto client = As<IDebugClient5>(&client5_);
        auto control = As<IDebugControl3>(&control3_);
        auto sys = As<IDebugSystemObjects4>(&sysObj4_);
        if (active_) {
            // Same-pid re-attach honors the explicit monitor choice both
            // ways. The previous "upgrade-only" rule was dropped:
            // the bp_manage(events, mode='auto') debug-port fallback
            // upgrades the session into monitor mode so hits auto-
            // resume, but it left the session stuck in monitor mode
            // after draining — a later debug_manage(regs) saw the next
            // bp hit auto-resume into the events ring and the user
            // read 'target not stopped'. Letting a plain
            // debug_manage(attach, pid=X) (monitor=false, the default)
            // downgrade cleanly means callers can switch back to
            // interactive debugging without a detach + re-launch cycle.
            if (pid_ == pid) {
                monitor_ = monitor;
                if (monitor_ && stopped_) {
                    // upgrading to monitor resumes a target left stopped
                    // at an un-continued event — otherwise the engine
                    // loop never reaches WaitForEvent and the debugee
                    // stays frozen.
                    control->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
                    stopped_ = false;
                }
                { StopInfoRec s0; FillStopInfoLocked(&s0, stopped_ ? "attach" : "none"); PublishStop(std::move(s0)); }
                return "";
            }
            return "debug session already active; detach first";
        }
        // force DEBUG_ENGOPT_INITIAL_BREAK before
        // AttachProcess. Without this, dbgeng runs the attach's
        // initial events (including the DbgUiRemoteBreakin int3)
        // through without parking the target, so WaitForEvent sees
        // no stop event and times out at 15s with S_FALSE even
        // though the attach technically succeeded. Launch has
        // always set this option explicitly; Attach never did, and
        // the bug was invisible as long as a prior Launch left the
        // flag set — any cold Attach (or Attach after a Launch with
        // breakOnEntry=false) manifested as the full-timeout hang
        // the "it worked on the previous release" report tracked down.
        //
        // enable SeDebugPrivilege on the agent's own
        // token. SYSTEM has the privilege but dbgeng needs it
        // enabled. Belt-and-braces with B12; harmless when already
        // enabled.
        //
        // pass DEBUG_ATTACH_INVASIVE_RESUME_PROCESS so
        // the target isn't left with every thread frozen after the
        // debug object attaches — matches cdb's default behavior.
        {
            HANDLE _tok = nullptr;
            if (OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &_tok) && _tok) {
                TOKEN_PRIVILEGES _tp{};
                _tp.PrivilegeCount = 1;
                _tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege",
                                           &_tp.Privileges[0].Luid)) {
                    AdjustTokenPrivileges(_tok, FALSE, &_tp,
                        sizeof(_tp), nullptr, nullptr);
                }
                CloseHandle(_tok);
            }
        }
        {
            ULONG _opts = 0;
            control->GetEngineOptions(&_opts);
            control->SetEngineOptions(_opts | DEBUG_ENGOPT_INITIAL_BREAK);
        }
        if (FAILED(client->AttachProcess(0, pid,
                        DEBUG_ATTACH_INVASIVE_RESUME_PROCESS))) {
            // tear down any partial engine state from the
            // failed AttachProcess call. Without this, a prior debugee
            // that process-exited can leave the dbgeng subsession in a
            // half-state that pins every follow-up attach with the same
            // vague "AttachProcess failed" — the only recovery was an
            // agent restart. EndSession here is a no-op when the engine
            // is already clean; see Detach(!active_) for the mirror
            // scrub path.
            client->EndSession(DEBUG_SESSION_END);
            return "AttachProcess failed";
        }
        if (control->WaitForEvent(0, 15000) != S_OK) {
            client->EndSession(DEBUG_SESSION_END);
            return "no attach event";
        }
        ULONG sysPid = 0, sysTid = 0;
        sys->GetCurrentProcessSystemId(&sysPid);
        sys->GetCurrentThreadSystemId(&sysTid);
        pid_ = sysPid;
        active_ = true;
        stopped_ = true;
        monitor_ = monitor;
        seq_++;
        events_.Push({++seq_, "session_status", pid_, sysTid, 0, 0,
                      monitor ? "attached (monitor)" : "attached", NowUnix(), false, 0, 0});
        { StopInfoRec s0; FillStopInfoLocked(&s0, "attach"); PublishStop(std::move(s0)); }
        if (monitor_) {
            // never leave the debugee frozen at the attach break —
            // observation mode resumes immediately and the engine loop
            // auto-continues bp hits from here on.
            control->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
            stopped_ = false;
            { StopInfoRec s0; FillStopInfoLocked(&s0, "none"); PublishStop(std::move(s0)); }
        }
        return "";
    });
}

std::string DbgSession::Detach(bool kill)
{
    return RunOnEngine([&]() -> std::string {
        auto client = As<IDebugClient5>(&client5_);
        if (!active_) {
            // no live session: still end any zombie engine state so the next
            // launch starts clean
            if (engineReady_) {
                client->EndSession(DEBUG_SESSION_END);
            }
            // B10 fix (idempotent): a Detach on an already-dead session
            // scrubs leftover state too, so a subsequent launch starts clean.
            bpIds_.clear();
            lastEvKind_.clear();
            lastEvCode_ = 0;
            injectedBreaks_ = 0;
            ResetStop();
            arch_ = TargetArch::Unknown;
            nextReasonHint_.clear();
            return "no active session";
        }
        // Terminate/DetachProcesses does the real work on the target. The
        // agent deaths seen here were the FillStatus reflection bug, not
        // dbgeng. No EndSession afterwards: on 24H2+ builds it can abort the
        // process, and a session with an exited process accepts CreateProcess2.
        if (kill) {
            client->TerminateProcesses();
        } else {
            client->DetachProcesses();
        }
        active_ = false;
        stopped_ = false;
        monitor_ = false;
        pid_ = 0;
        // B10 fix: Detach was leaking bpIds_ / lastEvKind_ / lastEvCode_ /
        // injectedBreaks_ / lastStop_ / arch_ into the next session. A fresh
        // Launch inherited stale bp ids (duplicate rows in bp_manage(list)),
        // stale lastEvKind_ (ResumeAfterInterrupt would pick GO_HANDLED for an
        // event from the previous session), stale arch_ (x86-after-x64 would
        // read "x64" until the next event landed), and stale lastStop_ (an
        // immediate Status after Launch would show the previous session's
        // rip/symbol). Scrub everything.
        bpIds_.clear();
        lastEvKind_.clear();
        lastEvCode_ = 0;
        injectedBreaks_ = 0;
        ResetStop();
        arch_ = TargetArch::Unknown;
        nextReasonHint_.clear();
        return "";
    });
}

std::string DbgSession::Continue(StopInfoRec* out, bool includeContext)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_ || !stopped_) {
            if (out) {
                FillStopInfoLocked(out, active_ ? "none" : "process_exit", includeContext);
            }
            return stopped_ ? "no active session" : "target not stopped";
        }
        auto control = As<IDebugControl3>(&control3_);
        // GO_HANDLED (not plain GO): the initial-break int3 in
        // ntdll!LdrpDoDebuggerBreak (and any breakpoint exception we handle
        // in the debugger) MUST be marked handled, or the OS re-dispatches
        // the exception into the target's SEH chain and the target loops on
        // the int3 forever. cdb/windbg's default filter tables do this for
        // us; we don't install those, so we do it explicitly.
        HRESULT hr = control->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
        if (FAILED(hr)) {
            if (out) FillStopInfoLocked(out, "none", includeContext);
            return "SetExecutionStatus failed hr=" + std::to_string(hr);
        }
        stopped_ = false;
        // SetExecutionStatus only ARMS the GO; dbgeng actually writes the
        // int3 patches into every enabled sw bp AND resumes the target
        // inside the next WaitForEvent on the engine thread. If a flood
        // of post-continue RPCs keeps the task queue hot, the engine loop
        // never idles into its WaitForEvent branch, dbgeng stays in
        // "GO wanted" with no patches written, and the sw bp never fires
        // (umagent reads back unchanged bytes, target runs free past the
        // address). Pump the dispatch here with a short wait — long
        // enough to let dbgeng transition out of the GO state and write
        // bp patches to target memory, short enough that Continue stays
        // responsive. If the target hits a bp inside this window
        // (common when the bp is at rip+1 of the launch-break int3) we
        // observe the event and mark stopped_. Step already does this
        // correctly via its own WaitForEvent(0, 30000).
        HRESULT whr = control->WaitForEvent(0, 50);
        if (whr == S_OK) {
            stopped_ = true;
            HandleEventLocked();
        }
        if (out) {
            if (stopped_) {
                *out = lastStop_;
                // top up crash context on demand. Exception stops
                // already have regs populated via HandleEventLocked's
                // FillStopInfoLocked(reason="exception"). For other reasons
                // (bp hits, step, etc.), fill on explicit request.
                if (includeContext && out->regs.empty()) {
                    FillCrashContextLocked(out);
                }
            } else {
                FillStopInfoLocked(out, "none", includeContext);
            }
        }
        return "";
    });
}

std::string DbgSession::Step(bool over, UINT64 count, StopInfoRec* out, bool includeContext)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_ || !stopped_) {
            if (out) FillStopInfoLocked(out, active_ ? "none" : "process_exit", includeContext);
            return stopped_ ? "no active session" : "target not stopped";
        }
        auto control = As<IDebugControl3>(&control3_);
        // dbgeng executes one operation per SetExecutionStatus; each subsequent
        // step completes when WaitForEvent observes the step event.
        // Step_over/Step_into implicitly handle any pending exception (they
        // never re-dispatch the initial break to SEH), so no _HANDLED variant.
        for (UINT64 i = 0; i < count; i++) {
            // tell HandleEventLocked that the next event resolves a
            // user-initiated step, so the single-step #DB (0x80000004) that
            // normally maps to reason="exception" surfaces as reason="step".
            nextReasonHint_ = "step";
            HRESULT hr = control->SetExecutionStatus(over ? DEBUG_STATUS_STEP_OVER : DEBUG_STATUS_STEP_INTO);
            if (FAILED(hr)) {
                nextReasonHint_.clear();
                if (out) FillStopInfoLocked(out, "none", includeContext);
                return "SetExecutionStatus failed hr=" + std::to_string(hr);
            }
            stopped_ = false;
            hr = control->WaitForEvent(0, 30000);
            if (hr == S_OK) {
                stopped_ = true;
                HandleEventLocked();
                continue; // next step
            }
            nextReasonHint_.clear();
            if (hr == S_FALSE) {
                stopped_ = false; // still running (e.g. stepped into a long call)
                if (out) {
                    FillStopInfoLocked(out, "none", includeContext);
                    out->timed_out = true;
                }
                return "";
            }
            if (out) FillStopInfoLocked(out, "none", includeContext);
            return "WaitForEvent failed hr=" + std::to_string(hr);
        }
        if (out) {
            if (stopped_) {
                *out = lastStop_;
                if (includeContext && out->regs.empty()) {
                    FillCrashContextLocked(out);
                }
            } else {
                FillStopInfoLocked(out, "none", includeContext);
            }
        }
        return "";
    });
}

// Status is a pure echo of the cached lastStop_ — it never stops
// the target, so it runs outside the engine thread (safe reads of booleans
// are atomic-enough on Windows for an advisory snapshot; the caller treats
// it as such). Mirrors active_/stopped_ live for the "nothing cached yet"
// case (fresh session before the initial event, say).
std::string DbgSession::Status(StopInfoRec* out, bool includeContext)
{
    if (!out) {
        return "";
    }
    return RunOnEngine([&]() -> std::string {
        if (lastStop_.seq == 0 && !active_) {
            // never had a session — return a bare snapshot rather than the
            // zeroed default so callers can distinguish "no session" cleanly.
            FillStopInfoLocked(out, "none", includeContext);
            return "";
        }
        *out = lastStop_;
        // mirror live liveness bits — a Detach between the cached snapshot
        // and this call must surface as active=false even if lastStop_ was
        // written while the session was still alive.
        out->active = active_;
        out->stopped = stopped_;
        out->timed_out = false;
        if (includeContext && out->stopped && out->regs.empty()) {
            FillCrashContextLocked(out);
        }
        return "";
    });
}

std::string DbgSession::Pause(UINT32 timeoutMs, StopInfoRec* out, bool includeContext)
{
    const UINT32 waitMs = ClampTimeout(timeoutMs, 5000);
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            if (out) FillStopInfoLocked(out, "process_exit", includeContext);
            return "no active session";
        }
        if (stopped_) {
            if (out) {
                *out = lastStop_;
                if (includeContext && out->regs.empty()) {
                    FillCrashContextLocked(out);
                }
            }
            return "";
        }
        // hint HandleEventLocked that the next int3 (which
        // EnsureStopped injects via DebugBreakProcess) is a Pause and should
        // surface as reason="pause" rather than reason="exception".
        nextReasonHint_ = "pause";
        if (std::string err = EnsureStopped(waitMs); !err.empty()) {
            nextReasonHint_.clear();
            // EnsureStopped handles its own HandleEventLocked on success.
            if (out) {
                FillStopInfoLocked(out, "none", includeContext);
                out->timed_out = true;
            }
            return "";
        }
        nextReasonHint_.clear();
        if (out) {
            *out = lastStop_;
            if (includeContext && out->regs.empty()) {
                FillCrashContextLocked(out);
            }
        }
        return "";
    });
}

std::string DbgSession::Wait(UINT32 timeoutMs, StopInfoRec* out, bool includeContext)
{
    // Monitor-mode note: in monitor mode, breakpoint hits auto-resume
    // inside WaitForStop's loop (see dbg_engine.cpp::ResumeMonitorEventLocked),
    // so Wait resolves only on process_exit or exception. This preserves
    // bp_manage(events, mode='auto') — monitored bp hits still stream into
    // the events ring without parking the target, while a Wait caller still
    // gets a meaningful stop signal when something fatal happens.
    const UINT32 waitMs = ClampTimeout(timeoutMs, 20000);
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            if (out) FillStopInfoLocked(out, "process_exit", includeContext);
            return "";
        }
        std::string werr = WaitForStop(waitMs, out);
        if (out && includeContext && out->stopped && out->regs.empty()) {
            FillCrashContextLocked(out);
        }
        return werr;
    });
}

std::string DbgSession::Run(UINT32 timeoutMs, StopInfoRec* out, bool includeContext)
{
    // See Wait for the monitor-mode comment; Run inherits the same policy
    // because its wait phase is WaitForStop.
    const UINT32 waitMs = ClampTimeout(timeoutMs, 20000);
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            if (out) FillStopInfoLocked(out, "process_exit", includeContext);
            return "no active session";
        }
        if (stopped_) {
            auto control = As<IDebugControl3>(&control3_);
            HRESULT hr = control->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
            if (FAILED(hr)) {
                if (out) FillStopInfoLocked(out, "none", includeContext);
                return "SetExecutionStatus failed hr=" + std::to_string(hr);
            }
            stopped_ = false;
        }
        std::string werr = WaitForStop(waitMs, out);
        if (out && includeContext && out->stopped && out->regs.empty()) {
            FillCrashContextLocked(out);
        }
        return werr;
    });
}

std::string DbgSession::RunTo(UINT64 address, UINT32 timeoutMs, StopInfoRec* out,
                              bool includeContext)
{
    const UINT32 waitMs = ClampTimeout(timeoutMs, 20000);
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            if (out) FillStopInfoLocked(out, "process_exit", includeContext);
            return "no active session";
        }
        if (!stopped_) {
            if (std::string err = EnsureStopped(5000); !err.empty()) {
                if (out) FillStopInfoLocked(out, "none", includeContext);
                return err;
            }
        }
        auto control4 = As<IDebugControl4>(&control4_);
        auto control3 = As<IDebugControl3>(&control3_);
        IDebugBreakpoint2* bp = nullptr;
        HRESULT hr = control4->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);
        if (FAILED(hr) || !bp) {
            if (out) FillStopInfoLocked(out, "none", includeContext);
            return "AddBreakpoint2 failed hr=" + std::to_string(hr);
        }
        bp->SetOffset(address);
        bp->SetFlags(DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ONE_SHOT);
        // RAII cleanup via a one-shot helper. BpAdd/BpRemove run via
        // RunOnEngine; inside this task we already own the engine, so the
        // helper removes the bp directly (stopping the target first if a
        // Wait timeout left it running — dbgeng rejects RemoveBreakpoint2
        // with E_UNEXPECTED on a running debugee).
        auto cleanup = [&]() {
            if (!bp) return;
            if (active_ && !stopped_) {
                (void)EnsureStopped(2000); // best effort
            }
            if (active_) {
                control4->RemoveBreakpoint2(bp);
            }
            bp = nullptr;
        };

        hr = control3->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
        if (FAILED(hr)) {
            cleanup();
            if (out) FillStopInfoLocked(out, "none", includeContext);
            return "SetExecutionStatus failed hr=" + std::to_string(hr);
        }
        stopped_ = false;
        std::string werr = WaitForStop(waitMs, out);
        cleanup();
        if (out && includeContext && out->stopped && out->regs.empty()) {
            FillCrashContextLocked(out);
        }
        return werr;
    });
}

std::string DbgSession::StepOut(UINT32 timeoutMs, StopInfoRec* out, bool includeContext)
{
    // Implementation choice: walk-stack + one-shot sw bp at the return
    // address, rather than DEBUG_STATUS_STEP_BRANCH. STEP_BRANCH is
    // documented to fire on the next branch taken, but dbgeng's WOW64
    // thunking layer intercepts branches on 32-bit-on-64 targets and can
    // swallow the step (we observed Step-out never returning on a WOW64
    // target that executed a long syscall thunk). The one-shot bp is
    // deterministic: dbgeng resumes, hits the return, and reports a normal
    // breakpoint event. Downside: if the caller's frame has already been
    // unwound (step-out from a tail call), the bp never fires and we rely
    // on timeoutMs to surface a timed_out=true echo to the caller.
    const UINT32 waitMs = ClampTimeout(timeoutMs, 20000);
    return RunOnEngine([&]() -> std::string {
        if (!active_ || !stopped_) {
            if (out) FillStopInfoLocked(out, active_ ? "none" : "process_exit", includeContext);
            return stopped_ ? "no active session" : "target not stopped";
        }
        auto control4 = As<IDebugControl4>(&control4_);
        auto control3 = As<IDebugControl3>(&control3_);
        DEBUG_STACK_FRAME frames[2]{};
        ULONG filled = 0;
        if (FAILED(control4->GetStackTrace(0, 0, 0, frames, 2, &filled)) || filled < 1) {
            if (out) FillStopInfoLocked(out, "none", includeContext);
            return "GetStackTrace failed";
        }
        UINT64 returnAddr = frames[0].ReturnOffset;
        if (!returnAddr) {
            if (out) FillStopInfoLocked(out, "none", includeContext);
            return "no return address on current frame";
        }
        IDebugBreakpoint2* bp = nullptr;
        HRESULT hr = control4->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);
        if (FAILED(hr) || !bp) {
            if (out) FillStopInfoLocked(out, "none", includeContext);
            return "AddBreakpoint2 failed hr=" + std::to_string(hr);
        }
        bp->SetOffset(returnAddr);
        bp->SetFlags(DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ONE_SHOT);
        // Shared cleanup pattern with RunTo — see the comment there.
        auto cleanup = [&]() {
            if (!bp) return;
            if (active_ && !stopped_) {
                (void)EnsureStopped(2000); // best effort
            }
            if (active_) {
                control4->RemoveBreakpoint2(bp);
            }
            bp = nullptr;
        };

        hr = control3->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED);
        if (FAILED(hr)) {
            cleanup();
            if (out) FillStopInfoLocked(out, "none", includeContext);
            return "SetExecutionStatus failed hr=" + std::to_string(hr);
        }
        stopped_ = false;
        std::string werr = WaitForStop(waitMs, out);
        cleanup();
        if (out && includeContext && out->stopped && out->regs.empty()) {
            FillCrashContextLocked(out);
        }
        return werr;
    });
}

} // namespace pry
