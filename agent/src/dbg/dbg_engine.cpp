#include "dbg_session.hpp"
#include "../common.h"

#include <dbgeng.h>
#include <objbase.h>

#include <algorithm>
#include <chrono>

namespace pry {

typedef HRESULT(WINAPI *PFN_DebugCreate)(_In_ REFIID, _Out_ PVOID*);

template <typename T>
static T* As(void** pp)
{
    return reinterpret_cast<T*>(*pp);
}

static PFN_DebugCreate GetDebugCreate()
{
    static PFN_DebugCreate fn = nullptr;
    static bool done = false;
    if (!done) {
        done = true;
        HMODULE h = LoadLibraryW(L"dbgeng.dll");
        if (h) {
            fn = (PFN_DebugCreate)GetProcAddress(h, "DebugCreate");
        }
    }
    return fn;
}

DbgSession& DbgSession::Instance()
{
    static DbgSession s;
    return s;
}

// runs ON the engine thread (called from Launch/Attach tasks)
std::string DbgSession::InitEngine()
{
    if (engineReady_) {
        return "";
    }
    auto create = GetDebugCreate();
    if (!create) {
        return "dbgeng.dll not available";
    }
    HRESULT hr = create(__uuidof(IDebugClient5), &client5_);
    if (FAILED(hr)) {
        return "DebugCreate failed hr=" + std::to_string(hr);
    }
    client5_ ? 0 : 0;
    // query facet interfaces via the client pointer
    auto client = As<IDebugClient5>(&client5_);
    client->QueryInterface(__uuidof(IDebugControl3), &control3_);
    client->QueryInterface(__uuidof(IDebugControl4), &control4_);
    client->QueryInterface(__uuidof(IDebugRegisters2), &regs2_);
    client->QueryInterface(__uuidof(IDebugDataSpaces4), &spaces4_);
    client->QueryInterface(__uuidof(IDebugSystemObjects4), &sysObj4_);
    client->QueryInterface(__uuidof(IDebugSymbols3), &symbols3_);
    if (!control3_ || !regs2_ || !spaces4_ || !sysObj4_ || !symbols3_) {
        return "dbgeng interface query failed";
    }
    engineReady_ = true;
    return "";
}

void DbgSession::PublishStop(StopInfoRec s)
{
    std::lock_guard<std::mutex> lk(stopM_);
    lastStop_ = std::move(s);
}

void DbgSession::ResetStop()
{
    std::lock_guard<std::mutex> lk(stopM_);
    lastStop_ = StopInfoRec{};
}

StopInfoRec DbgSession::SnapshotStop() const
{
    std::lock_guard<std::mutex> lk(stopM_);
    return lastStop_;
}

std::string DbgSession::RunOnEngine(std::function<std::string()> f)
{
    auto task = std::make_shared<std::packaged_task<std::string()>>(std::move(f));
    std::future<std::string> fut = task->get_future();
    {
        std::lock_guard<std::mutex> lk(qm_);
        if (!qOpen_) {
            return "agent shutting down";
        }
        // Mechanics audit P1: created under the queue mutex. Two RPCs
        // racing the old unlocked `if (!joinable()) engineThread_ = ...`
        // could both move-assign, and assigning over a joinable
        // std::thread is std::terminate (the whole agent died). Shutdown
        // clears qOpen_ under the same mutex, so no thread is created
        // after it.
        if (!engineThread_.joinable()) {
            engineThread_ = std::thread([this] { EngineLoop(); });
        }
        q_.emplace_back(task);
    }
    qcv_.notify_one();
    return fut.get();
}

void DbgSession::Shutdown()
{
    shutdown_ = true;
    {
        std::lock_guard<std::mutex> lk(qm_);
        qOpen_ = false;
    }
    qcv_.notify_all();
    if (engineThread_.joinable()) {
        engineThread_.join();
    }
    events_.Wake();
}

UINT32 DbgSession::SysTidFromEngineIdLocked(ULONG engTid)
{
    ULONG num = 0;
    if (FAILED(As<IDebugSystemObjects4>(&sysObj4_)->GetNumberThreads(&num)) || !num) {
        return engTid;
    }
    std::vector<ULONG> eng(num), sys(num);
    if (FAILED(As<IDebugSystemObjects4>(&sysObj4_)->GetThreadIdsByIndex(0, num, eng.data(), sys.data()))) {
        return engTid;
    }
    for (ULONG i = 0; i < num; i++) {
        if (eng[i] == engTid) {
            return sys[i];
        }
    }
    return engTid;
}

// memoize target arch via IDebugControl::GetEffectiveProcessorType.
// dbgeng publishes the processor type only after the first event the session
// sees, so the probe is called from HandleEventLocked and FillStopInfoLocked
// rather than InitEngine. Returns Unknown on failure (caller keeps trying).
TargetArch DbgSession::DetectArchLocked()
{
    if (!engineReady_) {
        return TargetArch::Unknown;
    }
    auto control = As<IDebugControl3>(&control3_);
    ULONG eff = 0;
    if (FAILED(control->GetEffectiveProcessorType(&eff)) || !eff) {
        // dbgeng has no effective type yet (pre-first-event probe). Fall
        // back to the cached value from a previous probe, if any.
        return arch_;
    }
    ULONG actual = 0;
    control->GetActualProcessorType(&actual);
    // WOW64: dbgeng effective=X86 on a target whose host is X64. Detect that
    // ambiguity so StopInfo.arch reports "wow64" instead of "x86".
    //
    // The result is re-probed every call (not memoized past the first) so a
    // WOW64 thread that transitions from x64 ntdll into x86 user code flips
    // StopInfo.arch and the GPR name set from the next regs call onward.
    // Detach's B10 scrub resets arch_ to Unknown for a fresh session.
    TargetArch newArch;
    if (eff == IMAGE_FILE_MACHINE_I386 && actual == IMAGE_FILE_MACHINE_AMD64) {
        newArch = TargetArch::WOW64;
    } else if (eff == IMAGE_FILE_MACHINE_I386) {
        newArch = TargetArch::X86;
    } else if (eff == IMAGE_FILE_MACHINE_AMD64) {
        newArch = TargetArch::X64;
    } else {
        newArch = TargetArch::Unknown;
    }
    arch_ = newArch;
    return arch_;
}

// snapshot the current engine state into *out. Called from
// HandleEventLocked (with &lastStop_) and from the StopInfo echo paths in
// dbg_process.cpp. Fills reason/pid/tid/rip/symbol/seq/arch/active/stopped;
// bp_id, exception_code, first_chance are stamped by the caller after the
// event discriminator is known.
//
// when `includeContext == true` OR
// `reason == "exception"`, tops up with GPRs + 16 bytes at rip via
// FillCrashContextLocked (defined in dbg_state.cpp — it uses the same
// GprNamesForArch arch mapping as the GetRegs path). Best-effort; failed
// reads leave the respective field empty and never alter stop_reason /
// timed_out.
void DbgSession::FillStopInfoLocked(StopInfoRec* out, const std::string& reason,
                                    bool includeContext)
{
    if (!out) {
        return;
    }
    out->active = active_;
    out->stopped = stopped_;
    out->timed_out = false;
    out->pid = pid_;
    out->tid = 0;
    out->rip = 0;
    out->symbol.clear();
    out->stop_reason = reason;
    out->seq = seq_;
    out->exception_code = 0;
    out->first_chance = false;
    out->bp_id = 0;
    out->regs.clear();
    out->bytes_at_rip_hex.clear();

    TargetArch a = DetectArchLocked();
    switch (a) {
    case TargetArch::X64:   out->arch = "x64"; break;
    case TargetArch::X86:   out->arch = "x86"; break;
    case TargetArch::WOW64: out->arch = "wow64"; break;
    default:                out->arch.clear(); break;
    }

    if (!engineReady_ || !active_) {
        return;
    }
    auto sys = As<IDebugSystemObjects4>(&sysObj4_);
    auto regs = As<IDebugRegisters2>(&regs2_);
    auto symbols = As<IDebugSymbols3>(&symbols3_);
    ULONG sysTid = 0;
    if (SUCCEEDED(sys->GetCurrentThreadSystemId(&sysTid))) {
        out->tid = sysTid;
    }
    if (stopped_) {
        ULONG64 ip = 0;
        if (SUCCEEDED(regs->GetInstructionOffset(&ip))) {
            out->rip = ip;
            char name[512] = {};
            ULONG sizeNeeded = 0;
            ULONG64 disp = 0;
            if (SUCCEEDED(symbols->GetNameByOffset(ip, name, sizeof(name), &sizeNeeded, &disp))
                && name[0]) {
                char buf[640];
                _snprintf_s(buf, _TRUNCATE, "%s+0x%llx", name,
                            (unsigned long long)disp);
                out->symbol = buf;
            }
        }
    }

    // crash-context enrichment. Fill regs + bytes_at_rip_hex when
    // the caller opted in OR on exception stops (the triage path this is
    // for). Only meaningful when the target is actually parked — a
    // running/inactive session has no stable registers to sample.
    if (stopped_ && (includeContext || reason == "exception")) {
        FillCrashContextLocked(out);
    }
}

void DbgSession::HandleEventLocked()
{
    auto control = As<IDebugControl3>(&control3_);
    auto sys = As<IDebugSystemObjects4>(&sysObj4_);

    ULONG type = 0;
    ULONG engTid = 0, engPid = 0;
    ULONG used = 0, textUsed = 0;
    char text[512]{};
    char desc[256]{};

    DEBUG_LAST_EVENT_INFO_EXCEPTION exc{};
    DEBUG_LAST_EVENT_INFO_BREAKPOINT bpInfo{};

    if (FAILED(control->GetLastEventInformation(&type, &engPid, &engTid, &exc, sizeof(exc), &used,
                                                text, sizeof(text), &textUsed))) {
        return;
    }

    DebugEventRec ev;
    ev.ts = NowUnix();
    ev.tid = SysTidFromEngineIdLocked(engTid);
    ev.pid = pid_;
    switch (type) {
    case DEBUG_EVENT_BREAKPOINT:
        control->GetLastEventInformation(&type, &engPid, &engTid, &bpInfo, sizeof(bpInfo), &used,
                                         nullptr, 0, nullptr);
        {
            ULONG num = 0;
            bool hw = false;
            auto control4 = As<IDebugControl4>(&control4_);
            if (SUCCEEDED(control4->GetNumberBreakpoints(&num)) && num && bpInfo.Id != DEBUG_ANY_ID) {
                IDebugBreakpoint2* bp = nullptr;
                if (SUCCEEDED(control4->GetBreakpointById2(bpInfo.Id, &bp)) && bp) {
                    // both GetType out-params are required; passing nullptr AVs
                    ULONG bpType = 0, procType = 0;
                    bp->GetType(&bpType, &procType);
                    hw = bpType == DEBUG_BREAKPOINT_DATA;
                    // the bp's own offset IS the hit address for exec bps
                    // and the watched address for data bps — far more
                    // useful downstream than the thread data offset.
                    ULONG64 bpOff = 0;
                    if (SUCCEEDED(bp->GetOffset(&bpOff))) {
                        ev.address = bpOff;
                    }
                    bp->Release();
                }
                ev.bp_id = (bpInfo.Id == DEBUG_ANY_ID) ? 0 : (UINT32)bpInfo.Id;
            }
            ev.kind = hw ? "bp_hw" : "bp_sw";
        }
        if (!ev.address) {
            sys->GetCurrentThreadDataOffset(&ev.address);
        }
        break;
    case DEBUG_EVENT_EXCEPTION:
        ev.kind = "exception";
        ev.code = (INT32)exc.ExceptionRecord.ExceptionCode;
        ev.address = exc.ExceptionRecord.ExceptionAddress;
        ev.first_chance = exc.FirstChance != 0;
        _snprintf_s(desc, _TRUNCATE, "first_chance=%d code=0x%08X",
                    (int)exc.FirstChance, (UINT32)exc.ExceptionRecord.ExceptionCode);
        ev.desc = desc;
        break;
    case DEBUG_EVENT_EXIT_PROCESS: {
        // B4 fix: the exception-shaped `exc` buffer only happened to land on
        // the right ExitCode byte. Re-call GetLastEventInformation with the
        // typed struct instead.
        DEBUG_LAST_EVENT_INFO_EXIT_PROCESS ep{};
        ULONG used2 = 0;
        control->GetLastEventInformation(&type, &engPid, &engTid, &ep, sizeof(ep), &used2,
                                         nullptr, 0, nullptr);
        ev.kind = "process_exit";
        ev.code = (INT32)ep.ExitCode;
        active_ = false;
        break;
    }
    case DEBUG_EVENT_CREATE_THREAD:
        ev.kind = "thread_create";
        sys->GetCurrentThreadDataOffset(&ev.address);
        break;
    case DEBUG_EVENT_EXIT_THREAD:
        ev.kind = "thread_exit";
        break;
    case DEBUG_EVENT_LOAD_MODULE: {
        // B3 fix: the previous implementation copied GetCurrentThreadDataOffset
        // (the TEB) into `address`. Re-query the typed struct and record the
        // module base both into `address` (back-compat) and the new
        // `module_base` field.
        DEBUG_LAST_EVENT_INFO_LOAD_MODULE lm{};
        ULONG used2 = 0;
        control->GetLastEventInformation(&type, &engPid, &engTid, &lm, sizeof(lm), &used2,
                                         nullptr, 0, nullptr);
        ev.kind = "module_load";
        ev.address = lm.Base;
        ev.module_base = lm.Base;
        break;
    }
    case DEBUG_EVENT_UNLOAD_MODULE: {
        // B3 companion: symmetric module-unload event. `Base` carries the
        // base of the module being unloaded; mirror it into `address` so old
        // clients keep seeing the image base on module events.
        DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE um{};
        ULONG used2 = 0;
        control->GetLastEventInformation(&type, &engPid, &engTid, &um, sizeof(um), &used2,
                                         nullptr, 0, nullptr);
        ev.kind = "module_unload";
        ev.address = um.Base;
        ev.module_base = um.Base;
        break;
    }
    case DEBUG_EVENT_SESSION_STATUS:
        ev.kind = "session_status";
        break;
    default:
        ev.kind = "session_status";
        break;
    }
    if (!ev.desc.empty() || text[0]) {
        ev.desc = ev.desc.empty() ? text : ev.desc + " " + text;
    }
    ev.seq = ++seq_;
    lastEvKind_ = ev.kind;
    lastEvCode_ = ev.code;

    // cache the stop snapshot so Status() can answer without parking
    // the target. Translate the event kind to the public stop_reason; the
    // event-specific fields (bp_id / exception_code / first_chance) are
    // stamped in after FillStopInfoLocked populates the baseline.
    std::string reason;
    if (ev.kind == "bp_sw")          reason = "bp_sw";
    else if (ev.kind == "bp_hw")     reason = "bp_hw";
    else if (ev.kind == "exception") reason = "exception";
    else if (ev.kind == "process_exit") reason = "process_exit";
    else                             reason = "none";
    // Hint consumption: Step sets "step" before resuming so a post-step
    // single-step #DB (reason="exception", code=0x80000004) surfaces as
    // "step" to the caller; Pause sets "pause" so the injected int3
    // DebugBreakProcess raised surfaces as "pause" rather than "exception".
    // Hint only applies to exceptions and bp hits and is single-shot.
    if (!nextReasonHint_.empty()) {
        if (nextReasonHint_ == "step" && reason == "exception"
            && lastEvCode_ == (INT32)0x80000004) {
            reason = "step";
        } else if (nextReasonHint_ == "pause" && reason == "exception"
                   && lastEvCode_ == (INT32)0x80000003) {
            reason = "pause";
        } else if (nextReasonHint_ == "pause" && (reason == "bp_sw" || reason == "bp_hw")) {
            // DebugBreakProcess landed inside dbgeng's own bp list (very rare)
            reason = "pause";
        }
        nextReasonHint_.clear();
    }
    StopInfoRec stop;
    FillStopInfoLocked(&stop, reason);
    stop.bp_id = ev.bp_id;
    if (ev.kind == "exception") {
        stop.exception_code = (UINT32)ev.code;
        stop.first_chance = ev.first_chance;
    }
    if (ev.kind == "process_exit") {
        // active_ already cleared above; reflect it in the echo.
        stop.active = false;
    }
    PublishStop(std::move(stop));

    events_.Push(ev);
}

// shared monitor-mode auto-resume. The EngineLoop idle pump used to
// inline this; WaitForStop (run on the engine thread via RunOnEngine) needs
// the same logic so a bp that lands inside a task's wait window doesn't park
// the monitored debugee.
void DbgSession::ResumeMonitorEventLocked()
{
    ULONG st = DEBUG_STATUS_GO;
    bool foreignStep = false;
    if (lastEvKind_ == "exception"
        && lastEvCode_ == (INT32)0x80000003
        && injectedBreaks_ > 0) {
        // leftover int3 from our own EnsureStopped injection — swallow it
        // (NOT_HANDLED would kill the debugee)
        injectedBreaks_--;
        st = DEBUG_STATUS_GO_HANDLED;
    } else if (lastEvKind_ == "bp_hw" || lastEvKind_ == "bp_sw") {
        st = DEBUG_STATUS_GO_HANDLED;
    } else if (lastEvKind_ == "exception"
               && lastEvCode_ == (INT32)0x80000004) {
        st = DEBUG_STATUS_GO_HANDLED;
        foreignStep = true;
    } else if (lastEvKind_ == "exception") {
        st = DEBUG_STATUS_GO_NOT_HANDLED;
    }
    if (foreignStep) {
        // a single-step dbgeng didn't arm (driver DR state predating the
        // attach, etc.) is a fault AT rip — resuming without RF refires
        // the #DB instantly and storms the debug port. Set RF so the
        // instruction executes once; the bp stays armed for the next hit.
        auto regs = As<IDebugRegisters2>(&regs2_);
        ULONG idx = 0;
        DEBUG_VALUE dv{};
        if (SUCCEEDED(regs->GetIndexByName("efl", &idx))
            && SUCCEEDED(regs->GetValue(idx, &dv))) {
            dv.I64 |= 0x10000; // EFLAGS.RF
            dv.Type = DEBUG_VALUE_INT64;
            regs->SetValue(idx, &dv);
        }
    }
    As<IDebugControl3>(&control3_)->SetExecutionStatus(st);
    stopped_ = false;
}

// engine-thread-only (always invoked via RunOnEngine). Pumps
// WaitForEvent in 100 ms slices up to timeoutMs. Returns "" on both stop and
// timeout; the caller checks out->timed_out to tell them apart. In monitor
// mode, auto-resumes bp hits (matching EngineLoop's idle pump) and keeps
// waiting until a process_exit or exception surfaces — per the plan,
// "resolve on process_exit / exception only" so monitored bp hits still
// stream into the events ring without parking the target.
std::string DbgSession::WaitForStop(UINT32 timeoutMs, StopInfoRec* out)
{
    if (!engineReady_) {
        if (out) FillStopInfoLocked(out, "none");
        return "engine not ready";
    }
    if (!active_) {
        if (out) FillStopInfoLocked(out, "process_exit");
        return "";
    }
    if (stopped_ && !monitor_) {
        if (out) *out = lastStop_;
        return "";
    }
    auto control = As<IDebugControl3>(&control3_);
    auto deadline = std::chrono::steady_clock::now()
                    + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        ULONG slice = (ULONG)std::min<long long>(remain, 100);
        HRESULT hr = control->WaitForEvent(0, slice);
        if (hr == S_OK) {
            stopped_ = true;
            HandleEventLocked();
            if (!monitor_) {
                if (out) *out = lastStop_;
                return "";
            }
            // monitor mode: resolve on process_exit or exception, auto-resume
            // bp / thread / module events and keep waiting.
            bool resolve = (lastEvKind_ == "exception" && injectedBreaks_ == 0)
                           || lastEvKind_ == "process_exit";
            if (!active_) {
                resolve = true;
            }
            if (resolve) {
                if (out) *out = lastStop_;
                return "";
            }
            ResumeMonitorEventLocked();
            // keep looping until deadline or a resolving event.
        }
        // S_FALSE / timeout slice → loop and re-poll
    }
    // timed out
    if (out) {
        if (stopped_) {
            *out = lastStop_;
        } else {
            FillStopInfoLocked(out, lastStop_.stop_reason.empty() ? "none" : lastStop_.stop_reason);
        }
        out->timed_out = true;
        out->active = active_;
        out->stopped = stopped_;
    }
    return "";
}

// shared timeout clamp. Every public waiting call caps timeoutMs at
// 30000; 0 means "default" (the per-verb default supplied by the caller).
UINT32 DbgSession::ClampTimeout(UINT32 req, UINT32 defMs)
{
    if (req == 0) {
        return defMs;
    }
    if (req > 30000) {
        return 30000;
    }
    return req;
}

void DbgSession::EngineLoop()
{
    // THE dbgeng thread. On 24H2+ builds event delivery is pinned to the
    // thread that owns the session: DebugCreate, GO, WaitForEvent and every
    // interaction must happen here, serialized through the task queue.
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    for (;;) {
        std::shared_ptr<std::packaged_task<std::string()>> task;
        bool have_task = false;
        {
            std::unique_lock<std::mutex> lk(qm_);
            // timed wait: the queue AND the event pump must both get turns on
            // this thread (an idle wait here would starve WaitForEvent)
            qcv_.wait_for(lk, std::chrono::milliseconds(50),
                          [&] { return !q_.empty() || !qOpen_; });
            if (!q_.empty()) {
                task = q_.front();
                q_.pop_front();
                have_task = true;
            } else if (!qOpen_) {
                break;
            }
        }
        if (have_task) {
            (*task)();
            continue;
        }
        // queue idle: pump debug events while a live session is running
        bool canWait = false;
        {
            std::lock_guard<std::mutex> lk(m_);
            canWait = engineReady_ && active_ && !stopped_;
            if (canWait) {
                HRESULT hr = As<IDebugControl3>(&control3_)->WaitForEvent(0, 100);
                if (hr == S_OK) {
                    stopped_ = true;
                    HandleEventLocked();
                    // monitor mode = passive observation: EVERY event resumes
                    // the debugee — leaving it stopped at an un-continued
                    // thread/module/exit event freezes the process (and wedges
                    // kernel Ps*ContextThread callers waiting on its threads).
                    if (monitor_ && stopped_ && active_) {
                        ResumeMonitorEventLocked();
                    }
                }
            }
        }
        if (!canWait) {
            Sleep(50);
        }
    }
    CoUninitialize();
}

// Must run on the engine thread (inside a RunOnEngine task). DebugBreakProcess
// injects an int3 thread — deterministic even on a quiet debugee, where
// SetInterrupt's "next suspension point" semantics can stall indefinitely.
std::string DbgSession::EnsureStopped(UINT32 timeoutMs)
{
    if (stopped_) {
        return "";
    }
    if (!engineReady_ || !active_ || !pid_) {
        return "no active session";
    }
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, pid_);
    if (!h) {
        return "OpenProcess failed gle=" + std::to_string(GetLastError());
    }
    BOOL ok = DebugBreakProcess(h);
    DWORD gle = GetLastError();
    CloseHandle(h);
    if (!ok) {
        return "DebugBreakProcess failed gle=" + std::to_string(gle);
    }
    injectedBreaks_++;
    auto control = As<IDebugControl3>(&control3_);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        HRESULT hr = control->WaitForEvent(0, 200);
        if (hr == S_OK) {
            stopped_ = true;
            HandleEventLocked();
            if (lastEvKind_ == "exception" && lastEvCode_ == (INT32)0x80000003) {
                injectedBreaks_--; // our int3 won the race — consumed
            }
            return "";
        }
    }
    return "interrupt did not stop the target";
}

// SetInterrupt-backed cancel. Called directly from the gRPC thread
// (NOT via RunOnEngine) because that's the whole point — the engine thread
// is wedged inside a WaitForEvent / symbol-server stall that RunOnEngine
// would queue behind. SetInterrupt is cross-thread safe per MSDN and
// returns immediately once dbgeng has armed the interrupt; the next
// WaitForEvent on the engine thread (idle pump or the owning task's inner
// wait) observes the resulting event and calls HandleEventLocked, which
// flips stopped_ to true and writes lastStop_. Our caller-thread poll
// below reads that transition.
//
// The stopped_ / lastStop_ reads from this thread race with the engine
// thread's writes inside HandleEventLocked; it's an advisory snapshot in
// the same sense as Status(). The copy at the end is serialized under m_
// so the record we hand back isn't half-written.
std::string DbgSession::Cancel(StopInfoRec* out)
{
    if (!engineReady_) {
        if (out) {
            std::lock_guard<std::mutex> lk(m_);
            FillStopInfoLocked(out, "none");
            out->stopped = false;
        }
        return "engine not ready";
    }
    if (!active_) {
        if (out) {
            std::lock_guard<std::mutex> lk(m_);
            FillStopInfoLocked(out, "process_exit");
        }
        return "no active session";
    }
    if (stopped_) {
        // Already parked — nothing to interrupt. Return the cached snapshot
        // so the caller's lease-release path still runs.
        if (out) {
            *out = SnapshotStop();
            out->active = active_;
            out->stopped = stopped_;
            out->timed_out = false;
        }
        return "";
    }
    auto control = As<IDebugControl3>(&control3_);
    HRESULT hr = control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
    if (FAILED(hr)) {
        if (out) {
            std::lock_guard<std::mutex> lk(m_);
            FillStopInfoLocked(out, "none");
        }
        return "SetInterrupt failed hr=" + std::to_string(hr);
    }
    // Bounded poll: up to ~2 s in 50 ms slices. The engine's idle pump
    // (or its owning task's WaitForEvent) picks up the injected break
    // and flips stopped_.
    auto deadline = std::chrono::steady_clock::now()
                    + std::chrono::milliseconds(2000);
    while (std::chrono::steady_clock::now() < deadline) {
        if (stopped_ || !active_) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (!out) {
        return "";
    }
    std::lock_guard<std::mutex> lk(m_);
    if (stopped_) {
        *out = SnapshotStop();
        out->active = active_;
        out->stopped = true;
        out->timed_out = false;
        // Surface Cancel's own reason over whatever HandleEventLocked
        // discriminated the event as — the caller asked for a cancel,
        // not a bp hit / exception / step.
        out->stop_reason = "pause";
    } else {
        FillStopInfoLocked(out, "none");
        out->stopped = false;
        out->timed_out = true;
    }
    return "";
}

// Must run on the engine thread. Continues a debugee we interrupted for an
// internal operation: the injected int3 / our bp hits are GO_HANDLED (the
// injected DbgBreakPoint thread must not redispatch — an unhandled int3
// kills the process), foreign single-steps get RF + GO_HANDLED so a stray
// armed DR cannot refire, real exceptions pass GO_NOT_HANDLED.
void DbgSession::ResumeAfterInterrupt()
{
    ULONG st = DEBUG_STATUS_GO;
    bool foreignStep = false;
    if (lastEvKind_ == "exception" && lastEvCode_ == (INT32)0x80000003
        && injectedBreaks_ > 0) {
        injectedBreaks_--;
        st = DEBUG_STATUS_GO_HANDLED;
    } else if (lastEvKind_ == "bp_hw" || lastEvKind_ == "bp_sw") {
        st = DEBUG_STATUS_GO_HANDLED;
    } else if (lastEvKind_ == "exception"
               && lastEvCode_ == (INT32)0x80000003) {
        // an int3 not ours (real __debugbreak in the debugee) — still
        // HANDLED in the interrupt-resume context so the state restores
        st = DEBUG_STATUS_GO_HANDLED;
    } else if (lastEvKind_ == "exception"
               && lastEvCode_ == (INT32)0x80000004) {
        st = DEBUG_STATUS_GO_HANDLED;
        foreignStep = true;
    } else if (lastEvKind_ == "exception") {
        st = DEBUG_STATUS_GO_NOT_HANDLED;
    }
    if (foreignStep) {
        auto regs = As<IDebugRegisters2>(&regs2_);
        ULONG idx = 0;
        DEBUG_VALUE dv{};
        if (SUCCEEDED(regs->GetIndexByName("efl", &idx))
            && SUCCEEDED(regs->GetValue(idx, &dv))) {
            dv.I64 |= 0x10000; // EFLAGS.RF
            dv.Type = DEBUG_VALUE_INT64;
            regs->SetValue(idx, &dv);
        }
    }
    As<IDebugControl3>(&control3_)->SetExecutionStatus(st);
    stopped_ = false;
}

} // namespace pry
