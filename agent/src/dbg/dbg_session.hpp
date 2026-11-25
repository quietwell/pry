#pragma once

#include <windows.h>

#include "../events.hpp"

#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace pry {

struct DebugEventRec {
    UINT64 seq = 0;
    // bp_sw | bp_hw | exception | process_exit | thread_create | thread_exit |
    //   module_load | module_unload | session_status
    std::string kind;
    UINT32 pid = 0;
    UINT32 tid = 0;
    UINT64 address = 0;
    INT32 code = 0;
    std::string desc;
    UINT64 ts = 0;
    // typed fields the gRPC layer now mirrors into
    // DebugEvent.first_chance / DebugEvent.module_base. first_chance is only
    // meaningful on kind=="exception"; module_base is only meaningful on
    // kind=="module_load" / "module_unload" (and equals `address` there — the
    // older `address`-is-module-base contract is preserved).
    bool first_chance = false;
    UINT64 module_base = 0;
    // breakpoint id on bp_sw / bp_hw events; 0 otherwise.
    UINT32 bp_id = 0;
};

struct RegsRec {
    UINT64 rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    UINT64 r8, r9, r10, r11, r12, r13, r14, r15;
    UINT64 rip;
    UINT32 rflags;
    UINT64 dr0, dr1, dr2, dr3, dr6, dr7;
};

struct ThreadRec {
    UINT32 tid = 0;
    UINT64 teb = 0;
    UINT64 start = 0;
    UINT32 suspend_count = 0;
};

struct StackFrameRec {
    UINT64 frame = 0;
    UINT64 ret = 0;
    std::string symbol;
    UINT64 displacement = 0;
    std::string module;
};

struct RegionRec {
    UINT64 base = 0, size = 0;
    UINT32 state = 0, protect = 0, type = 0;
    std::string module;
};

struct BpInfoRec {
    UINT32 id = 0;
    std::string kind; // sw | hw
    UINT64 address = 0;
    std::string access;
    bool enabled = false;
    // dbgeng is single-session, so every live bp here belongs to the
    // attached pid — tracked so bp_manage(list) reports it alongside the
    // driver bps instead of leaving it 0 and leading the caller to
    // believe the bp isn't bound to any process.
    UINT32 pid = 0;
};

// richer bp semantics (condition, commands, pass_count,
// one_shot, match_tid). Added as a params struct so the surface grows
// additively — the legacy 5-arg BpAdd stays wire-compatible via a thin
// forwarder that constructs a default-filled BpAddParams. gRPC maps every
// field 1:1 from BpAddRequest; see dbg_bp.cpp for the dbgeng command
// composition rules.
struct BpAddParams {
    bool hw = false;
    UINT64 address = 0;
    UINT32 size = 0;
    std::string access;      // hw: "exec" | "write" | "rw" | "read"
    std::string condition;   // dbgeng j-expression; empty = unconditional
    std::string commands;    // dbgeng command list executed at hit
    UINT32 pass_count = 0;   // 0 = break on every hit; N = break on hit N
    bool one_shot = false;   // auto-remove the bp on first observed hit
    UINT32 match_tid = 0;    // 0 = any thread; else sys-tid filter
};

// --------------------------------------------- StopInfo ----
// Mirrors the proto's StopInfo one-for-one. Named StopInfoRec (codebase
// convention: proto `Foo` ↔ C++ `FooRec`, e.g. DebugEvent ↔ DebugEventRec)
// so the C++ struct doesn't collide with the generated proto class
// `pry::StopInfo` in the same namespace. gRPC layer copies field-by-field;
// keep both shapes in sync with proto/pry.proto.
//
// The signature-level alias `StopInfo` is also exported so callers can write
// `DbgSession::Status(StopInfo*)` as the plan documents while the underlying
// record stays `StopInfoRec`.
struct StopInfoRec {
    bool active = false;
    bool stopped = false;
    bool timed_out = false;
    UINT32 pid = 0;
    UINT32 tid = 0;
    UINT64 rip = 0;              // zero-extended EIP on x86 / WOW64
    std::string symbol;          // "module!sym+0xN"; empty if unresolved
    std::string stop_reason;     // see proto StopInfo.stop_reason
    UINT64 seq = 0;
    std::string arch;            // "x64" | "x86" | "wow64"
    UINT32 exception_code = 0;
    bool first_chance = false;
    UINT32 bp_id = 0;
    // GPR snapshot filled automatically when
    // stop_reason == "exception" or when the verb's include_context flag
    // is set. (name, value) pairs; name follows GprNamesForArch's set
    // ("rax" .. "r15", "rip", "rflags") on x64, ("eax" .. "edi", "eip",
    // "rflags") on x86 / WOW64. Empty when not requested or when GetRegs
    // failed outright.
    std::vector<std::pair<std::string, UINT64>> regs;
    // 16 bytes starting at rip, lowercase hex,
    // no separators. Filled alongside `regs`. Empty when ReadVirtual
    // failed or the fill was not requested.
    std::string bytes_at_rip_hex;
};

enum class TargetArch { Unknown, X64, X86, WOW64 };

// single-line disasm record for Debug.Disasm RPC.
struct DisasmLineRec {
    UINT64 address = 0;
    std::string bytes_hex;
    std::string text;
};

// loaded-module record for Debug.Modules RPC.
struct ModuleInfoRec {
    UINT64 base = 0;
    UINT64 size = 0;
    std::string name;
    std::string path;
    UINT32 timestamp = 0;
    bool loaded = true;
};

// single dbgeng session (single active target per plan)
class DbgSession {
public:
    static DbgSession& Instance();

    std::string Launch(const std::string& cmdline, const std::string& workDir, bool breakOnEntry,
                       UINT32* pid, UINT32* tid);
    // Launch overload carrying the symmetric `monitor` flag from
    // AttachRequest. The 5-arg forwarder above calls this with monitor=false.
    std::string Launch(const std::string& cmdline, const std::string& workDir, bool breakOnEntry,
                       bool monitor, UINT32* pid, UINT32* tid);
    std::string Attach(UINT32 pid, bool monitor = false);
    std::string Detach(bool kill);

    // state-loop verbs. Every waiting call clamps timeoutMs to
    // [0, 30000]; 0 means "default" (20000 for run/wait, 5000 for pause).
    // Timeouts return "" (ok) with out->timed_out = true — never a hard error.
    //
    // each verb grows an `includeContext` trailing bool (default
    // false). When set, the final StopInfoRec is enriched with
    // `regs` + `bytes_at_rip_hex` (via FillCrashContextLocked). Exception
    // stops fill them unconditionally regardless of the flag.
    std::string Continue(StopInfoRec* out, bool includeContext = false);
    std::string Step(bool over, UINT64 count, StopInfoRec* out, bool includeContext = false);
    std::string Status(StopInfoRec* out, bool includeContext = false);
    std::string Pause(UINT32 timeoutMs, StopInfoRec* out, bool includeContext = false);
    std::string Wait(UINT32 timeoutMs, StopInfoRec* out, bool includeContext = false);
    std::string Run(UINT32 timeoutMs, StopInfoRec* out, bool includeContext = false);
    std::string RunTo(UINT64 address, UINT32 timeoutMs, StopInfoRec* out,
                      bool includeContext = false);
    std::string StepOut(UINT32 timeoutMs, StopInfoRec* out, bool includeContext = false);

    // SetInterrupt-backed cancel. Safe to call while another task
    // owns the engine thread (dbgeng's SetInterrupt is cross-thread safe),
    // which is the whole point — a wedged `.reload` or symbol-server stall
    // has no other abort primitive. Polls `stopped_` for up to ~2 s after
    // issuing the interrupt. On success, fills *out from lastStop_ with
    // reason="pause". On timeout, *out reflects the live state with
    // stopped=false.
    std::string Cancel(StopInfoRec* out);

    // Source-compat forwarders to the StopInfo* overloads (nullptr = no echo).
    std::string Continue() { return Continue(nullptr, false); }
    std::string Step(bool over, UINT64 count) { return Step(over, count, nullptr, false); }

    bool IsActive() const { return active_; }
    bool IsStopped() const { return stopped_; }
    bool MonitorMode() const { return monitor_; }
    UINT32 CurrentPid() const { return pid_; }

    // Existing single-tid overloads (kept for source compat). The explicit-tid
    // overloads below are the ones gRPC uses.
    std::string GetRegs(RegsRec* out);
    std::string SetRegs(const RegsRec& r, bool applyGprs, bool applyRip, bool applyRflags, bool applyDr);
    std::string Stacktrace(UINT32 maxFrames, std::vector<StackFrameRec>* out);

    // explicit-tid overloads with per-register warnings surfaced
    // through *warn (B7 partial-regs fix). tid=0 uses the engine's current
    // thread; non-zero temporarily SetCurrentThreadId's to that tid.
    // Implementations live in Agent 3's dbg_state.cpp.
    std::string GetRegs(RegsRec* out, UINT32 tid, std::vector<std::string>* warn);
    std::string SetRegs(const RegsRec& r, bool applyGprs, bool applyRip, bool applyRflags,
                        bool applyDr, UINT32 tid, std::vector<std::string>* warn);
    std::string Stacktrace(UINT32 maxFrames, UINT32 tid, std::vector<StackFrameRec>* out);

    std::string GetThreads(std::vector<ThreadRec>* out, UINT32* currentTid);
    std::string ReadMem(UINT64 addr, UINT64 len, std::vector<BYTE>* out);
    std::string WriteMem(UINT64 addr, const void* data, size_t len);
    std::string Regions(std::vector<RegionRec>* out);
    std::string Execute(const std::string& command, std::string* output); // raw dbgeng passthrough
    // post-command state echo. The engine re-reads
    // GetExecutionStatus after Execute(...) and sets stopped_/active_ so a
    // `g` / `q` / `.detach` drives the session state machine honestly. `state`
    // is filled from lastStop_ on success; may be nullptr for the legacy
    // one-arg-output path (which forwards here).
    std::string Execute(const std::string& command, std::string* output, StopInfoRec* state);

    // new informational / support verbs. Implementations land in a
    // follow-up TU (Agent 3/4 scope); Agent 2 only declares them so the
    // proto<->C++ surface types line up during parallel work.
    std::string Disasm(UINT64 address, UINT32 count, std::vector<DisasmLineRec>* out);
    std::string Resolve(const std::string& symbol, UINT64* addr, std::string* canonical);
    std::string DumpTo(const std::string& path, const std::string& kind, UINT64* bytes);
    std::string Modules(std::vector<ModuleInfoRec>* out);
    std::string SetExceptionFilter(UINT32 code, const std::string& action);

    std::string BpAdd(bool hw, UINT64 addr, UINT32 size, const std::string& access, UINT32* id);
    // params-struct overload. The 5-arg legacy forwarder above
    // constructs a default-filled BpAddParams and delegates here — new callers
    // (services_bp.cpp) use this directly to pass condition/commands/
    // pass_count/one_shot/match_tid.
    std::string BpAdd(const BpAddParams& p, UINT32* id);
    std::string BpRemove(UINT32 id);
    std::string BpList(std::vector<BpInfoRec>* out);
    std::string BpSetEnabled(UINT32 id, bool enabled);

    EventQueue<DebugEventRec>& Events() { return events_; }
    void Shutdown();

private:
    DbgSession() = default;
    std::string InitEngine();
    void EngineLoop();
    std::string RunOnEngine(std::function<std::string()> f);
    void HandleEventLocked();
    UINT32 SysTidFromEngineIdLocked(ULONG engTid);
    void* FindBpLocked(UINT32 id);
    // engine-thread-only: stop a running debugee (DebugBreakProcess is
    // deterministic — SetInterrupt's "next suspension point" can stall on a
    // quiet target) and resume the state we interrupted (GO_HANDLED for the
    // injected int3 / bp hits, GO_NOT_HANDLED for real exceptions).
    std::string EnsureStopped(UINT32 timeoutMs);
    void ResumeAfterInterrupt();

    // engine-thread-only helpers. WaitForStop pumps WaitForEvent in
    // short slices up to timeoutMs (zero-slice fallback honoured by dbgeng);
    // FillStopInfoLocked snapshots engine state into *out (reason supplied by
    // caller); DetectArchLocked memoizes `arch_` on first non-zero
    // GetEffectiveProcessorType.
    //
    // FillStopInfoLocked grows an `includeContext` trailing bool.
    // When true (or when `reason == "exception"`), the function tops the
    // snapshot up via FillCrashContextLocked. Existing callers that stay
    // on the default (false) keep the previous behavior.
    std::string WaitForStop(UINT32 timeoutMs, StopInfoRec* out);
    void FillStopInfoLocked(StopInfoRec* out, const std::string& reason,
                            bool includeContext = false);
    // crash-context enrichment helper. Reads the GPR set and 16
    // bytes at rip into *out. Best-effort: a failed GetRegs or ReadVirtual
    // leaves the respective field empty; `stop_reason` and `timed_out`
    // never change. Engine-thread-only; caller holds the engine (either
    // via RunOnEngine or from HandleEventLocked on the engine thread).
    void FillCrashContextLocked(StopInfoRec* out);
    TargetArch DetectArchLocked();
    // shared monitor-mode auto-resume (bp / single-step / injected
    // int3). Extracted so WaitForStop can replay the same resume logic the
    // EngineLoop runs when a task owns the engine thread.
    void ResumeMonitorEventLocked();
    // clamp a public waiting-call timeout to [0, cap]; 0 → default.
    static UINT32 ClampTimeout(UINT32 req, UINT32 defMs);

    void* client5_ = nullptr;   // IDebugClient5
    void* control3_ = nullptr;  // IDebugControl3
    void* control4_ = nullptr;  // IDebugControl4
    void* regs2_ = nullptr;     // IDebugRegisters2
    void* spaces4_ = nullptr;   // IDebugDataSpaces4
    void* sysObj4_ = nullptr;   // IDebugSystemObjects4
    void* symbols3_ = nullptr;  // IDebugSymbols3

    // Read cross-thread by Cancel() (the one entry point that deliberately
    // runs off the engine thread), so atomics rather than plain bools.
    std::atomic<bool> engineReady_{false};
    std::atomic<bool> active_{false};
    std::atomic<bool> stopped_{false};
    // monitor mode (Attach monitor=true): bp_hw/bp_sw/single-step hits
    // auto-resume so observation doesn't freeze the target — the
    // passive fallback for kernel-side bp trapping, which a hypervisor
    // can make impossible (descriptor-table exiting / EPT-RO IDT).
    bool monitor_ = false;
    // outstanding int3 events from OUR DebugBreakProcess injections — the
    // pump must GO_HANDLED them (a foreign int3 passed NOT_HANDLED becomes
    // an unhandled exception and kills the debugee)
    int injectedBreaks_ = 0;
    std::string lastEvKind_;
    INT32 lastEvCode_ = 0;
    UINT32 pid_ = 0;
    UINT64 seq_ = 0;
    std::vector<UINT32> bpIds_; // engine-level breakpoint ids we created

    // cached stop state. Written from HandleEventLocked (and from
    // the baseline initializer on Launch/Attach events). Status()/Pause()/
    // Wait()/Run()/RunTo()/StepOut()/Continue()/Step() copy from this —
    // never the other way around.
    StopInfoRec lastStop_;
    // Mechanics audit P1: lastStop_ is WRITTEN only on the engine thread,
    // always through PublishStop / ResetStop (under stopM_); engine-thread
    // code may read it lock-free, every other thread copies it with
    // SnapshotStop(). Cancel() used to copy it while HandleEventLocked was
    // assigning it (torn std::string members).
    mutable std::mutex stopM_;
    void PublishStop(StopInfoRec s);
    void ResetStop();
    StopInfoRec SnapshotStop() const;
    // next-stop reason refinement. Verbs that know a user intent
    // the event itself cannot carry (Step → "step", Pause's EnsureStopped-
    // injected int3 → "pause") set this hint before resuming; HandleEvent-
    // Locked consumes and clears it inside the event path, so lastStop_
    // stays written only from HandleEventLocked.
    std::string nextReasonHint_;
    // memoized target architecture (set by DetectArchLocked on the
    // first HandleEventLocked after dbgeng has published a processor type).
    TargetArch arch_ = TargetArch::Unknown;

    // single dedicated engine thread: dbgeng on 24H2+ delivers events only to
    // the thread that owns the session - every dbgeng call (create, GO, wait,
    // interact) is serialized onto EngineLoop via RunOnEngine
    std::mutex m_; // guards flags/events shared with RPC-facing accessors
    std::thread engineThread_;
    std::mutex qm_;
    std::condition_variable qcv_;
    std::deque<std::shared_ptr<std::packaged_task<std::string()>>> q_;
    bool qOpen_ = true;
    bool shutdown_ = false;
    EventQueue<DebugEventRec> events_;
};

} // namespace pry
