#include "dbg_session.hpp"
#include "../common.h"

#include <dbgeng.h>
#include <objbase.h>

namespace pry {

template <typename T>
static T* As(void** pp)
{
    return reinterpret_cast<T*>(*pp);
}

// forwarder. Old callers pass only (hw, addr, size, access, id) —
// we build a default BpAddParams (no condition/commands/pass_count/one_shot/
// match_tid) and route through the richer overload below. Keeps services_bp.cpp
// building unchanged while services_bp.cpp's new path migrates to BpAddParams.
std::string DbgSession::BpAdd(bool hw, UINT64 addr, UINT32 size, const std::string& access, UINT32* id)
{
    BpAddParams p;
    p.hw = hw;
    p.address = addr;
    p.size = size;
    p.access = access;
    return BpAdd(p, id);
}

// rich BpAdd. After SetOffset, applies:
//   - `pass_count` → SetPassCount. dbgeng counts the pass_count DOWN on each
//     hit and breaks when it reaches 0, so passing N programs the engine to
//     ignore N-1 hits and surface hit N. 0 means "break every hit" (dbgeng's
//     default).
//   - `match_tid` → SetMatchThreadId. Caller supplies the SYSTEM tid; we
//     translate it to the ENGINE tid via the current thread table so the
//     dbgeng filter matches reliably across re-attaches (engine ids are not
//     stable across sessions). An unknown sys-tid surfaces as an error
//     rather than a silent-no-filter arm.
//   - `commands` → SetCommand (dbgeng command list executed at hit).
//   - `condition` → combined into the command string as a j-expression:
//       commands empty :  "j (<cond>) 'gc'; 'gc'"
//       commands set   :  "j (<cond>) '<cmds>'; 'gc'"
//     dbgeng evaluates the j-expression on each hit: when it's true, it runs
//     the quoted command list; when it's false, `gc` (go-continue) resumes
//     the target without surfacing the stop. See WinDbg's `?` and `j`
//     documentation for the exact evaluator semantics.
//   - `one_shot` → appends "; bc <id>; gc" to the final command string so the
//     bp removes itself on the first observed hit and continues the target.
//
// Composition is additive: condition and commands can combine freely. one_shot
// layers on top. A bp with no extensions runs through SetCommand(nullptr),
// preserving the earlier behaviour byte-for-byte.
std::string DbgSession::BpAdd(const BpAddParams& p, UINT32* id)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            return "no active session";
        }
        if (!id) {
            return "nullptr id";
        }
        // dbgeng rejects bp ops on a running target (E_UNEXPECTED): do a
        // transparent break → arm → resume so the caller never sees it.
        bool wasRunning = !stopped_;
        if (wasRunning) {
            if (std::string err = EnsureStopped(5000); !err.empty()) {
                return err;
            }
        }
        // Pre-translate the match-tid (if any) under the stopped engine
        // state, so the SetMatchThreadId call below operates on the fresh
        // thread table and we fail loudly for an unknown sys-tid instead of
        // arming a never-matching filter.
        ULONG engMatchTid = 0;
        bool haveMatchTid = false;
        if (p.match_tid != 0) {
            auto sys = As<IDebugSystemObjects4>(&sysObj4_);
            ULONG num = 0;
            if (SUCCEEDED(sys->GetNumberThreads(&num)) && num) {
                std::vector<ULONG> eng(num), ids(num);
                if (SUCCEEDED(sys->GetThreadIdsByIndex(0, num, eng.data(), ids.data()))) {
                    for (ULONG i = 0; i < num; i++) {
                        if (ids[i] == p.match_tid) {
                            engMatchTid = eng[i];
                            haveMatchTid = true;
                            break;
                        }
                    }
                }
            }
            if (!haveMatchTid) {
                if (wasRunning) {
                    ResumeAfterInterrupt();
                }
                return "match_tid " + std::to_string(p.match_tid)
                       + " not found in engine thread table";
            }
        }

        auto control = As<IDebugControl4>(&control4_);
        IDebugBreakpoint2* bp = nullptr;
        HRESULT hr = control->AddBreakpoint2(p.hw ? DEBUG_BREAKPOINT_DATA : DEBUG_BREAKPOINT_CODE,
                                             DEBUG_ANY_ID, &bp);
        if (FAILED(hr) || !bp) {
            if (wasRunning) {
                ResumeAfterInterrupt();
            }
            return "AddBreakpoint2 failed hr=" + std::to_string(hr);
        }
        bp->SetOffset(p.address);
        if (p.hw) {
            ULONG acc = DEBUG_BREAK_EXECUTE;
            if (p.access == "write") {
                acc = DEBUG_BREAK_WRITE;
            } else if (p.access == "rw") {
                acc = DEBUG_BREAK_READ | DEBUG_BREAK_WRITE;
            } else if (p.access == "read") {
                acc = DEBUG_BREAK_READ;
            }
            bp->SetDataParameters(p.size ? p.size : 1, acc);
        }
        // Pass count: dbgeng's SetPassCount accepts the "break on hit N"
        // value directly — the engine internally decrements until the count
        // reaches 0. 0 (our default) leaves the engine's own default in place
        // ("break every hit").
        if (p.pass_count > 0) {
            bp->SetPassCount(p.pass_count);
        }
        if (haveMatchTid) {
            bp->SetMatchThreadId(engMatchTid);
        }

        // Compose the final command string. The j-expression wrapper is only
        // emitted when `condition` is non-empty; with no condition we hand
        // dbgeng the plain `commands` (or nothing).
        std::string cmd;
        if (!p.condition.empty()) {
            cmd = "j (";
            cmd += p.condition;
            cmd += ") '";
            cmd += p.commands.empty() ? "gc" : p.commands;
            cmd += "'; 'gc'";
        } else if (!p.commands.empty()) {
            cmd = p.commands;
        }
        // one_shot: append "; bc <id>; gc" so the bp deletes itself and the
        // target continues through the first hit. `bc` takes the engine's
        // decimal bp id, which we only know AFTER AddBreakpoint2 publishes
        // the id — read it first, then splice it in.
        ULONG bpId = DEBUG_ANY_ID;
        bp->GetId(&bpId);
        if (p.one_shot && bpId != DEBUG_ANY_ID) {
            if (!cmd.empty()) {
                cmd += "; ";
            }
            cmd += "bc ";
            cmd += std::to_string((unsigned)bpId);
            cmd += "; gc";
        }
        if (!cmd.empty()) {
            bp->SetCommand(cmd.c_str());
        }
        bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);
        *id = (UINT32)bpId;
        if (bpId != DEBUG_ANY_ID) {
            bpIds_.push_back(bpId);
        }
        if (wasRunning) {
            ResumeAfterInterrupt();
        }
        return "";
    });
}

void* DbgSession::FindBpLocked(UINT32 id)
{
    auto control = As<IDebugControl4>(&control4_);
    for (UINT32 known : bpIds_) {
        if (known != id) {
            continue;
        }
        IDebugBreakpoint2* bp = nullptr;
        if (SUCCEEDED(control->GetBreakpointById2(id, &bp))) {
            return bp;
        }
        break;
    }
    return nullptr;
}

std::string DbgSession::BpRemove(UINT32 id)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    bool wasRunning = !stopped_;
    if (wasRunning) {
        if (std::string err = EnsureStopped(5000); !err.empty()) {
            return err;
        }
    }
    IDebugBreakpoint2* bp = nullptr;
    if (FAILED(As<IDebugControl4>(&control4_)->GetBreakpointById2(id, &bp))) {
        if (wasRunning) {
            ResumeAfterInterrupt();
        }
        return "breakpoint not found: " + std::to_string(id);
    }
    As<IDebugControl4>(&control4_)->RemoveBreakpoint2(bp);
    if (wasRunning) {
        ResumeAfterInterrupt();
    }
    return "";
    });
}

std::string DbgSession::BpList(std::vector<BpInfoRec>* out)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    auto control = As<IDebugControl4>(&control4_);
    // dbgeng's own numbered list is authoritative; iterating our shadow
    // `bpIds_` returned duplicates and stale ids after a Detach →
    // Launch/Attach cycle (dbgeng re-uses id 0 for the first bp of each
    // live session, so GetBreakpointById2 resolved every past "0" to the
    // same current bp — the user saw N identical rows). Reset `bpIds_`
    // from this authoritative enumeration so BpRemove/BpSetEnabled still
    // have a consistent ownership set.
    bpIds_.clear();
    ULONG num = 0;
    if (FAILED(control->GetNumberBreakpoints(&num))) {
        return "GetNumberBreakpoints failed";
    }
    for (ULONG i = 0; i < num; i++) {
        IDebugBreakpoint2* bp = nullptr;
        if (FAILED(control->GetBreakpointByIndex2(i, &bp)) || !bp) {
            continue;
        }
        BpInfoRec info;
        ULONG bpId = 0;
        bp->GetId(&bpId);
        info.id = bpId;
        info.pid = pid_;  // dbgeng single-session: every live bp is in this pid
        bpIds_.push_back(bpId);
        ULONG64 off = 0;
        bp->GetOffset(&off);
        info.address = off;
        ULONG flags = 0;
        bp->GetFlags(&flags);
        info.enabled = (flags & DEBUG_BREAKPOINT_ENABLED) != 0;
        // both GetType out-params are required; passing nullptr AVs the process
        ULONG type = 0, procType = 0;
        bp->GetType(&type, &procType);
        info.kind = type == DEBUG_BREAKPOINT_DATA ? "hw" : "sw";
        if (type == DEBUG_BREAKPOINT_DATA) {
            ULONG size = 0, acc = 0;
            bp->GetDataParameters(&size, &acc);
            info.access = acc & DEBUG_BREAK_WRITE
                              ? ((acc & DEBUG_BREAK_READ) ? "rw" : "write")
                              : (acc & DEBUG_BREAK_READ ? "read" : "exec");
        }
        out->push_back(info);
        bp->Release();
    }
    return "";
    });
}

std::string DbgSession::BpSetEnabled(UINT32 id, bool enabled)
{
    return RunOnEngine([&]() -> std::string {
    if (!active_) {
        return "no active session";
    }
    bool wasRunning = !stopped_;
    if (wasRunning) {
        if (std::string err = EnsureStopped(5000); !err.empty()) {
            return err;
        }
    }
    IDebugBreakpoint2* bp = nullptr;
    if (FAILED(As<IDebugControl4>(&control4_)->GetBreakpointById2(id, &bp))) {
        if (wasRunning) {
            ResumeAfterInterrupt();
        }
        return "breakpoint not found: " + std::to_string(id);
    }
    if (enabled) {
        bp->AddFlags(DEBUG_BREAKPOINT_ENABLED);
    } else {
        bp->RemoveFlags(DEBUG_BREAKPOINT_ENABLED);
    }
    if (wasRunning) {
        ResumeAfterInterrupt();
    }
    return "";
    });
}

} // namespace pry
