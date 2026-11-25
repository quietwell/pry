#include "dbg_session.hpp"
#include "../common.h"

#include <dbgeng.h>
#include <objbase.h>

#include <cstdio>
#include <sstream>

namespace pry {

template <typename T>
static T* As(void** pp)
{
    return reinterpret_cast<T*>(*pp);
}

// RAII guard that temporarily swaps the engine's current thread to
// the engine-tid that owns `sysTid`, and restores the previous engine-tid on
// destruction. A `sysTid == 0` input leaves the current thread untouched (the
// no-tid case — caller wants whatever dbgeng's current thread is). Non-zero
// inputs that don't map to any known thread leave the engine thread alone and
// mark the guard as inactive so operator bool() reports false.
struct EngineThreadScope {
    EngineThreadScope(IDebugSystemObjects4* sys, UINT32 sysTid) : sys_(sys)
    {
        if (!sys_ || sysTid == 0) {
            return;
        }
        ULONG num = 0;
        if (FAILED(sys_->GetNumberThreads(&num)) || !num) {
            return;
        }
        std::vector<ULONG> eng(num), ids(num);
        if (FAILED(sys_->GetThreadIdsByIndex(0, num, eng.data(), ids.data()))) {
            return;
        }
        ULONG targetEng = 0;
        bool found = false;
        for (ULONG i = 0; i < num; i++) {
            if (ids[i] == sysTid) {
                targetEng = eng[i];
                found = true;
                break;
            }
        }
        if (!found) {
            return;
        }
        if (FAILED(sys_->GetCurrentThreadId(&prev_))) {
            return; // no safe restore point — do not arm
        }
        if (SUCCEEDED(sys_->SetCurrentThreadId(targetEng))) {
            armed_ = true;
        }
    }
    ~EngineThreadScope()
    {
        if (armed_ && sys_) {
            sys_->SetCurrentThreadId(prev_);
        }
    }
    bool armed() const { return armed_; }

private:
    IDebugSystemObjects4* sys_ = nullptr;
    ULONG prev_ = 0;
    bool armed_ = false;
};

// arch-aware GPR name list. Returns the register names for
// the current effective processor type. For x64 → rax..r15,rip; for x86 /
// WOW64 → eax..edi,eip. `ipName` is the matching instruction-pointer name
// ("rip" or "eip"). The caller layers DRx + rflags on top.
static void GprNamesForArch(TargetArch a, const char* const** outNames,
                            size_t* outCount, const char** ipName)
{
    static const char* kX64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    static const char* kX86[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    if (a == TargetArch::X86 || a == TargetArch::WOW64) {
        *outNames = kX86;
        *outCount = sizeof(kX86) / sizeof(kX86[0]);
        *ipName = "eip";
        return;
    }
    *outNames = kX64;
    *outCount = sizeof(kX64) / sizeof(kX64[0]);
    *ipName = "rip";
}

// no-tid forwarders. Delegate to the explicit-tid overloads with
// tid=0 (meaning "current thread") and nullptr warnings — callers that don't
// care about partial-read details get the previous fail-fast semantics via
// the overload returning non-empty on zero reads.
std::string DbgSession::GetRegs(RegsRec* out)
{
    return GetRegs(out, 0, nullptr);
}

std::string DbgSession::SetRegs(const RegsRec& r, bool applyGprs, bool applyRip,
                                bool applyRflags, bool applyDr)
{
    return SetRegs(r, applyGprs, applyRip, applyRflags, applyDr, 0, nullptr);
}

std::string DbgSession::Stacktrace(UINT32 maxFrames, std::vector<StackFrameRec>* out)
{
    return Stacktrace(maxFrames, 0, out);
}

std::string DbgSession::GetRegs(RegsRec* out, UINT32 tid, std::vector<std::string>* warn)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_ || !stopped_) {
            return "target not stopped";
        }
        if (!out) {
            return "nullptr out";
        }
        *out = RegsRec{};
        auto regs = As<IDebugRegisters2>(&regs2_);
        auto sys = As<IDebugSystemObjects4>(&sysObj4_);
        EngineThreadScope scope(sys, tid);
        if (tid != 0 && !scope.armed()) {
            return "tid " + std::to_string(tid) + " not found in engine thread table";
        }

        // B7: collect per-register failures instead of failing the whole call.
        // A failed read pushes "<name>:<reason>" into *warn and leaves the
        // field zero. Return non-empty only when ZERO registers were read.
        unsigned okReads = 0;
        auto note = [&](const char* name, const char* reason) {
            if (warn) {
                warn->emplace_back(std::string(name) + ":" + reason);
            }
        };
        auto get1 = [&](const char* name, UINT64* outVal) -> bool {
            ULONG idx = 0;
            if (FAILED(regs->GetIndexByName(name, &idx))) {
                note(name, "unknown_name");
                return false;
            }
            DEBUG_VALUE dv{};
            HRESULT hr = regs->GetValue(idx, &dv);
            if (FAILED(hr)) {
                char buf[32];
                _snprintf_s(buf, _TRUNCATE, "hr=0x%08lx", (unsigned long)hr);
                note(name, buf);
                return false;
            }
            *outVal = dv.I64;
            okReads++;
            return true;
        };

        // B9 (arch awareness): pick the right GPR set. On x86 / WOW64 dbgeng
        // GetValue(dv.I64) still returns a zero-extended UINT64 for the 32-bit
        // register, which RegsRec stores as 64-bit — the wire sees a plain
        // UINT64 either way.
        const TargetArch arch = DetectArchLocked();
        const char* const* gprNames = nullptr;
        size_t gprCount = 0;
        const char* ipName = "rip";
        GprNamesForArch(arch, &gprNames, &gprCount, &ipName);

        UINT64* const allFields[] = {&out->rax, &out->rcx, &out->rdx, &out->rbx,
                                     &out->rsp, &out->rbp, &out->rsi, &out->rdi,
                                     &out->r8,  &out->r9,  &out->r10, &out->r11,
                                     &out->r12, &out->r13, &out->r14, &out->r15};
        for (size_t i = 0; i < gprCount; i++) {
            (void)get1(gprNames[i], allFields[i]);
        }
        // IP (rip or eip): stored in out->rip uniformly.
        (void)get1(ipName, &out->rip);
        // rflags: dbgeng calls it "efl" on every arch.
        UINT64 rflags = 0;
        if (get1("efl", &rflags)) {
            out->rflags = (UINT32)rflags;
        }
        // DRx: B2 fix — read as UINT64 (RegsRec already widened). On x86
        // targets dbgeng still exposes the same DRx names; any failure is
        // surfaced through `warn` and skipped.
        (void)get1("dr0", &out->dr0);
        (void)get1("dr1", &out->dr1);
        (void)get1("dr2", &out->dr2);
        (void)get1("dr3", &out->dr3);
        (void)get1("dr6", &out->dr6);
        (void)get1("dr7", &out->dr7);

        if (okReads == 0) {
            return "no registers readable";
        }
        return "";
    });
}

std::string DbgSession::SetRegs(const RegsRec& r, bool applyGprs, bool applyRip,
                                bool applyRflags, bool applyDr, UINT32 tid,
                                std::vector<std::string>* warn)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_ || !stopped_) {
            return "target not stopped";
        }
        auto regs = As<IDebugRegisters2>(&regs2_);
        auto sys = As<IDebugSystemObjects4>(&sysObj4_);
        EngineThreadScope scope(sys, tid);
        if (tid != 0 && !scope.armed()) {
            return "tid " + std::to_string(tid) + " not found in engine thread table";
        }

        unsigned okWrites = 0;
        unsigned attempted = 0;
        auto note = [&](const char* name, const char* reason) {
            if (warn) {
                warn->emplace_back(std::string(name) + ":" + reason);
            }
        };
        auto set1 = [&](const char* name, UINT64 v) -> bool {
            attempted++;
            ULONG idx = 0;
            if (FAILED(regs->GetIndexByName(name, &idx))) {
                note(name, "unknown_name");
                return false;
            }
            DEBUG_VALUE dv{};
            dv.I64 = v;
            dv.Type = DEBUG_VALUE_INT64;
            HRESULT hr = regs->SetValue(idx, &dv);
            if (FAILED(hr)) {
                char buf[32];
                _snprintf_s(buf, _TRUNCATE, "hr=0x%08lx", (unsigned long)hr);
                note(name, buf);
                return false;
            }
            okWrites++;
            return true;
        };

        const TargetArch arch = DetectArchLocked();
        const char* const* gprNames = nullptr;
        size_t gprCount = 0;
        const char* ipName = "rip";
        GprNamesForArch(arch, &gprNames, &gprCount, &ipName);

        if (applyGprs) {
            // B1 fix: write every GPR unconditionally. The previous guard
            // `if (vals[i] && FAILED(...))` silently skipped vals[i] == 0, so
            // SetRegs(rax=0) was a no-op. Zero is a valid register value.
            const UINT64 vals64[] = {r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi,
                                     r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15};
            for (size_t i = 0; i < gprCount; i++) {
                (void)set1(gprNames[i], vals64[i]);
            }
        }
        if (applyRip) {
            (void)set1(ipName, r.rip);
        }
        if (applyRflags) {
            (void)set1("efl", (UINT64)r.rflags);
        }
        if (applyDr) {
            // B2 fix: write DRx as full 64-bit values. The old path happened
            // to work only because callers never requested >32-bit values; the
            // field width is correct at this layer now.
            (void)set1("dr0", r.dr0);
            (void)set1("dr1", r.dr1);
            (void)set1("dr2", r.dr2);
            (void)set1("dr3", r.dr3);
            (void)set1("dr6", r.dr6);
            (void)set1("dr7", r.dr7);
        }
        if (attempted && okWrites == 0) {
            return "no registers writable";
        }
        return "";
    });
}

std::string DbgSession::GetThreads(std::vector<ThreadRec>* out, UINT32* currentTid)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            return "no active session";
        }
        auto sys = As<IDebugSystemObjects4>(&sysObj4_);
        auto control4 = As<IDebugControl4>(&control4_);
        ULONG num = 0, cur = 0;
        if (FAILED(sys->GetNumberThreads(&num))) {
            return "GetNumberThreads failed";
        }
        std::vector<ULONG> eng(num), ids(num);
        if (FAILED(sys->GetThreadIdsByIndex(0, num, eng.data(), ids.data()))) {
            return "GetThreadIdsByIndex failed";
        }
        sys->GetCurrentThreadId(&cur);
        for (ULONG i = 0; i < num; i++) {
            ThreadRec t;
            t.tid = ids[i];
            if (SUCCEEDED(sys->SetCurrentThreadId(eng[i]))) {
                ULONG64 off = 0;
                if (SUCCEEDED(sys->GetCurrentThreadDataOffset(&off))) {
                    t.teb = off;
                }
                // B5: suspend_count. dbgeng's IDebugSystemObjects4 has no direct
                // query; use the Win32 SuspendThread-returns-previous-count idiom
                // (SuspendThread + ResumeThread net-zero the suspend state). Only
                // runs on a stopped target, so the pulse doesn't disturb a live
                // debugee any more than dbgeng already does.
                HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ids[i]);
                if (th) {
                    DWORD prev = SuspendThread(th);
                    if (prev != (DWORD)-1) {
                        t.suspend_count = (UINT32)prev;
                        ResumeThread(th);
                    }
                    CloseHandle(th);
                }
                // B5: thread start address. Approach: walk the thread's stack
                // and use the bottom-most frame's InstructionOffset as the
                // entry proxy. GetFunctionEntryByOffset (per the plan) returns
                // the function table entry rather than the thread's start, and
                // reading the TEB's Win32StartAddress needs a struct offset
                // that changes between TEB / TEB32 layouts — the bottom-of-
                // stack approach is deterministic across x64 and WOW64 and
                // doesn't require ntdll imports. Only the engine thread needs
                // to be stopped; stack walks are safe on suspended threads.
                if (stopped_) {
                    DEBUG_STACK_FRAME frames[64]{};
                    ULONG filled = 0;
                    if (SUCCEEDED(control4->GetStackTrace(0, 0, 0, frames,
                                                         (ULONG)(sizeof(frames) / sizeof(frames[0])),
                                                         &filled))
                        && filled) {
                        t.start = frames[filled - 1].InstructionOffset;
                    }
                }
            }
            out->push_back(t);
            if (eng[i] == cur) {
                *currentTid = ids[i];
            }
        }
        // restore the engine's current thread so later regs/stack calls act on
        // the event thread, not the last enumerated one
        sys->SetCurrentThreadId(cur);
        return "";
    });
}

std::string DbgSession::Stacktrace(UINT32 maxFrames, UINT32 tid, std::vector<StackFrameRec>* out)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_ || !stopped_) {
            return "target not stopped";
        }
        auto sys = As<IDebugSystemObjects4>(&sysObj4_);
        auto control = As<IDebugControl4>(&control4_);
        auto symbols = As<IDebugSymbols3>(&symbols3_);
        EngineThreadScope scope(sys, tid);
        if (tid != 0 && !scope.armed()) {
            return "tid " + std::to_string(tid) + " not found in engine thread table";
        }
        if (maxFrames == 0) {
            maxFrames = 64;
        }
        std::vector<DEBUG_STACK_FRAME> frames(maxFrames);
        ULONG filled = 0;
        if (FAILED(control->GetStackTrace(0, 0, 0, frames.data(), maxFrames, &filled))) {
            return "GetStackTrace failed";
        }
        char symBuf[512];
        char modBuf[260];
        for (ULONG i = 0; i < filled; i++) {
            StackFrameRec f;
            f.frame = frames[i].FrameOffset;
            f.ret = frames[i].ReturnOffset;
            ULONG sizeNeeded = 0;
            ULONG64 disp = 0;
            if (SUCCEEDED(symbols->GetNameByOffset(frames[i].InstructionOffset,
                                                   symBuf, sizeof(symBuf), &sizeNeeded, &disp))) {
                f.symbol = symBuf;
                f.displacement = disp;
            }
            // B5: resolve the owning module for each frame. Non-fatal on
            // miss (unmapped region, synthetic frame) — leave module empty
            // so downstream renders "frame 0: <no symbol>" cleanly instead
            // of failing the whole stack call.
            ULONG modIdx = 0;
            ULONG64 modBase = 0;
            if (SUCCEEDED(symbols->GetModuleByOffset(frames[i].InstructionOffset,
                                                    0, &modIdx, &modBase))) {
                ULONG needed = 0;
                if (SUCCEEDED(symbols->GetModuleNameString(DEBUG_MODNAME_MODULE,
                                                          modIdx, modBase,
                                                          modBuf, sizeof(modBuf),
                                                          &needed))
                    && modBuf[0]) {
                    f.module = modBuf;
                }
            }
            out->push_back(f);
        }
        return "";
    });
}

// Resolve — symbol-to-address lookup via IDebugSymbols3::GetOffsetByName.
// Accepts "module!name" (preferred) and bare symbol names (dbgeng searches all
// loaded modules). On success, fills *addr and canonical "module!name+0xNN" via
// GetNameByOffset so the caller sees exactly what dbgeng resolved to.
std::string DbgSession::Resolve(const std::string& symbol, UINT64* addr, std::string* canonical)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            return "no active session";
        }
        if (!addr) {
            return "nullptr addr";
        }
        if (symbol.empty()) {
            return "empty symbol";
        }
        auto symbols = As<IDebugSymbols3>(&symbols3_);
        ULONG64 off = 0;
        HRESULT hr = symbols->GetOffsetByName(symbol.c_str(), &off);
        if (FAILED(hr)) {
            return "GetOffsetByName failed hr=" + std::to_string(hr);
        }
        *addr = off;
        if (canonical) {
            char name[512] = {};
            ULONG needed = 0;
            ULONG64 disp = 0;
            if (SUCCEEDED(symbols->GetNameByOffset(off, name, sizeof(name), &needed, &disp))
                && name[0]) {
                char buf[640];
                _snprintf_s(buf, _TRUNCATE, "%s+0x%llx", name, (unsigned long long)disp);
                *canonical = buf;
            }
        }
        return "";
    });
}

// Modules — enumerate loaded modules via IDebugSymbols3. Returns
// name (module alias, e.g. "ntdll"), path (full image path), base, size,
// timestamp, loaded flag. `loaded=false` is set for modules the engine has
// seen unloaded (DEBUG_MODULE_UNLOADED in params.Flags).
std::string DbgSession::Modules(std::vector<ModuleInfoRec>* out)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            return "no active session";
        }
        if (!out) {
            return "nullptr out";
        }
        auto symbols = As<IDebugSymbols3>(&symbols3_);
        ULONG loaded = 0, unloaded = 0;
        if (FAILED(symbols->GetNumberModules(&loaded, &unloaded))) {
            return "GetNumberModules failed";
        }
        const ULONG total = loaded + unloaded;
        for (ULONG i = 0; i < total; i++) {
            ULONG64 base = 0;
            if (FAILED(symbols->GetModuleByIndex(i, &base))) {
                continue;
            }
            DEBUG_MODULE_PARAMETERS params{};
            if (FAILED(symbols->GetModuleParameters(1, &base, 0, &params))) {
                continue;
            }
            ModuleInfoRec rec;
            rec.base = base;
            rec.size = params.Size;
            rec.timestamp = params.TimeDateStamp;
            rec.loaded = (params.Flags & DEBUG_MODULE_UNLOADED) == 0;
            char name[260] = {};
            ULONG needed = 0;
            if (SUCCEEDED(symbols->GetModuleNameString(DEBUG_MODNAME_MODULE, i, base,
                                                      name, sizeof(name), &needed))
                && name[0]) {
                rec.name = name;
            }
            char imgPath[260] = {};
            if (SUCCEEDED(symbols->GetModuleNameString(DEBUG_MODNAME_IMAGE, i, base,
                                                      imgPath, sizeof(imgPath), &needed))
                && imgPath[0]) {
                rec.path = imgPath;
            }
            out->push_back(std::move(rec));
        }
        return "";
    });
}

// crash-context enrichment. Fills out->regs (arch-aware GPR set
// + rip + rflags) and out->bytes_at_rip_hex (16 bytes at rip, lowercase
// hex). Engine-thread-only — invoked from inside FillStopInfoLocked which
// is only reached either from HandleEventLocked (engine thread) or from a
// RunOnEngine task body.
//
// Best-effort semantics:
//   - A failed GetValue leaves that one register out of out->regs.
//   - A failed ReadVirtual leaves bytes_at_rip_hex empty.
//   - Neither failure touches stop_reason or timed_out.
void DbgSession::FillCrashContextLocked(StopInfoRec* out)
{
    if (!out || !engineReady_ || !active_ || !stopped_) {
        return;
    }
    auto regs = As<IDebugRegisters2>(&regs2_);
    auto spaces = As<IDebugDataSpaces4>(&spaces4_);

    const TargetArch arch = DetectArchLocked();
    const char* const* gprNames = nullptr;
    size_t gprCount = 0;
    const char* ipName = "rip";
    GprNamesForArch(arch, &gprNames, &gprCount, &ipName);

    auto push = [&](const char* name) {
        ULONG idx = 0;
        if (FAILED(regs->GetIndexByName(name, &idx))) {
            return;
        }
        DEBUG_VALUE dv{};
        if (FAILED(regs->GetValue(idx, &dv))) {
            return;
        }
        out->regs.emplace_back(std::string(name), (UINT64)dv.I64);
    };
    for (size_t i = 0; i < gprCount; i++) {
        push(gprNames[i]);
    }
    push(ipName);
    push("efl");

    // Bytes-at-rip: use the rip from `out` (already populated by
    // FillStopInfoLocked) when non-zero; otherwise probe the engine for
    // the current instruction offset.
    UINT64 ip = out->rip;
    if (!ip) {
        ULONG64 raw = 0;
        if (SUCCEEDED(regs->GetInstructionOffset(&raw))) {
            ip = raw;
        }
    }
    if (ip) {
        BYTE raw[16]{};
        ULONG got = 0;
        if (SUCCEEDED(spaces->ReadVirtual(ip, raw, sizeof(raw), &got)) && got) {
            std::ostringstream hex;
            for (ULONG b = 0; b < got; b++) {
                char hb[4];
                _snprintf_s(hb, _TRUNCATE, "%02x", raw[b]);
                hex << hb;
            }
            out->bytes_at_rip_hex = hex.str();
        }
    }
}

// Disasm — produce up to `count` disassembled lines starting at
// `address`. Uses IDebugControl3::Disassemble (which emits a formatted
// "<addr> <bytes> <mnemonic>" line) and separately reads memory for the
// `bytes_hex` field. Chose Disassemble over OutputDisassembly + capture
// callback because the single-call API returns EndOffset directly and keeps
// the implementation straightforward; the byte range is re-read from memory
// so bytes_hex is independent of whatever formatting the engine chose.
std::string DbgSession::Disasm(UINT64 address, UINT32 count, std::vector<DisasmLineRec>* out)
{
    return RunOnEngine([&]() -> std::string {
        if (!active_) {
            return "no active session";
        }
        if (!out) {
            return "nullptr out";
        }
        if (count == 0) {
            count = 16;
        }
        auto control = As<IDebugControl3>(&control3_);
        auto spaces = As<IDebugDataSpaces4>(&spaces4_);
        UINT64 cursor = address;
        for (UINT32 i = 0; i < count; i++) {
            char buf[256] = {};
            ULONG disSize = 0;
            ULONG64 endOff = 0;
            // Default flags (0) = whatever matches the effective processor; the
            // dbgeng-exposed DEBUG_DISASM_* flags are all for additional output
            // decorations (source lines, matching symbols) that we don't want.
            HRESULT hr = control->Disassemble(cursor, 0,
                                              buf, sizeof(buf), &disSize, &endOff);
            if (FAILED(hr)) {
                if (i == 0) {
                    return "Disassemble failed hr=" + std::to_string(hr);
                }
                break;
            }
            DisasmLineRec line;
            line.address = cursor;
            // dbgeng's Disassemble output is "<addr> <bytes> <mnemonic>\n".
            // Strip the trailing newline; the "text" field is the full line
            // (addr prefix included) so callers see exactly what windbg would
            // print. `bytes_hex` below carries just the opcode bytes for
            // tools that want to render them separately.
            std::string text = buf;
            while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
                text.pop_back();
            }
            line.text = std::move(text);
            if (endOff > cursor) {
                const ULONG64 len = endOff - cursor;
                if (len > 0 && len <= 32) {
                    BYTE raw[32]{};
                    ULONG got = 0;
                    if (SUCCEEDED(spaces->ReadVirtual(cursor, raw, (ULONG)len, &got))
                        && got) {
                        std::ostringstream hex;
                        hex << std::hex;
                        for (ULONG b = 0; b < got; b++) {
                            char hb[4];
                            _snprintf_s(hb, _TRUNCATE, "%02x", raw[b]);
                            hex << hb;
                        }
                        line.bytes_hex = hex.str();
                    }
                }
            }
            out->push_back(std::move(line));
            if (endOff <= cursor) {
                break; // decoder stalled; avoid infinite loop
            }
            cursor = endOff;
        }
        return "";
    });
}

} // namespace pry
