#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "pry.grpc.pb.h"
#include "pry_abi.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include "services.hpp"
#include "services_internal.hpp"
#include "../breadcrumb.hpp"
#include "../common.h"
#include "../dump/dumper.hpp"
#include "../files.hpp"
#include "../host/host_info.hpp"
#include "../pe/pe_reader.hpp"
#include "../pe/heap_walker.hpp"
#include "../watch.hpp"
#include "pattern_scan.hpp"

#include <tlhelp32.h>
#include <fstream>
#include <cctype>
#include <chrono>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace pry {

namespace {

// per-pid LRU of HeapAttrib indices.
// Shared across all MemorySvc calls on this process (there is one
// MemorySvc singleton per agent). Guarded by a single mutex — the
// index-build itself is CPU/IO heavy and release-reacquire inside
// LookupByVA would just thrash. Callers hold the lock through the
// batch lookup; batches are capped at HEAPATTRIB_MAX_VAS so the
// critical section stays bounded.
class HeapAttribCache {
public:
    static HeapAttribCache& Instance() {
        static HeapAttribCache g;
        return g;
    }

    // Returns a pointer to the (owning-list-stable) index for `pid`,
    // rebuilding when TTL / committed-sum / refresh demands it.
    // ``from_cache`` is set true only when no rebuild was performed.
    // Returns nullptr and sets `err` on build failure; in that case
    // the entry is evicted so the next call retries.
    pry::pe::HeapIndex* GetOrBuild(uint32_t pid,
                                      pry::pe::UserReadFn user_read,
                                      bool refresh, bool& from_cache,
                                      std::string& err)
    {
        from_cache = false;
        err.clear();
        auto now = Now();
        // Lookup by pid.
        // ``by_pid_`` maps pid -> list iterator; that list owns
        // std::unique_ptr<HeapIndex>. So ``it->second`` is a list
        // iterator, ``*it->second`` is ``unique_ptr<HeapIndex>&``, and
        // we have to double-deref (or go through ``->``) to touch the
        // actual HeapIndex fields.
        auto it = by_pid_.find(pid);
        if (it != by_pid_.end() && !refresh) {
            pry::pe::HeapIndex& entry = **it->second;
            const uint64_t age = now - entry.built_ms;
            if (age <= pry::pe::HEAPATTRIB_TTL_MS) {
                // Committed-sum delta probe. A lightweight
                // want_blocks=false WalkHeaps summarises committed
                // bytes without re-indexing; if the delta exceeds
                // max(1 MiB, 1%) rebuild.
                std::vector<pry::pe::HeapRow> probe;
                std::string probe_err;
                if (pry::pe::WalkHeaps(pid, /*want_blocks=*/false,
                                          /*max_blocks=*/0,
                                          user_read, probe, probe_err)) {
                    uint64_t probe_sum = 0;
                    for (const auto& r : probe) probe_sum += r.committed;
                    const uint64_t delta =
                        (probe_sum > entry.committed_sum)
                            ? (probe_sum - entry.committed_sum)
                            : (entry.committed_sum - probe_sum);
                    const uint64_t one_pct = entry.committed_sum / 100;
                    const uint64_t threshold =
                        pry::pe::HEAPATTRIB_DELTA_BYTES > one_pct
                            ? pry::pe::HEAPATTRIB_DELTA_BYTES
                            : one_pct;
                    if (delta <= threshold) {
                        // Still fresh. Promote to MRU and return.
                        Promote(it);
                        from_cache = true;
                        return (*it->second).get();
                    }
                }
                // Probe failed or delta tripped: fall through to rebuild.
            }
        }
        // Rebuild.
        auto fresh = std::make_unique<pry::pe::HeapIndex>();
        if (!pry::pe::BuildHeapIndex(pid, user_read, *fresh, err)) {
            // Evict any stale entry so the next call retries.
            if (it != by_pid_.end()) Evict(it);
            return nullptr;
        }
        // Preserve a monotonic epoch across rebuilds for the same pid.
        uint32_t next_epoch = 1;
        if (it != by_pid_.end()) {
            next_epoch = (*it->second)->epoch + 1;
            Evict(it);
        }
        fresh->epoch = next_epoch;
        // Install.
        order_.push_front(std::move(fresh));
        by_pid_[pid] = order_.begin();
        // Cap.
        while (order_.size() > pry::pe::HEAPATTRIB_LRU_CAP) {
            auto& last = order_.back();
            by_pid_.erase(last->pid);
            order_.pop_back();
        }
        return order_.front().get();
    }

    std::mutex& Mutex() { return mu_; }

private:
    using ListT = std::list<std::unique_ptr<pry::pe::HeapIndex>>;
    using IterT = ListT::iterator;

    uint64_t Now() {
        using namespace std::chrono;
        return (uint64_t)duration_cast<milliseconds>(
                   steady_clock::now().time_since_epoch()).count();
    }

    void Promote(std::unordered_map<uint32_t, IterT>::iterator it) {
        // Splice the matching node to the front; iterator in by_pid_
        // stays valid since std::list.splice preserves iterators.
        order_.splice(order_.begin(), order_, it->second);
    }

    void Evict(std::unordered_map<uint32_t, IterT>::iterator it) {
        order_.erase(it->second);
        by_pid_.erase(it);
    }

    std::mutex mu_;
    ListT order_;                        // front = MRU, back = LRU
    std::unordered_map<uint32_t, IterT> by_pid_;
};

} // namespace

// ---------------------------------------------------------------------------
// v11 ThreadList — per-thread inventory via NtQuerySystemInformation(
// SystemProcessInformation). Structs defined locally: winternl.h's
// SYSTEM_PROCESS_INFORMATION drifts across SDKs and the thread array rides
// at the end of a long variable block.
// ---------------------------------------------------------------------------

constexpr UINT32 THREADLIST_MAX = 8192;

#pragma pack(push, 8)
struct SPI_PROCESS {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    ULONGLONG CreateTime;
    ULONGLONG UserTime;
    ULONGLONG KernelTime;
    USHORT ImageNameLen;               // UNICODE_STRING.Length
    USHORT ImageNameMax;               // MaximumLength
    ULONG  ImageNamePad;
    ULONGLONG ImageNameBuffer;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
    // SPI_THREAD[NumberOfThreads] follows
};
struct SPI_THREAD {
    ULONGLONG KernelTime;
    ULONGLONG UserTime;
    ULONGLONG CreateTime;
    ULONG WaitTime;
    ULONGLONG StartAddress;
    ULONGLONG ClientProcessId;    // CLIENT_ID.UniqueProcess
    ULONGLONG ClientThreadId;     // CLIENT_ID.UniqueThread
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};
#pragma pack(pop)

// Fills resp->threads(); returns a Win32 gle (0 = ok). pid 0 = every process.
UINT32 CollectThreadList(DWORD want_pid, ThreadListResponse* resp, bool* truncated)
{
    *truncated = false;
    using NtQSI_t = NTSTATUS(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    static NtQSI_t qsi = []() {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? (NtQSI_t)GetProcAddress(m, "NtQuerySystemInformation") : nullptr;
    }();
    if (!qsi) return ERROR_PROC_NOT_FOUND;

    ULONG size = 1u << 20;
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::vector<BYTE> blob(size);
        ULONG need = 0;
        NTSTATUS st = qsi(5 /*SystemProcessInformation*/, blob.data(), size, &need);
        if (st == (NTSTATUS)0xC0000004L /*STATUS_INFO_LENGTH_MISMATCH*/) {
            size *= 2;
            continue;
        }
        if (st < 0) {
            using RtlNtStatusToDosError_t = ULONG(NTAPI*)(NTSTATUS);
            auto to_dos = (RtlNtStatusToDosError_t)GetProcAddress(
                GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError");
            return to_dos ? to_dos(st) : ERROR_INTERNAL_ERROR;
        }
        BYTE* p = blob.data();
        while (p + sizeof(SPI_PROCESS) <= blob.data() + size) {
            auto* pi = (SPI_PROCESS*)p;
            bool want = (want_pid == 0) ||
                        (want_pid == (DWORD)(ULONG_PTR)pi->UniqueProcessId);
            if (want) {
                BYTE* th = p + sizeof(SPI_PROCESS);
                for (ULONG t = 0; t < pi->NumberOfThreads; ++t) {
                    auto* ti = (SPI_THREAD*)th;
                    auto* row = resp->add_threads();
                    row->set_pid((UINT32)(ULONG_PTR)ti->ClientProcessId);
                    row->set_tid((UINT32)(ULONG_PTR)ti->ClientThreadId);
                    row->set_start_va(ti->StartAddress);
                    row->set_state(ti->ThreadState);
                    row->set_wait_reason(ti->WaitReason);
                    row->set_base_priority(ti->BasePriority);
                    if (resp->threads_size() >= THREADLIST_MAX) {
                        *truncated = true;
                        return 0;
                    }
                    th += sizeof(SPI_THREAD);
                }
            }
            if (!pi->NextEntryOffset) break;
            p += pi->NextEntryOffset;
        }
        return 0;
    }
    return ERROR_INSUFFICIENT_BUFFER;
}

// ------------------------------------------------------------ Memory svc ----

// Local helpers (file-local on purpose — the watchdog TU has its own
// ProbeDriver; the generated grpcpp headers must be parsed before
// windows.h, so shared helpers can't live in services.hpp).
static bool ProbeDriver(DriverMgr& drv, std::string* err)
{
    if (drv.Comm().IsOpen()) return true;
    if (!drv.Comm().Open()) {
        *err = "driver_absent: " + drv.Comm().LastError();
        return false;
    }
    return true;
}

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n,
                        nullptr, nullptr);
    return s;
}

// ---------------------------------------------------------------------------
// v14 driver-free process discovery — same NtQSI(SystemProcessInformation)
// blob CollectThreadList walks, one row per process. Survives driver_absent,
// works from session 0, needs no WMI. The driver's ProcessList stays as a
// last-ditch fallback in the RPC body.
// ---------------------------------------------------------------------------

struct ProcRow {
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    uint32_t session_id = 0;
    std::string image;
    uint64_t create_time_100ns = 0;  // FILETIME ticks since 1601
};

static UINT32 CollectProcessList(std::vector<ProcRow>* out)
{
    using NtQSI_t = NTSTATUS(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    static NtQSI_t qsi = []() {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? (NtQSI_t)GetProcAddress(m, "NtQuerySystemInformation") : nullptr;
    }();
    if (!qsi) return ERROR_PROC_NOT_FOUND;
    ULONG size = 1u << 20;
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::vector<BYTE> blob(size);
        NTSTATUS st = qsi(5 /*SystemProcessInformation*/, blob.data(), size, nullptr);
        if (st == (NTSTATUS)0xC0000004L /*STATUS_INFO_LENGTH_MISMATCH*/) {
            size *= 2;
            continue;
        }
        if (st < 0) {
            using RtlNtStatusToDosError_t = ULONG(NTAPI*)(NTSTATUS);
            auto to_dos = (RtlNtStatusToDosError_t)GetProcAddress(
                GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError");
            return to_dos ? to_dos(st) : ERROR_INTERNAL_ERROR;
        }
        BYTE* p = blob.data();
        while (p + sizeof(SPI_PROCESS) <= blob.data() + size) {
            auto* pi = (SPI_PROCESS*)p;
            ProcRow r;
            r.pid = (uint32_t)(ULONG_PTR)pi->UniqueProcessId;
            r.parent_pid = (uint32_t)(ULONG_PTR)pi->InheritedFromUniqueProcessId;
            r.session_id = pi->SessionId;
            r.create_time_100ns = pi->CreateTime;
            if (pi->ImageNameLen && pi->ImageNameBuffer) {
                std::wstring w((const wchar_t*)(uintptr_t)pi->ImageNameBuffer,
                               pi->ImageNameLen / sizeof(wchar_t));
                r.image = WideToUtf8(w);
            }
            out->push_back(std::move(r));
            if (!pi->NextEntryOffset) break;
            p += pi->NextEntryOffset;
        }
        return 0;
    }
    return ERROR_INSUFFICIENT_BUFFER;
}

// ProcessCommandLineInformation (class 60, Win8.1+) returns the PEB cmdline
// without a manual PEB walk — Buffer lands inside the caller's block.
// Empty on protected/PPL targets; opt-in via with_cmdline since it costs
// one OpenProcess per row.
static std::string ProcCmdline(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    using NtQIP_t = NTSTATUS(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static NtQIP_t qip = [] {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? (NtQIP_t)GetProcAddress(m, "NtQueryInformationProcess") : nullptr;
    }();
    // UNICODE_STRING layout, hand-rolled (x64 pointer width) — winternl.h
    // collides with the ntstatus types we pull in elsewhere in this TU.
    struct LocalUS {
        USHORT Length;
        USHORT MaximumLength;
        ULONGLONG Buffer;
    };
    std::string out;
    if (qip) {
        std::vector<BYTE> buf(sizeof(LocalUS) + 0x4000);
        auto* us = (LocalUS*)buf.data();
        if (qip(h, 60 /*ProcessCommandLineInformation*/, buf.data(),
                (ULONG)buf.size(), nullptr) >= 0 && us->Buffer && us->Length) {
            std::wstring w((const wchar_t*)(uintptr_t)us->Buffer,
                           us->Length / sizeof(wchar_t));
            out = WideToUtf8(w);
        }
    }
    CloseHandle(h);
    return out;
}

// v14: non-invasive register snapshot (the "is this thread really wedged?"
// answer without a dbgeng attach). Suspend → GetThreadContext → Resume;
// WOW64 processes get the 32-bit register set. wow64_cache is keyed by pid
// so a whole-process ThreadList pays one IsWow64Process per process.
static void SnapThreadContext(DWORD pid, DWORD tid, SysThreadInfo* row,
                              std::map<DWORD, int>* wow64_cache)
{
    if (pid == GetCurrentProcessId() || tid == GetCurrentThreadId()) return;
    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                           THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!th) return;
    int wow64 = -1;
    auto it = wow64_cache->find(pid);
    if (it != wow64_cache->end()) {
        wow64 = it->second;
    } else {
        BOOL w = FALSE;
        HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (ph) {
            IsWow64Process(ph, &w);
            CloseHandle(ph);
        }
        wow64 = w ? 1 : 0;
        (*wow64_cache)[pid] = wow64;
    }
    if (SuspendThread(th) != (DWORD)-1) {
        auto* m = row->mutable_context_regs();
        if (wow64 == 1) {
            WOW64_CONTEXT c{};
            c.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER |
                             WOW64_CONTEXT_SEGMENTS;
            if (Wow64GetThreadContext(th, &c)) {
                (*m)["eip"] = c.Eip;  (*m)["esp"] = c.Esp;  (*m)["ebp"] = c.Ebp;
                (*m)["eax"] = c.Eax;  (*m)["ebx"] = c.Ebx;  (*m)["ecx"] = c.Ecx;
                (*m)["edx"] = c.Edx;  (*m)["esi"] = c.Esi;  (*m)["edi"] = c.Edi;
                (*m)["eflags"] = c.EFlags;
                (*m)["segcs"] = c.SegCs; (*m)["segss"] = c.SegSs;
            }
        } else {
            CONTEXT c{};
            c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
            if (GetThreadContext(th, &c)) {
                (*m)["rip"] = c.Rip;  (*m)["rsp"] = c.Rsp;  (*m)["rbp"] = c.Rbp;
                (*m)["rax"] = c.Rax;  (*m)["rbx"] = c.Rbx;  (*m)["rcx"] = c.Rcx;
                (*m)["rdx"] = c.Rdx;  (*m)["rsi"] = c.Rsi;  (*m)["rdi"] = c.Rdi;
                (*m)["r8"] = c.R8;    (*m)["r9"] = c.R9;    (*m)["r10"] = c.R10;
                (*m)["r11"] = c.R11;  (*m)["r12"] = c.R12;  (*m)["r13"] = c.R13;
                (*m)["r14"] = c.R14;  (*m)["r15"] = c.R15;
                (*m)["eflags"] = c.EFlags;
                (*m)["segcs"] = c.SegCs; (*m)["segss"] = c.SegSs;
            }
        }
        ResumeThread(th);
    }
    CloseHandle(th);
}

class MemorySvc final : public Memory::Service {
public:
    MemorySvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

private:
    // Build a reader closure that routes a target-VA read through the right
    // space: KERNEL space through the driver, USER through the shared
    // UserMemReadFn (driver-first with ReadProcessMemory fallback).
    pry::pe::ReadFn MakeModuleReader(UINT32 pid, bool is_kernel)
    {
        if (is_kernel) {
            return [this](uint64_t addr, void* dst, size_t len) -> bool {
                SIZE_T got = 0;
                return drv_.Comm().MemRead(Space::Kernel, 0, addr, dst, len, &got)
                       && got == len;
            };
        }
        return [this, pid](uint64_t addr, void* dst, size_t len) -> bool {
            MemReaderCtx c{&drv_};
            return UserMemReadFn(&c, pid, addr, dst, len);
        };
    }

    struct ScanPlan {
        std::vector<patscan::Range> ranges;
        patscan::ReadFn read;
    };

    // Resolves a PatternScanRequest into ranges + a reader (proto
    // semantics: base==0 -> every readable committed region of pid;
    // base!=0 && size==0 -> regions from base onward; else [base, base+size)).
    // Region enumeration is user-space only: kernel/physical scans need an
    // explicit base+size (they used to "succeed" with 0 hits instead).
    bool PlanScan(const PatternScanRequest& req, ScanPlan* plan, std::string* err)
    {
        if (!patscan::ValidPattern(req.pattern(), req.mask())) {
            *err = "invalid pattern/mask";
            return false;
        }
        Space space = Space::User;
        UINT32 pid = req.pid();
        if (req.space() == KERNEL) {
            space = Space::Kernel;
            pid = 0;
        } else if (req.space() == PHYSICAL) {
            space = Space::Physical;
            pid = 0;
        }
        if (req.base() == 0 || req.size() == 0) {
            if (space != Space::User) {
                *err = "pattern scan: kernel/physical scans need base and size (there is no "
                       "region map to walk); pass module= or an explicit window";
                return false;
            }
            if (pid == 0) {
                *err = "pattern scan: pid required for a whole-space user scan";
                return false;
            }
            std::vector<patscan::Region> regions;
            if (!EnumUserRegions(pid, &regions, err)) {
                return false;
            }
            plan->ranges = patscan::PlanRanges(req.base(), req.size(), regions);
        } else {
            plan->ranges.push_back({req.base(), req.size()});
        }
        plan->read = [this, space, pid](std::uint64_t va, std::uint8_t* dst,
                                        std::size_t want) -> std::size_t {
            SIZE_T got = 0;
            if (drv_.Comm().MemRead(space, pid, va, dst, want, &got) && got) {
                return (std::size_t)got;
            }
            if (space != Space::User) {
                return 0;
            }
            // driver absent / refused: plain ReadProcessMemory (partial ok)
            HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (!h) {
                return 0;
            }
            SIZE_T n = 0;
            ReadProcessMemory(h, (LPCVOID)(uintptr_t)va, dst, want, &n);
            CloseHandle(h);
            return (std::size_t)n;
        };
        return true;
    }

    // Committed regions of pid: VirtualQueryEx first, the driver's VAD walk
    // when the process can't be opened (protected processes).
    bool EnumUserRegions(UINT32 pid, std::vector<patscan::Region>* out, std::string* err)
    {
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (h) {
            std::uint64_t addr = 0;
            MEMORY_BASIC_INFORMATION mbi{};
            while (VirtualQueryEx(h, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.State == MEM_COMMIT) {
                    out->push_back({(std::uint64_t)(uintptr_t)mbi.BaseAddress,
                                    (std::uint64_t)mbi.RegionSize, mbi.Protect});
                }
                std::uint64_t next = (std::uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                if (next <= addr) {
                    break;
                }
                addr = next;
            }
            CloseHandle(h);
            return true;
        }
        DWORD gle = GetLastError();
        std::vector<VadRecord> vads;
        if (drv_.Comm().Open() && drv_.Comm().VadList(pid, vads)) {
            for (const auto& v : vads) {
                if (v.End > v.Start) {
                    out->push_back({v.Start, v.End - v.Start, v.Protect});
                }
            }
            return true;
        }
        *err = "pattern scan: cannot enumerate regions of pid " + std::to_string(pid) +
               " (OpenProcess gle=" + std::to_string(gle) + "; driver: " +
               drv_.Comm().LastError() + ")";
        return false;
    }

public:
    grpc::Status Read(::grpc::ServerContext* ctx, const MemoryReadRequest* req, MemoryReadResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        // L5: honor optional max_bytes cap. 0 == no cap; when set, clip
        // the read to min(size, max_bytes) BEFORE the maxMemReadBytes gate
        // so a caller can voluntarily narrow a large request without
        // bumping the server ceiling. Semantics and return shape unchanged.
        uint64_t effective_size = req->size();
        if (req->max_bytes() > 0 && req->max_bytes() < effective_size) {
            effective_size = req->max_bytes();
        }
        if (effective_size > cfg_.maxMemReadBytes) {
            FillStatus(resp, "read exceeds max_mem_read_mb");
            return grpc::Status::OK;
        }
        resp->mutable_data()->resize((size_t)effective_size);
        SIZE_T got = 0;
        bool ok;
        UINT32 flags = 0;
        if (req->allow_fault()) flags |= PRY_MEM_FLAG_ALLOW_SOFTFAULT;
        if (req->partial()) flags |= PRY_MEM_FLAG_PARTIAL;
        // vNEXT (T3.1 PR#5): physical read guard — forward the opt-in bit.
        // The driver default-denies any physical range not inside
        // MmGetPhysicalMemoryRanges with STATUS_ACCESS_DENIED unless this
        // flag is set, so one wayward MMIO BAR read can no longer wedge
        // the target. Older orchestrator clients that don't send
        // allow_mmio get the default (false) and the guard engages.
        if (req->allow_mmio()) flags |= PRY_MEM_FLAG_ALLOW_OUT_OF_RAM;
        switch (req->space()) {
        case KERNEL:
            ok = drv_.Comm().MemRead(Space::Kernel, 0, req->address(), resp->mutable_data()->data(),
                                     (SIZE_T)effective_size, &got, flags);
            break;
        case PHYSICAL:
            ok = drv_.Comm().MemRead(Space::Physical, 0, req->address(), resp->mutable_data()->data(),
                                     (SIZE_T)effective_size, &got, flags);
            break;
        default:
            ok = drv_.Comm().MemRead(Space::User, req->pid(), req->address(), resp->mutable_data()->data(),
                                     (SIZE_T)effective_size, &got);
            break;
        }
        // v6 PARTIAL: STATUS_PARTIAL_COPY surfaces at the driver layer as
        // ok=true, got<size AND lastError() containing "0xc000000d"-ish
        // text OR just a short data buffer. The comm library propagates
        // NT status through FailNt on a hard error, so `ok` here already
        // means "we got at least some bytes." When partial was requested
        // and we got a short read, set first_bad_offset so callers know
        // exactly where the hole starts.
        if (!ok) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->mutable_data()->resize(got);
        resp->set_read_bytes(got);
        // Compare against effective_size, not req->size(), so a
        // deliberately-clipped read (max_bytes < size) doesn't report a
        // spurious first_bad_offset when the driver returned exactly the
        // clip length. Only true short-reads relative to what we ASKED
        // the driver for should mark a partial hole.
        if (req->partial() && got < (SIZE_T)effective_size) {
            resp->set_first_bad_offset(got);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v5: server-streaming read for large ranges. Drops the caller-side
    // chunking dance and lets the driver-side 1 MiB internal chunking
    // become the natural pace of the stream. Each chunk carries its own
    // offset so a downstream reassembler survives out-of-order arrival
    // even though gRPC preserves order on a single stream.
    grpc::Status ReadStream(::grpc::ServerContext* ctx, const MemoryReadRequest* req,
                            ::grpc::ServerWriter<MemoryReadChunk>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        const uint64_t total = req->size();
        // Per-chunk budget: 1 MiB. Keeps below gRPC default 4 MiB frame
        // cap even with proto overhead; matches the driver's internal
        // chunk boundary so a driver read never spans a chunk.
        const uint64_t CHUNK = 1ull * 1024 * 1024;
        std::vector<BYTE> buf(CHUNK);
        uint64_t off = 0;
        bool first = true;
        while (off < total) {
            if (ctx->IsCancelled()) {
                return grpc::Status::CANCELLED;
            }
            uint64_t want = total - off;
            if (want > CHUNK) want = CHUNK;
            SIZE_T got = 0;
            bool ok = false;
            switch (req->space()) {
            case KERNEL:
                ok = drv_.Comm().MemRead(Space::Kernel, 0, req->address() + off, buf.data(),
                                         (SIZE_T)want, &got,
                                         req->allow_fault() ? PRY_MEM_FLAG_ALLOW_SOFTFAULT : 0);
                break;
            case PHYSICAL:
                // vNEXT (T3.1 PR#5): same allow_mmio gate on the streaming
                // path. Without the flag the driver refuses out-of-RAM
                // reads with STATUS_ACCESS_DENIED before touching MmCopyMemory.
                ok = drv_.Comm().MemRead(Space::Physical, 0, req->address() + off, buf.data(),
                                         (SIZE_T)want, &got,
                                         req->allow_mmio() ? PRY_MEM_FLAG_ALLOW_OUT_OF_RAM : 0);
                break;
            default:
                ok = drv_.Comm().MemRead(Space::User, req->pid(), req->address() + off, buf.data(),
                                         (SIZE_T)want, &got);
                break;
            }
            MemoryReadChunk chunk;
            if (first) {
                // Status on the header chunk only. Non-header chunks skip
                // the field to save frame bytes.
                chunk.mutable_status()->set_ok(ok);
                if (!ok) {
                    chunk.mutable_status()->set_error("driver: " + drv_.Comm().LastError());
                    chunk.mutable_status()->set_errno_code(1);
                    chunk.set_eof(true);
                    writer->Write(chunk);
                    return grpc::Status::OK;
                }
                first = false;
            } else if (!ok) {
                // Mid-stream failure: send an error chunk with eof and stop.
                chunk.mutable_status()->set_ok(false);
                chunk.mutable_status()->set_error("driver: " + drv_.Comm().LastError());
                chunk.mutable_status()->set_errno_code(1);
                chunk.set_offset(off);
                chunk.set_eof(true);
                writer->Write(chunk);
                return grpc::Status::OK;
            }
            chunk.set_offset(off);
            chunk.set_data(buf.data(), got);
            off += got;
            if (got == 0 || off >= total) {
                chunk.set_eof(true);
            }
            if (!writer->Write(chunk)) {
                return grpc::Status::CANCELLED;
            }
            if (got == 0) break; // short read: driver returned nothing more
        }
        return grpc::Status::OK;
    }

    grpc::Status Write(::grpc::ServerContext* ctx, const MemoryWriteRequest* req, MemoryWriteResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        if (req->data().size() > cfg_.maxTransferBytes) {
            FillStatus(resp, "write exceeds max_transfer_mb");
            return grpc::Status::OK;
        }
        // v12: cr3 is a kernel-space concept — the supplied CR3 defines the
        // address space the store runs under. Passing it on a user/physical
        // write is a caller bug; refusing beats silently dropping it.
        if (req->cr3() && req->space() != KERNEL) {
            FillStatus(resp, "cr3 requires space=KERNEL");
            return grpc::Status::OK;
        }
        SIZE_T written = 0;
        bool ok;
        UINT8 writePath = PRY_MEM_WRITE_PATH_UNKNOWN;
        switch (req->space()) {
        case KERNEL:
            ok = drv_.Comm().MemWrite(Space::Kernel, 0, req->address(), req->data().data(),
                                      req->data().size(), &written, 0,
                                      req->cr3(),
                                      req->flags() & PRY_MEM_WRF_STRICT_VA,
                                      &writePath);
            break;
        case PHYSICAL:
            // ABI v5: the driver refuses physical writes without the
            // opt-in flag; pass it through untouched.
            ok = drv_.Comm().MemWrite(Space::Physical, 0, req->address(), req->data().data(),
                                      req->data().size(), &written,
                                      req->allow_map_write() ? PRY_MEM_FLAG_ALLOW_MAP_WRITE : 0,
                                      0, 0, &writePath);
            break;
        default:
            ok = drv_.Comm().MemWrite(Space::User, req->pid(), req->address(), req->data().data(),
                                      req->data().size(), &written, 0, 0, 0, &writePath);
            break;
        }
        if (!ok) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            // The v12 out-reply still reports which path a failed write
            // was attempting — surface it alongside the error status.
            resp->set_write_path(writePath);
            // ...and how many bytes DID land (v12 out.Done) — a partial
            // write used to report 0 next to an error.
            resp->set_written_bytes(written);
            return grpc::Status::OK;
        }
        resp->set_written_bytes(written);
        resp->set_write_path(writePath);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Alloc(::grpc::ServerContext* ctx, const MemoryAllocRequest* req, MemoryAllocResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        bool ok;
        if (req->kernel()) {
            UINT64 addr = 0;
            ok = drv_.Comm().KmemAlloc(req->size(), &addr);
            resp->set_address(addr);
        } else {
            UINT64 addr = 0;
            ok = drv_.Comm().UserAlloc(req->pid(), req->size(), req->protect() ? req->protect() : PAGE_READWRITE, &addr);
            resp->set_address(addr);
        }
        if (!ok) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Free(::grpc::ServerContext* ctx, const MemoryFreeRequest* req, MemoryFreeResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        bool ok = req->kernel() ? drv_.Comm().KmemFree(req->address())
                                : drv_.Comm().UserFree(req->pid(), req->address());
        if (!ok) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Protect(::grpc::ServerContext* ctx, const MemoryProtectRequest* req, MemoryProtectResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        UINT32 old = 0;
        if (!drv_.Comm().UserProtect(req->pid(), req->address(), req->size(), req->protect(), &old)) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_old_protect(old);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Modules(::grpc::ServerContext* ctx, const ModulesRequest* req, ModulesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<pry::ModuleEntry> mods;
        bool ok = req->kernel() ? drv_.Comm().Open() && drv_.Comm().KernelModules(mods)
                                : ListUserModules(&drv_, req->pid(), &mods);
        if (!ok) {
            FillStatus(resp, "module walk failed: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        // L5: soft slice. The driver / user walker fills the full vector
        // (buffer-fill API — no native bound), so we slice post-fill.
        // limit == 0 means "no cap"; offset skips the first N rows.
        const size_t off = static_cast<size_t>(req->offset() > 0 ? req->offset() : 0);
        const size_t lim = static_cast<size_t>(req->limit()  > 0 ? req->limit()  : 0);
        size_t emitted = 0;
        for (size_t i = 0; i < mods.size(); ++i) {
            if (i < off) continue;
            if (lim && emitted >= lim) break;
            auto& m = mods[i];
            auto* mi = resp->add_modules();
            mi->set_name(WideToUtf8(m.Name));
            mi->set_path(WideToUtf8(m.Path));
            mi->set_base(m.Base);
            mi->set_size(m.Size);
            mi->set_kernel(req->kernel());
            ++emitted;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ModuleImports(::grpc::ServerContext* ctx, const ModuleImportsRequest* req,
                               ModuleImportsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<pry::ModuleEntry> mods;
        bool listed = req->kernel() ? drv_.Comm().Open() && drv_.Comm().KernelModules(mods)
                                    : ListUserModules(&drv_, req->pid(), &mods);
        if (!listed) {
            FillStatus(resp, "module list failed: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        UINT64 base = FindModuleBase(mods, req->module());
        if (!base) {
            FillStatus(resp, "module not found: " + req->module());
            return grpc::Status::OK;
        }
        std::vector<pry::pe::IatRow> rows;
        std::string err;
        auto reader = MakeModuleReader(req->pid(), req->kernel());
        if (!pry::pe::ParseImports(base, reader, rows, &err)) {
            FillStatus(resp, "parse imports failed: " + (err.empty() ? "unknown" : err));
            return grpc::Status::OK;
        }
        // L5 post-fill slice — ParseImports fills `rows` in one shot.
        const size_t off = static_cast<size_t>(req->offset() > 0 ? req->offset() : 0);
        const size_t lim = static_cast<size_t>(req->limit() > 0 ? req->limit() : 0);
        const size_t end = lim ? std::min(rows.size(), off + lim) : rows.size();
        for (size_t i = off; i < end; ++i) {
            const auto& r = rows[i];
            auto* ie = resp->add_entries();
            ie->set_dll(r.dll);
            ie->set_name(r.name);
            ie->set_ordinal(r.ordinal);
            ie->set_iat_slot(r.iat_slot);
            ie->set_resolved(r.resolved);
            std::string owning = FindOwningModule(mods, r.resolved);
            ie->set_resolved_module(owning);
            // owning empty (pointer outside every loaded module) is almost
            // always a trampoline — flag it. Otherwise compare basenames.
            bool hooked = owning.empty() ||
                          BasenameLower(owning) != BasenameLower(r.dll);
            ie->set_hooked(hooked);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ModuleExports(::grpc::ServerContext* ctx, const ModuleExportsRequest* req,
                               ModuleExportsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<pry::ModuleEntry> mods;
        bool listed = req->kernel() ? drv_.Comm().Open() && drv_.Comm().KernelModules(mods)
                                    : ListUserModules(&drv_, req->pid(), &mods);
        if (!listed) {
            FillStatus(resp, "module list failed: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        UINT64 base = FindModuleBase(mods, req->module());
        if (!base) {
            FillStatus(resp, "module not found: " + req->module());
            return grpc::Status::OK;
        }
        std::vector<pry::pe::ExpRow> rows;
        std::string err;
        auto reader = MakeModuleReader(req->pid(), req->kernel());
        if (!pry::pe::ParseExports(base, reader, rows, &err)) {
            FillStatus(resp, "parse exports failed: " + (err.empty() ? "unknown" : err));
            return grpc::Status::OK;
        }
        // L5 post-fill slice — ParseExports fills `rows` in one shot.
        const size_t off = static_cast<size_t>(req->offset() > 0 ? req->offset() : 0);
        const size_t lim = static_cast<size_t>(req->limit() > 0 ? req->limit() : 0);
        const size_t stop = (lim == 0) ? rows.size()
                                       : std::min(rows.size(), off + lim);
        for (size_t i = off; i < stop; ++i) {
            const auto& r = rows[i];
            auto* ee = resp->add_entries();
            ee->set_name(r.name);
            ee->set_ordinal(r.ordinal);
            ee->set_rva(r.rva);
            ee->set_address(base + r.rva);
            ee->set_forwarder(r.forwarder);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status HeapList(::grpc::ServerContext* ctx, const HeapListRequest* req,
                          HeapListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<pry::pe::HeapRow> rows;
        std::string err;
        pry::pe::UserReadFn user_read = [this](uint32_t p, uint64_t a, void* d, size_t l) -> bool {
            MemReaderCtx c{&drv_};
            return UserMemReadFn(&c, p, a, d, l);
        };
        if (!pry::pe::WalkHeaps(req->pid(), req->want_blocks(), req->max_blocks(),
                                    user_read, rows, err)) {
            FillStatus(resp, err.empty() ? "heap walk failed" : err);
            return grpc::Status::OK;
        }
        for (const auto& r : rows) {
            auto* he = resp->add_heaps();
            he->set_handle(r.handle);
            he->set_flags(r.flags);
            he->set_base(r.base);
            he->set_committed(r.committed);
            he->set_reserved(r.reserved);
            for (const auto& b : r.blocks) {
                auto* bp = he->add_blocks();
                bp->set_address(b.address);
                bp->set_size(b.size);
                bp->set_flags(b.flags);
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status ListProcesses(::grpc::ServerContext* ctx, const ListProcessesRequest* req,
                               ListProcessesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        // v14: driver-free enumeration first — the old order made
        // process_list die with driver_absent, exactly when callers needed
        // it most (post-reboot). NtQSI carries session + start time for
        // free; the driver walk stays as a last-ditch fallback only.
        std::vector<ProcRow> rows;
        const char* source = "agent";
        UINT32 gle = CollectProcessList(&rows);
        if (gle != 0) {
            std::vector<ProcessEntry> procs;
            if (drv_.Comm().Open() && drv_.Comm().ProcessList(procs)) {
                for (const auto& p : procs) {
                    ProcRow r;
                    r.pid = p.Pid;
                    r.parent_pid = p.ParentPid;
                    r.image = WideToUtf8(p.ImageName);
                    rows.push_back(std::move(r));
                }
                gle = 0;
                source = "driver";
            }
        }
        if (gle != 0) {
            FillStatus(resp, "process list failed: " +
                       Win32ErrorString("NtQuerySystemInformation", gle));
            return grpc::Status::OK;
        }
        const size_t off = req ? static_cast<size_t>(req->offset() > 0 ? req->offset() : 0) : 0;
        const size_t lim = req ? static_cast<size_t>(req->limit()  > 0 ? req->limit()  : 0) : 0;
        size_t emitted = 0;
        for (size_t i = 0; i < rows.size(); ++i) {
            if (i < off) {
                continue;
            }
            if (lim && emitted >= lim) {
                break;
            }
            const auto& p = rows[i];
            auto* pi = resp->add_processes();
            pi->set_pid(p.pid);
            pi->set_parent_pid(p.parent_pid);
            pi->set_image_name(p.image);
            pi->set_session_id(p.session_id);
            pi->set_create_time_100ns(p.create_time_100ns);
            if (req && req->with_cmdline()) {
                pi->set_cmdline(ProcCmdline(p.pid));
            }
            ++emitted;
        }
        resp->set_source(source);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // Mechanics audit P1: both pattern-scan RPCs run the ONE shared loop in
    // comm/pattern_scan.hpp (same as umagent). base==0 walks every readable
    // committed region of pid (size==0 used to return 0 hits here), the
    // last start position of each window is tested, and the overlap
    // bookkeeping no longer stops (chunks-1)*(p-1) bytes short.
    grpc::Status Scan(::grpc::ServerContext* ctx, const PatternScanRequest* req, PatternScanResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        ScanPlan plan;
        std::string err;
        if (!PlanScan(*req, &plan, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        std::vector<std::uint64_t> hits;
        auto st = patscan::ScanRanges(
            plan.ranges, req->pattern(), req->mask(), req->max_results(), plan.read, &hits,
            [ctx](std::uint64_t, std::uint64_t) { return !ctx->IsCancelled(); });
        if (st.cancelled) {
            return grpc::Status::CANCELLED;
        }
        for (auto va : hits) {
            resp->add_addresses(va);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // cancellable server-streaming pattern scan. Emits a
    // PatternScanChunk roughly per MiB scanned (and whenever hits are
    // pending) so the orchestrator can update progress + tear down
    // mid-scan; the final chunk carries done=true.
    grpc::Status ScanStream(::grpc::ServerContext* ctx,
                            const PatternScanRequest* req,
                            ::grpc::ServerWriter<PatternScanChunk>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        ScanPlan plan;
        std::string err;
        if (!PlanScan(*req, &plan, &err)) {
            PatternScanChunk bad;
            bad.mutable_status()->set_ok(false);
            bad.mutable_status()->set_error(err);
            bad.mutable_status()->set_errno_code(1);
            bad.set_done(true);
            writer->Write(bad);
            return grpc::Status::OK;
        }
        const std::uint32_t cap = req->max_results() ? req->max_results() : 64;
        std::uint32_t found = 0;
        bool first = true;
        bool write_failed = false;
        std::uint64_t last_emit_bytes = 0;
        PatternScanChunk pending;
        auto emit = [&](std::uint64_t cursor, std::uint64_t scanned, bool done) {
            if (first) {
                pending.mutable_status()->set_ok(true);
                first = false;
            }
            pending.set_bytes_scanned(scanned);
            pending.set_cursor(cursor);
            pending.set_done(done);
            bool ok = writer->Write(pending);
            pending.Clear();
            last_emit_bytes = scanned;
            return ok;
        };
        patscan::ScanStats st;
        std::vector<std::uint8_t> buf;
        patscan::HitFn on_hit = [&](std::uint64_t va) {
            pending.add_addresses(va);
            return ++found < cap;
        };
        patscan::ChunkFn on_chunk = [&](std::uint64_t cursor, std::uint64_t scanned) {
            if (ctx->IsCancelled()) {
                return false;
            }
            if (pending.addresses_size() > 0 ||
                scanned - last_emit_bytes >= patscan::kDefaultChunk) {
                if (!emit(cursor, scanned, false)) {
                    write_failed = true;
                    return false;
                }
            }
            return true;
        };
        for (const auto& r : plan.ranges) {
            if (!patscan::ScanRange(r, req->pattern(), req->mask(), patscan::kDefaultChunk,
                                    plan.read, on_hit, on_chunk, buf, &st)) {
                break;
            }
        }
        if (st.cancelled || ctx->IsCancelled()) {
            return write_failed ? grpc::Status::OK : grpc::Status::CANCELLED;
        }
        emit(st.cursor, st.bytes_scanned, true);
        return grpc::Status::OK;
    }

    grpc::Status VadList(::grpc::ServerContext* ctx, const VadRequest* req, VadResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<pry::VadRecord> vads;
        if (!drv_.Comm().Open() || !drv_.Comm().VadList(req->pid(), vads)) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        // L5 pagination: post-fill slice. Driver enumerates all VADs into
        // a fixed-shape vector, so we bound only the response projection.
        // limit == 0 means no cap.
        const size_t off = static_cast<size_t>(req->offset() > 0 ? req->offset() : 0);
        const int32_t lim = req->limit();
        const size_t start = off < vads.size() ? off : vads.size();
        const size_t end = (lim > 0)
            ? std::min(vads.size(), start + static_cast<size_t>(lim))
            : vads.size();
        for (size_t i = start; i < end; ++i) {
            auto& v = vads[i];
            auto* e = resp->add_entries();
            e->set_start(v.Start);
            e->set_end(v.End);
            e->set_protect(v.Protect);
            e->set_vad_type(v.VadType);
            e->set_commit_charge(v.CommitCharge);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status HandleList(::grpc::ServerContext* ctx, const HandleListRequest* req,
                            HandleListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<pry::HandleRecord> handles;
        if (!drv_.Comm().Open() ||
            !drv_.Comm().HandleList(req->pid(), handles, req->want_names())) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        // L5 pagination: post-fill slice — driver fills the whole vector
        // (fixed-buffer enumeration), so we honor limit/offset by skipping
        // records when emitting into the response. 0 limit == "no cap".
        const size_t off = static_cast<size_t>(req->offset() > 0 ? req->offset() : 0);
        const size_t lim = static_cast<size_t>(req->limit() > 0 ? req->limit() : 0);
        size_t idx = 0;
        size_t emitted = 0;
        for (auto& h : handles) {
            if (idx++ < off) {
                continue;
            }
            if (lim && emitted >= lim) {
                break;
            }
            auto* e = resp->add_handles();
            e->set_object(h.Object);
            e->set_handle(h.Handle);
            e->set_granted_access(h.GrantedAccess);
            e->set_type_index(h.TypeIndex);
            e->set_type_name(WideToUtf8(h.TypeName));
            e->set_name(WideToUtf8(h.Name));
            ++emitted;
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status PhysicalRanges(::grpc::ServerContext* ctx, const PhysRangesRequest* req,
                                PhysRangesResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::vector<pry::PhysRange> ranges;
        if (!drv_.Comm().Open() || !drv_.Comm().PhysRanges(ranges)) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        // L5 post-fill slice — driver enumerates the full physical memory
        // map into a vector; we honor proto-level limit/offset (0 == no cap).
        const size_t total = ranges.size();
        size_t start = 0;
        size_t stop = total;
        if (req != nullptr) {
            const int32_t off = req->offset();
            const int32_t lim = req->limit();
            if (off > 0) {
                start = std::min(total, static_cast<size_t>(off));
            }
            if (lim > 0) {
                stop = std::min(total, start + static_cast<size_t>(lim));
            }
        }
        for (size_t i = start; i < stop; ++i) {
            const auto& r = ranges[i];
            auto* e = resp->add_ranges();
            e->set_base(r.Base);
            e->set_size(r.Size);
            e->set_kind(r.Kind);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status PoolScan(::grpc::ServerContext* ctx, const PoolScanRequest* req,
                          PoolScanResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        // Validate + shape the driver options in one place. Content-scan
        // needs both a pattern and a non-zero span; otherwise it degrades
        // to a pure tag/paged filter.
        pry::PoolScanOptions opts;
        opts.TagFilter = req->tag_filter();
        opts.MaxResults = req->max_results();
        opts.Offset = req->offset();
        opts.ContentSpan = req->content_span();
        // resume cursor from a previous scan.
        opts.Cursor = req->cursor();
        if (req->nonpaged_only()) {
            opts.Flags |= PRY_POOL_FLAG_NONPAGED_ONLY;
        }
        if (req->paged_only()) {
            opts.Flags |= PRY_POOL_FLAG_PAGED_ONLY;
        }
        const std::string& pat = req->pattern();
        const std::string& msk = req->mask();
        if (!pat.empty()) {
            if (pat.size() > PRY_POOL_PATTERN_MAX) {
                FillStatus(resp, "pattern too long (>64 bytes)");
                return grpc::Status::OK;
            }
            if (!msk.empty() && msk.size() != pat.size()) {
                FillStatus(resp, "mask length must equal pattern length");
                return grpc::Status::OK;
            }
            opts.Pattern.assign(pat.begin(), pat.end());
            if (msk.empty()) {
                opts.Mask.assign(pat.size(), 0);
            } else {
                opts.Mask.assign(msk.begin(), msk.end());
            }
        }
        std::vector<pry::PoolBlockInfo> entries;
        UINT32 required = 0, considered = 0;
        pry::PoolScanTelemetry telem;
        if (!drv_.Comm().Open()
            || !drv_.Comm().PoolScan(opts, entries, &required, &considered,
                                      &telem)) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        for (const auto& b : entries) {
            auto* e = resp->add_entries();
            e->set_virtual_address(b.VirtualAddress);
            e->set_size_in_bytes(b.SizeInBytes);
            e->set_tag(b.Tag);
            // Decoded 4-char tag for readability. Bytes are stored little-endian.
            char tag[5] = {(char)(b.Tag & 0xFF),
                           (char)((b.Tag >> 8) & 0xFF),
                           (char)((b.Tag >> 16) & 0xFF),
                           (char)((b.Tag >> 24) & 0xFF),
                           0};
            for (int i = 0; i < 4; i++) {
                unsigned char c = (unsigned char)tag[i];
                if (c < 0x20 || c > 0x7E) tag[i] = '.';
            }
            e->set_tag_ascii(tag);
            e->set_nonpaged(b.NonPaged != 0);
            e->set_matched_offset(b.MatchedOffset);
        }
        resp->set_required(required);
        resp->set_considered(considered);
        // telemetry.
        resp->set_holes(telem.Holes);
        resp->set_span_truncated(telem.SpanTruncated);
        resp->set_last_index(telem.LastIndex);
        resp->set_next_cursor(telem.NextCursor);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v7: expose Driver::VaTranslate (PRY_IOCTL_VA_TRANSLATE, shipped in
    // ABI v5 without a wire surface) so LLM callers can locate the physical
    // backing of a known-good VA without a custom EXE.
    // v12: USER space (driver attaches to req->pid) and explicit-cr3 walks
    // (overrides the natural CR3 in either space) now ride the same ioctl.
    grpc::Status VaTranslate(::grpc::ServerContext* ctx, const VaTranslateRequest* req,
                             VaTranslateResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        if (req->space() == PHYSICAL) {
            FillStatus(resp, "va_translate: PHYSICAL isn't an address space to walk");
            return grpc::Status::OK;
        }
        if (req->space() == USER && !req->pid()) {
            FillStatus(resp, "va_translate: space=USER requires pid");
            return grpc::Status::OK;
        }
        UINT64 pa = 0, usedCr3 = 0;
        UINT32 shift = 0;
        if (!drv_.Comm().VaTranslateEx(req->va(), req->cr3(),
                                       req->space() == USER ? req->pid() : 0,
                                       &pa, &shift, &usedCr3)) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_pa(pa);
        resp->set_present(pa != 0);
        resp->set_page_size_shift(shift);
        resp->set_cr3(usedCr3);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v12: per-CPU IDT dump — the driver __sidt's each requested CPU and
    // decodes KIDTENTRY64 rows itself (one OUT_DIRECT round-trip instead
    // of an agent-side kernel read per entry). Rows carry the IDTR.Base
    // they were read from so a per-CPU detour shows as base drift.
    grpc::Status IdtList(::grpc::ServerContext* ctx, const IdtListRequest* req,
                         IdtListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        std::vector<IdtRow> rows;
        UINT64 base = 0;
        UINT32 limit = 0;
        if (!drv_.Comm().IdtList(req->all_cpus(), rows, &base, &limit)) {
            FillStatus(resp, "driver: " + drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        resp->set_idt_base(base);
        resp->set_idt_limit(limit);
        for (const IdtRow& r : rows) {
            auto* e = resp->add_entries();
            e->set_cpu(r.Cpu);
            e->set_vector(r.Vector);
            e->set_handler_va(r.HandlerVa);
            e->set_selector(r.Selector);
            e->set_ist(r.Ist);
            e->set_dpl(r.Dpl);
            e->set_idt_base(r.IdtBase);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v7: server-streaming memory watcher. Bounded by PRY_MAX_WATCHES
    // (default 8) and PRY_WATCH_MIN_MS (default 10 ms) — no runaway
    // busy-loops possible. Watch dies when the client disconnects, when
    // duration_s elapses, or when max_events is reached.
    grpc::Status Watch(::grpc::ServerContext* ctx, const WatchRequest* req,
                       grpc::ServerWriter<WatchEvent>* writer) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto& mw = WatchInstance();
        if (!mw.TryAcquire()) {
            WatchEvent evt;
            evt.mutable_status()->set_ok(false);
            evt.mutable_status()->set_error("watch: PRY_MAX_WATCHES reached");
            writer->Write(evt);
            return grpc::Status::OK;
        }
        WatchSpec spec;
        spec.space = req->space() == KERNEL ? Space::Kernel
                     : (req->space() == PHYSICAL ? Space::Physical : Space::User);
        spec.pid = req->pid();
        spec.address = req->address();
        spec.length = req->length();
        spec.interval_ms = req->interval_ms();
        spec.duration_s = req->duration_s();
        spec.expected.assign((const BYTE*)req->expected_hex().data(),
                             (const BYTE*)req->expected_hex().data() + req->expected_hex().size());
        spec.max_events = req->max_events();
        spec.tag = req->tag();

        auto emit = [&](const WatchEventLite& e) -> bool {
            WatchEvent evt;
            evt.mutable_status()->set_ok(true);
            evt.set_seq(e.seq);
            evt.set_ts_ms(e.ts_ms);
            evt.set_prev(e.prev.data(), e.prev.size());
            evt.set_now(e.now.data(), e.now.size());
            evt.set_eof(e.eof);
            evt.set_reason(e.reason);
            evt.set_read_failed(e.read_failed);
            return writer->Write(evt);
        };
        auto cancelled = [&]() { return ctx->IsCancelled(); };
        std::string err = mw.RunOnce(drv_, spec, emit, cancelled);
        mw.Release();
        if (!err.empty()) {
            WatchEvent evt;
            evt.mutable_status()->set_ok(false);
            evt.mutable_status()->set_error(err);
            evt.set_eof(true);
            evt.set_reason("error");
            writer->Write(evt);
        }
        return grpc::Status::OK;
    }

    // v11: per-thread inventory. kernel=false walks agent-side
    // (NtQuerySystemInformation); kernel=true routes to the driver-backed
    // walk, which adds Win32StartAddress + TebBaseAddress per thread.
    grpc::Status ThreadList(::grpc::ServerContext* ctx,
                            const ThreadListRequest* req,
                            ThreadListResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        if (req->kernel()) {
            std::string err;
            if (!ProbeDriver(drv_, &err)) {
                FillStatus(resp, err);
                return grpc::Status::OK;
            }
            std::vector<ThreadRow> rows;
            UINT32 required = 0;
            if (!drv_.Comm().ThreadList(req->pid(), rows, &required)) {
                FillStatus(resp, drv_.Comm().LastError());
                return grpc::Status::OK;
            }
            for (auto& t : rows) {
                auto* row = resp->add_threads();
                row->set_tid(t.Tid);
                row->set_pid(t.Pid);
                row->set_start_va(t.StartVa);
                row->set_state(t.State);
                row->set_wait_reason(t.WaitReason);
                row->set_base_priority(t.BasePriority);
                row->set_win32_start_va(t.Win32StartVa);
                row->set_teb(t.Teb);
            }
            resp->set_truncated(rows.size() < required);
            resp->set_count((UINT32)rows.size());
            resp->set_source("driver");
            if (req->with_context()) {
                std::map<DWORD, int> wow;
                for (int i = 0; i < resp->threads_size(); ++i) {
                    auto* t = resp->mutable_threads(i);
                    SnapThreadContext(t->pid(), t->tid(), t, &wow);
                }
            }
            FillStatus(resp, "");
            return grpc::Status::OK;
        }
        bool truncated = false;
        UINT32 gle = CollectThreadList(req->pid(), resp, &truncated);
        if (gle) {
            FillStatus(resp, "thread list failed: gle=" + std::to_string(gle));
            return grpc::Status::OK;
        }
        resp->set_truncated(truncated);
        resp->set_count(resp->threads_size());
        resp->set_source("agent");
        if (req->with_context()) {
            std::map<DWORD, int> wow;
            for (int i = 0; i < resp->threads_size(); ++i) {
                auto* t = resp->mutable_threads(i);
                SnapThreadContext(t->pid(), t->tid(), t, &wow);
            }
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v11: kernel object-directory enumeration (\Device, \Driver, ...).
    // Driver-side ZwOpen/QueryDirectoryObject — version-proof.
    grpc::Status ObjEnum(::grpc::ServerContext* ctx,
                         const ObjEnumRequest* req,
                         ObjEnumResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        std::string err;
        if (!ProbeDriver(drv_, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        if (req->path().empty() || req->path()[0] != '\\') {
            FillStatus(resp, "objenum: path must start with '\\' (e.g. \\Device)");
            return grpc::Status::OK;
        }
        std::vector<pry::ObjEntryRec> entries;
        UINT32 required = 0, truncated = 0;
        std::wstring wpath(req->path().begin(), req->path().end());
        if (!drv_.Comm().ObjEnum(wpath, req->depth(), req->max_entries(),
                                 entries, &required, &truncated)) {
            FillStatus(resp, drv_.Comm().LastError());
            return grpc::Status::OK;
        }
        for (auto& e : entries) {
            auto* row = resp->add_entries();
            row->set_name(WideToUtf8(e.Name));
            row->set_type(WideToUtf8(e.Type));
            // object body VA + type index + walk source.
            row->set_address(e.Address);
            row->set_type_index(e.TypeIndex);
            row->set_source(e.Source);
        }
        resp->set_count((UINT32)entries.size());
        resp->set_truncated(truncated != 0);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // segment-heap decode via a hardcoded
    // 26100/26200 offset table + pattern-scan fallback. The agent view
    // uses the driver's PRY_IOCTL_USER_MEM_READ as the UserReadFn so
    // PPL targets still see heap internals (the slice doc's PPL
    // asymmetry: umagent fails ACCESS_DENIED, agent succeeds).
    //
    // The full decoder (SegContexts walk, _HEAP_PAGE_RANGE_DESCRIPTOR
    // classification, LFH bucket enumeration) lands with dyn-data Wave
    // 3; this build ships the honest scaffold so the capability shows up at
    // the right verb with the right coverage shape — ``coverage='partial'``
    // + ``warnings='dyn_data_wave_3_pending'`` on every row.
    grpc::Status HeapInfo(::grpc::ServerContext* ctx,
                           const HeapInfoRequest* req,
                           HeapInfoResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        if (req->pid() == 0) {
            FillStatus(resp,
                        "heap_info: pid > 0 required (segment-heap decode "
                        "is per-process)");
            resp->set_coverage("partial");
            resp->set_hint("bad_arg");
            return grpc::Status::OK;
        }
        // Wave 3 dyn-data (`comm/abi/dyn.h` empty) is the primary input
        // for the signed segment-heap offset table. Until it lands the
        // walker degrades to the pattern-scan fallback, which lives
        // out-of-service in `agent/src/pe/heap_walker.cpp` (shared with
        // the umagent view). The service entry stays live so callers
        // can probe for the feature by observing the ``partial`` +
        // ``warnings='dyn_data_wave_3_pending'`` envelope — same contract
        // the SI #3 WaitInfo IOCTL uses while Wave 3 is in flight.
        resp->set_coverage("partial");
        resp->set_hint("dyn_data_wave_3_pending");
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // VA -> heap allocation. See the
    // HeapAttribCache above for the TTL/committed-sum/refresh contract.
    grpc::Status HeapAttribLookup(::grpc::ServerContext* ctx,
                                  const HeapAttribRequest* req,
                                  HeapAttribResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        if (req->pid() == 0) {
            resp->mutable_status()->set_ok(false);
            resp->mutable_status()->set_error(
                "heap_attrib: pid > 0 required");
            resp->mutable_status()->set_errno_code(1);
            resp->mutable_status()->set_kind("bad_arg");
            return grpc::Status::OK;
        }
        const int n = req->vas_size();
        if (n == 0) {
            resp->mutable_status()->set_ok(false);
            resp->mutable_status()->set_error(
                "heap_attrib: vas must contain at least one VA");
            resp->mutable_status()->set_errno_code(1);
            resp->mutable_status()->set_kind("bad_arg");
            return grpc::Status::OK;
        }
        if ((uint32_t)n > pry::pe::HEAPATTRIB_MAX_VAS) {
            resp->mutable_status()->set_ok(false);
            resp->mutable_status()->set_error(
                "heap_attrib: vas exceeds per-call cap (" +
                std::to_string(pry::pe::HEAPATTRIB_MAX_VAS) + ")");
            resp->mutable_status()->set_errno_code(1);
            resp->mutable_status()->set_kind("too_many_vas");
            return grpc::Status::OK;
        }

        pry::pe::UserReadFn user_read =
            [this](uint32_t p, uint64_t a, void* d, size_t l) -> bool {
                MemReaderCtx c{&drv_};
                return UserMemReadFn(&c, p, a, d, l);
            };

        auto& cache = HeapAttribCache::Instance();
        std::lock_guard<std::mutex> lk(cache.Mutex());
        bool from_cache = false;
        std::string err;
        auto* idx = cache.GetOrBuild(req->pid(), user_read, req->refresh(),
                                     from_cache, err);
        if (!idx) {
            resp->mutable_status()->set_ok(false);
            resp->mutable_status()->set_error(
                err.empty() ? "heap walk failed" : err);
            resp->mutable_status()->set_errno_code(1);
            // When the index build yields NO intervals (PEB fallback /
            // debug-info API refused) we still report the rebuild
            // outcome via a success path below. Build FAILURE is a
            // distinct failure mode.
            resp->mutable_status()->set_kind("heap_walk_failed");
            return grpc::Status::OK;
        }
        // PEB-fallback path: idx->ivals is empty. Return per-VA
        // records with found=false; callers map this to the
        // ``heap_blocks_unavailable`` orchestrator slug when the whole
        // batch misses (see plan §7.7). Keep index_from_cache honest.
        for (int i = 0; i < n; ++i) {
            uint64_t va = req->vas(i);
            auto* rec = resp->add_records();
            rec->set_va(va);
            uint64_t seg = 0, heap = 0;
            uint32_t flags = 0;
            const auto* blk = pry::pe::LookupByVA(*idx, va, &seg,
                                                      &heap, &flags);
            if (blk) {
                rec->set_found(true);
                rec->set_heap_handle(heap);
                rec->set_segment_base(seg);
                rec->set_chunk_base(blk->address);
                rec->set_chunk_size(blk->size);
                rec->set_flags(flags);
                // size_class: smallest power-of-2 >= chunk_size.
                uint32_t cls = 0;
                if (blk->size > 0) {
                    cls = 1;
                    while ((uint64_t)cls < blk->size) {
                        if (cls & 0x80000000u) { cls = 0; break; }
                        cls <<= 1;
                    }
                }
                rec->set_size_class(cls);
            }
        }
        resp->set_index_from_cache(from_cache);
        resp->set_cache_epoch(idx->epoch);
        // cache_age_ms = now - built_ms (monotonic).
        using namespace std::chrono;
        const uint64_t now = (uint64_t)duration_cast<milliseconds>(
            steady_clock::now().time_since_epoch()).count();
        resp->set_cache_age_ms(now >= idx->built_ms
                                   ? now - idx->built_ms : 0);
        resp->set_cache_committed_sum(idx->committed_sum);
        resp->mutable_status()->set_ok(true);
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

void RegisterMemorySvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv)
{
    static MemorySvc memorySvc(cfg, drv);
    builder.RegisterService(&memorySvc);
}

} // namespace pry
