#pragma once

#include <windows.h>
#include <atomic>
#include <string>
#include <vector>

#include "pry_abi.h"

namespace pry {

enum class Space { User, Kernel, Physical };

struct PingInfo {
    UINT32 VersionMajor;
    UINT32 VersionMinor;
    UINT32 NtBuild;
    UINT32 Flags;
    UINT32 AbiVersion;
};

struct ModuleEntry {
    UINT64 Base;
    UINT64 Size;
    std::wstring Name;
    std::wstring Path;
};

struct ProcessEntry {
    UINT32 Pid;
    UINT32 ParentPid;
    std::wstring ImageName;
};

struct VadRecord {
    UINT64 Start;
    UINT64 End; // exclusive
    UINT32 Protect; // Win32 PAGE_*
    UINT32 VadType;
    UINT64 CommitCharge;
};

struct HandleRecord {
    UINT64 Object;
    UINT64 Handle;
    UINT32 GrantedAccess;
    UINT32 TypeIndex;
    std::wstring TypeName;
    std::wstring Name;
};

struct PhysRange {
    UINT64 Base;
    UINT64 Size;
    UINT32 Kind; // PRY_PHYS_KIND_*
};

struct PoolBlockInfo {
    UINT64 VirtualAddress;
    UINT64 SizeInBytes;
    UINT32 Tag;          // 4 ASCII chars packed little-endian
    UINT32 NonPaged;     // 1 = non-paged
    UINT64 MatchedOffset;
};

struct PoolScanOptions {
    UINT32 TagFilter = 0;
    UINT32 Flags = 0;
    UINT32 MaxResults = 0;
    UINT32 Offset = 0;
    UINT32 ContentSpan = 0;
    std::vector<UCHAR> Pattern; // <= PRY_POOL_PATTERN_MAX bytes
    std::vector<UCHAR> Mask;    // same length as Pattern (0 or '?' = wildcard)
    // resume cursor from a previous scan's NextCursor
    // (0 = fresh scan).
    UINT32 Cursor = 0;
};

// scan telemetry extracted from PRY_POOL_HDR.
struct PoolScanTelemetry {
    UINT32 Required = 0;
    UINT32 Considered = 0;
    UINT32 Holes = 0;
    UINT32 SpanTruncated = 0;
    UINT32 LastIndex = 0;
    UINT32 NextCursor = 0;
};

struct WatchdogEntry {
    UINT32 Id;
    UINT32 BugcheckCode;
    UINT64 DeadlineUs;
    UINT64 LastKickUs;
    UINT64 KickCount;
    UINT64 Cookie;
    UINT64 ArmedUs;
    std::string Label;
    // orchestrator convenience: DeadlineUs - NowUs (signed; negative = overdue)
    // Populated by List() from the header's NowUs.
    int64_t RemainingUs;
};

struct BpRecord {
    UINT32 Id;
    UINT32 Kind;
    UINT32 Pid;
    UINT32 Tid;
    UINT32 Slot;
    UINT32 Length;
    UINT32 Access;
    UINT32 Enabled;
    UINT64 Address;
    UCHAR OrigByte;
};

// v10: notify event ring + kernel object/thread enumeration.
// (Named *Rec: the generated proto messages live in this same namespace.)
struct PryEventRec {
    UINT64 Seq;
    UINT64 TsMs;
    UINT32 Kind; // PRY_EVT_KIND_*
    UINT32 Pid;
    UINT32 ParentPid;
    UINT32 Tid;
    UINT64 ImageBase;
    UINT64 ImageSize;
    std::wstring Image;
    // v11: BP_HIT payload (0 for other kinds)
    UINT64 Address;  // faulting RIP
    UINT64 Dr6;
    UINT32 BpId;
    UINT32 Slot;
    UINT32 Access;   // PRY_HW_*
    UINT32 Irql;
};

struct PryNotifyStats {
    UINT32 Registered;  // PRY_EVT_CLASS_* bitmask
    UINT32 ProcVariant; // 1 = Ex routine, 2 = classic, 0 = none
    UINT32 BpTrapMissed; // v11: hits consumed without a ring record
    UINT64 Buffered;
    UINT64 Dropped;
    UINT64 Seq;
    UINT64 Total;
};

struct ObjEntryRec {
    std::wstring Name;
    std::wstring Type;
    UINT32 IsDirectory;
    // object body VA + type index when the driver
    // resolved it (ObReferenceObjectByName); 0 on the ZwQueryDirectoryObject
    // fallback. Source is "walk" when address is populated, else "zwquery".
    UINT64 Address = 0;
    UINT32 TypeIndex = 0;
    std::string Source;    // "walk" | "zwquery"
};

struct ThreadRow {
    UINT32 Tid;
    UINT32 Pid;
    UINT32 State;
    UINT32 WaitReason;
    INT32 BasePriority;
    UINT32 Flags; // PRY_THREAD_FLAG_*
    UINT64 StartVa;
    UINT64 Win32StartVa;
    UINT64 Teb;
};

// v12: one decoded KIDTENTRY64 row plus the IDTR base it was read from.
struct IdtRow {
    UINT32 Cpu;
    UINT32 Vector;
    UINT64 HandlerVa;
    UINT32 Selector;
    UINT32 Ist;
    UINT32 Dpl;
    UINT32 Type;
    UINT32 Present;
    UINT64 IdtBase;
};

// Optional pre/post trace hooks. The agent registers one at startup to
// stamp a persistent breadcrumb around every driver call — see
// agent/src/breadcrumb.hpp. Nullptr = no hook (default; drv_exerciser
// runs unhooked). Callbacks must be reentrant and cheap.
using TracePreFn = uint64_t(*)(unsigned long ioctl, const void* in, unsigned long inSize);
using TracePostFn = void(*)(uint64_t token, bool ok, unsigned long win_gle_or_zero);

// Pure predicate behind Driver's hdr+rows reply validation: `count` rows of
// `entrySize` after a `hdrSize` header must fit the caller's buffer AND the
// byte count the driver returned (`ret`; only checked when count > 0).
inline bool ReplyRowsFit(unsigned long ret, size_t bufBytes, size_t hdrSize, size_t entrySize,
                         UINT32 count)
{
    const unsigned long long need =
        (unsigned long long)hdrSize + (unsigned long long)count * entrySize;
    return need <= bufBytes && (count == 0 || need <= (unsigned long long)ret);
}

// Thread-safety (mechanics audit P1): one Driver is shared by every gRPC
// worker thread of the agent. The device handle is guarded by an SRW lock
// (shared for IOCTLs, exclusive for open/close/reopen) and the last-error
// text is THREAD-LOCAL — LastError() reports the most recent failure of a
// Driver call made on the calling thread (any Driver instance), so read it
// right after the failing call, on the same thread.
class Driver {
public:
    Driver() = default;
    ~Driver() { Close(); }
    Driver(const Driver&) = delete;
    Driver& operator=(const Driver&) = delete;

    // Global (process-wide) trace hooks. Set once at startup; not reset.
    static void SetTraceHooks(TracePreFn pre, TracePostFn post);

    // Process-wide ABI enforcement. 0 (default) = off — drv_exerciser and
    // the mapper keep talking to whatever driver is loaded. The agent sets
    // PRY_ABI_VERSION at startup: every IOCTL except PING is then refused
    // with "driver_abi_mismatch: ..." (gle ERROR_REVISION_MISMATCH) while the
    // driver's PING-reported ABI differs, instead of misparsing its replies.
    // The driver ABI is (re)probed with one PING after every handle (re)open.
    static void RequireAbi(UINT32 abi);
    static UINT32 RequiredAbi();
    // ABI the driver reported on the last PING over the current handle;
    // 0 = not probed since the handle was (re)opened (or no driver).
    UINT32 DriverAbi() const { return abiVersion_.load(std::memory_order_acquire); }
    // Forget the cached ABI so the next call re-probes (driver swapped).
    void InvalidateAbi() { abiVersion_.store(0, std::memory_order_release); }

    bool Open();
    void Close();
    bool IsOpen() const { return h_.load(std::memory_order_acquire) != INVALID_HANDLE_VALUE; }
    const std::string& LastError() const { return ErrSlot(); }

    bool Ping(PingInfo* out);

    bool MemRead(Space space, UINT32 pid, UINT64 addr, void* buf, SIZE_T len, SIZE_T* got, UINT32 flags = 0);
    // v12: cr3 (kernel space only) writes under the caller-supplied address
    // space; flags2 carries PRY_MEM_WRF_* (STRICT_VA). When the driver
    // answers with a v12 out-reply, writePath reports the PRY_MEM_WRITE_PATH_*
    // the store actually took (UNKNOWN on a pre-v12 driver or no out buffer).
    bool MemWrite(Space space, UINT32 pid, UINT64 addr, const void* buf, SIZE_T len, SIZE_T* written,
                  UINT32 flags = 0, UINT64 cr3 = 0, UINT32 flags2 = 0, UINT8* writePath = nullptr);
    bool UserAlloc(UINT32 pid, UINT64 size, UINT32 protect, UINT64* addr);
    bool UserFree(UINT32 pid, UINT64 addr);
    bool UserProtect(UINT32 pid, UINT64 addr, UINT64 size, UINT32 protect, UINT32* oldProtect);
    bool KmemAlloc(UINT64 size, UINT64* addr);
    bool KmemFree(UINT64 addr);

    bool UserModules(UINT32 pid, std::vector<ModuleEntry>& out, bool wow64 = false);
    bool KernelModules(std::vector<ModuleEntry>& out);
    bool ProcessList(std::vector<ProcessEntry>& out);
    bool VadList(UINT32 pid, std::vector<VadRecord>& out);
    bool HandleList(UINT32 pid, std::vector<HandleRecord>& out, bool wantNames = false);

    bool CtxGet(UINT64 tid, ULONG flags, CONTEXT* ctx);
    bool CtxSet(UINT64 tid, ULONG flags, const CONTEXT* ctx);

    bool BpSwSet(UINT32 pid, UINT64 addr, UINT32* id, UCHAR* origByte);
    bool BpSwClear(UINT32 pid, UINT64 addr, UINT32 id);
    bool BpHwSet(UINT32 pid, UINT64 tid, UINT64 addr, UINT32 slot, UINT32 len, UINT32 access,
                 UINT32* id, UINT32* patched, UINT32 flags = 0);
    bool BpHwClear(UINT32 pid, UINT64 tid, UINT32 slot, UINT32* patched);
    bool BpList(std::vector<BpRecord>& out);

    bool RemoteCall(UINT32 pid, UINT64 tid, UINT64 target, UINT64 a1, UINT64 a2, UINT64 a3,
                    UINT32 flags, bool* queued, bool* alerted);

    // v13: synchronous kernel function call (driver work item at PASSIVE_LEVEL).
    // out->Status holds the op result (STATUS_SUCCESS/STATUS_TIMEOUT/...);
    // out->ReturnValue is rax. See pry_abi.h "kernel call" section.
    bool KernelCall(const PRY_KERNEL_CALL_IN& in, PRY_KERNEL_CALL_OUT* out);

    bool PhysRanges(std::vector<PhysRange>& out);
    bool PoolScan(const PoolScanOptions& opts, std::vector<PoolBlockInfo>& out,
                  UINT32* required = nullptr, UINT32* considered = nullptr,
                  PoolScanTelemetry* telemetry = nullptr);
    bool VaTranslate(UINT64 va, UINT64* pa);
    // v12: walk under an explicit cr3 (0 = resolve from pid/kernel context),
    // or a target process's tables (pid != 0). usedCr3 reports the CR3 the
    // walk actually ran under; pageSizeShift = 12/21/30 for the mapping leaf.
    bool VaTranslateEx(UINT64 va, UINT64 cr3, UINT32 pid, UINT64* pa,
                       UINT32* pageSizeShift = nullptr, UINT64* usedCr3 = nullptr);

    // v12: per-CPU IDT dump. allCpus walks every processor index (skips
    // holes); rows carry the IDTR.Base they were read from so per-CPU
    // drift is visible caller-side.
    bool IdtList(bool allCpus, std::vector<IdtRow>& out,
                 UINT64* idtBase = nullptr, UINT32* idtLimit = nullptr);

    // PR#6 T3.2 (2026-10): per-core MSR / CPUID reader. #GP on an
    // unimplemented MSR surfaces as per-row NtStatus=STATUS_UNSUCCESSFUL
    // (never a bugcheck); CPUID never faults on a legal operand.
    struct MsrRow { UINT32 Core; UINT32 NtStatus; UINT64 Value; };
    struct CpuidRow { UINT32 Core; UINT32 Eax; UINT32 Ebx; UINT32 Ecx; UINT32 Edx; };
    bool MsrRead(UINT32 msr, const std::vector<UINT32>& cores, bool allCores,
                 std::vector<MsrRow>& out);
    bool CpuidRead(UINT32 leaf, UINT32 subleaf, const std::vector<UINT32>& cores,
                   bool allCores, std::vector<CpuidRow>& out);

    // v8: wedge-detector watchdog. Arm sets/replaces a deadline slot; Kick
    // resets the deadline; Disarm removes the slot; List enumerates.
    // See pry_abi.h "Watchdog" section for contract.
    bool WatchdogArm(UINT32 id, UINT32 deadlineMs, UINT32 bugcheckCode,
                     UINT32 flags, UINT64 cookie, const std::string& label);
    bool WatchdogKick(UINT32 id, UINT32 deadlineMs, UINT64 cookie,
                      UINT64* kickCount = nullptr, UINT64* lastKickUs = nullptr,
                      UINT64* deadlineUs = nullptr);
    bool WatchdogDisarm(UINT32 id);
    bool WatchdogList(std::vector<WatchdogEntry>& out, UINT64* nowUs = nullptr);

    // v10: notify event ring (the agent's "ears") + kernel enumeration.
    // Subscribe registers the requested PsSet*NotifyRoutine classes
    // (kernel-visible state — the orchestrator gates it); Read drains
    // oldest-first and returns the cumulative dropped counter; Disable
    // unregisters everything; Stats snapshots the ring.
    // v11: `flags` is PRY_NOTIFY_FLAG_* — CLASS_BP refuses without
    // PRY_NOTIFY_FLAG_BP_HOOK_OK (the subscribe installs the int1 hook).
    bool NotifySubscribe(UINT32 classes, UINT32 flags,
                         UINT32* registered = nullptr);
    bool NotifyRead(UINT32 max, std::vector<PryEventRec>& out,
                    UINT64* dropped = nullptr, UINT64* lastSeq = nullptr);
    bool NotifyDisable(UINT32* registered = nullptr);
    bool NotifyStats(PryNotifyStats* out);

    // v10: kernel object-directory walk (\Device, \Driver, ...) and the
    // enriched kernel-side thread list. Both version-proof (documented
    // query paths driver-side).
    bool ObjEnum(const std::wstring& path, UINT32 depth, UINT32 maxEntries,
                 std::vector<ObjEntryRec>& out, UINT32* required = nullptr,
                 UINT32* truncated = nullptr);
    bool ThreadList(UINT32 pid, std::vector<ThreadRow>& out,
                    UINT32* required = nullptr);

    // SI #21: ObRegisterCallbacks-driven self-protection. Config installs
    // (enable=1) / tears down (enable=0, token-gated) / refreshes PIDs
    // (enable=2). Status is a read-only counters snapshot. Both wrap the
    // dedicated driver IOCTLs; raw IN/OUT structs stay in comm/abi/proc.h.
    bool SelfProtConfig(const PRY_SELFPROT_CONFIG_IN& in,
                        PRY_SELFPROT_CONFIG_OUT* out);
    bool SelfProtStatus(PRY_SELFPROT_STATUS_OUT* out);

    // SI #6: handle_dup / handle_close_remote / handle_compare.
    // Thin wrappers around the three new driver IOCTLs; raw IN/OUT
    // structs stay in comm/abi/proc.h.
    bool HandleDup(const PRY_HANDLE_DUP_IN& in, PRY_HANDLE_DUP_OUT* out);
    bool HandleCloseRemote(const PRY_HANDLE_CLOSE_IN& in,
                           PRY_HANDLE_CLOSE_OUT* out);
    bool HandleCompare(const PRY_HANDLE_CMP_IN& in,
                       PRY_HANDLE_CMP_OUT* out);
    // SI #9: kernel-stack walk delivered through a kernel-mode
    // APC on the target thread. `framesBytes` must hold at least the
    // PRY_STACKWALK_HDR plus whatever frame cap the caller wants.
    bool StackWalk(const PRY_STACKWALK_IN& in,
                   PRY_STACKWALK_HDR* hdr,
                   void* framesBuf, size_t framesBytes,
                   SIZE_T* bytesReturned);
    // SI #3: analyze-wait on thread. Driver walks ETHREAD/KTHREAD
    // under PsLookupThreadByThreadId's reference and fills the hdr +
    // optional trailers (arg frame + user stack) requested in `in`.
    // `trailerBytes` must hold `in.FrameCapture + in.UserStackCapture` on
    // top of the PRY_WAIT_INFO_HDR; `trailerBuf` can be nullptr when
    // both captures are 0. The hdr's Status surfaces STATUS_NOT_SUPPORTED
    // until the Wave 3 dyn-data probe lands.
    bool WaitInfo(const PRY_WAIT_INFO_IN& in,
                  PRY_WAIT_INFO_HDR* hdr,
                  void* trailerBuf, size_t trailerBytes,
                  SIZE_T* bytesReturned);

private:
    bool Call(ULONG ioctl, void* in, ULONG inSize, void* out, ULONG outSize, ULONG* bytesReturned);
    // One DeviceIoControl attempt under the shared lock. *reopened is set
    // when the handle proved stale (device gone) and was replaced, i.e. the
    // request never reached a live driver and may be re-sent once.
    bool CallOnce(ULONG ioctl, void* in, ULONG inSize, void* out, ULONG outSize,
                  ULONG* bytesReturned, bool* reopened);
    bool OpenLocked();   // exclusive lock held
    void CloseLocked();  // exclusive lock held
    void Fail(const char* what, DWORD gle);
    bool FailNt(const char* what, UINT32 ntStatus);
    // hdr+rows reply validation: `count` rows of `entrySize` must fit both
    // the caller's buffer (`bufBytes`) and the byte count the driver
    // returned (`ret`). False (lastError set) on a short/oversized reply —
    // the classic symptom of a driver whose entry struct changed size.
    bool RowsFit(const char* what, ULONG ret, size_t bufBytes, size_t hdrSize,
                 size_t entrySize, UINT32 count);
    static std::string& ErrSlot();
    // Raw NTSTATUS of the last failed call, lifted from ntdll's TEB slot
    // (RtlGetLastNtStatus via GetProcAddress — comm doesn't link ntdll).
    // 0 when unavailable or the failure wasn't NTSTATUS-backed.
    static ULONG LastNtStatus();
    // v12: driver ABI cached by Ping(); 0 = not probed yet. MemWrite consults
    // it to pick the legacy vs extended wire layout (an ext header on a v11
    // driver would be misparsed as payload — the version gate must never be
    // bypassed for shaped input). Reset on every handle (re)open.
    std::atomic<UINT32> abiVersion_{0};

    mutable SRWLOCK lock_ = SRWLOCK_INIT;
    std::atomic<HANDLE> h_{INVALID_HANDLE_VALUE};
};

// Growth cap for the BUFFER_OVERFLOW → retry-with-Required loops: a corrupt
// or hostile Required must not turn into a multi-GB allocation.
constexpr UINT32 PRY_COMM_MAX_ROWS = 1u << 20;

} // namespace pry


