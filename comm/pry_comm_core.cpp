// pry_comm core: device handle lifecycle, IOCTL dispatch, trace hooks,
// the ABI gate and the trivial Ping wrapper. Split from pry_comm.cpp
// (Phase 7c).
//
// Concurrency (mechanics audit P1): the agent shares ONE Driver across all
// gRPC worker threads.
//   * h_ is guarded by lock_: IOCTLs run under the SHARED lock, open /
//     close / reopen take it EXCLUSIVE — a handle is never closed while
//     another thread is inside DeviceIoControl on it.
//   * lastError is thread-local (ErrSlot), so concurrent failures no longer
//     race on one std::string.
//   * A failed IOCTL reopens the handle ONLY when the failure means the
//     handle/device is gone (see DeviceGone). ERROR_ACCESS_DENIED,
//     ERROR_NOT_FOUND, ERROR_NOT_READY, ... are driver refusals: the
//     request is NOT re-sent (the physical-read guard answers
//     STATUS_ACCESS_DENIED on purpose; re-sending it doubled the work and
//     tore the handle out from under every concurrent caller).
#include "pry_comm_internal.hpp"

#include <cstdio>
#include <string>

namespace pry {

namespace {

// NTSTATUS values that only the I/O manager produces for a dead device
// (none of them is returned by the pry driver's own handlers).
constexpr ULONG kStatusDeletePending = 0xC0000056;   // -> ERROR_ACCESS_DENIED
constexpr ULONG kStatusNoSuchDevice = 0xC000000E;    // -> ERROR_FILE_NOT_FOUND
constexpr ULONG kStatusDeviceRemoved = 0xC00002B6;   // -> ERROR_DEVICE_REMOVED

std::atomic<UINT32> g_required_abi{0};

} // namespace

std::string& Driver::ErrSlot()
{
    thread_local std::string err;
    return err;
}

void Driver::RequireAbi(UINT32 abi)
{
    g_required_abi.store(abi, std::memory_order_release);
}

UINT32 Driver::RequiredAbi()
{
    return g_required_abi.load(std::memory_order_acquire);
}

bool Driver::OpenLocked()
{
    if (h_.load(std::memory_order_relaxed) != INVALID_HANDLE_VALUE) {
        return true;
    }
    HANDLE h = CreateFileW(L"\\\\.\\PryDrv", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        Fail("CreateFile(\\\\.\\PryDrv)", GetLastError());
        return false;
    }
    abiVersion_.store(0, std::memory_order_release); // new device instance: re-probe
    h_.store(h, std::memory_order_release);
    return true;
}

void Driver::CloseLocked()
{
    HANDLE h = h_.exchange(INVALID_HANDLE_VALUE, std::memory_order_acq_rel);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    abiVersion_.store(0, std::memory_order_release);
}

bool Driver::Open()
{
    if (IsOpen()) {
        return true;
    }
    AcquireSRWLockExclusive(&lock_);
    bool ok = OpenLocked();
    ReleaseSRWLockExclusive(&lock_);
    return ok;
}

void Driver::Close()
{
    AcquireSRWLockExclusive(&lock_);
    CloseLocked();
    ReleaseSRWLockExclusive(&lock_);
}

ULONG Driver::LastNtStatus()
{
    // ntdll is mapped into every Windows process; fetch RtlGetLastNtStatus
    // lazily so targets that don't link ntdll.lib (mapper, drv_exerciser)
    // build unchanged.
    typedef LONG(NTAPI* RtlGetLastNtStatusFn)();
    static RtlGetLastNtStatusFn fn = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (RtlGetLastNtStatusFn)GetProcAddress(
            ntdll, "RtlGetLastNtStatus") : (RtlGetLastNtStatusFn) nullptr;
    }();
    return fn ? (ULONG)fn() : 0;
}

void Driver::Fail(const char* what, DWORD gle)
{
    char buf[64];
    sprintf_s(buf, " gle=%lu", (unsigned long)gle);
    std::string& err = ErrSlot();
    err = std::string(what) + buf;
    // The Win32 projection flattens the driver's NTSTATUS (e.g.
    // STATUS_UNEXPECTED_IO_ERROR -> gle=59). Appending the raw code keeps
    // the orchestrator's classifier pointed at the real fault class
    // instead of the generic driver-error bucket. Best-effort: a failure
    // that never reached an NT syscall leaves a stale/zero value — the
    // zero case is skipped here; a stale value still reads harmlessly.
    ULONG nt = LastNtStatus();
    if (nt != 0) {
        sprintf_s(buf, " nt=0x%08lx", nt);
        err += buf;
    }
}

bool Driver::FailNt(const char* what, UINT32 nt)
{
    char buf[64];
    sprintf_s(buf, " nt=0x%08x", nt);
    ErrSlot() = std::string(what) + buf;
    return false;
}

bool Driver::RowsFit(const char* what, ULONG ret, size_t bufBytes, size_t hdrSize,
                     size_t entrySize, UINT32 count)
{
    if (ReplyRowsFit(ret, bufBytes, hdrSize, entrySize, count)) {
        return true;
    }
    const unsigned long long need =
        (unsigned long long)hdrSize + (unsigned long long)count * entrySize;
    char buf[192];
    sprintf_s(buf,
              "%s: malformed reply (count=%u entry=%zu need=%llu returned=%lu buffer=%zu) — "
              "driver/agent ABI drift?",
              what, count, entrySize, need, (unsigned long)ret, bufBytes);
    ErrSlot() = buf;
    SetLastError(ERROR_INVALID_DATA);
    return false;
}

// v5: process-wide trace hooks. Set once at agent startup; drv_exerciser
// leaves them null so it doesn't pollute the agent's breadcrumb file.
static TracePreFn g_trace_pre = nullptr;
static TracePostFn g_trace_post = nullptr;

void Driver::SetTraceHooks(TracePreFn pre, TracePostFn post)
{
    g_trace_pre = pre;
    g_trace_post = post;
}

// True when a DeviceIoControl failure means the handle or the device
// instance behind it is gone (driver stopped / swapped / VM rollback), as
// opposed to the driver refusing this particular request. Called with the
// shared lock held so `h` cannot be closed and recycled underneath us.
static bool DeviceGone(DWORD gle, ULONG nt, HANDLE h)
{
    switch (gle) {
    case ERROR_INVALID_HANDLE: {
        // Only when OUR handle is actually invalid; a driver handler that
        // completes with STATUS_INVALID_HANDLE (handle ops on a bad remote
        // handle value) lands here too and must not trigger a reopen.
        DWORD flags = 0;
        return !GetHandleInformation(h, &flags);
    }
    case ERROR_DEV_NOT_EXIST:   // STATUS_DEVICE_DOES_NOT_EXIST
    case ERROR_DEVICE_REMOVED:  // STATUS_DEVICE_REMOVED
    case 433:                   // ERROR_NO_SUCH_DEVICE
        return true;
    case ERROR_ACCESS_DENIED:   // also a deliberate driver refusal
        return nt == kStatusDeletePending;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return nt == kStatusNoSuchDevice || nt == kStatusDeviceRemoved;
    default:
        // ERROR_NOT_FOUND, ERROR_NOT_READY (the driver answers
        // STATUS_DEVICE_NOT_READY on purpose), ... are refusals.
        return false;
    }
}

bool Driver::CallOnce(ULONG ioctl, void* in, ULONG inSize, void* out, ULONG outSize,
                      ULONG* bytesReturned, bool* reopened)
{
    *reopened = false;
    if (!Open()) {
        return false;
    }
    uint64_t token = 0;
    if (g_trace_pre) {
        token = g_trace_pre(ioctl, in, inSize);
    }
    DWORD ret = 0;
    DWORD gle = 0;
    ULONG nt = 0;
    bool gone = false;
    AcquireSRWLockShared(&lock_);
    HANDLE h = h_.load(std::memory_order_acquire);
    BOOL ok = FALSE;
    if (h == INVALID_HANDLE_VALUE) {
        // closed by another thread between Open() and here
        gle = ERROR_INVALID_HANDLE;
        gone = true;
    } else {
        ok = DeviceIoControl(h, ioctl, in, inSize, out, outSize, &ret, nullptr);
        if (!ok) {
            gle = GetLastError();
            nt = LastNtStatus();
            gone = DeviceGone(gle, nt, h);
        }
    }
    ReleaseSRWLockShared(&lock_);

    if (ok) {
        if (bytesReturned) {
            *bytesReturned = ret;
        }
        ErrSlot().clear();
        if (g_trace_post) g_trace_post(token, true, 0);
        return true;
    }
    Fail("DeviceIoControl", gle);
    if (g_trace_post) g_trace_post(token, false, gle);
    if (gone) {
        // Replace the stale handle — unless a concurrent caller already
        // did (h_ no longer the handle we failed on).
        AcquireSRWLockExclusive(&lock_);
        if (h_.load(std::memory_order_relaxed) == h) {
            CloseLocked();
        }
        bool reopenOk = OpenLocked();
        ReleaseSRWLockExclusive(&lock_);
        *reopened = reopenOk;
        if (!reopenOk) {
            // Open() recorded the CreateFile failure; keep the IOCTL context
            ErrSlot() = "device gone (DeviceIoControl gle=" + std::to_string(gle) +
                        "), reopen failed: " + ErrSlot();
        }
    }
    return false;
}

bool Driver::Call(ULONG ioctl, void* in, ULONG inSize, void* out, ULONG outSize, ULONG* bytesReturned)
{
    for (int attempt = 0; attempt < 2; ++attempt) {
        const UINT32 want = RequiredAbi();
        if (want != 0 && ioctl != PRY_IOCTL_PING) {
            UINT32 have = DriverAbi();
            if (have == 0) {
                PingInfo p{};
                if (!Ping(&p)) {
                    return false; // driver absent / unreachable: Ping set lastError
                }
                have = p.AbiVersion;
            }
            if (have != want) {
                char buf[160];
                sprintf_s(buf,
                          "driver_abi_mismatch: driver ABI %u != agent ABI %u — driver-backed "
                          "ops are refused until a matching driver is loaded",
                          have, want);
                ErrSlot() = buf;
                SetLastError(ERROR_REVISION_MISMATCH);
                return false;
            }
        }
        bool reopened = false;
        if (CallOnce(ioctl, in, inSize, out, outSize, bytesReturned, &reopened)) {
            return true;
        }
        // Re-send once, and only when the request provably never reached a
        // live driver (stale handle replaced by a fresh one).
        if (!reopened) {
            return false;
        }
    }
    return false;
}

bool Driver::Ping(PingInfo* out)
{
    PRY_PING_OUT p{};
    if (!Call(PRY_IOCTL_PING, nullptr, 0, &p, sizeof(p), nullptr)) {
        return false;
    }
    out->VersionMajor = p.VersionMajor;
    out->VersionMinor = p.VersionMinor;
    out->NtBuild = p.NtBuild;
    out->Flags = p.Flags;
    out->AbiVersion = p.AbiVersion;
    // v12: cache for MemWrite's legacy-vs-ext header decision and the ABI
    // gate. A successful ping is the only trustworthy answer to "which wire
    // shape does the driver parse".
    abiVersion_.store(p.AbiVersion, std::memory_order_release);
    return true;
}

ULONG IoctlFor(Space s, ULONG user, ULONG kernel, ULONG phys)
{
    switch (s) {
    case Space::Kernel: return kernel;
    case Space::Physical: return phys;
    default: return user;
    }
}

} // namespace pry
