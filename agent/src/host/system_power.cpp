// agent/src/host/system_power.cpp — target_manage.reboot.
//
// InitiateShutdownW composes reboot/shutdown/poweroff + the force flags +
// optional SHUTDOWN_GRACE_OVERRIDE in one call (the API MSDN currently
// recommends). ExitWindowsEx is kept only for the LOGOFF path because
// InitiateShutdownW has no session-logoff mode.
//
// Privilege: SeShutdownPrivilege lives in the LocalSystem service
// token by default but ships *disabled*, so AdjustTokenPrivileges must
// enable it first. The existing pry::host::AdjustPrivilege helper
// does exactly that and soft-returns "absent" when the token genuinely
// lacks the LUID (treated here as a hard failure — a service token
// without SeShutdownPrivilege can't perform a system shutdown).

#include "system_power.hpp"
#include "token_mutate.hpp"

#include <windows.h>
#include <reason.h>     // SHTDN_REASON_* constants

#include <cstdio>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

namespace pry::host {

namespace {

std::string Win32Message(DWORD err) {
    if (err == 0) {
        return {};
    }
    LPWSTR w = nullptr;
    DWORD n = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&w), 0, nullptr);
    if (!w || n == 0) {
        if (w) {
            ::LocalFree(w);
        }
        char buf[64];
        std::snprintf(buf, sizeof(buf), "win32 err=0x%08lx",
                      static_cast<unsigned long>(err));
        return buf;
    }
    int u = ::WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(n),
                                   nullptr, 0, nullptr, nullptr);
    std::string out;
    if (u > 0) {
        out.assign(static_cast<size_t>(u), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(n),
                              out.data(), u, nullptr, nullptr);
    }
    ::LocalFree(w);
    // FormatMessageW likes to end with "\r\n ."; trim.
    while (!out.empty() &&
           (out.back() == '\r' || out.back() == '\n' ||
            out.back() == ' '  || out.back() == '.')) {
        out.pop_back();
    }
    if (out.empty()) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "win32 err=0x%08lx",
                      static_cast<unsigned long>(err));
        out = buf;
    }
    return out;
}

}  // namespace

RebootResult InitiateReboot(const RebootParams& p) {
    RebootResult r;
    r.mode_applied    = static_cast<uint32_t>(p.mode);
    r.delay_s_applied = p.delay_s;

    // 1. Enable SeShutdownPrivilege on the agent process token.
    auto adj = AdjustPrivilege(static_cast<uint32_t>(::GetCurrentProcessId()),
                               0, "SeShutdownPrivilege", 0, 0, "enable");
    if (!adj.ok) {
        r.ok = false;
        r.win32_error = static_cast<uint32_t>(ERROR_PRIVILEGE_NOT_HELD);
        r.message = std::string("privilege_adjust_failed: ") + adj.err;
        return r;
    }
    if (adj.new_state == "absent") {
        r.ok = false;
        r.win32_error = static_cast<uint32_t>(ERROR_PRIVILEGE_NOT_HELD);
        r.message = "privilege_absent: SeShutdownPrivilege not in the agent "
                    "service token";
        return r;
    }

    const DWORD default_reason =
        SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER |
        SHTDN_REASON_FLAG_PLANNED;
    const DWORD reason_code =
        p.reason_code != 0 ? static_cast<DWORD>(p.reason_code)
                           : default_reason;

    // 2. Abort — AbortSystemShutdownW doesn't need the reason or flags.
    if (p.mode == RebootParams::Mode::Abort) {
        if (::AbortSystemShutdownW(nullptr)) {
            r.ok = true;
            return r;
        }
        DWORD gle = ::GetLastError();
        r.ok = false;
        r.win32_error = static_cast<uint32_t>(gle);
        r.message = Win32Message(gle);
        return r;
    }

    // 3. Logoff — ExitWindowsEx; InitiateShutdownW has no logoff mode.
    if (p.mode == RebootParams::Mode::Logoff) {
        UINT flags = EWX_LOGOFF | (p.force ? EWX_FORCE : 0u);
        if (::ExitWindowsEx(flags, reason_code)) {
            r.ok = true;
            return r;
        }
        DWORD gle = ::GetLastError();
        r.ok = false;
        r.win32_error = static_cast<uint32_t>(gle);
        r.message = Win32Message(gle);
        return r;
    }

    // 4. Reboot / Shutdown / PowerOff → InitiateShutdownW.
    DWORD flags = 0;
    switch (p.mode) {
        case RebootParams::Mode::Reboot:
            flags |= SHUTDOWN_RESTART;
            break;
        case RebootParams::Mode::Shutdown:
            flags |= SHUTDOWN_NOREBOOT;
            break;
        case RebootParams::Mode::PowerOff:
            flags |= SHUTDOWN_POWEROFF;
            break;
        default:
            // Already handled above; keep the compiler happy.
            break;
    }
    if (p.force) {
        flags |= SHUTDOWN_FORCE_OTHERS;
    }
    if (p.force_if_hung) {
        flags |= SHUTDOWN_FORCE_SELF;
    }
    // Grace override — bypass group-policy minimum timer when the caller
    // asked for a near-immediate reboot and wait_pre_shutdown isn't set.
    if (p.delay_s < 20 && !p.wait_pre_shutdown) {
        flags |= SHUTDOWN_GRACE_OVERRIDE;
    }

    DWORD rc = ::InitiateShutdownW(
        /*lpMachineName*/ nullptr,
        /*lpMessage    */ p.reason.empty() ? nullptr
                                           : const_cast<LPWSTR>(p.reason.c_str()),
        /*dwGracePeriod*/ p.delay_s,
        /*dwShutdownFlags*/ flags,
        /*dwReason    */ reason_code);
    if (rc == ERROR_SUCCESS) {
        r.ok = true;
        return r;
    }
    r.ok = false;
    r.win32_error = static_cast<uint32_t>(rc);
    r.message = Win32Message(rc);
    return r;
}

}  // namespace pry::host
