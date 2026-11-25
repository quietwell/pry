// agent/src/host/system_power.hpp — target_manage.reboot.
//
// Thin wrapper over InitiateShutdownW / ExitWindowsEx / AbortSystemShutdownW
// so the Reboot RPC handler stays a dispatch shell. Follows the
// host/host_info.{hpp,cpp} + host/token_mutate.{hpp,cpp} split pattern.

#pragma once

#include <cstdint>
#include <string>

namespace pry::host {

struct RebootParams {
    enum class Mode {
        Reboot,     // SHUTDOWN_RESTART
        Shutdown,   // SHUTDOWN_NOREBOOT (power stays on, user has to shut it)
        PowerOff,   // SHUTDOWN_POWEROFF (ACPI off)
        Logoff,     // ExitWindowsEx(EWX_LOGOFF ...)
        Abort,      // AbortSystemShutdownW — cancels a pending shutdown
    };
    Mode        mode              = Mode::Reboot;
    uint32_t    delay_s           = 0;
    bool        force             = false;  // SHUTDOWN_FORCE_OTHERS
    bool        force_if_hung     = false;  // SHUTDOWN_FORCE_SELF
    std::wstring reason           = L"pry target_manage.reboot";
    // 0 → auto: MAJOR_OTHER | MINOR_OTHER | FLAG_PLANNED.
    uint32_t    reason_code       = 0;
    // Keep SHUTDOWN_GRACE_OVERRIDE off so group-policy minimums apply.
    bool        wait_pre_shutdown = false;
};

struct RebootResult {
    bool        ok                 = false;
    // Win32 error from InitiateShutdownW (NOT GetLastError) or
    // GetLastError from the ExitWindowsEx/AbortSystemShutdownW paths.
    uint32_t    win32_error        = 0;
    std::string message;
    uint32_t    mode_applied       = 0;  // mirrors RebootRequest.Mode wire value
    uint32_t    delay_s_applied    = 0;
};

// Enables SeShutdownPrivilege on the current process token via the
// existing pry::host::AdjustPrivilege helper, then dispatches by
// mode. A hard "SeShutdownPrivilege absent" failure surfaces as
// ok=false with message="privilege_absent: ..." so the caller can
// classify it specifically (an Rpc handler will map to kind=
// 'privilege_absent'). Pure wrapper — no logging, no gRPC types.
RebootResult InitiateReboot(const RebootParams& p);

}  // namespace pry::host
