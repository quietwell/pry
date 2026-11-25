#pragma once

#include <string>

namespace pry {

struct AgentConfig {
    int port = 50074;
    std::string token;             // required (--token or --token-file)
    // --token-file <path> — token read from a SYSTEM+Admins-only
    // file instead of the (world-readable) service binPath. Wins over
    // --token when both are given. tokenError is non-empty when the file
    // could not be read; AgentMain refuses to start then.
    std::wstring tokenFile;
    std::string tokenError;
    std::wstring driverPath;       // default: <exedir>\pry_driver.sys
    std::wstring mapperPath;       // default: <exedir>\mapper.exe
    std::wstring trashDir;         // default: <exedir>\.pry_trash
    bool allowDriverLoad = true;
    bool allowDriverUnload = true;
    // --allow-delete: permits Files.Delete with no_trash=true (hard delete).
    // Without it a hard delete is refused with an explicit error and the
    // trash-safe delete (no_trash=false) keeps working. The default service
    // install passes it (scripts/install_agent_service.ps1 -AllowHardDelete).
    bool allowDelete = false;
    size_t maxTransferBytes = 512ull * 1024 * 1024;
    size_t maxMemReadBytes = 8ull * 1024 * 1024;

    // lifecycle + diagnostics.
    bool devConsole = false;       // --dev: console mode (also disables the
                                   // stdio-to-NUL redirect; see srv_log.hpp)
    std::wstring logPath;          // --log <path>: rotating agent+gRPC log
    size_t logMaxBytes = 4ull * 1024 * 1024; // --log-max-mb <n>

    // static-IPv4 pinning. Disabled unless pin_adapter
    // is non-empty. The agent re-applies pin_address/pin_prefix (and the
    // optional gateway) at service start and on NotifyUnicastIpAddressChange,
    // debounced by pin_debounce_ms. Only the named adapter is ever touched.
    // The hold-marker env var (PRY_NET_PIN_HOLD) or marker file silences
    // the re-pin for the duration of a deliberate NIC flap.
    std::wstring pinAdapter;
    std::wstring pinAddress;
    uint32_t pinPrefix = 24;
    std::wstring pinGateway;
    uint32_t pinDebounceMs = 5000;
    bool pinAtBootOnly = false;    // skip the change-notification path
    std::wstring pinHoldMarker;    // path checked each pin attempt; set →
                                   // skip. Falls back to %TEMP%\pry_net_pin_hold.

    static AgentConfig FromArgs(int argc, char** argv);
    static std::wstring ExeDir();
};

} // namespace pry
