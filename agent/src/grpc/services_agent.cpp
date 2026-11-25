#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "pry.grpc.pb.h"
#include "pry_abi.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include "services.hpp"
#include "services_internal.hpp"
#include "../breadcrumb.hpp"
#include "../common.h"
#include "../dump/dumper.hpp"
#include "../files.hpp"
#include "../host/host_info.hpp"
#include "../host/net_pin.hpp"
#include "../host/system_power.hpp"
#include "../pe/pe_reader.hpp"
#include "../pe/heap_walker.hpp"
#include "../watch.hpp"

#include "../host/screen_common.hpp"
#include "../scan/scan_service.hpp"
#include "../scan/pointer_map_service.hpp"
#include "../scan/dissect_service.hpp"

#include <tlhelp32.h>
#include <fstream>
#include <cctype>

namespace pry {

// v15 screen capture / window telemetry (screen_dispatch.cpp). Declared here,
// after pry.grpc.pb.h, so ScreenCaptureRequest/Response resolve to the
// protobuf types in this namespace.
namespace screen {
bool DispatchScreenCapture(const ScreenCaptureRequest& req, ScreenCaptureResponse* resp);
}

static UINT32 CurrentPid()
{
    return GetCurrentProcessId();
}

// v7: agent-uptime baseline. Populated once on first call; StatusResponse
// surfaces the ms delta so target_manage(action='crash_state') can detect a
// mid-session reboot (agent_uptime_ms < time since last successful call).
static std::atomic<uint64_t> g_agent_start_ms{0};
static uint64_t AgentUptimeMs()
{
    auto now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t start = g_agent_start_ms.load(std::memory_order_relaxed);
    if (start == 0) {
        g_agent_start_ms.compare_exchange_strong(start, now_ms);
        start = g_agent_start_ms.load(std::memory_order_relaxed);
    }
    return now_ms - start;
}

// v14: stable boot identity. NtQuerySystemInformation(SystemTimeOfDayInfo)
// returns the real boot FILETIME — immune to the suspend drift that makes
// "wall clock minus GetTickCount64" jitter across sleeps on VMs.
// T1.1d: exposed via services.hpp so the phone-home thread reports the
// exact same boot epoch the Status RPC does.
uint64_t BootEpochMs()
{
    struct TimeOfDay {
        LARGE_INTEGER BootTime, CurrentTime, TimeZoneBias;
        ULONG TimeZoneId, Reserved;
        ULONGLONG BootTimeBias, SleepTimeBias;
    } ti{};
    using NtQSIFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    static NtQSIFn ntqsi = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? (NtQSIFn)GetProcAddress(ntdll, "NtQuerySystemInformation") : nullptr;
    }();
    if (ntqsi && ntqsi(3 /*SystemTimeOfDayInformation*/, &ti, sizeof(ti), nullptr) == 0) {
        return (uint64_t)(ti.BootTime.QuadPart / 10000ULL - 11644473600000ULL);
    }
    auto now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return now_ms - GetTickCount64();
}

// v14: per-agent-lifetime id — pid+start-epoch is unique on a box and lets
// the orchestrator tell "agent restarted" apart from "machine rebooted".
// T1.1d: exposed via services.hpp — static initialization is first-call-
// wins, so the first caller (Status RPC or phone-home thread) seals the
// value for every later reader.
const std::string& AgentInstanceId()
{
    static const std::string id = [] {
        char buf[64];
        auto now = (unsigned long long)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        snprintf(buf, sizeof(buf), "%lu-%llu", (unsigned long)GetCurrentProcessId(), now);
        return std::string(buf);
    }();
    return id;
}

// ------------------------------------------------------------- Agent svc ----

class AgentSvc final : public Agent::Service {
public:
    AgentSvc(const AgentConfig& cfg, DriverMgr& drv) : cfg_(cfg), drv_(drv) {}

    grpc::Status Status(::grpc::ServerContext* ctx, const StatusRequest*, StatusResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        resp->set_agent_version(PRY_AGENT_VERSION);
        OSVERSIONINFOEXW os{};
        os.dwOSVersionInfoSize = sizeof(os);
        using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOEXW*);
        auto rtl = (RtlGetVersionFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
        if (rtl && rtl(&os) == 0) {
            // Win11 still reports dwMajorVersion 10 — the marketing name
            // derives from the build (>= 22000) plus the registry's
            // DisplayVersion (25H2/24H2/...). Dashboard: shows as
            // "Windows 11 25H2 (26200)" instead of "Windows 10.0 (26200)".
            std::string name = os.dwBuildNumber >= 22000 ? "Windows 11" : "Windows 10";
            static const std::string displayVersion = [] {
                wchar_t dv[32] = {};
                DWORD size = sizeof(dv);
                if (RegGetValueW(HKEY_LOCAL_MACHINE,
                                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                 L"DisplayVersion", RRF_RT_REG_SZ, nullptr, dv,
                                 &size) == ERROR_SUCCESS) {
                    int n = WideCharToMultiByte(CP_UTF8, 0, dv, -1, nullptr, 0,
                                                nullptr, nullptr);
                    if (n > 1) {
                        std::string out(n - 1, '\0');
                        WideCharToMultiByte(CP_UTF8, 0, dv, -1, out.data(), n,
                                            nullptr, nullptr);
                        return out;
                    }
                }
                return std::string();
            }();
            if (!displayVersion.empty()) {
                name += " " + displayVersion;
            }
            resp->set_os_version(name);
            resp->set_os_build(os.dwBuildNumber);
        }
        auto info = drv_.Query();
        // ABI gate report. driver_version
        // stayed the same from ABI v14 through v17, so the orchestrator could
        // not tell a stale driver apart; the PING ABI word can.
        resp->set_agent_abi_version(PRY_ABI_VERSION);
        resp->set_driver_abi_version(info.loaded ? info.ping.AbiVersion : 0);
        resp->set_driver_abi_ok(info.loaded && info.ping.AbiVersion == PRY_ABI_VERSION);
        if (info.loaded) {
            resp->set_driver_state(info.service ? DRIVER_SERVICE : DRIVER_MANUAL_MAPPED);
            resp->set_testsigning((info.ping.Flags & PRY_FLAG_TESTSIGNING) != 0);
            resp->set_hvci((info.ping.Flags & PRY_FLAG_HVCI) != 0);
            resp->set_driver_version(std::to_string(info.ping.VersionMajor) + "." +
                                     std::to_string(info.ping.VersionMinor));
            resp->set_patchguard_expected(true);
        } else {
            resp->set_driver_state(DRIVER_ABSENT);
            // Driver-absent fallback: without PING there is no flag word, and
            // leaving testsigning at proto-default false misled operators into
            // thinking the BCD flag had been lost across reboots. Read the
            // boot options the same way the driver would.
            wchar_t opts[512]{};
            DWORD sz = sizeof(opts);
            if (RegGetValueW(HKEY_LOCAL_MACHINE,
                             L"SYSTEM\\CurrentControlSet\\Control",
                             L"SystemStartOptions", RRF_RT_REG_SZ, nullptr,
                             opts, &sz) == ERROR_SUCCESS) {
                std::wstring upper = opts;
                for (auto& c : upper) {
                    if (c >= L'a' && c <= L'z') {
                        c -= (L'a' - L'A');
                    }
                }
                resp->set_testsigning(upper.find(L"TESTSIGNING") != std::wstring::npos);
            }
        }
        resp->set_agent_uptime_ms(AgentUptimeMs());
        resp->set_boot_epoch_ms(BootEpochMs());
        resp->set_agent_instance_id(AgentInstanceId());
        // v16 (Memory scanner wave 1): advertise ScanService availability.
        // Phase C landed the real handlers (scan_service.cpp) and this
        // build links them into the agent, so orchestrator takes the
        // on-target path.
        resp->set_scan_service_version(1);
        // v17 (Memory scanner wave 2 Phase L): advertise PointerMapService
        // + DissectService availability. Phase B-G shipped the real
        // handlers (pointer_map_service.cpp + dissect_service.cpp) and
        // this build links them in; orchestrator now routes pointer
        // map ops on-target and dissect through the fast path.
        resp->set_pointer_map_version(1);
        // dedicated DissectService
        // advert. Older agents reported 0 here and the
        // orchestrator used ``pointer_map_version`` as a proxy gate;
        // this field frees Wave 3 P1 to flip to 2 when Dissect.Compare
        // lands without touching ``pointer_map_version``.
        // bumped to 2 — Dissect.Compare
        // handler is registered on this build.
        resp->set_dissect_version(2);
        // Memory.HeapAttribLookup is
        // wired on the kernel agent (shares WalkHeaps + the driver-
        // backed UserMemReadFn fallback). Umagent leaves this at 0
        // since it has no HeapList surface.
        resp->set_memory_heap_attrib_version(1);
        // pack a lightweight adapter list onto every
        // Status call so the orchestrator can detect NIC flaps without
        // the full HostInfo roundtrip. Collecting adapters is cheap
        // (handful of rows); hardware/security-products skipped.
        try {
            pry::host::HostInfo hi;
            pry::host::ProbeAdapters(hi);
            for (const auto& a : hi.ipv4) {
                auto* row = resp->add_ipv4();
                row->set_adapter(a.adapter);
                row->set_address(a.address);
                row->set_prefix_len(a.prefix_len);
                row->set_origin(a.origin);
                row->set_gateway(a.gateway);
                row->set_mac(a.mac);
                row->set_up(a.up);
            }
        } catch (...) {
            // Status must never fail on adapter enumeration; drop silently.
        }
        resp->mutable_status()->set_ok(true);
        return grpc::Status::OK;
    }

    // unauthenticated identity probe — the ONE method the auth
    // processor lets through without a bearer token (comm/grpc_auth.hpp
    // DefaultExemptMethods). Returns no secrets: just enough for the
    // orchestrator to confirm which machine / process sits behind an
    // endpoint BEFORE it sends the token there. Deliberately no CheckAuth.
    grpc::Status Identify(::grpc::ServerContext*, const IdentifyRequest*,
                          IdentifyResponse* resp) override
    {
        resp->set_computer_name(ComputerNameUtf8());
        resp->set_boot_epoch_ms(BootEpochMs());
        resp->set_agent_instance_id(AgentInstanceId());
        resp->set_agent_version(PRY_AGENT_VERSION);
        resp->set_view_kind("kernel");
        return grpc::Status::OK;
    }

    grpc::Status DriverLoad(::grpc::ServerContext* ctx, const DriverLoadRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        if (req->method() == DriverLoadRequest::MANUAL_MAP) {
            // DriverMgr picks a live user process for the parked alertable
            // thread (System/4 has no PEB->Ldr — the old hardcode never worked)
            err = drv_.ManualMap(0);
        } else {
            err = drv_.LoadService();
        }
        resp->set_ok(err.empty());
        if (!err.empty()) {
            resp->set_error(err);
            resp->set_errno_code(1);
        }
        return grpc::Status::OK;
    }

    grpc::Status DriverUnload(::grpc::ServerContext* ctx, const DriverUnloadRequest* req, OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err = drv_.UnloadService(req->delete_service());
        resp->set_ok(err.empty());
        if (!err.empty()) {
            resp->set_error(err);
            resp->set_errno_code(1);
        }
        return grpc::Status::OK;
    }

    // reliable Windows-API reboot. Snapshots pre-reboot identity
    // FIRST so a mid-path privilege failure still returns a useful
    // baseline, then dispatches to pry::host::InitiateReboot (which
    // enables SeShutdownPrivilege on the service token and calls
    // InitiateShutdownW / ExitWindowsEx / AbortSystemShutdownW per mode).
    grpc::Status Reboot(::grpc::ServerContext* ctx, const RebootRequest* req,
                        RebootResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        // Pre-reboot identity snapshot — happens BEFORE anything that can
        // fail, so partial failures still tell the orchestrator what the
        // baseline (boot_epoch_ms, agent_instance_id) looked like.
        resp->set_boot_epoch_ms_at_issue(pry::BootEpochMs());
        resp->set_agent_instance_id_at_issue(pry::AgentInstanceId());

        pry::host::RebootParams p;
        switch (req->mode()) {
            case RebootRequest::SHUTDOWN:
                p.mode = pry::host::RebootParams::Mode::Shutdown; break;
            case RebootRequest::POWEROFF:
                p.mode = pry::host::RebootParams::Mode::PowerOff; break;
            case RebootRequest::LOGOFF:
                p.mode = pry::host::RebootParams::Mode::Logoff;   break;
            case RebootRequest::ABORT:
                p.mode = pry::host::RebootParams::Mode::Abort;    break;
            case RebootRequest::MODE_UNSPECIFIED:
            case RebootRequest::REBOOT:
            default:
                p.mode = pry::host::RebootParams::Mode::Reboot;   break;
        }
        p.delay_s          = req->delay_s();
        p.force            = req->force();
        p.force_if_hung    = req->force_if_hung();
        p.reason_code      = req->reason_code();
        p.wait_pre_shutdown = req->wait_pre_shutdown();
        // UTF-8 reason -> UTF-16 (keep default when empty).
        if (!req->reason().empty()) {
            const std::string& s = req->reason();
            int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
            if (n > 1) {
                std::wstring w(static_cast<size_t>(n - 1), L'\0');
                ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
                p.reason = std::move(w);
            }
        }

        auto r = pry::host::InitiateReboot(p);
        resp->set_ok(r.ok);
        resp->set_win32_error(r.win32_error);
        resp->set_message(r.message);
        resp->set_mode_applied(r.mode_applied);
        resp->set_delay_s_applied(r.delay_s_applied);
        return grpc::Status::OK;
    }

    // Swap-and-restart a service binary via a detached on-target script. The
    // RPC replies first; the script then stops the service, force-kills any
    // process still holding the image (covers SCM-untracked orphans — `sc
    // stop` alone leaves those running), quarantines the live exe under
    // prev\, promotes the staged upload, restarts, health-checks the listen
    // port, and rolls back on failure.
    grpc::Status SelfUpdate(::grpc::ServerContext* ctx, const SelfUpdateRequest* req,
                            OpStatus* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        auto fail = [&](const std::string& e) {
            resp->set_ok(false);
            resp->set_error(e);
            resp->set_errno_code(1);
            return grpc::Status::OK;
        };
        if (req->service_name() != "PryAgent" && req->service_name() != "PryUmagent") {
            return fail("service_name must be PryAgent or PryUmagent");
        }
        if (req->exe_path().empty() || req->staged_path().empty()) {
            return fail("exe_path and staged_path are required");
        }
        auto wide = [](const std::string& s) {
            int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
            std::wstring w(n ? n - 1 : 0, L'\0');
            if (n) {
                MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
            }
            return w;
        };
        // Canonicalize BEFORE the containment check: "C:\pry\..\Windows\x"
        // used to pass the plain prefix compare. ADS ("file:stream") and
        // device/long-path prefixes are refused outright.
        auto canon = [&](const std::string& in, std::wstring* out) -> bool {
            std::wstring w = wide(in);
            if (w.empty() || w.rfind(L"\\\\", 0) == 0) {
                return false; // UNC, \\?\ and \\.\ prefixes
            }
            DWORD n = GetFullPathNameW(w.c_str(), 0, nullptr, nullptr);
            if (n == 0 || n > 32768) {
                return false;
            }
            std::wstring full(n, L'\0');
            n = GetFullPathNameW(w.c_str(), (DWORD)full.size(), full.data(), nullptr);
            if (n == 0 || n >= full.size()) {
                return false;
            }
            full.resize(n);
            if (full.find(L':', 2) != std::wstring::npos) {
                return false; // alternate data stream
            }
            *out = full;
            return true;
        };
        std::wstring exeW, stagedW, install;
        if (!canon(req->exe_path(), &exeW) || !canon(req->staged_path(), &stagedW) ||
            !canon(WideToA(AgentConfig::ExeDir()), &install)) {
            return fail("exe_path/staged_path must be plain absolute local paths");
        }
        // This bounces pry services only — not a general replace primitive.
        auto lower = [](std::wstring s) {
            CharLowerBuffW(s.data(), (DWORD)s.size());
            return s;
        };
        std::wstring installL = lower(install);
        while (!installL.empty() && installL.back() == L'\\') {
            installL.pop_back();
        }
        auto underInstall = [&](const std::wstring& p) {
            std::wstring pl = lower(p);
            return pl.size() > installL.size() + 1 &&
                   pl.compare(0, installL.size(), installL) == 0 && pl[installL.size()] == L'\\';
        };
        if (!underInstall(exeW) || !underInstall(stagedW)) {
            return fail("exe_path/staged_path must be under " + WideToA(install));
        }
        if (lower(exeW) == lower(stagedW)) {
            return fail("exe_path and staged_path must differ");
        }
        if (GetFileAttributesW(stagedW.c_str()) == INVALID_FILE_ATTRIBUTES) {
            return fail("staged file not found: " + req->staged_path());
        }
        if (!req->sha256().empty()) {
            std::string want = req->sha256();
            std::transform(want.begin(), want.end(), want.begin(), ::tolower);
            if (Sha256FileHex(stagedW) != want) {
                return fail("staged sha256 mismatch");
            }
        }
        // listen_port is interpolated into the script: digits only, 1..65535.
        unsigned long portNum = (unsigned long)(req->service_name() == "PryAgent" ? cfg_.port
                                                                                   : 50075);
        if (!req->listen_port().empty()) {
            const std::string& lp = req->listen_port();
            if (lp.size() > 5 || lp.find_first_not_of("0123456789") != std::string::npos) {
                return fail("listen_port must be a decimal port number");
            }
            portNum = std::stoul(lp);
        }
        if (portNum == 0 || portNum > 65535) {
            return fail("listen_port out of range");
        }

        size_t sep = exeW.find_last_of(L'\\');
        std::wstring dir = exeW.substr(0, sep);
        std::wstring prev = dir + L"\\prev";
        std::wstring img = exeW.substr(sep + 1);
        std::wstring stem = img.substr(0, img.find_last_of(L'.'));
        std::wstring ts = std::to_wstring(NowUnix());
        std::wstring bak = prev + L"\\" + stem + L"." + ts + L".bak";
        std::wstring scriptPath = prev + L"\\selfupdate_" + ts + L".ps1";
        std::wstring logPath = prev + L"\\selfupdate_" + ts + L".log";
        CreateDirectoryW(prev.c_str(), nullptr);

        // PowerShell single-quoted literal. PowerShell also ends a
        // single-quoted string on U+2018..U+201B, so those are doubled too.
        auto psq = [](const std::wstring& v) {
            std::wstring o = L"'";
            for (wchar_t c : v) {
                o.push_back(c);
                if (c == L'\'' || (c >= 0x2018 && c <= 0x201B)) {
                    o.push_back(c);
                }
            }
            o.push_back(L'\'');
            return WideToA(o);
        };
        // PowerShell, not cmd: a detached console-less cmd deadlocks on `a|b`
        // pipes (reader never sees EOF) and silently drops redirected output.
        std::ofstream s(scriptPath, std::ios::binary | std::ios::trunc);
        if (!s) {
            return fail("cannot write updater script");
        }
        // UTF-8 BOM: Windows PowerShell 5.1 reads a BOM-less .ps1 as the ANSI
        // codepage, which would mangle any non-ASCII path below.
        s << "\xEF\xBB\xBF"
          << "$ErrorActionPreference = 'Continue'\n"
          << "$exe    = " << psq(exeW) << "\n"
          << "$staged = " << psq(stagedW) << "\n"
          << "$bak    = " << psq(bak) << "\n"
          << "$svc    = " << psq(wide(req->service_name())) << "\n"
          << "$port   = " << portNum << "\n"
          << "$img    = " << psq(stem) << "\n"
          << "$log    = " << psq(logPath) << "\n"
          << "function W($m) { $m | Out-File -LiteralPath $log -Append -Encoding utf8 }\n"
          // bounded wait for SCM to reach Stopped — SCM state lags process
          // death and `sc start` against STOP_PENDING fails with 1056
          << "function Wait-Stopped($secs) { $d = (Get-Date).AddSeconds($secs); while ((Get-Service $svc -EA SilentlyContinue).Status -ne 'Stopped' -and (Get-Date) -lt $d) { Start-Sleep 1 } }\n"
          << "function Start-Svc { for ($i = 0; $i -lt 6; $i++) { & sc.exe start $svc 2>&1 | Out-File -LiteralPath $log -Append; Start-Sleep 2; if ((Get-Service $svc -EA SilentlyContinue).Status -eq 'Running') { return $true } }; return $false }\n"
          << "function Stop-All { & sc.exe stop $svc 2>&1 | Out-File -LiteralPath $log -Append; Wait-Stopped 15; Get-Process -Name $img -EA SilentlyContinue | Stop-Process -Force; Wait-Stopped 10 }\n"
          // a port that answers once can still be a crash loop: require two
          // connects 3 s apart with the service Running in between
          << "function Test-Up { $c = New-Object Net.Sockets.TcpClient; try { $c.Connect('127.0.0.1', $port); return $c.Connected } catch { return $false } finally { $c.Close() } }\n"
          // -ErrorAction Stop: under 'Continue' a failed Move-Item was a
          // non-terminating error, the catch never ran and rollback never
          // triggered. -LiteralPath: '[' in a path is not a wildcard.
          << "function Restore-Bak { try { if (Test-Path -LiteralPath $bak) { Move-Item -LiteralPath $bak -Destination $exe -Force -ErrorAction Stop } } catch { W \"rollback move failed: $_\" }; if (-not (Test-Path -LiteralPath $exe)) { W 'ROLLBACK FAILED: service exe missing'; return $false }; return $true }\n"
          << "\"$(Get-Date -Format o) self-update $svc staged=$staged\" | Out-File -LiteralPath $log\n"
          // let this RPC's reply flush before the listener goes away
          << "Start-Sleep -Seconds 2\n"
          // SCM stop first (clean stop -> no failure-action restart), then
          // force-kill leftovers covering SCM-untracked orphans
          << "Stop-All\n"
          << "if (-not (Test-Path -LiteralPath $staged)) { W 'staged missing'; Start-Svc | Out-Null; exit 1 }\n"
          << "try {\n"
          << "  Move-Item -LiteralPath $exe -Destination $bak -Force -ErrorAction Stop\n"
          << "  Move-Item -LiteralPath $staged -Destination $exe -Force -ErrorAction Stop\n"
          << "} catch {\n"
          << "  W \"swap failed: $_\"\n"
          << "  if (-not (Test-Path -LiteralPath $exe)) { Restore-Bak | Out-Null }\n"
          << "  Start-Svc | Out-Null\n"
          << "  exit 1\n"
          << "}\n"
          << "if (-not (Start-Svc)) { W 'sc start failed' }\n"
          << "$up = $false\n"
          << "for ($i = 0; $i -lt 10 -and -not $up; $i++) { Start-Sleep 2; $up = Test-Up }\n"
          << "if ($up) { Start-Sleep 3; $up = ((Get-Service $svc -EA SilentlyContinue).Status -eq 'Running') -and (Test-Up) }\n"
          << "if ($up) { W 'OK'; exit 0 }\n"
          << "W 'health check failed - rolling back'\n"
          << "Stop-All\n"
          << "$restored = Restore-Bak\n"
          << "Start-Svc | Out-Null\n"
          << "if ($restored) { W 'ROLLBACK' } else { W 'ROLLBACK FAILED' }\n"
          << "exit 1\n";
        s.close();
        if (!s) {
            DeleteFileW(scriptPath.c_str());
            return fail("cannot write updater script");
        }

        // Spawn the updater the same way exec/detached.cpp does:
        // CREATE_NO_WINDOW gives powershell.exe a hidden console — it exits
        // instantly under DETACHED_PROCESS (no console at all). Stdout/stderr
        // go to a SEPARATE console log — pointing them at the script's own
        // log makes every Out-File in the script fail (bidirectional share
        // check: Out-File's FileShare.Read denies our held write handle).
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        std::wstring consoleLog = prev + L"\\selfupdate_" + ts + L".console.log";
        HANDLE hLog = CreateFileW(consoleLog.c_str(), GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE hNul = CreateFileW(L"NUL", GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hLog == INVALID_HANDLE_VALUE || hNul == INVALID_HANDLE_VALUE) {
            if (hLog != INVALID_HANDLE_VALUE) CloseHandle(hLog);
            if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);
            return fail("cannot open updater std handles");
        }
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = hNul;
        si.hStdOutput = hLog;
        si.hStdError = hLog;
        PROCESS_INFORMATION pi{};
        std::wstring cmd = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                           scriptPath + L"\"";
        BOOL spawned = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                                      CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW |
                                      CREATE_UNICODE_ENVIRONMENT,
                                      nullptr, dir.c_str(), &si, &pi);
        CloseHandle(hLog);
        CloseHandle(hNul);
        if (!spawned) {
            return fail(Win32ErrorString("CreateProcessW(updater)", GetLastError()));
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        resp->set_ok(true);
        return grpc::Status::OK;
    }

    // v5: read out the persistent driver-op breadcrumb ring. Two feeds:
    //   current — this agent lifetime (in-memory ring)
    //   prior   — loaded from the on-disk snapshot at agent Init(). "pending"
    //             entries from prior are upgraded to "wedged" in load —
    //             those are the calls that were in flight when the agent
    //             died last time.
    grpc::Status RecentOps(::grpc::ServerContext* ctx, const RecentOpsRequest* req,
                           RecentOpsResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        auto emit = [&](const std::vector<BreadcrumbEntry>& src, auto* out) {
            uint32_t limit = req->limit();
            size_t start = 0;
            if (limit && src.size() > limit) start = src.size() - limit;
            for (size_t i = start; i < src.size(); i++) {
                const auto& e = src[i];
                auto* p = out->Add();
                p->set_t_start_us(e.t_start_us);
                p->set_t_end_us(e.t_end_us);
                p->set_ioctl_code(e.ioctl_code);
                p->set_arg_summary(e.arg_summary);
                p->set_status_code(e.status_code);
                p->set_status_kind(e.status_kind);
                p->set_latency_us(e.t_end_us > e.t_start_us
                                  ? (e.t_end_us - e.t_start_us) : 0);
            }
        };
        emit(Breadcrumb::CurrentSnapshot(), resp->mutable_current());
        if (req->include_prior()) {
            emit(Breadcrumb::PriorSnapshot(), resp->mutable_prior());
        }
        resp->set_agent_start_epoch_ms(Breadcrumb::AgentStartEpochMs());
        resp->set_now_epoch_ms(Breadcrumb::NowEpochMs());
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v8: broad host fingerprint. Identity, full OS release (product name +
    // UBR + display version), security posture (secure boot, VBS, driver
    // blocklist, LSA-PPL, CPU features), optional hardware / WSC products.
    // Reads only; never touches config. The driver flag word wins for the
    // four bits it verifies (testsigning / HVCI / secureboot / kd), and the
    // usermode probe fills the rest.
    grpc::Status HostInfo(::grpc::ServerContext* ctx, const HostInfoRequest* req,
                          HostInfoResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        auto info = drv_.Query();
        uint32_t driver_flags = info.loaded ? info.ping.Flags : 0;
        bool driver_ok = info.loaded;

        pry::host::HostInfo h;
        pry::host::Collect(req->include_security_products(),
                              req->include_hardware(),
                              driver_flags, driver_ok,
                              AgentUptimeMs(), h);

        resp->set_computer_name(h.computer_name);
        resp->set_dns_hostname(h.dns_hostname);
        resp->set_domain(h.domain);
        resp->set_logged_on_user(h.logged_on_user);
        resp->set_agent_run_as(h.agent_run_as);
        resp->set_is_elevated(h.is_elevated);

        resp->set_product_name(h.product_name);
        resp->set_edition_id(h.edition_id);
        resp->set_display_version(h.display_version);
        resp->set_release_id(h.release_id);
        resp->set_build_major(h.build_major);
        resp->set_build_ubr(h.build_ubr);
        resp->set_full_build_string(h.full_build_string);
        resp->set_install_date(h.install_date);
        resp->set_boot_time(h.boot_time);
        resp->set_timezone(h.timezone);
        resp->set_arch(h.arch);

        resp->set_testsigning(h.testsigning.value);
        resp->set_testsigning_source(h.testsigning.source);
        resp->set_hvci(h.hvci.value);
        resp->set_hvci_source(h.hvci.source);
        resp->set_secureboot(h.secureboot.value);
        resp->set_secureboot_source(h.secureboot.source);
        resp->set_kernel_debugger(h.kernel_debugger.value);
        resp->set_kernel_debugger_source(h.kernel_debugger.source);
        resp->set_vbs_enabled(h.vbs_enabled.value);
        resp->set_vbs_source(h.vbs_enabled.source);
        resp->set_credential_guard(h.credential_guard.value);
        resp->set_credential_guard_source(h.credential_guard.source);
        resp->set_driver_blocklist_on(h.driver_blocklist_on.value);
        resp->set_driver_blocklist_source(h.driver_blocklist_on.source);
        resp->set_lsa_protected(h.lsa_protected.value);
        resp->set_lsa_protected_source(h.lsa_protected.source);
        resp->set_smep(h.smep);
        resp->set_smap(h.smap);
        resp->set_cet_shstk(h.cet_shstk);
        resp->set_patchguard_state(h.patchguard_state);
        // Kernel VA Shadow (Meltdown mitigation).
        resp->set_kva_shadow(h.kva_shadow.value);
        resp->set_kva_shadow_source(h.kva_shadow.source);

        resp->set_cpu_brand(h.cpu_brand);
        resp->set_cpu_cores(h.cpu_cores);
        resp->set_cpu_logical(h.cpu_logical);
        resp->set_phys_mem_bytes(h.phys_mem_bytes);
        resp->set_hypervisor_vendor(h.hypervisor_vendor);
        resp->set_is_vm(h.is_vm);

        resp->set_pc_uptime_ms(h.pc_uptime_ms);
        resp->set_agent_uptime_ms(h.agent_uptime_ms);
        resp->set_service_uptime_ms(h.service_uptime_ms);

        for (const auto& sp : h.security_products) {
            auto* row = resp->add_security_products();
            row->set_name(sp.name);
            row->set_state(sp.state);
            row->set_version(sp.version);
            row->set_kind(sp.kind);
        }
        for (const auto& err : h.probe_errors) {
            resp->add_probe_errors(err);
        }
        // network identity echo.
        for (const auto& a : h.ipv4) {
            auto* row = resp->add_ipv4();
            row->set_adapter(a.adapter);
            row->set_address(a.address);
            row->set_prefix_len(a.prefix_len);
            row->set_origin(a.origin);
            row->set_gateway(a.gateway);
            row->set_mac(a.mac);
            row->set_up(a.up);
        }
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    // v15: desktop/window screenshot via the session-1 worker.
    grpc::Status CaptureScreen(::grpc::ServerContext* grpcCtx,
                               const ScreenCaptureRequest* request,
                               ScreenCaptureResponse* resp) override
    {
        auto auth = CheckAuth(grpcCtx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        screen::DispatchScreenCapture(*request, resp);
        return grpc::Status::OK;
    }

    // v15: window enumeration. MUST route through the session-1 worker —
    // Session 0 cannot see the interactive desktop's windows.
    grpc::Status ListWindows(::grpc::ServerContext* grpcCtx,
                             const WindowListRequest* request,
                             WindowListResponse* resp) override
    {
        auto auth = CheckAuth(grpcCtx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }

        ScreenCaptureRequest scrReq;
        scrReq.set_mode("list");
        scrReq.set_pid(request->pid());
        scrReq.set_process_name(request->process_name());
        scrReq.set_query(request->query());
        scrReq.set_include_hidden(request->include_hidden());
        scrReq.set_include_details(request->include_details());
        // include_children / include_props are
        // accepted but NOT implemented by the session-1 worker yet
        // (host/window_enum.cpp walks top-level windows only). They used
        // to ride in as a "[feat8:chpr] " prefix on `query`, which nothing
        // stripped — the worker substring-matched the tag against every
        // title/class and returned an EMPTY list (mechanics audit P1).
        // The query is now passed through untouched; the flags are a
        // no-op until the worker grows EnumChildWindows / EnumPropsExW.
        ScreenCaptureResponse scrResp;
        screen::DispatchScreenCapture(scrReq, &scrResp);

        resp->mutable_status()->set_ok(scrResp.status().ok());
        if (!scrResp.status().ok()) {
            resp->mutable_status()->set_error(scrResp.status().error());
        }
        // windows_json is the authoritative payload; the orchestrator parses
        // it and computes total_windows.
        resp->set_windows_json(scrResp.windows_json());
        return grpc::Status::OK;
    }

    // EnumPropsExW walker on a single HWND.
    // Session-1 scoped (the session-0 agent service cannot see interactive
    // props); when the session-1 worker is unavailable the response
    // surfaces status.ok=false with the dispatcher's error so the
    // orchestrator can degrade cleanly.
    grpc::Status ListWindowProps(::grpc::ServerContext* grpcCtx,
                                  const ListWindowPropsRequest* request,
                                  ListWindowPropsResponse* resp) override
    {
        auto auth = CheckAuth(grpcCtx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        resp->set_hwnd(request->hwnd());
        // Phase 0 shell: ride the session-1 worker through the existing
        // dispatcher, which doesn't yet know about EnumPropsExW. The
        // worker-side EnumPropsExW walk lands with the host/window_enum
        // extension in a follow-up; this build ships the capability wiring
        // + the honest empty-props envelope so clients can enumerate
        // the verb via desktop_manage(action='actions').
        resp->mutable_status()->set_ok(true);
        return grpc::Status::OK;
    }

    // parent/child/owner tree builder. Same
    // Phase 0 shape as ListWindowProps — surface wiring is live, the
    // depth-capped EnumChildWindows recursion rides a session-1 worker
    // follow-up.
    grpc::Status GetWindowTree(::grpc::ServerContext* grpcCtx,
                                const GetWindowTreeRequest* request,
                                GetWindowTreeResponse* resp) override
    {
        auto auth = CheckAuth(grpcCtx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        auto* root = resp->mutable_root();
        root->set_hwnd(request->hwnd());
        root->set_pid(request->pid());
        resp->mutable_status()->set_ok(true);
        return grpc::Status::OK;
    }

private:
    static std::string ComputerNameUtf8()
    {
        wchar_t cn[MAX_COMPUTERNAME_LENGTH + 1]{};
        DWORD n = (DWORD)(sizeof(cn) / sizeof(cn[0]));
        if (!GetComputerNameW(cn, &n) || n == 0) {
            return {};
        }
        return WideToUtf8(std::wstring(cn, n));
    }
    static std::string WideToA(const std::wstring& w)
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(n ? n - 1 : 0, '\0');
        if (n) {
            WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
        }
        return s;
    }
    static std::string Sha256FileHex(const std::wstring& path)
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return "";
        }
        Sha256 sha;
        std::string err;
        if (!sha.Begin(&err)) {
            return "";
        }
        std::vector<char> buf(64 * 1024);
        while (in.read(buf.data(), (std::streamsize)buf.size()) || in.gcount()) {
            sha.Update(buf.data(), (size_t)in.gcount());
            if (!in) {
                break;
            }
        }
        return sha.FinishHex();
    }
    const AgentConfig& cfg_;
    DriverMgr& drv_;
};

// ---------------------------------------------------- NetPin svc ----

class NetPinSvc final : public NetPin::Service {
public:
    NetPinSvc(const AgentConfig& cfg, host::NetPinMgr& pin) : cfg_(cfg), pin_(pin) {}

    grpc::Status Status(::grpc::ServerContext* ctx, const NetPinStatusRequest*,
                        NetPinStatusResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        auto st = pin_.Snapshot();
        resp->set_enabled(st.enabled);
        resp->set_hold(st.hold);
        resp->set_adapter(st.adapter);
        resp->set_pinned_address(st.pinned_address);
        resp->set_pinned_prefix(st.pinned_prefix);
        resp->set_pinned_gateway(st.pinned_gateway);
        resp->set_current_address(st.current_address);
        resp->set_last_pin_at_epoch_ms(st.last_pin_at_epoch_ms);
        resp->set_pin_attempts(st.pin_attempts);
        resp->set_pin_failures_streak(st.pin_failures_streak);
        resp->set_last_error(st.last_error);
        resp->mutable_status()->set_ok(true);
        return grpc::Status::OK;
    }

    grpc::Status Apply(::grpc::ServerContext* ctx, const NetPinApplyRequest* req,
                       NetPinApplyResponse* resp) override
    {
        auto auth = CheckAuth(ctx, cfg_.token);
        if (!auth.ok()) {
            return auth;
        }
        std::string err;
        bool ok = pin_.ApplyOnce(req->clear_hold(), &err);
        resp->set_applied(ok);
        resp->set_details(err);
        FillStatus(resp, ok ? "" : err);
        return grpc::Status::OK;
    }

private:
    const AgentConfig& cfg_;
    host::NetPinMgr& pin_;
};

void RegisterAgentSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv)
{
    static AgentSvc agentSvc(cfg, drv);
    builder.RegisterService(&agentSvc);
}

void RegisterNetPinSvc(grpc::ServerBuilder& builder, const AgentConfig& cfg,
                       host::NetPinMgr& netPin)
{
    static NetPinSvc netPinSvc(cfg, netPin);
    builder.RegisterService(&netPinSvc);
}

// v16 Memory scanner wave 1: adapt the agent's UserMemReadFn/KernelMemReadFn
// (which take a MemReaderCtx + return bool-with-exact-len) to the
// ScanService's MemReadFn contract (space enum + out_read bytes). The
// kernel agent handles both USER and KERNEL space; PHYSICAL space is
// refused because the scanner has no concept of a single-process
// physical map.
static pry::scan::MemReadFn MakeKernelAgentMemReadFn(DriverMgr& drv)
{
    return [&drv](std::uint32_t pid, std::uint64_t va,
                   void* buf, std::size_t size,
                   pry::MemSpace space,
                   std::size_t* out_read) -> bool {
        MemReaderCtx ctx{&drv};
        bool ok = false;
        if (space == pry::KERNEL) {
            ok = KernelMemReadFn(&ctx, pid, va, buf, size);
        } else if (space == pry::USER) {
            ok = UserMemReadFn(&ctx, pid, va, buf, size);
        } else {
            if (out_read) *out_read = 0;
            return false;
        }
        if (out_read) *out_read = ok ? size : 0;
        return ok;
    };
}

void RegisterScanServiceAgent(grpc::ServerBuilder& builder,
                              const AgentConfig& /*cfg*/, DriverMgr& drv)
{
    pry::scan::RegisterScanService(builder, "kernel",
                                       MakeKernelAgentMemReadFn(drv));
}

// v17 Memory scanner wave 2: same reader plus a module enumerator built
// on ListUserModules (driver-first, toolhelp fallback). Both registrars
// (agent + umagent) inject one ModuleEnumFn per view; the shared TU
// doesn't pull DriverMgr.
static pry::scan::ModuleEnumFn MakeKernelAgentModuleEnumFn(DriverMgr& drv)
{
    return [&drv](std::uint32_t pid,
                   std::vector<pry::scan::ModuleInfo>* out) -> bool {
        std::vector<pry::ModuleEntry> mods;
        if (!ListUserModules(&drv, pid, &mods)) return false;
        out->reserve(mods.size());
        for (const auto& m : mods) {
            pry::scan::ModuleInfo mi;
            mi.name = WideToUtf8(m.Name);
            mi.path = WideToUtf8(m.Path);
            mi.base = m.Base;
            mi.size = m.Size;
            mi.timestamp_ms = 0;
            out->push_back(std::move(mi));
        }
        return !out->empty();
    };
}

void RegisterPointerMapServiceAgent(grpc::ServerBuilder& builder,
                                    const AgentConfig& /*cfg*/,
                                    DriverMgr& drv)
{
    pry::scan::RegisterPointerMapService(
        builder, "kernel",
        MakeKernelAgentMemReadFn(drv),
        MakeKernelAgentModuleEnumFn(drv));
}

void RegisterDissectServiceAgent(grpc::ServerBuilder& builder,
                                 const AgentConfig& /*cfg*/,
                                 DriverMgr& drv)
{
    pry::scan::RegisterDissectService(
        builder, "kernel",
        MakeKernelAgentMemReadFn(drv),
        MakeKernelAgentModuleEnumFn(drv));
}

} // namespace pry
