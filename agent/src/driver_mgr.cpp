#include "driver_mgr.hpp"
#include "common.h"
#include "exec.hpp"
#include "exec/cmdline_quote.hpp"

#include <sddl.h>

namespace pry {

DriverMgr::SysInfo DriverMgr::Query()
{
    SysInfo info;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, L"PryDrv", SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st{};
            if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_RUNNING) {
                info.service = true;
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    if (drv_.Open()) {
        info.loaded = drv_.Ping(&info.ping);
    } else {
        drv_.Close();
    }
    return info;
}

std::string DriverMgr::LoadService()
{
    if (!cfg_.allowDriverLoad) {
        return "driver ops disabled by agent config";
    }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        return Win32ErrorString("OpenSCManager", GetLastError());
    }
    std::wstring cmd = L"\\??\\" + cfg_.driverPath;
    SC_HANDLE svc = OpenServiceW(scm, L"PryDrv", SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        svc = CreateServiceW(scm, L"PryDrv", L"Pry kernel driver", SERVICE_START,
                             SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                             cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            std::string err = Win32ErrorString("CreateService", GetLastError());
            CloseServiceHandle(scm);
            return err;
        }
    }
    BOOL ok = StartServiceW(svc, 0, nullptr);
    DWORD gle = GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (!ok && gle != ERROR_SERVICE_ALREADY_RUNNING) {
        return Win32ErrorString("StartService(PryDrv)", gle);
    }
    // Fresh handle + fresh ABI probe against the (possibly new) driver.
    drv_.Close();
    return GateAfterLoad();
}

// the ABI gate re-runs after every load.
// A mismatch is reported as the DriverLoad error (the driver IS loaded, but
// every driver-backed RPC answers FAILED_PRECONDITION until a matching one
// is); "not reachable" right after a successful start is only logged, as
// before, so a slow device-object creation can't fail an otherwise good
// load.
std::string DriverMgr::GateAfterLoad()
{
    std::string gate = RunDriverGate(*this);
    if (gate.empty()) {
        return "";
    }
    OutputDebugStringA(("pry_agent: " + gate + "\n").c_str());
    if (drv_.DriverAbi() != 0) {
        return "driver loaded but refused by the ABI gate (" + gate +
               "); driver-backed RPCs answer FAILED_PRECONDITION until a matching driver is "
               "loaded";
    }
    return "";
}

std::string DriverMgr::UnloadService(bool delete_service)
{
    if (!cfg_.allowDriverUnload) {
        return "driver ops disabled by agent config";
    }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return Win32ErrorString("OpenSCManager", GetLastError());
    }
    SC_HANDLE svc = OpenServiceW(scm, L"PryDrv", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    CloseServiceHandle(scm);
    if (!svc) {
        return "PryDrv service not found";
    }
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    Sleep(500);
    if (delete_service) {
        BOOL deleted = DeleteService(svc);
        DWORD gle = GetLastError();
        CloseServiceHandle(svc);
        if (!deleted && gle != ERROR_SERVICE_MARKED_FOR_DELETE) {
            // deleted only on the last handle close; a reboot clears a held driver
            return Win32ErrorString("DeleteService(PryDrv); reboot to complete removal", gle);
        }
    } else {
        // keep the service entry registered — the update flow replaces the
        // .sys and reloads through it; a deleted-but-lingering entry makes
        // the immediate reload fail StartService with ERROR_SERVICE_DISABLED
        CloseServiceHandle(svc);
    }
    drv_.Close();
    return "";
}

std::string DriverMgr::ManualMap(UINT32 pid)
{
    if (!cfg_.allowDriverLoad) {
        return "driver ops disabled by agent config";
    }
    Driver drv2;
    if (!drv2.Open()) {
        return "manual map requires the driver already loaded (mapper talks IOCTLs)";
    }
    if (!pid) {
        // the mapper needs a live user process hosting an alertable parked
        // thread; System (4) has no PEB->Ldr so kernelbase is not loadable
        // there — prefer explorer, fall back to our own process
        pid = GetCurrentProcessId();
        std::vector<ProcessEntry> procs;
        if (drv2.ProcessList(procs)) {
            for (auto& p : procs) {
                if (_wcsicmp(p.ImageName.c_str(), L"explorer.exe") == 0 && p.Pid != 4 &&
                    p.Pid != GetCurrentProcessId()) {
                    pid = p.Pid;
                    break;
                }
            }
        }
    }
    drv2.Close();
    // stdout/stderr are drained while the mapper runs (it used to block on
    // a full 4 KiB pipe while we waited 120 s for it to exit); on timeout the
    // mapper's whole job is killed instead of being left running.
    std::wstring cmdLine = QuoteExe(cfg_.mapperPath) + L" --pid " + std::to_wstring(pid) +
                           L" --image " + QuoteArg(cfg_.driverPath);
    RunResult r = RunCommandLine(cmdLine, L"", 120000);
    if (!r.error.empty()) {
        return r.error + " (mapper)";
    }
    auto tail = [](const std::vector<BYTE>& v) {
        const size_t kMax = 2048;
        size_t off = v.size() > kMax ? v.size() - kMax : 0;
        return std::string(v.begin() + (ptrdiff_t)off, v.end());
    };
    if (r.timedOut) {
        return "mapper timed out after 120 s (killed): " + tail(r.out) + tail(r.err);
    }
    if (r.exitCode != 0) {
        return std::string("mapper exit=") + std::to_string(r.exitCode) + ": " + tail(r.out) +
               tail(r.err);
    }
    // A freshly mapped image may answer with a different ABI: re-probe.
    drv_.InvalidateAbi();
    return GateAfterLoad();
}

std::string RunDriverGate(DriverMgr& mgr)
{
    Driver& d = mgr.Comm();
    PingInfo p{};
    if (!d.Open() || !d.Ping(&p)) {
        return "gate: driver not reachable: " + d.LastError();
    }
    if (p.AbiVersion != PRY_ABI_VERSION) {
        return "gate: driver ABI " + std::to_string(p.AbiVersion) + " != agent ABI " +
               std::to_string(PRY_ABI_VERSION);
    }
    return "";
}

} // namespace pry
