// umagent/src/services_services.cpp
//
// umagent-only Services service: SCM services + drivers via
// EnumServicesStatusExW, with SERVICE_TRIGGER decode, launch-protected
// readout, service-SID resolution and (optional, driver-flavor only)
// EnumDeviceDrivers fallback for module base/size. Signer enrichment
// is driven orchestrator-side via the SI #8 Signatures.Verify RPC.
//
// Read-only this cycle; no start/stop/config/delete.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <sddl.h>
#include <winsvc.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "um_services.hpp"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace um {

namespace {

grpc::Status CheckAuthSvc(grpc::ServerContext* ctx,
                           const std::string& token)
{
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

static std::string Utf8FromWide(const wchar_t* w)
{
    if (!w || !*w) return "";
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0,
                                    nullptr, nullptr);
    if (n <= 1) return "";
    std::string out((size_t)(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

static std::wstring WideFromUtf8(const std::string& s)
{
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                    nullptr, 0);
    if (n <= 0) return {};
    std::wstring out((size_t)n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

static const char* StateName(DWORD s)
{
    switch (s) {
        case SERVICE_STOPPED:          return "STOPPED";
        case SERVICE_START_PENDING:    return "START_PENDING";
        case SERVICE_STOP_PENDING:     return "STOP_PENDING";
        case SERVICE_RUNNING:          return "RUNNING";
        case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
        case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
        case SERVICE_PAUSED:           return "PAUSED";
        default:                        return "";
    }
}

static DWORD StateFromName(const std::string& s)
{
    if (s == "STOPPED") return SERVICE_STOPPED;
    if (s == "RUNNING") return SERVICE_RUNNING;
    if (s == "PAUSED") return SERVICE_PAUSED;
    if (s == "START_PENDING") return SERVICE_START_PENDING;
    if (s == "STOP_PENDING") return SERVICE_STOP_PENDING;
    if (s == "CONTINUE_PENDING") return SERVICE_CONTINUE_PENDING;
    if (s == "PAUSE_PENDING") return SERVICE_PAUSE_PENDING;
    return 0;
}

static const char* StartTypeName(DWORD t)
{
    switch (t) {
        case SERVICE_BOOT_START:   return "BOOT_START";
        case SERVICE_SYSTEM_START: return "SYSTEM_START";
        case SERVICE_AUTO_START:   return "AUTO_START";
        case SERVICE_DEMAND_START: return "DEMAND_START";
        case SERVICE_DISABLED:     return "DISABLED";
        default:                    return "";
    }
}

static DWORD StartTypeFromName(const std::string& s)
{
    if (s == "BOOT_START")   return SERVICE_BOOT_START;
    if (s == "SYSTEM_START") return SERVICE_SYSTEM_START;
    if (s == "AUTO_START")   return SERVICE_AUTO_START;
    if (s == "DEMAND_START") return SERVICE_DEMAND_START;
    if (s == "DISABLED")     return SERVICE_DISABLED;
    return (DWORD)-1;
}

static const char* ServiceTypeName(DWORD t)
{
    if (t & SERVICE_KERNEL_DRIVER)        return "driver";
    if (t & SERVICE_FILE_SYSTEM_DRIVER)   return "driver";
    if (t & SERVICE_WIN32_OWN_PROCESS)    return "win32_own";
    if (t & SERVICE_WIN32_SHARE_PROCESS)  return "win32_share";
    if (t & SERVICE_USER_OWN_PROCESS)     return "user_own";
    if (t & SERVICE_USER_SHARE_PROCESS)   return "user_share";
    if (t & SERVICE_INTERACTIVE_PROCESS)  return "win32_interactive";
    return "unknown";
}

static const char* RowKindFromServiceType(DWORD t)
{
    if ((t & SERVICE_KERNEL_DRIVER) || (t & SERVICE_FILE_SYSTEM_DRIVER))
        return "driver";
    return "service";
}

static bool IEqualAsciiSvc(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = (char)::tolower((unsigned char)a[i]);
        char cb = (char)::tolower((unsigned char)b[i]);
        if (ca != cb) return false;
    }
    return true;
}

static bool ContainsCISvc(const std::vector<std::string>& v,
                           const std::string& s)
{
    if (v.empty()) return true;
    for (const auto& e : v) if (IEqualAsciiSvc(e, s)) return true;
    return false;
}

static void AppendWarning(pry::SvcEntry* row, const char* tag)
{
    std::string w = row->warnings();
    if (!w.empty()) w += ",";
    w += tag;
    row->set_warnings(w);
}

// Trigger GUID -> symbolic name. Keeps the orchestrator-side renderer
// out of the C++ side and gives an unknown GUID a stable raw rendering.
static std::string TriggerTypeName(DWORD t)
{
    switch (t) {
        case SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL:
            return "device_arrival";
        case SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY:
            return "ip_arrival";
        case SERVICE_TRIGGER_TYPE_DOMAIN_JOIN:
            return "domain_join";
        case SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT:
            return "firewall_port";
        case SERVICE_TRIGGER_TYPE_GROUP_POLICY:
            return "group_policy";
        case SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT:
            return "network_endpoint";
        case SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE:
            return "system_state";
        case SERVICE_TRIGGER_TYPE_CUSTOM:
            return "custom_etw";
        case SERVICE_TRIGGER_TYPE_AGGREGATE:
            return "aggregate";
        default:
            return "unknown";
    }
}

static std::string ActionName(DWORD a)
{
    switch (a) {
        case SERVICE_TRIGGER_ACTION_SERVICE_START: return "start";
        case SERVICE_TRIGGER_ACTION_SERVICE_STOP:  return "stop";
        default: return "";
    }
}

static std::string FailureActionName(DWORD a)
{
    switch (a) {
        case SC_ACTION_NONE:        return "none";
        case SC_ACTION_RESTART:     return "restart";
        case SC_ACTION_REBOOT:      return "reboot";
        case SC_ACTION_RUN_COMMAND: return "run_command";
        default:                     return "";
    }
}

static std::string FormatGuid(const GUID& g)
{
    wchar_t buf[64];
    swprintf_s(buf, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
               (unsigned long)g.Data1, g.Data2, g.Data3,
               g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
               g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return Utf8FromWide(buf);
}

static const char* ProtectedLevelName(DWORD lvl)
{
    switch (lvl) {
        case SERVICE_LAUNCH_PROTECTED_NONE:         return "none";
        case SERVICE_LAUNCH_PROTECTED_WINDOWS:      return "windows";
        case SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT: return "windows_light";
        case SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT: return "antimalware_light";
        default:                                      return "";
    }
}

static const char* SidTypeName(DWORD t)
{
    switch (t) {
        case SERVICE_SID_TYPE_NONE:         return "none";
        case SERVICE_SID_TYPE_UNRESTRICTED: return "unrestricted";
        case SERVICE_SID_TYPE_RESTRICTED:   return "restricted";
        default:                             return "";
    }
}

static std::string SidToString(PSID sid)
{
    LPWSTR w = nullptr;
    if (!::ConvertSidToStringSidW(sid, &w) || !w) return "";
    std::string out = Utf8FromWide(w);
    ::LocalFree(w);
    return out;
}

static std::vector<std::string> ParseMultiSz(const wchar_t* p)
{
    std::vector<std::string> out;
    if (!p) return out;
    while (*p) {
        out.push_back(Utf8FromWide(p));
        p += wcslen(p) + 1;
    }
    return out;
}

static void FillControlsAccepted(DWORD controls, pry::SvcEntry* row)
{
    struct Pair { DWORD mask; const char* name; };
    static const Pair kPairs[] = {
        {SERVICE_ACCEPT_STOP,                   "stop"},
        {SERVICE_ACCEPT_PAUSE_CONTINUE,         "pause_continue"},
        {SERVICE_ACCEPT_SHUTDOWN,               "shutdown"},
        {SERVICE_ACCEPT_PARAMCHANGE,            "paramchange"},
        {SERVICE_ACCEPT_NETBINDCHANGE,          "netbind"},
        {SERVICE_ACCEPT_HARDWAREPROFILECHANGE,  "hwprofile"},
        {SERVICE_ACCEPT_POWEREVENT,             "power"},
        {SERVICE_ACCEPT_SESSIONCHANGE,          "session"},
        {SERVICE_ACCEPT_PRESHUTDOWN,            "preshutdown"},
        {SERVICE_ACCEPT_TIMECHANGE,             "timechange"},
        {SERVICE_ACCEPT_TRIGGEREVENT,           "trigger"},
    };
    for (const auto& p : kPairs) {
        if (controls & p.mask) row->add_controls_accepted(p.name);
    }
}

static void DecorateFromConfig(SC_HANDLE scm, SC_HANDLE sh,
                                pry::SvcEntry* row)
{
    // SERVICE_QUERY_CONFIG: image path, dependencies, logon account.
    DWORD need = 0;
    ::QueryServiceConfigW(sh, nullptr, 0, &need);
    if (need) {
        std::vector<BYTE> buf(need);
        if (::QueryServiceConfigW(sh,
                                   reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buf.data()),
                                   need, &need)) {
            auto* cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buf.data());
            if (cfg->lpBinaryPathName)
                row->set_image_path(Utf8FromWide(cfg->lpBinaryPathName));
            if (cfg->lpServiceStartName)
                row->set_logon_account(Utf8FromWide(cfg->lpServiceStartName));
            for (auto s : ParseMultiSz(cfg->lpDependencies))
                row->add_dependencies(s);
            row->set_start_type(StartTypeName(cfg->dwStartType));
        }
    } else {
        AppendWarning(row, "cfg");
    }

    auto query_cfg2 = [&](DWORD level, std::vector<BYTE>& buf) -> bool {
        DWORD need2 = 0;
        ::QueryServiceConfig2W(sh, level, nullptr, 0, &need2);
        if (!need2) return false;
        buf.assign(need2, 0);
        return ::QueryServiceConfig2W(sh, level, buf.data(), need2, &need2) != 0;
    };

    std::vector<BYTE> tmp;
    if (query_cfg2(SERVICE_CONFIG_DESCRIPTION, tmp)) {
        auto* desc = reinterpret_cast<SERVICE_DESCRIPTIONW*>(tmp.data());
        if (desc && desc->lpDescription)
            row->set_description(Utf8FromWide(desc->lpDescription));
    } else {
        AppendWarning(row, "desc");
    }

    if (query_cfg2(SERVICE_CONFIG_DELAYED_AUTO_START_INFO, tmp)) {
        auto* d = reinterpret_cast<SERVICE_DELAYED_AUTO_START_INFO*>(tmp.data());
        row->set_delayed_auto_start(d && d->fDelayedAutostart);
    }

    if (query_cfg2(SERVICE_CONFIG_SERVICE_SID_INFO, tmp)) {
        auto* s = reinterpret_cast<SERVICE_SID_INFO*>(tmp.data());
        if (s) row->set_service_sid_type(SidTypeName(s->dwServiceSidType));
    }

    if (query_cfg2(SERVICE_CONFIG_LAUNCH_PROTECTED, tmp)) {
        auto* p = reinterpret_cast<SERVICE_LAUNCH_PROTECTED_INFO*>(tmp.data());
        if (p) row->set_launch_protected_level(ProtectedLevelName(p->dwLaunchProtected));
    }

    if (query_cfg2(SERVICE_CONFIG_FAILURE_ACTIONS, tmp)) {
        auto* fa = reinterpret_cast<SERVICE_FAILURE_ACTIONSW*>(tmp.data());
        if (fa && fa->cActions && fa->lpsaActions) {
            for (DWORD i = 0; i < fa->cActions; ++i) {
                auto* row_fa = row->add_failure_actions();
                row_fa->set_action(FailureActionName(fa->lpsaActions[i].Type));
                row_fa->set_delay_ms(fa->lpsaActions[i].Delay);
                if (fa->lpRebootMsg)
                    row_fa->set_reboot_message(Utf8FromWide(fa->lpRebootMsg));
                if (fa->lpCommand)
                    row_fa->set_run_command(Utf8FromWide(fa->lpCommand));
            }
        }
    } else {
        AppendWarning(row, "failure");
    }

    if (query_cfg2(SERVICE_CONFIG_TRIGGER_INFO, tmp)) {
        auto* ti = reinterpret_cast<SERVICE_TRIGGER_INFO*>(tmp.data());
        if (ti && ti->cTriggers && ti->pTriggers) {
            for (DWORD i = 0; i < ti->cTriggers; ++i) {
                const auto& t = ti->pTriggers[i];
                auto* row_tr = row->add_triggers();
                row_tr->set_type(TriggerTypeName(t.dwTriggerType));
                if (t.pTriggerSubtype)
                    row_tr->set_subtype(FormatGuid(*t.pTriggerSubtype));
                row_tr->set_action(ActionName(t.dwAction));
                for (DWORD j = 0; j < t.cDataItems && t.pDataItems; ++j) {
                    const auto& d = t.pDataItems[j];
                    if (d.cbData == 0 || !d.pData) continue;
                    // Interpret the raw bytes as a UTF-16 string when the
                    // trigger describes a named-pipe / RPC / port event.
                    std::string item;
                    if (d.dwDataType == SERVICE_TRIGGER_DATA_TYPE_STRING &&
                        d.cbData >= sizeof(wchar_t)) {
                        item = Utf8FromWide(reinterpret_cast<wchar_t*>(d.pData));
                    } else {
                        char hex[8];
                        snprintf(hex, sizeof(hex), "0x%X",
                                  (unsigned)d.dwDataType);
                        item = hex;
                    }
                    row_tr->add_data_items(item);
                }
            }
        }
    }
}

// --- EnumDeviceDrivers fallback for driver base/size when the kernel
// view is absent. Snapshot semantics; mid-unload races are flagged with
// a warning tag on the row.

struct DriverModule {
    uint64_t base;
    std::string path;
    std::string name;
};

static std::vector<DriverModule> SnapshotDriverModules()
{
    std::vector<DriverModule> out;
    DWORD need = 0;
    LPVOID tmp[1]{};
    ::EnumDeviceDrivers(tmp, 0, &need);
    if (!need) return out;
    DWORD count = need / sizeof(LPVOID);
    std::vector<LPVOID> bases(count);
    if (!::EnumDeviceDrivers(bases.data(), (DWORD)(bases.size() * sizeof(LPVOID)),
                              &need)) {
        return out;
    }
    count = need / sizeof(LPVOID);
    for (DWORD i = 0; i < count; ++i) {
        wchar_t path[MAX_PATH]{};
        if (!::GetDeviceDriverFileNameW(bases[i], path, (DWORD)std::size(path)))
            continue;
        wchar_t base_name[MAX_PATH]{};
        ::GetDeviceDriverBaseNameW(bases[i], base_name, (DWORD)std::size(base_name));
        DriverModule m{};
        m.base = (uint64_t)(uintptr_t)bases[i];
        m.path = Utf8FromWide(path);
        m.name = Utf8FromWide(base_name);
        out.push_back(std::move(m));
    }
    return out;
}

static bool IEqualPathBasename(const std::string& a, const std::string& b)
{
    auto base = [](const std::string& p) {
        size_t s = p.find_last_of("\\/");
        return s == std::string::npos ? p : p.substr(s + 1);
    };
    return IEqualAsciiSvc(base(a), base(b));
}

static void JoinDriverBase(pry::SvcEntry* row,
                            const std::vector<DriverModule>& drv)
{
    if (RowKindFromServiceType(0) == RowKindFromServiceType(0)) {}  // silence
    if (!(row->kind() == "driver")) return;
    for (const auto& d : drv) {
        if (IEqualPathBasename(row->image_path(), d.path) ||
            IEqualPathBasename(row->image_path(), d.name)) {
            row->set_module_base(d.base);
            // size + timestamp require a PE header read; defer to later.
            return;
        }
    }
    AppendWarning(row, "driver_base_fallback");
}

// Core enumerator — produces a vector of SvcEntry rows plus a count of
// those where decoration failed (degraded_rows). Caller handles paging.
static bool EnumerateSvc(SC_HANDLE scm,
                          const pry::SvcListRequest* req,
                          bool include_driver_base,
                          std::vector<pry::SvcEntry>* out,
                          uint32_t* degraded,
                          std::string* err)
{
    DWORD type_mask = 0;
    bool want_any_type = (req == nullptr || req->service_types_size() == 0);
    if (want_any_type) {
        type_mask = SERVICE_WIN32 | SERVICE_DRIVER | SERVICE_ADAPTER;
    } else {
        for (int i = 0; i < req->service_types_size(); ++i) {
            const std::string& t = req->service_types(i);
            if (IEqualAsciiSvc(t, "win32"))
                type_mask |= SERVICE_WIN32;
            else if (IEqualAsciiSvc(t, "driver"))
                type_mask |= SERVICE_DRIVER;
            else if (IEqualAsciiSvc(t, "adapter"))
                type_mask |= SERVICE_ADAPTER;
            else if (IEqualAsciiSvc(t, "user"))
                type_mask |= SERVICE_USER_SERVICE;
        }
    }
    if (!type_mask) type_mask = SERVICE_WIN32 | SERVICE_DRIVER | SERVICE_ADAPTER;

    DWORD state = SERVICE_STATE_ALL;
    DWORD need = 0, count = 0, resume = 0;
    ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, type_mask, state,
                              nullptr, 0, &need, &count, &resume, nullptr);
    if (::GetLastError() != ERROR_MORE_DATA && need == 0) {
        *err = "EnumServicesStatusExW probe failed";
        return false;
    }
    std::vector<BYTE> buf(need);
    if (!::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, type_mask, state,
                                   buf.data(), need, &need, &count, &resume,
                                   nullptr)) {
        *err = "EnumServicesStatusExW failed";
        return false;
    }
    auto* table = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());

    std::vector<std::string> start_filter, state_filter;
    if (req) {
        for (int i = 0; i < req->start_types_size(); ++i)
            start_filter.push_back(req->start_types(i));
        for (int i = 0; i < req->states_size(); ++i)
            state_filter.push_back(req->states(i));
    }
    std::string name_contains_lc;
    if (req && !req->name_contains().empty()) {
        name_contains_lc = req->name_contains();
        std::transform(name_contains_lc.begin(), name_contains_lc.end(),
                        name_contains_lc.begin(),
                        [](unsigned char c){ return (char)::tolower(c); });
    }

    std::vector<DriverModule> drv_cache;
    bool drv_cache_built = false;
    *degraded = 0;

    for (DWORD i = 0; i < count; ++i) {
        const auto& e = table[i];
        std::string name = Utf8FromWide(e.lpServiceName);
        if (!name_contains_lc.empty()) {
            std::string lc = name;
            std::transform(lc.begin(), lc.end(), lc.begin(),
                            [](unsigned char c){ return (char)::tolower(c); });
            if (lc.find(name_contains_lc) == std::string::npos) continue;
        }

        pry::SvcEntry row;
        row.set_name(name);
        row.set_display_name(Utf8FromWide(e.lpDisplayName));
        row.set_state(StateName(e.ServiceStatusProcess.dwCurrentState));
        row.set_service_type(ServiceTypeName(e.ServiceStatusProcess.dwServiceType));
        row.set_kind(RowKindFromServiceType(e.ServiceStatusProcess.dwServiceType));
        row.set_pid(e.ServiceStatusProcess.dwProcessId);
        FillControlsAccepted(e.ServiceStatusProcess.dwControlsAccepted, &row);

        if (!state_filter.empty() &&
            !ContainsCISvc(state_filter, row.state())) continue;

        SC_HANDLE sh = ::OpenServiceW(scm, e.lpServiceName,
                                        SERVICE_QUERY_CONFIG |
                                        SERVICE_QUERY_STATUS);
        if (sh) {
            DecorateFromConfig(scm, sh, &row);
            ::CloseServiceHandle(sh);
        } else {
            AppendWarning(&row, "scm_open");
            *degraded += 1;
        }

        if (!start_filter.empty() &&
            !ContainsCISvc(start_filter, row.start_type())) continue;

        if (row.kind() == "driver" && include_driver_base) {
            if (!drv_cache_built) {
                drv_cache = SnapshotDriverModules();
                drv_cache_built = true;
            }
            JoinDriverBase(&row, drv_cache);
        }

        if (!row.warnings().empty()) *degraded += 1;
        out->push_back(std::move(row));
    }
    return true;
}

class UmServicesSvc final : public pry::Services::Service {
public:
    explicit UmServicesSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status List(grpc::ServerContext* ctx,
                       const pry::SvcListRequest* req,
                       pry::SvcListResponse* resp) override
    {
        auto auth = CheckAuthSvc(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr,
                                          SC_MANAGER_ENUMERATE_SERVICE);
        if (!scm) {
            FillStatus(resp, "scm_denied: OpenSCManager failed");
            return grpc::Status::OK;
        }
        std::vector<pry::SvcEntry> rows;
        uint32_t degraded = 0;
        std::string err;
        bool ok = EnumerateSvc(scm, req, req->include_driver_base(),
                                 &rows, &degraded, &err);
        ::CloseServiceHandle(scm);
        if (!ok) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }

        uint32_t total = (uint32_t)rows.size();
        uint32_t limit = req->limit() ? req->limit() : 128;
        bool trunc = total > limit;
        uint32_t emitted = 0;
        for (auto& r : rows) {
            if (emitted >= limit) break;
            *resp->add_items() = std::move(r);
            ++emitted;
        }
        resp->set_total(total);
        resp->set_truncated(trunc);
        resp->set_degraded_rows(degraded);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Get(grpc::ServerContext* ctx,
                      const pry::SvcGetRequest* req,
                      pry::SvcGetResponse* resp) override
    {
        auto auth = CheckAuthSvc(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        if (req->name().empty()) {
            FillStatus(resp, "get: name is required");
            return grpc::Status::OK;
        }

        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr,
                                          SC_MANAGER_CONNECT);
        if (!scm) {
            FillStatus(resp, "scm_denied: OpenSCManager failed");
            return grpc::Status::OK;
        }
        std::wstring w = WideFromUtf8(req->name());
        SC_HANDLE sh = ::OpenServiceW(scm, w.c_str(),
                                        SERVICE_QUERY_CONFIG |
                                        SERVICE_QUERY_STATUS);
        if (!sh) {
            ::CloseServiceHandle(scm);
            FillStatus(resp, "svc_not_found: OpenService failed");
            return grpc::Status::OK;
        }
        SERVICE_STATUS_PROCESS st{};
        DWORD nread = 0;
        ::QueryServiceStatusEx(sh, SC_STATUS_PROCESS_INFO, (BYTE*)&st,
                                 sizeof(st), &nread);
        auto* row = resp->mutable_item();
        row->set_name(req->name());
        row->set_state(StateName(st.dwCurrentState));
        row->set_service_type(ServiceTypeName(st.dwServiceType));
        row->set_kind(RowKindFromServiceType(st.dwServiceType));
        row->set_pid(st.dwProcessId);
        FillControlsAccepted(st.dwControlsAccepted, row);
        DecorateFromConfig(scm, sh, row);
        if (row->kind() == "driver") {
            auto drv = SnapshotDriverModules();
            JoinDriverBase(row, drv);
        }
        ::CloseServiceHandle(sh);
        ::CloseServiceHandle(scm);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Dependencies(grpc::ServerContext* ctx,
                               const pry::SvcDependenciesRequest* req,
                               pry::SvcDependenciesResponse* resp) override
    {
        auto auth = CheckAuthSvc(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        if (req->name().empty()) {
            FillStatus(resp, "dependencies: name is required");
            return grpc::Status::OK;
        }
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr,
                                          SC_MANAGER_ENUMERATE_SERVICE);
        if (!scm) {
            FillStatus(resp, "scm_denied: OpenSCManager failed");
            return grpc::Status::OK;
        }
        std::wstring w = WideFromUtf8(req->name());
        SC_HANDLE sh = ::OpenServiceW(scm, w.c_str(),
                                        SERVICE_QUERY_CONFIG |
                                        SERVICE_ENUMERATE_DEPENDENTS);
        if (!sh) {
            ::CloseServiceHandle(scm);
            FillStatus(resp, "svc_not_found: OpenService failed");
            return grpc::Status::OK;
        }
        if (req->reverse()) {
            DWORD need = 0, count = 0;
            ::EnumDependentServicesW(sh, SERVICE_STATE_ALL,
                                      nullptr, 0, &need, &count);
            if (need) {
                std::vector<BYTE> buf(need);
                if (::EnumDependentServicesW(sh, SERVICE_STATE_ALL,
                                               reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data()),
                                               need, &need, &count)) {
                    auto* table = reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data());
                    for (DWORD i = 0; i < count; ++i) {
                        auto* row = resp->add_items();
                        row->set_name(Utf8FromWide(table[i].lpServiceName));
                        row->set_display_name(
                            Utf8FromWide(table[i].lpDisplayName));
                        row->set_state(StateName(table[i].ServiceStatus.dwCurrentState));
                        row->set_service_type(
                            ServiceTypeName(table[i].ServiceStatus.dwServiceType));
                        row->set_kind(RowKindFromServiceType(
                            table[i].ServiceStatus.dwServiceType));
                    }
                }
            }
        } else {
            DWORD need = 0;
            ::QueryServiceConfigW(sh, nullptr, 0, &need);
            if (need) {
                std::vector<BYTE> buf(need);
                if (::QueryServiceConfigW(sh,
                                            reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buf.data()),
                                            need, &need)) {
                    auto* cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buf.data());
                    for (auto& dep : ParseMultiSz(cfg->lpDependencies)) {
                        auto* row = resp->add_items();
                        row->set_name(dep);
                    }
                }
            }
        }
        ::CloseServiceHandle(sh);
        ::CloseServiceHandle(scm);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

    grpc::Status Drivers(grpc::ServerContext* ctx,
                          const pry::SvcDriversRequest* req,
                          pry::SvcDriversResponse* resp) override
    {
        auto auth = CheckAuthSvc(ctx, cfg_.token);
        if (!auth.ok()) return auth;
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr,
                                          SC_MANAGER_ENUMERATE_SERVICE);
        if (!scm) {
            FillStatus(resp, "scm_denied: OpenSCManager failed");
            return grpc::Status::OK;
        }
        pry::SvcListRequest sub;
        sub.add_service_types("driver");
        if (req->include_unloaded()) {
            // No separate state field — SERVICE_STATE_ALL in EnumerateSvc
            // already captures stopped drivers. Nothing extra to do.
        }
        std::vector<pry::SvcEntry> rows;
        uint32_t degraded = 0;
        std::string err;
        bool ok = EnumerateSvc(scm, &sub, true, &rows, &degraded, &err);
        ::CloseServiceHandle(scm);
        if (!ok) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }
        if (!req->include_unloaded()) {
            // Drop stopped / absent rows.
            std::vector<pry::SvcEntry> keep;
            keep.reserve(rows.size());
            for (auto& r : rows) {
                if (r.state() == "RUNNING") keep.push_back(std::move(r));
            }
            rows.swap(keep);
        }
        for (auto& r : rows) *resp->add_items() = std::move(r);
        FillStatus(resp, "");
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

}  // namespace

void RegisterServicesService(grpc::ServerBuilder& builder, const Config& cfg)
{
    static UmServicesSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
