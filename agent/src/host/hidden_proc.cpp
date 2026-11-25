// agent/src/host/hidden_proc.cpp — SI feature 2 (Wave 1): hidden-process
// detection.
//
// Pure usermode scanners (brute / registry / ETW) that produce PID
// oracle rows for the orchestrator to cross-join against the ground
// truth NtQSI process list. Shared TU: linked into both the agent
// (agent/CMakeLists.txt) and the umagent (umagent/CMakeLists.txt).
//
// Dependency notes
// ----------------
// * No driver IOCTLs — Wave 1 is driver-free. Wave 2's CSRSS mode will
//   use the driver's PRY_FUNC_HANDLE_LIST enrichment; the C++ stub
//   agent/src/host/csrss_scan.cpp is intentionally empty until then.
// * The ETW mode uses the base ``EnumerateTraceGuidsEx`` API (advapi32)
//   so it is independent of SI #8's ETW consumer scaffolding under
//   agent/src/etw/. If that consumer later publishes a richer
//   ``pry::etw::BeginEtwProcessList`` API we can swap this scanner
//   over without touching the response shape.
//
// Slice doc: an internal plan
// §Feature 2.

#include "hidden_proc.hpp"

#include <windows.h>
#include <psapi.h>
#include <evntrace.h>  // EnumerateTraceGuidsEx + TraceGuidQueryInfo
#include <evntcons.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32")
// psapi is already linked by the agent and umagent targets.

namespace pry::host {

namespace {

std::string ToLower(const std::string& s)
{
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return (char)::tolower(c); });
    return out;
}

std::string Basename(const std::string& path)
{
    size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string WideToUtf8(const wchar_t* w, size_t wlen)
{
    if (!w || !wlen) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, (int)wlen,
                                   nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, (int)wlen,
                          out.data(), n, nullptr, nullptr);
    return out;
}

HiddenPidRow* FindOrAdd(std::vector<HiddenPidRow>* rows, uint32_t pid)
{
    for (auto& r : *rows) {
        if (r.pid == pid) return &r;
    }
    rows->push_back(HiddenPidRow{});
    rows->back().pid = pid;
    return &rows->back();
}

void AppendSource(HiddenPidRow* row, const char* mode)
{
    if (!row->sources.empty()) row->sources.push_back(',');
    row->sources.append(mode);
}

std::string ProcessImageName(HANDLE h)
{
    if (!h) return {};
    wchar_t buf[MAX_PATH];
    DWORD len = sizeof(buf) / sizeof(buf[0]);
    // QueryFullProcessImageNameW works with PROCESS_QUERY_LIMITED_INFORMATION
    // which is what we try to open with.
    if (!::QueryFullProcessImageNameW(h, 0, buf, &len) || !len) {
        return {};
    }
    std::string full = WideToUtf8(buf, len);
    return Basename(full);
}

}  // namespace

// -----------------------------------------------------------------------
// Brute scanner.
//
// Walk PID range [step, pid_max] with OpenProcess:
//   SUCCESS         => PID exists; capture image + handle count +
//                       exit-time (so a lingering zombie surfaces).
//   ACCESS_DENIED   => PID exists but is PPL/protected — still a yes.
//   INVALID_PARAM   => PID is not live.
// Non-fatal: any one PID failing cleanly for another reason just drops
// off the oracle output.
// -----------------------------------------------------------------------
bool BruteScan(uint32_t pid_max, uint32_t step,
               std::vector<HiddenPidRow>* rows, std::string* err)
{
    if (!rows) {
        if (err) *err = "hidden_proc: brute: rows=nullptr";
        return false;
    }
    if (!step) step = 4;
    if (!pid_max) pid_max = 100000;
    pid_max = std::min<uint32_t>(pid_max, 1 << 24);

    for (uint32_t pid = step; pid <= pid_max; pid += step) {
        HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                  FALSE, pid);
        DWORD gle = h ? 0 : ::GetLastError();
        if (!h && gle != ERROR_ACCESS_DENIED) {
            // No such pid, or a soft failure — skip.
            continue;
        }
        auto* row = FindOrAdd(rows, pid);
        bool was_new = !row->present_brute;
        row->present_brute = true;
        if (was_new) AppendSource(row, "brute");

        if (h) {
            if (row->image.empty()) {
                row->image = ProcessImageName(h);
            }
            DWORD hc = 0;
            if (::GetProcessHandleCount(h, &hc)) {
                row->handle_count = hc;
            }
            FILETIME ft_create{}, ft_exit{}, ft_kernel{}, ft_user{};
            if (::GetProcessTimes(h, &ft_create, &ft_exit,
                                   &ft_kernel, &ft_user)) {
                ULARGE_INTEGER li{};
                li.LowPart = ft_exit.dwLowDateTime;
                li.HighPart = ft_exit.dwHighDateTime;
                row->exit_time_100ns = li.QuadPart;  // 0 when still live
            }
            ::CloseHandle(h);
        }
    }
    return true;
}

// -----------------------------------------------------------------------
// Registry scanner.
//
// Two feeds, deduped into one PID set that we only toggle present_registry
// on when the PID shows up:
//   1. HKLM\SYSTEM\CurrentControlSet\Services — grab every "ImagePath"
//      value basename; match against EnumProcesses output's image name.
//   2. The "009" (English) PerfLib Counter blob — rarely rich on
//      modern Windows, so we treat (1) as the primary signal.
// Any failure (missing key, denied) marks the mode failed in err but we
// still try the other mode.
// -----------------------------------------------------------------------
namespace {

bool EnumServiceImageNames(std::set<std::string>* images,
                           std::string* err)
{
    HKEY root = nullptr;
    LONG rc = ::RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services",
        0, KEY_READ, &root);
    if (rc != ERROR_SUCCESS) {
        if (err) {
            char b[64];
            std::snprintf(b, sizeof(b),
                          "hidden_proc: registry: Services open failed, "
                          "rc=%ld", rc);
            *err = b;
        }
        return false;
    }
    DWORD idx = 0;
    wchar_t sub[256];
    while (true) {
        DWORD slen = sizeof(sub) / sizeof(sub[0]);
        LONG er = ::RegEnumKeyExW(root, idx++, sub, &slen,
                                    nullptr, nullptr, nullptr, nullptr);
        if (er == ERROR_NO_MORE_ITEMS) break;
        if (er != ERROR_SUCCESS) continue;
        HKEY svc = nullptr;
        if (::RegOpenKeyExW(root, sub, 0, KEY_READ, &svc)
                != ERROR_SUCCESS) {
            continue;
        }
        wchar_t path[1024];
        DWORD plen = sizeof(path);
        DWORD type = 0;
        if (::RegQueryValueExW(svc, L"ImagePath", nullptr, &type,
                                reinterpret_cast<LPBYTE>(path),
                                &plen) == ERROR_SUCCESS
                && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            size_t wlen = plen / sizeof(wchar_t);
            while (wlen && path[wlen - 1] == 0) wlen--;
            std::string u = WideToUtf8(path, wlen);
            // ImagePath may carry quotes / argv — grab the first token.
            std::string tok;
            size_t i = 0;
            while (i < u.size() && (u[i] == '"' || u[i] == ' ')) ++i;
            while (i < u.size() && u[i] != '"' && u[i] != ' ') {
                tok.push_back(u[i++]);
            }
            if (!tok.empty()) {
                images->insert(ToLower(Basename(tok)));
            }
        }
        ::RegCloseKey(svc);
    }
    ::RegCloseKey(root);
    return true;
}

}  // namespace

bool RegistryScan(std::vector<HiddenPidRow>* rows, std::string* err)
{
    if (!rows) {
        if (err) *err = "hidden_proc: registry: rows=nullptr";
        return false;
    }
    std::set<std::string> svc_images;
    std::string svc_err;
    bool svc_ok = EnumServiceImageNames(&svc_images, &svc_err);
    if (!svc_ok && err && err->empty()) *err = svc_err;

    // Build pid->basename inventory from EnumProcesses.
    DWORD pids[8192];
    DWORD bytes_ret = 0;
    if (!::EnumProcesses(pids, sizeof(pids), &bytes_ret)) {
        if (err && err->empty()) {
            char b[80];
            std::snprintf(b, sizeof(b),
                          "hidden_proc: registry: EnumProcesses failed, "
                          "gle=%lu", ::GetLastError());
            *err = b;
        }
        return svc_ok;  // partial — services alone give us nothing to join
    }
    uint32_t n = bytes_ret / sizeof(DWORD);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t pid = pids[i];
        if (!pid) continue;
        HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                  FALSE, pid);
        if (!h) continue;
        std::string img = ProcessImageName(h);
        ::CloseHandle(h);
        if (img.empty()) continue;
        std::string lo = ToLower(img);
        if (!svc_images.count(lo)) continue;
        auto* row = FindOrAdd(rows, pid);
        bool was_new = !row->present_registry;
        row->present_registry = true;
        if (row->image.empty()) row->image = img;
        if (was_new) AppendSource(row, "registry");
    }
    return svc_ok;
}

// -----------------------------------------------------------------------
// ETW scanner.
//
// EnumerateTraceGuidsEx(TraceGuidQueryList) returns every provider GUID
// registered right now; TraceGuidQueryInfo on each returns the pid list
// of its process owners.
// -----------------------------------------------------------------------
bool EtwScan(std::vector<HiddenPidRow>* rows, std::string* err)
{
    if (!rows) {
        if (err) *err = "hidden_proc: etw: rows=nullptr";
        return false;
    }
    ULONG rc = ERROR_INSUFFICIENT_BUFFER;
    std::vector<GUID> guids;
    for (ULONG attempt = 0; attempt < 4; ++attempt) {
        ULONG needed = 0;
        rc = ::EnumerateTraceGuidsEx(
            TraceGuidQueryList, nullptr, 0,
            guids.empty() ? nullptr : guids.data(),
            (ULONG)(guids.size() * sizeof(GUID)),
            &needed);
        if (rc == ERROR_SUCCESS) break;
        if (rc != ERROR_INSUFFICIENT_BUFFER || !needed) break;
        guids.resize(needed / sizeof(GUID) + 16);
    }
    if (rc != ERROR_SUCCESS) {
        if (err) {
            char b[80];
            std::snprintf(b, sizeof(b),
                          "hidden_proc: etw: QueryList failed, rc=%lu",
                          rc);
            *err = b;
        }
        return false;
    }
    // Probe each provider for its owning PID set.
    std::vector<uint8_t> info(sizeof(TRACE_GUID_INFO)
                               + 64 * sizeof(TRACE_PROVIDER_INSTANCE_INFO));
    for (const auto& g : guids) {
        ULONG needed = 0;
        rc = ERROR_INSUFFICIENT_BUFFER;
        for (ULONG attempt = 0; attempt < 3; ++attempt) {
            rc = ::EnumerateTraceGuidsEx(TraceGuidQueryInfo,
                                          (LPVOID)&g, sizeof(GUID),
                                          info.data(),
                                          (ULONG)info.size(), &needed);
            if (rc == ERROR_SUCCESS) break;
            if (rc != ERROR_INSUFFICIENT_BUFFER || !needed) break;
            info.resize(needed);
        }
        if (rc != ERROR_SUCCESS || info.size() < sizeof(TRACE_GUID_INFO)) {
            continue;
        }
        auto* hdr = reinterpret_cast<TRACE_GUID_INFO*>(info.data());
        ULONG insts = hdr->InstanceCount;
        ULONG off = sizeof(TRACE_GUID_INFO);
        for (ULONG i = 0; i < insts && off + sizeof(TRACE_PROVIDER_INSTANCE_INFO)
                                        <= info.size(); ++i) {
            auto* inst = reinterpret_cast<TRACE_PROVIDER_INSTANCE_INFO*>(
                info.data() + off);
            uint32_t pid = inst->Pid;
            if (pid) {
                auto* row = FindOrAdd(rows, pid);
                bool was_new = !row->present_etw;
                row->present_etw = true;
                if (was_new) AppendSource(row, "etw");
                if (row->image.empty()) {
                    HANDLE h = ::OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                    if (h) {
                        row->image = ProcessImageName(h);
                        ::CloseHandle(h);
                    }
                }
            }
            if (!inst->NextOffset) break;
            off += inst->NextOffset;
        }
    }
    return true;
}

bool ScanHiddenProcesses(const HiddenScanRequest& req,
                         HiddenScanResult* out,
                         std::string* err)
{
    if (!out) {
        if (err) *err = "hidden_proc: out=nullptr";
        return false;
    }
    out->rows.clear();
    out->modes_run.clear();
    out->modes_failed.clear();

    uint32_t pid_max = req.pid_max ? req.pid_max : 100000;
    uint32_t step = req.step ? req.step : 4;
    out->pid_max_used = pid_max;
    out->step_used = step;

    bool any_run = false;

    if (req.do_brute) {
        std::string e;
        if (BruteScan(pid_max, step, &out->rows, &e)) {
            out->modes_run.emplace_back("brute");
            any_run = true;
        } else {
            out->modes_failed.emplace_back("brute");
        }
    }
    if (req.do_registry) {
        std::string e;
        if (RegistryScan(&out->rows, &e)) {
            out->modes_run.emplace_back("registry");
            any_run = true;
        } else {
            out->modes_failed.emplace_back("registry");
        }
    }
    if (req.do_etw) {
        std::string e;
        if (EtwScan(&out->rows, &e)) {
            out->modes_run.emplace_back("etw");
            any_run = true;
        } else {
            out->modes_failed.emplace_back("etw");
        }
    }
    if (!any_run && !req.do_brute && !req.do_registry && !req.do_etw) {
        if (err) *err = "hidden_proc: no modes requested";
        return false;
    }
    return true;
}

}  // namespace pry::host
