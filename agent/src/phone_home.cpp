// T1.1d — Agent phone-home. See phone_home.hpp.
//
// Dependencies are intentionally Windows-SDK only:
//   * iphlpapi (GetAdaptersAddresses)  — already linked for net_pin
//   * winhttp  (optional outbound POST) — added by this change
// No vcpkg, no WinINet, no cURL. The thread detaches and runs until the
// process exits.

#include "phone_home.hpp"
#include "srv_log.hpp"

// Winsock2 MUST come before windows.h / iphlpapi.h on MSVC — otherwise
// windows.h pulls in the legacy winsock.h first and iphlpapi.h ends up
// without GAA_FLAG_* / PIP_ADAPTER_ADDRESSES. WIN32_LEAN_AND_MEAN tells
// windows.h to skip winsock.h entirely so our winsock2 include wins.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

// Avoid pulling in a JSON dependency for a 7-field flat object.

namespace pry {

namespace {

// ---------- utilities ---------------------------------------------------

std::wstring Utf8ToWide(const std::string& in)
{
    if (in.empty()) {
        return std::wstring();
    }
    int n = MultiByteToWideChar(CP_UTF8, 0, in.data(), (int)in.size(), nullptr, 0);
    std::wstring w(n > 0 ? n : 0, L'\0');
    if (n > 0) {
        MultiByteToWideChar(CP_UTF8, 0, in.data(), (int)in.size(), w.data(), n);
    }
    return w;
}

// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Treat anything else (including
// 100.64.0.0/10 CGN, 169.254/16 link-local, public IPs, loopback) as not
// something to phone home with — the orchestrator lives on the lab LAN and
// those are the ranges it can route back to.
bool IsPrivateIPv4(uint32_t host_order_addr)
{
    uint8_t a = (uint8_t)(host_order_addr >> 24);
    uint8_t b = (uint8_t)(host_order_addr >> 16);
    if (a == 10) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    return false;
}

// Snapshot of the current filtered IPv4 set. Sorted so the change detector
// (set-equality) doesn't trip on adapter-order jitter.
std::vector<std::string> CurrentPrivateIPv4Addresses()
{
    std::vector<std::string> out;
    ULONG size = 15 * 1024;
    std::vector<char> buf(size);
    DWORD rc = GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME,
        nullptr,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()),
        &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.assign(size, 0);
        rc = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
            GAA_FLAG_SKIP_FRIENDLY_NAME,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()),
            &size);
    }
    if (rc != NO_ERROR) {
        return out;
    }
    auto* a = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    for (; a != nullptr; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) {
            continue;
        }
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }
        for (auto* ua = a->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
            if (ua->Address.lpSockaddr == nullptr ||
                ua->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            auto* sin = reinterpret_cast<const sockaddr_in*>(ua->Address.lpSockaddr);
            uint32_t host_order = ntohl(sin->sin_addr.s_addr);
            uint8_t first = (uint8_t)(host_order >> 24);
            uint8_t second = (uint8_t)(host_order >> 16);
            if (first == 127) continue;                      // loopback
            if (first == 169 && second == 254) continue;     // link-local
            if (!IsPrivateIPv4(host_order)) continue;        // not RFC1918
            char text[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &sin->sin_addr, text, sizeof(text));
            out.emplace_back(text);
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

// ISO8601 UTC timestamp — "2026-10-27T15:04:05Z". Matches _now() in
// registry.py so correlated reads look native.
std::string IsoUtcNow()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[32];
    _snprintf_s(buf, _TRUNCATE, "%04u-%02u-%02uT%02u:%02u:%02uZ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// Minimal JSON escaper for ASCII-with-control-chars. Agent-side identifiers
// (computer name, agent instance id) stay inside this safe subset; the
// escaper is still conservative for \" / \\ / control bytes.
void JsonEscapeTo(std::string& dst, const std::string& s)
{
    dst.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  dst.append("\\\""); break;
            case '\\': dst.append("\\\\"); break;
            case '\b': dst.append("\\b"); break;
            case '\f': dst.append("\\f"); break;
            case '\n': dst.append("\\n"); break;
            case '\r': dst.append("\\r"); break;
            case '\t': dst.append("\\t"); break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    _snprintf_s(esc, _TRUNCATE, "\\u%04x", (unsigned)c);
                    dst.append(esc);
                } else {
                    dst.push_back((char)c);
                }
        }
    }
    dst.push_back('"');
}

std::string BuildPayload(const std::string& computer_name,
                         const std::string& machine_label,
                         uint16_t port,
                         const std::vector<std::string>& ipv4,
                         uint64_t boot_epoch_ms,
                         const std::string& agent_instance_id,
                         const std::string& written_at)
{
    std::string out;
    out.reserve(256 + ipv4.size() * 24);
    out.push_back('{');
    out.append("\"computer_name\":"); JsonEscapeTo(out, computer_name); out.push_back(',');
    out.append("\"machine_label\":"); JsonEscapeTo(out, machine_label); out.push_back(',');

    char num[48];
    _snprintf_s(num, _TRUNCATE, "%u", (unsigned)port);
    out.append("\"port\":"); out.append(num); out.push_back(',');

    out.append("\"ipv4\":[");
    for (size_t i = 0; i < ipv4.size(); ++i) {
        if (i) out.push_back(',');
        JsonEscapeTo(out, ipv4[i]);
    }
    out.push_back(']'); out.push_back(',');

    _snprintf_s(num, _TRUNCATE, "%llu", (unsigned long long)boot_epoch_ms);
    out.append("\"boot_epoch_ms\":"); out.append(num); out.push_back(',');

    out.append("\"agent_instance_id\":");
    JsonEscapeTo(out, agent_instance_id); out.push_back(',');

    out.append("\"written_at\":"); JsonEscapeTo(out, written_at);
    out.push_back('}');
    return out;
}

// ---------- local JSON write -------------------------------------------

// Writes to C:\ProgramData\pry\agent_endpoint.json atomically — temp
// file in the same directory + MoveFileExW(..., MOVEFILE_REPLACE_EXISTING).
// Readers (operators over the admin share) never see a half-written file.
void WriteEndpointJson(const std::string& payload)
{
    const wchar_t* dir = L"C:\\ProgramData\\pry";
    const wchar_t* final_path = L"C:\\ProgramData\\pry\\agent_endpoint.json";
    const wchar_t* temp_path  = L"C:\\ProgramData\\pry\\agent_endpoint.json.tmp";

    if (!CreateDirectoryW(dir, nullptr)) {
        DWORD gle = GetLastError();
        if (gle != ERROR_ALREADY_EXISTS) {
            char dbg[160];
            _snprintf_s(dbg, _TRUNCATE,
                        "[phone_home] CreateDirectory %ls failed gle=%lu\n",
                        dir, (unsigned long)gle);
            OutputDebugStringA(dbg);
            return;
        }
    }

    HANDLE h = CreateFileW(temp_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        char dbg[160];
        _snprintf_s(dbg, _TRUNCATE, "[phone_home] CreateFile tmp failed gle=%lu\n",
                    (unsigned long)GetLastError());
        OutputDebugStringA(dbg);
        return;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, payload.data(), (DWORD)payload.size(), &written, nullptr);
    CloseHandle(h);
    if (!ok || written != payload.size()) {
        OutputDebugStringA("[phone_home] WriteFile tmp short/failed\n");
        DeleteFileW(temp_path);
        return;
    }
    if (!MoveFileExW(temp_path, final_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        char dbg[160];
        _snprintf_s(dbg, _TRUNCATE, "[phone_home] MoveFileEx failed gle=%lu\n",
                    (unsigned long)GetLastError());
        OutputDebugStringA(dbg);
        DeleteFileW(temp_path);
    }
}

// ---------- WinHTTP POST -----------------------------------------------

// Parse a URL just enough to drive WinHttpOpen/Connect/OpenRequest.
// Accepts "http://host[:port]/[path]" and "https://host[:port]/[path]".
// Any failure returns false and the caller skips the HTTP step.
struct ParsedUrl {
    bool secure = false;
    std::wstring host;
    INTERNET_PORT port = 0;
    std::wstring path;  // starts with '/' (defaults to "/api/agent_report")
};

bool ParseUrl(const std::string& url_utf8, ParsedUrl& out)
{
    std::wstring url = Utf8ToWide(url_utf8);
    if (url.empty()) return false;

    URL_COMPONENTSW uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host_buf[256]{};
    wchar_t path_buf[512]{};
    uc.lpszHostName = host_buf;
    uc.dwHostNameLength = (DWORD)(sizeof(host_buf) / sizeof(host_buf[0]));
    uc.lpszUrlPath = path_buf;
    uc.dwUrlPathLength = (DWORD)(sizeof(path_buf) / sizeof(path_buf[0]));

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) {
        return false;
    }
    out.host = std::wstring(uc.lpszHostName, uc.dwHostNameLength);
    out.port = uc.nPort;
    out.secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    out.path = path.empty() ? L"/api/agent_report" : path;
    return !out.host.empty() && out.port != 0;
}

void PostToOrchestrator(const ParsedUrl& url, const std::string& payload)
{
    HINTERNET session = WinHttpOpen(L"pry_agent/phone_home",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        char dbg[128];
        _snprintf_s(dbg, _TRUNCATE,
                    "[phone_home] WinHttpOpen failed gle=%lu\n",
                    (unsigned long)GetLastError());
        OutputDebugStringA(dbg);
        return;
    }
    // 2-second connect + send/receive. The lab orchestrator is on the same
    // L2 as the agent; anything that doesn't answer in 2s is routed via
    // the retry loop (next 30s tick), not by stacking blocked requests.
    DWORD two_sec = 2000;
    WinHttpSetTimeouts(session, two_sec, two_sec, two_sec, two_sec);

    HINTERNET conn = WinHttpConnect(session, url.host.c_str(), url.port, 0);
    if (!conn) {
        char dbg[128];
        _snprintf_s(dbg, _TRUNCATE,
                    "[phone_home] WinHttpConnect failed gle=%lu\n",
                    (unsigned long)GetLastError());
        OutputDebugStringA(dbg);
        WinHttpCloseHandle(session);
        return;
    }
    DWORD flags = url.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", url.path.c_str(), nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return;
    }

    // Private-LAN posture: skip cert validation for https targets. The
    // orchestrator typically listens over plain http on the lab subnet;
    // this just keeps the HTTPS code path working when an operator forwards
    // the dashboard through a self-signed proxy. Payload has no secrets
    // (host IPs + hostname + agent id), so a MITM gains nothing here that
    // sniffing the LAN wouldn't already give them.
    if (url.secure) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    const wchar_t* headers = L"Content-Type: application/json\r\n";
    BOOL ok = WinHttpSendRequest(req, headers, (DWORD)-1,
                                 (LPVOID)payload.data(),
                                 (DWORD)payload.size(),
                                 (DWORD)payload.size(), 0);
    if (ok) {
        ok = WinHttpReceiveResponse(req, nullptr);
    }
    if (!ok) {
        char dbg[160];
        _snprintf_s(dbg, _TRUNCATE,
                    "[phone_home] send/recv failed gle=%lu\n",
                    (unsigned long)GetLastError());
        OutputDebugStringA(dbg);
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
}

// ---------- thread body ------------------------------------------------

struct ThreadCfg {
    std::string orchestrator_url;
    std::string computer_name;
    std::string machine_label;
    uint16_t port = 0;
    uint64_t boot_epoch_ms = 0;
    std::string agent_instance_id;
};

void EmitOnce(const ThreadCfg& cfg, const std::vector<std::string>& ipv4,
              bool parsed_url, const ParsedUrl& url)
{
    const std::string payload = BuildPayload(
        cfg.computer_name, cfg.machine_label, cfg.port, ipv4,
        cfg.boot_epoch_ms, cfg.agent_instance_id, IsoUtcNow());
    WriteEndpointJson(payload);
    if (parsed_url) {
        PostToOrchestrator(url, payload);
    }
}

void ThreadMain(ThreadCfg cfg)
{
    ParsedUrl url{};
    bool parsed_url = false;
    if (!cfg.orchestrator_url.empty()) {
        parsed_url = ParseUrl(cfg.orchestrator_url, url);
        if (!parsed_url) {
            char dbg[160];
            _snprintf_s(dbg, _TRUNCATE,
                        "[phone_home] could not parse orchestrator url '%s' — "
                        "falling back to file-only mode\n",
                        cfg.orchestrator_url.c_str());
            OutputDebugStringA(dbg);
        }
    }

    std::vector<std::string> last = CurrentPrivateIPv4Addresses();
    EmitOnce(cfg, last, parsed_url, url);

    // 15 x 2s = ~30s. Re-emit on every address-set change AND once per
    // outer loop as a heartbeat even without changes.
    using namespace std::chrono_literals;
    for (;;) {
        bool changed = false;
        for (int tick = 0; tick < 15; ++tick) {
            std::this_thread::sleep_for(2s);
            auto now = CurrentPrivateIPv4Addresses();
            if (now != last) {
                last = std::move(now);
                changed = true;
                break;
            }
        }
        if (!changed) {
            last = CurrentPrivateIPv4Addresses();
        }
        EmitOnce(cfg, last, parsed_url, url);
    }
}

} // namespace

void StartPhoneHomeThread(const std::string& orchestrator_url,
                          const std::string& computer_name,
                          const std::string& machine_label,
                          uint16_t port,
                          uint64_t boot_epoch_ms,
                          const std::string& agent_instance_id)
{
    ThreadCfg cfg{};
    cfg.orchestrator_url = orchestrator_url;
    cfg.computer_name = computer_name;
    cfg.machine_label = machine_label.empty() ? computer_name : machine_label;
    cfg.port = port;
    cfg.boot_epoch_ms = boot_epoch_ms;
    cfg.agent_instance_id = agent_instance_id;

    try {
        std::thread(ThreadMain, std::move(cfg)).detach();
        srvlog::Logf("phone_home: started (orchestrator=%s, port=%u, label=%s)",
                     orchestrator_url.empty() ? "(file-only)" : orchestrator_url.c_str(),
                     (unsigned)port,
                     machine_label.empty() ? computer_name.c_str() : machine_label.c_str());
    } catch (...) {
        srvlog::Logf("phone_home: failed to spawn thread");
        OutputDebugStringA("[phone_home] std::thread spawn failed\n");
    }
}

} // namespace pry
