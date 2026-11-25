#include <grpcpp/grpcpp.h>

#include "grpc_auth.hpp"
#include "token_file.hpp"
#include "um_services.hpp"
#include "umem.hpp"
#include "srv_log.hpp"
#include "listen_watch.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <windows.h>

int UmMain(int argc, char** argv);

namespace {

void Usage()
{
    fprintf(stderr,
            "pry_umagent: usermode-only memory/module view (parity cross-check target)\n"
            "usage: pry_umagent.exe --port 50075 (--token-file <path> | --token <secret>)\n"
            "       [--bind 127.0.0.1] [--max-read-mb 8] [--dev] [--log <path>]\n"
            "  no token = auth DISABLED (dev only; refuse to expose that beyond loopback)\n");
}

// ---- minimal SCM wrapper: umagent previously had none, so the service timed
// ---- out (7009) and SCM killed it; same coarse stop semantics as the agent

SERVICE_STATUS g_status{};
SERVICE_STATUS_HANDLE g_handle = nullptr;
int (*g_fn)(int, char**) = nullptr;
int g_argc = 0;
char** g_argv = nullptr;

void SetState(DWORD state, DWORD waitHint = 0)
{
    if (!g_handle) {
        return;
    }
    static DWORD checkpoint = 0;
    g_status.dwCurrentState = state;
    g_status.dwCheckPoint = state == SERVICE_RUNNING || state == SERVICE_STOPPED ? 0 : ++checkpoint;
    g_status.dwWaitHint = waitHint;
    SetServiceStatus(g_handle, &g_status);
}

DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD, LPVOID, LPVOID)
{
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        SetState(SERVICE_STOP_PENDING, 5000);
        SetState(SERVICE_STOPPED);
        ExitProcess(0);
    }
    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR* argv)
{
    LPCWSTR name = (argv && argv[0]) ? argv[0] : L"PryUmagent";
    g_handle = RegisterServiceCtrlHandlerExW(name, ServiceCtrlHandler, nullptr);
    if (!g_handle) {
        return;
    }
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetState(SERVICE_START_PENDING, 5000);
    std::thread([] {
        SetState(SERVICE_RUNNING);
        int rc = g_fn(g_argc, g_argv);
        // Report a non-zero worker exit as a service failure so SCM
        // failure recovery (sc failureflag 1) fires — same as the agent.
        if (rc != 0) {
            g_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
            g_status.dwServiceSpecificExitCode = (DWORD)rc;
        }
        SetState(SERVICE_STOPPED);
    }).detach();
}

int RunAsServiceOrConsole(bool console, int (*fn)(int, char**), int argc, char** argv)
{
    if (console) {
        return fn(argc, argv);
    }
    SERVICE_TABLE_ENTRYW table[2]{};
    table[0].lpServiceName = const_cast<LPWSTR>(L"PryUmagent");
    table[0].lpServiceProc = ServiceMain;
    g_fn = fn;
    g_argc = argc;
    g_argv = argv;
    if (!StartServiceCtrlDispatcherW(table)) {
        if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            return 1;
        }
        return fn(argc, argv);
    }
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool console = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dev")) {
            console = true;
        }
    }
    return RunAsServiceOrConsole(console, UmMain, argc, argv);
}

int UmMain(int argc, char** argv)
{
    um::Config cfg;
    std::wstring logPath;
    std::wstring tokenFile;
    bool dev = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            cfg.port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--token") && i + 1 < argc) {
            cfg.token = argv[++i];
        } else if (!strcmp(argv[i], "--token-file") && i + 1 < argc) {
            int n = MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, nullptr, 0);
            tokenFile.resize(n ? n - 1 : 0);
            if (n) {
                MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, tokenFile.data(), n);
            }
        } else if (!strcmp(argv[i], "--bind") && i + 1 < argc) {
            cfg.bind = argv[++i];
        } else if (!strcmp(argv[i], "--max-read-mb") && i + 1 < argc) {
            cfg.maxReadBytes = (uint64_t)atoi(argv[++i]) << 20;
        } else if (!strcmp(argv[i], "--dev")) {
            dev = true;
        } else if (!strcmp(argv[i], "--log") && i + 1 < argc) {
            int n = MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, nullptr, 0);
            logPath.resize(n ? n - 1 : 0);
            if (n) {
                MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, logPath.data(), n);
            }
        } else {
            Usage();
            return 2;
        }
    }
    if (cfg.port <= 0) {
        Usage();
        return 2;
    }
    // --token-file (SYSTEM+Admins-only file written by
    // install_agent_service.ps1) wins over --token. An unreadable file is a
    // hard stop: never fall back to a stale --token or to no auth.
    std::string tokenErr;
    if (!tokenFile.empty()) {
        std::string t;
        if (!pry::ReadTokenFile(tokenFile, &t, &tokenErr)) {
            fprintf(stderr, "pry_umagent: --token-file: %s\n", tokenErr.c_str());
            pry::srvlog::Open(logPath);
            pry::srvlog::Logf("refusing to start: --token-file: %s", tokenErr.c_str());
            pry::srvlog::Close();
            return 2;
        }
        cfg.token = t;
    }

    um::EnableDebugPriv(); // best effort: SeDebugPrivilege when run elevated

    // same stdio/log safety as the agent (see srv_log.hpp).
    pry::srvlog::Open(logPath);
    if (!dev) {
        if (pry::srvlog::Enabled()) {
            pry::srvlog::CaptureStderr(); // stdout→NUL, stderr→rotating log
        } else {
            pry::srvlog::RedirectStdioToNul();
        }
    }
    pry::srvlog::Logf("pry_umagent %s starting (pid %lu)", cfg.version.c_str(),
                         (unsigned long)GetCurrentProcessId());
    if (cfg.token.empty()) {
        // Empty token = bearer auth disabled (kept for --dev parity runs).
        // Loud, and louder when the listener is reachable off-box.
        const bool loopback = pry::auth::IsLoopbackBind(cfg.bind);
        pry::srvlog::Logf("WARNING: AUTH DISABLED (no --token/--token-file)%s",
                             loopback ? " — loopback bind only"
                                      : " AND BOUND TO A NON-LOOPBACK ADDRESS: anyone who can "
                                        "reach this port can read/write process memory");
        fprintf(stderr, "pry_umagent: WARNING: AUTH DISABLED (no token)%s\n",
                loopback ? "" : " on a non-loopback bind");
    }

    // bind-retry + listener self-test/rebind, same as the
    // agent — the umagent shares every failure mode from the rig report.
    std::string addr = cfg.bind + ":" + std::to_string(cfg.port);
    for (int generation = 1;; generation++) {
        std::unique_ptr<grpc::Server> server;
        for (int attempt = 1;; attempt++) {
            grpc::ServerBuilder builder;
            // One server-wide auth check (comm/grpc_auth.hpp): every method
            // of every service — including the memory scanner services and
            // ThreadInspect, which never called CheckAuth — needs the bearer
            // token, except /pry.Agent/Identify.
            pry::auth::ServerAuthPolicy policy;
            policy.token = cfg.token;
            policy.exempt_methods = pry::auth::DefaultExemptMethods();
            builder.AddListeningPort(addr,
                                     pry::auth::MakeServerCredentials(std::move(policy)));
            // match the agent + orchestrator client caps —
            // handle tables and module dumps blow past the 4 MB default.
            builder.SetMaxReceiveMessageSize(128 * 1024 * 1024);
            builder.SetMaxSendMessageSize(128 * 1024 * 1024);
            // Same fix as the agent: stock sync-server defaults starve the view
            // after two concurrent blocking calls.
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::NUM_CQS, 4);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 16);
            um::RegisterServices(builder, cfg);
            server = builder.BuildAndStart();
            if (server) {
                break;
            }
            DWORD delay = attempt >= 6 ? 15000 : (DWORD)(500 << (attempt - 1));
            pry::srvlog::Logf("listen on %s failed (attempt %d) — retrying in %lu ms",
                                 addr.c_str(), attempt, (unsigned long)delay);
            fprintf(stderr, "listen on %s failed (attempt %d) — retrying in %lu ms\n",
                    addr.c_str(), attempt, (unsigned long)delay);
            Sleep(delay);
        }
        pry::srvlog::Logf("pry_umagent %s listening on %s (auth %s)%s",
                             cfg.version.c_str(), addr.c_str(),
                             cfg.token.empty() ? "DISABLED" : "token",
                             generation > 1 ? " [rebound]" : "");
        printf("pry_umagent %s listening on %s (auth %s)%s\n", cfg.version.c_str(),
               addr.c_str(), cfg.token.empty() ? "DISABLED" : "token",
               generation > 1 ? " [rebound]" : "");
        fflush(stdout);

        std::atomic<bool> wedged{false};
        grpc::Server* srv = server.get();
        pry::listenwatch::Watch watch((uint16_t)cfg.port, [srv, &wedged] {
            wedged.store(true);
            srv->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
        });

        server->Wait();
        watch.Stop();
        if (wedged.load()) {
            pry::srvlog::Logf("listener wedge confirmed — rebuilding (generation %d)",
                                 generation + 1);
            Sleep(1000);
            continue;
        }
        pry::srvlog::Logf("server Wait() returned unexpectedly — rebuilding listener");
        continue;
    }
}
