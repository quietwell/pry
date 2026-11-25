#include "src/breadcrumb.hpp"
#include "src/config.hpp"
#include "src/driver_mgr.hpp"
#include "src/exec.hpp"
#include "src/grpc/services.hpp"
#include "src/host/net_pin.hpp"
#include "src/host/screen_common.hpp"
#include "src/listen_watch.hpp"
#include "src/log_ring.hpp"
#include "src/phone_home.hpp"
#include "src/service/service_main.hpp"
#include "src/srv_log.hpp"
#include "src/common.h"

#include "pry_comm.h"
#include "grpc_auth.hpp"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace pry;

// v5 breadcrumb hooks — one line of arg summary per IOCTL, cheap to
// compute. Anything more detailed is left to per-service logging.
static uint64_t BreadcrumbPre(unsigned long ioctl, const void* in, unsigned long inSize)
{
    char buf[96];
    _snprintf_s(buf, _TRUNCATE, "ioctl=0x%lx inSize=%lu", (unsigned long)ioctl,
                (unsigned long)inSize);
    return Breadcrumb::OnPre((uint32_t)ioctl, buf);
}
static void BreadcrumbPost(uint64_t token, bool ok, unsigned long gle)
{
    Breadcrumb::OnPost(token, ok ? "ok" : "error", (uint32_t)gle);
}

static void Usage()
{
    fprintf(stderr,
            "pry_agent %s\n"
            "usage: pry_agent.exe --port 50074 (--token-file <path> | --token <secret>) [--dev]\n"
            "  [--driver <path>] [--mapper <path>] [--no-driver-ops] [--allow-delete]\n"
            "  [--log <path>] [--log-max-mb <n>]\n"
            "  [--pin-adapter <friendly>] [--pin-address <ipv4>] [--pin-prefix <len>]\n"
            "  [--pin-gateway <ipv4>] [--pin-debounce-ms <n>] [--pin-at-boot-only]\n"
            "  [--pin-hold-marker <path>]\n"
            "service mode: sc create PryAgent binPath= \"...\\pry_agent.exe --port 50074 --token-file C:\\pry\\agent.token\"\n"
            "  (--token-file keeps the secret out of the world-readable binPath; --token still works)\n"
            "NEVER wrap in `cmd /c` — stdio pipes nobody drains wedge the accept path.\n",
            PRY_AGENT_VERSION);
}

static int AgentMain(int argc, char** argv)
{
    AgentConfig cfg = AgentConfig::FromArgs(argc, argv);
    if (cfg.token.empty()) {
        // The agent never runs unauthenticated (unlike the umagent's dev
        // mode). A --token-file that cannot be read is a hard stop — we
        // must not silently fall back to a stale --token or to no auth.
        if (!cfg.tokenError.empty()) {
            fprintf(stderr, "pry_agent: --token-file: %s\n", cfg.tokenError.c_str());
            srvlog::Open(cfg.logPath, cfg.logMaxBytes);
            srvlog::Logf("refusing to start: --token-file: %s", cfg.tokenError.c_str());
            srvlog::Close();
        }
        Usage();
        return 2;
    }

    // T1.1d — phone-home URL. CLI wins; env is the fallback. Both empty
    // means file-only mode (still spawns the thread, but no HTTP POST).
    // Kept out of AgentConfig for now because the knob is opt-in field
    // infra, not a core daemon setting.
    std::string orchestrator_url;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--orchestrator-url") == 0 && i + 1 < argc) {
            orchestrator_url = argv[++i];
            break;
        }
    }
    if (orchestrator_url.empty()) {
        char env[512]{};
        DWORD n = GetEnvironmentVariableA("PRY_ORCHESTRATOR_URL", env,
                                          (DWORD)sizeof(env));
        if (n > 0 && n < sizeof(env)) {
            orchestrator_url.assign(env, n);
        }
    }

    // rotating log + stdio safety BEFORE anything prints.
    // In service/task context (no --dev) stdout/stderr can be pipes nobody
    // drains; a full pipe blocks the writer — a gRPC event-engine thread
    // in that state is exactly the rig's "process up, port dead" wedge.
    // gRPC's own diagnostics (gpr_log) route into the same file.
    srvlog::Open(cfg.logPath, cfg.logMaxBytes);
    if (!cfg.devConsole) {
        if (srvlog::Enabled()) {
            srvlog::CaptureStderr(); // stdout→NUL, stderr→rotating log
        } else {
            srvlog::RedirectStdioToNul();
        }
    }
    srvlog::Logf("pry_agent %s starting (pid %lu, port %d, auth token from %s, log %s)",
                 PRY_AGENT_VERSION, (unsigned long)GetCurrentProcessId(), cfg.port,
                 cfg.tokenFile.empty() ? "--token (visible in the service binPath; prefer "
                                         "--token-file)"
                                       : "--token-file",
                 cfg.logPath.empty() ? "(off)" : "on");

    // Init breadcrumb before we touch the driver so the first ping shows
    // up in the ring. Failure to init just means no persistent ring —
    // agent still works.
    if (!Breadcrumb::Init()) {
        srvlog::Logf("breadcrumb: init failed (persistent forensics disabled)");
        fprintf(stderr, "breadcrumb: init failed (persistent forensics disabled)\n");
    } else {
        Driver::SetTraceHooks(BreadcrumbPre, BreadcrumbPost);
    }

    // v7: kernel-log rotation policy. Best-effort rotate at startup if the
    // on-disk log already blew past the cap during the previous lifetime;
    // subsequent rotations happen opportunistically before Files.LogTail
    // reads large windows. Path matches DriverEntry's log target.
    LogRing::Configure(L"C:\\Users\\Public\\Desktop\\pry_kernel.log", 0);
    std::string rot_err;
    LogRing::TryRotate(&rot_err);
    if (!rot_err.empty()) {
        srvlog::Logf("log_ring: %s", rot_err.c_str());
    }

    DriverMgr drvMgr(cfg);
    ExecMgr exec;

    // static-IPv4 pin (no-op unless --pin-adapter set).
    // Started before the listener so the adapter carries its pinned
    // address before the first client reconnect attempt.
    host::NetPinMgr netPin(cfg);
    netPin.Start();

    std::string addr = "0.0.0.0:" + std::to_string(cfg.port);

    // ABI gate: enforced, not just logged.
    // comm refuses every non-PING IOCTL while the driver's ABI differs, and
    // the server-wide hook below answers driver-only RPCs with
    // FAILED_PRECONDITION. Re-evaluated after every DriverLoad and every
    // handle reopen (comm re-probes with one PING).
    Driver::RequireAbi(PRY_ABI_VERSION);
    auto gate = RunDriverGate(drvMgr);
    if (!gate.empty()) {
        srvlog::Logf("driver gate: %s", gate.c_str());
        printf("driver gate: %s\n", gate.c_str());
        if (drvMgr.Comm().DriverAbi() != 0) {
            srvlog::Logf("driver gate: ABI MISMATCH - driver-backed RPCs answer "
                         "FAILED_PRECONDITION until a matching driver is loaded");
        }
    } else {
        PingInfo p{};
        drvMgr.Comm().Ping(&p);
        srvlog::Logf("driver: v%u.%u build %u flags=%x", p.VersionMajor, p.VersionMinor,
                     p.NtBuild, p.Flags);
        printf("driver: v%u.%u build %u flags=%x\n", p.VersionMajor, p.VersionMinor, p.NtBuild,
               p.Flags);
    }

    // generation loop. BuildAndStart failures (stale
    // instance still holding the port, transient WSAEADDRINUSE during NIC
    // churn) retry with backoff instead of exiting; the listenwatch probe
    // tears down and rebuilds a wedged listener (process up, port dead).
    // A wedge that comes back within 10 minutes of the previous one means
    // in-process rebind is not recovering it — exit(1) so SCM failure
    // recovery takes over with a fresh process.
    std::atomic<bool> stop_requested{false};
    int wedge_streak = 0;
    uint64_t last_wedge_ms = 0;
    for (int generation = 1;; generation++) {
        std::unique_ptr<grpc::Server> server;
        for (int attempt = 1;; attempt++) {
            grpc::ServerBuilder builder;
            // One server-wide auth check (comm/grpc_auth.hpp): every method
            // of every service needs "authorization: Bearer <token>" except
            // /pry.Agent/Identify; the ABI gate rides the same hook.
            auth::ServerAuthPolicy policy;
            policy.token = cfg.token;
            policy.exempt_methods = auth::DefaultExemptMethods();
            policy.gate = [&drvMgr](std::string_view method) {
                return DriverAbiGate(drvMgr, method);
            };
            builder.AddListeningPort(addr, auth::MakeServerCredentials(std::move(policy)));
            // lift message size caps to match the orchestrator
            // client (gRPC's 4 MB default silently closes streams for
            // large handle tables, full module dumps and process_snapshot
            // round-trips).
            builder.SetMaxReceiveMessageSize(128 * 1024 * 1024);
            builder.SetMaxSendMessageSize(128 * 1024 * 1024);
            // v14: the sync-server defaults (1 CQ / 2 pollers) meant TWO blocked
            // handlers — a hung RunExe plus a long-poll ConsoleRead, or one
            // LogFollow stream — starved EVERY other RPC on the box. Lift the
            // poller budget so a wedged exec call can't take the agent's whole
            // gRPC surface down with it.
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::NUM_CQS, 4);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 16);
            RegisterServices(builder, cfg, drvMgr, exec, netPin);
            server = builder.BuildAndStart();
            if (server) {
                break;
            }
            // 0.5s, 1s, 2s, 4s, 8s, then 15s steady-state. The usual cause is
            // a stale instance still bound to the port (e.g. started before a
            // NIC flap removed its address) — it dies on its own or via SCM
            // recovery, and then we take the port over.
            DWORD delay = attempt >= 6 ? 15000 : (DWORD)(500 << (attempt - 1));
            srvlog::Logf("listen on %s failed (attempt %d) — retrying in %lu ms",
                         addr.c_str(), attempt, (unsigned long)delay);
            fprintf(stderr, "listen on %s failed (attempt %d) — retrying in %lu ms\n",
                    addr.c_str(), attempt, (unsigned long)delay);
            Sleep(delay);
        }
        srvlog::Logf("pry_agent %s listening on %s (auth token)%s",
                     PRY_AGENT_VERSION, addr.c_str(),
                     generation > 1 ? " [rebound]" : "");
        printf("pry_agent %s listening on %s (auth %s)%s\n", PRY_AGENT_VERSION,
               addr.c_str(), cfg.token.empty() ? "DISABLED" : "token",
               generation > 1 ? " [rebound]" : "");

        // T1.1d — spawn the phone-home thread once per process lifetime.
        // The listener rebind loop reruns on wedge recovery but the thread
        // is detached and runs forever, so a `static` latch keeps us from
        // leaking one thread per generation.
        static bool phone_home_started = false;
        if (!phone_home_started) {
            phone_home_started = true;
            // Resolve computer_name — the Status RPC fills HostInfo via
            // GetComputerNameExW; here we only need the short NetBIOS name,
            // which GetComputerNameW returns directly without the host_info
            // probe cost.
            wchar_t cn_w[MAX_COMPUTERNAME_LENGTH + 1]{};
            DWORD cn_len = (DWORD)(sizeof(cn_w) / sizeof(cn_w[0]));
            std::string computer_name;
            if (GetComputerNameW(cn_w, &cn_len) && cn_len > 0) {
                int n = WideCharToMultiByte(CP_UTF8, 0, cn_w, (int)cn_len,
                                            nullptr, 0, nullptr, nullptr);
                if (n > 0) {
                    computer_name.resize((size_t)n);
                    WideCharToMultiByte(CP_UTF8, 0, cn_w, (int)cn_len,
                                        computer_name.data(), n, nullptr, nullptr);
                }
            }
            // The agent has no first-class "machine_label" of its own: the
            // orchestrator-side alias is set operator-side, so we send the
            // computer_name as the label too and let the dashboard route
            // (api.py :: /api/agent_report) fall back on it when
            // machine_label is empty.
            StartPhoneHomeThread(
                orchestrator_url,
                computer_name,
                computer_name,  // machine_label — see comment above
                (uint16_t)cfg.port,
                pry::BootEpochMs(),
                pry::AgentInstanceId());
        }

        // Self-test the listener: after 3 dead loopback probes, shutdown
        // with a deadline and let the loop rebuild (fresh socket, dead
        // client connections reaped).
        std::atomic<bool> wedged{false};
        grpc::Server* srv = server.get();
        listenwatch::Watch watch((uint16_t)cfg.port, [srv, &wedged] {
            wedged.store(true);
            srv->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
        });
        // SCM STOP (service mode): unwind Wait() and exit the loop cleanly.
        SetServiceStopHook([srv, &stop_requested] {
            stop_requested.store(true);
            srv->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(3));
        });

        server->Wait();

        SetServiceStopHook(nullptr);
        watch.Stop();
        if (stop_requested.load()) {
            srvlog::Logf("stop requested — shutting down");
            break;
        }
        // Wedged listener or an unrequested Wait() return: same class of
        // failure. Rebuild once; if it recurs within 10 minutes, exit so
        // SCM failure recovery takes over with a fresh process.
        uint64_t now = GetTickCount64();
        const char* why = wedged.load() ? "listener wedge confirmed"
                                        : "server Wait() returned unexpectedly";
        if (last_wedge_ms != 0 && now - last_wedge_ms < 10 * 60000ull) {
            wedge_streak++;
        } else {
            wedge_streak = 1;
        }
        last_wedge_ms = now;
        if (wedge_streak >= 2) {
            srvlog::Logf("%s; %dx within 10 min — exiting for SCM restart", why,
                         wedge_streak);
            break;
        }
        srvlog::Logf("%s — rebuilding (generation %d)", why, generation + 1);
        Sleep(1000);
        continue;
    }

    netPin.Stop();
    DbgSession::Instance().Shutdown();
    // Force one final flush so an SCM-clean stop preserves the last
    // ops for the next Init() to inspect.
    Breadcrumb::FlushSync();
    srvlog::Logf(wedge_streak >= 2 ? "pry_agent exiting after repeated listener wedge"
                                   : "pry_agent stopped cleanly");
    srvlog::Close();
    return wedge_streak >= 2 ? 1 : 0;
}

int main(int argc, char** argv)
{
    // v15: --screenshot children are re-launches of this exe inside the user
    // session (CreateProcessAsUserW from the Session-0 service). They must run
    // as a plain process — never through the SCM dispatcher.
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--screenshot")) {
            return pry::screen::RunScreenWorkerCli(argc, argv);
        }
    }
    bool console = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dev")) {
            console = true;
        }
    }
    return RunAsServiceOrConsole(console, "PryAgent", AgentMain, argc, argv);
}
