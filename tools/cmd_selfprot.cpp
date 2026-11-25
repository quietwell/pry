// SI adoption feature #21 — drv_exerciser recipes for the SelfProt IOCTLs.
// See an internal plan feature
// 21 Test plan: install, non-trusted OpenProcess(PROCESS_TERMINATE) must
// fail, STATUS counters reflect the strip, teardown succeeds against a
// matching DisableToken.

#include "exerciser_common.hpp"

using namespace pry;

int CmdSelfProtStatus()
{
    PRY_SELFPROT_STATUS_OUT out{};
    if (!g_drv.SelfProtStatus(&out)) {
        printf("FAIL selfprot-status: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS selfprot-status installed=%u alt=%u pids=%u flags=0x%x "
           "proc=0x%x thread=0x%x hits=%llu stripped=%llu bypassed=%llu "
           "state=0x%x\n",
           out.Installed, out.Altitude, out.ProtectedPids, out.Flags,
           out.ProcessAccessKeep, out.ThreadAccessKeep,
           (unsigned long long)out.PreOpHits,
           (unsigned long long)out.Stripped,
           (unsigned long long)out.Bypassed,
           out.State);
    return 0;
}

int CmdSelfProtSet(UINT32 enable, UINT32 flags, const std::vector<UINT32>& pids,
                   UINT32 procKeep, UINT32 threadKeep, UINT64 token)
{
    PRY_SELFPROT_CONFIG_IN in{};
    in.Enable = enable;
    in.Flags = flags;
    in.ProcessAccessKeep = procKeep;
    in.ThreadAccessKeep = threadKeep;
    in.DisableToken = token;
    UINT32 n = 0;
    for (UINT32 pid : pids) {
        if (!pid) continue;
        if (n >= PRY_SELFPROT_MAX_PIDS) break;
        in.ProtectedPids[n++] = pid;
    }
    in.PidCount = n;
    PRY_SELFPROT_CONFIG_OUT out{};
    bool ok = g_drv.SelfProtConfig(in, &out);
    if (!ok) {
        printf("FAIL selfprot-set enable=%u st=0x%x: %s\n",
               enable, out.Status, g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS selfprot-set enable=%u flags=0x%x pids=%u installed=%u "
           "alt=%u disable_token=0x%llx state=0x%x\n",
           enable, flags, out.ProtectedPids, out.Installed, out.Altitude,
           (unsigned long long)out.DisableToken, out.State);
    return 0;
}

// Smoke: install -> OpenProcess from this process (self-open, allowed) ->
// disable with the echoed token. Doesn't require a second process; the
// slice doc §Test plan smoke uses a separate non-trusted shell for the
// deny half. This recipe is the "does the install round-trip at all"
// baseline.
int CmdSelfProtSmoke()
{
    UINT32 self = GetCurrentProcessId();
    std::vector<UINT32> pids{self};
    printf("smoke: install enable=1 flags=INCLUDE_THREADS protect=[%u]\n", self);
    if (CmdSelfProtSet(1, 0x1 /*INCLUDE_THREADS*/, pids, 0, 0, 0)) return 1;
    CmdSelfProtStatus();

    PRY_SELFPROT_STATUS_OUT st{};
    if (!g_drv.SelfProtStatus(&st)) {
        printf("FAIL selfprot smoke: status readback failed: %s\n",
               g_drv.LastError().c_str());
        return 1;
    }
    if (!st.Installed) {
        printf("FAIL selfprot smoke: install did not stick\n");
        return 1;
    }

    // Self-open — always allowed by the pre-op. Just exercises the hook.
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, self);
    if (!h) {
        printf("FAIL selfprot smoke: self-open failed gle=%lu "
               "(pre-op must allow self-open)\n", GetLastError());
        // fall through to the teardown so we don't leak the callback
    } else {
        CloseHandle(h);
    }

    // Capture the first-install token for the OFF below.
    PRY_SELFPROT_CONFIG_IN probe{};
    probe.Enable = 1; // refresh via re-install reuses the token already set
    probe.Flags = 0x1;
    probe.PidCount = 1;
    probe.ProtectedPids[0] = self;
    PRY_SELFPROT_CONFIG_OUT probeOut{};
    g_drv.SelfProtConfig(probe, &probeOut);
    UINT64 token = probeOut.DisableToken;

    printf("smoke: disable with DISABLE_TOKEN_OK token=0x%llx\n",
           (unsigned long long)token);
    if (CmdSelfProtSet(0 /*OFF*/, 0x2 /*DISABLE_TOKEN_OK*/, {}, 0, 0, token)) {
        return 1;
    }
    CmdSelfProtStatus();
    return 0;
}
