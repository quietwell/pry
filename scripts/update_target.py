"""Update pry binaries on the lab target over the agent's gRPC.

agent/umagent: upload the new build next to the live exe as *.new, then the
SelfUpdate RPC spawns a detached on-target swap script — stop the service,
force-kill any process still holding the image (covers SCM-untracked
orphans), quarantine the old exe under prev\\, promote the staged file,
restart, port-check, auto-rollback on failure.

driver: upload the new build as pry_driver.sys.new and verify its sha256
against the local build BEFORE touching the live driver -> driver_unload ->
back the live .sys up to prev\\pry_driver.<ts>.sys -> promote the staged
file -> verify the on-disk sha -> driver_load. If driver_load fails the
backup is restored and reloaded (rollback). If unload fails the driver is
still resident: the verified .sys.new stays staged (exit 2) — NOTHING
promotes it at reboot; reboot the target and re-run this script, which
promotes the staged file before loading (and says so).

Every component's upload is verified (bytes + sha256 vs the local build)
before anything is swapped; a mismatch aborts that component.

  orchestrator/.venv/Scripts/python.exe scripts/update_target.py --component all
  orchestrator/.venv/Scripts/python.exe scripts/update_target.py --component driver
  orchestrator/.venv/Scripts/python.exe scripts/update_target.py --clean
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestrator" / "src"))

import yaml  # noqa: E402
from pry.agent_client import AgentClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
REMOTE_DIR = r"C:\pry"

COMPONENTS = {
    "agent": {
        "service": "PryAgent",
        "exe": REMOTE_DIR + r"\pry_agent.exe",
        "src": "build/agent/Release/pry_agent.exe",
    },
    "umagent": {
        "service": "PryUmagent",
        "exe": REMOTE_DIR + r"\pry_umagent.exe",
        "src": "build/umagent/Release/pry_umagent.exe",
    },
    "driver": {
        "exe": REMOTE_DIR + r"\pry_driver.sys",
        "src": "build/driver/Release/pry_driver.sys",
    },
}

# --clean: everything in C:\pry not in this set is quarantined to prev\<ts>\
KEEP = {
    "pry_agent.exe", "pry_agent.new", "pry_umagent.exe", "pry_umagent.new",
    "pry_driver.sys", "pry_driver.sys.new", "drv_exerciser.exe", "mapper.exe",
    "install_agent_service.ps1", "INSTALL.txt", "Start_PRY.bat",
    "PryTestSigning.cer",
    "watch", "prev", ".pry_trash",
}


def local_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def upload_verified(up: dict, local_sha: str, what: str) -> bool:
    """True when the agent wrote exactly the local build. Prints why not."""
    remote = str(up.get("sha256") or "").lower()
    if not up.get("ok", True) or remote != local_sha.lower():
        print(f"FAIL: upload of {what} not verified: ok={up.get('ok')} "
              f"agent sha={remote[:16] or '<none>'} local sha={local_sha[:16]} "
              f"bytes={up.get('bytes_written')}/{up.get('local_bytes')} "
              f"{up.get('error') or ''}".rstrip())
        return False
    return True


async def remote_sha(c: AgentClient, path: str) -> str:
    """sha256 of a target file, '' when it does not exist / can't be read."""
    try:
        return str((await c.file_hash(path)).get("sha256") or "").lower()
    except Exception:
        return ""


def local_git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, timeout=10).stdout.strip() or "nogit"
    except Exception:
        return "nogit"


async def try_connect(host: str, port: int, token: str, timeout_s: float = 90.0) -> AgentClient:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        c = AgentClient(host, port, token)
        try:
            await asyncio.wait_for(c.connect(), timeout=5)
            st = await c.status()
            if st.get("ok"):
                return c
        except Exception as exc:
            last = exc
            try:
                await c.close()
            except Exception:
                pass
            await asyncio.sleep(2)
    raise RuntimeError(f"{host}:{port} did not come back within {timeout_s}s: {last!r}")


async def wait_down(host: str, port: int, token: str, timeout_s: float = 30.0) -> bool:
    """Poll until the endpoint stops answering. The swap only provably began
    once the service drops — verifying before that races the updater script's
    initial delay and reads the still-running old process."""
    deadline = time.time() + timeout_s
    await asyncio.sleep(2)
    while time.time() < deadline:
        c = AgentClient(host, port, token)
        try:
            await asyncio.wait_for(c.connect(), timeout=3)
            await c.status()
            await c.close()
        except Exception:
            return True
        await asyncio.sleep(1)
    return False


async def swap_service(host: str, port: int, token: str, comp: dict, src: Path,
                       expect_sha: str, verify_port: int, smoke: bool,
                       legacy: bool = False) -> int:
    """agent + umagent share this flow. `port` is the kernel agent (all file
    ops + SelfUpdate go through it); `verify_port` is where the updated
    service itself listens (agent: kernel port, umagent: user port). The
    umagent serves no Files API, so the post-swap hash check stays on the
    kernel view."""
    name = comp["service"]
    exe = comp["exe"]
    staged = exe + ".new"

    c = await try_connect(host, port, token, timeout_s=20)
    local_sha = local_sha256(src)
    try:
        print(f"==> upload {src.name} -> {staged}")
        up = await c.file_upload(str(src), staged)
        print(f"    {up.get('bytes_written')} bytes sha={local_sha[:16]}...")
        # never hand SelfUpdate a staged file that is not the local build
        if not upload_verified(up, local_sha, staged) \
                or await remote_sha(c, staged) != local_sha:
            print(f"FAIL: staged {staged} does not match the local build — "
                  "not swapping")
            await c.run_shell(f'del /q "{staged}" 2>nul', "cmd", "", 10000)
            return 1

        print(f"==> SelfUpdate {name} (connection will drop - expected)")
        if legacy:
            raise RuntimeError("legacy")
        try:
            r = await c.self_update(name, exe, staged, sha256=local_sha,
                                    listen_port=str(verify_port))
            if not r.get("ok"):
                if "predates" in (r.get("error") or ""):
                    raise RuntimeError("legacy")
                print(f"FAIL: SelfUpdate refused: {r.get('error')}")
                return 1
        except RuntimeError as exc:
            if str(exc) != "legacy":
                # channel can die mid-RPC if the updater script wins the race —
                # the verify step below is the source of truth either way
                print(f"    self_update RPC dropped: {exc} (continuing to verify)")
            else:
                raise
        except Exception as exc:
            if "UNIMPLEMENTED" not in str(exc):
                print(f"    self_update RPC dropped: {exc} (continuing to verify)")
            else:
                raise RuntimeError("legacy") from exc
    except RuntimeError as exc:
        if str(exc) != "legacy":
            raise
        # bootstrap path: agent too old for SelfUpdate — move the locked exe
        # aside (rename is allowed on a mapped image), drop the new binary
        # into the freed name, restart with an orphan-kill mop-up
        print("    agent lacks SelfUpdate — legacy move/restart path")
        img = exe.rsplit("\\", 1)[-1]
        await c.run_shell(f'move /y "{exe}" "{exe}.old"', "cmd", "", 15000)
        up = await c.file_upload(str(src), exe)
        if not upload_verified(up, local_sha, exe):
            # put the old binary back; no restart, nothing was swapped
            await c.run_shell(f'move /y "{exe}.old" "{exe}"', "cmd", "", 15000)
            print(f"FAIL: legacy upload of {exe} not verified — restored "
                  "the previous binary, service left running")
            return 1
        # drop the staged .new the SelfUpdate path would have consumed —
        # must run before the restart while the channel is still up
        await c.run_shell(f'del /q "{staged}" 2>nul', "cmd", "", 10000)
        # detached: the chain stops our own service — a synchronous run_shell
        # dies with it (or gets killed by the exec timeout mid-ping, which is
        # how the taskkill/start tail never fired). RunDetached returns before
        # the work starts and survives the agent going down.
        await c.run_detached(
            f'cmd.exe /c "sc.exe stop {name} & ping -n 6 127.0.0.1 >nul & '
            f'taskkill /f /im {img} 2>nul & ping -n 3 127.0.0.1 >nul & '
            f'sc.exe start {name}"', workdir=REMOTE_DIR)
    finally:
        try:
            await c.close()
        except Exception:
            pass

    # the swap only provably began once the service drops — verifying earlier
    # races the updater's initial delay and reads the still-running old build
    if not await wait_down(host, verify_port, token):
        print("    note: drop not observed (fast swap or poll raced it) — "
              "verify below is the source of truth")
    c2 = await try_connect(host, verify_port, token)
    try:
        st = await c2.status()
        ver = st.get("agent_version", "")
        uptime_s = int(st.get("agent_uptime_ms", "0")) // 1000
        print(f"==> back online: version={ver} uptime={uptime_s}s")
        problems = []
        if expect_sha != "nogit" and expect_sha not in ver:
            problems.append(f"version {ver!r} does not contain {expect_sha}")
        if uptime_s > 120:
            problems.append(f"uptime {uptime_s}s — process not freshly restarted")
        # umagent has no Files service — hash via the kernel agent instead
        hc = c2 if verify_port == port else await try_connect(host, port, token, timeout_s=20)
        try:
            h = await hc.file_hash(exe)
        finally:
            if hc is not c2:
                await hc.close()
        if h.get("sha256", "").lower() != local_sha.lower():
            problems.append("on-disk sha != uploaded build")
        if smoke:
            try:
                # mem_processes needs the driver on the kernel view; the agent
                # runs fine without it, so smoke the driver-free Files API
                if verify_port == port:
                    await c2.file_list_dir(REMOTE_DIR)
                else:
                    await c2.mem_processes()
            except Exception as exc:
                problems.append(f"smoke check failed: {exc}")
        if problems:
            for p in problems:
                print(f"FAIL: {p}")
            print(f"    (check {REMOTE_DIR}\\prev\\selfupdate_*.log on target)")
            return 1
        print(f"UPDATE OK: {name} -> {ver}")
        return 0
    finally:
        await c2.close()


_DRIVER_LOADED = ("DRIVER_SERVICE", "DRIVER_MANUAL_MAPPED")


async def _shell_ok(c: AgentClient, cmd: str, what: str) -> bool:
    r = await c.run_shell(cmd, "cmd", "", 15000)
    if r.get("exit_code") != 0:
        print(f"    {what} failed: {((r.get('stderr') or '') + (r.get('stdout') or '')).strip()[:200]}")
        return False
    return True


async def swap_driver(c: AgentClient, src: Path) -> int:
    exe = COMPONENTS["driver"]["exe"]
    staged = exe + ".new"
    local_sha = local_sha256(src)

    # 1. stage + verify BEFORE touching the live driver. A staged file left
    #    by an earlier run whose unload failed is reused when it is this
    #    build, replaced otherwise — either way it is promoted below.
    prev_staged = await remote_sha(c, staged)
    if prev_staged:
        if prev_staged == local_sha:
            print(f"==> found {staged} staged by an earlier run (unload had "
                  "failed) — it matches this build; promoting it before load")
        else:
            print(f"==> found a stale {staged} from an earlier run — "
                  "replacing it with this build")
    if prev_staged != local_sha:
        print(f"==> upload {src.name} -> {staged}")
        up = await c.file_upload(str(src), staged)
        if not upload_verified(up, local_sha, staged):
            await c.run_shell(f'del /q "{staged}" 2>nul', "cmd", "", 10000)
            return 1
        print(f"    {up.get('bytes_written')} bytes sha={local_sha[:16]}... verified")

    # 2. unload the running driver
    st = await c.status()
    if st.get("driver_state") in ("DRIVER_ABSENT", ""):
        print("==> driver not loaded — swapping the .sys then loading")
    else:
        print("==> driver_unload")
        # keep the SCM service entry — driver_load(method="service") needs it
        # to still exist for the reload
        r = await c.driver_unload(delete_service=False)
        if not r.get("ok"):
            print(f"    unload failed: {r.get('error')}")
            print(f"    the verified build stays staged at {staged}; nothing "
                  "promotes it at boot — reboot the target, then re-run this "
                  "script (it promotes the staged file before loading)")
            return 2

    # 3. back up the live .sys, promote the staged one, verify on disk
    ts = int(time.time())
    backup = f"{REMOTE_DIR}\\prev\\pry_driver.{ts}.sys"
    had_live = bool(await remote_sha(c, exe))
    if had_live and not await _shell_ok(
            c, f'if not exist "{REMOTE_DIR}\\prev" mkdir "{REMOTE_DIR}\\prev" & '
               f'move /y "{exe}" "{backup}"', "backup of the live driver"):
        print("FAIL: could not back up the live driver — not swapping")
        return 1
    if not await _shell_ok(c, f'move /y "{staged}" "{exe}"', "promote"):
        if had_live:
            await _shell_ok(c, f'move /y "{backup}" "{exe}"', "restore")
        print("FAIL: could not promote the staged driver")
        return 1
    if await remote_sha(c, exe) != local_sha:
        print(f"FAIL: on-disk {exe} sha != local build after promote")
        return await _rollback_driver(c, exe, backup, had_live)
    print(f"==> promoted {staged} -> {exe}"
          + (f" (previous build kept at {backup})" if had_live else ""))

    # 4. load; roll back to the backup if the new build will not load
    print("==> driver_load (service)")
    r = await c.driver_load(method="service")
    if not r.get("ok"):
        print(f"FAIL: driver_load: {r.get('error')}")
        return await _rollback_driver(c, exe, backup, had_live)
    st = await c.status()
    ds, dv = st.get("driver_state"), st.get("driver_version")
    print(f"==> driver_state={ds} driver_version={dv}")
    if ds not in _DRIVER_LOADED:
        print("FAIL: driver not loaded after swap")
        return await _rollback_driver(c, exe, backup, had_live)
    if st.get("driver_abi_version") and st.get("driver_abi_ok") is False:
        print(f"WARN: driver ABI v{st.get('driver_abi_version')} != agent "
              f"ABI v{st.get('agent_abi_version')} — rebuild/redeploy the "
              "agent too")
    # in-place smoke: the exerciser exercises the same IOCTL surface the
    # orchestrator will use — catches a broken .sys before we call it good
    r = await c.run_shell("drv_exerciser.exe ping", "cmd", REMOTE_DIR, 20000)
    out = (r.get("stdout") or "") + (r.get("stderr") or "")
    if r.get("exit_code") != 0 or "FAIL" in out.upper():
        print(f"FAIL: drv_exerciser ping: {out.strip()[:200]}")
        return 1
    print("UPDATE OK: pry_driver.sys (exerciser ping passed)")
    return 0


async def _rollback_driver(c: AgentClient, exe: str, backup: str,
                           had_live: bool) -> int:
    """Put the previous driver build back and reload it."""
    if not had_live:
        print("    no previous driver build to roll back to")
        return 1
    print(f"==> ROLLBACK: restoring {backup} -> {exe}")
    try:
        await c.driver_unload(delete_service=False)
    except Exception:
        pass
    ts = int(time.time())
    await _shell_ok(c, f'if exist "{exe}" move /y "{exe}" '
                       f'"{REMOTE_DIR}\\prev\\pry_driver.{ts}.failed.sys"',
                    "quarantine of the failed build")
    if not await _shell_ok(c, f'copy /y "{backup}" "{exe}"', "restore"):
        print(f"FAIL: rollback could not restore {backup} — the target has "
              "no driver file; copy it back by hand")
        return 1
    r = await c.driver_load(method="service")
    st = await c.status()
    print(f"    rollback driver_load ok={r.get('ok')} "
          f"driver_state={st.get('driver_state')}")
    return 1


async def sweep(c: AgentClient) -> int:
    entries = await c.file_list_dir(REMOTE_DIR)
    ts = int(time.time())
    dest = f"{REMOTE_DIR}\\prev\\{ts}"
    keep = {k.lower() for k in KEEP}
    moved = []
    for e in entries:
        # DirEntry.name is the FULL path on this agent — keep-check the basename
        base = e["name"].rsplit("\\", 1)[-1]
        if base.lower() in keep:
            continue
        r = await c.run_shell(
            f'if not exist "{dest}" mkdir "{dest}" & '
            f'move /y "{REMOTE_DIR}\\{base}" "{dest}\\"', "cmd", "", 15000)
        if r.get("exit_code") == 0:
            moved.append(base)
        else:
            print(f"    could not move {base}: {(r.get('stderr') or '').strip()}")
    print(f"==> quarantined {len(moved)} files -> {dest}")
    for m in moved:
        print(f"    {m}")
    # prev\ pruning: keep exactly one rollback point — the newest .bak per
    # component — plus EVERY driver backup (pry_driver.<ts>.sys, the
    # only rollback point the driver swap has); delete everything else
    # (updater scripts, logs, older baks, dated quarantine dirs)
    prev_entries = await c.file_list_dir(REMOTE_DIR + r"\prev")
    newest_bak: dict[str, tuple[str, int]] = {}
    for e in prev_entries:
        base = e["name"].rsplit("\\", 1)[-1]
        stem = base.split(".")[0].lower()
        if base.lower().endswith(".bak") and stem in (
                "pry_agent", "pry_umagent", "pry_driver"):
            cur = newest_bak.get(stem)
            if not cur or e["mtime_unix"] > cur[1]:
                newest_bak[stem] = (base, e["mtime_unix"])
    keep_prev = {v[0].lower() for v in newest_bak.values()}
    keep_prev.update(
        e["name"].rsplit("\\", 1)[-1].lower() for e in prev_entries
        if not e.get("dir")
        and re.fullmatch(r"pry_driver\.\d+\.sys",
                         e["name"].rsplit("\\", 1)[-1].lower()))
    pruned = 0
    for e in prev_entries:
        base = e["name"].rsplit("\\", 1)[-1]
        if base.lower() in keep_prev:
            continue
        if e["dir"]:
            cmd = f'rmdir /s /q "{REMOTE_DIR}\\prev\\{base}"'
        else:
            cmd = f'del /q "{REMOTE_DIR}\\prev\\{base}"'
        r = await c.run_shell(cmd, "cmd", "", 15000)
        if r.get("exit_code") == 0:
            pruned += 1
    print(f"==> pruned {pruned} prev\\ artifacts (kept {len(keep_prev)}: newest "
          ".bak per service + every driver backup)")
    return 0


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "configs" / "local.yaml"))
    ap.add_argument("--component", choices=[*COMPONENTS, "all"], default="all")
    ap.add_argument("--src", default="", help="local binary path (single-component runs only)")
    ap.add_argument("--clean", action="store_true", help="quarantine stale files in C:\\pry to prev\\<ts>")
    ap.add_argument("--no-smoke", action="store_true")
    ap.add_argument("--legacy", action="store_true",
                    help="skip SelfUpdate; force the move/upload/restart path "
                         "(bootstrap when the running agent's updater is buggy)")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    host, port, token = cfg["target"]["host"], cfg["target"]["port"], cfg["target"]["token"]
    uport = cfg.get("targets", {}).get("user", {}).get("port", 50075)
    expect_sha = local_git_sha()

    comps = list(COMPONENTS) if args.component == "all" else [args.component]
    if args.src and len(comps) != 1:
        ap.error("--src requires a single --component")

    c = await try_connect(host, port, token, timeout_s=20)
    rc = 0
    try:
        if args.clean:
            rc |= await sweep(c)
        for name in comps:
            comp = COMPONENTS[name]
            src = Path(args.src) if args.src else ROOT / comp["src"]
            if not src.is_file():
                print(f"FAIL: missing build artifact {src} (run scripts\\build.ps1)")
                return 1
            if name == "driver":
                rc |= await swap_driver(c, src)
                continue
            # umagent is bounced through the kernel agent's SelfUpdate; its own
            # gRPC has no Exec/Files surface. agent updates bounce through itself.
            owner_port = port
            verify_port = uport if name == "umagent" else port
            rc |= await swap_service(host, owner_port, token, comp, src,
                                     expect_sha, verify_port, not args.no_smoke,
                                     legacy=args.legacy)
            # agent self-update killed the channel — reconnect if it died
            try:
                if not (await c.status()).get("ok"):
                    raise RuntimeError("stale")
            except Exception:
                try:
                    await c.close()
                except Exception:
                    pass
                c = await try_connect(host, port, token)
    finally:
        try:
            await c.close()
        except Exception:
            pass
    return rc


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
