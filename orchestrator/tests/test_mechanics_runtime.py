"""mechanics-audit 2026-11-24 — plugin runner I/O + process tree, emulator
session serialization / run caps, IDA bridge dispatcher + stderr + manifest.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from pry import plugins


# ---------------------------------------------------------------- plugins --

def _plugin(root: Path, name: str, body: str, params: str = "{}") -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "plugin.yaml").write_text(
        f"name: {name}\ndescription: x\ntarget: any\nparams: {params}\n",
        encoding="utf-8")
    (d / "run.py").write_text(body, encoding="utf-8")


def _cfg(root: Path):
    return SimpleNamespace(plugins=SimpleNamespace(dir=str(root)),
                           artifacts=SimpleNamespace(pdb_cache=""),
                           symbols=None)


class _Sess:
    clients: dict = {}

    def view_kind_of(self, k):
        return ""

    def require_client(self, name):
        raise RuntimeError("no target")


async def test_plugin_result_over_64k_survives(tmp_path):
    _plugin(tmp_path, "big", "def run(sdk, params):\n"
            "    return {'summary': 'big', 'rows': ['x' * 100] * 3000}\n")
    out = await plugins.run_plugin(_cfg(tmp_path), _Sess(), None, "", "big",
                                   {}, timeout_s=60)
    assert len(out["rows"]) == 3000          # ~300 KB: was a JSON error


async def test_plugin_params_ride_stdin_not_argv(tmp_path, monkeypatch):
    _plugin(tmp_path, "echo", "def run(sdk, params):\n"
            "    return {'got': params}\n",
            params="{blob: {type: str}}")
    seen: list[tuple] = []
    real = asyncio.create_subprocess_exec

    async def _spy(*args, **kw):
        seen.append(args)
        return await real(*args, **kw)

    monkeypatch.setattr(plugins.asyncio, "create_subprocess_exec", _spy)
    blob = "p" * 40_000                      # > the 32K Windows argv cap
    out = await plugins.run_plugin(_cfg(tmp_path), _Sess(), None, "",
                                   "echo", {"blob": blob}, timeout_s=60)
    assert out["got"]["blob"] == blob
    argv = [a for call in seen for a in call]
    assert "--params-json" not in argv and blob not in argv


def _alive(pid: int) -> bool:
    import ctypes
    k32 = ctypes.WinDLL("kernel32")
    k32.OpenProcess.restype = ctypes.c_void_p
    h = k32.OpenProcess(0x00100000, False, pid)      # SYNCHRONIZE
    if not h:
        return False
    try:
        return k32.WaitForSingleObject(ctypes.c_void_p(h), 0) != 0
    finally:
        k32.CloseHandle(ctypes.c_void_p(h))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows tree kill")
async def test_plugin_cancel_kills_whole_tree(tmp_path):
    pidfile = tmp_path / "child.pid"
    _plugin(tmp_path, "spawner", (
        "import subprocess, sys, time\n"
        "def run(sdk, params):\n"
        "    p = subprocess.Popen([sys.executable, '-c',"
        " 'import time; time.sleep(120)'])\n"
        f"    open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
        "    time.sleep(120)\n"))
    task = asyncio.create_task(plugins.run_plugin(
        _cfg(tmp_path), _Sess(), None, "", "spawner", {}, timeout_s=300))
    deadline = time.monotonic() + 60
    while not pidfile.exists() and time.monotonic() < deadline:
        await asyncio.sleep(0.1)
    assert pidfile.exists(), "plugin never started its helper"
    gpid = int(pidfile.read_text())
    assert _alive(gpid)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not _alive(gpid), "grandchild survived plugin cancellation"


# --------------------------------------------------------------- emulate --

def _unicorn_or_skip():
    pytest.importorskip("unicorn")
    from pry import emulate
    return emulate


async def test_emulator_close_waits_for_inflight_op_and_reap_skips_busy():
    emu = _unicorn_or_skip()
    s = emu.create_session(arch="x64", engine="unicorn")
    order: list[str] = []

    async def _hold():
        async with s.lock:
            order.append("op-start")
            await asyncio.sleep(0.3)
            order.append("op-end")

    t = asyncio.create_task(_hold())
    await asyncio.sleep(0.05)
    s.last_ts -= 10_000                        # idle by the clock...
    assert emu.reap_idle(ttl_s=1) == 0          # ...but busy: not reaped
    closed = await emu.close_session_locked(s.id)
    order.append("closed")
    await t
    assert closed is True and s.closed
    assert order == ["op-start", "op-end", "closed"]
    assert await emu.close_session_locked(s.id) is False


def test_unicorn_run_without_limits_gets_default_cap(monkeypatch):
    emu = _unicorn_or_skip()
    monkeypatch.setattr(emu._UnicornEngine, "DEFAULT_RUN_TIMEOUT_S", 0.3)
    s = emu.create_session(arch="x64", engine="unicorn")
    try:
        s.engine.load_shellcode(bytes.fromhex("ebfe"), 0)   # jmp $
        t0 = time.monotonic()
        r = s.engine.run()
        assert time.monotonic() - t0 < 5
        assert r["limits_defaulted"] == {"timeout_s": 0.3}
    finally:
        emu.close_session(s.id)


# ---------------------------------------------------------- IDA bridge ----

_STDERR_FLOOD = r"""
import sys
sys.stderr.write("A" * 300000 + "\nLAST_LINE_MARKER\n")
sys.stderr.flush()
sys.exit(3)
"""


def _bridge(tmp_path: Path, script: str):
    from pry.ida_bridge import IdaBridge, IdaConfigLite
    fake = tmp_path / "fake_shim.py"
    fake.write_text(script, encoding="utf-8")
    b = IdaBridge(IdaConfigLite(command=[sys.executable, str(fake)]),
                  tmp_path / "artifacts")
    b._manifest_path = tmp_path / "ida_sessions.json"
    return b


async def test_bridge_stderr_tail_is_real_tail_and_never_blocks(tmp_path):
    from pry.ida_bridge import IdaBridgeError
    b = _bridge(tmp_path, _STDERR_FLOOD)
    t0 = time.monotonic()
    with pytest.raises(IdaBridgeError) as info:
        await b.ensure_started()
    # undrained, 300 KB of stderr blocked the shim until the 30 s
    # initialize timeout, and the "tail" was the first 2000 bytes
    assert time.monotonic() - t0 < 20
    assert "LAST_LINE_MARKER" in str(info.value)
    await b.stop()


async def test_bridge_revives_dead_dispatcher_and_records_auto_flag(tmp_path):
    import test_ida_bridge as tib
    # empty idb_list: a real open (the stock fake pre-adopts "victim",
    # which never records an input path / manifest row)
    script = tib.FAKE_SERVER.replace(
        'text = json.dumps([{"session_id": "sid_victim", '
        '"preferred_session_id": "victim"}])', "text = json.dumps([])")
    assert script != tib.FAKE_SERVER
    b = _bridge(tmp_path, script)
    binary = tmp_path / "victim.exe"
    binary.write_bytes(b"MZ\x90\x00fake")
    try:
        env = await b.open_database(binary, "victim",
                                    run_auto_analysis=False)
        assert env["status"] == "ready"
        manifest = json.loads(b._manifest_path.read_text(encoding="utf-8"))
        assert manifest["sessions"]["victim"]["run_auto_analysis"] is False
        # Kill the dispatcher while the shim lives: calls must not wedge.
        b._dispatcher_task.cancel()
        await asyncio.sleep(0.05)
        out = await asyncio.wait_for(
            b.ida_manage("decompile", "victim", {"address": "0x1400"}), 10)
        assert "decompiled database=sid_victim" in out
    finally:
        await b.stop()
