"""Plugin discovery, param validation, and subprocess execution (phase 2).

A plugin is `plugins/<name>/` (the tracked pack) or `scripts_user/<name>/`
(local overlay) with:
  plugin.yaml  name, description, target (kernel|user|any), params schema
  run.py       def run(sdk, params) -> dict   (sync or async)

Execution happens in a subprocess (`python -m pry.plugin_runner`) so
plugins can block or crash without taking the MCP server down; the SDK is
built inside the runner from a view descriptor passed on stdin. Results are
captured as JSON and auto-filed as a finding with evidence.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


class PluginError(RuntimeError):
    pass


class PluginTimeoutError(PluginError):
    """Raised by :func:`run_plugin` when the subprocess outlived its
    deadline. Carries the last 64 KiB of each stream and the id of the
    ledger finding (if the write succeeded) so the submit/poll surface
    can surface them without re-reading the stream."""

    def __init__(self, msg: str, *, partial_stdout: str = "",
                 partial_stderr: str = "", finding_id: str = "",
                 timeout_s: float = 0.0) -> None:
        super().__init__(msg)
        self.partial_stdout = partial_stdout
        self.partial_stderr = partial_stderr
        self.finding_id = finding_id
        self.timeout_s = timeout_s


@dataclass
class PluginMeta:
    name: str
    description: str
    target: str
    path: str
    params: dict[str, Any] = field(default_factory=dict)


def plugin_roots(cfg: Any) -> list[Path]:
    """Plugin directories to scan, highest precedence first.

    `cfg.plugins.dir` when set (CWD-relative) is the only root. Otherwise the
    repo-root `scripts_user` (personal overlay, gitignored) is scanned before
    the tracked `plugins` pack, so a local plugin shadows a shipped one of the
    same name.
    """
    configured = getattr(getattr(cfg, "plugins", None), "dir", "")
    if configured:
        p = Path(configured)
        if p.is_dir():
            return [p]
        raise PluginError(f"plugins dir not found: {p}")
    repo = Path(__file__).resolve().parents[3]
    roots = [repo / d for d in ("scripts_user", "plugins") if (repo / d).is_dir()]
    if not roots:
        raise PluginError("no plugin directory found (expected plugins/ or "
                          "scripts_user/; set plugins.dir in config)")
    return roots


def resolve_plugins_dir(cfg: Any) -> Path:
    """Primary plugin dir: `cfg.plugins.dir` if set, else the tracked
    repo-root `plugins` pack (falling back to `scripts_user`)."""
    roots = plugin_roots(cfg)
    repo = Path(__file__).resolve().parents[3]
    for root in roots:
        if root == repo / "plugins":
            return root
    return roots[0]


_BAD_MANIFESTS: dict[str, str] = {}


def discover(cfg: Any) -> list[PluginMeta]:
    by_name: dict[str, PluginMeta] = {}
    _BAD_MANIFESTS.clear()
    # lowest precedence first so `scripts_user` overrides the shipped pack
    for root in reversed(plugin_roots(cfg)):
        for d in sorted(root.iterdir()):
            if not d.is_dir() or d.name.startswith("_"):
                continue
            try:
                meta = load_meta(d)
            except yaml.YAMLError as exc:
                # one plugin with a malformed manifest previously
                # crashed the whole `script_manage list` — yaml.safe_load
                # raised ScannerError/MarkedYAMLError and the exception
                # propagated to the tool caller. Skip the plugin, record
                # the parse error, and continue so the caller still sees
                # every other valid manifest.
                _BAD_MANIFESTS[d.name] = f"YAML parse error: {exc}"
                continue
            except Exception as exc:
                _BAD_MANIFESTS[d.name] = f"{type(exc).__name__}: {exc}"
                continue
            if meta is not None:
                by_name[meta.name] = meta
    return [by_name[k] for k in sorted(by_name)]


def bad_manifests() -> dict[str, str]:
    """Copy of the last discover() pass's parse-error map — plugin name → err.

    Empty when every manifest loaded cleanly. Useful for surfacing skipped
    plugins in `script_manage list` without breaking the happy path.
    """
    return dict(_BAD_MANIFESTS)


def plugin_dir(cfg: Any, name: str) -> Path:
    if name.startswith("_") or "/" in name or "\\" in name or ".." in name:
        raise PluginError(f"invalid plugin name {name!r}")
    for root in plugin_roots(cfg):
        d = root / name
        if (d / "plugin.yaml").is_file():
            return d
    raise PluginError(f"unknown plugin {name!r} (plugins: "
                      f"{[m.name for m in discover(cfg)]})")


def load_meta(d: Path) -> PluginMeta | None:
    yaml_path = d / "plugin.yaml"
    if not yaml_path.is_file():
        return None
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    return PluginMeta(
        name=str(raw.get("name") or d.name),
        description=str(raw.get("description") or ""),
        target=str(raw.get("target") or "any"),
        path=str(d),
        params=dict(raw.get("params") or {}),
    )


def validate_params(schema: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """Minimal schema subset: type, required, default, enum, description."""
    types = {"str": str, "int": int, "float": (int, float), "bool": bool,
             "list": list, "dict": dict}
    out: dict[str, Any] = {}
    for key, spec in schema.items():
        spec = spec if isinstance(spec, dict) else {"type": spec}
        value = params.get(key)
        if value is None:
            if "default" in spec:
                out[key] = spec["default"]
            elif spec.get("required"):
                raise PluginError(f"missing required param {key!r}")
            continue
        want = types.get(str(spec.get("type", "str")))
        if want and not isinstance(value, want):
            raise PluginError(f"param {key!r} must be {spec.get('type')}, "
                              f"got {type(value).__name__}")
        enum = spec.get("enum")
        if enum and value not in enum:
            raise PluginError(f"param {key!r} must be one of {enum}")
        out[key] = value
    extra = set(params) - set(schema)
    if extra:
        raise PluginError(f"unknown params: {sorted(extra)}")
    return out


def _view_descriptors(session: Any) -> dict[str, dict[str, Any]]:
    views: dict[str, dict[str, Any]] = {}
    for name, client in session.clients.items():
        label = (session.machine_label(name)
                 if hasattr(session, "machine_label") else {})
        views[name] = {
            "host": client.host,
            "port": client.port,
            "token": client.token,
            "timeout_ms": int(client.timeout_ms),
            "machine": label.get("machine") or name,
            "computer_name": label.get("computer_name") or "",
        }
    return views


def _symbols_descriptor(cfg: Any) -> dict[str, Any]:
    sym = getattr(cfg, "symbols", None)
    cache = getattr(cfg.artifacts, "pdb_cache", "artifacts/symbols") if cfg else ""
    if cfg is not None and hasattr(cfg, "pdb_cache_dir"):
        cache = str(cfg.pdb_cache_dir())
    elif cache and not Path(cache).is_absolute():
        cache = str(Path(__file__).resolve().parents[2] / cache)
    return {
        "cache_dir": str(cache),
        "allow_download": bool(getattr(sym, "allow_download", True)),
        "servers": list(getattr(sym, "servers", []) or []),
    }


async def run_plugin(cfg: Any, session: Any, ledger: Any, session_id: str, name: str,
                     params: dict[str, Any], timeout_s: float = 300.0,
                     *, progress_file: str = "",
                     proc_sink: Any = None) -> dict[str, Any]:
    """Run a plugin in a subprocess and return its result envelope.

    ``progress_file`` — optional path the SDK writes
    ``sdk.progress(fraction, note)`` updates into (JSON blob, atomically
    replaced). Picked up by ``script_manage(action='status')``.
    ``proc_sink`` — optional ``callable(proc)`` invoked right after the
    subprocess starts, so the submit/poll surface can hold a handle for
    ``action='cancel'``.
    """
    meta = load_meta(plugin_dir(cfg, name))
    if meta is None:
        raise PluginError(f"plugin {name!r} has no plugin.yaml")
    clean = validate_params(meta.params, params)

    required = meta.target
    if required in ("kernel", "user"):
        # Multi-machine: the requirement is a view KIND present on some
        # connected machine — keys are '<machine>.<kind>' now.
        if not any(session.view_kind_of(k) == required
                   for k in session.clients):
            raise PluginError(f"plugin {name!r} requires the {required!r} view (connect it first)")

    nt_build = 0
    try:
        nt_build = int((await session.require_client("kernel").status()).get("os_build") or 0)
    except Exception:
        pass

    # The result envelope travels through a temp file, not stdout: the
    # stdout/stderr readers keep only a bounded tail (diagnostics), and a
    # result over that tail used to be truncated into invalid JSON.
    fd, result_file = tempfile.mkstemp(prefix="pry_plugin_",
                                       suffix=".json")
    os.close(fd)
    payload = {
        "views": _view_descriptors(session),
        "nt_build": nt_build,
        # (an in-memory ledger has db_path=None — never hand the runner
        # the literal path "None")
        "ledger": (str(ledger.db_path)
                   if getattr(ledger, "db_path", None) else ""),
        "session_id": session_id,
        "symbols": _symbols_descriptor(cfg),
        # Canonical artifact root from the orchestrator config — plugins
        # used to guess Path.cwd()/artifacts, which moved with the launch
        # cwd. Empty string is fine: PrySDK falls back to cwd/artifacts.
        "artifacts_dir": str(cfg.artifacts_dir()) if hasattr(cfg, "artifacts_dir") else "",
        "progress_file": progress_file,
        # params ride stdin only (argv is capped at 32K chars on Windows).
        "params": clean,
    }
    runner_args: list[str] = [
        sys.executable, "-m", "pry.plugin_runner",
        "--plugin-dir", str(Path(meta.path)),
        "--result-file", result_file,
    ]
    if progress_file:
        runner_args.extend(["--progress-file", progress_file])
    try:
        return await _run_plugin_proc(
            runner_args, payload, ledger=ledger, session_id=session_id,
            name=name, timeout_s=timeout_s, proc_sink=proc_sink,
            result_file=result_file)
    finally:
        try:
            os.unlink(result_file)
        except OSError:
            pass


def _win_kill_tree(pid: int, timeout_s: float) -> None:
    """Terminate ``pid`` and all its descendants and WAIT until each one
    has fully exited (process handle signalled = address space torn
    down). ``sys.executable`` in a venv is a launcher, so the plugin's
    interpreter is a grandchild; waiting only for the launcher let the
    real interpreter linger — with the ledger's WAL index still mapped,
    which made the next orchestrator write fail with SQLITE_IOERR."""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    TH32CS_SNAPPROCESS = 0x2
    PROCESS_TERMINATE = 0x0001
    SYNCHRONIZE = 0x00100000

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260)]

    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    invalid = wintypes.HANDLE(-1).value
    children: dict[int, list[int]] = {}
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap and snap != invalid:
        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            ok = k32.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                children.setdefault(int(pe.th32ParentProcessID), []).append(
                    int(pe.th32ProcessID))
                ok = k32.Process32NextW(snap, ctypes.byref(pe))
        finally:
            k32.CloseHandle(snap)
    tree: list[int] = []
    todo = [pid]
    while todo:
        cur = todo.pop()
        if cur in tree or cur == 0:
            continue
        tree.append(cur)
        todo.extend(children.get(cur, ()))
    handles = []
    for p in tree:   # open every handle BEFORE killing anything
        h = k32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, p)
        if h:
            handles.append(h)
    try:
        for h in handles:
            k32.TerminateProcess(h, 1)
        deadline = time.monotonic() + max(0.0, timeout_s)
        for h in handles:
            left = max(0, int((deadline - time.monotonic()) * 1000))
            k32.WaitForSingleObject(h, left)
    finally:
        for h in handles:
            k32.CloseHandle(h)


async def kill_process_tree(proc: Any, *, timeout_s: float = 5.0) -> None:
    """Kill a plugin runner AND everything it spawned.

    ``proc.kill()`` only reaches the direct child; a plugin that started
    its own helpers (or a hung native call in a grandchild) survived
    cancellation. Windows: ``taskkill /T`` while the parent still exists
    (the tree is found through parent pids). POSIX: the runner gets its
    own session at spawn, so its process group is killed. Idempotent."""
    if proc is None or getattr(proc, "returncode", 0) is not None:
        return
    pid = getattr(proc, "pid", None)
    if pid:
        if sys.platform == "win32":
            try:
                await asyncio.to_thread(_win_kill_tree, int(pid), timeout_s)
            except Exception:
                pass
        else:  # pragma: no cover - POSIX path
            try:
                os.killpg(pid, signal.SIGKILL)
            except Exception:
                pass
    try:
        proc.kill()
    except Exception:
        pass
    try:
        await asyncio.wait_for(proc.wait(), timeout_s)
    except Exception:
        pass


async def _file_timeout_finding(ledger: Any, session_id: str, name: str,
                                timeout_s: float, log_text: str) -> str:
    """Best-effort timeout finding + log evidence. Retries briefly: the
    killed runner (its interpreter is a grandchild of the venv launcher
    on Windows) can still hold the ledger's WAL index mapped for a few
    hundred ms after the kill, which surfaces as a transient
    SQLITE_IOERR on our next write."""
    import logging as _logging
    import sqlite3 as _sqlite3
    delay = 0.05
    last: Exception | None = None
    sid = session_id
    for _ in range(8):
        try:
            sid = sid or ledger.start_session("plugins")
            fid = ledger.record(
                sid, "info", f"plugin: {name} (timeout)",
                f"timed out after {timeout_s:.0f}s", refs=f"plugin:{name}")
            ledger.add_evidence(fid, "plugin_timeout_log", log_text)
            return fid
        except _sqlite3.OperationalError as exc:
            last = exc
            await asyncio.sleep(delay)
            delay = min(delay * 2, 0.5)
        except Exception as exc:  # noqa: BLE001 — non-fatal per plan
            last = exc
            break
    _logging.getLogger(__name__).warning(
        "plugin %s: timeout finding not filed: %s", name, last)
    return ""


async def _run_plugin_proc(runner_args: list[str], payload: dict[str, Any],
                           *, ledger: Any, session_id: str, name: str,
                           timeout_s: float, proc_sink: Any,
                           result_file: str) -> dict[str, Any]:
    spawn_kw: dict[str, Any] = {}
    if sys.platform != "win32":  # pragma: no cover - POSIX path
        spawn_kw["start_new_session"] = True
    proc = await asyncio.create_subprocess_exec(
        *runner_args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **spawn_kw,
    )
    if proc_sink is not None:
        try:
            proc_sink(proc)
        except Exception:
            pass
    try:
        return await _drive_plugin_proc(
            proc, payload, ledger=ledger, session_id=session_id, name=name,
            timeout_s=timeout_s, result_file=result_file)
    finally:
        # Cancellation (script_manage cancel, client disconnect, server
        # shutdown) or any error: never leave the runner tree behind.
        if proc.returncode is None:
            await asyncio.shield(kill_process_tree(proc))


async def _drive_plugin_proc(proc: Any, payload: dict[str, Any], *,
                             ledger: Any, session_id: str, name: str,
                             timeout_s: float,
                             result_file: str) -> dict[str, Any]:
    # NOTE: `proc.communicate()` accumulates stdout/stderr in a local
    # list that is lost on wait_for() cancellation, so a timeout path
    # that calls communicate() after the fact gets empty bytes.
    # Instead drive the three streams ourselves: a writer closes stdin,
    # and two readers accumulate into _buf_out/_buf_err even if we have
    # to kill the child mid-stream. The partial stream is then readable
    # from the buffers for the ledger write.
    _buf_out = bytearray()
    _buf_err = bytearray()
    _MAX = 64 * 1024

    async def _drain(stream: Any, buf: bytearray) -> None:
        if stream is None:
            return
        try:
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    return
                buf.extend(chunk)
                # Cap so a verbose plugin can't balloon memory. We keep
                # the TAIL (what tends to be most relevant on timeout).
                over = len(buf) - _MAX
                if over > 0:
                    del buf[:over]
        except Exception:
            # Reader cancellation / pipe closure is expected on kill.
            return

    stdout_task = asyncio.create_task(_drain(proc.stdout, _buf_out))
    stderr_task = asyncio.create_task(_drain(proc.stderr, _buf_err))

    async def _feed_stdin() -> None:
        try:
            if proc.stdin is not None:
                proc.stdin.write(json.dumps(payload).encode())
                try:
                    await proc.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                try:
                    proc.stdin.close()
                except Exception:
                    pass
        except Exception:
            pass

    stdin_task = asyncio.create_task(_feed_stdin())

    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_s)
        # Make sure readers drain any final buffered bytes.
        await asyncio.gather(stdout_task, stderr_task, stdin_task,
                             return_exceptions=True)
        out = bytes(_buf_out)
        err = bytes(_buf_err)
    except asyncio.TimeoutError:
        # Kill the child (and its tree) and salvage whatever the pipes
        # buffered so the ledger (and the submit/poll surface) keep
        # partial evidence. The ledger write MUST stay best-effort —
        # losing it is not a reason to lose the whole stream.
        await kill_process_tree(proc, timeout_s=2.0)
        # Give the readers a moment to collect whatever landed before
        # the pipes closed. gather(..., return_exceptions=True) absorbs
        # any CancelledError they raised when the child died.
        for t in (stdout_task, stderr_task, stdin_task):
            if not t.done():
                try:
                    await asyncio.wait_for(asyncio.shield(t), timeout=1.0)
                except Exception:
                    t.cancel()
        partial_stdout = bytes(_buf_out)[-_MAX:].decode("utf-8", "replace")
        partial_stderr = bytes(_buf_err)[-_MAX:].decode("utf-8", "replace")
        finding_id = ""
        if ledger is not None:
            combined = (
                f"=== stderr (last {len(partial_stderr)} chars) ===\n"
                f"{partial_stderr}\n"
                f"=== stdout (last {len(partial_stdout)} chars) ===\n"
                f"{partial_stdout}\n")
            finding_id = await _file_timeout_finding(
                ledger, session_id, name, timeout_s, combined)
        raise PluginTimeoutError(
            f"plugin {name!r} timed out after {timeout_s:.0f}s",
            partial_stdout=partial_stdout,
            partial_stderr=partial_stderr,
            finding_id=finding_id,
            timeout_s=timeout_s,
        )

    envelope: Any = None
    try:
        raw = Path(result_file).read_bytes()
    except OSError:
        raw = b""
    if raw.strip():
        try:
            envelope = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            envelope = None
    if envelope is None:
        # Runner died before writing the result file (or a pre-result-file
        # runner): the envelope, if any, is the stdout tail.
        try:
            envelope = json.loads(out.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            raise PluginError(f"plugin {name!r} produced no JSON result "
                              f"(exit {proc.returncode}); stderr tail: "
                              f"{err.decode('utf-8', 'replace')[-400:]}")
    if not isinstance(envelope, dict) or not envelope.get("ok"):
        err_s = envelope.get("error") if isinstance(envelope, dict) else envelope
        raise PluginError(f"plugin {name!r} failed: {err_s}")
    return envelope.get("result", {})


def file_result(ledger: Any, session_id: str, name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Auto-file a plugin result as a finding with evidence."""
    severity = str(result.get("severity") or "info")
    summary = str(result.get("summary") or "")
    sid = session_id or ledger.start_session("plugins")
    fid = ledger.record(sid, severity, f"plugin: {name}", summary, refs=f"plugin:{name}")
    eid = ledger.add_evidence(fid, "plugin_result", json.dumps(result, indent=2, default=str))
    return {"finding_id": fid, "evidence_id": eid, "session_id": sid, "severity": severity}


def meta_dict(meta: PluginMeta) -> dict[str, Any]:
    return asdict(meta)
