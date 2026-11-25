"""Host toolchain discovery and the per-process build environment.

Supported in slice 1:

* ``msvc`` — ``cl`` + ``link`` from a Visual Studio / Build Tools
  install, environment from ``vcvarsall.bat`` (``amd64`` for x64,
  ``amd64_x86`` for x86), captured once per process and cached.
* ``clang-cl`` — ``clang-cl`` + ``lld-link`` (``link`` when no
  ``lld-link`` sits beside it). It accepts the same flag profile and
  takes the CRT/SDK headers and libraries from the same vcvars
  environment, so a Visual Studio install is still required.

``mingw-gcc`` is reported when ``gcc`` is on PATH but is not supported.

Discovery only probes the filesystem (standard install roots, the
optional config overrides, PATH). Nothing is executed unless the caller
passes ``allow_exec=True`` — that is, unless host compiles are allowed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ReconError

TOOLCHAINS = ("msvc", "clang-cl")
VCVARS_ARG = {"x64": "amd64", "x86": "amd64_x86"}
ENV_TIMEOUT_S = 120
_UNSAFE_PATH = re.compile(r'["%&|<>^\r\n]')

_ENV_CACHE: dict[tuple[str, str], dict[str, str]] = {}
_ENV_LOCK = threading.Lock()


@dataclass
class Toolchain:
    name: str
    available: bool
    supported: bool = True
    version: str = ""
    install: str = ""
    vcvarsall: str = ""
    compiler: str = ""          # clang-cl path; MSVC's cl comes from PATH
    linker: str = ""            # lld-link path, or "" for MSVC link
    arches: tuple[str, ...] = ()
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name,
                               "available": self.available,
                               "supported": self.supported}
        for k in ("version", "install", "compiler", "linker", "reason"):
            v = getattr(self, k)
            if v:
                out[k] = v
        if self.arches:
            out["arches"] = list(self.arches)
        out.update(self.extra)
        return out


def _program_files() -> list[Path]:
    roots = []
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        v = os.environ.get(var)
        if v and Path(v) not in roots:
            roots.append(Path(v))
    return roots


def _vs_installs(vs_path: str) -> list[Path]:
    """VS install roots holding vcvarsall.bat, newest-looking first."""
    if vs_path:
        p = Path(vs_path)
        return [p] if (p / "VC/Auxiliary/Build/vcvarsall.bat").is_file() \
            else []
    found: list[Path] = []
    for pf in _program_files():
        base = pf / "Microsoft Visual Studio"
        if not base.is_dir():
            continue
        for bat in base.glob("*/*/VC/Auxiliary/Build/vcvarsall.bat"):
            root = bat.parents[3]
            if root not in found:
                found.append(root)

    def key(p: Path) -> tuple[int, str]:
        ver = _msvc_version(p)
        nums = tuple(int(x) for x in re.findall(r"\d+", ver)[:3])
        return (nums[0] * 10**8 + nums[1] * 10**5 + nums[2]
                if len(nums) == 3 else 0, str(p))
    return sorted(found, key=key, reverse=True)


def _vswhere_installs() -> list[Path]:
    exe = None
    for pf in _program_files():
        cand = pf / "Microsoft Visual Studio/Installer/vswhere.exe"
        if cand.is_file():
            exe = cand
            break
    if exe is None:
        return []
    try:
        r = subprocess.run([str(exe), "-products", "*", "-latest",
                            "-property", "installationPath"],
                           capture_output=True, text=True, timeout=30,
                           errors="replace",
                           creationflags=getattr(subprocess,
                                                 "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in r.stdout.splitlines():
        p = Path(line.strip())
        if line.strip() and (p / "VC/Auxiliary/Build/vcvarsall.bat").is_file():
            out.append(p)
    return out


def _msvc_version(install: Path) -> str:
    f = install / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt"
    try:
        return f.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _msvc_arches(install: Path, version: str) -> tuple[str, ...]:
    bin_ = install / "VC/Tools/MSVC" / version / "bin"
    out = []
    if (bin_ / "Hostx64/x64/cl.exe").is_file():
        out.append("x64")
    if (bin_ / "Hostx64/x86/cl.exe").is_file() or \
            (bin_ / "Hostx86/x86/cl.exe").is_file():
        out.append("x86")
    return tuple(out)


def _find_clang(install: Path | None, override: str) -> Path | None:
    cands: list[Path] = []
    if override:
        cands.append(Path(override))
    if install is not None:
        cands += [install / "VC/Tools/Llvm/x64/bin/clang-cl.exe",
                  install / "VC/Tools/Llvm/bin/clang-cl.exe"]
    for pf in _program_files():
        cands.append(pf / "LLVM/bin/clang-cl.exe")
    local = os.environ.get("LOCALAPPDATA")
    if local:                   # a per-user LLVM (no admin rights needed)
        cands.append(Path(local) / "Programs/LLVM/bin/clang-cl.exe")
    on_path = shutil.which("clang-cl")
    if on_path:
        cands.append(Path(on_path))
    for c in cands:
        if c.is_file():
            return c
    return None


def discover(cfg: Any = None, *, allow_exec: bool = False) -> list[Toolchain]:
    """Every toolchain the host offers (available or not)."""
    vs_path = str(getattr(cfg, "vs_path", "") or "")
    clang_override = str(getattr(cfg, "clang_cl", "") or "")
    lld_override = str(getattr(cfg, "lld_link", "") or "")
    installs = _vs_installs(vs_path)
    if not installs and allow_exec and not vs_path:
        installs = _vswhere_installs()
    out: list[Toolchain] = []
    install = installs[0] if installs else None
    if install is not None:
        ver = _msvc_version(install)
        arches = _msvc_arches(install, ver)
        out.append(Toolchain(
            name="msvc", available=bool(arches), version=ver,
            install=str(install),
            vcvarsall=str(install / "VC/Auxiliary/Build/vcvarsall.bat"),
            arches=arches,
            reason="" if arches else "cl.exe missing for x64 and x86"))
    else:
        out.append(Toolchain(
            name="msvc", available=False,
            reason="no Visual Studio / Build Tools install found (install "
                   "the 'Desktop development with C++' workload, or set "
                   "reconstruct.vs_path)"))
    clang = _find_clang(install, clang_override)
    if clang is None:
        out.append(Toolchain(
            name="clang-cl", available=False,
            reason="clang-cl not found (install the Visual Studio 'C++ "
                   "Clang tools for Windows' component or LLVM, or set "
                   "reconstruct.clang_cl)"))
    else:
        lld = Path(lld_override) if lld_override else \
            clang.with_name("lld-link.exe")
        tc = Toolchain(name="clang-cl", available=install is not None,
                       compiler=str(clang),
                       linker=str(lld) if lld.is_file() else "",
                       install=str(install) if install else "",
                       vcvarsall=str(install / "VC/Auxiliary/Build/"
                                     "vcvarsall.bat") if install else "",
                       arches=("x64", "x86") if install else ())
        if install is None:
            tc.reason = ("clang-cl takes the CRT/SDK headers and libraries "
                         "from a Visual Studio install; none was found")
        if allow_exec:
            tc.version = _clang_version(clang)
        out.append(tc)
    gcc = shutil.which("gcc")
    if gcc:
        out.append(Toolchain(name="mingw-gcc", available=True,
                             supported=False, compiler=gcc,
                             reason="detected; not supported in slice 1"))
    return out


def _clang_version(clang: Path) -> str:
    try:
        r = subprocess.run([str(clang), "--version"], capture_output=True,
                           text=True, timeout=30, errors="replace",
                           creationflags=getattr(subprocess,
                                                 "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"clang version (\S+)", r.stdout)
    return m.group(1) if m else ""


def pick(toolchains: list[Toolchain], name: str, arch: str) -> Toolchain:
    valid = [t.name for t in toolchains if t.supported]
    for t in toolchains:
        if t.name != name:
            continue
        if not t.supported:
            raise ReconError("toolchain_unsupported",
                             f"{name}: {t.reason}",
                             hint="toolchain= msvc | clang-cl")
        if not t.available:
            raise ReconError("toolchain_missing", f"{name}: {t.reason}",
                             hint="reconstruct_manage(action='toolchains') "
                                  "lists what this host has")
        if arch not in t.arches:
            raise ReconError("toolchain_missing",
                             f"{name} has no {arch} compiler on this host",
                             hint=f"available arches: {list(t.arches)}")
        return t
    raise ReconError("bad_arg", f"unknown toolchain {name!r}",
                     field="toolchain", closest=[n for n in valid
                                                 if n[:2] == name[:2]],
                     hint="toolchain= msvc | clang-cl")


def vcvars_env(vcvarsall: str, arch: str) -> dict[str, str]:
    """The environment vcvarsall sets for *arch* (cached per process)."""
    if arch not in VCVARS_ARG:
        raise ReconError("bad_arg", f"unknown arch {arch!r}", field="arch")
    if _UNSAFE_PATH.search(vcvarsall) or not Path(vcvarsall).is_file():
        raise ReconError("toolchain_missing",
                         f"vcvarsall.bat not usable: {vcvarsall!r}")
    key = (vcvarsall.lower(), arch)
    with _ENV_LOCK:
        env = _ENV_CACHE.get(key)
        if env is not None:
            return dict(env)
        cmd = (f'cmd.exe /d /s /c ""{vcvarsall}" {VCVARS_ARG[arch]} '
               f'>nul 2>&1 && set"')
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", timeout=ENV_TIMEOUT_S,
                               creationflags=getattr(subprocess,
                                                     "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired as exc:
            raise ReconError("toolchain_failed",
                             "vcvarsall.bat timed out") from exc
        env = {}
        for line in r.stdout.splitlines():
            k, sep, v = line.partition("=")
            if sep and k and not k.startswith("="):
                env[k] = v
        upper = {k.upper() for k in env}
        if r.returncode != 0 or "INCLUDE" not in upper or "LIB" not in upper:
            raise ReconError("toolchain_failed",
                             f"vcvarsall.bat {VCVARS_ARG[arch]} did not set "
                             "INCLUDE/LIB",
                             hint="repair the Visual Studio C++ workload")
        _ENV_CACHE[key] = env
        return dict(env)


def which_in(env: dict[str, str], exe: str) -> str:
    path = next((v for k, v in env.items() if k.upper() == "PATH"), "")
    found = shutil.which(exe, path=path)
    if not found:
        raise ReconError("toolchain_failed",
                         f"{exe} not on the vcvars PATH")
    return found


__all__ = ["TOOLCHAINS", "Toolchain", "discover", "pick", "vcvars_env",
           "which_in"]
