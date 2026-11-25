"""Build C source into a reconstruction DLL (never loaded natively).

Profile (pinned in Phase 0, see the slice-1 plan):

* compile — C only (``/TC``), ``/GS-``, ``/Gy``, ``/MD``, ``/W3``, the
  optimization level from an allowlist (``Od O1 O2``), ``/fp:`` from an
  allowlist, ``/Oi`` unless ``intrinsics=false``, ``/D`` defines that
  pass a strict regex, and on x86 an optional ``/arch:IA32|SSE|SSE2``.
  clang-cl gets the same flags plus ``--target``.
* link — ``/DLL /NOENTRY /DYNAMICBASE:NO /BASE:<fixed>`` with one
  ``/EXPORT:`` per requested export and the CRT import libraries listed
  explicitly (under ``/NOENTRY`` no CRT object pulls them in): with
  ``/MD`` the reconstruction's CRT calls become imports, so both sides
  reach the same semantic stubs.

The **source guard** runs before any tool does. After line splices and
comments are removed it allows only angle-bracket includes of plain
relative header names plus ``"pry_recon.h"``, an allowlist of
preprocessor directives and pragmas, and no ``_Pragma`` / ``__pragma``
operators or trigraphs. That keeps prompt-injected source from reading
host files into diagnostics (``#include "C:/…"``, ``#embed``) or passing
linker options (``#pragma comment(linker, …)``).

Build outputs land in ``artifacts/reconstruct/builds/<build_id>/``; the
id is content-addressed over source, header, flags, exports, toolchain
and arch, so an identical request is a cache hit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analysis import pe
from .errors import ReconError, bad_arg
from .toolchain import Toolchain, vcvars_env, which_in

PROFILE_VERSION = "1"
MAX_SOURCE_BYTES = 512 * 1024
MAX_DLL_BYTES = 16 << 20
MAX_LOG_BYTES = 64 * 1024
OPT_LEVELS = ("Od", "O1", "O2")
FP_MODELS = ("precise", "strict", "fast")
X86_ARCH = ("", "IA32", "SSE", "SSE2")
BASES = {"x64": 0x180000000, "x86": 0x10000000}
HEADER_NAME = "pry_recon.h"
HEADER_PATH = Path(__file__).with_name("include") / HEADER_NAME
CRT_LIBS = ("msvcrt.lib", "vcruntime.lib", "ucrt.lib", "kernel32.lib")

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_DEFINE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}(=[A-Za-z0-9_.+\-]{0,64})?\Z")
_HEADER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./\-]{0,127}\.h\Z")
_DIRECTIVES = frozenset({
    "include", "define", "undef", "if", "ifdef", "ifndef", "elif",
    "elifdef", "elifndef", "else", "endif", "error", "warning", "line",
    "pragma"})
_PRAGMAS = frozenset({
    "once", "pack", "warning", "intrinsic", "function", "optimize",
    "inline_depth", "inline_recursion", "loop", "float_control",
    "fenv_access", "fp_contract", "region", "endregion", "message",
    "push_macro", "pop_macro", "STDC", "clang", "GCC"})
_DIAG = re.compile(
    r"^(?P<file>[^\s(][^(]*?)\((?P<line>\d+)(?:,(?P<col>\d+))?\)\s*:\s*"
    r"(?P<sev>fatal error|error|warning|note)\s*(?P<code>[A-Z]+\d+)?\s*:?\s*"
    r"(?P<msg>.*)$")
_LINKDIAG = re.compile(
    r"^(?P<file>[^:]+?)\s*:\s*(?P<sev>fatal error|error|warning)\s+"
    r"(?P<code>LNK\d+)\s*:\s*(?P<msg>.*)$")


@dataclass
class BuildRequest:
    source: str
    exports: list[str]
    arch: str = "x64"
    toolchain: str = "msvc"
    opt: str = "O2"
    fp: str = "precise"
    intrinsics: bool = True
    defines: list[str] = field(default_factory=list)
    x86_arch: str = ""


# ---------------------------------------------------------------------------
# Source guard
# ---------------------------------------------------------------------------

def _strip_comments(src: str) -> str:
    """Remove comments, keeping string/char literals and line breaks."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            seg = src[i:n if j < 0 else j + 2]
            out.append(" " + "\n" * seg.count("\n"))
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check_source(src: str) -> None:
    """Raise ``source_rejected`` for anything outside the allowlist."""
    if len(src.encode("utf-8", "replace")) > MAX_SOURCE_BYTES:
        raise ReconError("source_rejected",
                         f"source exceeds {MAX_SOURCE_BYTES} bytes")
    if "\0" in src:
        raise ReconError("source_rejected", "source contains a NUL byte")
    if re.search(r"\?\?[=/'()!<>\-]", src):
        raise ReconError("source_rejected", "trigraphs are not allowed",
                         hint="spell the characters out")
    text = _strip_comments(re.sub(r"\\\r?\n", "", src))
    op = re.search(r"\b(_Pragma|__pragma)\b", text)
    if op:
        raise ReconError("source_rejected",
                         f"the {op.group(1)} operator is not allowed",
                         hint="use a #pragma line from the allowlist")
    for no, line in enumerate(text.splitlines(), 1):
        s = line.lstrip()
        if s.startswith("%:"):
            raise ReconError("source_rejected",
                             f"line {no}: digraph directives are not "
                             "allowed")
        if not s.startswith("#"):
            continue
        body = s[1:].lstrip()
        m = re.match(r"([A-Za-z_]+)", body)
        if not m:
            if body.strip():
                raise ReconError("source_rejected",
                                 f"line {no}: unknown directive")
            continue
        name = m.group(1)
        rest = body[m.end():].strip()
        if name not in _DIRECTIVES:
            raise ReconError("source_rejected",
                             f"line {no}: #{name} is not allowed",
                             hint="allowed: " + ", ".join(sorted(_DIRECTIVES)))
        if name == "include":
            _check_include(rest, no)
        elif name == "pragma":
            pm = re.match(r"([A-Za-z_]+)", rest)
            if not pm or pm.group(1) not in _PRAGMAS:
                raise ReconError(
                    "source_rejected",
                    f"line {no}: #pragma {pm.group(1) if pm else rest!r} "
                    "is not allowed",
                    hint="allowed pragmas: " + ", ".join(sorted(_PRAGMAS)))


def _check_include(rest: str, no: int) -> None:
    if rest == f'"{HEADER_NAME}"':
        return
    m = re.fullmatch(r"<([^<>]*)>", rest)
    if not m:
        raise ReconError("source_rejected",
                         f"line {no}: only #include <header.h> and "
                         f'#include "{HEADER_NAME}" are allowed',
                         hint="a reconstruction is one C file; inline "
                              "your helpers")
    name = m.group(1).strip()
    if ".." in name or not _HEADER.match(name):
        raise ReconError("source_rejected",
                         f"line {no}: include <{name}> is not a plain "
                         "relative header name")


# ---------------------------------------------------------------------------
# Command lines
# ---------------------------------------------------------------------------

def validate(req: BuildRequest) -> None:
    if req.arch not in BASES:
        raise bad_arg(f"arch: unknown arch {req.arch!r}", field="arch",
                      given=req.arch, valid=tuple(BASES))
    if not req.exports:
        raise bad_arg("exports: name at least one function to export",
                      field="exports")
    if len(req.exports) > 64:
        raise bad_arg("exports: at most 64", field="exports")
    for e in req.exports:
        if not isinstance(e, str) or not _IDENT.match(e):
            raise bad_arg(f"exports: {e!r} is not a C identifier",
                          field="exports")
    if req.opt not in OPT_LEVELS:
        raise bad_arg(f"opt: {req.opt!r} not allowed", field="opt",
                      given=req.opt, valid=OPT_LEVELS)
    if req.fp not in FP_MODELS:
        raise bad_arg(f"fp: {req.fp!r} not allowed", field="fp",
                      given=req.fp, valid=FP_MODELS)
    if req.x86_arch not in X86_ARCH:
        raise bad_arg(f"x86_arch: {req.x86_arch!r} not allowed (AVX "
                      "variants emit instructions Unicorn cannot run)",
                      field="x86_arch", given=req.x86_arch,
                      valid=[a for a in X86_ARCH if a])
    if req.x86_arch and req.arch != "x86":
        raise bad_arg("x86_arch: only for arch='x86'", field="x86_arch")
    if len(req.defines) > 32:
        raise bad_arg("defines: at most 32", field="defines")
    for d in req.defines:
        if not isinstance(d, str) or not _DEFINE.match(d):
            raise bad_arg(f"defines: {d!r} must be NAME or NAME=VALUE "
                          "(letters, digits, _ . + -)", field="defines")


def compile_flags(req: BuildRequest) -> list[str]:
    flags = ["/nologo", "/c", "/TC", "/GS-", "/Gy", "/MD", "/W3",
             "/diagnostics:column", f"/{req.opt}", f"/fp:{req.fp}"]
    if req.intrinsics:
        flags.append("/Oi")
    if req.x86_arch:
        flags.append(f"/arch:{req.x86_arch}")
    flags += [f"/D{d}" for d in req.defines]
    if req.toolchain == "clang-cl":
        flags.append("--target=" + ("x86_64-pc-windows-msvc"
                                    if req.arch == "x64"
                                    else "i686-pc-windows-msvc"))
    return flags


def link_flags(req: BuildRequest) -> list[str]:
    flags = ["/nologo", "/DLL", "/NOENTRY", "/DYNAMICBASE:NO",
             f"/BASE:{BASES[req.arch]:#x}",
             "/MACHINE:" + ("X64" if req.arch == "x64" else "X86"),
             "/INCREMENTAL:NO"]
    flags += [f"/EXPORT:{e}" for e in req.exports]
    return flags


def build_id(req: BuildRequest, tc: Toolchain) -> str:
    header = HEADER_PATH.read_bytes()
    blob = json.dumps({
        "profile": PROFILE_VERSION,
        "source": hashlib.sha256(req.source.encode("utf-8")).hexdigest(),
        "header": hashlib.sha256(header).hexdigest(),
        "toolchain": tc.name, "version": tc.version,
        "compiler": tc.compiler, "linker": tc.linker,
        "arch": req.arch, "compile": compile_flags(req),
        "link": link_flags(req)}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def parse_diagnostics(log: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in log.splitlines():
        line = raw.strip()
        m = _DIAG.match(line)
        if m:
            row: dict[str, Any] = {
                "file": Path(m.group("file").strip()).name,
                "line": int(m.group("line")),
                "severity": m.group("sev"),
                "message": m.group("msg").strip()}
            if m.group("col"):
                row["col"] = int(m.group("col"))
            if m.group("code"):
                row["code"] = m.group("code")
            rows.append(row)
            continue
        m = _LINKDIAG.match(line)
        if m:
            rows.append({"file": Path(m.group("file").strip()).name,
                         "severity": m.group("sev"), "code": m.group("code"),
                         "message": m.group("msg").strip()})
    return rows[:200]


def _export_matches(want: str, have: str) -> bool:
    """``crc`` matches ``crc``, ``_crc``, ``_crc@12``, ``@crc@12``."""
    h = have
    if h.startswith(("_", "@")) and h[1:].split("@", 1)[0] == want:
        return True
    return h.split("@", 1)[0] == want


def resolve_export(img: pe.PeImage, name: str) -> dict[str, Any] | None:
    exact = [e for e in img.exports if e["name"] == name]
    if exact:
        return exact[0]
    loose = [e for e in img.exports if e["name"] and
             _export_matches(name, e["name"])]
    return loose[0] if len(loose) == 1 else None


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def _run(argv: list[str], env: dict[str, str], cwd: Path,
         timeout: float) -> tuple[int, str]:
    try:
        r = subprocess.run(argv, env=env, cwd=str(cwd), capture_output=True,
                           text=True, errors="replace", timeout=timeout,
                           creationflags=getattr(subprocess,
                                                 "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise ReconError("compile_failed",
                         f"{Path(argv[0]).name} timed out after "
                         f"{timeout:.0f}s") from exc
    except OSError as exc:
        raise ReconError("toolchain_failed",
                         f"{Path(argv[0]).name}: {exc}") from exc
    log = (r.stdout or "") + (r.stderr or "")
    return r.returncode, log[-MAX_LOG_BYTES:]


def load_build(root: Path, bid: str) -> tuple[dict[str, Any], Path]:
    """(meta, dll path) of an existing build, or ``ReconError``."""
    if not re.fullmatch(r"[0-9a-f]{16}", bid or ""):
        raise bad_arg("build_id: 16 hex chars from a compile result",
                      field="build_id")
    d = root / bid
    meta_p, dll = d / "meta.json", d / "recon.dll"
    if not (meta_p.is_file() and dll.is_file()):
        raise ReconError("build_missing", f"no build {bid}",
                         hint="compile first: reconstruct_manage("
                              "action='compile', code=..., exports=[...])")
    return json.loads(meta_p.read_text(encoding="utf-8")), dll


def build(req: BuildRequest, tc: Toolchain, root: Path, *,
          compile_timeout_s: float = 60, link_timeout_s: float = 30
          ) -> dict[str, Any]:
    """Compile + link; returns the build's meta (``cached`` when hit)."""
    validate(req)
    check_source(req.source)
    bid = build_id(req, tc)
    final = root / bid
    if (final / "meta.json").is_file() and (final / "recon.dll").is_file():
        meta = json.loads((final / "meta.json").read_text(encoding="utf-8"))
        meta["cached"] = True
        return meta
    root.mkdir(parents=True, exist_ok=True)
    work = root / f".tmp-{bid}-{uuid.uuid4().hex[:8]}"
    work.mkdir()
    try:
        meta = _build_in(req, tc, work, bid, compile_timeout_s,
                         link_timeout_s)
        try:
            os.replace(work, final)
        except OSError:
            if not (final / "recon.dll").is_file():
                raise
        meta["cached"] = False
        return meta
    finally:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)


def _build_in(req: BuildRequest, tc: Toolchain, work: Path, bid: str,
              compile_timeout_s: float, link_timeout_s: float
              ) -> dict[str, Any]:
    (work / "source.c").write_text(req.source, encoding="utf-8")
    shutil.copyfile(HEADER_PATH, work / HEADER_NAME)
    env = vcvars_env(tc.vcvarsall, req.arch)
    if tc.name == "clang-cl":
        cc = tc.compiler
        ld = tc.linker or which_in(env, "link.exe")
    else:
        cc = which_in(env, "cl.exe")
        ld = which_in(env, "link.exe")
    t0 = time.monotonic()
    cflags = compile_flags(req)
    rc, clog = _run([cc, *cflags, "/Forecon.obj", "source.c"], env, work,
                    compile_timeout_s)
    diags = parse_diagnostics(clog)
    log = f"> {Path(cc).name} {' '.join(cflags)} source.c\n{clog}\n"
    if rc != 0:
        (work / "build.log").write_text(log, encoding="utf-8")
        raise ReconError("compile_failed", "the compiler rejected the source",
                         extra={"diagnostics": diags,
                                "log_tail": clog[-4000:]})
    lflags = link_flags(req)
    rc, llog = _run([ld, *lflags, "/OUT:recon.dll", "recon.obj",
                     *CRT_LIBS], env, work, link_timeout_s)
    log += f"> {Path(ld).name} {' '.join(lflags)} recon.obj\n{llog}\n"
    (work / "build.log").write_text(log, encoding="utf-8")
    ldiags = parse_diagnostics(llog)
    if rc != 0:
        raise ReconError("compile_failed", "the linker failed",
                         extra={"diagnostics": diags + ldiags,
                                "log_tail": llog[-4000:]})
    dll = work / "recon.dll"
    size = dll.stat().st_size
    if size > MAX_DLL_BYTES:
        raise ReconError("compile_failed",
                         f"recon.dll is {size} bytes (cap {MAX_DLL_BYTES})")
    data = dll.read_bytes()
    img = pe.parse(data)
    exports: dict[str, int] = {}
    missing = []
    for e in req.exports:
        hit = resolve_export(img, e)
        if hit is None:
            missing.append(e)
        else:
            exports[e] = int(hit["rva"])
    if missing:
        raise ReconError("compile_failed",
                         f"export(s) missing from the DLL: {missing}",
                         extra={"diagnostics": diags + ldiags})
    for leftover in ("recon.obj", "recon.lib", "recon.exp"):
        try:
            (work / leftover).unlink()
        except OSError:
            pass
    meta: dict[str, Any] = {
        "build_id": bid, "toolchain": tc.name, "version": tc.version,
        "arch": req.arch, "compile_flags": cflags, "link_flags": lflags,
        "exports": {k: f"0x{v:x}" for k, v in exports.items()},
        "image_base": f"0x{img.image_base:x}",
        "imports": sorted({f"{d['dll']}!{e['name'] or e['ordinal']}"
                           for d in img.imports for e in d["entries"]}),
        "dll_sha256": hashlib.sha256(data).hexdigest(),
        "dll_bytes": size, "profile_version": PROFILE_VERSION,
        "build_s": round(time.monotonic() - t0, 3),
        "diagnostics": diags + ldiags,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (work / "meta.json").write_text(json.dumps(meta, indent=1),
                                    encoding="utf-8")
    return meta


__all__ = ["BuildRequest", "CRT_LIBS", "FP_MODELS", "HEADER_PATH",
           "OPT_LEVELS", "build", "build_id", "check_source",
           "compile_flags", "link_flags", "load_build", "parse_diagnostics",
           "resolve_export", "validate"]
