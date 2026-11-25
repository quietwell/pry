"""reconstruct.compile / reconstruct.toolchain.

Pure tests (source guard, flag allowlist, build ids, diagnostics,
export matching, discovery over a fake install tree) always run; the
real MSVC build tests skip when no Visual Studio C++ toolchain is
installed, the clang-cl ones when clang-cl is absent.
"""

from __future__ import annotations

import pytest

from pry.analysis import pe
from pry.reconstruct import compile as cc
from pry.reconstruct import toolchain as tcm
from pry.reconstruct.errors import ReconError

OK_SRC = '''
#include <stdint.h>
#include <string.h>
#include "pry_recon.h"
#pragma once
#pragma warning(disable: 4100)
#pragma pack(push, 1)
#define N 4
/* a comment with #include "C:/secret" inside is fine */
// so is #pragma comment(linker, "/x") in a line comment
u32 add1(u32 x) { const char *s = "#include \\"nope\\""; (void)s; return x + N; }
'''


def test_source_guard_accepts_normal_reconstructions() -> None:
    cc.check_source(OK_SRC)


@pytest.mark.parametrize("src", [
    '#include "C:/Users/x/secret.txt"\n',
    '#include "other.h"\n',
    '#include "../pry_recon.h"\n',
    '#include <../../secret.h>\n',
    '#include <C:\\secret.h>\n',
    '#include </etc/passwd.h>\n',
    '#define H <stdio.h>\n#include H\n',
    '#pragma comment(linker, "/EXPORT:x")\n',
    '#pragma comment(lib, "advapi32")\n',
    '#pragma include_alias(<a.h>, "C:/x")\n',
    '#pragma section("x", read)\n',
    '_Pragma("comment(lib, \\"x\\")")\n',
    '__pragma(comment(lib, "x"))\n',
    '#embed "C:/x"\n',
    '#import "x.tlb"\n',
    '#include_next <stdio.h>\n',
    '#pra\\\ngma comment(lib, "x")\n',
    '#/**/pragma comment(lib, "x")\n',
    '%:include "C:/x"\n',
    '??=include "C:/x"\n',
    'int x;\0\n',
])
def test_source_guard_rejects(src) -> None:
    with pytest.raises(ReconError) as ei:
        cc.check_source(src)
    assert ei.value.kind == "source_rejected"


@pytest.mark.parametrize("field,kw", [
    ("opt", {"opt": "O3"}),
    ("fp", {"fp": "except"}),
    ("defines", {"defines": ["A B"]}),
    ("defines", {"defines": ['X="1"']}),
    ("x86_arch", {"x86_arch": "AVX2", "arch": "x86"}),
    ("x86_arch", {"x86_arch": "SSE2", "arch": "x64"}),
    ("exports", {"exports": ["bad name"]}),
    ("exports", {"exports": []}),
    ("arch", {"arch": "arm64"}),
])
def test_request_validation(field, kw) -> None:
    args = {"source": "int f(void){return 0;}", "exports": ["f"]}
    args.update(kw)
    with pytest.raises(ReconError) as ei:
        cc.validate(cc.BuildRequest(**args))
    assert ei.value.field == field


def test_flag_profiles() -> None:
    req = cc.BuildRequest(source="", exports=["f", "g"], arch="x86",
                          opt="O1", fp="strict", defines=["DEBUG", "K=3"],
                          x86_arch="SSE2")
    flags = cc.compile_flags(req)
    for f in ("/TC", "/GS-", "/Gy", "/MD", "/O1", "/fp:strict", "/Oi",
              "/arch:SSE2", "/DDEBUG", "/DK=3"):
        assert f in flags
    assert not any(f.startswith("--target") for f in flags)
    link = cc.link_flags(req)
    for f in ("/DLL", "/NOENTRY", "/DYNAMICBASE:NO", "/BASE:0x10000000",
              "/MACHINE:X86", "/EXPORT:f", "/EXPORT:g"):
        assert f in link
    clang = cc.compile_flags(cc.BuildRequest(source="", exports=["f"],
                                             arch="x64",
                                             toolchain="clang-cl"))
    assert "--target=x86_64-pc-windows-msvc" in clang
    clang86 = cc.compile_flags(cc.BuildRequest(source="", exports=["f"],
                                               arch="x86",
                                               toolchain="clang-cl"))
    assert "--target=i686-pc-windows-msvc" in clang86


def test_build_id_is_content_addressed() -> None:
    tc = tcm.Toolchain(name="msvc", available=True, version="14.51",
                       arches=("x64",))
    base = cc.BuildRequest(source="int f(void){return 0;}", exports=["f"])
    a = cc.build_id(base, tc)
    assert a == cc.build_id(cc.BuildRequest(**vars(base)), tc)
    assert a != cc.build_id(cc.BuildRequest(**{**vars(base), "opt": "Od"}),
                            tc)
    assert a != cc.build_id(cc.BuildRequest(**{**vars(base),
                                               "source": "int f(void){}"}),
                            tc)
    other = tcm.Toolchain(name="clang-cl", available=True, arches=("x64",))
    assert a != cc.build_id(base, other)
    assert len(a) == 16


def test_diagnostics_parser() -> None:
    log = (
        "source.c\n"
        "C:\\b\\source.c(12,5): error C2065: 'x': undeclared identifier\n"
        "source.c(3): warning C4100: 'y': unreferenced formal parameter\n"
        "source.c(7,1): error: use of undeclared identifier 'z'\n"
        "recon.obj : error LNK2019: unresolved external symbol memcpy "
        "referenced in function f\n")
    rows = cc.parse_diagnostics(log)
    assert rows[0] == {"file": "source.c", "line": 12, "col": 5,
                       "severity": "error", "code": "C2065",
                       "message": "'x': undeclared identifier"}
    assert rows[1]["severity"] == "warning" and "col" not in rows[1]
    assert rows[2]["message"].startswith("use of undeclared")
    assert rows[3]["code"] == "LNK2019"


def test_export_matching_tolerates_x86_decoration() -> None:
    class Img:
        exports = [{"name": "_add@8", "rva": 0x10},
                   {"name": "@mul@12", "rva": 0x20},
                   {"name": "plain", "rva": 0x30}]
    assert cc.resolve_export(Img(), "add")["rva"] == 0x10
    assert cc.resolve_export(Img(), "mul")["rva"] == 0x20
    assert cc.resolve_export(Img(), "plain")["rva"] == 0x30
    assert cc.resolve_export(Img(), "nope") is None


def _fake_vs(root, *, x86=True, clang=False, lld=False):
    vs = root / "VS"
    build = vs / "VC/Auxiliary/Build"
    build.mkdir(parents=True)
    (build / "vcvarsall.bat").write_text("@echo off\n")
    (build / "Microsoft.VCToolsVersion.default.txt").write_text("14.99.1\n")
    tools = vs / "VC/Tools/MSVC/14.99.1/bin/Hostx64"
    (tools / "x64").mkdir(parents=True)
    (tools / "x64/cl.exe").write_bytes(b"")
    if x86:
        (tools / "x86").mkdir(parents=True)
        (tools / "x86/cl.exe").write_bytes(b"")
    if clang:
        llvm = vs / "VC/Tools/Llvm/x64/bin"
        llvm.mkdir(parents=True)
        (llvm / "clang-cl.exe").write_bytes(b"")
        if lld:
            (llvm / "lld-link.exe").write_bytes(b"")
    return vs


def test_discovery_over_a_fake_install(tmp_path) -> None:
    vs = _fake_vs(tmp_path, clang=True, lld=True)

    class Cfg:
        vs_path = str(vs)
        clang_cl = ""
        lld_link = ""
    tcs = {t.name: t for t in tcm.discover(Cfg())}
    msvc = tcs["msvc"]
    assert msvc.available and msvc.version == "14.99.1"
    assert msvc.arches == ("x64", "x86")
    clang = tcs["clang-cl"]
    assert clang.available and clang.compiler.endswith("clang-cl.exe")
    assert clang.linker.endswith("lld-link.exe")
    assert tcm.pick(list(tcs.values()), "clang-cl", "x86") is clang


def test_discovery_without_clang_and_pick_errors(tmp_path) -> None:
    vs = _fake_vs(tmp_path, x86=False)

    class Cfg:
        vs_path = str(vs)
        clang_cl = str(tmp_path / "missing" / "clang-cl.exe")
        lld_link = ""
    tcs = tcm.discover(Cfg())
    by = {t.name: t for t in tcs}
    with pytest.raises(ReconError) as ei:
        tcm.pick(tcs, "msvc", "x86")
    assert ei.value.kind == "toolchain_missing"
    if not by["clang-cl"].available:
        with pytest.raises(ReconError) as ei:
            tcm.pick(tcs, "clang-cl", "x64")
        assert ei.value.kind == "toolchain_missing"
    with pytest.raises(ReconError) as ei:
        tcm.pick(tcs, "gcc", "x64")
    assert ei.value.kind == "bad_arg"
    gcc = by.get("mingw-gcc")
    if gcc is not None:
        with pytest.raises(ReconError) as ei:
            tcm.pick(tcs, "mingw-gcc", "x64")
        assert ei.value.kind == "toolchain_unsupported"


def test_discovery_finds_a_per_user_llvm(tmp_path, monkeypatch) -> None:
    vs = _fake_vs(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        monkeypatch.setenv(var, str(empty))
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))

    class Cfg:
        vs_path = str(vs)
        clang_cl = ""
        lld_link = ""
    assert not {t.name: t for t in tcm.discover(Cfg())}["clang-cl"].available
    llvm = tmp_path / "local/Programs/LLVM/bin"
    llvm.mkdir(parents=True)
    (llvm / "clang-cl.exe").write_bytes(b"")
    (llvm / "lld-link.exe").write_bytes(b"")
    clang = {t.name: t for t in tcm.discover(Cfg())}["clang-cl"]
    assert clang.available
    assert clang.compiler == str(llvm / "clang-cl.exe")
    assert clang.linker == str(llvm / "lld-link.exe")


def test_vcvars_env_rejects_unsafe_paths(tmp_path) -> None:
    bad = tmp_path / 'x" & calc & "'
    with pytest.raises(ReconError):
        tcm.vcvars_env(str(bad), "x64")


# ---------------------------------------------------------- real builds --

def _host(name: str):
    try:
        tcs = tcm.discover(None, allow_exec=True)
    except Exception:  # pragma: no cover
        return None
    for t in tcs:
        if t.name == name and t.available and t.supported:
            return t
    return None


MSVC = _host("msvc")
CLANG = _host("clang-cl")
needs_msvc = pytest.mark.skipif(MSVC is None, reason="no MSVC toolchain")
needs_clang = pytest.mark.skipif(CLANG is None, reason="no clang-cl")

ADD = '#include "pry_recon.h"\nu32 add3(u32 x) { return x + 3; }\n'


@needs_msvc
@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_msvc_build_cache_and_errors(tmp_path, arch) -> None:
    if arch not in MSVC.arches:
        pytest.skip(f"no {arch} cl")
    req = cc.BuildRequest(source=ADD, exports=["add3"], arch=arch)
    meta = cc.build(req, MSVC, tmp_path)
    assert meta["cached"] is False and meta["arch"] == arch
    meta2, dll = cc.load_build(tmp_path, meta["build_id"])
    img = pe.parse(dll.read_bytes())
    assert img.machine == (0x8664 if arch == "x64" else 0x14C)
    assert img.image_base == cc.BASES[arch]
    assert cc.resolve_export(img, "add3") is not None
    assert (tmp_path / meta["build_id"] / "source.c").is_file()
    assert not (tmp_path / meta["build_id"] / "recon.obj").exists()
    again = cc.build(req, MSVC, tmp_path)
    assert again["cached"] is True and again["build_id"] == meta["build_id"]
    with pytest.raises(ReconError) as ei:
        cc.build(cc.BuildRequest(source='#include "pry_recon.h"\n'
                                        "u32 f(void) { return y; }",
                                 exports=["f"], arch=arch), MSVC, tmp_path)
    assert ei.value.kind == "compile_failed"
    assert any(d.get("code") == "C2065" for d in ei.value.extra["diagnostics"])
    with pytest.raises(ReconError) as ei:
        cc.build(cc.BuildRequest(source=ADD, exports=["nothere"], arch=arch),
                 MSVC, tmp_path)
    assert ei.value.kind == "compile_failed"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".tmp")]


@needs_clang
@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_clang_cl_build(tmp_path, arch) -> None:
    req = cc.BuildRequest(source=ADD, exports=["add3"], arch=arch,
                          toolchain="clang-cl")
    meta = cc.build(req, CLANG, tmp_path)
    assert meta["toolchain"] == "clang-cl" and meta["cached"] is False
    assert any(f.startswith("--target=") for f in meta["compile_flags"])
    _meta, dll = cc.load_build(tmp_path, meta["build_id"])
    img = pe.parse(dll.read_bytes())
    assert img.machine == (0x8664 if arch == "x64" else 0x14C)
    assert img.image_base == cc.BASES[arch]
    assert cc.resolve_export(img, "add3") is not None
    assert cc.build(req, CLANG, tmp_path)["cached"] is True
    msvc_req = cc.BuildRequest(source=ADD, exports=["add3"], arch=arch)
    if MSVC is not None and arch in MSVC.arches:
        assert cc.build_id(msvc_req, MSVC) != meta["build_id"]
    with pytest.raises(ReconError) as ei:
        cc.build(cc.BuildRequest(source='#include "pry_recon.h"\n'
                                        "u32 f(void) { return y; }",
                                 exports=["f"], arch=arch,
                                 toolchain="clang-cl"), CLANG, tmp_path)
    assert ei.value.kind == "compile_failed"
    diags = ei.value.extra["diagnostics"]
    assert any(d["severity"] == "error" and d.get("line") == 2
               and "undeclared identifier" in d["message"] for d in diags)
    with pytest.raises(ReconError) as ei:
        cc.build(cc.BuildRequest(source=ADD, exports=["nothere"], arch=arch,
                                 toolchain="clang-cl"), CLANG, tmp_path)
    assert ei.value.kind == "compile_failed"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".tmp")]
