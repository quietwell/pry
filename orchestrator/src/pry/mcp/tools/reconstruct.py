"""``reconstruct_manage`` — reconstruct-and-verify (slice 1).

Check a C reconstruction of one function against the original binary:
compile the C into a DLL (host MSVC or clang-cl, gated by
``security.allow_host_compile``), then run the original and the
reconstruction under Unicorn on the same generated inputs and compare
every declared output. Behavioral only: a pass means "behaved the same
on these inputs, with this coverage", never equivalence in general.

The original comes from the same sources ``bin_manage`` takes (artifact
``sha256=`` / ``path=``, or ``source='memory'`` + ``module=`` /
``address=`` for a live image). Build outputs are read as bytes by the
emulator's mapper and never loaded natively. See docs/RECONSTRUCT.md.
"""

from __future__ import annotations

import asyncio

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context

RECON_ACTIONS = ["toolchains", "compile", "call", "verify", "actions"]

_SIG_EXAMPLE = ('{"ret":"u32","params":[{"name":"x","type":"u32"}]}')

_RECON_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "reconstruct_manage(action='actions')"},
    "toolchains": {"one_liner": "host C toolchains (msvc, clang-cl), the "
                                "default, and the compile gate state",
                   "key_args": "none",
                   "example": "reconstruct_manage(action='toolchains')"},
    "compile": {"one_liner": "build C source into a reconstruction DLL "
                             "artifact (gated: security.allow_host_compile)",
                "key_args": "code | code_path, exports, arch, toolchain, "
                            "options_json",
                "example": "reconstruct_manage(action='compile', "
                           "code='#include \"pry_recon.h\"\\n"
                           "u32 add1(u32 x) { return x + 1; }', "
                           "exports=['add1'])"},
    "call": {"one_liner": "run one function once under emulation with "
                          "explicit args — the original, the "
                          "reconstruction, or both (no gate)",
             "key_args": "sha256 | path | source, func, build_id, export, "
                         "signature_json, args_json",
             "example": "reconstruct_manage(action='call', sha256='<64 hex>'"
                        ", func='0x140001000', signature_json='"
                        + _SIG_EXAMPLE + "', args_json='{\"x\": 7}')"},
    "verify": {"one_liner": "differential run of the original vs the "
                            "reconstruction over generated + explicit "
                            "inputs, with coverage",
               "key_args": "sha256 | path | source, func, build_id, export, "
                           "code, signature_json, cases, seed, cases_json, "
                           "cases_path, min_coverage, timeout_s, "
                           "options_json",
               "example": "reconstruct_manage(action='verify', "
                          "sha256='<64 hex>', func='0x140001000', "
                          "build_id='<16 hex>', export='add1', "
                          "signature_json='" + _SIG_EXAMPLE + "', "
                          "cases=500, seed=7)"},
}

_MACHINES = {0x8664: "x64", 0x14C: "x86"}


def _recon_err(exc) -> str:
    return _j(exc.envelope())


def _gate_refusal(what: str) -> str:
    return _j({"ok": False, "kind": "not_allowed",
               "error": (f"reconstruct_manage {what}: host compiles are "
                         "disabled (security.allow_host_compile=false) — "
                         "compiling runs the host C toolchain on agent-"
                         "supplied source"),
               "hint": ("enable security.allow_host_compile in the "
                        "orchestrator config to allow compiles; call and "
                        "verify against an existing build_id need no "
                        "gate")})


def _parse_json_arg(value: Any, name: str) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name}: JSON text or an object")
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name}: invalid JSON ({exc})") from exc


#: options_json keys → defaults. Compile knobs: opt, fp, intrinsics,
#: defines, x86_arch. Run knobs: boundary, probe, max_insns, inputs.
_OPTION_DEFAULTS: dict[str, Any] = {
    "opt": "O2", "fp": "precise", "intrinsics": True, "defines": [],
    "x86_arch": "", "boundary": True, "probe": True, "max_insns": 0,
    "inputs": "guided"}


def _options(raw: Any) -> dict:
    """Validate ``options_json`` → the full knob dict (defaults filled)."""
    from ...reconstruct.errors import bad_arg
    obj = _parse_json_arg(raw, "options_json")
    if obj is None:
        obj = {}
    if not isinstance(obj, dict):
        raise bad_arg("options_json: an object, e.g. {\"opt\": \"Od\"}",
                      field="options_json")
    out = dict(_OPTION_DEFAULTS)
    out["defines"] = []
    for k, v in obj.items():
        if k not in _OPTION_DEFAULTS:
            raise bad_arg(f"options_json: unknown option {k!r}",
                          field=f"options_json.{k}", given=str(k),
                          valid=tuple(_OPTION_DEFAULTS))
        want = type(_OPTION_DEFAULTS[k])
        if want is bool and not isinstance(v, bool):
            raise bad_arg(f"options_json.{k}: true or false",
                          field=f"options_json.{k}")
        if want is int and (isinstance(v, bool) or not isinstance(v, int)
                            or not 0 <= v <= 100_000_000):
            raise bad_arg(f"options_json.{k}: an integer 0..100000000",
                          field=f"options_json.{k}")
        if want is str and not isinstance(v, str):
            raise bad_arg(f"options_json.{k}: a string",
                          field=f"options_json.{k}")
        if want is list and not (isinstance(v, list) and
                                 all(isinstance(x, str) for x in v)):
            raise bad_arg(f"options_json.{k}: a list of strings",
                          field=f"options_json.{k}")
        out[k] = v
    from ...reconstruct.inputs import INPUT_MODES
    if out["inputs"] not in INPUT_MODES:
        raise bad_arg(f"options_json.inputs: {' | '.join(INPUT_MODES)}",
                      field="options_json.inputs", given=str(out["inputs"]),
                      valid=INPUT_MODES)
    return out


def register(mcp, ctx: Context) -> None:
    """Register the ``reconstruct_manage`` tool on *mcp*."""

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def reconstruct_manage(
            action: Annotated[str, Field(json_schema_extra={"enum": RECON_ACTIONS})],
            sha256: str = "",
            path: str = "",
            source: str = "artifact",
            module: str = "",
            pid: int = 0,
            address: Any = 0,
            size: int = 0,
            space: str = "user",
            name: str = "",
            kernel: bool = False,
            layout: str = "auto",
            func: Any = "",
            build_id: str = "",
            export: str = "",
            code: str = "",
            code_path: str = "",
            exports: list[str] | None = None,
            toolchain: str = "",
            arch: str = "",
            options_json: Any = "",
            signature_json: Any = "",
            args_json: Any = "",
            cases: int = -1,
            seed: int = 1,
            cases_json: Any = "",
            cases_path: str = "",
            timeout_s: float = 60.0,
            min_coverage: float = 0.0) -> str:
        """Reconstruct-and-verify: compile a C reconstruction of one
        function (host MSVC or clang-cl; gated by
        security.allow_host_compile) and verify it against the original
        binary under Unicorn — both sides run the same explicit,
        boundary and coverage-guided inputs; the report gives
        matched/mismatched counts, the first mismatches with inputs, and
        the original's block coverage. x64 (Win64) and x86 (cdecl/stdcall/fastcall/
        thiscall). A pass is bounded by its inputs and coverage.
        Per-verb help: reconstruct_manage(action='actions')."""
        args = {"action": action, "path": path or sha256 or module,
                "source": source, "build_id": build_id}

        async def run() -> Any:
            if action not in RECON_ACTIONS:
                return _unknown_action("reconstruct_manage", action,
                                       RECON_ACTIONS, _RECON_ACTION_HELP)
            if action == "actions":
                return _actions_help("reconstruct_manage", _RECON_ACTION_HELP)
            from ...reconstruct.errors import ReconError
            try:
                o = _options(options_json)
                if action == "toolchains":
                    return await asyncio.to_thread(_toolchains, ctx)
                if action == "compile":
                    if not _gate_on(ctx):
                        return _gate_refusal("compile")
                    meta = await _compile(ctx, code=code, code_path=code_path,
                                          exports=exports or [],
                                          toolchain=toolchain,
                                          arch=arch or "x64", opt=o["opt"],
                                          fp=o["fp"],
                                          intrinsics=o["intrinsics"],
                                          defines=o["defines"],
                                          x86_arch=o["x86_arch"])
                    return _out(meta)
                loader = dict(source=source, path=path, sha256=sha256,
                              module=module, pid=pid, address=address,
                              size=size, space=space, name=name,
                              kernel=kernel, layout=layout, action=action)
                if action == "call":
                    return await _call(ctx, loader, func=func,
                                       build_id=build_id, export=export,
                                       arch=arch,
                                       signature_json=signature_json,
                                       args_json=args_json, seed=seed,
                                       max_insns=o["max_insns"])
                return await _verify(
                    ctx, loader, func=func, build_id=build_id,
                    export=export, code=code, code_path=code_path,
                    toolchain=toolchain, arch=arch, opt=o["opt"],
                    fp=o["fp"], intrinsics=o["intrinsics"],
                    defines=o["defines"], x86_arch=o["x86_arch"],
                    signature_json=signature_json, cases=cases, seed=seed,
                    cases_json=cases_json, cases_path=cases_path,
                    boundary=o["boundary"], probe=o["probe"],
                    timeout_s=timeout_s, min_coverage=min_coverage,
                    max_insns=o["max_insns"], inputs=o["inputs"])
            except ReconError as exc:
                return _recon_err(exc)
            except ValueError as exc:
                return _j({"ok": False, "kind": "bad_arg", "error": str(exc)})
            except Exception as exc:  # unicorn / capstone missing
                from ...codegen import CodegenUnavailable
                if isinstance(exc, CodegenUnavailable):
                    return _codegen_extra_err(exc)
                raise

        return await _guard(ctx, "reconstruct_manage", action, args, run)


# ---------------------------------------------------------------------------
# Helpers (module scope so tests can drive them directly)
# ---------------------------------------------------------------------------

def _gate_on(ctx: Context) -> bool:
    return bool(getattr(ctx.cfg.security, "allow_host_compile", False))


def _rcfg(ctx: Context):
    from ...config import ReconstructConfig
    return getattr(ctx.cfg, "reconstruct", None) or ReconstructConfig()


def _artifacts_dir(ctx: Context) -> Path:
    # The anchored store (PRY_ARTIFACTS_DIR, else artifacts.dir at the
    # repo root): the one resolve_artifact_path reads code_path= and
    # cases_path= from. Path(artifacts.dir) followed the server's cwd, so
    # a server booted from orchestrator/ wrote builds and runs to a
    # second store that the cases_path= replays never read.
    return Path(ctx.cfg.artifacts_dir())


def _out(data: dict) -> str:
    from .bin import _jh
    return _jh(data)


def _toolchains(ctx: Context) -> str:
    from ...reconstruct import toolchain as _tc
    rc = _rcfg(ctx)
    gate = _gate_on(ctx)
    tcs = _tc.discover(rc, allow_exec=gate)
    try:
        from ...codegen import _load_unicorn
        _load_unicorn()
        emulator = {"available": True}
    except Exception as exc:
        emulator = {"available": False, "error": str(exc),
                    "hint": "pip install 'pry[codegen]'"}
    return _out({"ok": True, "toolchains": [t.to_json() for t in tcs],
                 "default": rc.default_toolchain,
                 "allow_host_compile": gate,
                 "emulator": emulator,
                 "note": ("call and verify run on Unicorn and need no "
                          "toolchain; compile needs "
                          "security.allow_host_compile=true"
                          if not gate else
                          "compile is enabled on this host")})


def _read_artifact_text(ctx: Context, rel: str, what: str,
                        cap: int = 64 << 20) -> str:
    from .._artifacts import resolve_artifact_path
    p = resolve_artifact_path(ctx.cfg, rel)
    if p is None:
        raise ValueError(f"{what}: {rel!r} is outside artifacts_dir")
    try:
        if p.stat().st_size > cap:
            raise ValueError(f"{what}: {p.name} is over {cap} bytes")
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"{what}: {exc}") from exc


async def _compile(ctx: Context, *, code: str, code_path: str,
                   exports: list[str], toolchain: str, arch: str, opt: str,
                   fp: str, intrinsics: bool, defines: list[str],
                   x86_arch: str) -> dict:
    from ...reconstruct import compile as _cc
    from ...reconstruct import report as _rep
    from ...reconstruct import toolchain as _tc
    from ...reconstruct.errors import bad_arg
    rc = _rcfg(ctx)
    if code and code_path:
        raise bad_arg("compile: pass code= or code_path=, not both",
                      field="code")
    if code_path:
        code = _read_artifact_text(ctx, code_path, "code_path",
                                   cap=_cc.MAX_SOURCE_BYTES)
    if not code.strip():
        raise bad_arg("compile: code= (C source text) or code_path= "
                      "(a .c file under artifacts/) is required",
                      field="code")
    name = toolchain or rc.default_toolchain
    req = _cc.BuildRequest(source=code, exports=list(exports), arch=arch,
                           toolchain=name, opt=opt, fp=fp,
                           intrinsics=intrinsics, defines=list(defines),
                           x86_arch=x86_arch)
    _cc.validate(req)
    _cc.check_source(req.source)

    def work() -> dict:
        tcs = _tc.discover(rc, allow_exec=True)
        tc = _tc.pick(tcs, name, arch)
        return _cc.build(req, tc, _rep.builds_root(_artifacts_dir(ctx)),
                         compile_timeout_s=rc.compile_timeout_s,
                         link_timeout_s=rc.link_timeout_s)

    meta = await asyncio.to_thread(work)
    out = {"ok": True, **meta,
           "path": f"reconstruct/builds/{meta['build_id']}",
           "next": {"verify": {
               "tool": "reconstruct_manage", "action": "verify",
               "args": {"build_id": meta["build_id"],
                        "export": next(iter(meta["exports"]), "")}}}}
    warnings = [d for d in meta.get("diagnostics", [])
                if d.get("severity") == "warning"]
    if warnings:
        out["warnings_count"] = len(warnings)
    return out


async def _original_side(ctx: Context, loader: dict, func: Any, arch: str):
    """Load the original and resolve func → (Side, info)."""
    from ...analysis.engine import ImageView, wrap_blob
    from ...reconstruct.errors import bad_arg
    from ...reconstruct.harness import Side
    from .bin import _load_source
    data, origin, img_base, img, _salvage, data_sha = await _load_source(
        ctx, **loader)
    if isinstance(data, str):
        return None, data
    if img is not None:
        side_arch = _MACHINES.get(img.machine)
        if side_arch is None:
            raise bad_arg(f"original: machine {img.machine:#x} is not x64 "
                          "or x86", field="sha256")
        if arch and arch != side_arch:
            raise bad_arg(f"arch={arch!r} but the original is {side_arch}",
                          field="arch")
        view = ImageView(img, base_va=img_base or 0)
    else:
        side_arch = arch or "x64"
        if side_arch not in ("x64", "x86"):
            raise bad_arg("arch: x64 | x86", field="arch", given=side_arch,
                          valid=("x64", "x86"))
        base = img_base or 0
        if not base:
            # A raw blob has no base: map it off page zero (so NULL
            # dereferences still fault) and read a numeric func as an
            # offset into it.
            base = 0x10000000 if side_arch == "x86" else 0x140000000
            if isinstance(func, int) and not isinstance(func, bool) \
                    and 0 <= func < len(data):
                func = base + func
            elif isinstance(func, str) and func.strip()[:2].lower() == "0x":
                try:
                    off = int(func, 16)
                    if off < len(data):
                        func = base + off
                except ValueError:
                    pass
        view = wrap_blob(data, base_va=base)
    va = _resolve_func(view, img, func)
    info = {"origin": origin, "sha256": data_sha, "func_va": f"0x{va:x}",
            "image_base": f"0x{view.base_va:x}", "arch": side_arch}
    return Side("original", view, va, side_arch), info


def _resolve_func(view, img, func: Any) -> int:
    from ...reconstruct.compile import resolve_export
    from ...reconstruct.errors import bad_arg
    if func is None or func == "" or func == 0:
        raise bad_arg("func= is required: a VA, 'module+0xRVA', or an "
                      "export name", field="func")
    va: int | None = None
    if isinstance(func, int) and not isinstance(func, bool):
        va = func
    else:
        s = str(func).strip()
        if "+" in s:
            _mod, _sep, off = s.rpartition("+")
            try:
                va = view.base_va + int(off.strip(), 0)
            except ValueError:
                va = None
        else:
            try:
                va = int(s, 0)
            except ValueError:
                va = None
            if va is None and img is not None:
                hit = resolve_export(img, s)
                if hit is not None:
                    va = view.base_va + int(hit["rva"])
                else:
                    names = [e["name"] for e in img.exports if e["name"]]
                    raise bad_arg(f"func: no export named {s!r}",
                                  field="func", given=s, valid=names)
    if va is None:
        raise bad_arg(f"func: cannot parse {func!r}", field="func")
    if not view.is_exec(va):
        lo = view.base_va
        raise bad_arg(f"func: {va:#x} is not inside an executable section "
                      f"of the original (image base {lo:#x})", field="func",
                      hint="pass a VA, 'module+0xRVA' or an export name")
    return va


def _recon_side(ctx: Context, build_id: str, export: str):
    from ...analysis import pe as _pe
    from ...analysis.engine import ImageView
    from ...reconstruct.compile import load_build, resolve_export
    from ...reconstruct.errors import bad_arg
    from ...reconstruct.harness import Side
    from ...reconstruct.report import builds_root
    meta, dll = load_build(builds_root(_artifacts_dir(ctx)), build_id)
    img = _pe.parse(dll.read_bytes())
    names = list(meta.get("exports", {}))
    want = export or (names[0] if len(names) == 1 else "")
    if not want:
        raise bad_arg("export= names the reconstruction's function",
                      field="export", hint=f"this build exports {names}")
    hit = resolve_export(img, want)
    if hit is None:
        raise bad_arg(f"export: {want!r} is not exported by build "
                      f"{build_id}", field="export", given=want,
                      valid=names)
    view = ImageView(img)
    va = img.image_base + int(hit["rva"])
    return Side("reconstruction", view, va, meta["arch"]), meta, want


def _signature(signature_json: Any, arch: str):
    from ...reconstruct.signature import parse_signature
    spec = _parse_json_arg(signature_json, "signature_json")
    if spec is None:
        spec = ""
    return parse_signature(spec, arch=arch)


async def _call(ctx: Context, loader: dict, *, func: Any, build_id: str,
                export: str, arch: str, signature_json: Any,
                args_json: Any, seed: int, max_insns: int) -> str:
    from ...reconstruct.errors import bad_arg
    from ...reconstruct.inputs import parse_case_list
    from ...reconstruct.verify import run_call
    has_original = bool(loader["sha256"] or loader["path"]
                        or loader["source"] == "memory")
    sides = []
    info: dict = {}
    if has_original:
        side, oinfo = await _original_side(ctx, loader, func, arch)
        if side is None:
            return oinfo
        sides.append(side)
        info["original"] = oinfo
    if build_id:
        rside, meta, want = await asyncio.to_thread(_recon_side, ctx,
                                                    build_id, export)
        sides.append(rside)
        info["reconstruction"] = {"build_id": build_id, "export": want,
                                  "toolchain": meta.get("toolchain"),
                                  "arch": meta.get("arch")}
    if not sides:
        raise bad_arg("call: name the original (sha256= | path= | "
                      "source='memory') and/or the reconstruction "
                      "(build_id=)", field="sha256")
    archs = {s.arch for s in sides}
    if len(archs) != 1:
        raise bad_arg(f"call: the sides disagree on arch {sorted(archs)}",
                      field="build_id")
    sig = _signature(signature_json, sides[0].arch)
    raw = _parse_json_arg(args_json, "args_json")
    if raw is None:
        raw = {} if not any(p for p in sig.params if not p.len_of) else None
    if raw is None:
        raise bad_arg("call: args_json= gives every param's value, e.g. "
                      '{"x": 7}', field="args_json")
    values = parse_case_list(sig, [raw], origin="explicit",
                             where="args_json")[0]
    rc = _rcfg(ctx)
    out = await asyncio.to_thread(run_call, sides, sig, values, seed=seed,
                                  max_insns=max_insns or rc.max_insns)
    for label, src_info in info.items():
        out.setdefault(label, {})["source"] = src_info
    return _out(out)


async def _verify(ctx: Context, loader: dict, *, func: Any, build_id: str,
                  export: str, code: str, code_path: str, toolchain: str,
                  arch: str, opt: str, fp: str, intrinsics: bool,
                  defines: list[str], x86_arch: str, signature_json: Any,
                  cases: int, seed: int, cases_json: Any, cases_path: str,
                  boundary: bool, probe: bool, timeout_s: float,
                  min_coverage: float, max_insns: int,
                  inputs: str = "guided") -> str:
    from ...reconstruct import report as _rep
    from ...reconstruct.errors import bad_arg
    from ...reconstruct.inputs import parse_case_list, read_cases_jsonl
    from ...reconstruct.verify import VerifyOptions, run_verify
    if not (loader["sha256"] or loader["path"]
            or loader["source"] == "memory"):
        raise bad_arg("verify: the original is required — sha256=, path= or "
                      "source='memory' (+ module=/address=)", field="sha256")
    oside, oinfo = await _original_side(ctx, loader, func, arch)
    if oside is None:
        return oinfo
    compiled = None
    if code or code_path:
        if build_id:
            raise bad_arg("verify: pass build_id= or code=, not both",
                          field="build_id")
        if not _gate_on(ctx):
            return _gate_refusal("verify with code=")
        if not export:
            raise bad_arg("verify with code=: export= names the function to "
                          "compare", field="export")
        compiled = await _compile(ctx, code=code, code_path=code_path,
                                  exports=[export], toolchain=toolchain,
                                  arch=oside.arch, opt=opt, fp=fp,
                                  intrinsics=intrinsics, defines=defines,
                                  x86_arch=x86_arch)
        build_id = compiled["build_id"]
    if not build_id:
        raise bad_arg("verify: build_id= (from compile) or code= is "
                      "required", field="build_id")
    rside, meta, want = await asyncio.to_thread(_recon_side, ctx, build_id,
                                                export)
    if rside.arch != oside.arch:
        raise bad_arg(f"verify: the build is {rside.arch} but the original "
                      f"is {oside.arch}", field="build_id",
                      hint=f"recompile with arch='{oside.arch}'")
    sig = _signature(signature_json, oside.arch)
    explicit = []
    raw_cases = _parse_json_arg(cases_json, "cases_json")
    if raw_cases is not None:
        explicit = parse_case_list(sig, raw_cases, origin="explicit",
                                   where="cases_json")
    replay = []
    if cases_path:
        replay = read_cases_jsonl(sig, _read_artifact_text(
            ctx, cases_path, "cases_path"))
    rc = _rcfg(ctx)
    n_cases = rc.default_cases if cases < 0 else cases
    if not 0 <= min_coverage <= 1:
        raise bad_arg("min_coverage: 0..1", field="min_coverage")
    if not 0 < timeout_s <= 3600:
        raise bad_arg("timeout_s: 0..3600", field="timeout_s")
    opts = VerifyOptions(cases=n_cases, seed=seed, explicit=explicit,
                         replay=replay, boundary=boundary,
                         timeout_s=timeout_s, min_coverage=min_coverage,
                         probe=probe, max_insns=max_insns or rc.max_insns,
                         inputs=inputs)
    report = await asyncio.to_thread(run_verify, oside, rside, sig, opts)
    report["original"] = {**oinfo, **report["original"]}
    report["reconstruction"] = {
        "build_id": build_id, "export": want,
        "toolchain": meta.get("toolchain"), "version": meta.get("version"),
        "compile_flags": meta.get("compile_flags"),
        **report["reconstruction"]}
    report["signature"] = sig.to_json()
    run_id, run_dir = _rep.new_run_dir(_rep.runs_root(_artifacts_dir(ctx)))
    report["run_id"] = run_id
    full = dict(report)
    full["_cases"] = report.pop("_cases")
    full["_mismatches"] = report.pop("_mismatches")
    await asyncio.to_thread(_rep.write_run, run_dir, full)
    rel = f"reconstruct/runs/{run_id}"
    report["files"] = {"report": f"{rel}/report.json",
                       "inputs": f"{rel}/inputs.jsonl",
                       "mismatches": f"{rel}/mismatches.jsonl"}
    if compiled is not None:
        report["compiled"] = {"build_id": build_id,
                              "cached": compiled.get("cached", False),
                              "diagnostics": compiled.get("diagnostics", [])}
    replay_opts: dict = {"boundary": False}
    if max_insns:
        replay_opts["max_insns"] = max_insns
    replay_args: dict = {"func": f"0x{oside.func_va:x}",
                         "build_id": build_id, "export": want,
                         "signature_json": json.dumps(sig.to_json()),
                         "cases_path": f"{rel}/inputs.jsonl", "cases": 0,
                         "options_json": replay_opts, "seed": seed}
    for k in ("sha256", "path", "module", "pid", "name"):
        if loader.get(k):
            replay_args[k] = loader[k]
    if loader["source"] != "artifact":
        replay_args["source"] = loader["source"]
    report["next"] = {"replay": {"tool": "reconstruct_manage",
                                 "action": "verify", "args": replay_args}}
    return _out(report)
