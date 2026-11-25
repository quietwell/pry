"""reconstruct_manage through the MCP server (acceptance 4 and 5).

* compile refuses with kind='not_allowed' and names
  security.allow_host_compile while the gate is off; verify with code=
  refuses the same way; call/verify against artifacts need no gate.
* verify writes report.json / inputs.jsonl / mismatches.jsonl under
  artifacts/reconstruct/runs/<run_id>/ and the inputs replay.
* nothing in pry/reconstruct loads a build output natively.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from pathlib import Path

import pytest

import _pebuild as pb
from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.tools import Context, build_server
from pry.ownership import OwnershipRegistry
from pry.session import Session

SIG = json.dumps({"ret": "u32", "params": [{"name": "x", "type": "u32"}]})


async def _ctx(tmp_path, *, gate: bool = False):
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.security.allow_host_compile = gate
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    art = tmp_path / "artifacts"
    (art / "spill").mkdir(parents=True, exist_ok=True)
    clients = ClientRegistry()
    ctx = Context(cfg=cfg, session=Session(cfg),
                  ledger=FindingsLedger(art / "findings.db"),
                  bridge=IdaBridge(IdaConfigLite.from_config(cfg.ida), art),
                  clients=clients,
                  leases=LeaseManager(publish_event=lambda ev:
                                      asyncio.create_task(
                                          clients.publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx), art


async def _call(server, args: dict) -> dict:
    token = CLIENT_ID.set("peer-test")
    try:
        result = await server.call_tool("reconstruct_manage", args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        merged.update(body["error"])
    merged.setdefault("ok", body.get("ok"))
    merged["_provenance"] = body.get("provenance")
    return merged


def _asm_image(src: str, **kw) -> bytes:
    return pb.build(machine="x64",
                    code=lambda lay: pb.asm(src, "x64", lay.text_va),
                    exports={"f": 0}, **kw).data


def _seed_original(art: Path, src: str) -> tuple[str, str]:
    data = _asm_image(src)
    p = art / "dumps" / "orig.dll"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return "dumps/orig.dll", hashlib.sha256(data).hexdigest()


def _seed_build(art: Path, src: str, bid: str = "0123456789abcdef") -> str:
    """A build dir as compile would leave it (no compiler needed)."""
    d = art / "reconstruct" / "builds" / bid
    d.mkdir(parents=True)
    (d / "recon.dll").write_bytes(_asm_image(src))
    (d / "meta.json").write_text(json.dumps({
        "build_id": bid, "toolchain": "msvc", "version": "test",
        "arch": "x64", "exports": {"f": "0x1000"},
        "compile_flags": ["/O2"]}))
    return bid


async def test_actions_and_toolchains_report_the_gate(tmp_path) -> None:
    _ctx_, server, _art = await _ctx(tmp_path)
    out = await _call(server, {"action": "actions"})
    assert out["ok"] is True
    out = await _call(server, {"action": "toolchains"})
    assert out["ok"] is True and out["allow_host_compile"] is False
    names = {t["name"] for t in out["toolchains"]}
    assert {"msvc", "clang-cl"} <= names


async def test_compile_refused_while_the_gate_is_off(tmp_path) -> None:
    _c, server, _art = await _ctx(tmp_path)
    out = await _call(server, {"action": "compile", "exports": ["f"],
                               "code": "int f(void) { return 1; }"})
    assert out["ok"] is False and out["kind"] == "not_allowed"
    assert "security.allow_host_compile" in out["hint"]
    path, _sha = _seed_original(tmp_path / "artifacts", "mov eax, ecx\nret")
    out = await _call(server, {"action": "verify", "path": path, "func": "f",
                               "code": "int f(int x) { return x; }",
                               "export": "f", "signature_json": SIG})
    assert out["kind"] == "not_allowed"


async def test_compile_guard_runs_before_the_toolchain(tmp_path) -> None:
    _c, server, _art = await _ctx(tmp_path, gate=True)
    out = await _call(server, {"action": "compile", "exports": ["f"],
                               "code": '#include "C:/secret.txt"\n'})
    assert out["ok"] is False and out["kind"] == "source_rejected"


async def test_call_needs_no_gate(tmp_path) -> None:
    pytest.importorskip("unicorn")
    pytest.importorskip("keystone")
    _c, server, art = await _ctx(tmp_path)
    path, sha = _seed_original(art, "lea eax, [rcx+5]\nret")
    out = await _call(server, {"action": "call", "sha256": sha, "func": "f",
                               "signature_json": SIG, "args_json": {"x": 37}})
    assert out["ok"] is True, out
    assert out["original"]["outcome"] == "returned"
    assert out["original"]["ret"]["value"] == 42
    assert out["_provenance"]["untrusted_content"] is True
    bad = await _call(server, {"action": "call", "path": path,
                               "func": "nope", "signature_json": SIG,
                               "args_json": {"x": 1}})
    assert bad["kind"] == "bad_arg" and "valid: f" in bad["hint"]


async def test_verify_writes_the_run_and_replays(tmp_path) -> None:
    pytest.importorskip("unicorn")
    pytest.importorskip("keystone")
    _c, server, art = await _ctx(tmp_path)
    path, _sha = _seed_original(art, "lea eax, [rcx+5]\nret")
    bid = _seed_build(art, "mov eax, ecx\nadd eax, 5\nret")
    out = await _call(server, {"action": "verify", "path": path,
                               "func": "0x180001000", "build_id": bid,
                               "export": "f", "signature_json": SIG,
                               "cases": 50, "seed": 9})
    assert out["ok"] is True, out
    assert out["verdict"] == "equivalent_on_tested_inputs"
    assert out["seed"] == 9 and re.fullmatch(r"r\d{4}", out["run_id"])
    run_dir = art / out["files"]["report"].rsplit("/", 1)[0]
    rep = json.loads((run_dir / "report.json").read_text())
    assert rep["verdict"] == out["verdict"]
    lines = (run_dir / "inputs.jsonl").read_text().splitlines()
    assert len(lines) == out["cases_run"]
    replay = out["next"]["replay"]["args"]
    assert replay["cases_path"] == out["files"]["inputs"]
    again = await _call(server, {"action": "verify", **replay})
    assert again["ok"] is True and again["cases_run"] == len(lines)
    assert again["run_id"] != out["run_id"]


async def test_builds_and_runs_use_the_anchored_store(tmp_path,
                                                       monkeypatch) -> None:
    """A relative artifacts.dir is anchored like every other store
    (PRY_ARTIFACTS_DIR, else the repo root), never the server's cwd.
    The start script boots the server from orchestrator/, where a
    cwd-relative store hid builds and broke the cases_path= replay."""
    pytest.importorskip("unicorn")
    pytest.importorskip("keystone")
    ctx, server, art = await _ctx(tmp_path)
    monkeypatch.setenv("PRY_ARTIFACTS_DIR", str(art))
    ctx.cfg.artifacts.dir = "artifacts"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    path, _sha = _seed_original(art, "lea eax, [rcx+5]\nret")
    bid = _seed_build(art, "mov eax, ecx\nadd eax, 5\nret")
    out = await _call(server, {"action": "verify", "path": path, "func": "f",
                               "build_id": bid, "export": "f",
                               "signature_json": SIG, "cases": 10})
    assert out["ok"] is True, out
    assert (art / out["files"]["inputs"]).is_file()
    again = await _call(server, {"action": "verify",
                                 **out["next"]["replay"]["args"]})
    assert again["ok"] is True, again
    assert again["cases_run"] == out["cases_run"]
    assert not (elsewhere / "artifacts").exists()


async def test_verify_reports_a_mismatch(tmp_path) -> None:
    pytest.importorskip("unicorn")
    pytest.importorskip("keystone")
    _c, server, art = await _ctx(tmp_path)
    path, _sha = _seed_original(art, "lea eax, [rcx+5]\nret")
    bid = _seed_build(art, "lea eax, [rcx+6]\nret")
    out = await _call(server, {"action": "verify", "path": path, "func": "f",
                               "build_id": bid, "signature_json": SIG,
                               "cases": 20})
    assert out["verdict"] == "mismatch"
    first = out["mismatches"][0]
    assert first["field"] == "ret" and "inputs" in first
    run_dir = art / out["files"]["mismatches"].rsplit("/", 1)[0]
    rows = (run_dir / "mismatches.jsonl").read_text().splitlines()
    assert rows and json.loads(rows[0])["field"] == "ret"


def test_reconstruct_never_loads_build_outputs_natively() -> None:
    import pry.reconstruct as pkg
    root = Path(pkg.__file__).parent
    # Any ctypes use, native DLL loaders, or shell launches. (The stub
    # table names "LoadLibraryA" as an API to stub; only a call counts.)
    pattern = re.compile(r"\bctypes\b|\bwindll\b|\bWinDLL\b|\bCDLL\b|"
                         r"os\.startfile|os\.system|\bLoadLibrary\w*\s*\(")
    hits = [f"{p.name}:{n}" for p in root.rglob("*.py")
            for n, line in enumerate(p.read_text(encoding="utf-8")
                                     .splitlines(), 1)
            if pattern.search(line)]
    assert not hits, hits
    tool = Path(pkg.__file__).parents[1] / "mcp" / "tools" / "reconstruct.py"
    assert not pattern.search(tool.read_text(encoding="utf-8"))


def _toolchain_available(name: str) -> bool:
    from pry.reconstruct import toolchain as tcm
    try:
        return any(t.name == name and t.available
                   for t in tcm.discover(None, allow_exec=True))
    except Exception:  # pragma: no cover
        return False


@pytest.mark.parametrize("toolchain", [
    pytest.param("msvc", marks=pytest.mark.skipif(
        not _toolchain_available("msvc"), reason="no MSVC toolchain")),
    pytest.param("clang-cl", marks=pytest.mark.skipif(
        not _toolchain_available("clang-cl"), reason="no clang-cl")),
])
async def test_compile_then_verify_through_the_tool(tmp_path,
                                                    toolchain) -> None:
    pytest.importorskip("unicorn")
    pytest.importorskip("keystone")
    _c, server, art = await _ctx(tmp_path, gate=True)
    path, sha = _seed_original(art, "lea eax, [rcx+5]\nret")
    code = '#include "pry_recon.h"\nu32 f(u32 x) { return x + 5; }\n'
    out = await _call(server, {"action": "compile", "exports": ["f"],
                               "code": code, "toolchain": toolchain})
    assert out["ok"] is True, out
    bid = out["build_id"]
    assert out["toolchain"] == toolchain and out["cached"] is False
    assert out["next"]["verify"]["args"]["build_id"] == bid
    again = await _call(server, {"action": "compile", "exports": ["f"],
                                 "code": code, "toolchain": toolchain})
    assert again["cached"] is True and again["build_id"] == bid
    rep = await _call(server, {"action": "verify", "sha256": sha,
                               "func": "f", "build_id": bid, "export": "f",
                               "signature_json": SIG, "cases": 100})
    assert rep["verdict"] == "equivalent_on_tested_inputs", rep
    assert rep["reconstruction"]["toolchain"] == toolchain
    # verify with code= compiles first (gate on) and reports the build
    rep2 = await _call(server, {"action": "verify", "path": path,
                                "func": "f", "export": "f",
                                "toolchain": toolchain,
                                "code": '#include "pry_recon.h"\n'
                                        "u32 f(u32 x) { return x + 6; }\n",
                                "signature_json": SIG, "cases": 20})
    assert rep2["verdict"] == "mismatch"
    assert rep2["compiled"]["build_id"] != bid
    assert rep2["reconstruction"]["toolchain"] == toolchain


def test_options_json_is_validated_key_by_key() -> None:
    from pry.mcp.tools.reconstruct import _options
    from pry.reconstruct.errors import ReconError
    o = _options({"opt": "Od", "defines": ["X=1"], "probe": False})
    assert (o["opt"], o["defines"], o["probe"], o["boundary"]) == \
        ("Od", ["X=1"], False, True)
    assert _options("") == _options(None) == _options("{}")
    with pytest.raises(ReconError) as ei:
        _options({"optt": "O1"})
    assert ei.value.field == "options_json.optt" and "opt" in ei.value.closest
    for bad in ({"probe": "yes"}, {"max_insns": -1}, {"defines": "X"},
                {"opt": 2}):
        with pytest.raises(ReconError):
            _options(bad)
