"""reconstruct.verify — the acceptance bug matrix on hand-assembled pairs.

Every seeded bug must come back ``mismatch`` naming the first differing
output; an equivalent pair must come back
``equivalent_on_tested_inputs``; unsupported constructs, all-fault runs,
an unstable original, low coverage and the time budget must all come
back ``inconclusive`` with a reason — never a match.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("unicorn")
pytest.importorskip("keystone")

import _pebuild as pb  # noqa: E402

from pry.analysis import pe  # noqa: E402
from pry.analysis.engine import ImageView  # noqa: E402
from pry.reconstruct.harness import Side  # noqa: E402
from pry.reconstruct.signature import parse_signature  # noqa: E402
from pry.reconstruct.verify import (VerifyOptions, run_call,  # noqa: E402
                                       run_verify)

API = {"KERNEL32.dll": ["GetTickCount", "Sleep"]}


def side(label: str, src, machine: str = "x64", **kw) -> Side:
    def code(lay):
        text = src(lay) if callable(src) else src
        return pb.asm(text, machine, lay.text_va)
    built = pb.build(machine=machine, code=code, **kw)
    return Side(label, ImageView(pe.parse(built.data)), built.layout.text_va,
                machine)


def verify(orig, recon, spec, machine="x64", **opts):
    sig = parse_signature(spec, arch=machine)
    kw = dict(cases=200, seed=3)
    kw.update(opts)
    o = side("original", orig, machine, **(kw.pop("o_kw", {})))
    r = side("reconstruction", recon, machine, **(kw.pop("r_kw", {})))
    rep = run_verify(o, r, sig, VerifyOptions(**kw))
    rep.pop("_cases")
    rep.pop("_mismatches")
    return rep


U32_X = {"ret": "u32", "params": [{"name": "x", "type": "u32"}]}
U32_XY = {"ret": "u32", "params": [{"name": "x", "type": "u32"},
                                   {"name": "y", "type": "u32"}]}
SUM = {"ret": "u32", "params": [
    {"name": "buf", "type": "buf_in", "size": [0, 64]},
    {"name": "n", "type": "u64", "len_of": "buf"}]}


def test_equivalent_pair_passes_with_coverage() -> None:
    orig = "imul eax, ecx, 31\nxor eax, 0xA5A5A5A5\nret"
    recon = "mov eax, ecx\nshl eax, 5\nsub eax, ecx\nxor eax, 0xA5A5A5A5\nret"
    rep = verify(orig, recon, U32_X)
    assert rep["verdict"] == "equivalent_on_tested_inputs", rep
    assert rep["mismatched"] == 0 and rep["matched"] == rep["cases_run"]
    assert rep["coverage"]["blocks_hit"] == rep["coverage"]["blocks_total"]
    assert rep["not_compared"]


SUM_ORIG = """
    xor eax, eax
    xor r8d, r8d
top:
    cmp r8, rdx
    jae done
    movzx r9d, byte ptr [rcx+r8]
    add eax, r9d
    inc r8
    jmp top
done:
    ret
"""


@pytest.mark.parametrize("name,orig,recon,spec,field", [
    ("loop bound off by one", SUM_ORIG,
     SUM_ORIG.replace("jae done", "ja done"), SUM, "outcome"),
    ("signed compare", "xor eax, eax\ncmp ecx, edx\nsetb al\nret",
     "xor eax, eax\ncmp ecx, edx\nsetl al\nret", U32_XY, "ret"),
    ("missing final transform", "imul eax, ecx, 31\nxor eax, 0xA5A5A5A5\nret",
     "imul eax, ecx, 31\nret", U32_X, "ret"),
    ("arithmetic shift", "mov eax, ecx\nshr eax, 3\nret",
     "mov eax, ecx\nsar eax, 3\nret", U32_X, "ret"),
    ("truncated accumulator", SUM_ORIG,
     SUM_ORIG.replace("add eax, r9d", "add al, r9b"), SUM, "ret"),
])
def test_bug_matrix_value_bugs(name, orig, recon, spec, field) -> None:
    rep = verify(orig, recon, spec)
    assert rep["verdict"] == "mismatch", (name, rep.get("reasons"))
    assert rep["mismatches"][0]["field"] == field, (name, rep["mismatches"][0])


def test_bug_matrix_uninitialized_local() -> None:
    orig = "mov eax, ecx\nret"
    recon = """
        cmp ecx, 5
        jbe skip
        mov dword ptr [rsp-8], 0
    skip:
        mov eax, ecx
        add eax, dword ptr [rsp-8]
        ret
    """
    rep = verify(orig, recon, U32_X)
    assert rep["verdict"] == "mismatch"
    assert rep["mismatches"][0]["field"] == "stability"
    # without the probe the bug still shows, but only as a value diff
    rep = verify(orig, recon, U32_X, probe=False)
    assert rep["verdict"] == "mismatch"


def test_bug_matrix_output_overrun_hits_the_guard_page() -> None:
    fill = """
        xor eax, eax
    top:
        cmp rax, rdx
        {cond} done
        mov byte ptr [rcx+rax], 0x5A
        inc rax
        jmp top
    done:
        ret
    """
    spec = {"ret": "void", "params": [
        {"name": "out", "type": "buf_out", "size": [0, 32]},
        {"name": "n", "type": "u64", "len_of": "out"}]}
    rep = verify(fill.format(cond="jae"), fill.format(cond="ja"), spec)
    assert rep["verdict"] == "mismatch"
    first = rep["mismatches"][0]
    assert first["field"] == "outcome"
    assert first["reconstruction"].startswith("fault:write")


def test_bug_matrix_api_order() -> None:
    def call(first, second):
        def src(lay):
            return f"""
                sub rsp, 0x28
                mov rax, {lay.iat['KERNEL32.dll!' + first]:#x}
                call qword ptr [rax]
                mov rax, {lay.iat['KERNEL32.dll!' + second]:#x}
                call qword ptr [rax]
                xor eax, eax
                add rsp, 0x28
                ret
            """
        return src
    rep = verify(call("GetTickCount", "Sleep"), call("Sleep", "GetTickCount"),
                 {"ret": "u32", "params": []},
                 o_kw={"imports": API}, r_kw={"imports": API})
    assert rep["verdict"] == "mismatch"
    m = rep["mismatches"][0]
    assert m["field"] == "api" and m["offset"] == 0
    assert m["original"][:2] == ["GetTickCount", "Sleep"]


def test_x86_stdcall_vs_cdecl_is_a_cleanup_mismatch() -> None:
    spec = {"ret": "i32", "cc": "stdcall", "params": [
        {"name": "a", "type": "i32"}, {"name": "b", "type": "i32"}]}
    rep = verify("mov eax, [esp+4]\nadd eax, [esp+8]\nret 8",
                 "mov eax, [esp+4]\nadd eax, [esp+8]\nret", spec, "x86")
    assert rep["verdict"] == "mismatch"
    assert rep["mismatches"][0]["field"] == "cleanup"
    ok = verify("mov eax, [esp+4]\nadd eax, [esp+8]\nret 8",
                "mov eax, [esp+8]\nadd eax, [esp+4]\nret 8", spec, "x86")
    assert ok["verdict"] == "equivalent_on_tested_inputs"


@pytest.mark.parametrize("body,why", [
    ("mov eax, 0x55\nsyscall\nret", "unsupported:syscall"),
    ("vaddps ymm0, ymm1, ymm2\nmov eax, ecx\nret", "unsupported:opcode"),
    ("mov rax, 0x12345000\ncall rax\nret", "unresolved_call"),
    ("top:\njmp top", "cap"),
])
def test_unsupported_constructs_are_inconclusive(body, why) -> None:
    rep = verify(body, body, U32_X, cases=10, max_insns=50_000)
    assert rep["verdict"] == "inconclusive"
    assert rep["matched"] == 0 and rep["unsupported"] == rep["cases_run"]
    assert why in " ".join(rep["reasons"])


def test_all_fault_runs_are_inconclusive() -> None:
    body = "xor eax, eax\nmov eax, [rax]\nret"
    rep = verify(body, body, U32_X, cases=10)
    assert rep["verdict"] == "inconclusive"
    assert "faulted or trapped" in " ".join(rep["reasons"])


def test_unstable_original_is_inconclusive() -> None:
    body = "mov eax, dword ptr [rsp-0x40]\nret"
    rep = verify(body, "mov eax, ecx\nret", U32_X, cases=10)
    assert rep["verdict"] == "inconclusive"
    assert rep["unstable"] == rep["cases_run"]
    assert "missing a parameter" in " ".join(rep["reasons"])


def test_low_coverage_is_inconclusive() -> None:
    body = """
        cmp ecx, 0x7fffffff
        ja big
        mov eax, 1
        ret
    big:
        mov eax, 2
        ret
    """
    spec = {"ret": "u32", "params": [{"name": "x", "type": "u32",
                                      "range": [0, 100]}]}
    rep = verify(body, body, spec, cases=20, min_coverage=0.9)
    assert rep["verdict"] == "inconclusive"
    assert rep["coverage"]["blocks_hit"] < rep["coverage"]["blocks_total"]
    assert "min_coverage" in " ".join(rep["reasons"])


def test_a_shared_tail_does_not_cover_the_block_before_it() -> None:
    """The engine leaves `mov eax, 1` running on into `done: ret`, which
    is also a block of its own. Executing only the shared `ret` must not
    count the `mov` block as covered."""
    body = """
        xor eax, eax
        cmp ecx, 0x1337BEEF
        jne done
        mov eax, 1
    done:
        ret
    """
    rep = verify(body, body, U32_X, cases=50, inputs="random")
    cov = rep["coverage"]
    assert (cov["blocks_hit"], cov["blocks_total"]) == (2, 3), cov
    assert [u["first"] for u in cov["uncovered"]] == ["mov eax, 1"]


def test_time_budget_gives_partial_inconclusive() -> None:
    body = "mov eax, ecx\nret"
    rep = verify(body, body, U32_X, cases=10_000, timeout_s=0.2)
    assert rep["partial"] is True and rep["verdict"] == "inconclusive"
    assert rep["cases_run"] < rep["cases_total"]


def test_explicit_cases_run_first_and_call_compares() -> None:
    sig = parse_signature(U32_X, arch="x64")
    o = side("original", "mov eax, ecx\nadd eax, 1\nret")
    r = side("reconstruction", "lea eax, [rcx+1]\nret")
    rep = run_verify(o, r, sig, VerifyOptions(
        cases=0, boundary=False, explicit=[{"x": 41}, {"x": 0xFFFFFFFF}]))
    assert rep["cases_run"] == 2 and rep["verdict"] == \
        "equivalent_on_tested_inputs"
    out = run_call([o, r], sig, {"x": 41})
    assert out["match"] is True
    assert out["original"]["ret"]["value"] == 42


def test_thousand_cases_of_a_loop_within_budget() -> None:
    """Acceptance 6: 1,000 cases of a few-hundred-instruction function
    well inside 60 s."""
    spec = {"ret": "u32", "params": [
        {"name": "buf", "type": "buf_in", "size": [0, 128]},
        {"name": "n", "type": "u64", "len_of": "buf"}]}
    rep_t = time.monotonic()
    rep = verify(SUM_ORIG, SUM_ORIG, spec, cases=1000)
    took = time.monotonic() - rep_t
    assert rep["verdict"] == "equivalent_on_tested_inputs"
    # duplicate random cases are skipped, so "1000" yields ~1000 distinct
    assert rep["cases_run"] == rep["cases_total"] >= 950
    assert took < 60, took
