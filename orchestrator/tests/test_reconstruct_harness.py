"""reconstruct.harness on hand-assembled images (no compiler needed).

Covers register/stack argument placement and entry alignment (Win64 and
the four x86 conventions), narrow-argument garbage, float returns (XMM0
and the x87 trampoline), EDX:EAX returns, guard pages, regular /
delay-load / CFG stubs, the fake TEB on both arches, every outcome
class, and the coverage mapping.
"""

from __future__ import annotations

import struct

import pytest

pytest.importorskip("unicorn")
pytest.importorskip("keystone")

import _pebuild as pb  # noqa: E402

from pry.analysis import pe  # noqa: E402
from pry.analysis.engine import ImageView  # noqa: E402
from pry.reconstruct.coverage import coverage, static_function  # noqa: E402
from pry.reconstruct.harness import Harness, Side, choose_arena  # noqa: E402
from pry.reconstruct.inputs import parse_case_list  # noqa: E402
from pry.reconstruct.signature import (bits_float, float_bits,  # noqa: E402
                                          parse_signature)


def make(machine: str, src, sig_spec: dict, **kw):
    """Build an image whose .text starts with *src*; return a harness."""
    def code(lay):
        text = src(lay) if callable(src) else src
        return pb.asm(text, machine, lay.text_va)
    built = pb.build(machine=machine, code=code, **kw)
    img = pe.parse(built.data)
    view = ImageView(img)
    sig = parse_signature(sig_spec, arch=machine)
    side = Side("original", view, built.layout.text_va, machine)
    h = Harness(side, sig, choose_arena(machine, [side.span()]))
    return h, sig, built


def run(h, sig, args: dict, fill: int = 0, case: int = 0):
    vals = parse_case_list(sig, [args], origin="explicit", where="t")[0]
    return h.run(vals, case, fill)


def body(r, name):
    pre, n = r.windows[name]
    return r.buffers[name][pre:pre + n]


# ---------------------------------------------------------------- x64 --

def test_x64_register_and_stack_args_and_alignment() -> None:
    src = """
        mov rax, [rsp+0x30]
        mov [rax], rcx
        mov [rax+8], rdx
        mov [rax+16], r8
        mov [rax+24], r9
        mov r10, [rsp+0x28]
        mov [rax+32], r10
        mov rax, rsp
        and eax, 0xf
        ret
    """
    spec = {"ret": "u64", "params": [
        {"name": n, "type": "u64"} for n in "abcde"] + [
        {"name": "out", "type": "buf_out", "size": 40}]}
    h, sig, _ = make("x64", src, spec)
    r = run(h, sig, {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "out": 40})
    assert r.outcome == "returned", r.detail
    assert body(r, "out") == struct.pack("<5Q", 1, 2, 3, 4, 5)
    assert r.ret == 8                      # RSP ≡ 8 (mod 16) at entry
    assert r.abi_clobbered == ()


def test_x64_narrow_args_carry_garbage_upper_bits() -> None:
    h, sig, _ = make("x64", "mov rax, rcx\nret",
                     {"ret": "u64", "params": [{"name": "x", "type": "u8"}]})
    a = run(h, sig, {"x": 0x5A}, fill=0)
    b = run(h, sig, {"x": 0x5A}, fill=1)
    assert a.ret & 0xFF == 0x5A == b.ret & 0xFF
    assert a.ret != b.ret                  # upper bits differ per fill
    h2, sig2, _ = make("x64", "mov rax, rcx\nret",
                       {"ret": "u8", "params": [{"name": "x", "type": "u8"}]})
    assert run(h2, sig2, {"x": 7}, 0).ret == run(h2, sig2, {"x": 7}, 1).ret


def test_x64_float_args_and_return() -> None:
    h, sig, _ = make("x64", "addsd xmm0, xmm1\nret",
                     {"ret": "f64", "params": [{"name": "a", "type": "f64"},
                                               {"name": "b", "type": "f64"}]})
    r = run(h, sig, {"a": 1.25, "b": 2.5})
    assert bits_float(r.ret, 8) == 3.75


def test_x64_guard_page_catches_a_one_byte_overrun() -> None:
    src = """
        xor eax, eax
    top:
        cmp rax, rdx
        ja done
        mov byte ptr [rcx+rax], 0x41
        inc rax
        jmp top
    done:
        ret
    """
    spec = {"ret": "void", "params": [
        {"name": "buf", "type": "buf_out", "size": [0, 32]},
        {"name": "n", "type": "u64", "len_of": "buf"}]}
    h, sig, _ = make("x64", src, spec)
    r = run(h, sig, {"buf": 16})
    assert r.outcome == "fault:write"
    lo, hi = h.slots["buf"]
    assert r.fault_va == hi                 # first byte of the guard page


def test_x64_iat_delay_and_cfg_stubs() -> None:
    def src(lay):
        return f"""
            push rbx
            sub rsp, 0x20
            mov rbx, rcx
            mov rcx, rbx
            lea rdx, [rbx+8]
            mov r8d, 8
            mov rax, {lay.iat['VCRUNTIME140.dll!memcpy']:#x}
            call qword ptr [rax]
            mov rax, {lay.cfg_check_slot:#x}
            mov rax, [rax]
            call rax
            mov rax, {lay.delay_iat['USER32.dll!GetDC']:#x}
            call qword ptr [rax]
            mov rcx, rax
            mov rax, {lay.iat['KERNEL32.dll!GetTickCount']:#x}
            call qword ptr [rax]
            add rax, rcx
            add rsp, 0x20
            pop rbx
            ret
        """
    spec = {"ret": "u64", "params": [
        {"name": "buf", "type": "buf_inout", "size": 16}],
        "stubs": {"GetTickCount": 100, "USER32!GetDC": 5}}
    h, sig, built = make("x64", src, spec,
                         imports={"VCRUNTIME140.dll": ["memcpy"],
                                  "KERNEL32.dll": ["GetTickCount"]},
                         delay_imports={"USER32.dll": ["GetDC"]},
                         cfg=True, cfg_initial=0x7FF00000)
    data = bytes(range(16))
    r = run(h, sig, {"buf": data.hex()})
    assert r.outcome == "returned", (r.outcome, r.detail)
    assert body(r, "buf") == data[8:16] + data[8:16]
    assert r.ret == 105
    assert r.api == ("GetDC", "GetTickCount")
    assert r.api_semantic == {"memcpy": 1}


def test_x64_teb_self_pointer() -> None:
    h, sig, _ = make("x64", "mov rax, qword ptr gs:[0x30]\nret",
                     {"ret": "u64", "params": []})
    # keystone emits the moffs form here, which Unicorn reads without the
    # GS base (Phase 0); encode the SIB form compilers use instead.
    h2_src = bytes.fromhex("65488B042530000000C3")
    built = pb.build(machine="x64", code=h2_src)
    side = Side("original", ImageView(pe.parse(built.data)),
                built.layout.text_va, "x64")
    h2 = Harness(side, sig, choose_arena("x64", [side.span()]))
    r = h2.run({}, 0, 0)
    assert r.outcome == "returned" and r.ret == h2.data_va


@pytest.mark.parametrize("src,outcome,detail", [
    ("xor ecx, ecx\nmov eax, 1\nxor edx, edx\ndiv ecx\nret",
     "cpu_exception", "divide_error"),
    ("ud2", "cpu_exception", "invalid_opcode"),
    ("int3\nret", "cpu_exception", "int3"),
    ("vaddps ymm0, ymm1, ymm2\nret", "unsupported:opcode", "vaddps"),
    ("mov eax, 0x55\nsyscall\nret", "unsupported:syscall", "syscall"),
    ("mov rax, 0x12345000\njmp rax", "unresolved_call", ""),
    ("xor eax, eax\nmov rax, [rax]\nret", "fault:read", ""),
    ("top:\njmp top", "cap", "instruction limit"),
])
def test_x64_outcome_classes(src, outcome, detail) -> None:
    h, sig, _ = make("x64", src, {"ret": "u64", "params": []})
    h.max_insns = 20_000
    r = h.run({}, 0, 0)
    assert r.outcome == outcome, (r.outcome, r.detail)
    assert detail in r.detail


def test_x64_coverage_maps_static_blocks() -> None:
    src = """
        cmp ecx, 10
        jb small
        mov eax, 2
        ret
    small:
        mov eax, 1
        ret
    """
    h, sig, built = make("x64", src, {"ret": "u32", "params": [
        {"name": "x", "type": "u32"}]})
    sf = static_function(h.side.view, h.side.func_va, bits=64)
    assert len(sf.blocks) == 3
    h.set_coverage(True, (sf.lo, sf.hi))
    for x in (1, 2, 3):
        assert run(h, sig, {"x": x}).ret == 1
    cov = coverage(sf, h.tbs)
    assert (cov["blocks_hit"], cov["blocks_total"]) == (2, 3)
    assert cov["uncovered"][0]["first"].startswith("mov eax, 2")
    run(h, sig, {"x": 50})
    assert coverage(sf, h.tbs)["blocks_hit"] == 3


def test_globals_are_restored_between_runs() -> None:
    def src(lay):
        return f"""
            mov rdx, {lay.data_va:#x}
            mov eax, [rdx]
            add eax, ecx
            mov [rdx], eax
            ret
        """
    h, sig, _ = make("x64", src, {"ret": "u32", "params": [
        {"name": "x", "type": "u32"}]}, data=struct.pack("<I", 1000))
    for _ in range(3):
        r = run(h, sig, {"x": 5})
        assert r.ret == 1005 and r.image_writes == 1


# ---------------------------------------------------------------- x86 --

@pytest.mark.parametrize("cc,src,args,expect,cleanup", [
    ("cdecl", "mov eax, [esp+4]\nsub eax, [esp+8]\nret",
     {"a": 10, "b": 3}, 7, 0),
    ("stdcall", "mov eax, [esp+4]\nsub eax, [esp+8]\nret 8",
     {"a": 10, "b": 3}, 7, 8),
])
def test_x86_stack_conventions(cc, src, args, expect, cleanup) -> None:
    h, sig, _ = make("x86", src, {"ret": "i32", "cc": cc, "params": [
        {"name": "a", "type": "i32"}, {"name": "b", "type": "i32"}]})
    r = run(h, sig, args)
    assert (r.outcome, r.ret, r.cleanup) == ("returned", expect, cleanup)


def test_x86_fastcall_and_thiscall() -> None:
    h, sig, _ = make("x86", "mov eax, ecx\nimul eax, edx\nadd eax, [esp+4]\n"
                     "ret 4", {"ret": "i32", "cc": "fastcall", "params": [
                         {"name": "a", "type": "i32"},
                         {"name": "b", "type": "i32"},
                         {"name": "c", "type": "i32"}]})
    r = run(h, sig, {"a": 6, "b": 7, "c": 8})
    assert (r.ret, r.cleanup) == (50, 4)
    h, sig, _ = make("x86", "mov eax, [ecx]\nadd eax, [esp+4]\nret 4",
                     {"ret": "u32", "cc": "thiscall", "params": [
                         {"name": "self", "type": "buf_in", "size": 4},
                         {"name": "a", "type": "u32"}]})
    r = run(h, sig, {"self": struct.pack("<I", 1000).hex(), "a": 23})
    assert (r.ret, r.cleanup) == (1023, 4)


def test_x86_x87_float_return_and_edx_eax() -> None:
    h, sig, _ = make("x86", "fld qword ptr [esp+4]\nfadd qword ptr [esp+12]"
                     "\nret", {"ret": "f64", "params": [
                         {"name": "a", "type": "f64"},
                         {"name": "b", "type": "f64"}]})
    r = run(h, sig, {"a": 0.5, "b": 0.25})
    assert bits_float(r.ret, 8) == 0.75
    h, sig, _ = make("x86", "fld dword ptr [esp+4]\nfadd st(0), st(0)\nret",
                     {"ret": "f32", "params": [{"name": "a", "type": "f32"}]})
    r = run(h, sig, {"a": 1.5})
    assert r.ret == float_bits(3.0, 4)
    h, sig, _ = make("x86", "mov eax, [esp+4]\nmov edx, [esp+8]\nadd eax, 1"
                     "\nadc edx, 0\nret", {"ret": "u64", "params": [
                         {"name": "a", "type": "u64"}]})
    assert run(h, sig, {"a": 0xFFFFFFFF}).ret == 0x100000000


def test_x86_teb_through_fs() -> None:
    h, sig, _ = make("x86", "mov eax, dword ptr fs:[0x18]\nret",
                     {"ret": "u32", "params": []})
    assert h.run({}, 0, 0).ret == h.data_va


def test_x86_alldiv_semantic_stub() -> None:
    def src(lay):
        return f"""
            push dword ptr [esp+16]
            push dword ptr [esp+16]
            push dword ptr [esp+16]
            push dword ptr [esp+16]
            call dword ptr [{lay.iat['ntdll.dll!_alldiv']:#x}]
            ret
        """
    h, sig, _ = make("x86", src, {"ret": "i64", "params": [
        {"name": "a", "type": "i64"}, {"name": "b", "type": "i64"}]},
        imports={"ntdll.dll": ["_alldiv"]})
    r = run(h, sig, {"a": -100, "b": 7})
    assert r.outcome == "returned" and r.ret == (-14) & ((1 << 64) - 1)
    assert r.cleanup == 0 and r.api_semantic == {"_alldiv": 1}
    r = run(h, sig, {"a": 1, "b": 0})
    assert r.outcome == "cpu_exception" and "divide_error" in r.detail
