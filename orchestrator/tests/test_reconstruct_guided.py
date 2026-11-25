"""reconstruct (slice 2, piece 1) — coverage-guided inputs.

* the dictionary reads compares, ``lea`` offsets and range checks off
  the original and skips frame arithmetic;
* guided inputs reach a magic compare and a two-byte string check that
  random inputs (same seed, same budget) never do;
* guided cases repeat for a seed, respect every signature rule, and the
  ``inputs`` option is validated.
"""

from __future__ import annotations

import pytest

pytest.importorskip("unicorn")
pytest.importorskip("keystone")

import _pebuild as pb  # noqa: E402

from pry.analysis import pe  # noqa: E402
from pry.analysis.engine import ImageView  # noqa: E402
from pry.reconstruct.coverage import static_function  # noqa: E402
from pry.reconstruct.errors import ReconError  # noqa: E402
from pry.reconstruct.harness import Side  # noqa: E402
from pry.reconstruct.inputs import GuidedGen  # noqa: E402
from pry.reconstruct.signature import parse_signature  # noqa: E402
from pry.reconstruct.verify import VerifyOptions, run_verify  # noqa: E402

U32_X = {"ret": "u32", "params": [{"name": "x", "type": "u32"}]}
STR = {"ret": "u32", "params": [{"name": "s", "type": "cstr",
                                 "size": [0, 16]}]}

MAGIC = """
    xor eax, eax
    cmp ecx, 0x1337BEEF
    jne done
    mov eax, 1
done:
    ret
"""

MZ = """
    xor eax, eax
    cmp byte ptr [rcx], 0x4D
    jne done
    cmp byte ptr [rcx+1], 0x5A
    jne done
    mov eax, 1
done:
    ret
"""


# base == 0 and s starts "0x": an int and two string bytes at once.
PREFIX = """
    xor eax, eax
    test ecx, ecx
    jnz done
    cmp byte ptr [rdx], 0x30
    jne done
    cmp byte ptr [rdx+1], 0x78
    jne done
    mov eax, 16
done:
    ret
"""
PREFIX_SIG = {"ret": "u32", "params": [
    {"name": "base", "type": "u32"},
    {"name": "s", "type": "cstr", "size": [0, 8]}]}


def side(label: str, src: str) -> Side:
    built = pb.build(machine="x64",
                     code=lambda lay: pb.asm(src, "x64", lay.text_va))
    return Side(label, ImageView(pe.parse(built.data)), built.layout.text_va,
                "x64")


def verify(src: str, spec: dict, **opts) -> dict:
    sig = parse_signature(spec, arch="x64")
    return run_verify(side("original", src), side("reconstruction", src),
                      sig, VerifyOptions(**opts))


def test_dictionary_reads_compares_and_range_checks() -> None:
    o = side("original", """
        sub rsp, 0x28
        cmp ecx, 0x1337BEEF
        je hit
        lea eax, [rdx - 0x30]
        cmp al, 9
        ja miss
        test r8b, 0xfd
        jz miss
    hit:
        mov eax, 1
        add rsp, 0x28
        ret
    miss:
        xor eax, eax
        add rsp, 0x28
        ret
    """)
    consts = set(static_function(o.view, o.func_va, bits=64).constants)
    # the compare and both edges of it
    assert {0x1337BEEF, 0x1337BEEE, 0x1337BEF0} <= consts
    # lea's offset, the range check '0'..'9' and the byte past it
    assert {0x30, 0x39, 0x3A, 9} <= consts
    assert {0xFD, 1} <= consts
    assert 0x28 not in consts          # frame arithmetic is skipped


def test_compare_log_reports_what_each_site_saw() -> None:
    from pry.reconstruct.harness import Harness, choose_arena
    o = side("original", MZ)
    sf = static_function(o.view, o.func_va, bits=64)
    assert [(s.width, s.imm) for s in sf.cmp_sites] == [(1, 0x4D), (1, 0x5A)]
    sig = parse_signature(STR, arch="x64")
    h = Harness(o, sig, choose_arena("x64", [o.span()]), seed=1,
                max_insns=10_000)
    h.set_cmp_sites(sf.cmp_sites)
    h.run({"s": b"QZ"}, 0, 0)
    assert h.cmp_log == [(ord("Q"), 0x4D, 1)]
    h.run({"s": b"MQ"}, 1, 0)
    assert h.cmp_log == [(ord("Q"), 0x5A, 1)]     # site 1 matched
    h.run({"s": b"M"}, 2, 0)
    assert h.cmp_log == [(0, 0x5A, 1)]            # read the terminator


def test_compare_log_speaks_in_input_terms_after_a_range_lea() -> None:
    o = side("original", "lea eax, [rcx - 0x30]\ncmp al, 9\nret")
    (site,) = static_function(o.view, o.func_va, bits=64).cmp_sites
    assert (site.reg, site.imm, site.bias) == ("al", 9, 0x30)


def test_input_to_state_writes_the_expected_value() -> None:
    sig = parse_signature(PREFIX_SIG, arch="x64")
    gen = GuidedGen(sig, seed=2)
    gen.add({"base": 7, "s": b"Q"}, [(7, 0, 4), (ord("Q"), 0x30, 1)])
    gen.add({"base": 0, "s": b"0"}, [(0, ord("x"), 1)])
    seen = {(v["base"], v["s"]) for v, _o in (gen.next() for _ in range(200))}
    assert (0, b"Q") in seen            # the int compare
    assert (7, b"0") in seen            # a byte replaced in place
    assert (0, b"0x") in seen           # appended past the terminator


@pytest.mark.parametrize("src,spec", [(MAGIC, U32_X), (MZ, STR),
                                      (PREFIX, PREFIX_SIG)],
                         ids=["magic-u32", "MZ-string", "0x-prefix"])
def test_guided_reaches_what_random_does_not(src, spec) -> None:
    g = verify(src, spec, cases=400, seed=3, inputs="guided")
    r = verify(src, spec, cases=400, seed=3, inputs="random")
    assert g["coverage"]["ratio"] == 1.0, g["coverage"]
    assert r["coverage"]["ratio"] < 1.0, r["coverage"]
    assert g["verdict"] == r["verdict"] == "equivalent_on_tested_inputs"
    assert g["inputs"]["mode"] == "guided" and g["inputs"]["corpus"] >= 2
    assert g["inputs"]["dictionary"] >= 3
    assert r["inputs"] == {"mode": "random",
                           "by_origin": {"boundary": r["inputs"]["by_origin"]
                                         ["boundary"],
                                         "random": r["inputs"]["by_origin"]
                                         ["random"]}}


def test_guided_cases_repeat_for_a_seed() -> None:
    a = verify(MZ, STR, cases=120, seed=11)["_cases"]
    b = verify(MZ, STR, cases=120, seed=11)["_cases"]
    c = verify(MZ, STR, cases=120, seed=12)["_cases"]
    assert a == b
    assert a != c
    assert {row["origin"] for row in a} >= {"boundary", "random", "guided"}


def test_guided_values_keep_the_signature_rules() -> None:
    sig = parse_signature({"ret": "u32", "params": [
        {"name": "buf", "type": "buf_in", "size": [4, 32],
         "size_multiple": 4},
        {"name": "n", "type": "u32", "len_of": "buf"},
        {"name": "s", "type": "cstr", "size": [1, 8]},
        {"name": "w", "type": "wstr", "size": [0, 6]},
        {"name": "k", "type": "u8", "range": [10, 20]},
        {"name": "flag", "type": "bool"},
        {"name": "out", "type": "buf_out", "size": [1, 8]}]}, arch="x64")
    gen = GuidedGen(sig, seed=5, constants=(0, 0x41, 0x1337BEEF, -1, 300))
    for i in range(2000):
        vals, origin = gen.next()
        assert origin in ("random", "guided")
        assert 4 <= len(vals["buf"]) <= 32 and len(vals["buf"]) % 4 == 0
        assert vals["n"] == len(vals["buf"])
        assert 1 <= len(vals["s"]) <= 8 and 0 not in vals["s"]
        w = vals["w"]
        assert len(w) % 2 == 0 and len(w) // 2 <= 6
        assert all(w[j:j + 2] != b"\0\0" for j in range(0, len(w), 2))
        assert 10 <= vals["k"] <= 20
        assert vals["flag"] in (0, 1)
        assert 1 <= len(vals["out"]) <= 8 and not any(vals["out"])
        if i % 7 == 0:
            gen.add(vals)


def test_inputs_option_is_validated() -> None:
    from pry.mcp.tools.reconstruct import _options
    assert _options({})["inputs"] == "guided"
    assert _options({"inputs": "random"})["inputs"] == "random"
    with pytest.raises(ReconError) as ei:
        _options({"inputs": "fuzz"})
    assert ei.value.field == "options_json.inputs"
    with pytest.raises(ReconError):
        verify(MAGIC, U32_X, cases=1, inputs="fuzz")
