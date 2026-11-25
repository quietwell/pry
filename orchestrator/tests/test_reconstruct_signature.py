"""reconstruct.signature + reconstruct.inputs — pure Python, no engine."""

from __future__ import annotations

import json

import pytest

from pry.reconstruct.errors import ReconError
from pry.reconstruct.inputs import (encode_case, generate_cases,
                                       parse_case_list, read_cases_jsonl)
from pry.reconstruct.signature import (bits_float, float_bits,
                                          parse_signature)

CRC = {"ret": "u32", "params": [
    {"name": "crc", "type": "u32"},
    {"name": "buf", "type": "buf_in", "size": [0, 64]},
    {"name": "len", "type": "u32", "len_of": "buf"}]}


def _err(spec, arch="x64") -> ReconError:
    with pytest.raises(ReconError) as ei:
        parse_signature(spec, arch=arch)
    return ei.value


def test_parse_basic_and_defaults() -> None:
    sig = parse_signature(json.dumps(CRC), arch="x64")
    assert sig.cc == "win64" and sig.ret == "u32"
    buf = sig.param("buf")
    assert (buf.size_min, buf.size_max, buf.align) == (0, 64, 1)
    assert [p.name for p in sig.generated()] == ["crc", "buf"]
    assert parse_signature(sig.to_json(), arch="x64").to_json() == \
        sig.to_json()
    assert parse_signature(CRC, arch="x86").cc == "cdecl"


def test_unknown_names_get_closest_suggestions() -> None:
    e = _err({"ret": "u32", "params": [{"name": "x", "type": "uint32"}]})
    assert e.kind == "bad_arg" and e.field == "params[0].type"
    assert "u32" in e.closest or "i32" in e.closest
    e = _err({"ret": "u32", "parms": []})
    assert e.field == "parms" and "params" in e.closest
    e = _err({"ret": "u32", "params": [{"name": "n", "type": "u32",
                                        "len_of": "bufx"}]})
    assert "len_of" in e.field


def test_convention_rules() -> None:
    sig = parse_signature({"ret": "i32", "cc": "stdcall", "params": []},
                          arch="x64")
    assert sig.cc == "win64" and sig.warnings
    assert _err({"ret": "i32", "cc": "win64"}, "x86").field == "cc"
    assert _err({"ret": "i32", "cc": "thiscall",
                 "params": [{"name": "a", "type": "f64"}]}, "x86")
    ok = parse_signature({"ret": "i32", "cc": "thiscall", "params": [
        {"name": "self", "type": "ptr"}, {"name": "a", "type": "i32"}]},
        arch="x86")
    assert ok.cc == "thiscall"


def test_limits() -> None:
    many = {"ret": "void", "params": [{"name": f"p{i}", "type": "u8"}
                                      for i in range(9)]}
    assert _err(many).field == "params"
    big = {"ret": "void", "params": [
        {"name": "b", "type": "buf_in", "size": [0, 1 << 21]}]}
    assert "size" in _err(big).field
    dup = {"ret": "void", "params": [{"name": "a", "type": "u8"},
                                     {"name": "a", "type": "u8"}]}
    assert "duplicate" in str(_err(dup))
    e = _err({"ret": "u8", "params": [{"name": "a", "type": "u8",
                                       "range": [0, 300]}]})
    assert e.field == "params[0].range"


def test_stubs_and_ignore() -> None:
    sig = parse_signature({"ret": "u32", "params": [
        {"name": "out", "type": "buf_out", "size": 4}],
        "stubs": {"kernel32!GetTickCount": [5, 6],
                  "Sleep": {"ret": 0, "argc": 1}},
        "ignore": ["api", "out"]}, arch="x86")
    assert sig.stubs["GetTickCount"].rets == (5, 6)
    assert sig.stubs["Sleep"].argc == 1
    assert sig.ignore == {"api", "out"}
    assert _err({"ret": "u32", "ignore": ["rett"]}).closest == ["ret"]


def test_float_bits_roundtrip() -> None:
    for v in (0.0, -0.0, 1.5, float("inf"), 1e-310):
        assert bits_float(float_bits(v, 8), 8) == v or v != v
    assert float_bits(1.0, 4) == 0x3F800000
    assert float_bits(float("nan"), 4) == 0x7FC00000


def test_generation_is_deterministic_and_linked() -> None:
    sig = parse_signature(CRC, arch="x64")
    a = generate_cases(sig, seed=7, count=50)
    b = generate_cases(sig, seed=7, count=50)
    c = generate_cases(sig, seed=8, count=50)
    enc = [encode_case(sig, x) for x in a]
    assert enc == [encode_case(sig, x) for x in b]
    assert enc != [encode_case(sig, x) for x in c]
    for case in a:
        assert case.values["len"] == len(case.values["buf"])
    origins = {x.origin for x in a}
    assert origins == {"boundary", "random"}
    sizes = {len(x.values["buf"]) for x in a if x.origin == "boundary"}
    assert {0, 1, 63, 64} <= sizes
    crcs = {x.values["crc"] for x in a if x.origin == "boundary"}
    assert {0, 1, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF} <= crcs


def test_explicit_cases_and_replay_roundtrip() -> None:
    sig = parse_signature({"ret": "f64", "params": [
        {"name": "x", "type": "f64"},
        {"name": "s", "type": "cstr", "size": [0, 16]},
        {"name": "w", "type": "wstr", "size": [0, 16]},
        {"name": "o", "type": "buf_out", "size": [0, 8]},
        {"name": "n", "type": "i16"}]}, arch="x64")
    vals = parse_case_list(sig, [{"x": "nan", "s": "hi", "w": "ab",
                                  "o": 4, "n": -3},
                                 {"x": {"f64": "0x3ff0000000000000"},
                                  "s": {"hex": "4142"}, "w": {"text": "z"},
                                  "o": {"size": 0}, "n": "0x7fff"}],
                           origin="explicit", where="cases_json")
    assert vals[0]["s"] == b"hi" and vals[0]["w"] == "ab".encode("utf-16-le")
    assert vals[0]["o"] == bytes(4) and vals[0]["n"] == -3
    assert vals[1]["x"] == 0x3FF0000000000000 and vals[1]["n"] == 0x7FFF
    cases = generate_cases(sig, seed=1, count=5, explicit=vals)
    assert [c.origin for c in cases[:2]] == ["explicit", "explicit"]
    jsonl = "\n".join(json.dumps(encode_case(sig, c)) for c in cases)
    back = read_cases_jsonl(sig, jsonl)
    assert back == [c.values for c in cases]


def test_explicit_case_errors() -> None:
    sig = parse_signature(CRC, arch="x64")
    with pytest.raises(ReconError) as ei:
        parse_case_list(sig, [{"crc": 1, "bufx": "00"}], origin="explicit",
                        where="cases_json")
    assert "buf" in ei.value.closest
    with pytest.raises(ReconError):
        parse_case_list(sig, [{"crc": 1 << 40, "buf": ""}],
                        origin="explicit", where="cases_json")
    # an explicit len overrides the derived one (e.g. to test overruns)
    v = parse_case_list(sig, [{"crc": 1, "buf": "0011", "len": 9}],
                        origin="explicit", where="cases_json")[0]
    assert v["len"] == 9
