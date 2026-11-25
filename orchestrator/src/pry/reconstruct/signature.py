"""Signature spec — the C prototype both sides are called with.

The harness cannot infer types, so the caller declares them::

    {"ret": "u32",
     "params": [
       {"name": "crc", "type": "u32"},
       {"name": "buf", "type": "buf_in", "size": [0, 4096]},
       {"name": "len", "type": "u32", "len_of": "buf"}
     ]}

Scalars ``i8 u8 i16 u16 i32 u32 i64 u64 bool ptr f32 f64``; buffers
``buf_in buf_out buf_inout`` (a pointer to bytes the harness owns);
strings ``cstr wstr`` (NUL-terminated, printable by default). ``len_of``
ties an integer to a buffer's byte length (or a string's character
count), divided by ``len_scale``. ``cc`` picks the x86 convention;
x64 always uses Win64. Every problem raises :class:`ReconError`
``bad_arg`` naming the field and the closest valid spelling.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

from .errors import ReconError, bad_arg

INT_TYPES: dict[str, tuple[int, bool]] = {
    "i8": (1, True), "u8": (1, False), "i16": (2, True), "u16": (2, False),
    "i32": (4, True), "u32": (4, False), "i64": (8, True), "u64": (8, False),
    "bool": (1, False),
}
FLOAT_TYPES: dict[str, int] = {"f32": 4, "f64": 8}
PTR_TYPE = "ptr"
BUFFER_TYPES = ("buf_in", "buf_out", "buf_inout")
STRING_TYPES = ("cstr", "wstr")
SCALAR_TYPES = tuple(INT_TYPES) + (PTR_TYPE,) + tuple(FLOAT_TYPES)
PARAM_TYPES = SCALAR_TYPES + BUFFER_TYPES + STRING_TYPES
RET_TYPES = SCALAR_TYPES + ("void",)
CALL_CONVS = ("default", "win64", "cdecl", "stdcall", "fastcall", "thiscall")
ARCHES = ("x64", "x86")
FILLS = ("random", "zero", "bytes")

MAX_PARAMS = 8
MAX_BUFFER_BYTES = 1 << 20
MAX_STRING_CHARS = 1 << 16
MAX_TOTAL_BYTES = 8 << 20
MAX_STUB_RETS = 64

_TOP_KEYS = ("ret", "params", "cc", "stubs", "ignore", "float_ulps")
_PARAM_KEYS = ("name", "type", "size", "size_multiple", "fill", "fill_hex",
               "align", "len_of", "len_scale", "range", "values")
_STUB_KEYS = ("ret", "argc")
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_DEFAULT_SIZE = {"buffer": (0, 64), "string": (0, 32)}


@dataclass(frozen=True)
class Param:
    name: str
    type: str
    size_min: int = 0
    size_max: int = 0
    size_multiple: int = 1
    fill: str = "random"
    fill_bytes: bytes = b""
    align: int = 16
    len_of: str = ""
    len_scale: int = 1
    range: tuple[int, int] | None = None
    values: tuple[Any, ...] = ()

    @property
    def is_int(self) -> bool:
        return self.type in INT_TYPES or self.type == PTR_TYPE

    @property
    def is_float(self) -> bool:
        return self.type in FLOAT_TYPES

    @property
    def is_buffer(self) -> bool:
        return self.type in BUFFER_TYPES

    @property
    def is_string(self) -> bool:
        return self.type in STRING_TYPES

    @property
    def is_memory(self) -> bool:
        """Passed as a pointer to harness-owned memory."""
        return self.is_buffer or self.is_string

    @property
    def char_size(self) -> int:
        return 2 if self.type == "wstr" else 1

    def max_bytes(self) -> int:
        """Bytes the param can occupy, terminator included."""
        if self.is_string:
            return (self.size_max + 1) * self.char_size
        return self.size_max


@dataclass(frozen=True)
class StubSpec:
    """Return values for one stubbed import (by function name).

    ``rets`` is consumed per call (the last value repeats). ``argc`` is
    the dword count an x86 stdcall callee pops; ``None`` means the
    built-in table, else 0 (cdecl)."""

    rets: tuple[int, ...] = (0,)
    argc: int | None = None


@dataclass(frozen=True)
class Signature:
    arch: str
    cc: str
    ret: str
    params: tuple[Param, ...]
    stubs: dict[str, StubSpec]
    ignore: frozenset[str]
    float_ulps: int
    warnings: tuple[str, ...]

    @property
    def ptr_size(self) -> int:
        return 8 if self.arch == "x64" else 4

    def int_spec(self, type_: str) -> tuple[int, bool]:
        """(width bytes, signed) for an integer-like type."""
        if type_ == PTR_TYPE:
            return self.ptr_size, False
        return INT_TYPES[type_]

    def param(self, name: str) -> Param:
        for p in self.params:
            if p.name == name:
                return p
        raise KeyError(name)

    def generated(self) -> tuple[Param, ...]:
        """Params the input generator draws (``len_of`` ones derive)."""
        return tuple(p for p in self.params if not p.len_of)

    def to_json(self) -> dict[str, Any]:
        """Normalized form, echoed in reports (re-parses to the same)."""
        params: list[dict[str, Any]] = []
        for p in self.params:
            row: dict[str, Any] = {"name": p.name, "type": p.type}
            if p.is_memory:
                row["size"] = [p.size_min, p.size_max]
                if p.size_multiple != 1:
                    row["size_multiple"] = p.size_multiple
                row["align"] = p.align
                if p.type != "buf_out" and p.is_buffer:
                    row["fill"] = p.fill
                    if p.fill == "bytes":
                        row["fill_hex"] = p.fill_bytes.hex()
            if p.len_of:
                row["len_of"] = p.len_of
                if p.len_scale != 1:
                    row["len_scale"] = p.len_scale
            if p.range is not None:
                row["range"] = list(p.range)
            if p.values:
                row["values"] = list(p.values)
            params.append(row)
        out: dict[str, Any] = {"ret": self.ret, "cc": self.cc,
                               "params": params}
        if self.stubs:
            out["stubs"] = {k: ({"ret": list(v.rets)} if v.argc is None
                                else {"ret": list(v.rets), "argc": v.argc})
                            for k, v in sorted(self.stubs.items())}
        if self.ignore:
            out["ignore"] = sorted(self.ignore)
        if self.float_ulps:
            out["float_ulps"] = self.float_ulps
        return out


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _int_limits(width: int, signed: bool) -> tuple[int, int]:
    bits = width * 8
    if signed:
        return -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    return 0, (1 << bits) - 1


def _as_int(v: Any, field: str) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip(), 0)
        except ValueError:
            pass
    raise bad_arg(f"{field}: expected an integer, got {v!r}", field=field)


def _check_keys(obj: dict, allowed: tuple[str, ...], where: str) -> None:
    for k in obj:
        if k not in allowed:
            raise bad_arg(f"{where}: unknown field {k!r}",
                          field=f"{where}.{k}" if where else k,
                          given=str(k), valid=allowed)


def _size_range(p: dict, kind: str, field: str,
                cap: int) -> tuple[int, int]:
    raw = p.get("size", list(_DEFAULT_SIZE[kind]))
    if isinstance(raw, (int, str)) and not isinstance(raw, bool):
        lo = hi = _as_int(raw, field)
    elif isinstance(raw, (list, tuple)) and len(raw) == 2:
        lo, hi = _as_int(raw[0], field), _as_int(raw[1], field)
    else:
        raise bad_arg(f"{field}: size is an int or [min, max]", field=field)
    if lo < 0 or hi < lo:
        raise bad_arg(f"{field}: need 0 <= min <= max (got [{lo}, {hi}])",
                      field=field)
    if hi > cap:
        raise bad_arg(f"{field}: max {hi} exceeds the {cap} cap",
                      field=field)
    return lo, hi


def _parse_param(p: Any, i: int, arch: str) -> Param:
    where = f"params[{i}]"
    if not isinstance(p, dict):
        raise bad_arg(f"{where}: each param is an object "
                      "{name, type, ...}", field=where)
    _check_keys(p, _PARAM_KEYS, where)
    name = p.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise bad_arg(f"{where}.name: a C identifier is required "
                      f"(got {name!r})", field=f"{where}.name")
    type_ = p.get("type")
    if type_ not in PARAM_TYPES:
        raise bad_arg(f"{where}.type: unknown type {type_!r}",
                      field=f"{where}.type", given=str(type_),
                      valid=PARAM_TYPES)
    kw: dict[str, Any] = {"name": name, "type": type_}
    memory = type_ in BUFFER_TYPES or type_ in STRING_TYPES
    if memory:
        kind = "string" if type_ in STRING_TYPES else "buffer"
        cap = MAX_STRING_CHARS if kind == "string" else MAX_BUFFER_BYTES
        lo, hi = _size_range(p, kind, f"{where}.size", cap)
        mult = _as_int(p.get("size_multiple", 1), f"{where}.size_multiple")
        if not 1 <= mult <= 4096:
            raise bad_arg(f"{where}.size_multiple: 1..4096",
                          field=f"{where}.size_multiple")
        lo = -(-lo // mult) * mult
        hi = (hi // mult) * mult
        if hi < lo:
            raise bad_arg(f"{where}: no size in range is a multiple of "
                          f"{mult}", field=f"{where}.size")
        align = _as_int(p.get("align", 1), f"{where}.align")
        if align < 1 or align > 4096 or align & (align - 1):
            raise bad_arg(f"{where}.align: a power of two in 1..4096",
                          field=f"{where}.align")
        kw.update(size_min=lo, size_max=hi, size_multiple=mult, align=align)
        fill = p.get("fill", "random")
        if fill not in FILLS:
            raise bad_arg(f"{where}.fill: unknown fill {fill!r}",
                          field=f"{where}.fill", given=str(fill),
                          valid=FILLS)
        if fill == "bytes":
            try:
                fb = bytes.fromhex(str(p.get("fill_hex", "")))
            except ValueError as exc:
                raise bad_arg(f"{where}.fill_hex: {exc}",
                              field=f"{where}.fill_hex") from exc
            if not 1 <= len(fb) <= 4096:
                raise bad_arg(f"{where}.fill_hex: 1..4096 bytes for "
                              "fill='bytes'", field=f"{where}.fill_hex")
            kw["fill_bytes"] = fb
        elif "fill_hex" in p:
            raise bad_arg(f"{where}.fill_hex: only with fill='bytes'",
                          field=f"{where}.fill_hex")
        kw["fill"] = fill
        for k in ("len_of", "len_scale", "range", "values"):
            if k in p:
                raise bad_arg(f"{where}.{k}: not valid on a {type_} param",
                              field=f"{where}.{k}")
        return Param(**kw)
    for k in ("size", "size_multiple", "fill", "fill_hex", "align"):
        if k in p:
            raise bad_arg(f"{where}.{k}: only buffers and strings take "
                          f"{k}", field=f"{where}.{k}")
    if type_ in FLOAT_TYPES:
        for k in ("len_of", "len_scale", "range"):
            if k in p:
                raise bad_arg(f"{where}.{k}: not valid on a float param",
                              field=f"{where}.{k}")
        vals = p.get("values", [])
        if not isinstance(vals, list):
            raise bad_arg(f"{where}.values: a list", field=f"{where}.values")
        fvals = []
        for v in vals:
            if isinstance(v, bool) or not isinstance(v, (int, float, str)):
                raise bad_arg(f"{where}.values: numbers only",
                              field=f"{where}.values")
            try:
                fvals.append(float(v))
            except ValueError as exc:
                raise bad_arg(f"{where}.values: {exc}",
                              field=f"{where}.values") from exc
        kw["values"] = tuple(fvals)
        return Param(**kw)
    # integer-like scalar
    width, signed = (8 if arch == "x64" else 4, False) \
        if type_ == PTR_TYPE else INT_TYPES[type_]
    lo_t, hi_t = _int_limits(width, signed)
    if "len_of" in p:
        if type_ in ("bool", PTR_TYPE):
            raise bad_arg(f"{where}.len_of: needs an integer type, not "
                          f"{type_}", field=f"{where}.len_of")
        kw["len_of"] = str(p["len_of"])
        scale = _as_int(p.get("len_scale", 1), f"{where}.len_scale")
        if not 1 <= scale <= 4096:
            raise bad_arg(f"{where}.len_scale: 1..4096",
                          field=f"{where}.len_scale")
        kw["len_scale"] = scale
        for k in ("range", "values"):
            if k in p:
                raise bad_arg(f"{where}.{k}: a len_of param is derived "
                              "from its buffer", field=f"{where}.{k}")
        return Param(**kw)
    if "len_scale" in p:
        raise bad_arg(f"{where}.len_scale: only with len_of",
                      field=f"{where}.len_scale")
    if "range" in p:
        r = p["range"]
        if not (isinstance(r, (list, tuple)) and len(r) == 2):
            raise bad_arg(f"{where}.range: [lo, hi]", field=f"{where}.range")
        lo, hi = _as_int(r[0], f"{where}.range"), _as_int(r[1], f"{where}.range")
        if lo > hi or lo < lo_t or hi > hi_t:
            raise bad_arg(f"{where}.range: [{lo}, {hi}] is not inside "
                          f"{type_} [{lo_t}, {hi_t}]", field=f"{where}.range")
        kw["range"] = (lo, hi)
    vals = p.get("values", [])
    if not isinstance(vals, list):
        raise bad_arg(f"{where}.values: a list", field=f"{where}.values")
    ivals = []
    for v in vals:
        iv = _as_int(v, f"{where}.values")
        if not lo_t <= iv <= hi_t:
            raise bad_arg(f"{where}.values: {iv} is outside {type_}",
                          field=f"{where}.values")
        ivals.append(iv)
    kw["values"] = tuple(ivals)
    return Param(**kw)


def _parse_stubs(raw: Any) -> dict[str, StubSpec]:
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        raise bad_arg("stubs: an object {\"dll!Name\": ret | [rets] | "
                      "{ret, argc}}", field="stubs")
    out: dict[str, StubSpec] = {}
    for key, val in raw.items():
        name = str(key).strip().rsplit("!", 1)[-1]
        if not name or any(c.isspace() for c in name):
            raise bad_arg(f"stubs: bad import name {key!r}", field="stubs")
        argc: int | None = None
        rv: Any = val
        if isinstance(val, dict):
            _check_keys(val, _STUB_KEYS, f"stubs.{key}")
            rv = val.get("ret", 0)
            if "argc" in val:
                argc = _as_int(val["argc"], f"stubs.{key}.argc")
                if not 0 <= argc <= 32:
                    raise bad_arg(f"stubs.{key}.argc: 0..32",
                                  field=f"stubs.{key}.argc")
        rets = rv if isinstance(rv, list) else [rv]
        if not 1 <= len(rets) <= MAX_STUB_RETS:
            raise bad_arg(f"stubs.{key}: 1..{MAX_STUB_RETS} return values",
                          field=f"stubs.{key}")
        out[name] = StubSpec(
            rets=tuple(_as_int(r, f"stubs.{key}") & ((1 << 64) - 1)
                       for r in rets), argc=argc)
    return out


def parse_signature(spec: Any, *, arch: str) -> Signature:
    """Parse and validate *spec* (a JSON string or an object)."""
    if arch not in ARCHES:
        raise bad_arg(f"arch: unknown arch {arch!r}", field="arch",
                      given=str(arch), valid=ARCHES)
    if isinstance(spec, str):
        if not spec.strip():
            raise bad_arg("signature_json is required — declare ret and "
                          "params", field="signature_json",
                          hint='e.g. {"ret": "u32", "params": [{"name": '
                               '"x", "type": "u32"}]}')
        try:
            spec = json.loads(spec)
        except json.JSONDecodeError as exc:
            raise bad_arg(f"signature_json: invalid JSON ({exc})",
                          field="signature_json") from exc
    if not isinstance(spec, dict):
        raise bad_arg("signature_json: a JSON object is required",
                      field="signature_json")
    _check_keys(spec, _TOP_KEYS, "")
    warnings: list[str] = []
    ret = spec.get("ret")
    if ret is None:
        ret = "void"
        warnings.append("ret not declared: the return value is not "
                        "compared")
    if ret not in RET_TYPES:
        raise bad_arg(f"ret: unknown type {ret!r}", field="ret",
                      given=str(ret), valid=RET_TYPES)
    raw_params = spec.get("params", [])
    if not isinstance(raw_params, list):
        raise bad_arg("params: a list", field="params")
    if len(raw_params) > MAX_PARAMS:
        raise bad_arg(f"params: at most {MAX_PARAMS} in slice 1 (got "
                      f"{len(raw_params)})", field="params")
    params = tuple(_parse_param(p, i, arch) for i, p in enumerate(raw_params))
    names = [p.name for p in params]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise bad_arg(f"params: duplicate name(s) {sorted(dup)}",
                      field="params")
    memory = [p.name for p in params if p.is_memory]
    for i, p in enumerate(params):
        if p.len_of and p.len_of not in memory:
            raise bad_arg(f"params[{i}].len_of: {p.len_of!r} is not a "
                          "buffer or string param", field=f"params[{i}].len_of",
                          given=p.len_of, valid=memory)
    total = sum(p.max_bytes() for p in params if p.is_memory)
    if total > MAX_TOTAL_BYTES:
        raise bad_arg(f"params: buffers total {total} bytes, over the "
                      f"{MAX_TOTAL_BYTES} cap", field="params")
    for p in params:
        if p.type == "buf_out" and p.fill != "random":
            warnings.append(f"{p.name}: buf_out is pre-filled with a canary; "
                            "fill is ignored")
    cc = spec.get("cc", "default")
    if cc not in CALL_CONVS:
        raise bad_arg(f"cc: unknown calling convention {cc!r}", field="cc",
                      given=str(cc), valid=CALL_CONVS)
    if arch == "x64":
        if cc not in ("default", "win64"):
            warnings.append(f"cc={cc} ignored: x64 has one calling "
                            "convention (Win64)")
        cc = "win64"
    else:
        if cc == "win64":
            raise bad_arg("cc: win64 is the x64 convention; x86 takes "
                          "cdecl, stdcall, fastcall or thiscall", field="cc")
        if cc == "default":
            cc = "cdecl"
        if cc == "thiscall":
            if not params or not (params[0].is_memory or (
                    params[0].is_int and
                    (4 if params[0].type == PTR_TYPE
                     else INT_TYPES[params[0].type][0]) <= 4)):
                raise bad_arg("cc=thiscall: params[0] must be the `this` "
                              "pointer (ptr, a 32-bit int, or a buffer)",
                              field="params[0]")
    ignore_raw = spec.get("ignore", [])
    if not isinstance(ignore_raw, list):
        raise bad_arg("ignore: a list of output names", field="ignore")
    valid_ignore = ["ret", "api", "cleanup"] + memory
    for item in ignore_raw:
        if item not in valid_ignore:
            raise bad_arg(f"ignore: unknown output {item!r}", field="ignore",
                          given=str(item), valid=valid_ignore)
    ulps = _as_int(spec.get("float_ulps", 0), "float_ulps")
    if not 0 <= ulps <= 1 << 20:
        raise bad_arg("float_ulps: 0..1048576", field="float_ulps")
    return Signature(arch=arch, cc=cc, ret=ret, params=params,
                     stubs=_parse_stubs(spec.get("stubs")),
                     ignore=frozenset(ignore_raw), float_ulps=ulps,
                     warnings=tuple(warnings))


def float_bits(value: float, width: int) -> int:
    """IEEE bits of *value* at *width* bytes (NaN-preserving for f64)."""
    import struct
    if width == 4:
        if math.isnan(value):
            return 0x7FC00000
        try:
            return struct.unpack("<I", struct.pack("<f", value))[0]
        except OverflowError:
            return 0x7F800000 if value > 0 else 0xFF800000
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def bits_float(bits: int, width: int) -> float:
    import struct
    if width == 4:
        return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]
    return struct.unpack("<d", struct.pack("<Q", bits & ((1 << 64) - 1)))[0]


__all__ = ["ARCHES", "BUFFER_TYPES", "CALL_CONVS", "FLOAT_TYPES",
           "INT_TYPES", "MAX_PARAMS", "PARAM_TYPES", "PTR_TYPE",
           "RET_TYPES", "STRING_TYPES", "Param", "ReconError", "Signature",
           "StubSpec", "bits_float", "float_bits", "parse_signature"]
