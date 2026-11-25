"""Case generation — explicit cases, the boundary set, and the generated
cases: coverage-guided (:class:`GuidedGen`, the default) or seeded
random (:func:`generate_cases`).

Internal value forms (per param type):

* integers / ``bool`` / ``ptr`` — Python ``int`` (signed types signed);
* ``f32`` / ``f64`` — the IEEE **bit pattern** as an ``int``, so NaN
  payloads, ``-0.0`` and denormals survive generation, replay and
  comparison exactly;
* ``buf_in`` / ``buf_inout`` — the buffer's bytes;
* ``buf_out`` — zero ``bytes`` of the chosen size (the harness fills a
  canary; only the size is an input);
* ``cstr`` / ``wstr`` — the characters' bytes in the target encoding,
  terminator excluded.

The JSON form (``inputs.jsonl``, ``cases_json``) is bit-exact and
re-parses to the same values, so every run can be replayed.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import bad_arg
from .signature import FLOAT_TYPES, Param, Signature, bits_float, float_bits

MAX_CASES = 10_000
MAX_BOUNDARY_CASES = 512

_F64_SPECIAL = (0x0, 0x8000000000000000, 0x3FF0000000000000,
                0xBFF0000000000000, 0x3FE0000000000000, 0x4000000000000000,
                0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000,
                0x0000000000000001, 0x0010000000000000, 0x7FEFFFFFFFFFFFFF,
                0xFFEFFFFFFFFFFFFF, 0x3DDB7CDFD9D7BDBB, 0x4202A05F20000000,
                0x400921FB54442D18)
_F32_SPECIAL = (0x0, 0x80000000, 0x3F800000, 0xBF800000, 0x3F000000,
                0x40000000, 0x7F800000, 0xFF800000, 0x7FC00000, 0x00000001,
                0x00800000, 0x7F7FFFFF, 0xFF7FFFFF, 0x2EDBE6FF, 0x501502F9,
                0x40490FDB)
_SIZE_POINTS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                127, 128, 129, 255, 256, 257, 511, 512, 1023, 1024, 4095,
                4096, 4097)
_PRINTABLE = bytes(range(0x20, 0x7F))


@dataclass
class Case:
    index: int
    origin: str                      # explicit | replay | boundary | random
    values: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

def int_bounds(sig: Signature, p: Param) -> tuple[int, int]:
    width, signed = sig.int_spec(p.type)
    bits = width * 8
    if p.type == "bool":
        return 0, 1
    if signed:
        return -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    return 0, (1 << bits) - 1


def _norm_int(sig: Signature, p: Param, v: int, field_: str) -> int:
    """Accept either the signed or the unsigned spelling of a value."""
    width, signed = sig.int_spec(p.type)
    bits = width * 8
    if p.type == "bool":
        if v not in (0, 1):
            raise bad_arg(f"{field_}: bool takes 0 or 1 (got {v})",
                          field=field_)
        return v
    if not -(1 << (bits - 1)) <= v < (1 << bits):
        raise bad_arg(f"{field_}: {v} does not fit {p.type}", field=field_)
    v &= (1 << bits) - 1
    if signed and v >> (bits - 1):
        v -= 1 << bits
    return v


def _sizes(p: Param) -> list[int]:
    lo, hi, m = p.size_min, p.size_max, p.size_multiple
    pts = set(_SIZE_POINTS) | {lo, lo + m, hi, max(lo, hi - m)}
    out = sorted({s for s in pts if lo <= s <= hi and s % m == 0})
    return out or [lo]


def _content(p: Param, size: int, rng: random.Random,
             mode: str = "") -> bytes:
    """*size* is bytes for buffers, characters for strings."""
    if p.type == "buf_out":
        return bytes(size)
    if p.is_string:
        chars = bytes(rng.choice(_PRINTABLE) for _ in range(size))
        if p.type == "wstr":
            return chars.decode("latin-1").encode("utf-16-le")
        return chars
    mode = mode or p.fill
    if mode == "zero":
        return bytes(size)
    if mode == "ff":
        return b"\xFF" * size
    if mode == "bytes":
        reps = -(-size // len(p.fill_bytes)) if size else 0
        return (p.fill_bytes * reps)[:size]
    return rng.randbytes(size)


def _boundary_values(sig: Signature, p: Param,
                     rng: random.Random) -> list[Any]:
    if p.is_memory:
        out: list[Any] = [_content(p, s, rng) for s in _sizes(p)]
        if p.is_buffer and p.type != "buf_out" and p.fill == "random":
            mid = _sizes(p)[len(_sizes(p)) // 2]
            out += [_content(p, mid, rng, "zero"), _content(p, mid, rng, "ff")]
        return out
    if p.is_float:
        width = FLOAT_TYPES[p.type]
        pool = list(_F32_SPECIAL if width == 4 else _F64_SPECIAL)
        return pool + [float_bits(v, width) for v in p.values]
    lo, hi = int_bounds(sig, p)
    width, signed = sig.int_spec(p.type)
    bits = width * 8
    vals: set[int] = {0, 1, 2, lo, hi, lo + 1, hi - 1}
    if signed:
        vals |= {-1, -2}
    for k in (7, 8, 15, 16, 31, 32, 63):
        if k < bits:
            vals |= {(1 << k) - 1, 1 << k, (1 << k) + 1}
            if signed:
                vals |= {-(1 << k), -(1 << k) - 1}
    if p.range is not None:
        rlo, rhi = p.range
        vals = {v for v in vals if rlo <= v <= rhi}
        vals |= {rlo, rhi, min(rlo + 1, rhi), max(rhi - 1, rlo),
                 rlo + (rhi - rlo) // 2}
    vals |= set(p.values)
    return sorted(v for v in vals if lo <= v <= hi)


def _typical(sig: Signature, p: Param, rng: random.Random) -> Any:
    if p.is_memory:
        sizes = _sizes(p)
        size = min(sizes, key=lambda s: abs(s - 16))
        return _content(p, size, rng)
    if p.is_float:
        return float_bits(1.5, FLOAT_TYPES[p.type])
    if p.range is not None:
        return rng.randint(*p.range)
    lo, hi = int_bounds(sig, p)
    return max(lo, min(hi, rng.randint(1, 100)))


def _random_value(sig: Signature, p: Param, rng: random.Random) -> Any:
    if p.is_memory:
        r = rng.random()
        if r < 0.3:
            size = rng.choice(_sizes(p))
        else:
            span = p.size_max - p.size_min
            size = p.size_min + int(span * rng.random() ** 2)
            size -= size % p.size_multiple
            size = max(size, p.size_min)
        return _content(p, size, rng)
    if p.is_float:
        width = FLOAT_TYPES[p.type]
        r = rng.random()
        if r < 0.2:
            pool = list(_F32_SPECIAL if width == 4 else _F64_SPECIAL)
            pool += [float_bits(v, width) for v in p.values]
            return rng.choice(pool)
        if r < 0.7:
            return float_bits(rng.uniform(-1000.0, 1000.0), width)
        if r < 0.85:
            return float_bits(rng.uniform(-1.0, 1.0), width)
        return rng.getrandbits(width * 8)
    lo, hi = int_bounds(sig, p)
    if p.range is not None:
        lo, hi = p.range
    r = rng.random()
    if r < 0.2:
        return rng.choice(_boundary_values(sig, p, rng))
    if r < 0.3 and p.values:
        return rng.choice(p.values)
    if r < 0.45:
        small = rng.randint(-128, 255) if lo < 0 else rng.randint(0, 255)
        return max(lo, min(hi, small))
    return rng.randint(lo, hi)


def derive_lengths(sig: Signature, values: dict[str, Any],
                   explicit: Iterable[str] = ()) -> dict[str, Any]:
    """Fill each ``len_of`` param from its buffer (unless given)."""
    given = set(explicit)
    for p in sig.params:
        if not p.len_of or p.name in given:
            continue
        src = sig.param(p.len_of)
        n = len(values[src.name]) // src.char_size // p.len_scale
        lo, hi = int_bounds(sig, p)
        values[p.name] = min(n, hi)
    return values


# ---------------------------------------------------------------------------
# JSON form
# ---------------------------------------------------------------------------

def encode_value(sig: Signature, p: Param, v: Any) -> Any:
    if p.is_float:
        width = FLOAT_TYPES[p.type]
        return {p.type: f"0x{v:0{width * 2}x}",
                "approx": repr(bits_float(v, width))}
    if p.type == "buf_out":
        return {"size": len(v)}
    if p.is_buffer:
        return {"hex": v.hex()}
    if p.is_string:
        try:
            text = v.decode("utf-16-le" if p.type == "wstr" else "ascii")
            if all(0x20 <= ord(c) < 0x7F for c in text):
                return {"text": text}
        except UnicodeDecodeError:
            pass
        return {"hex": v.hex()}
    return v


def decode_value(sig: Signature, p: Param, raw: Any, field_: str) -> Any:
    if p.is_float:
        width = FLOAT_TYPES[p.type]
        if isinstance(raw, dict):
            key = p.type if p.type in raw else ("f64" if "f64" in raw
                                                else "f32")
            if key not in raw:
                raise bad_arg(f"{field_}: float as a number or "
                              f'{{"{p.type}": "0x<bits>"}}', field=field_)
            bits = int(str(raw[key]), 0)
            if key != p.type:
                bits = float_bits(bits_float(bits, FLOAT_TYPES[key]), width)
            return bits & ((1 << (width * 8)) - 1)
        if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
            raise bad_arg(f"{field_}: a number", field=field_)
        try:
            return float_bits(float(raw), width)
        except ValueError as exc:
            raise bad_arg(f"{field_}: {exc}", field=field_) from exc
    if p.is_memory:
        data = _decode_bytes(p, raw, field_)
        if p.is_string:
            chars = len(data) // p.char_size
            if chars > p.size_max:
                raise bad_arg(f"{field_}: {chars} chars exceeds size max "
                              f"{p.size_max}", field=field_)
            return data
        if len(data) > p.size_max:
            raise bad_arg(f"{field_}: {len(data)} bytes exceeds size max "
                          f"{p.size_max}", field=field_)
        return data
    if isinstance(raw, bool):
        raw = int(raw)
    if isinstance(raw, str):
        try:
            raw = int(raw.strip(), 0)
        except ValueError as exc:
            raise bad_arg(f"{field_}: integer expected", field=field_) \
                from exc
    if not isinstance(raw, int):
        raise bad_arg(f"{field_}: integer expected (got {raw!r})",
                      field=field_)
    return _norm_int(sig, p, raw, field_)


def _decode_bytes(p: Param, raw: Any, field_: str) -> bytes:
    if p.type == "buf_out":
        size = raw.get("size") if isinstance(raw, dict) else raw
        if isinstance(size, str) and not isinstance(raw, dict):
            # A hex string for an out buffer: its length is the size.
            try:
                return bytes(len(bytes.fromhex(size)))
            except ValueError:
                pass
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise bad_arg(f"{field_}: buf_out takes its size, an int or "
                          '{"size": N}', field=field_)
        return bytes(size)
    if isinstance(raw, dict):
        if "hex" in raw:
            raw = raw["hex"]
        elif "text" in raw:
            text = str(raw["text"])
            return text.encode("utf-16-le" if p.type == "wstr" else "utf-8")
        else:
            raise bad_arg(f'{field_}: {{"hex": "..."}} or {{"text": "..."}}',
                          field=field_)
    elif isinstance(raw, list):
        try:
            return bytes(int(b) & 0xFF for b in raw)
        except (TypeError, ValueError) as exc:
            raise bad_arg(f"{field_}: byte list of ints", field=field_) \
                from exc
    elif p.is_string and isinstance(raw, str):
        return raw.encode("utf-16-le" if p.type == "wstr" else "utf-8")
    if not isinstance(raw, str):
        raise bad_arg(f"{field_}: hex string expected", field=field_)
    try:
        return bytes.fromhex(raw.replace(" ", ""))
    except ValueError as exc:
        raise bad_arg(f"{field_}: {exc}", field=field_) from exc


def encode_case(sig: Signature, case: Case) -> dict[str, Any]:
    return {"case": case.index, "origin": case.origin,
            "inputs": {p.name: encode_value(sig, p, case.values[p.name])
                       for p in sig.params}}


def parse_case_list(sig: Signature, raw: Any, *, origin: str,
                    where: str) -> list[dict[str, Any]]:
    """Explicit / replayed cases → value dicts (``len_of`` derived)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError as exc:
            raise bad_arg(f"{where}: invalid JSON ({exc})", field=where) \
                from exc
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise bad_arg(f"{where}: a list of case objects", field=where)
    if len(raw) > MAX_CASES:
        raise bad_arg(f"{where}: at most {MAX_CASES} cases", field=where)
    names = [p.name for p in sig.params]
    out: list[dict[str, Any]] = []
    for i, obj in enumerate(raw):
        if isinstance(obj, dict) and "inputs" in obj and \
                isinstance(obj["inputs"], dict):
            obj = obj["inputs"]           # an inputs.jsonl row
        if not isinstance(obj, dict):
            raise bad_arg(f"{where}[{i}]: a case is an object "
                          "{param: value}", field=f"{where}[{i}]")
        for k in obj:
            if k not in names:
                raise bad_arg(f"{where}[{i}]: unknown param {k!r}",
                              field=f"{where}[{i}].{k}", given=str(k),
                              valid=names)
        values: dict[str, Any] = {}
        for p in sig.params:
            if p.name in obj:
                values[p.name] = decode_value(sig, p, obj[p.name],
                                              f"{where}[{i}].{p.name}")
            elif not p.len_of:
                raise bad_arg(f"{where}[{i}]: missing param {p.name!r}",
                              field=f"{where}[{i}].{p.name}")
        explicit_lens = [p.name for p in sig.params
                         if p.len_of and p.name in obj]
        out.append(derive_lengths(sig, values, explicit_lens))
    return out


def read_cases_jsonl(sig: Signature, text: str) -> list[dict[str, Any]]:
    rows: list[Any] = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise bad_arg(f"cases_path: line {n}: invalid JSON ({exc})",
                          field="cases_path") from exc
    return parse_case_list(sig, rows, origin="replay", where="cases_path")


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate_cases(sig: Signature, *, seed: int, count: int,
                   explicit: list[dict[str, Any]] | None = None,
                   replay: list[dict[str, Any]] | None = None,
                   boundary: bool = True) -> list[Case]:
    """Explicit, then replayed, then the boundary set, then *count*
    seeded random cases. Deterministic for a given (signature, seed)."""
    if not 0 <= count <= MAX_CASES:
        raise bad_arg(f"cases: 0..{MAX_CASES} (got {count})", field="cases")
    rng = random.Random(seed)
    out: list[Case] = []
    seen: set[str] = set()

    def add(values: dict[str, Any], origin: str, dedupe: bool) -> None:
        key = case_key(sig, values)
        if dedupe and key in seen:
            return
        seen.add(key)
        out.append(Case(index=len(out), origin=origin, values=values))

    for vals in explicit or []:
        add(dict(vals), "explicit", False)
    for vals in replay or []:
        add(dict(vals), "replay", False)
    gen = sig.generated()
    if boundary:
        typical = {p.name: _typical(sig, p, rng) for p in gen}
        add(derive_lengths(sig, dict(typical)), "boundary", True)
        n_boundary = 0
        for p in gen:
            for v in _boundary_values(sig, p, rng):
                if n_boundary >= MAX_BOUNDARY_CASES:
                    break
                vals = dict(typical)
                vals[p.name] = v
                before = len(out)
                add(derive_lengths(sig, vals), "boundary", True)
                n_boundary += len(out) - before
    for _ in range(count):
        vals = {p.name: _random_value(sig, p, rng) for p in gen}
        add(derive_lengths(sig, vals), "random", True)
    return out


def case_key(sig: Signature, values: dict[str, Any]) -> str:
    """Canonical form of one case's inputs, for de-duplication."""
    return json.dumps({p.name: encode_value(sig, p, values[p.name])
                       for p in sig.params}, sort_keys=True)


# ---------------------------------------------------------------------------
# Guided generation
# ---------------------------------------------------------------------------

INPUT_MODES = ("guided", "random")
GUIDED_FRESH = 0.25        # share of guided-phase cases that are fresh


def _wrap_int(sig: Signature, p: Param, v: int) -> int:
    """*v* in *p*'s value space: clipped into ``range``, else wrapped to
    the type's width and signedness."""
    if p.range is not None:
        return max(p.range[0], min(p.range[1], v))
    if p.type == "bool":
        return v & 1
    width, signed = sig.int_spec(p.type)
    bits = width * 8
    v &= (1 << bits) - 1
    if signed and v >> (bits - 1):
        v -= 1 << bits
    return v


def _tokens(constants: Iterable[int]) -> list[bytes]:
    """Each constant as little-endian bytes, in the narrowest of 1, 2, 4
    or 8 bytes that holds it (``-1`` → ``ff``, ``0x5A4D`` → ``MZ``)."""
    out: list[bytes] = []
    seen: set[bytes] = set()
    for v in constants:
        for width in (1, 2, 4, 8):
            bits = width * 8
            if -(1 << (bits - 1)) <= v < (1 << bits):
                t = (v & ((1 << bits) - 1)).to_bytes(width, "little")
                if t not in seen:
                    seen.add(t)
                    out.append(t)
                break
    return out


class GuidedGen:
    """The guided phase's case source.

    A case is either fresh (as in slice 1, plus dictionary draws) or a
    mutation of a corpus entry — a case that reached a new edge of the
    original. The caller feeds the corpus with :meth:`add`, passing the
    compare log of the run that earned the entry. Half the mutations of
    an entry with a log are input-to-state: take a compare that failed
    (observed X, expected K) and write K where X sits in the input.
    Everything draws from one seeded stream, so the same seed, signature
    and feedback give the same cases.
    """

    def __init__(self, sig: Signature, *, seed: int,
                 constants: Iterable[int] = ()) -> None:
        self.sig = sig
        self.rng = random.Random(f"guided:{seed}")
        self.gen = sig.generated()
        self.ints = list(dict.fromkeys(int(c) for c in constants))
        self.tokens = _tokens(self.ints)
        self.dict_bytes = [t[0] for t in self.tokens if len(t) == 1 and t[0]]
        self.corpus: list[dict[str, Any]] = []
        self.logs: list[tuple[tuple[int, int, int], ...]] = []

    def add(self, values: dict[str, Any],
            cmp_log: Iterable[tuple[int, int, int]] = ()) -> None:
        self.corpus.append(dict(values))
        self.logs.append(tuple(cmp_log))

    def next(self) -> tuple[dict[str, Any], str]:
        """(values, origin) — origin ``random`` (fresh) or ``guided``."""
        rng = self.rng
        if not self.corpus or not self.gen or rng.random() < GUIDED_FRESH:
            vals = {p.name: self._fresh(p) for p in self.gen}
            return derive_lengths(self.sig, vals), "random"
        # Favor recent entries: they hold the newest edges.
        i = len(self.corpus) - 1 - int(len(self.corpus) * rng.random() ** 2)
        vals = dict(self.corpus[i])
        if self.logs[i] and rng.random() < 0.5 and \
                self._i2s(vals, rng.choice(self.logs[i])):
            return derive_lengths(self.sig, vals), "guided"
        k = 1 if len(self.gen) == 1 or rng.random() < 0.7 else 2
        for p in rng.sample(list(self.gen), k):
            vals[p.name] = self._mutate(p, vals[p.name])
        return derive_lengths(self.sig, vals), "guided"

    def _i2s(self, vals: dict[str, Any],
             obs: tuple[int, int, int]) -> bool:
        """Write the expected value where the observed one sits; False
        when no input holds it."""
        v, k, w = obs
        mask = (1 << (8 * w)) - 1
        params = list(self.gen)
        self.rng.shuffle(params)
        for p in params:
            if p.is_int:
                cur = vals[p.name]
                if cur & mask == v:
                    vals[p.name] = _wrap_int(self.sig, p, (cur & ~mask) | k)
                    return True
            elif p.is_memory and p.type != "buf_out":
                data = vals[p.name]
                vb, kb = v.to_bytes(w, "little"), k.to_bytes(w, "little")
                hits = [j for j in range(len(data) - w + 1)
                        if data[j:j + w] == vb]
                if hits:
                    j = self.rng.choice(hits)
                    data = data[:j] + kb + data[j + w:]
                elif p.is_string and v == 0 and \
                        len(data) // p.char_size < p.size_max:
                    data = data + kb          # the compare read the NUL
                else:
                    continue
                vals[p.name] = self._finish(p, self._units(p, data))
                return True
        return False

    # -- values --------------------------------------------------------------

    def _dict_int(self, p: Param) -> int:
        v = self.rng.choice(self.ints) + self.rng.choice((0, 0, 0, 1, -1))
        return _wrap_int(self.sig, p, v)

    def _fresh(self, p: Param) -> Any:
        rng = self.rng
        if p.is_int and self.ints and rng.random() < 0.25:
            return self._dict_int(p)
        v = _random_value(self.sig, p, rng)
        if p.is_memory and p.type != "buf_out" and self.tokens and \
                rng.random() < 0.3:
            units = self._units(p, v)
            t = self._token_units(p, rng.choice(self.tokens))
            pos = rng.randint(0, len(units))
            units[pos:pos] = t
            v = self._finish(p, units)
        return v

    def _mutate(self, p: Param, v: Any) -> Any:
        rng, sig = self.rng, self.sig
        if p.is_float:
            width = FLOAT_TYPES[p.type]
            r = rng.random()
            if r < 0.4:
                return v ^ (1 << rng.randrange(width * 8))
            if r < 0.6 and p.values:
                return float_bits(rng.choice(p.values), width)
            return _random_value(sig, p, rng)
        if p.is_int:
            r = rng.random()
            if r < 0.3 and self.ints:
                return self._dict_int(p)
            if r < 0.4 and p.values:
                return rng.choice(p.values)
            if r < 0.55:
                return rng.choice(_boundary_values(sig, p, rng))
            if r < 0.75:
                step = rng.randint(1, 16) * rng.choice((-1, 1))
                return _wrap_int(sig, p, v + step)
            if r < 0.9:
                width = 1 if p.type == "bool" else sig.int_spec(p.type)[0]
                return _wrap_int(sig, p, v ^ (1 << rng.randrange(width * 8)))
            return _random_value(sig, p, rng)
        if p.type == "buf_out":
            return bytes(rng.choice(_sizes(p))) if rng.random() < 0.5 else v
        return self._mutate_units(p, v)

    # -- buffers and strings, as units (bytes, or UTF-16 code units) ---------

    def _units(self, p: Param, v: bytes) -> list[int]:
        cs = p.char_size
        return [int.from_bytes(v[i:i + cs], "little")
                for i in range(0, len(v) - len(v) % cs, cs)]

    def _token_units(self, p: Param, t: bytes) -> list[int]:
        if p.char_size == 1 or len(t) == 1:
            return list(t)
        t = t + b"\0" * (len(t) % 2)
        return [int.from_bytes(t[i:i + 2], "little")
                for i in range(0, len(t), 2)]

    def _unit(self, p: Param) -> int:
        rng = self.rng
        r = rng.random()
        if r < 0.4 and self.dict_bytes:
            return rng.choice(self.dict_bytes)
        if p.is_string and r < 0.9:
            return rng.choice(_PRINTABLE)
        if p.is_string:
            return rng.randint(1, 0xFF if p.char_size == 1 else 0xFFFF)
        return rng.randrange(256)

    def _mutate_units(self, p: Param, v: bytes) -> bytes:
        rng = self.rng
        units = self._units(p, v)
        bits = 8 * p.char_size
        for _ in range(rng.randint(1, 3)):
            n = len(units)
            r = rng.random()
            if r < 0.2 and n:
                i = rng.randrange(n)
                units[i] ^= 1 << rng.randrange(bits)
            elif r < 0.4 and n:
                units[rng.randrange(n)] = self._unit(p)
            elif r < 0.55 and n < p.size_max:
                units.insert(rng.randint(0, n), self._unit(p))
            elif r < 0.65 and n > p.size_min:
                del units[rng.randrange(n)]
            elif r < 0.8 and self.tokens:
                t = self._token_units(p, rng.choice(self.tokens))
                pos = rng.randint(0, n)
                if rng.random() < 0.5:
                    units[pos:pos + len(t)] = t
                else:
                    units[pos:pos] = t
            elif r < 0.9 and len(self.corpus) > 1:
                other = self._units(p, rng.choice(self.corpus)[p.name])
                units = units[:rng.randint(0, n)] + \
                    other[rng.randint(0, len(other)):]
            else:
                size = rng.choice(_sizes(p))
                if size <= n:
                    units = units[:size]
                else:
                    units += [self._unit(p) for _ in range(size - n)]
        return self._finish(p, units)

    def _finish(self, p: Param, units: list[int]) -> bytes:
        """Back into *p*'s rules: no NUL inside a string, the size range,
        and ``size_multiple``."""
        rng = self.rng
        if p.is_string:
            units = [u or rng.choice(_PRINTABLE) for u in units]
        m = p.size_multiple
        hi = p.size_max - p.size_max % m
        units = units[:hi]
        while (len(units) < p.size_min or len(units) % m) and \
                len(units) < p.size_max:
            units.append(self._unit(p))
        return b"".join(u.to_bytes(p.char_size, "little") for u in units)


def preview_value(sig: Signature, p: Param, v: Any,
                  max_bytes: int = 64) -> Any:
    """Response-sized form of one input value."""
    enc = encode_value(sig, p, v)
    if isinstance(enc, dict) and "hex" in enc and len(v) > max_bytes:
        return {"hex": v[:max_bytes].hex(), "bytes": len(v),
                "truncated": True}
    if isinstance(enc, dict) and "text" in enc and len(enc["text"]) > \
            max_bytes:
        return {"text": enc["text"][:max_bytes], "chars": len(enc["text"]),
                "truncated": True}
    return enc


__all__ = ["Case", "GuidedGen", "INPUT_MODES", "MAX_CASES", "case_key",
           "decode_value", "derive_lengths", "encode_case", "encode_value",
           "generate_cases", "int_bounds", "parse_case_list",
           "preview_value", "read_cases_jsonl"]
