"""Per-case comparison of two runs.

Compared, in order (the first difference names the case's field):

1. the outcome class (``returned``, ``fault:write``, ...) — two runs that
   fault or trap the same way compare on the class alone;
2. the return value, masked to the declared width (the upper RAX bits
   of a 32-bit return are garbage); ``bool`` by truth value; floats
   bitwise unless ``float_ulps`` allows a distance (then any NaN equals
   any NaN);
3. every buffer and string, byte for byte, *including* the canary
   bytes either side of it — an over- or underrun shows up as a
   difference at a negative offset or past the end;
4. the order of default-stubbed API calls;
5. x86 only: the bytes the callee popped (``stdcall`` vs ``cdecl``).

Anything in the signature's ``ignore`` is skipped.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .harness import RunResult
from .signature import FLOAT_TYPES, Signature, bits_float

WINDOW = 16


@dataclass
class Diff:
    field: str
    original: Any
    reconstruction: Any
    offset: int | None = None
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"field": self.field,
                               "original": self.original,
                               "reconstruction": self.reconstruction}
        if self.offset is not None:
            out["offset"] = self.offset
        if self.detail:
            out["detail"] = self.detail
        return out


def show_ret(sig: Signature, v: int | None) -> Any:
    """Human form of a raw return value."""
    if v is None:
        return None
    rt = sig.ret
    if rt in FLOAT_TYPES:
        w = FLOAT_TYPES[rt]
        f = bits_float(v, w)
        return {"bits": f"0x{v:0{w * 2}x}", "value": repr(f)}
    width, signed = sig.int_spec(rt)
    bits = width * 8
    out: dict[str, Any] = {"hex": f"0x{v:0{width * 2}x}"}
    if signed and v >> (bits - 1):
        out["value"] = v - (1 << bits)
    else:
        out["value"] = v
    return out


def _ordered(bits: int, width: int) -> int:
    """Map float bits to a monotone integer line (for ULP distance)."""
    sign = 1 << (width * 8 - 1)
    return -(bits & (sign - 1)) if bits & sign else bits


def _float_equal(sig: Signature, a: int, b: int) -> bool:
    if a == b:
        return True
    if not sig.float_ulps:
        return False
    w = FLOAT_TYPES[sig.ret]
    fa, fb = bits_float(a, w), bits_float(b, w)
    if math.isnan(fa) and math.isnan(fb):
        return True
    if math.isnan(fa) or math.isnan(fb):
        return False
    return abs(_ordered(a, w) - _ordered(b, w)) <= sig.float_ulps


def _outcome(r: RunResult) -> str:
    return f"{r.outcome} ({r.detail})" if r.detail else r.outcome


def _buffer_diff(name: str, a: bytes, b: bytes,
                 window: tuple[int, int]) -> Diff | None:
    if a == b:
        return None
    pre, n = window
    i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]),
             min(len(a), len(b)))
    off = i - pre
    lo = max(0, i - WINDOW)
    hi = i + WINDOW
    if off < 0:
        where = f"{-off} byte(s) before the buffer (underrun)"
    elif off >= n:
        where = f"{off - n} byte(s) past the end of the {n}-byte buffer " \
                "(overrun)"
    else:
        where = f"inside the {n}-byte buffer"
    return Diff(field=name, offset=off, detail=where,
                original={"hex": a[lo:hi].hex(), "from": lo - pre},
                reconstruction={"hex": b[lo:hi].hex(), "from": lo - pre})


def compare_runs(sig: Signature, a: RunResult, b: RunResult, *,
                 stop_at_first: bool = False) -> list[Diff]:
    """Differences between *a* (original) and *b* (reconstruction)."""
    if a.outcome != b.outcome:
        return [Diff("outcome", _outcome(a), _outcome(b))]
    if a.outcome != "returned":
        return []
    diffs: list[Diff] = []
    if sig.ret != "void" and "ret" not in sig.ignore:
        ra, rb = a.ret, b.ret
        if sig.ret == "bool":
            same = bool((ra or 0) & 0xFF) == bool((rb or 0) & 0xFF)
        elif sig.ret in FLOAT_TYPES:
            same = ra is not None and rb is not None and \
                _float_equal(sig, ra, rb)
        else:
            same = ra == rb
        if not same:
            diffs.append(Diff("ret", show_ret(sig, ra), show_ret(sig, rb)))
            if stop_at_first:
                return diffs
    for p in sig.params:
        if not p.is_memory or p.name in sig.ignore:
            continue
        d = _buffer_diff(p.name, a.buffers.get(p.name, b""),
                         b.buffers.get(p.name, b""),
                         a.windows.get(p.name, (0, 0)))
        if d is not None:
            diffs.append(d)
            if stop_at_first:
                return diffs
    if "api" not in sig.ignore and a.api != b.api:
        i = next((k for k in range(min(len(a.api), len(b.api)))
                  if a.api[k] != b.api[k]), min(len(a.api), len(b.api)))
        diffs.append(Diff("api", list(a.api[:i + 8]), list(b.api[:i + 8]),
                          offset=i, detail=f"call order differs at call #{i}"))
        if stop_at_first:
            return diffs
    if sig.arch == "x86" and "cleanup" not in sig.ignore and \
            a.cleanup != b.cleanup:
        diffs.append(Diff("cleanup", a.cleanup, b.cleanup,
                          detail="bytes the callee popped (stdcall vs "
                                 "cdecl?)"))
    return diffs


__all__ = ["Diff", "compare_runs", "show_ret"]
