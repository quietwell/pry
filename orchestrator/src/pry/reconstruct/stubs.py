"""Import stubs for the call harness.

Every IAT and delay-IAT slot of a mapped image points at a stub slot.
A stub is matched by **function name only** (the DLL is ignored), so a
user-mode ``VCRUNTIME140!memcpy``, an ``api-ms-win-crt-string`` import
and ``ntoskrnl!memcpy`` all reach the same semantics.

* **Semantic stubs** implement the pure memory/string routines (and the
  x86 64-bit math helpers) in Python. They are *not* part of the
  compared API order: an original with ``memcpy`` inlined and a
  reconstruction that imports it must still compare equal.
* **The default stub** logs the call (that order *is* compared),
  returns the signature's ``stubs`` value (0 by default) and marks the
  case ``api_stubbed``. On x86 it pops the stdcall argument bytes from
  the signature's ``argc``, else from a small built-in table, else 0.

Stubs never touch host state; they only read/write emulated memory and
respect page protections (a write into a read-only page faults as it
would natively).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:  # pragma: no cover
    from .harness import Harness

MAX_STUB_BYTES = 64 << 20       # a longer memcpy is a runaway length
MAX_SCAN = 1 << 20              # strlen & co. give up past this


class StubFault(Exception):
    """A stub touched memory the real routine would have faulted on."""

    def __init__(self, access: str, va: int, detail: str = "") -> None:
        super().__init__(f"{access} fault at {va:#x}")
        self.access = access
        self.va = va
        self.detail = detail


class StubCpuException(Exception):
    """A stub raised what the CPU would (``_alldiv`` by zero → #DE)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class StubLimit(Exception):
    """A runaway length (> ``MAX_STUB_BYTES`` over mapped memory)."""


# x86 stdcall argument dword counts for common imports the default stub
# may meet. Unlisted imports pop nothing (cdecl) unless the signature's
# ``stubs`` gives ``argc``.
KNOWN_X86_ARGC: dict[str, int] = {
    "GetTickCount": 0, "GetTickCount64": 0, "GetLastError": 0,
    "SetLastError": 1, "Sleep": 1, "SleepEx": 2, "GetCurrentProcess": 0,
    "GetCurrentThread": 0, "GetCurrentProcessId": 0,
    "GetCurrentThreadId": 0, "QueryPerformanceCounter": 1,
    "QueryPerformanceFrequency": 1, "GetSystemTimeAsFileTime": 1,
    "GetSystemTime": 1, "GetLocalTime": 1, "OutputDebugStringA": 1,
    "OutputDebugStringW": 1, "CloseHandle": 1, "GetModuleHandleA": 1,
    "GetModuleHandleW": 1, "GetProcAddress": 2, "LoadLibraryA": 1,
    "LoadLibraryW": 1, "FreeLibrary": 1, "VirtualAlloc": 4,
    "VirtualFree": 3, "VirtualProtect": 4, "HeapAlloc": 3, "HeapFree": 3,
    "HeapReAlloc": 4, "GetProcessHeap": 0, "ExitProcess": 1,
    "TerminateProcess": 2, "MultiByteToWideChar": 6,
    "WideCharToMultiByte": 8, "lstrlenA": 1, "lstrlenW": 1,
    "EnterCriticalSection": 1, "LeaveCriticalSection": 1,
    "InitializeCriticalSection": 1, "DeleteCriticalSection": 1,
    "TlsGetValue": 1, "TlsSetValue": 2, "GetVersion": 0,
    "IsDebuggerPresent": 0, "RaiseException": 4,
    "ExAllocatePoolWithTag": 3, "ExAllocatePool2": 3, "ExFreePoolWithTag": 2,
    "ExFreePool": 1, "KeQueryPerformanceCounter": 1, "KeGetCurrentIrql": 0,
    "KeQuerySystemTime": 1, "KeQueryTickCount": 1,
    "IoGetCurrentProcess": 0, "PsGetCurrentProcessId": 0,
    "PsGetCurrentThreadId": 0, "ZwClose": 1, "NtClose": 1,
}


# ---------------------------------------------------------------------------
# Helpers over the harness' memory API
# ---------------------------------------------------------------------------

def _cmp(a: bytes, b: bytes) -> int:
    return -1 if a < b else (1 if a > b else 0)


def _scan(h: "Harness", va: int, width: int, limit: int) -> bytes:
    """Bytes from *va* up to (not incl.) the first NUL unit."""
    out = bytearray()
    unit = b"\0" * width
    chunk = 0x100
    cur = va
    while len(out) < limit * width:
        data = h.read_mem(cur, chunk)
        for i in range(0, len(data) - width + 1, width):
            if data[i:i + width] == unit:
                out += data[:i]
                return bytes(out)
        out += data
        cur += chunk
    return bytes(out[:limit * width])


def _s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v >> 31 else v


def _s64(v: int) -> int:
    v &= (1 << 64) - 1
    return v - (1 << 64) if v >> 63 else v


# ---------------------------------------------------------------------------
# Semantic stubs: fn(harness) -> return value (int, full width)
# ---------------------------------------------------------------------------

def _memcpy(h: "Harness") -> int:
    dst, src, n = h.arg(0), h.arg(1), h.arg_size(2)
    h.write_mem(dst, h.read_mem(src, n))
    return dst


def _memset(h: "Harness") -> int:
    dst, c, n = h.arg(0), h.arg(1) & 0xFF, h.arg_size(2)
    h.write_mem(dst, bytes([c]) * n)
    return dst


def _memcmp(h: "Harness") -> int:
    a, b, n = h.arg(0), h.arg(1), h.arg_size(2)
    return _cmp(h.read_mem(a, n), h.read_mem(b, n)) & 0xFFFFFFFF


def _memchr(h: "Harness") -> int:
    s, c, n = h.arg(0), h.arg(1) & 0xFF, h.arg_size(2)
    idx = h.read_mem(s, n).find(bytes([c]))
    return 0 if idx < 0 else s + idx


def _strlen(h: "Harness") -> int:
    return len(_scan(h, h.arg(0), 1, MAX_SCAN))


def _strnlen(h: "Harness") -> int:
    return len(_scan(h, h.arg(0), 1, min(h.arg_size(1), MAX_SCAN)))


def _wcslen(h: "Harness") -> int:
    return len(_scan(h, h.arg(0), 2, MAX_SCAN)) // 2


def _wcsnlen(h: "Harness") -> int:
    return len(_scan(h, h.arg(0), 2, min(h.arg_size(1), MAX_SCAN))) // 2


def _strcmp_w(width: int, bounded: bool) -> Callable[["Harness"], int]:
    def fn(h: "Harness") -> int:
        limit = min(h.arg_size(2), MAX_SCAN) if bounded else MAX_SCAN
        a = _scan(h, h.arg(0), width, limit)
        b = _scan(h, h.arg(1), width, limit)
        if width == 2:
            ua = [int.from_bytes(a[i:i + 2], "little")
                  for i in range(0, len(a), 2)]
            ub = [int.from_bytes(b[i:i + 2], "little")
                  for i in range(0, len(b), 2)]
            return (-1 if ua < ub else (1 if ua > ub else 0)) & 0xFFFFFFFF
        return _cmp(a, b) & 0xFFFFFFFF
    return fn


def _strcpy_w(width: int) -> Callable[["Harness"], int]:
    def fn(h: "Harness") -> int:
        dst, src = h.arg(0), h.arg(1)
        h.write_mem(dst, _scan(h, src, width, MAX_SCAN) + b"\0" * width)
        return dst
    return fn


def _rtl_zero(h: "Harness") -> int:
    h.write_mem(h.arg(0), bytes(h.arg_size(1)))
    return 0


def _rtl_fill(h: "Harness") -> int:
    # RtlFillMemory(Destination, Length, Fill) — note the argument order.
    h.write_mem(h.arg(0), bytes([h.arg(2) & 0xFF]) * h.arg_size(1))
    return 0


def _rtl_move(h: "Harness") -> int:
    dst, src, n = h.arg(0), h.arg(1), h.arg_size(2)
    h.write_mem(dst, h.read_mem(src, n))
    return 0


def _rtl_compare(h: "Harness") -> int:
    a, b, n = h.arg(0), h.arg(1), h.arg_size(2)
    da, db = h.read_mem(a, n), h.read_mem(b, n)
    for i in range(n):
        if da[i] != db[i]:
            return i
    return n


# x86 64-bit math helpers. Stack: [esp+4]=a lo, +8 a hi, +12 b lo, +16 b
# hi; result in EDX:EAX; the callee pops 16 bytes. *dvrm* also return
# the remainder in EBX:ECX. The shifts take EDX:EAX and CL, pop nothing.

def _q(h: "Harness", n: int) -> int:
    return (h.arg(n) & 0xFFFFFFFF) | ((h.arg(n + 1) & 0xFFFFFFFF) << 32)


def _div_args(h: "Harness", signed: bool) -> tuple[int, int]:
    a, b = _q(h, 0), _q(h, 2)
    if b == 0:
        raise StubCpuException("divide_error")
    return (_s64(a), _s64(b)) if signed else (a, b)


def _trunc_div(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def _alldiv(h: "Harness") -> int:
    a, b = _div_args(h, True)
    return _trunc_div(a, b) & ((1 << 64) - 1)


def _aulldiv(h: "Harness") -> int:
    a, b = _div_args(h, False)
    return a // b


def _allrem(h: "Harness") -> int:
    a, b = _div_args(h, True)
    return (a - _trunc_div(a, b) * b) & ((1 << 64) - 1)


def _aullrem(h: "Harness") -> int:
    a, b = _div_args(h, False)
    return a % b


def _allmul(h: "Harness") -> int:
    return (_q(h, 0) * _q(h, 2)) & ((1 << 64) - 1)


def _dvrm(signed: bool) -> Callable[["Harness"], int]:
    def fn(h: "Harness") -> int:
        a, b = _div_args(h, signed)
        q = _trunc_div(a, b) if signed else a // b
        r = a - q * b
        r &= (1 << 64) - 1
        h.set_reg("ebx", r >> 32)
        h.set_reg("ecx", r & 0xFFFFFFFF)
        return q & ((1 << 64) - 1)
    return fn


def _shift(kind: str) -> Callable[["Harness"], int]:
    def fn(h: "Harness") -> int:
        v = (h.reg("eax") & 0xFFFFFFFF) | ((h.reg("edx") & 0xFFFFFFFF) << 32)
        n = h.reg("ecx") & 0xFF
        if kind == "shl":
            return 0 if n >= 64 else (v << n) & ((1 << 64) - 1)
        if kind == "shr":
            sv = _s64(v)
            return (sv >> min(n, 63)) & ((1 << 64) - 1)
        return 0 if n >= 64 else v >> n
    return fn


# name -> (fn, x86 callee-popped dwords, x86-only)
SEMANTIC: dict[str, tuple[Callable[["Harness"], int], int, bool]] = {
    "memcpy": (_memcpy, 0, False),
    "memmove": (_memcpy, 0, False),
    "memset": (_memset, 0, False),
    "memcmp": (_memcmp, 0, False),
    "memchr": (_memchr, 0, False),
    "strlen": (_strlen, 0, False),
    "strnlen": (_strnlen, 0, False),
    "wcslen": (_wcslen, 0, False),
    "wcsnlen": (_wcsnlen, 0, False),
    "strcmp": (_strcmp_w(1, False), 0, False),
    "strncmp": (_strcmp_w(1, True), 0, False),
    "wcscmp": (_strcmp_w(2, False), 0, False),
    "wcsncmp": (_strcmp_w(2, True), 0, False),
    "strcpy": (_strcpy_w(1), 0, False),
    "wcscpy": (_strcpy_w(2), 0, False),
    "RtlZeroMemory": (_rtl_zero, 2, False),
    "RtlFillMemory": (_rtl_fill, 3, False),
    "RtlMoveMemory": (_rtl_move, 3, False),
    "RtlCopyMemory": (_rtl_move, 3, False),
    "RtlCompareMemory": (_rtl_compare, 3, False),
    "_alldiv": (_alldiv, 4, True),
    "_aulldiv": (_aulldiv, 4, True),
    "_allrem": (_allrem, 4, True),
    "_aullrem": (_aullrem, 4, True),
    "_allmul": (_allmul, 4, True),
    "_alldvrm": (_dvrm(True), 4, True),
    "_aulldvrm": (_dvrm(False), 4, True),
    "_allshl": (_shift("shl"), 0, True),
    "_allshr": (_shift("shr"), 0, True),
    "_aullshr": (_shift("ushr"), 0, True),
}


def semantic_for(name: str, arch: str) -> tuple[Callable[["Harness"], int],
                                               int] | None:
    """The semantic stub for import *name* on *arch*, or ``None``."""
    row = SEMANTIC.get(name)
    if row is None:
        return None
    fn, argc, x86_only = row
    if x86_only and arch != "x86":
        return None
    return fn, argc


__all__ = ["KNOWN_X86_ARGC", "MAX_STUB_BYTES", "SEMANTIC", "StubCpuException",
           "StubFault", "StubLimit", "semantic_for"]
