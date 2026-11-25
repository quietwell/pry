"""Primitive scalar readers, FILETIME conversion, and the magic-byte sniff.

Low-level helpers shared by every dump-body decoder in this package.
"""

from __future__ import annotations

import struct

from .offsets import MDMP_SIG, PAGE_SIG, VALID_32, VALID_64


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _filetime_to_iso(ft: int) -> str | None:
    """Windows FILETIME (100ns since 1601-01-01) -> ISO-8601 UTC."""
    if not ft:
        return None
    import datetime as _dt
    try:
        epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
        ts = epoch + _dt.timedelta(microseconds=ft / 10)
        return ts.isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _filetime_to_epoch_ms(ft: int) -> int:
    if not ft:
        return 0
    # 116444736000000000 = FILETIME ticks between 1601 and 1970.
    return int((ft - 116444736000000000) // 10000)


def dump_epoch_ms(parsed: dict) -> int:
    """Crash time as unix epoch ms (0 when unknown) — for same-boot
    freshness checks against status().boot_epoch_ms."""
    return _filetime_to_epoch_ms(int(parsed.get("system_time_filetime") or 0))


def sig_check(head: bytes) -> str | None:
    """Signature sniff for a probe buffer (first 8 bytes). Returns the
    format tag or None — used by the ``latest`` header probe."""
    if head[:4] == PAGE_SIG and head[4:8] in (VALID_64, VALID_32):
        return "kernel_dump"
    if head[:4] == MDMP_SIG:
        return "mdmp"
    return None
