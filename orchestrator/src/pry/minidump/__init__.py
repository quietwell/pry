"""Pure-Python Windows crash-dump parser.

Covers the kernel crash-dump family (``DUMP_HEADER64`` — full / summary /
triage / bitmap bodies) and, minimally, usermode minidumps ("MDMP").

The stable return shape WP1 callers rely on::

    {"ok": True, "format": "kernel_dump"|"mdmp",
     "bugcheck": {"code": int, "name": str},
     "params": [int, int, int, int],
     "context": {...} | None, "exception": {...} | None,
     "dtb": int|None, "kd_data_block": int|None,
     "size": int, "path": str, ...}

Header offsets were pinned against the WDK-internal ``Dump.h`` (Microsoft
Research Singularity tree mirror) and cross-checked against volatility's
``_DMP_HEADER64`` listing and a Windows-10 dump hexdump. The notable
trap: the 700-byte ``PhysicalMemoryBlockBuffer`` sits inside a union
with the 8-byte-aligned ``PHYSICAL_MEMORY_DESCRIPTOR64``, so the union
is 704 bytes — ``ContextRecord`` lands at 0x348 (not 0x344) and
``EXCEPTION_RECORD64`` at 0xF00.

Body layout depends on ``DumpType`` (@0xF98):

  * FULL(1)          — physical pages stored sequentially after the
                       0x2000 header, in ``PhysicalMemoryBlock`` run order.
  * SUMMARY(2),
    BITMAP_FULL(5),
    BITMAP_KERNEL(6) — ``SUMMARY_DUMP64`` subheader at 0x2000 carrying a
                       PFN-indexed bitmap; page data at its ``HeaderSize``
                       file offset (signature "SDMP"/"FDMP").
  * TRIAGE(4)        — ``TRIAGE_DUMP64`` at 0x2000; the saved call-stack
                       pages are embedded (this is what lives in
                       ``C:\\Windows\\Minidump\\*.dmp``).
  * HEADER(3)        — header only, no page data.
"""

from __future__ import annotations

from .bugcheck import bugcheck_name, dump_type_name
from .header import dump_epoch_ms, sig_check
from .live import resolve_va
from .parse import parse_dump
from .triage import read_triage_stack

__all__ = [
    "bugcheck_name",
    "dump_epoch_ms",
    "dump_type_name",
    "parse_dump",
    "read_triage_stack",
    "resolve_va",
    "sig_check",
]
