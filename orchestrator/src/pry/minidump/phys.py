"""Physical-address readers + VA->PA walker for kernel-dump bodies.

``_PhysReader`` abstracts the two body layouts the parser handles:
run-based (FULL) and PFN-bitmap (SUMMARY/BITMAP_*). ``_vtop`` walks the
dump's stored page tables so stack-frame reads can resolve a VA against
the physical pages the dump actually captured.
"""

from __future__ import annotations

from array import array

from .header import _u32, _u64
from .offsets import (
    HEADER_SIZE_64,
    PAGE_SIZE,
    _BITMAP_DUMP_TYPES,
    _OFF_PHYS_MEM,
    _SUM_BITMAP,
    _SUM_BITMAP_SIZE,
    _SUM_HEADER_SIZE,
    _SUM_SIGNATURE,
)


class _PhysReader:
    """Physical-address -> bytes for the kernel-dump body layouts.

    ``runs``  : [(base_pfn, page_count, file_offset)] — run-based bodies
                (DumpType FULL=1) where pages are packed in run order.
    ``bitmap``: (bitmap_bytes, data_start_file_offset) — PFN-indexed
                bodies (SUMMARY/BITMAP_*), bit i = PFN i present.
    """

    # Rank-table block size (bytes of bitmap per cumulative entry). 64 B =
    # 512 PFNs: a 16 GiB dump's 512 KiB bitmap -> 8K table entries, and a
    # rank query popcounts at most 63 bytes in C.
    _RANK_BLOCK = 64

    def __init__(self, fh, runs=None, bitmap=None, data_start=0):
        self._fh = fh
        self._runs = runs
        self._bitmap = bitmap
        self._data_start = data_start
        self._rank_table: array | None = None

    def _run_offset(self, pa: int) -> int | None:
        for base_pfn, page_count, file_off in self._runs or ():
            base = base_pfn * PAGE_SIZE
            if base <= pa < base + page_count * PAGE_SIZE:
                return file_off + (pa - base)
        return None

    def _build_rank_table(self) -> array:
        """Cumulative popcount at each ``_RANK_BLOCK`` boundary — built
        once per dump (the old per-read pure-Python popcount over the
        whole bitmap prefix was ~70 ms per physical read on 16 GiB)."""
        bitmap = self._bitmap
        blk = self._RANK_BLOCK
        table = array("Q", [0])
        total = 0
        for off in range(0, len(bitmap), blk):
            total += int.from_bytes(bitmap[off:off + blk], "little").bit_count()
            table.append(total)
        self._rank_table = table
        return table

    def _bitmap_rank(self, pfn: int) -> int:
        """Number of set bits below ``pfn`` in the PFN bitmap."""
        bitmap = self._bitmap
        table = self._rank_table or self._build_rank_table()
        nbytes, rem = divmod(pfn, 8)
        blk_i, _ = divmod(nbytes, self._RANK_BLOCK)
        start = blk_i * self._RANK_BLOCK
        count = table[blk_i]
        if nbytes > start:
            count += int.from_bytes(bitmap[start:nbytes], "little").bit_count()
        if rem:
            count += (bitmap[nbytes] & ((1 << rem) - 1)).bit_count()
        return count

    def pa_to_file(self, pa: int) -> int | None:
        if self._runs is not None:
            return self._run_offset(pa)
        if self._bitmap is not None:
            pfn = pa // PAGE_SIZE
            nbits = len(self._bitmap) * 8
            if pfn >= nbits:
                return None
            if not (self._bitmap[pfn // 8] >> (pfn % 8)) & 1:
                return None
            return self._data_start + self._bitmap_rank(pfn) * PAGE_SIZE
        return None

    def read(self, pa: int, n: int) -> bytes | None:
        off = self.pa_to_file(pa)
        if off is None or off < 0:
            return None
        self._fh.seek(off)
        data = self._fh.read(n)
        return data if len(data) == n else None

    def read_u64(self, pa: int) -> int | None:
        data = self.read(pa, 8)
        return _u64(data, 0) if data else None


def _vtop(phys: _PhysReader, dtb: int, va: int) -> int | None:
    """4-level x64 VA -> PA walk against the dump's stored pages."""
    if not dtb:
        return None
    cr3 = dtb & ~0xFFF
    masks = {
        4: 0x000FFFFFFFFFF000,   # entry points at next-level table
        3: 0x000FFFFFC0000000,   # 1 GiB page
        2: 0x000FFFFFFFE00000,   # 2 MiB page
        1: 0x000FFFFFFFFFF000,
    }
    e = phys.read_u64(cr3 + ((va >> 39) & 0x1FF) * 8)
    if not e or not (e & 1):
        return None
    e = phys.read_u64((e & masks[4]) + ((va >> 30) & 0x1FF) * 8)
    if not e or not (e & 1):
        return None
    if e & 0x80:  # PS — 1 GiB leaf
        return (e & masks[3]) + (va & 0x3FFFFFFF)
    e = phys.read_u64((e & masks[4]) + ((va >> 21) & 0x1FF) * 8)
    if not e or not (e & 1):
        return None
    if e & 0x80:  # PS — 2 MiB leaf
        return (e & masks[2]) + (va & 0x1FFFFF)
    e = phys.read_u64((e & masks[4]) + ((va >> 12) & 0x1FF) * 8)
    if not e or not (e & 1):
        return None
    return (e & masks[1]) + (va & 0xFFF)


def _stack_qwords(read_va, rsp: int, count: int = 32) -> list[dict[str, int]]:
    """qwords up the stack from ``rsp``; stops at the first unmapped gap."""
    out: list[dict[str, int]] = []
    va = rsp
    for _ in range(max(0, count)):
        data = read_va(va, 8)
        if data is None:
            break
        out.append({"va": va, "value": _u64(data, 0)})
        va += 8
    return out


def _phys_reader_from_header(fh, data: bytes, dump_type: int) -> _PhysReader | None:
    """Build the physical-memory reader matching the dump body layout."""
    if dump_type == 1:  # FULL — run-based pages right after the header
        num_runs = _u32(data, _OFF_PHYS_MEM)
        runs = []
        file_off = HEADER_SIZE_64
        for i in range(min(num_runs, 256)):
            base = _u64(data, _OFF_PHYS_MEM + 0x10 + i * 16)
            cnt = _u64(data, _OFF_PHYS_MEM + 0x18 + i * 16)
            runs.append((base, cnt, file_off))
            file_off += cnt * PAGE_SIZE
        return _PhysReader(fh, runs=runs)
    if dump_type in _BITMAP_DUMP_TYPES:
        fh.seek(HEADER_SIZE_64)
        sub = fh.read(_SUM_BITMAP)
        if len(sub) < _SUM_BITMAP:
            return None
        sig = bytes(sub[_SUM_SIGNATURE:_SUM_SIGNATURE + 4])
        if sig not in (b"SDMP", b"FDMP", b"DUMP"):
            return None
        header_size = _u32(sub, _SUM_HEADER_SIZE)
        bitmap_bits = _u32(sub, _SUM_BITMAP_SIZE)
        bitmap_len = (bitmap_bits + 7) // 8
        fh.seek(HEADER_SIZE_64 + _SUM_BITMAP)
        bitmap = fh.read(bitmap_len)
        if len(bitmap) != bitmap_len:
            return None
        data_start = header_size if header_size >= HEADER_SIZE_64 else \
            HEADER_SIZE_64 + _SUM_BITMAP + bitmap_len
        return _PhysReader(fh, bitmap=bitmap, data_start=data_start)
    return None
