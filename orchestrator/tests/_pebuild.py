"""General PE32 / PE32+ builder for the reconstruct and pe tests.

Unlike ``_pefixture`` (PE64, fixed 0x200-byte sections) this lays out a
real image: section alignment 0x1000, file alignment 0x200, headers
0x400, and

* ``.text``  at RVA 0x1000 (``text_pages`` pages),
* ``.rdata`` — imports, delay imports (RVA- or VA-based descriptors),
  exports, a load config with CFG check/dispatch pointer slots,
* ``.data``  — ``data`` bytes plus ``bss`` zero bytes past the raw end,
* ``.bss``   — optional, no raw data at all (``bss_section``).

``code`` is bytes or ``callable(layout) -> bytes`` so test code can
reference IAT slots, ``.data`` and the CFG slots by VA.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable

SECT_ALIGN = 0x1000
FILE_ALIGN = 0x200
HDR_SIZE = 0x400
TEXT_RVA = 0x1000

X_TEXT = 0x60000020
X_RDATA = 0x40000040
X_DATA = 0xC0000040
X_BSS = 0xC0000080


def _align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


@dataclass
class Layout:
    machine: str
    image_base: int
    ptr: int
    text_va: int
    rdata_va: int
    data_va: int
    bss_va: int
    iat: dict[str, int] = field(default_factory=dict)
    delay_iat: dict[str, int] = field(default_factory=dict)
    cfg_check_slot: int = 0
    cfg_dispatch_slot: int = 0


@dataclass
class Built:
    data: bytes
    layout: Layout
    exports: dict[str, int]      # name -> VA

    @property
    def image_base(self) -> int:
        return self.layout.image_base


class _Blob:
    """Append-only section body with RVA bookkeeping."""

    def __init__(self, rva: int) -> None:
        self.rva = rva
        self.buf = bytearray()

    def at(self) -> int:
        return self.rva + len(self.buf)

    def align(self, a: int) -> None:
        while len(self.buf) % a:
            self.buf.append(0)

    def put(self, b: bytes, a: int = 1) -> int:
        self.align(a)
        r = self.at()
        self.buf += b
        return r

    def reserve(self, n: int, a: int = 1) -> int:
        return self.put(bytes(n), a)

    def patch(self, rva: int, b: bytes) -> None:
        off = rva - self.rva
        self.buf[off:off + len(b)] = b


def build(*, machine: str = "x64", image_base: int | None = None,
          code: bytes | Callable[[Layout], bytes] = b"\xC3",
          text_pages: int = 1,
          imports: dict[str, list[str]] | None = None,
          delay_imports: dict[str, list[str]] | None = None,
          delay_va_based: bool = False,
          exports: dict[str, int] | None = None,
          data: bytes = b"", bss: int = 0, bss_section: int = 0,
          cfg: bool = False, cfg_initial: int = 0,
          dll: bool = True) -> Built:
    """*exports* maps name → offset into ``.text``."""
    x64 = machine == "x64"
    ptr = 8 if x64 else 4
    base = image_base if image_base is not None else (
        0x180000000 if x64 else 0x10000000)
    text_size = text_pages * SECT_ALIGN
    rdata_va = TEXT_RVA + text_size
    pfmt = "<Q" if x64 else "<I"
    ord_flag = 1 << (ptr * 8 - 1)

    # ---- .rdata: lay everything out first (code needs the slot VAs).
    rd = _Blob(rdata_va)
    lay = Layout(machine=machine, image_base=base, ptr=ptr,
                 text_va=base + TEXT_RVA, rdata_va=base + rdata_va,
                 data_va=0, bss_va=0)
    imp_dir = (0, 0)
    imports = imports or {}
    if imports:
        desc_rva = rd.reserve((len(imports) + 1) * 20, 4)
        imp_dir = (desc_rva, (len(imports) + 1) * 20)
        for i, (dll_name, names) in enumerate(imports.items()):
            name_rva = rd.put(dll_name.encode() + b"\0", 2)
            hints = [rd.put(b"\0\0" + n.encode() + b"\0", 2) for n in names]
            ilt = rd.put(b"".join(struct.pack(pfmt, h) for h in hints)
                         + bytes(ptr), ptr)
            iat = rd.put(b"".join(struct.pack(pfmt, h) for h in hints)
                         + bytes(ptr), ptr)
            for j, n in enumerate(names):
                lay.iat[f"{dll_name}!{n}"] = base + iat + j * ptr
            rd.patch(desc_rva + i * 20,
                     struct.pack("<IIIII", ilt, 0, 0, name_rva, iat))
    delay_dir = (0, 0)
    delay_imports = delay_imports or {}
    if delay_imports:
        d_rva = rd.reserve((len(delay_imports) + 1) * 32, 4)
        delay_dir = (d_rva, (len(delay_imports) + 1) * 32)
        bias = base if delay_va_based else 0
        for i, (dll_name, names) in enumerate(delay_imports.items()):
            name_rva = rd.put(dll_name.encode() + b"\0", 2)
            hmod = rd.reserve(ptr, ptr)
            hints = [rd.put(b"\0\0" + n.encode() + b"\0", 2) for n in names]
            int_t = rd.put(b"".join(struct.pack(pfmt, h + bias)
                                    for h in hints) + bytes(ptr), ptr)
            # Delay IAT slots start out pointing at an unmapped "thunk".
            iat = rd.put(b"".join(struct.pack(pfmt, 0xDEAD0000 + j)
                                  for j in range(len(names))) + bytes(ptr),
                         ptr)
            for j, n in enumerate(names):
                lay.delay_iat[f"{dll_name}!{n}"] = base + iat + j * ptr
            rd.patch(d_rva + i * 32, struct.pack(
                "<IIIIIIII", 0 if delay_va_based else 1, name_rva + bias,
                hmod + bias, iat + bias, int_t + bias, 0, 0, 0))
    lc_dir = (0, 0)
    if cfg:
        check = rd.put(struct.pack(pfmt, cfg_initial), ptr)
        disp = rd.put(struct.pack(pfmt, cfg_initial), ptr)
        lay.cfg_check_slot = base + check
        lay.cfg_dispatch_slot = base + disp
        size = 0x94 if x64 else 0x5C
        lc = bytearray(size)
        struct.pack_into("<I", lc, 0, size)
        if x64:
            struct.pack_into("<QQ", lc, 0x70, base + check, base + disp)
        else:
            struct.pack_into("<II", lc, 0x48, base + check, base + disp)
        lc_rva = rd.put(bytes(lc), 8)
        lc_dir = (lc_rva, size)
    exp_rva_size = (0, 0)
    exports = exports or {}
    if exports:
        names = sorted(exports)
        n = len(names)
        dir_rva = rd.reserve(40, 4)
        eat = rd.put(b"".join(struct.pack("<I", TEXT_RVA + exports[k])
                              for k in names), 4)
        name_rvas = [rd.put(k.encode() + b"\0") for k in names]
        npt = rd.put(b"".join(struct.pack("<I", r) for r in name_rvas), 4)
        ords = rd.put(b"".join(struct.pack("<H", i) for i in range(n)), 2)
        dll_name = rd.put(b"test.dll\0")
        rd.patch(dir_rva, struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dll_name,
                                      1, n, n, eat, npt, ords))
        exp_rva_size = (dir_rva, rd.at() - dir_rva)
    rdata_vsize = max(len(rd.buf), 1)

    data_rva = _align(rdata_va + rdata_vsize, SECT_ALIGN)
    data_vsize = max(len(data) + bss, 1)
    lay.data_va = base + data_rva
    bss_rva = _align(data_rva + data_vsize, SECT_ALIGN)
    lay.bss_va = base + bss_rva if bss_section else 0
    end_rva = bss_rva + (_align(bss_section, SECT_ALIGN) if bss_section
                         else 0)

    body = code(lay) if callable(code) else code
    if len(body) > text_size:
        raise ValueError("code larger than .text")

    sections = [(b".text", TEXT_RVA, text_size, body, X_TEXT),
                (b".rdata", rdata_va, rdata_vsize, bytes(rd.buf), X_RDATA),
                (b".data", data_rva, data_vsize, data, X_DATA)]
    if bss_section:
        sections.append((b".bss", bss_rva, bss_section, b"", X_BSS))

    # ---- headers
    hdr = bytearray(HDR_SIZE)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    nt = 0x80
    hdr[nt:nt + 4] = b"PE\0\0"
    opt_size = 0xF0 if x64 else 0xE0
    chars = 0x2022 if dll else 0x0022
    if not x64:
        chars |= 0x0100
    struct.pack_into("<HHIIIHH", hdr, nt + 4, 0x8664 if x64 else 0x14C,
                     len(sections), 0x5E2A5B00, 0, 0, opt_size, chars)
    opt = nt + 24
    struct.pack_into("<H", hdr, opt, 0x20B if x64 else 0x10B)
    struct.pack_into("<I", hdr, opt + 16, 0)              # no entry
    struct.pack_into("<I", hdr, opt + 20, TEXT_RVA)
    if x64:
        struct.pack_into("<Q", hdr, opt + 24, base)
    else:
        struct.pack_into("<I", hdr, opt + 24, rdata_va)   # BaseOfData
        struct.pack_into("<I", hdr, opt + 28, base)
    struct.pack_into("<II", hdr, opt + 32, SECT_ALIGN, FILE_ALIGN)
    struct.pack_into("<HHHHHH", hdr, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", hdr, opt + 56, end_rva)        # SizeOfImage
    struct.pack_into("<I", hdr, opt + 60, HDR_SIZE)
    struct.pack_into("<HH", hdr, opt + 68, 2, 0x0140)
    if x64:
        struct.pack_into("<QQQQII", hdr, opt + 72, 0x100000, 0x1000,
                         0x100000, 0x1000, 0, 16)
        dd = opt + 112
    else:
        struct.pack_into("<IIIIII", hdr, opt + 72, 0x100000, 0x1000,
                         0x100000, 0x1000, 0, 16)
        dd = opt + 96
    for idx, (rva, size) in ((0, exp_rva_size), (1, imp_dir),
                             (10, lc_dir), (13, delay_dir)):
        struct.pack_into("<II", hdr, dd + idx * 8, rva, size)
    sec_tab = opt + opt_size
    raw = HDR_SIZE
    blobs = []
    for i, (name, rva, vsize, content, ch) in enumerate(sections):
        raw_size = _align(len(content), FILE_ALIGN) if content else 0
        struct.pack_into("<8sIIIIIIHHI", hdr, sec_tab + i * 40, name,
                         vsize, rva, raw_size, raw if raw_size else 0,
                         0, 0, 0, 0, ch)
        if raw_size:
            blobs.append(content.ljust(raw_size, b"\0"))
            raw += raw_size
    img = bytes(hdr) + b"".join(blobs)
    return Built(data=img, layout=lay,
                 exports={k: base + TEXT_RVA + v for k, v in exports.items()})


def asm(source: str, machine: str, address: int) -> bytes:
    """Keystone-assemble *source* at *address* (tests importorskip it)."""
    import keystone
    ks = keystone.Ks(keystone.KS_ARCH_X86,
                     keystone.KS_MODE_64 if machine == "x64"
                     else keystone.KS_MODE_32)
    enc, _ = ks.asm(source, address)
    return bytes(enc or b"")
