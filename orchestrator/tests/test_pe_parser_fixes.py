"""PE parser fixes found while building reconstruct-and-verify.

* ``_parse_delay_imports`` unpacked 8 descriptor dwords into 7 names, so
  every delay-load descriptor raised and ``_parse_directories``
  swallowed it: delay imports never reached ``img.imports``.
* VC6-era delay descriptors (Attributes bit 0 clear) store VAs; their
  slots and names are now rebased to RVAs.
* ``rva_to_off`` (file layout) treated every RVA below "end of optional
  header + first section VA" as a header offset, so reads in the first
  ~0x200 bytes of ``.text`` came from the wrong file offset once the
  file was larger than that RVA.
* PE32 load config: the CFG dispatch / table / count / flags offsets
  were 4-8 bytes off.
"""

from __future__ import annotations

import struct

import _pebuild as pb
import pytest

from pry.analysis import pe
from pry.analysis.engine import ImageView
from pry.analysis.image_map import image_regions


@pytest.mark.parametrize("machine,va_based", [("x64", False), ("x86", False),
                                              ("x86", True)])
def test_delay_imports_reach_the_import_list(machine, va_based) -> None:
    # VA-based (VC6) descriptors hold 32-bit VAs, so they are PE32-only.
    b = pb.build(machine=machine,
                 imports={"KERNEL32.dll": ["GetTickCount"]},
                 delay_imports={"USER32.dll": ["MessageBoxA", "GetDC"],
                                "dbghelp.dll": ["SymInitialize"]},
                 delay_va_based=va_based)
    img = pe.parse(b.data)
    delayed = [d for d in img.imports if d["delayed"]]
    assert [d["dll"] for d in delayed] == ["USER32.dll", "dbghelp.dll"]
    names = [e["name"] for e in delayed[0]["entries"]]
    assert names == ["MessageBoxA", "GetDC"]
    # thunk_rva is an RVA for both descriptor kinds.
    slot = b.image_base + delayed[0]["entries"][1]["thunk_rva"]
    assert slot == b.layout.delay_iat["USER32.dll!GetDC"]
    regular = [d for d in img.imports if not d["delayed"]]
    assert regular[0]["entries"][0]["name"] == "GetTickCount"


def test_zeroed_delay_descriptor_does_not_raise() -> None:
    class Fake:
        pe32_plus = True
        imports: list = []
        imports_truncated = False
        image_base = 0x140000000

        def read_rva(self, rva, size):
            return bytes(size)

        def cstr_rva(self, rva, cap=260):
            return ""

    pe._parse_delay_imports(Fake(), 0x1000)   # used to raise ValueError
    assert Fake.imports == []


def test_reads_at_the_start_of_text_use_the_section_offset() -> None:
    marker = b"\x90\xCC" * 8 + b"TEXTSTART"
    b = pb.build(machine="x64", code=marker, data=b"D" * 0x1000)
    img = pe.parse(b.data)
    assert len(b.data) > 0x1200          # file bigger than the bad bound
    text = next(s for s in img.sections if s.name == ".text")
    assert text.raw_off == 0x400
    assert img.read_rva(0x1000, len(marker)) == marker
    assert img.read_rva(0x1010, 9) == b"TEXTSTART"
    # header bytes still map identity
    assert img.read_rva(0, 2) == b"MZ"


@pytest.mark.parametrize("machine", ["x64", "x86"])
def test_load_config_cfg_fields(machine) -> None:
    b = pb.build(machine=machine, cfg=True, cfg_initial=0x7FF00000)
    img = pe.parse(b.data)
    lc = img.load_config
    assert lc["guard_cf_check_va"] == b.layout.cfg_check_slot
    assert lc["guard_cf_dispatch_va"] == b.layout.cfg_dispatch_slot


def test_pe32_load_config_offsets() -> None:
    raw = bytearray(0x5C)
    struct.pack_into("<I", raw, 0, 0x5C)
    struct.pack_into("<IIIII", raw, 0x48, 0x11, 0x22, 0x33, 0x44, 0x55)

    class Img:
        pe32_plus = False
        directories = [(0, 0)] * 16
        load_config: dict = {}

        def read_rva(self, rva, size):
            return bytes(raw[:size])

    img = Img()
    img.directories = [(0, 0)] * 10 + [(0x2000, 0x5C)] + [(0, 0)] * 5
    pe._parse_load_config(img)
    lc = img.load_config
    assert (lc["guard_cf_check_va"], lc["guard_cf_dispatch_va"],
            lc["guard_cf_table_va"], lc["guard_cf_count"],
            lc["guard_flags"]) == (0x11, 0x22, 0x33, 0x44, 0x55)


def test_image_regions_full_vsize_maps_bss() -> None:
    b = pb.build(machine="x64", data=b"\x01\x02", bss=0x2000,
                 bss_section=0x3000, imports={"KERNEL32.dll": ["Sleep"]})
    view = ImageView(pe.parse(b.data))
    full = {r.label: r for r in image_regions(view, full_vsize=True)}
    assert full["headers"].prot == "r"
    assert full[".data"].size == 0x2002 and full[".data"].data[:2] == b"\1\2"
    assert full[".bss"].size == 0x3000 and full[".bss"].data == b""
    legacy = {r.label for r in image_regions(view, full_vsize=False)}
    # rop_emu's historical plan: raw bytes only, no headers, no .bss
    assert ".bss" not in legacy and "headers" not in legacy
    assert {".text", ".rdata", ".data"} <= legacy
