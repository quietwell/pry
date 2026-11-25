"""Section → emulator-region planning shared by the Unicorn consumers.

``rop_emu`` (gadget/chain validation) and ``reconstruct`` (function
harness) both lay a PE's sections into a private Unicorn address space.
The walk over the section table — span, protection, which bytes to
write — lives here once; each consumer maps the planned regions with
its own primitive.

Two plans:

* ``full_vsize=False`` — the historical ``rop_emu`` plan: for a
  file-layout artifact only each section's raw bytes are mapped, so
  ``.bss`` past the raw end is absent and a section with no raw data is
  skipped. Kept bit-for-bit so gadget validation does not change.
* ``full_vsize=True`` — what executing a whole function needs: every
  section spans its full virtual size, zero-filled past the raw data,
  and the header page is mapped read-only (code reads ``__ImageBase``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .engine import ImageView


@dataclass(frozen=True)
class Region:
    """One planned region at its real (unmasked) VA.

    ``data`` lands at ``va``; the region spans ``size`` bytes, and any
    tail past ``len(data)`` is zero-filled by the mapper."""

    va: int
    data: bytes
    size: int
    prot: str      # subset of "rwx", always readable
    label: str


def section_prot(section) -> str:
    prot = "r"
    if section.writable:
        prot += "w"
    if section.exec:
        prot += "x"
    return prot


def image_regions(view: "ImageView", *,
                  full_vsize: bool = False) -> list[Region]:
    """Plan the regions for *view*'s image (or blob)."""
    img = view.img
    base = view.base_va
    out: list[Region] = []
    if img is None:
        # Blob source: the whole buffer is executable by definition.
        for s, e in view.exec_ranges():
            data = view.read(s, e - s)
            if data:
                out.append(Region(s, data, len(data), "rwx", "blob"))
        return out
    if full_vsize and img.sections:
        first = min(s.va for s in img.sections)
        hdr = view.read(base, min(first, 0x1000)) if first else b""
        if hdr:
            out.append(Region(base, hdr, max(first, len(hdr)), "r",
                              "headers"))
    for sec in img.sections:
        span = max(sec.vsize, sec.raw_size)
        if span <= 0:
            continue
        label = (sec.name or "").strip("\0")
        va = base + sec.va
        if not full_vsize:
            n = sec.raw_size if img.layout == "file" else span
            data = view.read(va, n)
            if not data:
                continue
            out.append(Region(va, data, len(data), section_prot(sec), label))
            continue
        if img.layout == "file":
            n = min(sec.raw_size, span)
        else:
            n = span
        data = view.read(va, n) if n else b""
        out.append(Region(va, data, span, section_prot(sec), label))
    return out
