"""Image-coherency mismatch classifier.

SI feature #1 (image coherency scoring) ports System Informer's
``imgcoherency`` to pry. The C++ fast path on umagent/agent walks
the mapped image vs the on-disk file, skipping bits set in the exclusion
bitmap (relocs, IAT, LoadConfig overrides, CFG tables, ImageBase in the
optional header), and produces a bytes_mismatched / bytes_compared ratio
plus a list of ``MismatchRange`` entries (RVA + length + section hint).

This module stays Python-only and testable without a target. It takes
the C++ side's ``mismatches`` list plus a section layout and emits a
single ``classification`` label — the semantic bucket an operator cares
about (``iat_hooked`` / ``inline_hooked`` / ``section_overwritten`` /
``relocs_unresolved`` / ``clean`` / ``unknown``).

The rules follow the slice doc (04-umagent-orchestrator.md §Feature 1,
"Core logic outline" step 8):

* every mismatch inside ``.idata`` or an IAT thunk run → ``iat_hooked``
* every mismatch is a run of <= 16 bytes at (or <= 32 bytes past) the
  start of a ``.text`` section → ``inline_hooked``
* any one section has > 60% of its bytes mismatched →
  ``section_overwritten``
* mismatches touch the reloc directory with a shaky exclusion bitmap →
  ``relocs_unresolved`` (implementation bug, not a hook)
* no mismatches → ``clean``
* otherwise ``unknown``.
"""

from __future__ import annotations

from typing import Any, Iterable


# Section-name heuristics. Case-insensitive; checked against ``name``
# field on each mismatch row (populated by the C++ side) or against the
# section layout the caller passes in.
_IAT_SECTION_NAMES = frozenset({".idata", ".iat"})
_TEXT_SECTION_NAMES = frozenset({".text"})


def _section_for_rva(rva: int, sections: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the section row (dict with ``name``, ``va``, ``size``) that
    contains *rva*, or ``None`` when no section matches. Linear scan — the
    section count is bounded by the PE spec (<=96)."""
    for sec in sections:
        try:
            va = int(sec.get("va", 0))
            size = int(sec.get("size", sec.get("vsize", 0)))
        except (TypeError, ValueError):
            continue
        if size <= 0:
            continue
        if va <= rva < va + size:
            return sec
    return None


def classify(
    mismatches: list[dict[str, Any]],
    *,
    sections: list[dict[str, Any]] | None = None,
    reloc_dir: tuple[int, int] | None = None,
) -> str:
    """Return a single-label classification for *mismatches*.

    *mismatches* is the list from the C++ side; each row carries at
    least ``rva`` and ``length``. ``hint`` / ``section`` are optional
    pre-labels the C++ fast path can set (e.g. ``iat_slot`` for IAT
    overlap) — they short-circuit the Python heuristics when present.

    *sections* is the module's section layout as a list of
    ``{"name": str, "va": int, "size": int}`` dicts. May be omitted
    when every mismatch already carries a ``section`` field.

    *reloc_dir* is the ``(rva, size)`` tuple of the base-reloc data
    directory. When mismatches overlap this range and the exclusion
    bitmap did not swallow them, we flag ``relocs_unresolved`` so the
    operator knows this is a config/implementation drift, not a hook.
    """
    if not mismatches:
        return "clean"

    sections = sections or []
    # First pass: resolve per-mismatch section hints and tally section
    # overlap by name. We also check reloc overlap because that pins
    # the ``relocs_unresolved`` bucket.
    reloc_rva, reloc_size = (reloc_dir or (0, 0))
    reloc_end = reloc_rva + reloc_size
    reloc_hits = 0
    section_hits: dict[str, int] = {}
    section_sizes: dict[str, int] = {}
    for sec in sections:
        name = str(sec.get("name", "")).lower()
        try:
            section_sizes[name] = int(sec.get("size", sec.get("vsize", 0)))
        except (TypeError, ValueError):
            section_sizes[name] = 0

    all_iat = True
    all_inline = True
    for m in mismatches:
        try:
            rva = int(m.get("rva", 0))
            length = int(m.get("length", 0))
        except (TypeError, ValueError):
            all_iat = False
            all_inline = False
            continue
        if length <= 0:
            continue
        # Reloc overlap — any touch is a signal.
        if reloc_size and rva < reloc_end and rva + length > reloc_rva:
            reloc_hits += 1
        # Section lookup — prefer the pre-labelled hint when the C++
        # side set one; otherwise walk the layout.
        sec_name = str(m.get("section", "")).lower()
        if not sec_name:
            sec = _section_for_rva(rva, sections)
            sec_name = str(sec.get("name", "")).lower() if sec else ""
        if sec_name:
            section_hits[sec_name] = section_hits.get(sec_name, 0) + length
        hint = str(m.get("hint", "")).lower()
        # IAT bucket: C++ hint wins; else section-name match.
        in_iat = hint in {"iat_slot", "iat"} or sec_name in _IAT_SECTION_NAMES
        if not in_iat:
            all_iat = False
        # Inline-hook bucket: short run near a .text section start.
        if sec_name in _TEXT_SECTION_NAMES and length <= 16:
            sec = _section_for_rva(rva, sections)
            sec_va = int(sec.get("va", 0)) if sec else 0
            if rva - sec_va > 32:
                all_inline = False
        else:
            all_inline = False

    if reloc_hits:
        # Reloc touches with the exclusion bitmap "shaky" — i.e. the
        # scorer surfaced them instead of swallowing them. Treat it as
        # a drift finding so operators don't chase a phantom hook.
        return "relocs_unresolved"

    if all_iat:
        return "iat_hooked"

    # Section-overwritten: a single section has > 60% mismatched bytes.
    for name, hit_bytes in section_hits.items():
        sec_size = section_sizes.get(name, 0)
        if sec_size and hit_bytes * 100 >= 60 * sec_size:
            return "section_overwritten"

    if all_inline:
        return "inline_hooked"

    return "unknown"


__all__ = ["classify"]
