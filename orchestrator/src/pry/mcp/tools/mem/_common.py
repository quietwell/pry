"""Mem-local helpers lifted out of ``mem.py``'s ``register()`` closure.

Phase R4 pulls these pre-closure constants and small helper functions
up to module scope so the per-verb modules landing in Phase R5 can
import them directly instead of re-closing over the register scope.

Public surface is deliberately underscore-prefixed to match the
historical names callers inside ``memory_manage`` referenced through closure.
Every lifted body is byte-identical to the pre-R4 definition except
``_ptr_symbol``, which took the enclosing ``ctx`` through closure and
now takes it as an explicit first argument (slice doc §Commit 4).
"""

from __future__ import annotations

import asyncio
from typing import Any


__all__ = [
    "_KERNEL_QWORD_MIN",
    "_USER_QWORD_MIN",
    "_USER_QWORD_MAX",
    "_IDT_ALLOW_PREFIXES",
    "_MMIO_BLOCKED_HINT",
    "_looks_invalid_addr",
    "_looks_mmio_guard",
    "_kernel_va_err",
    "_mod_ranges",
    "_lookup_mod",
    "_ptr_symbol",
    "_fmt_modsym",
]


# ---- forensic verb constants ------------------------------------- #

_KERNEL_QWORD_MIN = 0xFFFF800000000000
_USER_QWORD_MIN = 0x10000
_USER_QWORD_MAX = 0x800000000000

# IDT handler allowlist (module-name prefixes). A handler landing
# anywhere else — or in no module at all — is flagged `suspicious`.
# It's a warning flag, not a verdict: hypervisor IDT detours are
# exactly what lights up here.
_IDT_ALLOW_PREFIXES = ("ntoskrnl", "ntkrnlmp", "hal", "kd", "cng",
                       "ksecdd", "pry")


# ---- module-range lookup ------------------------------------------------ #

def _mod_ranges(mods: list[dict]) -> list[tuple[int, int, str]]:
    """Module rows -> sorted [(lo, hi, name)] coverage list."""
    out: list[tuple[int, int, str]] = []
    for m in mods or []:
        try:
            b = m.get("base", 0)
            z = m.get("size", 0)
            b_i = int(b, 0) if isinstance(b, str) else int(b or 0)
            z_i = int(z, 0) if isinstance(z, str) else int(z or 0)
        except (TypeError, ValueError):
            continue
        if b_i and z_i:
            out.append((b_i, b_i + z_i, str(m.get("name", ""))))
    out.sort()
    return out


def _lookup_mod(ranges: list[tuple[int, int, str]],
                va: int) -> tuple[int, int, str] | None:
    # Module lists are small (~hundreds); a linear scan is fine and
    # tolerates overlapping ranges better than bisect.
    for lo, hi, nm in ranges:
        if lo <= va < hi:
            return lo, hi, nm
    return None


async def _ptr_symbol(ctx: Any, img_cache: dict, mod_name: str, off: int,
                      path: str = "") -> dict | None:
    """Best-effort RVA -> symbol via lookup_rva — silent on any miss.

    `img_cache` maps module name -> local image path (or None) so a
    bulk scan pays the artifacts-dir probe once per module.

    ``ctx`` is the ``Context`` the closure used to capture — passed in
    explicitly post-R4 so this helper can live at module scope.
    """
    if mod_name not in img_cache:
        try:
            from ..symbols import _resolve_image
            img, _ = _resolve_image(ctx, mod_name, path)
        except Exception:  # noqa: BLE001 - no local image = no symbols
            img = None
        img_cache[mod_name] = img
    img = img_cache.get(mod_name)
    if not img:
        return None
    try:
        from .... import symbols as _sym
        hit = await asyncio.to_thread(
            _sym.lookup_rva, img, off,
            str(ctx.cfg.pdb_cache_dir()),
            ctx.cfg.symbols.allow_download,
            ctx.cfg.symbols.servers or None)
        if hit.get("found"):
            return hit
    except Exception:  # noqa: BLE001 - symbolization is gravy
        pass
    return None


def _fmt_modsym(row: dict) -> str:
    """'ntoskrnl.exe!KiDispatchException+0x10' / 'ntoskrnl.exe+0x1234'."""
    mod = str(row.get("module") or "")
    if not mod:
        return ""
    sym = row.get("symbol")
    if sym:
        disp = int(row.get("symbol_disp") or 0)
        return f"{mod}!{sym}+{disp:#x}" if disp else f"{mod}!{sym}"
    return f"{mod}+{int(row.get('rva') or 0):#x}"


# ---- NTSTATUS / Win32 projection sniffers ------------------------------- #

def _looks_invalid_addr(msg: str) -> bool:
    m = msg.upper()
    # the MMIO/BAR class joins the family — device-backed VAs
    # fail MmCopyMemory with NTSTATUS whose Win32 projection is
    # gle=59 (UNEXP_NET_ERR) or gle=1117 (IO_DEVICE); the raw nt=
    # forms ride along once comm surfaces them.
    return ("STATUS_INVALID_ADDRESS" in m or "C0000141" in m
            or "GLE=487" in m
            or "GLE=59" in m or "GLE=1117" in m
            or "UNEXP_NET_ERR" in m or "IO_DEVICE" in m
            or "C00000E9" in m or "C00000C4" in m
            or "C0000185" in m)


def _looks_mmio_guard(msg: str) -> bool:
    """vNEXT T3.1 (PR#5): the driver returns STATUS_ACCESS_DENIED
    (0xC0000022) when the physical-read guard trips on an out-of-RAM
    address and allow_mmio was not set. STATUS_INVALID_ADDRESS stays
    reserved for genuinely-invalid addresses that fell through the
    map paths, so matching the DENIED code (and its Win32 projection
    gle=5) is specific to the guard."""
    m = msg.upper()
    return ("STATUS_ACCESS_DENIED" in m or "C0000022" in m
            or "GLE=5" in m)


_MMIO_BLOCKED_HINT = (
    "address is outside RAM ranges. Pass allow_mmio=True to attempt — "
    "WARNING: reading PCI device MMIO (xHCI, GPU, NIC) can wedge the "
    "driver. Prefer the hv UC-alias path for device inspection.")


def _kernel_va_err(action: str, exc: Exception) -> dict:
    """INVALID_ADDRESS on a kernel read — enrich in-place with
    the dt/decode pointer (_error_enrich isn't reachable from here)."""
    return {"ok": False, "kind": "invalid_address",
            "error": f"{action}: {exc}",
            "hint": ("kernel VA is unmapped, outside a valid range, or "
                     "backed by MMIO/device memory MmCopyMemory won't "
                     "touch — memory_manage(action='probe_va') tests "
                     "readability, memory_manage(action='va_translate') shows "
                     "the PA (a BAR-backed page reads via "
                     "space='physical' at that PA). For struct dumps "
                     "prefer memory_manage(action='dt', value='<TYPE>', ...) "
                     "or read decode={'type':..., 'module':...}")}
