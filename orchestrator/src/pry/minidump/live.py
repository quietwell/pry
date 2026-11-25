"""Live-target VA -> ``{module, offset, base, text, symbol?}`` resolver.

Deliberately a second copy of ``memory_manage``'s ~15-line module walk —
``mem.py`` is owned by WP2, so WP1 carries its own per ``_shared.md``.
"""

from __future__ import annotations

import asyncio
from typing import Any


async def resolve_va(ctx, c, va: int, *, kernel: bool = True,
                     pid: int = 0) -> dict[str, Any] | None:
    """VA -> ``{module, offset, base, text, symbol?}`` against the live
    target's module map, with best-effort PDB symbolization.

    Deliberately a second copy of memory_manage ``resolve``'s ~15-line module
    walk — mem.py is owned by WP2, so WP1 carries its own per _shared.md.
    Returns None when the VA falls outside every known module (or the
    module list can't be fetched).
    """
    try:
        mods = await c.mem_modules(pid, kernel)
    except Exception:
        return None
    hit: tuple[dict, int, int] | None = None
    for m in mods:
        try:
            base_i = int(m.get("base") or 0)
            size_i = int(m.get("size") or 0)
        except (TypeError, ValueError):
            continue
        if base_i and base_i <= va < base_i + size_i:
            hit = (m, base_i, size_i)
            break
        if base_i > va:
            break
    if hit is None:
        return None
    m, base_i, size_i = hit
    off = va - base_i
    name = str(m.get("name") or "?")
    row: dict[str, Any] = {
        "va": va, "module": name, "path": m.get("path"),
        "base": base_i, "offset": off, "module_size": size_i,
        "text": f"{name}+0x{off:x}",
    }
    # Symbolization is gravy: _resolve_image needs a local copy of the
    # module (dumped/ingested), dbghelp needs the PDB — either failing is
    # silent, the module+offset text stands.
    try:
        from .. import symbols as _sym
        from ..mcp.tools.symbols import _resolve_image
        img, _img_name = _resolve_image(ctx, name, "")
        if img:
            cfg = ctx.cfg
            pdb_cache = (str(cfg.pdb_cache_dir())
                         if hasattr(cfg, "pdb_cache_dir")
                         else str(getattr(getattr(cfg, "artifacts", None),
                                          "pdb_cache", "") or ""))
            symcfg = getattr(cfg, "symbols", None)
            hit2 = await asyncio.to_thread(
                _sym.lookup_rva, img, off, pdb_cache,
                getattr(symcfg, "allow_download", True),
                getattr(symcfg, "servers", None) or None)
            if isinstance(hit2, dict) and hit2.get("found"):
                row["symbol"] = hit2["name"]
                row["symbol_rva"] = hit2.get("rva")
                disp = int(hit2.get("displacement") or 0)
                row["symbol_disp"] = disp
                row["text"] = f"{name}!{hit2['name']}+0x{disp:x}"
    except Exception:
        pass
    return row
