"""``resolve`` verb body (VA <-> module+offset <-> module!symbol).

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .._runtime.addrs import _addr, _addr_resolve
from .._runtime.response import _j, _j_hex


async def handle_resolve(ctx, c, *, pid: int, value: str, address: Any,
                         module: str, space: str, kernel: bool,
                         path: str) -> str:
    v = str(value or address or module or "").strip()
    if not v:
        return _j({"ok": False,
                    "error": "resolve: 'value' (or 'address' / 'module') required",
                    "hint": "value=0xfffff80000abc123 | value='ntoskrnl.exe+0xabc123' "
                            "| value='ntoskrnl.exe!PsLoadedModuleList'"})
    use_kernel = kernel or space in ("kernel", "physical") or space == "user" and pid == 0
    # `module!symbol(+addend)` — resolves the symbol's
    # RVA out of the module's PDB (dbghelp on a dumped/local
    # image), then adds the live module base. Needs a local
    # image: file_manage(action='dump_module') or path=.
    if "!" in v and not v.lower().startswith("0x"):
        from ..symbols import _resolve_image
        from .... import symbols as _sym
        mod_name, _, sym_expr = v.partition("!")
        sym_name, _, add_s = sym_expr.partition("+")
        mod_name = mod_name.strip()
        sym_name = sym_name.strip()
        try:
            add = _addr(add_s.strip()) if add_s.strip() else 0
        except (ValueError, TypeError) as exc:
            return _j({"ok": False, "kind": "invalid_parameter",
                       "error": f"resolve: bad addend in "
                                f"{v!r}: {exc}"})
        if not mod_name or not sym_name:
            return _j({"ok": False, "kind": "invalid_parameter",
                       "error": f"resolve: {v!r} not valid "
                                "module!symbol(+addend)"})
        mods = await c.mem_modules(pid, use_kernel)
        mod_low = mod_name.lower()
        hit_mod = None
        for m in mods:
            nm = str(m.get("name", "")).lower()
            pth = str(m.get("path", "")).lower()
            if (nm == mod_low or pth.endswith("\\" + mod_low)
                    or nm.startswith(mod_low)):
                hit_mod = m
                break
        if hit_mod is None:
            return _j({"ok": False, "kind": "module_not_found",
                       "error": f"resolve: module {mod_name!r} "
                                "not in the "
                                f"{'kernel' if use_kernel else 'user'} "
                                "module list",
                       "hint": "memory_manage(action='modules', "
                               "filter=…) to browse loaded "
                               "names"})
        b = hit_mod.get("base", 0)
        base_i = int(b, 0) if isinstance(b, str) else int(b)
        try:
            img, img_name = _resolve_image(ctx, mod_name, path)
        except _sym.SymbolError as exc:
            return _j({"ok": False, "kind": "module_not_found",
                       "error": str(exc)})
        try:
            rvas = await asyncio.to_thread(
                _sym.resolve_rvas, img, [sym_name],
                str(ctx.cfg.pdb_cache_dir()),
                ctx.cfg.symbols.allow_download,
                ctx.cfg.symbols.servers or None)
        except _sym.SymbolError as exc:
            return _j({"ok": False, "kind": "dbghelp_failed",
                       "error": str(exc)})
        if sym_name not in rvas:
            return _j({"ok": False, "kind": "symbol_not_found",
                       "error": f"{sym_name!r} not in "
                                f"{img_name!r}'s PDB",
                       "hint": "symbols_manage(action='resolve',"
                               f" module={mod_name!r}, ...) for "
                               "bulk lookups / diagnostics"})
        rva = rvas[sym_name]
        return _j_hex({"ok": True,
                       "va": base_i + rva + add,
                       "module": mod_name, "symbol": sym_name,
                       "rva": rva, "module_base": base_i,
                       "addend": add,
                       "resolved_from": "module!symbol"})
    # module+offset case — reuse existing helper.
    if "+" in v and not v.lower().startswith("0x"):
        va = await _addr_resolve(v, c, kernel=use_kernel, pid=pid, name="value")
        mod_name, _, off = v.partition("+")
        return _j_hex({"ok": True, "va": va,
                        "module": mod_name.strip(),
                        "offset": _addr(off),
                        "resolved_from": "module+offset"})
    # Numeric address case — search kernel/user module ranges.
    try:
        va = _addr(v, name="value")
    except ValueError:
        return _j({"ok": False,
                    "error": f"resolve: {v!r} not a hex/decimal address, "
                              "module+offset, or module!symbol notation",
                    "hint": "module!symbol needs a local image — "
                            "file_manage(action='dump_module') or "
                            "symbols_manage(action='resolve')"})
    mods = await c.mem_modules(pid, use_kernel)
    for m in mods:
        b = m.get("base", 0)
        s = m.get("size", 0)
        base_i = int(b, 0) if isinstance(b, str) else int(b)
        size_i = int(s, 0) if isinstance(s, str) else int(s)
        if base_i <= va < base_i + size_i:
            out: dict[str, Any] = {"ok": True, "va": va,
                                   "module": m.get("name"),
                                   "path": m.get("path"),
                                   "base": base_i,
                                   "offset": va - base_i,
                                   "module_size": size_i,
                                   "resolved_from": "address"}
            # best-effort symbolization — when a local
            # image exists for the module, SymFromAddrW names
            # the nearest symbol + displacement. Failures are
            # silent: symbol lookup is gravy, not the payload.
            try:
                from ..symbols import _resolve_image
                from .... import symbols as _sym
                img, _ = _resolve_image(
                    ctx, str(m.get("name") or ""), path)
                if img:
                    hit = await asyncio.to_thread(
                        _sym.lookup_rva, img, va - base_i,
                        str(ctx.cfg.pdb_cache_dir()),
                        ctx.cfg.symbols.allow_download,
                        ctx.cfg.symbols.servers or None)
                    if hit.get("found"):
                        out["symbol"] = hit["name"]
                        out["symbol_rva"] = hit["rva"]
                        out["symbol_disp"] = hit["displacement"]
            except Exception:
                pass
            return _j_hex(out)
    return _j_hex({"ok": True, "va": va, "module": None,
                    "resolved_from": "address_unresolved",
                    "hint": "VA is not inside any known module "
                            f"({'kernel' if use_kernel else 'user pid=' + str(pid)}) — "
                            "verify pid or space, or try the other side"})
