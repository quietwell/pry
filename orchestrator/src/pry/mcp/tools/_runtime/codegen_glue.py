"""Phase 1 codegen: disasm / assemble helpers.

Both actions are dispatched by ``memory_manage``. They live at module scope so
tests can import them directly without spinning up the whole FastMCP
server. The ``_annotate_symbols`` helper is reusable by any op_str
post-pass that wants ``module+offset`` hints next to raw constants.
"""

from __future__ import annotations

from typing import Any

from .addrs import _addr, _enrich_win32
from .response import _j, _j_hex


def _codegen_extra_err(exc: Exception) -> str:
    """Turn a CodegenUnavailable into the standard {ok:false, kind, ...} envelope."""
    from ....codegen import CodegenUnavailable
    if isinstance(exc, CodegenUnavailable):
        return _j({"ok": False, "kind": exc.kind, "error": str(exc),
                   "hint": exc.hint})
    # Bad-arg variants carry `.kind`/`.hint` attributes too.
    kind = getattr(exc, "kind", None) or "internal"
    hint = getattr(exc, "hint", "") or ""
    return _j({"ok": False, "kind": kind,
               "error": f"{type(exc).__name__}: {exc}",
               "hint": hint})


def _annotate_symbols(instructions: list[dict[str, Any]],
                      mods: list[dict[str, Any]]) -> None:
    """Best-effort: for every op_str that mentions a 0x... constant, if the
    value falls inside one of the mods, append ``module+offset`` alongside
    the raw value in a new ``sym`` field. Non-destructive to op_str.
    """
    if not mods or not instructions:
        for ins in instructions:
            ins.setdefault("sym", None)
        return

    # Build a sorted (base, size, name) table for O(log n) lookups.
    rows: list[tuple[int, int, str]] = []
    for m in mods:
        b = m.get("base", 0)
        s = m.get("size", 0)
        try:
            base_i = int(b, 0) if isinstance(b, str) else int(b)
            size_i = int(s, 0) if isinstance(s, str) else int(s)
        except Exception:
            continue
        if base_i and size_i:
            rows.append((base_i, size_i, str(m.get("name") or "")))
    rows.sort()

    def _lookup(va: int) -> str | None:
        # Linear scan is fine for typical module counts (< 500). If this
        # ever becomes hot, swap for bisect over (base, base+size).
        for base_i, size_i, nm in rows:
            if base_i <= va < base_i + size_i:
                return f"{nm}+0x{va - base_i:x}"
            if base_i > va:
                break
        return None

    import re as _re
    hex_pat = _re.compile(r"0x([0-9a-fA-F]+)")
    for ins in instructions:
        found = None
        for m in hex_pat.finditer(str(ins.get("op_str", ""))):
            try:
                va = int(m.group(1), 16)
            except ValueError:
                continue
            sym = _lookup(va)
            if sym is not None:
                found = sym
                break
        ins["sym"] = found


async def _mem_disasm(ctx, *, name: str, pid: int, space: str,
                       address: int, bytes_hex: str,
                       arch: str, syntax: str, count: int, size: int,
                       detail: bool, resolve_symbols: bool,
                       allow_fault: bool, timeout_s: float) -> str:
    """Dispatch handler for ``memory_manage(action='disasm')``."""
    from ....codegen import disasm as _disasm

    # Cap the caller-supplied count/size to keep responses bounded.
    max_count = min(int(count or 64), 4096)
    max_size = min(int(size or (max_count * 15)), 64 * 1024)

    truncated = False
    first_bad = 0
    source = "buffer"
    payload: bytes = b""

    if bytes_hex:
        try:
            payload = bytes.fromhex(bytes_hex.replace(" ", "").replace(",", ""))
        except ValueError as exc:
            return _j({"ok": False,
                       "error": f"disasm: bytes_hex not valid hex: {exc}",
                       "kind": "bad_arg"})
    else:
        if not address:
            return _j({"ok": False,
                       "kind": "bad_arg",
                       "error": "disasm: supply either bytes_hex or address"})
        source = "target"
        try:
            c = ctx.session.require_client(name)
        except Exception as exc:
            return _j({"ok": False, "kind": "no_target",
                       "error": f"disasm: no target connected: {exc}",
                       "hint": "target_manage(action='connect') first, "
                               "or pass bytes_hex for pure-compute disasm"})
        # Attempt partial read for graceful truncation on unmapped pages.
        try:
            got = await c.mem_read(pid, address, max_size, space,
                                    allow_fault=allow_fault,
                                    partial=True, want_meta=True,
                                    timeout=timeout_s or None)
            if isinstance(got, tuple):
                payload, meta = got
                first_bad = int(meta.get("first_bad_offset", 0))
                if int(meta.get("read_bytes", len(payload))) < max_size:
                    truncated = True
            else:
                payload = got
        except TypeError:
            # Older client stub without partial/want_meta support.
            payload = await c.mem_read(pid, address, max_size, space,
                                        allow_fault=allow_fault,
                                        timeout=timeout_s or None)
        except Exception as exc:
            return _j({"ok": False, "kind": "read_failed",
                       "error": f"disasm: mem_read failed: {exc}",
                       "hint": _enrich_win32(str(exc))})

    if not payload:
        return _j({"ok": True, "arch": arch, "start": hex(address),
                   "instructions": [], "bytes_used": 0,
                   "truncated": truncated, "source": source})

    try:
        instructions = _disasm(payload, arch,
                                syntax=syntax,
                                address=int(address or 0),
                                count=max_count,
                                detail=detail)
    except Exception as exc:
        return _codegen_extra_err(exc)

    bytes_used = sum(int(i.get("size", 0)) for i in instructions)
    if bytes_used < len(payload):
        truncated = True

    if resolve_symbols and source == "target":
        try:
            c = ctx.session.require_client(name)
            use_kernel = space in ("kernel", "physical")
            mods = await c.mem_modules(pid, use_kernel)
            _annotate_symbols(instructions, mods)
        except Exception:
            for ins in instructions:
                ins.setdefault("sym", None)
    else:
        for ins in instructions:
            ins.setdefault("sym", None)

    out = {"ok": True, "arch": arch, "start": hex(int(address or 0)),
           "instructions": instructions,
           "bytes_used": bytes_used,
           "truncated": truncated,
           "source": source}
    if first_bad:
        out["first_bad_offset"] = first_bad
    return _j_hex(out)


async def _mem_assemble(ctx, *, name: str, pid: int, space: str,
                         code: str, arch: str, address: int,
                         write_to: int | str, dry_run: bool,
                         allow_map_write: bool) -> str:
    """Dispatch handler for ``memory_manage(action='assemble')``."""
    from ....codegen import assemble as _assemble, disasm as _disasm, AssembleError

    if not code or not str(code).strip():
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "assemble: `code` is required"})

    # Write-target coercion.
    write_addr = 0
    if write_to:
        try:
            write_addr = _addr(write_to, name="write_to")
        except Exception as exc:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": f"assemble: bad write_to: {exc}"})

    # Refuse to silently write to a target when the caller left dry_run
    # at its default. The plan explicitly calls out this as `unsafe_default`.
    if write_addr and dry_run:
        return _j({"ok": False, "kind": "unsafe_default",
                   "error": "assemble: write_to set but dry_run=true; "
                            "set dry_run=false to authorize the write",
                   "hint": "dry_run=true assembles + returns bytes without "
                           "touching the target"})

    try:
        encoded, ins_count, labels = _assemble(code, arch,
                                                address=int(address or write_addr or 0))
    except AssembleError as exc:
        return _j({"ok": False, "kind": exc.kind,
                   "error": str(exc),
                   "hint": exc.hint,
                   "count": exc.count})
    except Exception as exc:
        return _codegen_extra_err(exc)

    # Round-trip through disasm so the caller sees exactly what the CPU sees.
    try:
        roundtrip = _disasm(encoded, arch,
                             address=int(address or write_addr or 0),
                             count=max(1, ins_count) * 2 + 8)
    except Exception:
        roundtrip = []

    resp: dict[str, Any] = {
        "ok": True,
        "bytes_hex": encoded.hex(),
        "size": len(encoded),
        "ins_count": ins_count,
        "dry_run": bool(dry_run),
        "roundtrip": roundtrip,
    }
    if labels:
        resp["labels"] = {k: hex(v) for k, v in labels.items()}

    if write_addr and not dry_run:
        if space == "user" and not pid:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "assemble+write: user-space write requires "
                                "pid=<target>; use space='kernel' for kernel "
                                "VAs"})
        try:
            c = ctx.session.require_client(name)
        except Exception as exc:
            return _j({"ok": False, "kind": "no_target",
                       "error": f"assemble+write: no target connected: {exc}"})
        try:
            written = await c.mem_write(pid, write_addr, encoded, space,
                                         allow_map_write=allow_map_write)
        except Exception as exc:
            return _j({"ok": False, "kind": "write_failed",
                       "error": f"assemble+write: mem_write failed: {exc}",
                       "hint": _enrich_win32(str(exc)),
                       "bytes_hex": encoded.hex(), "size": len(encoded)})
        resp["written"] = int(written)
        resp["write_to"] = hex(write_addr)

    return _j_hex(resp)


__all__ = [
    "_codegen_extra_err",
    "_annotate_symbols",
    "_mem_disasm",
    "_mem_assemble",
]
