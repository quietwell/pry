"""``read`` verb body — plain / batch / VA->PA / typed decode.

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
This file is a slice-doc hard-cap exception (§Phase R5 mapping table):
one logical verb with four parameterizations where splitting would
scatter the "which path am I on" validation.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.addrs import _addr, _addr_resolve
from .._runtime.response import _ascii, _j
from ._common import (
    _MMIO_BLOCKED_HINT,
    _kernel_va_err,
    _looks_invalid_addr,
    _looks_mmio_guard,
)


async def handle_read(ctx, c, *, pid: int, addr: int, size: int,
                      space: str, decode: Any, reads: list[dict] | None,
                      from_va: Any, resolve_physical: bool,
                      address: Any, module: str, path: str,
                      include_ascii: bool, allow_fault: bool,
                      allow_mmio: bool, partial: bool,
                      timeout_s: float, offset: int,
                      kernel_lookup: bool) -> str:
    # `offset` used to be a silent no-op on read
    # (the read branch never referenced it while `apply_page_opts`
    # consumed it for list actions). A caller migrating from a
    # base+offset call convention would see the wrong bytes with
    # no diagnostic. Refuse the read outright and point at the
    # intended migration path.
    if offset:
        return _j({"ok": False,
                   "kind": "unknown_kwarg",
                   "error": ("'offset' has no meaning on memory_manage read; "
                             "the read address is 'address' itself. "
                             "Pass address=hex(base+offset) if you want a "
                             "shifted read."),
                   "hint": f"add offset to address before calling: "
                           f"address = base + 0x{offset:X}"})
    # batch mode — a list of {va, size, decode?} dicts.
    # Every row runs independently; a single failed row appears as
    # {address, error, size:0} and the rest of the batch still
    # returns. `_addr_resolve` is used for module+offset support.
    if reads:
        from ...conversions import decode_buffer as _decode_buf
        from ...conversions import ConversionError as _ConvErr
        results: list[dict] = []
        for spec in reads:
            if not isinstance(spec, dict):
                results.append({"error": f"read entry must be a dict, "
                                f"got {type(spec).__name__}"})
                continue
            va_raw = spec.get("va") if "va" in spec else spec.get("address")
            sz_raw = spec.get("size", 0)
            dec = spec.get("decode")
            try:
                va_i = await _addr_resolve(va_raw, c,
                                           kernel=kernel_lookup,
                                           pid=pid, name="reads[].va")
                sz_i = int(sz_raw or 0)
                if sz_i <= 0:
                    results.append({"address": hex(va_i),
                                    "error": "size required (> 0)"})
                    continue
                row_data = await c.mem_read(pid, va_i, sz_i, space,
                                            allow_fault=allow_fault,
                                            timeout=timeout_s or None)
                row: dict[str, Any] = {"address": hex(va_i),
                                        "size": len(row_data),
                                        "hex": row_data.hex()}
                if include_ascii or not dec:
                    row["ascii"] = _ascii(row_data)
                if dec:
                    try:
                        decoded = _decode_buf(row_data, dec)
                    except _ConvErr as exc:
                        row["decode_error"] = f"{exc.kind}: {exc}"
                    else:
                        row["values"] = decoded["values"]
                        row["layout"] = decoded["layout"]
                        if decoded.get("truncated"):
                            row["truncated"] = True
                        if decoded.get("remainder_hex"):
                            row["remainder_hex"] = decoded["remainder_hex"]
                results.append(row)
            except Exception as exc:  # noqa: BLE001 - per-row salvage: one bad va must not sink the batch
                addr_hint = ""
                try:
                    addr_hint = hex(int(va_raw, 0)
                                    if isinstance(va_raw, str)
                                    else int(va_raw or 0))
                except (TypeError, ValueError):
                    addr_hint = str(va_raw)
                results.append({"address": addr_hint,
                                "error": f"{type(exc).__name__}: {exc}"})
        bad = any("error" in r for r in results)
        return _j({"batch": True,
                   "count": len(results),
                   "coverage": _coverage(
                       "mem-read",
                       "partial" if bad else "complete",
                       *(["read_failed_mid_buffer"] if bad
                         else [])),
                   "results": results})
    # VA -> PA -> physical read shortcut. One
    # driver round-trip replaces (va_translate) +
    # (memory_manage read space=physical). `resolve_physical=true`
    # with a non-physical space is invalid; `from_va` +
    # non-zero `address` is a collision.
    if resolve_physical and space != "physical":
        return _j({"ok": False, "kind": "invalid_parameter",
                   "error": ("resolve_physical=true only makes "
                             "sense with space='physical'; drop "
                             "either the flag or set space='physical'"),
                   "hint": "use plain memory_manage read for kernel or "
                           "user VAs"})
    if from_va and address:
        return _j({"ok": False, "kind": "kwarg_collision",
                   "error": ("read: pass either 'address' OR "
                             "'from_va', not both — the two "
                             "select different code paths (raw "
                             "PA vs VA-first translate)"),
                   "hint": "drop `address` when using from_va"})
    if from_va and (space == "physical" or resolve_physical):
        from_va_i = _addr(from_va, name="from_va")
        try:
            tr = await c.mem_va_translate(from_va_i,
                                           space="kernel",
                                           pid=pid)
        except Exception as exc:  # noqa: BLE001 - translate fault -> pte_absent
            return _j({"ok": False, "kind": "pte_absent",
                       "error": (f"mem_va_translate({hex(from_va_i)}) "
                                 f"failed: {type(exc).__name__}: {exc}"),
                       "hint": "the VA has no PTE; use probe_va for "
                               "the PML4/PDPT/PD/PT layer breakdown"})
        if not tr.get("present"):
            return _j({"ok": False, "kind": "pte_absent",
                       "error": (f"VA {hex(from_va_i)} has no valid PTE "
                                 f"(present=false)"),
                       "translate": tr,
                       "hint": "probe_va shows the layer that fenced "
                               "the walk"})
        pa = int(tr.get("pa", 0))
        n = size or 64
        # vNEXT T3.1 (PR#5): forward allow_mmio through the
        # VA->PA shortcut too. A VA that resolves into MMIO
        # (xHCI BAR for example) would otherwise mysteriously
        # succeed here but be refused by the plain physical
        # read path. Guard both routes identically.
        try:
            data = await c.mem_read(pid, pa, n, "physical",
                                     allow_fault=allow_fault,
                                     allow_mmio=allow_mmio,
                                     timeout=timeout_s or None)
        except Exception as exc:  # noqa: BLE001
            if not allow_mmio and _looks_mmio_guard(str(exc)):
                return _j({"ok": False, "kind": "mmio_blocked",
                           "error": f"read: {exc}",
                           "va": hex(from_va_i),
                           "physical_address": hex(pa),
                           "hint": _MMIO_BLOCKED_HINT})
            raise
        payload: dict[str, Any] = {
            "va": hex(from_va_i),
            "physical_address": hex(pa),
            "size": len(data),
            "hex": data.hex(),
            "cr3": hex(int(tr.get("cr3", 0))),
            "page_size_shift": int(tr.get("page_size_shift", 0)),
        }
        if decode:
            from ...conversions import decode_buffer as _decode_buf
            from ...conversions import ConversionError as _ConvErr
            try:
                decoded = _decode_buf(data, decode)
            except _ConvErr as exc:
                return _j({"ok": False, "kind": exc.kind,
                           "error": str(exc),
                           "hint": getattr(exc, "hint", "")})
            payload["values"] = decoded["values"]
            payload["layout"] = decoded["layout"]
            if decoded.get("truncated"):
                payload["truncated"] = True
        if include_ascii or not decode:
            payload["ascii"] = _ascii(data)
        payload["coverage"] = _coverage("mem-read", "complete")
        return _j(payload)
    n = size or 64
    # fail fast when the caller forgot both pid= and
    # space=kernel — otherwise the driver's PryUserMemRead
    # rejects Pid=0 with STATUS_INVALID_PARAMETER (c000000d)
    # and the caller sees a bare gle=87 with no hint. This
    # is the shape the field regression took: `mem_manage
    # read kernel=true` was routing to space=user before
    # the alias-promotion above landed.
    if space == "user" and not pid:
        return _j({"ok": False,
                   "error": "user-space read requires pid=<target>; "
                            "use space='kernel' for kernel VAs "
                            "(the driver rejects pid=0 user reads "
                            "with STATUS_INVALID_PARAMETER)"})
    # gRPC message cap on the agent side is 4 MiB. When the
    # caller asks for more, auto-use the streaming path
    # instead of refusing — v5 wired Memory.ReadStream so
    # this is now transparent.
    MAX_READ = 4 * 1024 * 1024 - 0x1000
    if n > MAX_READ:
        if not hasattr(c, "mem_read_all"):
            return _j({"ok": False,
                       "error": f"read size {n} exceeds per-call cap "
                                f"{MAX_READ}; agent < v5 (no ReadStream)"})
        data = await c.mem_read_all(pid, addr, n, space,
                                     allow_fault=allow_fault,
                                     timeout=timeout_s or None)
        return _j({"address": hex(addr), "size": len(data),
                   "hex": data.hex(), "ascii": _ascii(data),
                   "stream": True,
                   "coverage": _coverage(
                       "mem-read",
                       "complete" if len(data) >= n else "partial",
                       *(["read_failed_mid_buffer"]
                         if len(data) < n else []))})
    if partial:
        # v6 kernel PARTIAL: caller wants the valid prefix
        # + the offset of the first hole. Surface both.
        got = await c.mem_read(pid, addr, n, space,
                                allow_fault=allow_fault,
                                partial=True, want_meta=True,
                                timeout=timeout_s or None)
        data, meta = got
        hole = int(meta.get("read_bytes", len(data))) < n
        return _j({"address": hex(addr), "size": len(data),
                   "requested": n,
                   "hex": data.hex(), "ascii": _ascii(data),
                   "partial": True,
                   "read_bytes": meta.get("read_bytes", len(data)),
                   "first_bad_offset": meta.get("first_bad_offset", 0),
                   "coverage": _coverage(
                       "mem-read",
                       "partial" if hole else "complete",
                       *(["read_failed_mid_buffer"] if hole
                         else []))})
    try:
        # vNEXT T3.1 (PR#5): allow_mmio opts the physical read
        # out of the default-deny guard. want_meta=True surfaces
        # ``agent_without_allow_mmio`` from the agent-client so
        # we can warn when the orchestrator was built against
        # pre-T3.1 proto bindings.
        if space == "physical" and allow_mmio:
            data, _mmio_meta = await c.mem_read(
                pid, addr, n, space,
                allow_fault=allow_fault, want_meta=True,
                allow_mmio=True,
                timeout=timeout_s or None)
        else:
            _mmio_meta = {}
            data = await c.mem_read(pid, addr, n, space,
                                    allow_fault=allow_fault,
                                    timeout=timeout_s or None)
    except Exception as exc:  # noqa: BLE001 - point kernel-read INVALID_ADDRESS at dt/decode
        # vNEXT T3.1 (PR#5): STATUS_ACCESS_DENIED on a physical
        # read without allow_mmio means the driver guard tripped
        # on an out-of-RAM address. Surface the dedicated kind
        # so callers can distinguish "wedge-dangerous MMIO" from
        # the generic invalid_address family. Check the guard
        # first — INVALID_ADDRESS still routes to the dt/decode
        # pointer for kernel VAs.
        if space == "physical" and not allow_mmio and \
                _looks_mmio_guard(str(exc)):
            return _j({"ok": False, "kind": "mmio_blocked",
                       "error": f"read: {exc}",
                       "address": hex(addr),
                       "hint": _MMIO_BLOCKED_HINT})
        if space in ("kernel", "physical") and \
                _looks_invalid_addr(str(exc)):
            return _j(_kernel_va_err("read", exc))
        raise
    # `decode=` turns the raw bytes into typed
    # values. Always include hex+size so a caller who wants the
    # underlying buffer keeps it; skip the ascii preview unless
    # the caller explicitly asked (the values+layout are the
    # signal now, ascii mostly noise).
    payload: dict[str, Any] = {"address": hex(addr),
                                "size": len(data),
                                "hex": data.hex()}
    # vNEXT T3.1 (PR#5): warn when allow_mmio was asked but
    # this orchestrator was built against pre-T3.1 proto
    # bindings. The agent cannot see the flag so the read
    # falls through to pre-guard behaviour — same byte path
    # as before the field was added. Do NOT refuse; a
    # regression vs. today would be worse than a warning.
    if space == "physical" and allow_mmio \
            and _mmio_meta.get("agent_without_allow_mmio"):
        payload.setdefault("warnings", []).append(
            "allow_mmio flag not supported by this agent build; "
            "falling through to pre-guard behavior — upgrade "
            "agent for MMIO default-deny")
    if decode:
        from ...conversions import decode_buffer as _decode_buf
        from ...conversions import ConversionError as _ConvErr
        # named-type decode — decode={'type':
        # '_EPROCESS', 'module': 'ntoskrnl.exe'} (build_id /
        # path / source optional; module=/path= fall back to
        # the outer kwargs). Resolves via the IDA-dumped
        # layout cache or straight from the PDB with dbghelp.
        if isinstance(decode, dict) and \
                (decode.get("type") or decode.get("type_name")):
            from ..symbols import _resolve_type_layout
            from ...conversions import (
                decode_typed_buffer as _decode_typed)
            lay, lerr = await _resolve_type_layout(
                ctx, decode, module=module, path=path)
            if lerr is not None:
                return _j(lerr)
            try:
                decoded = _decode_typed(
                    data, lay["members"],
                    type_name=lay.get("type_name", ""),
                    size=lay.get("size", 0),
                    types=lay.get("types"),
                    max_depth=int(decode.get("depth") or 2))
            except _ConvErr as exc:
                return _j({"ok": False, "kind": exc.kind,
                           "error": str(exc),
                           "hint": getattr(exc, "hint", "")})
            payload["type"] = lay.get("type_name")
            payload["layout_source"] = lay.get("source")
            if lay.get("build_id"):
                payload["build_id"] = lay["build_id"]
            if lay.get("image"):
                payload["image"] = lay["image"]
            if lay.get("note"):
                payload["layout_note"] = lay["note"]
        else:
            try:
                decoded = _decode_buf(data, decode)
            except _ConvErr as exc:
                return _j({"ok": False, "kind": exc.kind,
                           "error": str(exc),
                           "hint": getattr(exc, "hint", "")})
        payload["values"] = decoded["values"]
        payload["layout"] = decoded["layout"]
        if decoded.get("truncated"):
            payload["truncated"] = True
        if decoded.get("remainder_hex"):
            payload["remainder_hex"] = decoded["remainder_hex"]
    if include_ascii or not decode:
        payload["ascii"] = _ascii(data)
    payload["coverage"] = _coverage(
        "mem-read", "complete" if len(data) >= n else "partial",
        *(["read_failed_mid_buffer"] if len(data) < n else []))
    return _j(payload)
