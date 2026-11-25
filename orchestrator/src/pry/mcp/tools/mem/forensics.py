"""Forensic verb bodies: ``resolve_range``/``dps``, ``dt``, ``idt``,
``walk_list``, ``read_qwords``, ``read_unicode_string`` / ``read_ansi_string``.

Phase R5 move — every body lifted verbatim from ``mem.py``'s
``register()`` closure.
"""

from __future__ import annotations

import struct
from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.addrs import _addr
from .._runtime.envelope import _list_envelope
from .._runtime.response import _ascii, _hexify_dict, _j
from ._common import (
    _IDT_ALLOW_PREFIXES,
    _KERNEL_QWORD_MIN,
    _USER_QWORD_MAX,
    _USER_QWORD_MIN,
    _fmt_modsym,
    _kernel_va_err,
    _looks_invalid_addr,
    _lookup_mod,
    _mod_ranges,
    _ptr_symbol,
)


async def handle_resolve_range(ctx, c, *, action: str, pid: int,
                               addr: int, base_i: int, size: int,
                               space: str, allow_fault: bool,
                               timeout_s: float, resolve_symbols: bool,
                               path: str, include_ascii: bool,
                               compact: bool, verbosity: str,
                               filter: Any, summary: bool,
                               fields: list[str] | None, limit: int,
                               offset: int, max_results: int) -> str:
    # dps-style pointer annotation over a
    # range. Each qword is classified by canonical VA shape and
    # resolved against the module map; symbolization is opt-in
    # (resolve_symbols) since it's one dbghelp call per unique
    # module. `partial=True` makes PTE holes truncate the sweep
    # honestly instead of failing it.
    start = base_i or addr
    if not size or int(size) <= 0:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"{action}: size= is required (>0, "
                            "cap 1 MiB)",
                   "hint": "memory_manage(action='resolve_range', "
                           "space='kernel', address='0x...', "
                           "size=0x200)"})
    if space == "user" and not pid:
        return _j({"ok": False,
                   "error": "user-space resolve_range requires "
                            "pid=<target>; use space='kernel' "
                            "for kernel VAs (the driver rejects "
                            "pid=0 user reads with "
                            "STATUS_INVALID_PARAMETER)"})
    n = min(int(size), 0x100000)
    try:
        got = await c.mem_read(pid, start, n, space,
                               allow_fault=allow_fault,
                               partial=True, want_meta=True,
                               timeout=timeout_s or None)
    except Exception as exc:  # noqa: BLE001 - same INVALID_ADDRESS hint as read
        if space in ("kernel", "physical") and \
                _looks_invalid_addr(str(exc)):
            return _j(_kernel_va_err(action, exc))
        raise
    if isinstance(got, tuple):
        data, meta = got
    else:
        data, meta = got, {}
    # Kernel pointers resolve against the kernel module map no
    # matter the scan space (a user-space buffer can hold
    # kernel VAs); user pointers resolve against the pid's
    # list when a pid was given. Both lists are best-effort —
    # a umagent view can't enumerate kernel modules.
    kernel_ranges: list[tuple[int, int, str]] = []
    user_ranges: list[tuple[int, int, str]] = []
    try:
        kernel_ranges = _mod_ranges(
            await c.mem_modules(pid, True))
    except Exception:  # noqa: BLE001 - unresolved stays honest
        kernel_ranges = []
    if pid:
        try:
            user_ranges = _mod_ranges(
                await c.mem_modules(pid, False))
        except Exception:  # noqa: BLE001
            user_ranges = []
    rows: list[dict] = []
    pointers = 0
    resolved = 0
    img_cache: dict[str, Any] = {}
    qwords = len(data) // 8
    for i in range(qwords):
        off = i * 8
        (q,) = struct.unpack_from("<Q", data, off)
        row: dict[str, Any] = {"off": off, "va": q}
        if q == 0:
            row["class"] = "zero"
        elif q >= _KERNEL_QWORD_MIN:
            pointers += 1
            hit = _lookup_mod(kernel_ranges, q)
            if hit:
                lo, _hi, mod = hit
                row["class"] = "kernel"
                row["module"] = mod
                row["rva"] = q - lo
                resolved += 1
            else:
                row["class"] = "kernel_unresolved"
        elif _USER_QWORD_MIN <= q < _USER_QWORD_MAX:
            row["class"] = "user"
            pointers += 1
            hit = _lookup_mod(user_ranges, q)
            if hit:
                lo, _hi, mod = hit
                row["module"] = mod
                row["rva"] = q - lo
                resolved += 1
        else:
            row["class"] = "nonptr"
        if resolve_symbols and row.get("module"):
            sym = await _ptr_symbol(
                ctx, img_cache, row["module"],
                int(row["rva"]), path)
            if sym:
                row["symbol"] = sym["name"]
                row["symbol_rva"] = sym.get("rva")
                row["symbol_disp"] = sym.get("displacement")
        row["name"] = _fmt_modsym(row) or \
            f"<{row['class'].replace('_', ' ')}>"
        rows.append(row)
    # Class gate: `filter` doubles as the row-class selector.
    # "" / "ptr" keeps pointer-looking rows (+zeros when
    # include_ascii doubles as include_zeros); "all" dumps
    # every scanned qword; any other string/dict filters the
    # pointer rows through _list_envelope as usual.
    flt = filter.strip().lower() if isinstance(filter, str) else ""
    keep_ptr = {"kernel", "kernel_unresolved", "user"}
    if include_ascii:  # repurposed: include_zeros
        keep_ptr.add("zero")
    if isinstance(filter, dict) and filter:
        kept, env_filter = rows, filter
    elif flt == "all":
        kept, env_filter = rows, ""
    else:
        kept = [r for r in rows if r["class"] in keep_ptr]
        env_filter = "" if flt in ("", "ptr") else filter
    if compact or verbosity == "compact":
        if env_filter:
            # Row filters operate on dicts — apply before the
            # text-line collapse (a dict filter on str rows
            # would crash _filter_rows).
            from ..._envelope.paging import _filter_rows as _fr
            kept = _fr(kept, env_filter)
            env_filter = ""
        kept = [f"off={r['off']:#06x}  0x{r['va']:016X}  "
                f"{r['name']}" for r in kept]
    extras: dict[str, Any] = {
        "start": hex(start), "space": space,
        "scanned": len(data), "requested": n,
        "qwords": qwords,
        "pointers": pointers, "resolved": resolved,
        "truncated": len(data) < n,
    }
    if meta.get("first_bad_offset"):
        extras["first_bad_offset"] = meta["first_bad_offset"]
    if meta.get("first_bad_offset") or len(data) < n:
        cov = _coverage("mem-read", "partial",
                        "read_failed_mid_buffer")
    else:
        cov = _coverage("mem-read", "complete")
    env = _list_envelope(
        kept, tool="memory_manage", action=action,
        limit=limit or max_results, offset=offset,
        fields=fields or (),
        filter=env_filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras=extras,
    )
    env["coverage"] = cov
    return _hexify_dict(env, add_int_mirror=True)


async def handle_dt(ctx, c, *, pid: int, addr: int, size: int,
                    space: str, value: str, module: str, path: str,
                    decode: Any, include_ascii: bool,
                    allow_fault: bool, timeout_s: float) -> str:
    # named-type read sugar — the
    # `read decode={'type':...}` path without making the
    # caller spell the decode dict. `value` is the type name;
    # a decode={} dict still merges in for the exotic knobs
    # (build_id/source/depth/cache_dir).
    tname = str(value or "").strip()
    if not tname:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "dt: value='<TYPE_NAME>' is "
                            "required (e.g. "
                            "value='_KTRAP_FRAME')",
                   "hint": "memory_manage(action='dt', "
                           "value='_KTRAP_FRAME', "
                           "module='ntoskrnl.exe', "
                           "space='kernel', address='0x...')"})
    if not addr:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "dt: address= is required",
                   "hint": "address accepts int, '0x...' or "
                           "'module+0xoff'"})
    if space == "user" and not pid:
        return _j({"ok": False,
                   "error": "user-space dt requires "
                            "pid=<target>; use space='kernel' "
                            "for kernel VAs (the driver "
                            "rejects pid=0 user reads with "
                            "STATUS_INVALID_PARAMETER)"})
    from ..symbols import _resolve_type_layout
    spec = dict(decode) if isinstance(decode, dict) else {}
    spec["type"] = tname
    lay, lerr = await _resolve_type_layout(
        ctx, spec, module=module, path=path)
    if lerr is not None:
        return _j(lerr)
    assert lay is not None
    n = int(size or lay.get("size") or 0)
    if n <= 0:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"dt: layout for {tname!r} has "
                            "size 0 — pass size= explicitly"})
    try:
        data = await c.mem_read(pid, addr, n, space,
                                allow_fault=allow_fault,
                                timeout=timeout_s or None)
    except Exception as exc:  # noqa: BLE001 - same INVALID_ADDRESS hint as read
        if space in ("kernel", "physical") and \
                _looks_invalid_addr(str(exc)):
            return _j(_kernel_va_err("dt", exc))
        raise
    from ...conversions import decode_typed_buffer as _dty
    from ...conversions import ConversionError as _ConvErr
    try:
        decoded = _dty(
            data, lay["members"],
            type_name=lay.get("type_name", ""),
            size=lay.get("size", 0),
            types=lay.get("types"),
            max_depth=int(spec.get("depth") or 2))
    except _ConvErr as exc:
        return _j({"ok": False, "kind": exc.kind,
                   "error": str(exc),
                   "hint": getattr(exc, "hint", "")})
    payload: dict[str, Any] = {
        "address": hex(addr), "size": len(data),
        "hex": data.hex(),
        "type": lay.get("type_name"),
        "layout_source": lay.get("source"),
    }
    if lay.get("build_id"):
        payload["build_id"] = lay["build_id"]
    if lay.get("image"):
        payload["image"] = lay["image"]
    if lay.get("note"):
        payload["layout_note"] = lay["note"]
    payload["values"] = decoded["values"]
    payload["layout"] = decoded["layout"]
    if decoded.get("truncated"):
        payload["truncated"] = True
        payload["coverage"] = _coverage("mem-read", "partial",
                                        "decode_truncated")
    else:
        payload["coverage"] = _coverage("mem-read", "complete")
    if decoded.get("remainder_hex"):
        payload["remainder_hex"] = decoded["remainder_hex"]
    if include_ascii:
        payload["ascii"] = _ascii(data)
    return _j(payload)


async def handle_idt(ctx, c, *, pid: int, all_cpus: bool, path: str,
                     compact: bool, verbosity: str, filter: Any,
                     summary: bool, fields: list[str] | None,
                     limit: int, offset: int, max_results: int) -> str:
    # per-CPU IDT dump. Needs the WP4
    # IdtList RPC — feature-gated so the verb lands before the
    # driver side does; an old agent gets kind='agent_old'.
    if not hasattr(c, "idt_list"):
        return _j({"ok": False, "kind": "agent_old",
                   "error": "idt: agent < v12 "
                            "(Memory.IdtList missing)",
                   "hint": "rebuild agent with ABI v12"})
    # KIDT is per-processor — `all_cpus` dumps every table;
    # the default call gets the current CPU's.
    try:
        res = await c.idt_list(all_cpus=all_cpus)
    except Exception as exc:  # noqa: BLE001 - UNIMPLEMENTED == agent_old
        msg = str(exc)
        if "UNIMPLEMENTED" in msg:
            return _j({"ok": False, "kind": "agent_old",
                       "error": f"idt: {msg}",
                       "hint": "rebuild agent with ABI v12"})
        return _j({"ok": False, "kind": "idt_failed",
                   "error": msg})
    if isinstance(res, dict) and res.get("ok") is False:
        return _j({"ok": False, "kind": "idt_failed",
                   "error": res.get("error",
                                    "idt list failed")})
    entries = res.get("entries", []) \
        if isinstance(res, dict) else []
    try:
        kranges = _mod_ranges(await c.mem_modules(pid, True))
    except Exception:  # noqa: BLE001 - unresolved still dumps
        kranges = []
    img_cache: dict[str, Any] = {}
    rows: list[dict] = []
    def _ei(e: dict, k: str) -> int:
        try:
            return int(_addr(e.get(k), name=k) or 0)
        except (TypeError, ValueError):
            return 0
    suspicious = 0
    for e in entries:
        hva = _ei(e, "handler_va")
        row = {
            "cpu": _ei(e, "cpu"),
            "vector": _ei(e, "vector"),
            "handler_va": hex(hva),
            "selector": _ei(e, "selector"),
            "ist": _ei(e, "ist"),
            "dpl": _ei(e, "dpl"),
        }
        hit = _lookup_mod(kranges, hva)
        if hit:
            lo, _hi, mod = hit
            row["module"] = mod
            row["rva"] = hva - lo
            sym = await _ptr_symbol(ctx, img_cache, mod,
                                    hva - lo, path)
            if sym:
                row["symbol"] = sym["name"]
                row["symbol_disp"] = sym.get("displacement")
            row["name"] = _fmt_modsym(row)
            if not mod.lower().startswith(_IDT_ALLOW_PREFIXES):
                row["suspicious"] = True
        else:
            row["suspicious"] = True
        if row.get("suspicious"):
            suspicious += 1
        rows.append(row)
    rows.sort(key=lambda r: (r["cpu"], r["vector"]))
    def _res_int(k: str) -> int:
        if not isinstance(res, dict):
            return 0
        try:
            return int(_addr(res.get(k), name=k) or 0)
        except (TypeError, ValueError):
            return 0
    extras = {
        "idt_base": hex(_res_int("idt_base")),
        "idt_limit": _res_int("idt_limit"),
        "all_cpus": all_cpus,
        "suspicious": suspicious,
    }
    if all_cpus:
        # Per-CPU bases — present when the agent reports them
        # (per-cpu map on the response, or per-row base).
        bases: dict[str, int] = {}
        raw_bases = (res.get("per_cpu_bases")
                     or res.get("bases")) \
            if isinstance(res, dict) else None
        if isinstance(raw_bases, dict):
            for k, v in raw_bases.items():
                try:
                    bases[str(k)] = int(_addr(v))
                except (TypeError, ValueError):
                    continue
        else:
            for e in entries:
                if e.get("idt_base") is not None:
                    try:
                        bases[str(int(_addr(e.get("cpu", 0))
                                        or 0))] = \
                            int(_addr(e["idt_base"]))
                    except (TypeError, ValueError):
                        continue
        if bases:
            extras["per_cpu_bases"] = {
                k: hex(v)
                for k, v in sorted(bases.items(),
                                   key=lambda kv: int(kv[0]))}
            if len(set(bases.values())) > 1:
                extras["base_drift"] = True
                extras["drift_note"] = (
                    "per-CPU IDT bases differ — KIDT is "
                    "per-processor, but a copied/detoured "
                    "table looks the same; cross-check "
                    "handler_drift")
        # Same vector resolving to different handlers on
        # different CPUs is the detour signature.
        by_vec: dict[int, set] = {}
        for r in rows:
            by_vec.setdefault(r["vector"], set()).add(
                r["handler_va"])
        drifted = sorted(v for v, s in by_vec.items()
                         if len(s) > 1)
        if drifted:
            extras["handler_drift"] = drifted[:64]
            extras["handler_drift_total"] = len(drifted)
    env_filter = filter
    if compact or verbosity == "compact":
        if env_filter:
            # Apply dict/str row filters before the text-line
            # collapse (see resolve_range).
            from ..._envelope.paging import _filter_rows as _fr
            rows = _fr(rows, env_filter)
            env_filter = ""
        rows = [
            f"cpu{r['cpu']}  vec={r['vector']:#04x}  "
            f"{r['handler_va']}  ist={r['ist']}  dpl={r['dpl']}"
            f"  {r.get('name') or '<unresolved>'}"
            f"{'  SUSPICIOUS' if r.get('suspicious') else ''}"
            for r in rows]
    env = _list_envelope(
        rows, tool="memory_manage", action="idt",
        limit=limit or max_results, offset=offset,
        fields=fields or (),
        filter=env_filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras=extras,
    )
    env["coverage"] = _coverage("enumeration", "complete")
    return _hexify_dict(env, add_int_mirror=True)


async def handle_walk_list(ctx, c, *, pid: int, addr: int, size: int,
                           space: str, value: str, decode: Any,
                           count: int, max_results: int,
                           allow_fault: bool, timeout_s: float) -> str:
    # walk_list — follow a linked-list from `base`
    # hopping `next_offset` bytes into each node to read the next
    # pointer. Every kernel-object walk used to hand-roll this in
    # exec_idapython or repeated memory_manage pattern_scans.
    from ...conversions import decode_buffer as _decode_buf
    from ...conversions import ConversionError as _ConvErr
    next_off_raw = value or "0"
    try:
        next_off = _addr(next_off_raw, name="next_offset")
    except ValueError as exc:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"walk_list: {exc}",
                   "hint": "pass value=<offset-of-next-pointer> "
                           "(int or hex string) — e.g. value='0x8'"})
    # count -> max_hops override; max_results -> back-compat.
    max_hops = count if count and count != 64 else max_results or 64
    # want_names doubles as `stop_when_self`; default True. We
    # use a dedicated flag through `filter=self:false` /
    # `filter=null:false` — simplest is to just default to
    # both stops on unless the caller passes `include_ascii=True`
    # (which we repurpose as "no self/null stop"). Cleanest
    # long-term: dedicated flags, but keep the surface tight
    # for now.
    stop_when_self = True
    stop_when_null = True
    read_size = size or 8
    visited: set[int] = set()
    nodes: list[dict] = []
    va_cur = int(addr)
    stopped_at = "max_hops"
    for hop in range(max(1, int(max_hops))):
        if va_cur == 0 and stop_when_null:
            stopped_at = "null"
            break
        if va_cur in visited and stop_when_self:
            stopped_at = "self"
            break
        visited.add(va_cur)
        node: dict[str, Any] = {"va": hex(va_cur), "hop": hop}
        if decode:
            try:
                node_bytes = await c.mem_read(
                    pid, va_cur, read_size, space,
                    allow_fault=allow_fault,
                    timeout=timeout_s or None)
            except Exception as exc:  # noqa: BLE001 - salvage node
                node["error"] = f"{type(exc).__name__}: {exc}"
                nodes.append(node)
                break
            try:
                decoded = _decode_buf(node_bytes, decode)
            except _ConvErr as exc:
                node["decode_error"] = f"{exc.kind}: {exc}"
            else:
                node["values"] = decoded["values"]
                node["layout"] = decoded["layout"]
                if decoded.get("truncated"):
                    node["truncated"] = True
        try:
            ptr_bytes = await c.mem_read(
                pid, va_cur + next_off, 8, space,
                allow_fault=allow_fault,
                timeout=timeout_s or None)
        except Exception as exc:  # noqa: BLE001 - salvage tail
            node["next_error"] = f"{type(exc).__name__}: {exc}"
            nodes.append(node)
            stopped_at = "next_read_failed"
            break
        if len(ptr_bytes) < 8:
            node["truncated"] = True
            nodes.append(node)
            stopped_at = "short_next_ptr"
            break
        (next_va,) = struct.unpack("<Q", ptr_bytes)
        node["next_va"] = hex(next_va)
        nodes.append(node)
        va_cur = next_va
    return _j({"base": hex(int(addr)),
               "next_offset": hex(next_off),
               "node_count": len(nodes),
               "stopped_at": stopped_at,
               "nodes": nodes})


async def handle_read_qwords(ctx, c, *, pid: int, addr: int,
                             space: str, count: int, max_results: int,
                             allow_fault: bool, timeout_s: float) -> str:
    cnt = int(count if count and count != 64 else max_results or 8)
    if cnt <= 0:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "read_qwords: count must be > 0"})
    data = await c.mem_read(pid, addr, cnt * 8, space,
                            allow_fault=allow_fault,
                            timeout=timeout_s or None)
    from ...conversions import decode_buffer as _decode_buf
    decoded = _decode_buf(data, [f"u64"] * cnt)
    return _j({"address": hex(addr),
               "count": cnt,
               "size": len(data),
               "hex": data.hex(),
               "values": decoded["values"],
               "values_hex": [f"0x{v:016X}"
                              for v in decoded["values"]],
               "layout": decoded["layout"],
               "truncated": decoded["truncated"]})


async def handle_read_string(ctx, c, *, action: str, pid: int, addr: int,
                             space: str, allow_fault: bool,
                             timeout_s: float) -> str:
    # Layout: UNICODE_STRING / ANSI_STRING —
    #   Length:u16, MaxLength:u16, pad:u32, Buffer:ptr
    # Buffer is a VA to the raw wide/ansi chars. Length is in
    # BYTES for wchars; we decode the referenced buffer under
    # utf-16-le / mbcs and strip a trailing NUL when present.
    header = await c.mem_read(pid, addr, 16, space,
                              allow_fault=allow_fault,
                              timeout=timeout_s or None)
    if len(header) < 16:
        return _j({"ok": False, "kind": "partial_read",
                   "error": f"{action}: header truncated "
                            f"({len(header)}/16 bytes at {hex(addr)})"})
    length, max_length = struct.unpack_from("<HH", header, 0)
    (buffer_va,) = struct.unpack_from("<Q", header, 8)
    out: dict[str, Any] = {
        "address": hex(addr),
        "length": int(length),
        "max_length": int(max_length),
        "buffer_va": hex(buffer_va),
        "text": "",
    }
    if length == 0 or buffer_va == 0:
        return _j(out)
    try:
        body = await c.mem_read(pid, buffer_va, int(length), space,
                                allow_fault=allow_fault,
                                timeout=timeout_s or None)
    except Exception as exc:  # noqa: BLE001 - report the buffer read failure
        out["buffer_error"] = f"{type(exc).__name__}: {exc}"
        return _j(out)
    if action == "read_unicode_string":
        text = body.decode("utf-16-le", errors="replace")
    else:
        text = body.decode("mbcs", errors="replace")
    # UNICODE_STRING can carry a trailing NUL when MaxLength >
    # Length; strip a single trailing NUL for readability.
    out["text"] = text.rstrip("\x00")
    out["bytes_hex"] = body.hex()
    return _j(out)
