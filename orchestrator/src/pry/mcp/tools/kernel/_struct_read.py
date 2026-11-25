"""Memory scanner wave 3 §6 — ``kernel_manage(action='struct_read')``.

A single tool call that resolves a named type's layout (PDB-first,
falling back to a shipped offset table), reads just the fields the
caller asked for from the kernel view, and decodes each one to a
typed value. Replaces the two-step ``symbols_manage(action='layout')``
+ ``memory_manage(action='read')`` dance operators had to compose by
hand.

Field kinds this release can decode:

* ``scalar``       — little-endian unsigned integer (1/2/4/8 bytes).
* ``ptr``          — raw ``u64`` pointer.
* ``string_ansi``  — fixed-size ``CHAR[N]`` array trimmed at the first
                     NUL (ImageFileName, Signature, etc.).
* ``string_us``    — ``UNICODE_STRING`` header followed by a buffer
                     pointer, read as UTF-16-LE.

Scope is intentionally tight for Wave 3: ``_EPROCESS`` on the kernel
view. The decoder itself is type-agnostic — pointing it at another
type only needs the type to resolve via the layout path (PDB cache
or baked JSON).
"""
from __future__ import annotations

import logging
import struct
from typing import Any, Awaitable, Callable

from .._runtime.response import _j, _j_hex
from .... import symbols as _sym

from . import _invariants

log = logging.getLogger("pry.mcp.tools.kernel")


# Safety caps — a runaway caller asking for a 4 GiB "string" should
# trip a bad_arg, not panic the agent via mem_read.
_MAX_FIELD_BYTES = 0x2000      # 8 KiB — enough for any sensible Wave 3 field
_MAX_BUF_CHARS   = 0x1000      # 4 Ki UTF-16 code units for string_us bodies


# ----------------------------------------------------------------------
# PDB layout -> {field: {offset, size, kind}} normaliser
# ----------------------------------------------------------------------

_SCALAR_INT_NAMES = {
    "char", "signed char", "unsigned char",
    "short", "signed short", "unsigned short",
    "int", "signed int", "unsigned int",
    "long", "signed long", "unsigned long",
    "long long", "signed long long", "unsigned long long",
    "__int8", "__int16", "__int32", "__int64",
    "unsigned __int8", "unsigned __int16", "unsigned __int32",
    "unsigned __int64",
    "bool", "wchar_t",
    # Windows kernel typedefs — SymGetTypeInfo often reports these verbatim.
    "UCHAR", "CHAR", "USHORT", "SHORT", "ULONG", "LONG",
    "ULONGLONG", "LONGLONG", "ULONG64", "LONG64",
    "UINT", "INT", "UINT8", "UINT16", "UINT32", "UINT64",
    "INT8", "INT16", "INT32", "INT64",
    "DWORD", "WORD", "BYTE", "QWORD", "DWORD64",
    "SIZE_T", "HANDLE",
}


def _classify_pdb_member(entry: dict[str, Any]) -> str | None:
    """Best-effort kind inference from a dbghelp ``layout`` member.

    ``type_layout`` returns a ``type`` string like ``unsigned long``,
    ``_PEB*``, ``UCHAR[15]``, ``_LIST_ENTRY``, ``_UNICODE_STRING`` —
    not the ``kind`` the struct_read decoder consumes. Map by shape:

    * ``X*``                                    -> ``ptr``
    * ``_UNICODE_STRING`` / ``UNICODE_STRING``  -> ``string_us``
    * ``UCHAR[N]`` / ``CHAR[N]``                -> ``string_ansi``
    * primitive integer typedef (list above)    -> ``scalar``

    Returns ``None`` when the member is a nested UDT, bitfield, or
    anything else the Wave 3 decoder doesn't speak. The caller surfaces
    those as ``unsupported_kind`` rather than guessing.
    """
    tname = str(entry.get("type", "")).strip()
    if not tname:
        return None
    # Bitfields are advisory metadata on the entry; struct_read can't
    # slice them with per-field mem_read calls, so refuse early.
    if entry.get("bit_length"):
        return None
    if tname.endswith("*"):
        return "ptr"
    # Array form: "UCHAR[15]" or "CHAR [15]"
    if "[" in tname and tname.rstrip("]").endswith(tuple(str(i) for i in range(10))):
        head = tname.split("[", 1)[0].strip()
        if head in {"UCHAR", "CHAR", "unsigned char", "char", "signed char",
                    "BYTE"}:
            return "string_ansi"
    base = tname.rstrip("*").strip()
    if base in {"_UNICODE_STRING", "UNICODE_STRING"}:
        return "string_us"
    if base in _SCALAR_INT_NAMES:
        return "scalar"
    return None


def _normalise_layout(layout: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """PDB ``layout`` dict (or a baked offset table) -> ``{field_name:
    {offset, size, kind}}``.

    Accepts two shapes:

    1. ``{"members": [{"name", "offset", "size", "type"|"kind"}]}`` —
       the dbghelp ``layout`` reply, or any mock that mirrors it.
    2. ``{"<fieldname>": {"offset": ..., "size": ..., "kind": ...}}`` —
       the shipped ``artifacts/invariants/eprocess/*.json`` shape.
    """
    out: dict[str, dict[str, Any]] = {}
    members = layout.get("members")
    if isinstance(members, list):
        for m in members:
            if not isinstance(m, dict):
                continue
            name = str(m.get("name") or "")
            if not name:
                continue
            kind = m.get("kind") or _classify_pdb_member(m)
            if not kind:
                continue
            try:
                off = int(m["offset"])
                size = int(m.get("size") or 0)
            except (KeyError, TypeError, ValueError):
                continue
            if size <= 0:
                continue
            out[name] = {"offset": off, "size": size, "kind": str(kind)}
        return out
    # Baked offset table shape.
    for name, spec in layout.items():
        if name in {"build", "arch", "assertion", "type_name"}:
            continue
        if not isinstance(spec, dict):
            continue
        if spec.get("offset") is None or spec.get("size") is None:
            # Placeholder — null offset means "shipped-stub, not
            # validated"; let the caller see it as a miss, not a crash.
            continue
        kind = spec.get("kind")
        if not kind:
            continue
        try:
            off = int(spec["offset"], 0) if isinstance(spec["offset"], str) \
                else int(spec["offset"])
            size = int(spec["size"])
        except (TypeError, ValueError):
            continue
        out[name] = {"offset": off, "size": size, "kind": str(kind)}
    return out


# ----------------------------------------------------------------------
# Field decoders
# ----------------------------------------------------------------------

def _decode_scalar(buf: bytes, size: int) -> int:
    if size == 1:
        return buf[0]
    if size == 2:
        return struct.unpack_from("<H", buf)[0]
    if size == 4:
        return struct.unpack_from("<I", buf)[0]
    if size == 8:
        return struct.unpack_from("<Q", buf)[0]
    return int.from_bytes(buf[:size], "little", signed=False)


def _decode_ptr(buf: bytes) -> int:
    if len(buf) < 8:
        raise ValueError("ptr field is smaller than 8 bytes")
    return struct.unpack_from("<Q", buf)[0]


def _decode_ansi(buf: bytes) -> str:
    end = buf.find(b"\x00")
    s = buf if end < 0 else buf[:end]
    return s.decode("latin-1", "replace")


def _decode_unicode_string_header(buf: bytes) -> tuple[int, int, int]:
    """``UNICODE_STRING`` is ``{USHORT Length; USHORT MaximumLength;
    ULONG _pad; PWSTR Buffer;}`` on x64 (16 bytes). Returns
    ``(length_bytes, max_bytes, buffer_va)``.
    """
    if len(buf) < 16:
        raise ValueError("UNICODE_STRING header smaller than 16 bytes")
    length, maximum = struct.unpack_from("<HH", buf, 0)
    buffer = struct.unpack_from("<Q", buf, 8)[0]
    return int(length), int(maximum), int(buffer)


# ----------------------------------------------------------------------
# Public handler
# ----------------------------------------------------------------------

ReadFn = Callable[[int, int], Awaitable[bytes]]
LayoutFn = Callable[[], Awaitable[dict[str, Any] | None]]


async def _read_field(reader: ReadFn, base_va: int, off: int,
                      size: int) -> tuple[bytes, dict[str, Any] | None]:
    """Read ``size`` bytes at ``base_va+off``. Returns ``(buf, err)``.

    ``err`` is a non-``None`` typed envelope when the read failed — the
    caller surfaces it as ``kind='stale_target'`` (EPROCESS unlinked
    between resolve + read) or ``kind='kernel_read_failed'``.
    """
    if size <= 0 or size > _MAX_FIELD_BYTES:
        return b"", {"kind": "bad_arg",
                     "error": f"field size {size} outside "
                              f"[1, 0x{_MAX_FIELD_BYTES:x}]"}
    try:
        buf = await reader(base_va + off, size)
    except Exception as exc:  # noqa: BLE001 — remote read, map below
        msg = str(exc)
        kind = "stale_target" if "access violation" in msg.lower() \
            or "invalid" in msg.lower() else "kernel_read_failed"
        return b"", {"kind": kind,
                     "error": f"mem_read va=0x{base_va + off:x} "
                              f"size={size}: {msg}"}
    if len(buf) < size:
        return b"", {"kind": "short_read",
                     "error": f"short read at va=0x{base_va + off:x} — "
                              f"asked {size}, got {len(buf)}"}
    return buf, None


async def decode_fields(reader: ReadFn, base_va: int,
                        layout: dict[str, dict[str, Any]],
                        wanted: list[str] | None
                        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Core decode loop — pure logic, no MCP plumbing.

    Pulled out of :func:`handle_struct_read` so the unit tests can
    stub ``reader`` without having to fake a whole MCP context.

    Returns ``(fields_out, errors)``. Each error is a dict carrying
    ``{field, kind, error}`` so a partially-successful read still
    shows which members tripped.
    """
    fields_out: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []
    # Default field set is every top-level scalar field — matches §6.2.
    if wanted is None:
        wanted = [n for n, spec in layout.items()
                  if spec.get("kind") == "scalar"]
    seen: set[str] = set()
    for name in wanted:
        if name in seen:
            continue
        seen.add(name)
        spec = layout.get(name)
        if spec is None:
            errors.append({"field": name, "kind": "field_not_in_layout",
                           "error": f"{name!r} absent from the resolved "
                                    "layout"})
            continue
        off = int(spec["offset"])
        size = int(spec["size"])
        kind = str(spec["kind"])
        buf, err = await _read_field(reader, base_va, off, size)
        if err is not None:
            errors.append({"field": name, **err})
            continue
        try:
            if kind == "scalar":
                fields_out[name] = _decode_scalar(buf, size)
            elif kind == "ptr":
                fields_out[name] = _decode_ptr(buf)
            elif kind == "string_ansi":
                fields_out[name] = _decode_ansi(buf)
            elif kind == "string_us":
                length, _maximum, buffer_va = _decode_unicode_string_header(buf)
                if not buffer_va or not length:
                    fields_out[name] = ""
                    continue
                # Cap the follow-on read defensively — stale pointers
                # to huge Length values should not nuke the agent.
                take = min(int(length), _MAX_BUF_CHARS * 2)
                body, berr = await _read_field(
                    reader, buffer_va, 0, take)
                if berr is not None:
                    errors.append({"field": name, **berr,
                                   "error": berr.get("error", "")
                                            + f" (UNICODE_STRING "
                                              f"Buffer@0x{buffer_va:x})"})
                    continue
                try:
                    fields_out[name] = body.decode("utf-16-le", "replace")
                except Exception:  # noqa: BLE001
                    fields_out[name] = body.hex()
            else:
                errors.append({"field": name, "kind": "unsupported_kind",
                               "error": f"kind={kind!r} not decoded "
                                        "by Wave 3 struct_read"})
        except Exception as exc:  # noqa: BLE001
            errors.append({"field": name, "kind": "decode_failed",
                           "error": f"{kind} decode: {exc}"})
    return fields_out, errors


async def _resolve_pdb_layout(ctx, *, module: str, type_name: str,
                              max_depth: int) -> tuple[dict[str, Any] | None,
                                                       dict[str, Any] | None]:
    """Fetch a type layout via the orchestrator's dbghelp pathway.

    Returns ``(layout, err)``. ``layout`` is the raw dbghelp dict
    (``{members: [...]}``); ``err`` is a typed envelope when the PDB
    fast-path cannot answer and the caller must try a baked table.
    """
    from ..symbols import _resolve_image  # local import avoids cycle
    try:
        img, _img_name = _resolve_image(ctx, module, "")
    except _sym.SymbolError as exc:
        return None, {"ok": False, "kind": "module_not_found",
                      "error": str(exc)}
    if not img:
        return None, {"ok": False, "kind": "invalid_parameter",
                      "error": "struct_read needs module= to find the "
                               "image (ntoskrnl.exe for _EPROCESS)"}
    import asyncio as _aio
    pdb_dir = str(ctx.cfg.pdb_cache_dir())
    allow_dl = ctx.cfg.symbols.allow_download
    servers = ctx.cfg.symbols.servers or None
    try:
        res = await _aio.to_thread(
            _sym.type_layout, img, type_name, pdb_dir, allow_dl,
            servers, max(1, int(max_depth)))
    except _sym.SymbolError as exc:
        return None, {"ok": False, "kind": "pdb_missing",
                      "error": str(exc)}
    if not res.get("ok"):
        kind = str(res.get("kind") or "pdb_missing")
        return None, {"ok": False, "kind": kind,
                      "error": str(res.get("error") or
                                   "type_layout failed")}
    return res, None


async def _resolve_pid_to_eprocess(ctx, client, lookup_by: dict[str, Any]
                                   ) -> tuple[int | None, dict[str, Any] | None]:
    """PID -> EPROCESS VA via the agent's ``ListProcesses`` RPC.

    §6.3 r2 — avoid hand-rolling a kernel walk. Current proto only
    carries ``pid``, ``image_name``, ``cmdline``, ``create_time_100ns``
    and ``session_id`` on ``ProcessInfo``; a future rev that adds
    ``eprocess``/``process_object`` is picked up automatically via
    ``getattr``. Until then ``pid`` lookup is "assist, not resolve":
    returns ``pid_lookup_unavailable`` with a hint to pass ``va=`` or
    opt into ``allow_invariant=true``.
    """
    try:
        pid = int(lookup_by.get("pid"))
    except (TypeError, ValueError):
        return None, {"ok": False, "kind": "invalid_parameter",
                      "error": "lookup_by.pid must be an integer"}
    try:
        rows = await client.mem_processes(limit=0, offset=0,
                                          with_cmdline=False)
    except Exception as exc:  # noqa: BLE001 - map to kind
        return None, {"ok": False, "kind": "list_processes_failed",
                      "error": f"ListProcesses: {exc}"}
    match: dict[str, Any] | None = None
    for row in rows:
        try:
            if int(row.get("pid") or 0) == pid:
                match = row
                break
        except (TypeError, ValueError):
            continue
    if match is None:
        return None, {"ok": False, "kind": "pid_not_found",
                      "error": f"pid {pid} not in ListProcesses "
                               "output"}
    # proto3 silently drops unknown fields, so a future 'eprocess' key
    # arrives here as a dict entry the moment it ships. Accept both
    # 'eprocess' and 'process_object' as names the agent might surface.
    for key in ("eprocess", "process_object", "eprocess_va"):
        raw = match.get(key)
        if raw:
            try:
                return int(raw, 0) if isinstance(raw, str) else int(raw), None
            except (TypeError, ValueError):
                continue
    return None, {"ok": False, "kind": "pid_lookup_unavailable",
                  "error": "ListProcesses in this proto rev does not "
                           "surface an EPROCESS VA (ProcessInfo has "
                           "pid/image_name/cmdline only).",
                  "hint": "pass va='0x...' directly (walk EPROCESS "
                          "by hand once), or set "
                          "lookup_by.allow_invariant=true to engage the "
                          "unknown-build invariant walker"}


def _parse_va(raw: Any) -> int | None:
    if raw is None:
        return None
    try:
        if isinstance(raw, bool):
            return None
        if isinstance(raw, str):
            raw = raw.strip()
            if not raw:
                return None
            return int(raw, 0)
        return int(raw)
    except (TypeError, ValueError):
        return None


async def handle_struct_read(ctx, client, *, name: str, module: str,
                             type_name: str, va: Any,
                             lookup_by: dict[str, Any] | None,
                             fields: list[str] | None,
                             max_depth: int) -> str:
    """``kernel_manage(action='struct_read', ...)`` body."""
    if ctx.session.view_kind_of(name) == "user":
        return _j({"ok": False, "kind": "view_mismatch",
                   "error": "struct_read needs a kernel view — got "
                            f"{name!r} (user)",
                   "hint": "pass name='<machine>.kernel' or focus a "
                           "kernel view first"})
    if not module:
        module = "ntoskrnl.exe"
    tname = str(type_name or "").strip()
    if not tname:
        return _j({"ok": False, "kind": "invalid_parameter",
                   "error": "struct_read needs type_name= "
                            "(e.g. '_EPROCESS')"})
    # Wave 3 scope guard — _EPROCESS only (plan §6.4). An operator
    # asking for _ETHREAD today gets a clear "not yet" rather than a
    # half-wired path.
    if tname.upper() not in {"_EPROCESS", "EPROCESS"}:
        return _j({"ok": False, "kind": "unsupported_type",
                   "error": f"type_name={tname!r} not covered by Wave "
                            "3 struct_read (scope: _EPROCESS)",
                   "hint": "Wave 4 widens to _ETHREAD / _DRIVER_OBJECT "
                           "/ _KPCR"})

    # ----- base VA resolution --------------------------------------
    base_va = _parse_va(va)
    lookup_src: dict[str, Any] = {}
    layout_src = "pdb"
    build_str = ""
    offsets_source: dict[str, Any] = {}

    if base_va is None and lookup_by:
        base_va, err = await _resolve_pid_to_eprocess(ctx, client,
                                                     lookup_by or {})
        if base_va is None:
            allow_inv = bool((lookup_by or {}).get("allow_invariant"))
            if not allow_inv:
                return _j(err)
            # Fall through: walker will scan for an EPROCESS matching
            # lookup_by.pid. The walker returns 'scan_only' when it
            # can't anchor without a candidate base.
            lookup_src = {"attempted": "list_processes",
                          "error": err.get("error", "")}
        else:
            lookup_src = {"attempted": "list_processes", "ok": True}

    if base_va is None:
        return _j({"ok": False, "kind": "invalid_parameter",
                   "error": "struct_read needs va='0x...' or "
                            "lookup_by={'kind':'pid','pid':N}",
                   "lookup_source": lookup_src})

    # ----- layout resolution: PDB first, baked JSON fallback --------
    layout: dict[str, dict[str, Any]] | None = None
    layout_err: dict[str, Any] | None = None

    raw_layout, err = await _resolve_pdb_layout(
        ctx, module=module, type_name=tname, max_depth=int(max_depth or 1))
    if raw_layout is not None:
        layout = _normalise_layout(raw_layout)
        if not layout:
            layout_err = {"kind": "layout_empty",
                          "error": "PDB resolved but no decodable "
                                   "fields (bitfields/UDTs only)"}
            layout = None
    else:
        layout_err = err

    if layout is None:
        # Baked-JSON fallback: works even without a PDB on the host.
        try:
            host = await client.host_info(include_hardware=False,
                                          include_security_products=False)
        except Exception:  # noqa: BLE001 — no agent host_info
            host = None
        build_major = 0
        if host and host.get("ok"):
            try:
                build_major = int(host.get("build_major") or 0)
            except (TypeError, ValueError):
                build_major = 0
        build_str = str((host or {}).get("full_build_string") or "")
        baked = _invariants.load_baked(build_major) if build_major else None
        if baked is not None and not _normalise_layout(
                baked.get("eprocess") or {}):
            # Shipped stub (every offset null): no table, so fall
            # through to the invariant walker instead of decoding {}.
            offsets_source = {"build": baked.get("build"),
                              "source": "baked_stub"}
            baked = None
        if baked is not None:
            layout = _normalise_layout(baked.get("eprocess") or {})
            layout_src = "baked"
            offsets_source = {"build": baked.get("build"),
                              "source": "baked",
                              "assertion": baked.get("assertion") or {}}
            # Assert DISPATCHER_HEADER type byte before trusting the
            # offsets — a known build whose EPROCESS layout drifted
            # should fall through, not silently decode garbage.
            if offsets_source.get("assertion"):
                assn = offsets_source["assertion"]
                try:
                    off = int(assn["dispatcher_header_type_at"], 0) \
                        if isinstance(assn["dispatcher_header_type_at"], str) \
                        else int(assn["dispatcher_header_type_at"])
                    expected = int(assn["dispatcher_header_type_value"], 0) \
                        if isinstance(
                            assn["dispatcher_header_type_value"], str) \
                        else int(assn["dispatcher_header_type_value"])
                except (KeyError, TypeError, ValueError):
                    off, expected = 0x00, 0x03
                try:
                    hb = await client.mem_read(
                        0, base_va + off, 1, "kernel")
                except Exception as exc:  # noqa: BLE001
                    return _j({"ok": False,
                               "kind": "assertion_read_failed",
                               "error": f"DISPATCHER_HEADER read "
                                        f"failed: {exc}"})
                if not hb or hb[0] != (expected & 0xFF):
                    layout = None
                    layout_src = "pdb"
                    offsets_source = {"build": baked.get("build"),
                                      "assertion_failed": True,
                                      "expected": expected,
                                      "got": int(hb[0]) if hb else None}

    if layout is None:
        # Invariant walker as last resort, if the caller asked for it.
        allow_inv = bool((lookup_by or {}).get("allow_invariant"))
        if not allow_inv:
            payload = {"ok": False,
                       "kind": "eprocess_offsets_unknown",
                       "error": "No PDB and no baked offset table for "
                                f"this build ({build_str or 'unknown'})"
                                + (" (the shipped table is a null-offset "
                                   "stub)." if offsets_source.get("source")
                                   == "baked_stub" else "."),
                       "hint": ("add a JSON under artifacts/invariants/"
                                "eprocess/ for this build, or retry "
                                "with lookup_by.allow_invariant=true"),
                       "build": build_str,
                       "assertion_source": offsets_source,
                       "pdb_error": layout_err or {}}
            return _j_hex(payload)
        walker = _invariants.InvariantFieldFinder()
        async def _read(va_: int, size: int) -> bytes:
            return await client.mem_read(0, va_, size, "kernel")
        hint_pid = None
        try:
            if lookup_by:
                hint_pid = int(lookup_by.get("pid"))
        except (TypeError, ValueError):
            hint_pid = None
        cached: dict[str, dict[str, Any]] = {}
        try:
            cached = _normalise_layout(_invariants.load_discovered(
                build_str, ctx.cfg.artifacts_dir()) or {})
        except Exception:  # noqa: BLE001 — cache is best-effort
            cached = {}
        if cached and await _invariants.discovered_layout_holds(
                _read, base_va, cached, hint_pid):
            layout = cached
            layout_src = "discovered_cache"
            offsets_source = {"source": "discovered_cache",
                              "build": build_str}
        if layout is None:
            scan = await walker.scan(_read, base_va, hint_pid=hint_pid)
            if not scan.get("ok"):
                payload = {"ok": False, "kind": scan.get("kind") or
                                     "eprocess_offsets_unknown",
                           "error": scan.get("error",
                                             "invariant walker failed"),
                           "hint": ("ship artifacts/invariants/eprocess/"
                                    f"{build_str}.json with the fields "
                                    "below, then retry without "
                                    "allow_invariant"),
                           "build": build_str,
                           "candidate_offsets": scan.get("offsets") or {}}
                return _j_hex(payload)
            layout = scan["layout"]
            layout_src = "invariant_scan"
            offsets_source = {"source": "invariant_scan",
                              "build": build_str,
                              "evidence": scan.get("evidence") or {}}
            # Persist to a discovered cache so a second call on the same
            # build reuses the offsets. No build string, no cache: an
            # "unknown" entry could belong to any build.
            try:
                _invariants.cache_discovered(build_str,
                                             scan.get("eprocess") or {},
                                             ctx.cfg.artifacts_dir())
            except Exception:  # noqa: BLE001 — cache is best-effort
                pass

    # ----- field decode ---------------------------------------------
    async def reader(va_: int, size: int) -> bytes:
        return await client.mem_read(0, va_, size, "kernel")

    fields_out, errors = await decode_fields(
        reader, base_va, layout, fields)
    payload: dict[str, Any] = {
        "ok": True,
        "module": module,
        "type_name": tname,
        "base_va": base_va,
        "fields": fields_out,
        "layout_source": layout_src,
    }
    if offsets_source:
        payload["offsets"] = offsets_source
    if lookup_src:
        payload["lookup_source"] = lookup_src
    if errors:
        payload["partial"] = True
        payload["errors"] = errors
    return _j_hex(payload)
