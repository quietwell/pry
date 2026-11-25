"""SI #14 process-snapshot minidump helpers for ``dump_manage``.

Lifted out of ``dump.py`` so the dispatcher stays under the 700-line
cap. Pure helpers; no runtime dependencies on FastMCP or the context —
tests import ``_mem_process_snapshot`` / ``_resolve_minidump_flags`` /
``_MINIDUMP_FLAG_MAP`` / ``_DEFAULT_MINIDUMP_FLAGS`` directly.

The C++ side (agent/src/dump/process_dump.cpp) runs the stepped
access-mask ladder behind PssCaptureSnapshot + MiniDumpWriteDump; this
module just translates MINIDUMP_TYPE flag names to a bitmask and shapes
the response envelope.
"""

from __future__ import annotations

from typing import Any

from .._coverage import coverage as _coverage


def _hx(v: Any) -> str:
    try:
        return f"0x{int(v):x}"
    except (TypeError, ValueError):
        return str(v)


# SI #14: MINIDUMP_TYPE strings -> bit values. Names mirror dbghelp.h;
# the orchestrator kwarg accepts either "WithFullMemory" or the full
# "MiniDumpWithFullMemory" spelling.
_MINIDUMP_FLAG_MAP: dict[str, int] = {
    "Normal":                               0x00000000,
    "WithDataSegs":                         0x00000001,
    "WithFullMemory":                       0x00000002,
    "WithHandleData":                       0x00000004,
    "FilterMemory":                         0x00000008,
    "ScanMemory":                           0x00000010,
    "WithUnloadedModules":                  0x00000020,
    "WithIndirectlyReferencedMemory":       0x00000040,
    "FilterModulePaths":                    0x00000080,
    "WithProcessThreadData":                0x00000100,
    "WithPrivateReadWriteMemory":           0x00000200,
    "WithoutOptionalData":                  0x00000400,
    "WithFullMemoryInfo":                   0x00000800,
    "WithThreadInfo":                       0x00001000,
    "WithCodeSegs":                         0x00002000,
    "WithoutAuxiliaryState":                0x00004000,
    "WithFullAuxiliaryState":               0x00008000,
    "WithPrivateWriteCopyMemory":           0x00010000,
    "IgnoreInaccessibleMemory":             0x00020000,
    "WithTokenInformation":                 0x00040000,
    "WithModuleHeaders":                    0x00080000,
    "FilterTriage":                         0x00100000,
    "WithAvxXStateContext":                 0x00200000,
    "WithIptTrace":                         0x00400000,
    "ScanInaccessiblePartialPages":         0x00800000,
}
_DEFAULT_MINIDUMP_FLAGS: int = (
    _MINIDUMP_FLAG_MAP["WithFullMemory"]
    | _MINIDUMP_FLAG_MAP["WithThreadInfo"]
    | _MINIDUMP_FLAG_MAP["WithHandleData"]
    | _MINIDUMP_FLAG_MAP["WithUnloadedModules"]
    | _MINIDUMP_FLAG_MAP["WithFullMemoryInfo"]
    | _MINIDUMP_FLAG_MAP["WithTokenInformation"]
)


def _resolve_minidump_flags(flags: list[str] | None,
                             ) -> tuple[int, list[str], list[str]]:
    """``flags`` -> (bitmask, used_names, unknown_names).

    Empty / None gives the default bitmask with ``used_names=[]`` so the
    response can echo ``flags_used=['<default>']`` honestly.
    """
    if not flags:
        return _DEFAULT_MINIDUMP_FLAGS, [], []
    mask = 0
    used: list[str] = []
    unknown: list[str] = []
    for f in flags:
        key = str(f or "").strip()
        if not key:
            continue
        base = key[len("MiniDump"):] if key.startswith("MiniDump") else key
        if base in _MINIDUMP_FLAG_MAP:
            mask |= _MINIDUMP_FLAG_MAP[base]
            used.append(base)
        else:
            unknown.append(key)
    return mask, used, unknown


async def _mem_process_snapshot(ctx, c, *, pid: int,
                                 dump_flags: list[str] | None,
                                 output_path: str, use_snapshot: bool,
                                 name: str) -> dict:
    """Run ProcessDump.CreateDump on the agent/umagent view ``c``.

    Returns an envelope dict (ok, kind, path, size, sha256,
    access_mask_used, snapshot_used, flags_used, flags_unknown,
    source, coverage).
    """
    if pid <= 0:
        return {"ok": False, "kind": "bad_arg",
                "error": "process_snapshot: pid > 0 is required"}
    mask, used_names, unknown = _resolve_minidump_flags(dump_flags)
    source = str(ctx.session.view_kind_of(name) or "driver")
    source = "umagent" if source == "user" else source
    try:
        res = await c.process_dump(pid=pid, flags=mask,
                                    output_path=output_path or "",
                                    use_snapshot=bool(use_snapshot))
    except Exception as exc:  # noqa: BLE001 — surface as a named error
        return {"ok": False, "kind": "process_snapshot_failed",
                "error": f"{type(exc).__name__}: {exc}",
                "source": source}
    kind = str(res.get("kind") or "")
    if not res.get("ok"):
        return {"ok": False,
                "kind": kind or "process_snapshot_failed",
                "error": res.get("error") or "process_snapshot failed",
                "pid": pid, "source": source,
                "flags_used": used_names or ["<default>"],
                "flags_unknown": unknown}
    return {
        "ok": True,
        "pid": pid,
        "source": source,
        "local_path": "",
        "remote_path": res.get("path", ""),
        "size": int(res.get("size") or 0),
        "sha256": res.get("sha256", ""),
        "access_mask_used": int(res.get("access_mask_used") or 0),
        "access_mask_used_hex": _hx(res.get("access_mask_used") or 0),
        "snapshot_used": bool(res.get("snapshot_used")),
        "dump_type_flags": int(mask),
        "dump_type_flags_hex": _hx(int(mask)),
        "flags_used": used_names or ["<default>"],
        "flags_unknown": unknown,
        "coverage": _coverage(
            "process-snapshot",
            "complete" if not unknown else "partial",
            *(() if not unknown else ("unknown_flags",))),
    }


# SysDbgGetLiveKernelDump flag names ->
# SYSDBG_LIVEDUMP_FLAG_* bits. Mirrors the slice doc §Feature 5 and the
# umagent helper in umagent/src/dump/live_kernel_dump.cpp. Names map to
# the SYSDBG_LIVEDUMP_FLAG_* / SYSDBG_LIVEDUMP_SELECTIVE_* bits as
# documented inside the (unexported) ntdbg.h; the umagent is the
# authority on the exact bitmask, this map keeps the orchestrator-side
# contract stable.
_LIVE_KERNEL_FLAG_MAP: dict[str, int] = {
    # Hypervisor-visible pages. Requires the LKD HV extension bit on
    # the running build; umagent surfaces kind='not_supported' if the
    # bit is unavailable (see slice doc §Edge cases).
    "hypervisor_pages":  0x00000001,
    # Usermode page selector + USE_DUMP_STORAGE_STACK. Convenience bit
    # that the umagent translates into SYSDBG_LIVEDUMP_FLAG_
    # USE_DUMP_STORAGE_STACK plus the usermode-pages selector in
    # AddPagesControl.
    "usermode":          0x00000002,
    # Stack-only pages (per-thread kernel + user stacks). Smallest
    # footprint; useful on long-running RAM-heavy targets.
    "stack_only":        0x00000004,
    # SYSDBG_LIVEDUMP_FLAG_COMPRESS_MEMORY_PAGES_DATA. Also set by the
    # convenience ``compression=True`` kwarg.
    "compression":       0x00000010,
    # Selective kernel dump with no page selector — aggressive, kernel
    # pages only. Mutually exclusive with usermode/stack_only (first
    # one wins on the umagent side).
    "page_table_only":   0x00000020,
}


def _resolve_live_kernel_flags(flags: list[str] | None, compression: bool,
                               ) -> tuple[int, list[str], list[str]]:
    """``flags`` + ``compression`` -> (bitmask, used_names, unknown).

    * Empty / None flags with ``compression=False`` gives a zero mask;
      the umagent falls back to a non-selective kernel dump.
    * ``compression=True`` always ORs in the compression bit, even if the
      caller didn't name ``"compression"`` explicitly — ``used_names``
      records the implicit addition.
    """
    mask = 0
    used: list[str] = []
    unknown: list[str] = []
    for f in (flags or []):
        key = str(f or "").strip().lower()
        if not key:
            continue
        if key in _LIVE_KERNEL_FLAG_MAP:
            mask |= _LIVE_KERNEL_FLAG_MAP[key]
            if key not in used:
                used.append(key)
        else:
            unknown.append(key)
    if compression:
        mask |= _LIVE_KERNEL_FLAG_MAP["compression"]
        if "compression" not in used:
            used.append("compression")
    return mask, used, unknown


async def _mem_live_kernel_dump(ctx, c, *, output_path: str,
                                flags: list[str] | None,
                                compression: bool,
                                allow_cancel: bool,
                                name: str) -> dict:
    """Call ``ProcessDump.CreateLiveKernelDump`` on view ``c`` and
    translate the response into the operator envelope.

    Writes land on the *target*'s disk — the orchestrator never sees the
    bytes, only ``{path, size, sha256}``. Callers that need the dump
    content locally invoke ``dump_manage(action='parse', remote_path=...)``
    after this call.

    The ``allow_live_kernel_dump`` config gate is checked in
    ``Session.assert_allowed`` (see ``session/core.py``), so by the time
    we land here the operator has already approved the capture.
    """
    mask, used, unknown = _resolve_live_kernel_flags(flags, bool(compression))
    source = str(ctx.session.view_kind_of(name) or "driver")
    source = "umagent" if source == "user" else source
    try:
        res = await c.live_kernel_dump(
            output_path=str(output_path or ""),
            flags=list(flags or []),
            compression=bool(compression),
            allow_cancel=bool(allow_cancel),
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "kind": "live_kernel_dump_failed",
                "error": f"{type(exc).__name__}: {exc}",
                "source": source,
                "flags_requested": list(flags or []),
                "flags_used_mask_hex": _hx(mask)}
    kind = str(res.get("kind") or "")
    if not res.get("ok"):
        env = {"ok": False,
               "kind": kind or "live_kernel_dump_failed",
               "error": res.get("error")
                        or "SysDbgGetLiveKernelDump failed",
               "source": source,
               "flags_requested": list(flags or []),
               "flags_used": used or ["<none>"],
               "flags_unknown": unknown,
               "flags_used_mask": int(mask),
               "flags_used_mask_hex": _hx(mask)}
        if res.get("error_detail"):
            env["error_detail"] = res["error_detail"]
        return env
    actual_mask = int(res.get("flags_used_mask") or 0)
    return {
        "ok": True,
        "source": source,
        "path": res.get("path", ""),
        "size": int(res.get("size") or 0),
        "sha256": res.get("sha256", ""),
        "flags_requested": list(flags or []),
        "flags_used": used or ["<none>"],
        "flags_unknown": unknown,
        "flags_used_mask": actual_mask or int(mask),
        "flags_used_mask_hex": _hx(actual_mask or int(mask)),
        "coverage": _coverage(
            "live-kernel-dump",
            "complete" if not unknown else "partial",
            *(() if not unknown else ("unknown_flags",))),
    }


__all__ = [
    "_DEFAULT_MINIDUMP_FLAGS",
    "_LIVE_KERNEL_FLAG_MAP",
    "_MINIDUMP_FLAG_MAP",
    "_mem_live_kernel_dump",
    "_mem_process_snapshot",
    "_resolve_live_kernel_flags",
    "_resolve_minidump_flags",
]
