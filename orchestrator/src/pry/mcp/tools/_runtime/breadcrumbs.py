"""Breadcrumb helpers.

Best-effort hooks that write a tool_events row + upsert artifact rows
after a real tool call succeeds. Every helper swallows its own errors
because losing a breadcrumb is preferable to failing the underlying
tool response.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from ....caller import current_client_id


def _sha256_file(path: str, chunk: int = 1 << 20) -> tuple[str, int]:
    """Return (sha256_hex, size_bytes) for a local file. On any error
    returns (`""`, `0`) — a caller writing a breadcrumb without a hash
    still gets a useful `module`-scoped event."""
    try:
        h = hashlib.sha256()
        n = 0
        with open(path, "rb") as fh:
            while True:
                buf = fh.read(chunk)
                if not buf:
                    break
                h.update(buf)
                n += len(buf)
        return h.hexdigest(), n
    except OSError:
        return "", 0


def _kind_from_ext(name: str) -> str:
    """Coarse artifact-kind classifier for the ``artifacts.kind`` column."""
    n = (name or "").lower()
    if n.endswith(".sys"):
        return "sys"
    if n.endswith(".dll"):
        return "dll"
    if n.endswith(".exe"):
        return "exe"
    if n.endswith(".dmp"):
        return "crashdump"
    if n.endswith(".i64") or n.endswith(".idb"):
        return "ida_db"
    return "bin"


def _register_dumped_module(ctx, dest: str, module: str,
                            kernel: bool) -> None:
    """Hook after `file_manage dump_module`: hash the file, upsert an
    artifact + alias, write a tool_event under the caller's client_id."""
    if not dest or not os.path.exists(dest):
        return
    sha, size = _sha256_file(dest)
    base = Path(dest).name
    alias = module.replace("\\", "/").split("/")[-1] or base
    cid = current_client_id()
    sid = ctx.get_current_session_id(cid) or ""
    if sha:
        ctx.ledger.upsert_artifact(
            sha, name=alias, kind=_kind_from_ext(alias), size=size,
            origin=("dump_module_kernel" if kernel else "dump_module_user"),
            alias=alias,
        )
    ctx.ledger.event(
        "file_manage", "dump_module", agent_id=cid, session_id=sid,
        artifact_sha=sha, module=alias,
        summary=f"{alias} → {dest} ({size} bytes, kernel={bool(kernel)})",
    )


# Analysis-session name -> (sha256, on_disk_path) cache, populated on
# open. ida_manage/ghidra_manage passthrough actions (decompile,
# rename_function, …) look up the sha via the session name so their
# breadcrumbs land on the same artifact row without an extra hash pass.
# Keys are prefixed ``<engine>:`` so an IDA and a Ghidra session sharing
# a friendly name never cross-wire their artifact rows.
_IDA_SESSION_SHA_CACHE: dict[str, tuple[str, str]] = {}


def _session_row_key(engine: str, session_name: str) -> str:
    """Ledger `ida_sessions` PK for an analysis session.

    IDA sessions keep the bare name (pre-engine rows/tests expect it);
    other engines get an ``engine:`` prefix so an IDA ``tcpip`` and a
    Ghidra ``tcpip`` never clobber each other's row. `about()` shows
    the prefix — provenance is visible, not a collision.
    """
    return session_name if engine == "ida" else f"{engine}:{session_name}"


def _register_ida_open(ctx, session_name: str, path: str,
                       async_open: bool, engine: str = "ida") -> None:
    """Hook after `*_manage open`/`open_async` succeeds. Best-effort."""
    if not session_name:
        return
    tool = f"{engine}_manage"
    sha, size = _sha256_file(path) if path and os.path.exists(path) else ("", 0)
    alias = Path(path).name if path else session_name
    cid = current_client_id()
    sid = ctx.get_current_session_id(cid) or ""
    if sha:
        ctx.ledger.upsert_artifact(
            sha, name=alias, kind=_kind_from_ext(alias), size=size,
            origin=f"{engine}_open", alias=alias,
        )
        # remember the mapping for later passthrough events
        _IDA_SESSION_SHA_CACHE[f"{engine}:{session_name}"] = (sha, path or "")
    ctx.ledger.open_ida_session(
        _session_row_key(engine, session_name),
        artifact_sha=sha, opened_by_agent=cid,
        on_disk_path=path or "", engine=engine,
    )
    ctx.ledger.event(
        tool, "open_async" if async_open else "open",
        agent_id=cid, session_id=sid, artifact_sha=sha, module=alias,
        summary=f"session={session_name} path={path}",
    )


def _register_ida_close(ctx, session_name: str,
                        engine: str = "ida") -> None:
    if not session_name:
        return
    tool = f"{engine}_manage"
    ctx.ledger.close_ida_session(_session_row_key(engine, session_name))
    cid = current_client_id()
    sha = _IDA_SESSION_SHA_CACHE.get(f"{engine}:{session_name}", ("", ""))[0]
    ctx.ledger.event(
        tool, "close", agent_id=cid, artifact_sha=sha,
        summary=f"session={session_name}",
    )
    _IDA_SESSION_SHA_CACHE.pop(f"{engine}:{session_name}", None)


def _register_ida_action(ctx, session_name: str, action: str,
                         args: dict[str, Any] | None,
                         engine: str = "ida") -> None:
    """Hook after every non-open/close passthrough (decompile,
    rename_function, set_comment, list_imports, …). Kept tight — one
    row per call, summary trimmed."""
    if not session_name:
        return
    tool = f"{engine}_manage"
    sha, _ = _IDA_SESSION_SHA_CACHE.get(f"{engine}:{session_name}", ("", ""))
    # pull one primary arg for the summary
    primary = ""
    if isinstance(args, dict):
        for k in ("function_address", "start_address", "address",
                  "new_name", "name", "function_name", "variable_name",
                  "filter", "query"):
            v = args.get(k)
            if v:
                primary = f"{k}={v}"; break
    summary = f"{action}({primary}) session={session_name}"
    cid = current_client_id()
    ctx.ledger.event(
        tool, action, agent_id=cid, artifact_sha=sha,
        summary=summary[:400],
    )
    ctx.ledger.touch_ida_session(_session_row_key(engine, session_name))


def _pattern_scan_breadcrumb(ctx, *, pattern: str, space: str,
                             address: Any, size: int, module: str = "") -> None:
    """Hook after `memory_manage pattern_scan` / `scan_start` succeeds."""
    cid = current_client_id()
    addr_s = f"0x{address:x}" if isinstance(address, int) else str(address or "")
    ctx.ledger.event(
        "memory_manage", "pattern_scan", agent_id=cid, module=module,
        address=addr_s,
        summary=f"space={space} pattern={pattern!r} size={size}",
    )


def _script_run_breadcrumb(ctx, *, name: str, target: str,
                           params_json: str) -> None:
    cid = current_client_id()
    trunc = params_json if len(params_json) < 200 else params_json[:197] + "..."
    ctx.ledger.event(
        "script_manage", "run", agent_id=cid, target=target,
        summary=f"{name}({trunc})",
    )


__all__ = [
    "_sha256_file",
    "_kind_from_ext",
    "_register_dumped_module",
    "_IDA_SESSION_SHA_CACHE",
    "_session_row_key",
    "_register_ida_open",
    "_register_ida_close",
    "_register_ida_action",
    "_pattern_scan_breadcrumb",
    "_script_run_breadcrumb",
]
