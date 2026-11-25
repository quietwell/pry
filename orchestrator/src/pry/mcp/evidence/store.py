"""Evidence record store — deterministic ids, atomic saves, retention.

Storage layout (under the existing artifacts root):

    artifacts/evidence/<2-hex>/<ev_<32hex>>.json   # complete record, canonical JSON

``ev_`` id format: ``ev_`` + 32 lowercase hex chars (sha256 prefix over the
canonical ``{"request": sanitized_request, "record": complete_record}``
blob). Lookup validation regex ``^ev_[0-9a-f]{32}$`` — anything else is a
``missing_evidence`` error, never a filesystem path: ids are validated
BEFORE any path join, so traversal via a crafted id is impossible.

``split_detail`` / ``stamp_result`` / ``with_evidence`` implement Task 3.4:
the shared ``detail`` kwarg on heavy actions. ``detail="summary"`` retains
the complete record first, then replaces the inline payload with
``views.summary_view``; ``detail="complete"`` (default) delivers inline AND
retains so a later ``evidence_get`` works. Retention failures never break
the tool response — the original result passes through.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Coroutine

from .._envelope.build import sanitize_received_args

log = logging.getLogger(__name__)

EVIDENCE_ID_RE = re.compile(r"^ev_[0-9a-f]{32}$")
PREVIEW_BYTES = 512

# Heavy (tool, action) pairs that carry the `detail` parameter (Task 3.4).
# ida_manage/ghidra_manage passthroughs are handled in detail_applies —
# their action space is open-ended.
_HEAVY_MEMORY_ACTIONS: frozenset[str] = frozenset({
    # reads / decode
    "read", "disasm", "dt", "dps", "idt", "resolve_range", "walk_list",
    "read_qwords", "read_unicode_string", "read_ansi_string",
    # scans
    "pattern_scan", "scan_result", "strings", "iocs", "entropy",
    # inventory
    "modules", "process_list", "vad", "handles", "imports", "exports",
    "heaps", "phys_ranges", "pool_scan", "threads", "obj_enum",
})

DETAIL_ACTIONS: dict[str, frozenset[str]] = {
    # ``memory_manage`` is the canonical public home; the
    # internal ``memory_manage`` dispatcher keeps its own entry so the stamp
    # applies regardless of which tool name reached this helper.
    "memory_manage": _HEAVY_MEMORY_ACTIONS,
    "dump_manage": frozenset({"parse", "stack"}),
}

# ida/ghidra verbs that are session/discovery plumbing, never payload.
_META_ACTIONS = frozenset({
    "actions", "list", "schemas", "tools", "health", "open", "open_async",
    "open_status", "close",
})
_META_ACTION_PREFIXES = (
    "ida_job_", "ida_log", "ida_result",
    "ghidra_job_", "ghidra_log", "ghidra_result",
)


class EvidenceIdError(ValueError):
    """An evidence id failed ``^ev_[0-9a-f]{32}$`` validation."""


def valid_id(evidence_id: str) -> bool:
    """True only for well-formed ``ev_<32 lowercase hex>`` ids."""
    return bool(evidence_id) and bool(EVIDENCE_ID_RE.fullmatch(str(evidence_id)))


def _canonical(obj: Any) -> str:
    """The one canonical serialization (ids, on-disk records, sizes)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str)


def _id_from_blobs(record_blob: str, request_blob: str) -> str:
    # == _canonical({"request": req, "record": rec}): sort_keys orders
    # "record" before "request", and nested values serialize identically
    # — so the id is derived from the record blob without re-encoding it.
    blob = '{"record":' + record_blob + ',"request":' + request_blob + "}"
    return "ev_" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def record_id(complete_record: dict, request: dict) -> str:
    """Deterministic ``ev_`` + first 32 hex of sha256 over
    ``json.dumps({"request": sanitized_request,
    "record": complete_record}, sort_keys=True, separators=(",", ":"))``.
    Same request + same record -> same id, regardless of dict key order."""
    return _id_from_blobs(_canonical(complete_record),
                          _canonical(sanitize_received_args(request)))


def _path_for(digest_id: str, artifacts_root: Path) -> Path:
    # Callers MUST run valid_id() before this join — enforced here too.
    if not valid_id(digest_id):
        raise EvidenceIdError(f"invalid evidence id {digest_id!r}")
    return (Path(artifacts_root) / "evidence" / digest_id[3:5]
            / f"{digest_id}.json")


def _write_blob(digest_id: str, blob: str, artifacts_root: Path) -> Path:
    """Atomic write of an already-serialized record. The temp name is
    unique per writer so two concurrent retains of the same id never
    replace each other's half-written temp."""
    dest = _path_for(digest_id, artifacts_root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f"{dest.name}.{os.getpid()}."
                         f"{uuid.uuid4().hex[:8]}.tmp")
    try:
        tmp.write_text(blob, encoding="utf-8")
        os.replace(tmp, dest)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return dest


def save(digest_id: str, complete_record: dict, *,
         artifacts_root: Path, blob: str | None = None) -> Path:
    """Write ``artifacts/evidence/<digest[3:5]>/<digest>.json`` (canonical
    JSON, atomic: unique temp then ``os.replace``). Returns the path.
    ``blob`` = the record's already-computed canonical serialization."""
    return _write_blob(digest_id,
                       blob if blob is not None else _canonical(complete_record),
                       artifacts_root)


def _bounded_dumps(obj: Any, limit: int) -> str:
    """``json.dumps(obj, default=str)[:limit]`` without serializing all
    of ``obj`` — the incremental encoder stops after ``limit`` chars."""
    out: list[str] = []
    n = 0
    for chunk in json.JSONEncoder(default=str).iterencode(obj):
        out.append(chunk)
        n += len(chunk)
        if n >= limit:
            break
    return "".join(out)[:limit]


def load(digest_id: str, *, artifacts_root: Path) -> dict:
    """Load a retained record. Raises ``EvidenceIdError`` for malformed ids
    (before any filesystem access) and ``FileNotFoundError`` for unknown
    but well-formed ids."""
    path = _path_for(digest_id, artifacts_root)
    if not path.exists():
        raise FileNotFoundError(f"no evidence record {digest_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def delete(digest_id: str, *, artifacts_root: Path) -> bool:
    """Remove one retained record file. False when it was already gone."""
    path = _path_for(digest_id, artifacts_root)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def delete_all(artifacts_root: Path) -> int:
    """Remove every retained record file under ``artifacts/evidence/``.
    Only filenames matching the id regex are touched. Returns the count."""
    root = Path(artifacts_root) / "evidence"
    if not root.is_dir():
        return 0
    n = 0
    for p in root.glob("*/*.json"):
        if EVIDENCE_ID_RE.fullmatch(p.stem):
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
    return n


def continuation(evidence_id: str, offset: int = 0, limit: int = 64) -> dict:
    """The ``continuation`` handle pointing at knowledge_manage/evidence_get."""
    return {"tool": "knowledge_manage", "action": "evidence_get",
            "args": {"evidence_id": evidence_id, "offset": int(offset),
                     "limit": int(limit)}}


def build_record(request: dict, data: Any, *, coverage: dict | None = None,
                 provenance: dict | None = None, tool: str = "",
                 action: str = "") -> dict:
    """``{request: sanitized, data: payload}`` plus optional Part 1 blocks
    and tool/action labels — the shape ``views.*`` and the id digest read."""
    rec: dict[str, Any] = {"request": sanitize_received_args(request),
                           "data": data}
    if tool:
        rec["tool"] = tool
    if action:
        rec["action"] = action
    if isinstance(coverage, dict):
        rec["coverage"] = coverage
    if isinstance(provenance, dict):
        rec["provenance"] = provenance
    return rec


def retain_record(*, request: dict, data: Any, artifacts_root: Path,
                  ledger: Any, tool: str, action: str,
                  detail: str = "complete", coverage: dict | None = None,
                  provenance: dict | None = None, parent_id: str = "",
                  operation: str = "") -> tuple[dict, dict]:
    """Build + persist the record, write the unattached ``tool_result``
    ledger row, return ``(record, envelope evidence block)``.

    The row id IS the digest, so double retention (tool stamp + spill path)
    collapses to one row via INSERT OR IGNORE. The record is serialized
    exactly once (that one blob yields the id, the file and the size)."""
    prep = _prepare(request=request, data=data, coverage=coverage,
                    provenance=provenance, tool=tool, action=action)
    save(prep.ev, prep.record, artifacts_root=Path(artifacts_root),
         blob=prep.blob)
    return prep.record, _finish_retain(prep, ledger=ledger, tool=tool,
                                       action=action, detail=detail,
                                       parent_id=parent_id,
                                       operation=operation,
                                       artifacts_root=artifacts_root)


@dataclass
class _Prepared:
    record: dict
    ev: str
    blob: str
    preview: str
    cov_json: str

    @property
    def size(self) -> int:
        return len(self.blob)


def _prepare(*, request: dict, data: Any, coverage: dict | None,
             provenance: dict | None, tool: str, action: str) -> _Prepared:
    """CPU half of retention (thread-safe, no ledger access)."""
    record = build_record(request, data, coverage=coverage,
                          provenance=provenance, tool=tool, action=action)
    blob = _canonical(record)
    ev = _id_from_blobs(blob, _canonical(record["request"]))
    cov_json = (json.dumps(coverage, default=str)
                if isinstance(coverage, dict) else "")
    return _Prepared(record=record, ev=ev, blob=blob,
                     preview=_bounded_dumps(data, PREVIEW_BYTES),
                     cov_json=cov_json)


def _finish_retain(prep: _Prepared, *, ledger: Any, tool: str, action: str,
                   detail: str, parent_id: str, operation: str,
                   artifacts_root: Any = None) -> dict:
    """Ledger half of retention — must run on the ledger's thread."""
    if ledger is not None:
        ledger.add_evidence_record(prep.ev, tool, action, operation,
                                   prep.cov_json, prep.size, detail,
                                   parent_id, prep.preview)
    if artifacts_root is not None:
        maybe_sweep(Path(artifacts_root), ledger)
    block: dict[str, Any] = {"evidence_id": prep.ev, "detail": detail}
    if detail == "summary":
        # Fully inline small complete results omit the continuation;
        # summaries always page back, so they always carry it.
        block["continuation"] = continuation(prep.ev)
    return block


# --------------------------------------------------------------- retention --
# Records are re-derivable caches of tool results; without pruning the
# store grew forever. A total-size cap (oldest first, default 2 GiB) and
# an optional TTL (PRY_EVIDENCE_TTL_DAYS, default 0 = off so existing
# old records are not silently aged out), swept in a daemon thread at
# most every _SWEEP_INTERVAL_S — the first retain after startup sweeps
# immediately. 0 disables a limit.

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


EVIDENCE_TTL_DAYS = _env_float("PRY_EVIDENCE_TTL_DAYS", 0.0)
EVIDENCE_MAX_MB = _env_float("PRY_EVIDENCE_MAX_MB", 2048.0)
_SWEEP_INTERVAL_S = 600.0
_SWEEP_LOCK = threading.Lock()
_LAST_SWEEP: dict[str, float] = {}


def sweep(artifacts_root: Path, *, ttl_s: float | None = None,
          max_bytes: int | None = None, now: float | None = None) -> list[str]:
    """Delete retained records past the TTL, then the oldest until the
    store fits ``max_bytes``; also clears orphaned ``*.tmp`` writes.
    Blocking. Returns the evidence ids removed."""
    ttl_s = (EVIDENCE_TTL_DAYS * 86400.0) if ttl_s is None else ttl_s
    max_bytes = (int(EVIDENCE_MAX_MB * 1024 * 1024)
                 if max_bytes is None else max_bytes)
    now = time.time() if now is None else now
    root = Path(artifacts_root) / "evidence"
    if not root.is_dir():
        return []
    entries: list[tuple[float, int, Path]] = []
    for p in root.glob("*/*"):
        try:
            st = p.stat()
        except OSError:
            continue
        if p.name.endswith(".tmp"):
            if now - st.st_mtime > 3600:
                try:
                    p.unlink()
                except OSError:
                    pass
            continue
        if p.suffix == ".json" and EVIDENCE_ID_RE.fullmatch(p.stem):
            entries.append((st.st_mtime, st.st_size, p))
    entries.sort()
    removed: list[str] = []
    keep: list[tuple[float, int, Path]] = []
    for mtime, size, p in entries:
        if ttl_s and now - mtime > ttl_s:
            try:
                p.unlink()
                removed.append(p.stem)
            except OSError:
                keep.append((mtime, size, p))
        else:
            keep.append((mtime, size, p))
    total = sum(s for _m, s, _p in keep)
    for _mtime, size, p in keep:
        if not max_bytes or total <= max_bytes:
            break
        try:
            p.unlink()
            removed.append(p.stem)
            total -= size
        except OSError:
            pass
    return removed


def _drop_rows(db_path: Path | None, ids: list[str]) -> None:
    """Delete swept ids' ledger rows through a private connection (the
    sweep runs off the loop; the ledger's own connection is loop-bound).
    WAL + busy_timeout make the concurrent writer safe."""
    if not ids or db_path is None:
        return
    import sqlite3
    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
    except sqlite3.Error:
        return
    try:
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            conn.execute(
                "DELETE FROM evidence WHERE kind='tool_result' AND id IN ("
                + ",".join("?" * len(chunk)) + ")", chunk)
        conn.commit()
    except sqlite3.Error as exc:
        log.warning("evidence sweep: ledger rows kept (%s)", exc)
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
    finally:
        conn.close()


def maybe_sweep(artifacts_root: Path, ledger: Any = None) -> bool:
    """Start a background sweep if the interval elapsed (never blocks)."""
    key = str(artifacts_root)
    now = time.monotonic()
    with _SWEEP_LOCK:
        last = _LAST_SWEEP.get(key)
        if last is not None and now - last < _SWEEP_INTERVAL_S:
            return False
        _LAST_SWEEP[key] = now
    db_path = getattr(ledger, "db_path", None)

    def _run() -> None:
        try:
            removed = sweep(Path(artifacts_root))
            if removed:
                log.info("evidence sweep: removed %d record(s)", len(removed))
                _drop_rows(db_path, removed)
        except Exception as exc:  # noqa: BLE001 — housekeeping only
            log.warning("evidence sweep failed: %s", exc)

    threading.Thread(target=_run, name="pry-evidence-sweep",
                     daemon=True).start()
    return True


def retain(*, request: dict, data: Any, artifacts_root: Path, ledger: Any,
           tool: str, action: str, detail: str = "complete",
           coverage: dict | None = None, provenance: dict | None = None,
           parent_id: str = "", operation: str = "") -> dict:
    """``retain_record`` returning just the envelope evidence block."""
    _record, block = retain_record(
        request=request, data=data, artifacts_root=artifacts_root,
        ledger=ledger, tool=tool, action=action, detail=detail,
        coverage=coverage, provenance=provenance, parent_id=parent_id,
        operation=operation)
    return block


def split_detail(detail: Any) -> tuple[str, bool]:
    """Normalize the shared ``detail`` kwarg -> ``(evidence_detail, bool)``.

    memory_manage's ``detail`` predates the evidence envelope: on ``disasm`` it
    was a bool switching capstone detail. Both meanings coexist:
    ``True`` -> legacy on + "complete"; ``False`` -> legacy off +
    "complete"; ``"summary"``/``"complete"`` -> that detail, legacy off.
    """
    if detail is True:
        return "complete", True
    if not detail:  # False / None / ""
        return "complete", False
    s = str(detail).strip().lower()
    if s == "summary":
        return "summary", False
    if s == "complete":
        return "complete", False
    return "complete", bool(detail)


def detail_applies(tool: str, action: str) -> bool:
    """Does this (tool, action) carry the ``detail`` parameter (Task 3.4)?"""
    if tool in ("ida_manage", "ghidra_manage"):
        return (action not in _META_ACTIONS
                and not action.startswith(_META_ACTION_PREFIXES))
    return action in DETAIL_ACTIONS.get(tool, frozenset())


def _to_int(v: Any) -> int:
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        return 0


def stamp_result(ctx: Any, tool: str, action: str, request: dict,
                 result: Any, detail: str) -> Any:
    """Post-process one heavy-tool result for the evidence envelope.

    Runs between the tool body and ``_guard``'s coercion. Accepts both
    result shapes the heavy tools produce — a JSON string (``_j`` /
    ``_j_hex``) or a ready dict (``_hexify_dict`` returns, e.g. the
    mem.py ``_list_envelope`` envelopes):
      * ``detail="complete"`` — retain the complete record, attach the
        ``evidence`` block (``envelope_from_result`` lifts it to
        ``env["evidence"]``).
      * ``detail="summary"`` — retain FIRST (never re-execute), then
        replace the inline payload with ``views.summary_view(record)``
        (counts + provenance + coverage; ``coverage`` is copied from the
        complete result so ``unknown`` is never laundered into
        ``complete``).

    Anything that isn't a successful JSON object result passes through
    unchanged; a retention failure logs and passes the ORIGINAL result
    through so a summary can never lose the payload to a store hiccup.
    """
    if detail not in ("complete", "summary"):
        return result
    ledger = getattr(ctx, "ledger", None)
    cfg = getattr(ctx, "cfg", None)
    if ledger is None or cfg is None:
        return result
    root = Path(cfg.artifacts_dir())
    try:
        staged = _stage(tool, action, request, result, detail, root)
    except Exception as exc:  # noqa: BLE001 — retention is best-effort
        log.warning("evidence retain failed (%s %s): %s", tool, action, exc)
        return result
    return _commit_stage(staged, result, ledger=ledger, tool=tool,
                         action=action, detail=detail, root=root)


async def stamp_result_async(ctx: Any, tool: str, action: str,
                             request: dict, result: Any, detail: str) -> Any:
    """:func:`stamp_result` with the parse / serialize / hash / file write
    in a worker thread; only the ledger row insert runs on the loop
    (sqlite connection affinity). Same output."""
    if detail not in ("complete", "summary"):
        return result
    ledger = getattr(ctx, "ledger", None)
    cfg = getattr(ctx, "cfg", None)
    if ledger is None or cfg is None:
        return result
    root = Path(cfg.artifacts_dir())
    try:
        staged = await asyncio.to_thread(_stage, tool, action, request,
                                         result, detail, root)
    except Exception as exc:  # noqa: BLE001 — retention is best-effort
        log.warning("evidence retain failed (%s %s): %s", tool, action, exc)
        return result
    return _commit_stage(staged, result, ledger=ledger, tool=tool,
                         action=action, detail=detail, root=root)


def _stage(tool: str, action: str, request: dict, result: Any, detail: str,
           root: Path) -> tuple | None:
    """Thread-safe half of stamping: parse the tool result once, build +
    serialize + persist the record, and pre-render the output. Returns
    ``None`` to pass the result through unchanged."""
    # Tool bodies return either a JSON string (_j/_j_hex) or a ready dict
    # (e.g. mem.py's `return _hexify_dict(env)`); stamp both shapes.
    encoded = isinstance(result, str)
    if encoded:
        try:
            parsed = json.loads(result)
        except (TypeError, ValueError):
            return None
    elif isinstance(result, dict):
        parsed = result
    else:
        return None
    if not isinstance(parsed, dict) or parsed.get("ok") is not True:
        return None
    if isinstance(parsed.get("evidence"), dict):
        return None  # producer already stamped — idempotent
    already_env = "kind" in parsed and "data" in parsed
    payload = (parsed.get("data") if already_env else
               {k: v for k, v in parsed.items()
                if k not in ("ok", "warnings", "evidence")})
    prep = _prepare(
        request=request or {}, data=payload,
        coverage=(parsed.get("coverage")
                  if isinstance(parsed.get("coverage"), dict) else None),
        provenance=(parsed.get("provenance")
                    if isinstance(parsed.get("provenance"), dict) else None),
        tool=tool, action=action)
    save(prep.ev, prep.record, artifacts_root=root, blob=prep.blob)
    summary = None
    if detail == "summary":
        from .views import summary_view
        summary = summary_view(prep.record)
    return prep, parsed, encoded, summary


def _commit_stage(staged: tuple | None, result: Any, *, ledger: Any,
                  tool: str, action: str, detail: str, root: Path) -> Any:
    """Loop-thread half: ledger row, then the stamped output."""
    if staged is None:
        return result
    prep, parsed, encoded, summary = staged
    try:
        block = _finish_retain(prep, ledger=ledger, tool=tool, action=action,
                               detail=detail, parent_id="", operation="",
                               artifacts_root=root)
    except Exception as exc:  # noqa: BLE001 — retention is best-effort
        log.warning("evidence retain failed (%s %s): %s", tool, action, exc)
        return result
    if summary is not None:
        out = dict(summary)
        out["ok"] = True
        out["evidence"] = block
        return json.dumps(out, default=str) if encoded else out
    if encoded:
        # Splice the block into the producer's JSON instead of
        # re-serializing a possibly multi-MB payload a second time.
        text = result.rstrip()
        if "evidence" not in parsed and text.endswith("}") and parsed:
            return (text[:-1].rstrip() + ', "evidence": '
                    + json.dumps(block, default=str) + "}")
        parsed["evidence"] = block
        return json.dumps(parsed, default=str)
    parsed["evidence"] = block
    return parsed


def with_evidence(ctx: Any, tool: str, action: str, request: dict,
                  fn: Callable[..., Coroutine[Any, Any, Any]],
                  detail: Any) -> Callable[..., Coroutine[Any, Any, Any]]:
    """Wrap a heavy tool's ``run`` so its result is evidence-stamped before
    ``_guard`` envelopes it. Zero-overhead pass-through when the action
    doesn't carry ``detail`` (see ``detail_applies``)."""
    ev_detail, _legacy = split_detail(detail)
    if not detail_applies(tool, action):

        async def _passthrough() -> Any:
            return await fn()

        return _passthrough

    async def _stamped() -> Any:
        return await stamp_result_async(ctx, tool, action, request,
                                        await fn(), ev_detail)

    return _stamped
