"""Passthrough job store: chunk math, retention pruning, result stash,
background job spawn, spill-directory resolution, and listing spill.

Direct port of ``idalib_shim.jobs`` — the machinery is engine-agnostic;
the JOBS record shape is identical so ``ghidra_job_*``/``ghidra_result``
behave exactly like their ``ida_job_*``/``ida_result`` counterparts.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import threading
import time
import uuid
from pathlib import Path

from .logging import _log


# Same budgeting model as the IDA shim: anything the backend doesn't
# return within SOFT_DEADLINE_S OR whose serialised text exceeds
# CHUNK_BYTES becomes a job the caller polls/pages.  Ghidra decompile of
# a large function is slower than Hex-Rays, so the default soft deadline
# is a bit more generous.
SOFT_DEADLINE_S = float(os.environ.get("PRY_GHIDRA_JOB_SOFT_DEADLINE_S", "30"))
CHUNK_BYTES = int(os.environ.get("PRY_GHIDRA_JOB_CHUNK_BYTES", "24000"))
JOB_RETENTION_S = float(os.environ.get("PRY_GHIDRA_JOB_RETENTION_S", "1800"))


# job_id -> {tool, args, task, status, result_text, error, started_at, ...}
# result_text is set once the task completes; chunks/total are derived
# from it on the fly by ghidra_result. See _stash_result / _spawn_job.
JOBS: dict[str, dict] = {}
JOBS_LOCK = asyncio.Lock()


def _chunk_count(total_bytes: int, chunk_bytes: int) -> int:
    if total_bytes <= 0:
        return 0
    return (total_bytes + chunk_bytes - 1) // chunk_bytes


async def _prune_jobs_locked() -> None:
    now = time.monotonic()
    stale = [jid for jid, j in JOBS.items()
             if j.get("finished_at") and now - j["finished_at"] > JOB_RETENTION_S]
    for jid in stale:
        JOBS.pop(jid, None)


async def _stash_result(tool: str, args: dict, sid: str, text: str) -> str:
    """Create a done job holding `text`. Returns job_id."""
    job_id = "j_" + uuid.uuid4().hex[:12]
    async with JOBS_LOCK:
        await _prune_jobs_locked()
        JOBS[job_id] = {
            "tool": tool, "args": args, "sid": sid,
            "task": None, "started_at": time.monotonic(),
            "status": "done", "result_text": text,
            "error": None, "total_bytes": len(text),
            "chunk_bytes": CHUNK_BYTES,
            "finished_at": time.monotonic(),
        }
    return job_id


async def _spawn_job(tool: str, args: dict, sid: str,
                     coro_factory) -> str:
    """Create a pending job that runs `coro_factory()` to completion in
    the background. Returns job_id immediately. On completion, the task
    stores result_text on the JOBS entry."""
    # Imported lazily to keep this module free of the listing/content
    # cycle at import time.
    from .listing import _flat_text_from_content

    job_id = "j_" + uuid.uuid4().hex[:12]
    started = time.monotonic()

    async def _run() -> None:
        try:
            content = await coro_factory()
            text = _flat_text_from_content(content) if isinstance(content, list) else str(content)
            async with JOBS_LOCK:
                j = JOBS.get(job_id)
                if j is None:
                    return
                j["status"] = "done"
                j["result_text"] = text
                j["total_bytes"] = len(text)
                j["finished_at"] = time.monotonic()
        except asyncio.CancelledError:
            async with JOBS_LOCK:
                j = JOBS.get(job_id)
                if j is not None and j["status"] == "pending":
                    j["status"] = "cancelled"
                    j["finished_at"] = time.monotonic()
            raise
        except Exception as exc:  # noqa: BLE001
            async with JOBS_LOCK:
                j = JOBS.get(job_id)
                if j is not None:
                    j["status"] = "error"
                    j["error"] = f"{type(exc).__name__}: {exc}"
                    j["finished_at"] = time.monotonic()

    task = asyncio.create_task(_run(), name=f"ghidra-job-{tool}-{job_id}")
    async with JOBS_LOCK:
        await _prune_jobs_locked()
        JOBS[job_id] = {
            "tool": tool, "args": args, "sid": sid,
            "task": task, "started_at": started,
            "status": "pending", "result_text": None,
            "error": None, "total_bytes": 0,
            "chunk_bytes": CHUNK_BYTES,
            "finished_at": None,
        }
    return job_id


def _shim_spill_dir() -> Path:
    """Where to write full-listing bytes for chunked envelopes so
    file_manage(action='read_artifact', sha256=...) can serve them by
    content hash long after the in-memory JOBS entry has expired.

    Same resolution order as the idalib shim: PRY_MCP_SPILL_DIR >
    <PRY_ARTIFACTS_DIR>/spill > <repo>/artifacts/spill.
    """
    envd = os.environ.get("PRY_MCP_SPILL_DIR")
    if envd:
        return Path(envd)
    artifacts = os.environ.get("PRY_ARTIFACTS_DIR")
    if artifacts:
        return Path(artifacts) / "spill"
    return Path(__file__).resolve().parent.parent.parent / "artifacts" / "spill"


def _atomic_write(dest: Path, raw: bytes) -> None:
    """tmp (unique per writer) + os.replace — a crash or a concurrent
    writer can never leave a truncated listing under its content hash
    (the exists() dedupe would then trust it forever)."""
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}."
                         f"{uuid.uuid4().hex[:8]}.tmp")
    try:
        tmp.write_bytes(raw)
        os.replace(tmp, dest)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


# Listing spills were never pruned. Size cap (PRY_MCP_SPILL_MAX_MB,
# default 2048; 0 = off) over this shim's ``*.listing`` files, oldest
# (least recently written/read) first, swept at most every 10 minutes in
# a daemon thread. Shares the orchestrator's spill dir and knob.
def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


_LISTING_MAX_MB = _env_float("PRY_MCP_SPILL_MAX_MB", 2048.0)
_SWEEP_INTERVAL_S = 600.0
_SWEEP_STATE = {"last": None}
_SWEEP_LOCK = threading.Lock()


def _sweep_listings(spill_dir: Path, max_bytes: int | None = None) -> int:
    """Evict oldest ``<sha>.listing`` files until under the cap; also
    drop stale write temps. Returns the number of files removed."""
    cap = int(_LISTING_MAX_MB * 1024 * 1024) if max_bytes is None else max_bytes
    now = time.time()
    rows = []
    removed = 0
    for p in spill_dir.iterdir():
        try:
            st = p.stat()
        except OSError:
            continue
        if p.name.endswith(".tmp") and p.name.startswith("."):
            if now - st.st_mtime > 3600:
                try:
                    p.unlink()
                    removed += 1
                except OSError:
                    pass
            continue
        if p.suffix == ".listing" and len(p.stem) == 64:
            rows.append((st.st_mtime, st.st_size, p))
    if not cap:
        return removed
    rows.sort()
    total = sum(r[1] for r in rows)
    for _mtime, size, p in rows:
        if total <= cap:
            break
        try:
            p.unlink()
            removed += 1
            total -= size
        except OSError:
            pass
    return removed


def _maybe_sweep(spill_dir: Path) -> None:
    now = time.monotonic()
    with _SWEEP_LOCK:
        last = _SWEEP_STATE["last"]
        if last is not None and now - last < _SWEEP_INTERVAL_S:
            return
        _SWEEP_STATE["last"] = now

    def _run() -> None:
        try:
            n = _sweep_listings(spill_dir)
            if n:
                _log(f"shim: spill sweep removed {n} file(s)")
        except Exception as exc:  # noqa: BLE001 — housekeeping only
            _log(f"shim: spill sweep failed: {exc}")

    threading.Thread(target=_run, name="shim-spill-sweep", daemon=True).start()


def _write_listing_spill(raw: bytes) -> str:
    """Write full listing bytes to <spill_dir>/<sha256>.listing (dedup
    by content hash). Returns the sha256 hex digest. Filesystem errors
    are logged but non-fatal — the envelope still carries the sha256 +
    preview, and the in-memory JOBS cache remains available for
    legacy ghidra_result(job_id, page) fetches.
    """
    sha = hashlib.sha256(raw).hexdigest()
    try:
        spill_dir = _shim_spill_dir()
        spill_dir.mkdir(parents=True, exist_ok=True)
        dest = spill_dir / f"{sha}.listing"
        if not dest.exists():
            _atomic_write(dest, raw)
        else:
            try:
                os.utime(dest, None)  # LRU for the sweep
            except OSError:
                pass
        _maybe_sweep(spill_dir)
    except OSError as exc:
        _log(f"shim: spill write failed for {sha[:12]}...: {exc}")
    return sha
