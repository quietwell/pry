"""Shared artifact-store resolution: canonical paths + sha256 index.

Every artifact producer/consumer used to resolve ``artifacts.dir``
independently against the process cwd — two orchestrator launches with
different cwds produced two stores (``<repo>/artifacts`` vs
``orchestrator/artifacts``) and each consumer's relative-path join picked
one at random. ``config.artifacts_dir()`` now anchors relative dirs at
the repo root, and all tool-layer artifact paths funnel through
``resolve_artifact_path`` so these spellings stay equivalent everywhere:

    dumps/x.sys                                artifacts-relative (the
                                             `path` list_artifacts emits)
    artifacts/dumps/x.sys                      leading store-name prefix
    D:\\Source\\pry\\artifacts\\dumps\\x.sys absolute (`abs_path`)
    spill/<sha256>.bin                         spill payloads, including a
                                             spill_dir relocated outside
                                             artifacts/ by
                                             PRY_MCP_SPILL_DIR

``find_artifact_by_sha`` covers the WHOLE store — dumps/, ingested/,
spill/, and store_binary's ``<sha256>/`` workdirs — so ``sha256=``
lookups stop being spill-only.

mechanics-audit P0 #5: lookups no longer re-hash the store. Every file
the tool layer writes, ingests or hashes is recorded in a process-wide
``path -> (sha, size, mtime)`` index that is persisted to the ledger's
``artifact_paths`` table (and seeded back from it after a restart). A
lookup verifies candidate rows with a ``stat`` and only hashes files the
index has never seen or that changed since — and the async entry point
(``find_artifact_by_sha_async``) runs all filesystem work in a worker
thread so the event loop never stalls on it.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import threading
import weakref
from pathlib import Path, PureWindowsPath
from typing import Any

_HEX_PREFIX_RE = re.compile(r"[0-9a-f]{1,64}")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")

# Files under artifacts/ that are never content-addressed artifacts and
# change constantly (the ledger itself, write temps) — skip in the walk.
_WALK_SKIP_SUFFIXES = (".tmp", ".db", ".db-wal", ".db-shm", ".db-journal",
                       ".idx")

# path(str) -> (sha256, size, mtime). Written from worker threads too —
# single dict ops are atomic under the GIL; compound updates hold _LOCK.
_INDEX: dict[str, tuple[str, int, float]] = {}
_DIRTY: set[str] = set()          # paths not yet persisted to the ledger
_SEEDED: "weakref.WeakSet[Any]" = weakref.WeakSet()  # ledgers loaded
_LOCK = threading.Lock()


def valid_sha_prefix(sha_prefix: str) -> str | None:
    """Lowercase hex prefix (1-64 chars) or None. Guards every glob/path
    join: a raw prefix like ``../..`` or ``c:`` reached
    ``spill.glob(pref + '*')`` before."""
    pref = (sha_prefix or "").strip().lower()
    return pref if _HEX_PREFIX_RE.fullmatch(pref) else None


_RESERVED_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)] + [f"LPT{i}" for i in range(1, 10)])


def safe_basename(name: str, default: str = "file.bin") -> str:
    """A target-/user-supplied file name reduced to one safe local path
    component: the last segment under Windows *and* POSIX separator rules
    (so ``..\\..\\x``, ``C:x``, ``/etc/x`` all collapse), NTFS-invalid
    and control characters replaced, no leading/trailing dots or spaces,
    never ``.``/``..`` or a DOS device name."""
    base = PureWindowsPath(str(name or "")).name
    base = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", base).strip(" .")
    if not base or base in (".", ".."):
        base = default
    if base.split(".", 1)[0].upper() in _RESERVED_NAMES:
        base = "_" + base
    return base[:200]


def note_artifact(path: str | Path, sha256: str, size: int = -1,
                  mtime: float = -1.0) -> None:
    """Record ``path -> sha256`` in the process index (thread-safe).
    ``size``/``mtime`` default to a fresh stat. Persisted to the ledger
    by the next :func:`flush_index` (always on the loop thread)."""
    if not sha256 or not path:
        return
    p = str(path)
    if size < 0 or mtime < 0:
        try:
            st = Path(p).stat()
        except OSError:
            return
        size, mtime = int(st.st_size), float(st.st_mtime)
    with _LOCK:
        _INDEX[p] = (sha256.lower(), int(size), float(mtime))
        _DIRTY.add(p)


def flush_index(ledger: Any) -> None:
    """Persist index rows recorded since the last flush. Must run on the
    thread that owns the ledger's sqlite connection (the event loop)."""
    if ledger is None or not hasattr(ledger, "record_artifact_paths"):
        return
    with _LOCK:
        if not _DIRTY:
            return
        rows = [(v[0], p, v[1], v[2]) for p in _DIRTY
                if (v := _INDEX.get(p)) is not None]
        _DIRTY.clear()
    try:
        ledger.record_artifact_paths(rows)
    except Exception:  # noqa: BLE001 — index persistence is best-effort
        pass


def _seed_from_ledger(ledger: Any) -> None:
    """Load the persisted index once per ledger (loop thread)."""
    if ledger is None:
        return
    try:
        if ledger in _SEEDED:
            return
        _SEEDED.add(ledger)
    except TypeError:  # not weak-referenceable (test doubles)
        pass
    conn = getattr(ledger, "_conn", None)
    if conn is None:
        return
    try:
        rows = conn.execute(
            "SELECT sha256, path, size, mtime FROM artifact_paths").fetchall()
    except Exception:  # noqa: BLE001 — pre-index DB / closed handle
        return
    with _LOCK:
        for r in rows:
            _INDEX.setdefault(str(r[1]), (str(r[0]), int(r[2] or 0),
                                          float(r[3] or 0.0)))


def artifact_sha256(p: str | Path, chunk: int = 1 << 20) -> str:
    """sha256 of a local artifact, cached on (path, size, mtime) through
    the shared index. Returns "" when the file vanishes or hashing fails
    — a listing must never fail because a file was deleted concurrently.
    Blocking: call from a worker thread for anything big."""
    path = Path(p)
    try:
        st = path.stat()
    except OSError:
        return ""
    key = str(path)
    hit = _INDEX.get(key)
    if hit is not None and hit[1] == st.st_size and hit[2] == st.st_mtime:
        return hit[0]
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                buf = fh.read(chunk)
                if not buf:
                    break
                h.update(buf)
    except OSError:
        return ""
    digest = h.hexdigest()
    note_artifact(key, digest, int(st.st_size), float(st.st_mtime))
    return digest


def artifact_roots(cfg) -> list[Path]:
    """Resolved containment roots: artifacts_dir first, plus spill_dir
    when it diverges (PRY_MCP_SPILL_DIR can point outside artifacts/).
    """
    roots: list[Path] = []
    for r in (cfg.artifacts_dir(), cfg.spill_dir()):
        try:
            rr = Path(r).resolve()
        except OSError:
            continue
        if rr not in roots:
            roots.append(rr)
    return roots


def resolve_artifact_path(cfg, raw: str) -> Path | None:
    """Resolve one user-supplied artifact path to an absolute Path under
    a store root, or None when the input escapes every root.

    A leading component equal to a root's own name — or the literal
    ``artifacts`` — is stripped: callers keep pasting the store prefix
    the returned paths already carry (``artifacts/ingested/x.sys`` used
    to double-prefix to ``artifacts/artifacts/ingested/…``). Existence
    is NOT checked — a contained-but-missing path still resolves, and
    the caller decides between not_found and bad_arg.
    """
    if not raw:
        return None
    roots = artifact_roots(cfg)
    if not roots:
        return None
    p = Path(raw)
    if p.is_absolute():
        rp = p.resolve()
        return rp if any(r == rp or r in rp.parents for r in roots) else None
    parts = [seg for seg in p.parts if seg not in ("", ".")]
    base, rest = roots[0], parts
    if parts:
        head = parts[0].lower()
        for i, r in enumerate(roots):
            if head == r.name.lower() or (i == 0 and head == "artifacts"):
                base, rest = r, parts[1:]
                break
        else:
            # 'spill/<sha>.bin' still routes to the spill root when it's
            # relocated outside artifacts/ under a different dir name.
            if head == "spill" and len(roots) > 1:
                base, rest = roots[1], parts[1:]
    if not rest:
        return base
    cand = (base / Path(*rest)).resolve()
    return cand if any(r == cand or r in cand.parents for r in roots) else None


def _contained(p: Path, roots: list[Path]) -> bool:
    try:
        rp = p.resolve()
    except OSError:
        return False
    return any(r == rp or r in rp.parents for r in roots)


def _lookup_sync(cfg, pref: str) -> tuple[str, str] | None:
    """Blocking core of the sha lookup (``pref`` already validated)."""
    # 1. Spill payloads are named <sha256>.<ext>: a stem glob is free.
    try:
        spill = Path(cfg.spill_dir())
        for p in sorted(spill.glob(pref + "*")):
            if (p.is_file() and p.suffix.lower() not in (".idx", ".tmp")
                    and _HEX64_RE.fullmatch(p.stem.lower())):
                return str(p), p.stem.lower()
    except OSError:
        pass
    roots = artifact_roots(cfg)
    # 2. Index candidates — verified by stat; only a changed file rehashes.
    with _LOCK:
        cands = [(path, v) for path, v in _INDEX.items()
                 if v[0].startswith(pref)]
    for path, (sha, size, mtime) in cands:
        p = Path(path)
        if not _contained(p, roots):
            continue
        try:
            st = p.stat()
        except OSError:
            with _LOCK:
                _INDEX.pop(path, None)
            continue
        if st.st_size == size and st.st_mtime == mtime:
            return str(p), sha
        digest = artifact_sha256(p)
        if digest.startswith(pref):
            return str(p), digest
    # 3. Walk for files the index has never seen (copied in by hand,
    #    downloads, pre-index stores). Known-unchanged files cost a stat;
    #    each new file is hashed once and then indexed for good.
    art = Path(cfg.artifacts_dir())
    if not art.is_dir():
        return None
    for f in sorted(art.rglob("*")):
        if f.name.lower().endswith(_WALK_SKIP_SUFFIXES):
            continue
        try:
            if not f.is_file():
                continue
        except OSError:
            continue
        digest = artifact_sha256(f)
        if digest and digest.startswith(pref):
            return str(f), digest
    return None


def find_artifact_by_sha(cfg, sha_prefix: str, *,
                         ledger: Any = None) -> tuple[str, str] | None:
    """sha256 prefix -> (abs_path, digest) across the whole store.

    Blocking — async callers use :func:`find_artifact_by_sha_async`. A
    prefix that is not 1-64 hex chars resolves to None (never a glob or
    path join)."""
    pref = valid_sha_prefix(sha_prefix)
    if pref is None:
        return None
    _seed_from_ledger(ledger)
    hit = _lookup_sync(cfg, pref)
    flush_index(ledger)
    return hit


async def find_artifact_by_sha_async(cfg, sha_prefix: str, *,
                                     ledger: Any = None
                                     ) -> tuple[str, str] | None:
    """:func:`find_artifact_by_sha` with the filesystem walk / hashing in
    a worker thread; ledger reads/writes stay on the calling (loop)
    thread, which owns the sqlite connection."""
    pref = valid_sha_prefix(sha_prefix)
    if pref is None:
        return None
    _seed_from_ledger(ledger)
    hit = await asyncio.to_thread(_lookup_sync, cfg, pref)
    flush_index(ledger)
    return hit


async def hash_artifact_async(p: str | Path, *, ledger: Any = None) -> str:
    """Off-loop :func:`artifact_sha256` + index persistence."""
    digest = await asyncio.to_thread(artifact_sha256, p)
    flush_index(ledger)
    return digest
