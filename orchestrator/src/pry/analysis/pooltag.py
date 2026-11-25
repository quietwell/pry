"""Pool-tag -> owner-driver lookup.

Loads the vendored ``pry/data/pooltag.txt`` into a dict keyed by the
4-char ASCII tag. Format matches Microsoft's WDK ``triage/pooltag.txt``:

    TAG - OWNER - DESCRIPTION

- ``TAG`` is 1..4 printable ASCII bytes (trailing spaces padded to 4).
- ``OWNER`` is ``<driver>`` or ``<driver>!<component>`` (we keep both
  halves — ``driver`` is the key the orchestrator exposes).
- Comments (`#`, `;`, or ``rem``) and blank lines are skipped so a WDK
  scrape (which uses ``rem`` headers) can be dropped in verbatim.

Feature #4 of the System-Informer adoption plan — see
``an internal plan``.
The loader is lazy + cached: the first ``pool_scan`` enrichment call
in a server lifetime pays the parse cost (microseconds for a few KB),
every subsequent lookup is O(1). ``load_pooltag_db()`` is also safe to
call directly from tests.
"""

from __future__ import annotations

import logging
from pathlib import Path
from threading import Lock
from typing import Any

log = logging.getLogger("pry.analysis.pooltag")

# Loaded database. ``None`` means "load not yet attempted"; a dict (even
# empty) means we tried and this is the result.
_DB: dict[str, dict[str, str]] | None = None
_DB_META: dict[str, Any] = {}
_LOCK = Lock()


# ---------------------------------------------------------------- parsing ---

def _parse_line(raw: str) -> tuple[str, str, str, str] | None:
    """Parse one ``TAG - OWNER - DESCRIPTION`` line.

    Returns ``(tag4, driver, component, description)`` where ``tag4`` is
    normalised to 4 bytes (space-padded, as the kernel emits them).
    Returns ``None`` for comments / blanks / unparseable lines.
    """
    line = raw.rstrip("\r\n")
    stripped = line.strip()
    if not stripped:
        return None
    if stripped[0] in "#;":
        return None
    if stripped.lower().startswith("rem ") or stripped.lower() == "rem":
        return None
    # WDK uses literal " - " separators but tolerates runs of whitespace.
    # Split on " - " first (preserves hyphens inside descriptions), fall
    # back to splitting on "-" with trimming when the canonical form is
    # missing (older samples / hand-authored lines).
    parts = [p.strip() for p in line.split(" - ", 2)]
    if len(parts) < 2:
        parts = [p.strip() for p in line.split("-", 2)]
        if len(parts) < 2:
            return None
    tag_raw = parts[0]
    owner = parts[1] if len(parts) > 1 else ""
    desc = parts[2] if len(parts) > 2 else ""
    # Tag normalisation: strip surrounding quotes, truncate / pad to 4.
    tag = tag_raw.strip().strip("'\"")
    if not tag:
        return None
    if len(tag) > 4:
        tag = tag[:4]
    tag4 = tag.ljust(4)
    # Owner: ``nt!ps`` -> driver=``nt``, component=``ps``.
    if "!" in owner:
        driver, _, component = owner.partition("!")
        driver = driver.strip()
        component = component.strip()
    else:
        driver = owner.strip()
        component = ""
    return tag4, driver, component, desc.strip()


def _parse_text(text: str) -> dict[str, dict[str, str]]:
    db: dict[str, dict[str, str]] = {}
    for raw in text.splitlines():
        parsed = _parse_line(raw)
        if parsed is None:
            continue
        tag4, driver, component, desc = parsed
        # First definition wins — the vendored file is authored
        # deliberately; a WDK scrape may contain duplicates with the
        # less-specific entry later. Later-wins would hide the better
        # entry, so we keep the first explicit mapping.
        db.setdefault(tag4, {
            "driver": driver,
            "component": component,
            "description": desc,
        })
    return db


# -------------------------------------------------------- source discovery --

def _candidate_paths() -> list[Path]:
    """Where to look for ``pooltag.txt`` — package resource first,
    repo-root ``orchestrator/data/pooltag.txt`` second (slice-doc path
    for a hand-dropped file during dev)."""
    out: list[Path] = []
    # 1. Package resource (works in editable installs AND wheels).
    try:
        from importlib.resources import files as _resources_files
        pkg_path = _resources_files("pry.data").joinpath("pooltag.txt")
        # ``files()`` can return a Traversable; realise it to a Path if
        # possible (editable install) or spool it to a temp copy. The
        # cheap path is Path-ness: a MultiplexedPath or ZipPath has no
        # ``__fspath__`` but ``read_text`` still works on it.
        try:
            out.append(Path(str(pkg_path)))
        except TypeError:
            # Non-filesystem resource: we'll read via the Traversable
            # directly in load_pooltag_db().
            out.append(pkg_path)  # type: ignore[arg-type]
    except (ModuleNotFoundError, FileNotFoundError):
        pass
    # 2. Repo-local fallback for a dev scrape dropped at the slice-doc path.
    #    Walk upward from this file: ``src/pry/analysis/pooltag.py``
    #    -> ``src/pry/analysis`` -> ``src/pry`` -> ``src`` ->
    #    ``orchestrator`` -> ``<repo-root>``.
    here = Path(__file__).resolve()
    for base in (here.parents[3], here.parents[4] if len(here.parents) >= 5
                 else here.parents[3]):
        candidate = base / "data" / "pooltag.txt"
        if candidate not in out:
            out.append(candidate)
    return out


# ----------------------------------------------------------------- API ------

def load_pooltag_db(path: str | Path | None = None,
                     *, force: bool = False) -> dict[str, dict[str, str]]:
    """Load the pooltag database. Cached module-level after first call.

    ``path`` lets callers (tests) point at a specific file. ``force=True``
    discards any cache and reparses. A missing or unreadable file yields
    an empty dict and sets ``_DB_META['status']='missing'`` so callers
    can report ``tags_enriched=False`` without ever raising.
    """
    global _DB
    with _LOCK:
        if _DB is not None and not force and path is None:
            return _DB
        text: str | None = None
        src: str | None = None
        if path is not None:
            try:
                text = Path(path).read_text(encoding="utf-8")
                src = str(path)
            except OSError as exc:
                log.warning("pooltag: cannot read %s: %s", path, exc)
        else:
            for cand in _candidate_paths():
                try:
                    text = cand.read_text(encoding="utf-8")  # type: ignore[union-attr]
                    src = str(cand)
                    break
                except (OSError, AttributeError):
                    continue
                except FileNotFoundError:
                    continue
        if text is None:
            _DB = {}
            _DB_META.clear()
            _DB_META.update({"status": "missing", "entries": 0, "source": None})
            return _DB
        db = _parse_text(text)
        _DB = db
        _DB_META.clear()
        _DB_META.update({"status": "loaded" if db else "empty",
                          "entries": len(db), "source": src})
        return _DB


def lookup_pool_tag(tag: str | bytes | int) -> dict[str, str] | None:
    """Look up a 4-char pool tag; returns ``None`` on miss.

    ``tag`` accepts the usual shapes:
    - ``str``: ``'Proc'`` / ``'Pr'`` (padded) / ``'Proc '``.
    - ``bytes``: the raw little-endian 4-byte tag.
    - ``int``: ``PoolTag`` as the agent returns it.
    """
    db = load_pooltag_db()
    if not db:
        return None
    key = _normalise_tag(tag)
    if key is None:
        return None
    hit = db.get(key)
    if hit is not None:
        return hit
    # Second-chance: strip trailing spaces and retry (callers may pass
    # a shorter form; db stores padded form).
    stripped = key.rstrip()
    if stripped != key:
        return db.get(stripped.ljust(4))
    return None


def _normalise_tag(tag: str | bytes | int) -> str | None:
    """Return the canonical 4-char ASCII form of ``tag`` or ``None``."""
    if isinstance(tag, int):
        if tag <= 0:
            return None
        raw = tag.to_bytes(4, "little", signed=False)
        # Strip trailing NULs; the kernel's non-ASCII high byte zeros out
        # for short tags like ``'Proc'`` (0x636F7250).
        try:
            key = raw.decode("ascii", "strict").rstrip("\x00")
        except UnicodeDecodeError:
            # Non-ASCII tag: best-effort replace, downstream matcher
            # tolerates the padded form.
            key = raw.decode("ascii", "replace")
        return key.ljust(4)[:4]
    if isinstance(tag, bytes):
        if not tag:
            return None
        try:
            key = tag[:4].decode("ascii", "strict").rstrip("\x00")
        except UnicodeDecodeError:
            key = tag[:4].decode("ascii", "replace")
        return key.ljust(4)[:4]
    if isinstance(tag, str):
        t = tag.strip()
        if not t:
            return None
        return t[:4].ljust(4)
    return None


def pooltag_meta() -> dict[str, Any]:
    """Expose loader status for ``pool_scan``'s envelope (`tags_enriched`,
    source path for debugging). Triggers a load if one hasn't happened."""
    load_pooltag_db()
    return dict(_DB_META)


__all__ = [
    "load_pooltag_db",
    "lookup_pool_tag",
    "pooltag_meta",
]
