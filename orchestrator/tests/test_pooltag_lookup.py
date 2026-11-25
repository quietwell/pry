"""Pool-tag lookup — unit tests for the vendored pooltag.txt loader.

Covers:
- parse happy path (`TAG - DRIVER - DESCRIPTION`).
- comment / blank / `rem` line handling (so a WDK scrape drops in verbatim).
- 4-char padding + int/bytes/str input shapes.
- missing-file is a graceful empty dict + status='missing' (never raises).
- load cache invalidation via ``force=True``.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from pry.analysis import pooltag as _pt


@pytest.fixture(autouse=True)
def _reset_pooltag_cache():
    _pt._DB = None
    _pt._DB_META.clear()
    yield
    _pt._DB = None
    _pt._DB_META.clear()


def test_vendored_pooltag_loads_canonical_tags():
    """The vendored file ships enough tags to answer the integration
    smoke test (Proc / Even / Thre all route to the ``nt`` driver)."""
    db = _pt.load_pooltag_db()
    assert len(db) >= 50  # seed vendored at least this many
    assert _pt.lookup_pool_tag("Proc")["driver"] == "nt"
    assert _pt.lookup_pool_tag("Even")["driver"] == "nt"
    assert _pt.lookup_pool_tag("Thre")["driver"] == "nt"
    meta = _pt.pooltag_meta()
    assert meta["status"] == "loaded"
    assert meta["entries"] == len(db)
    assert meta["source"] is not None


def test_lookup_accepts_int_bytes_str(tmp_path):
    p = tmp_path / "pt.txt"
    p.write_text(
        "# synthetic fixture\n"
        "Fake - fakedrv!foo - synthetic fixture entry\n"
        "Shr  - sd         - short three-char tag (padded)\n",
        encoding="utf-8",
    )
    _pt.load_pooltag_db(p, force=True)
    # str
    hit = _pt.lookup_pool_tag("Fake")
    assert hit and hit["driver"] == "fakedrv"
    assert hit["component"] == "foo"
    # bytes
    assert _pt.lookup_pool_tag(b"Fake")["driver"] == "fakedrv"
    # int (little-endian 'Fake' => bytes = 'Fake')
    val = int.from_bytes(b"Fake", "little")
    assert _pt.lookup_pool_tag(val)["driver"] == "fakedrv"
    # Shorter tag padded both at write-time (file) and lookup-time.
    assert _pt.lookup_pool_tag("Shr")["driver"] == "sd"


def test_comments_rem_and_blanks_ignored(tmp_path):
    p = tmp_path / "pt.txt"
    p.write_text(
        "# a comment\n"
        "; another comment\n"
        "rem WDK-style comment line\n"
        "\n"
        "   \n"
        "Prc1 - drvA - entry one\n"
        "Prc2 - drvB - entry two with - a dash inside\n",
        encoding="utf-8",
    )
    _pt.load_pooltag_db(p, force=True)
    assert _pt.lookup_pool_tag("Prc1")["driver"] == "drvA"
    # Verify the description keeps interior dashes intact.
    e2 = _pt.lookup_pool_tag("Prc2")
    assert e2["driver"] == "drvB"
    assert "dash inside" in e2["description"]


def test_missing_file_returns_empty(tmp_path):
    p = tmp_path / "does-not-exist.txt"
    assert _pt.load_pooltag_db(p, force=True) == {}
    assert _pt.pooltag_meta()["status"] == "missing"
    # A lookup against the empty cache is a soft miss, never an exception.
    assert _pt.lookup_pool_tag("Proc") is None


def test_cache_is_sticky_until_force(tmp_path):
    p = tmp_path / "pt.txt"
    p.write_text("Aaaa - d1 - initial\n", encoding="utf-8")
    _pt.load_pooltag_db(p, force=True)
    assert _pt.lookup_pool_tag("Aaaa")["driver"] == "d1"
    # Overwrite on disk; without force we keep the cached entry.
    p.write_text("Aaaa - d2 - updated\n", encoding="utf-8")
    _pt.load_pooltag_db()  # no path, no force
    assert _pt.lookup_pool_tag("Aaaa")["driver"] == "d1"
    # Force reparse honours the new content.
    _pt.load_pooltag_db(p, force=True)
    assert _pt.lookup_pool_tag("Aaaa")["driver"] == "d2"


def test_miss_returns_none():
    _pt.load_pooltag_db(force=True)
    assert _pt.lookup_pool_tag("zzzz") is None
    assert _pt.lookup_pool_tag("") is None
    assert _pt.lookup_pool_tag(0) is None
