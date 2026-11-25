"""Memory scanner wave 3 §6.4 — shipped offset-table schema lint.

Each JSON under ``artifacts/invariants/eprocess/`` must:

* Parse as JSON and be a dict.
* Carry ``build``, ``arch``, ``eprocess``, ``assertion`` top-level keys.
* Declare the DISPATCHER_HEADER assertion pair.
* Name at minimum ``UniqueProcessId`` / ``ActiveProcessLinks`` /
  ``ImageFileName`` / ``Peb`` under ``eprocess``.
* For every present field: ``size`` is a positive int, ``kind`` is one
  of the Wave 3 supported kinds. ``offset`` may be ``null`` (an
  explicit placeholder the loader skips).

Deliberately lint-level — not a functional check. A field whose
offset is null will *not* decode through the fast-path; the loader
skips nulls and falls back to the live PDB (and then the invariant
walker), which is the whole point of shipping stubs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest  # noqa: F401

_ORCH_DIR = Path(__file__).resolve().parents[2]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

_REPO_ROOT = _ORCH_DIR.parent
_BAKED_DIR = _REPO_ROOT / "artifacts" / "invariants" / "eprocess"

_REQUIRED_FILES = [
    "win10_19041.json",
    "win10_19045.json",
    "win11_22631.json",
    "win11_26100.json",
]

_REQUIRED_FIELDS = [
    "UniqueProcessId",
    "ActiveProcessLinks",
    "ImageFileName",
    "Peb",
]

_SUPPORTED_KINDS = {"scalar", "ptr", "string_ansi", "string_us"}


def test_all_four_build_files_present():
    assert _BAKED_DIR.is_dir(), f"expected {_BAKED_DIR}"
    for name in _REQUIRED_FILES:
        assert (_BAKED_DIR / name).is_file(), \
            f"missing baked offset table: {name}"


@pytest.mark.parametrize("filename", _REQUIRED_FILES)
def test_baked_table_schema(filename):
    path = _BAKED_DIR / filename
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{filename}: top-level not an object"

    for key in ("build", "arch", "eprocess", "assertion"):
        assert key in data, f"{filename}: missing key {key!r}"

    assert isinstance(data["build"], str) and data["build"], \
        f"{filename}: build must be a non-empty string"
    assert data["arch"] in {"x64", "arm64"}, \
        f"{filename}: arch must be x64 or arm64"

    assn = data["assertion"]
    assert isinstance(assn, dict), f"{filename}: assertion not a dict"
    assert "dispatcher_header_type_at" in assn, \
        f"{filename}: missing assertion.dispatcher_header_type_at"
    assert "dispatcher_header_type_value" in assn, \
        f"{filename}: missing assertion.dispatcher_header_type_value"
    # The expected value is always 0x03 on x64 (KOBJECTS::ProcessObject).
    v = assn["dispatcher_header_type_value"]
    if isinstance(v, str):
        v = int(v, 0)
    assert v == 0x03, \
        f"{filename}: assertion value must be 0x03"

    ep = data["eprocess"]
    assert isinstance(ep, dict), f"{filename}: eprocess not a dict"
    for field in _REQUIRED_FIELDS:
        assert field in ep, f"{filename}: missing eprocess.{field}"
        spec = ep[field]
        assert isinstance(spec, dict), \
            f"{filename}: eprocess.{field} not an object"
        # size is always required (used to decide the read width even
        # for a stub).
        size = spec.get("size")
        assert isinstance(size, int) and size > 0, \
            f"{filename}: eprocess.{field}.size must be a positive int"
        kind = spec.get("kind")
        assert kind in _SUPPORTED_KINDS, \
            f"{filename}: eprocess.{field}.kind={kind!r} not supported"
        # offset may be null (placeholder); if present, accept hex str
        # or int.
        off = spec.get("offset")
        if off is None:
            continue
        if isinstance(off, str):
            int(off, 0)  # raises if not parseable
        else:
            assert isinstance(off, int), \
                f"{filename}: eprocess.{field}.offset wrong type"


def test_loader_reads_each_shipped_file_without_error():
    """Round-trip through the loader so a schema mismatch surfaces
    here (not at MCP-call time)."""
    from src.pry.mcp.tools.kernel import _invariants
    for name in _REQUIRED_FILES:
        # Derive the build_major from the filename ("win10_19041" -> 19041).
        stem = Path(name).stem.split("_")[-1]
        build_major = int(stem)
        data = _invariants.load_baked(build_major, baked_dir=_BAKED_DIR)
        assert data is not None, f"loader could not read {name}"
