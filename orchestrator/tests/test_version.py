"""Version-skew test: pyproject ``project.version`` and ``SERVER_VERSION``
(server.py) must agree.

Formats in play:
- pyproject ``project.version``: "X.Y.Z" (PEP 440, three components)
- ``SERVER_VERSION`` (server.py): "X.Y.Z" with an optional "-YYYY-MM-DD" build
  stamp, which is ignored for the comparison

Both normalize to an int tuple with trailing zeros stripped before
comparison, so X.Y.0 equals X.Y.
"""

from __future__ import annotations

import re
import tomllib

import _catalog


def _norm(version: str) -> tuple[int, ...]:
    parts = tuple(int(p) for p in version.split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def test_versions_in_sync() -> None:
    pyproject = tomllib.loads(_catalog.PYPROJECT_PATH.read_text(encoding="utf-8"))
    pyproject_version = pyproject["project"]["version"]

    server_src = _catalog.SERVER_PY_PATH.read_text(encoding="utf-8")
    match = re.search(r'SERVER_VERSION\s*=\s*"([^"]+)"', server_src)
    assert match, "SERVER_VERSION not found in server.py"
    server_version = re.sub(r"-\d{4}-\d{2}-\d{2}$", "", match.group(1))

    assert _norm(pyproject_version) == _norm(server_version), (
        f"pyproject {pyproject_version} != SERVER_VERSION {server_version}"
    )
