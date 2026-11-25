"""Suite-wide fixtures.

Endpoint self-heal (``pry.endpoint_hints``) has two background behaviors
that must never fire by accident in unit tests:

* hostname-based endpoint discovery would call the real OS resolver when a
  fake connect fails;
* the per-view link watcher would poll fake clients from a background task.

Both are on in production and off here; the tests that exercise them turn
them on explicitly (and patch the resolver).
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _endpoint_heal_off_by_default(monkeypatch):
    monkeypatch.setenv("PRY_NAME_RESOLVE", "0")
    monkeypatch.setenv("PRY_LINK_HEAL", "0")
    yield


@pytest.fixture(autouse=True, scope="session")
def _audit_log_in_tmp(tmp_path_factory):
    """Keep test-run audit logs out of the real ~/.pry/audit.

    Every Session() opens a per-process audit directory; without this the
    suite left one real directory per run (tens of thousands on the dev
    host)."""
    import os
    base = tmp_path_factory.mktemp("audit")
    prev = os.environ.get("PRY_AUDIT_BASE_DIR")
    os.environ["PRY_AUDIT_BASE_DIR"] = str(base)
    yield
    if prev is None:
        os.environ.pop("PRY_AUDIT_BASE_DIR", None)
    else:
        os.environ["PRY_AUDIT_BASE_DIR"] = prev
