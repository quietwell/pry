"""Tool-catalog drift test: the committed snapshot must match the live
FastMCP registry exactly.

On failure regenerate and commit:

    uv run python scripts/gen_tool_catalog.py
"""

from __future__ import annotations

import pytest

import _catalog

KNOWN_TOOLS = {
    "target_manage", "memory_manage", "debug_manage", "bp_manage", "exec_manage",
    "file_manage", "ida_manage", "ghidra_manage", "script_manage",
    "knowledge_manage", "reg_manage", "watchdog_manage",
    "value_manage", "emulate_manage", "bin_manage", "device_manage",
    "event_manage", "symbols_manage", "dump_manage", "desktop_manage",
    "cpu_manage",
    # taxonomy refactor adds ten new tools:
    "process_manage", "thread_manage", "module_manage", "object_manage",
    "kernel_manage", "memory_manage", "desktop_manage",
    "token_manage", "net_manage", "svc_manage",
    # pre-Wave-3 taxonomy split: target_manage lost its machine registry
    # (machines_*) and its SI #21 self-protection surface (selfprot_*) to
    # their own dispatchers for discoverability.
    "machines_manage", "selfprot_manage",
    # reconstruct-and-verify slice 1
    "reconstruct_manage",
}


async def test_catalog_matches_live_registry() -> None:
    committed = _catalog.load_catalog()
    live = await _catalog.build_live_catalog()
    if live != committed:
        pytest.fail(
            "tool catalog drifted; run "
            "`uv run python scripts/gen_tool_catalog.py` and commit the result"
        )


def test_catalog_contains_exactly_the_known_tools() -> None:
    catalog = _catalog.load_catalog()
    names = {entry["tool"] for entry in catalog["tools"]}
    assert names == KNOWN_TOOLS


def test_findings_manage_is_absent() -> None:
    """taxonomy brief §7.1 — the deprecated findings_manage
    alias is removed outright. No ``@mcp.tool`` registration, no
    catalog row, no alias row."""
    catalog = _catalog.load_catalog()
    names = {entry["tool"] for entry in catalog["tools"]}
    assert "findings_manage" not in names


def test_internal_dispatcher_names_absent_from_catalog() -> None:
    """the pre-taxonomy internal dispatcher names must not
    appear in the generated catalog. memory_manage / desktop_manage
    are the canonical replacements and should be present."""
    catalog = _catalog.load_catalog()
    names = {entry["tool"] for entry in catalog["tools"]}
    assert "mem_rw" not in names
    assert "screen_manage" not in names
    assert "memory_manage" in names
    assert "desktop_manage" in names
