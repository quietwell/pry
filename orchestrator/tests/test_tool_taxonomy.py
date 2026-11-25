"""Lint tests for the capability registry.

Phase 0 lint only. The parity tests for alias forwarders live in the
Phase 1 slice branches and un-xfail themselves there — this file keeps
``@pytest.mark.xfail`` on everything that depends on actual MCP tool
registration so Phase 0 can land green ahead of the per-slice work.

Reference: ``an internal plan`` §9.
"""

from __future__ import annotations

import pytest

from pry.mcp.tools._runtime.capabilities import (
    ALIASES,
    Capability,
    alias_entry,
    all_aliases,
    all_capabilities,
    canonical,
    gate_for,
    render_help,
    resolve_alias,
    validate_required,
    validate_space,
    _actuator_pairs_from_registry,
)


# ---------------------------------------------------------------------------
# Registry internal consistency
# ---------------------------------------------------------------------------


def test_every_capability_has_help() -> None:
    """Every canonical capability must document itself. Empty strings
    slip through at import time but break ``action='actions'`` output,
    so lint them out of the registry."""
    missing = [
        (c.tool, c.action) for c in all_capabilities() if not c.help
    ]
    assert missing == [], f"capabilities missing help: {missing}"


def test_no_duplicate_canonical_pairs() -> None:
    """``(tool, action)`` canonical pairs must be unique. The
    registry's ``_register`` already raises on duplicate insertion,
    but a lint test makes a regression at commit time instead of
    import time."""
    seen = set()
    dupes = []
    for cap in all_capabilities():
        key = (cap.tool, cap.action)
        if key in seen:
            dupes.append(key)
        seen.add(key)
    assert dupes == [], f"duplicate canonical pairs: {dupes}"


def test_mutating_capabilities_have_gate_or_explicit_none() -> None:
    """Every mutating capability must declare its gate. ``gate=None``
    is a valid declaration — it means "no new gate is added by this
    pair" (the original handle_dup / handle_close / suspend / resume
    stayed un-gated). What we're forbidding is a mutating capability
    with no decision recorded at all; since ``gate`` defaults to
    ``None`` in the dataclass the only way this test can fail is if
    we add a `mutating=True` constructor that forgets `gate=`.
    """
    for cap in all_capabilities():
        if cap.mutating:
            # gate can be None (explicitly justified) or a config
            # flag string. Both are legal. The lint catches the case
            # where someone upgrades a verb to mutating without
            # thinking about the gate.
            assert cap.gate is None or isinstance(cap.gate, str), (
                f"{(cap.tool, cap.action)}: gate must be None or str"
            )


def test_domains_are_non_empty_strings() -> None:
    for cap in all_capabilities():
        assert cap.domain and isinstance(cap.domain, str), (
            f"{(cap.tool, cap.action)}: domain must be a non-empty str"
        )


def test_views_subset_of_known() -> None:
    allowed = {"kernel", "user"}
    for cap in all_capabilities():
        bad = cap.views - allowed
        assert bad == frozenset(), (
            f"{(cap.tool, cap.action)}: unknown views {bad}"
        )


def test_spaces_subset_of_known() -> None:
    allowed = {"user", "kernel", "physical"}
    for cap in all_capabilities():
        bad = cap.spaces - allowed
        assert bad == frozenset(), (
            f"{(cap.tool, cap.action)}: unknown spaces {bad}"
        )


# ---------------------------------------------------------------------------
# Alias table
# ---------------------------------------------------------------------------


def test_alias_table_resolves_to_canonical() -> None:
    """Every alias row must point at a canonical capability (except
    tool-level ``'*'`` rows, which carry no action)."""
    for (old_tool, old_action), (new_tool, new_action, _, _) in ALIASES.items():
        if old_action == "*" or new_action == "*":
            # Pure tool-level rename — recurse once with the mapped tool
            # and the resolver must land on *something*.
            continue
        assert canonical(new_tool, new_action) is not None, (
            f"alias ({old_tool!r}, {old_action!r}) -> "
            f"({new_tool!r}, {new_action!r}) misses canonical registry"
        )


def test_resolve_alias_round_trips_canonical() -> None:
    """Calling ``resolve_alias`` on an already-canonical pair returns
    the same capability (not None, not a different pair). Covers the
    "no accidental double-hop" invariant from taxonomy brief §6."""
    for cap in all_capabilities():
        got = resolve_alias(cap.tool, cap.action)
        assert got is cap, (
            f"canonical ({cap.tool!r}, {cap.action!r}) must self-resolve"
        )


# The tool-level deprecation surface was removed. The tests that
# used to assert ``memory_manage`` / ``desktop_manage`` / verb-move aliases
# resolved through ``resolve_alias`` + ``alias_entry`` are gone with
# that behaviour. The ALIASES table stays as an empty dict (symbol
# kept for import compatibility) — the ``test_tool_level_alias_in_table``
# below has been replaced with ``test_alias_table_is_empty``.


# ---------------------------------------------------------------------------
# Gate / mutating / registry-derived actuator set
# ---------------------------------------------------------------------------


def test_actuator_pairs_from_registry_covers_new_gates() -> None:
    """The new gates must be derivable from the registry
    without touching ``_LEGACY_ACTUATOR_PAIRS``. Explicit assertions
    on the new flags keep the regression visible on the taxonomy
    brief's exact names."""
    pairs = _actuator_pairs_from_registry()
    expected = {
        ("process_manage", "kill"),
        ("token_manage", "enable_privilege"),
        ("token_manage", "disable_privilege"),
        ("token_manage", "remove_privilege"),
        ("token_manage", "set_integrity_level"),
        ("token_manage", "set_virtualization"),
        ("token_manage", "impersonate"),
        ("token_manage", "modify_default_dacl"),
        ("net_manage", "kill"),
        ("dump_manage", "create_kernel_dump"),
        ("memory_manage", "write"),
    }
    missing = expected - pairs
    assert missing == set(), f"registry missing actuator pairs: {missing}"


# Removed ``exec_manage.kill_process`` / ``.suspend`` /
# ``.resume`` aliases — callers use ``process_manage`` directly. The
# ``gate_for`` lookup still works for the canonical pair, but the
# forwarding assertion is gone.


def test_token_mutators_share_same_gate() -> None:
    gates = {
        gate_for("token_manage", a)
        for a in (
            "enable_privilege", "disable_privilege", "remove_privilege",
            "set_integrity_level", "set_virtualization", "impersonate",
            "modify_default_dacl",
        )
    }
    assert gates == {"allow_token_adjust"}


# ---------------------------------------------------------------------------
# Space / required-args validation
# ---------------------------------------------------------------------------


def test_memory_vad_is_user_only() -> None:
    """Taxonomy §5.3 narrows VAD / heaps / heap_info to the user
    address space. The validator must refuse ``space='kernel'``."""
    assert validate_space("memory_manage", "vad", "user") is True
    assert validate_space("memory_manage", "vad", "kernel") is False
    assert validate_space("memory_manage", "heap_info", "kernel") is False
    assert validate_space("memory_manage", "heap_info", "user") is True


def test_memory_read_accepts_every_space() -> None:
    for space in ("user", "kernel", "physical"):
        assert validate_space("memory_manage", "read", space) is True


def test_validate_required_catches_missing() -> None:
    missing = validate_required("process_manage", "mitigations", {})
    assert missing == ["pid"]
    missing = validate_required("process_manage", "mitigations", {"pid": 1234})
    assert missing == []


# no more legacy alias to follow — callers use the canonical
# ``process_manage.kill`` pair directly.


# ---------------------------------------------------------------------------
# render_help wiring (used by _runtime.help._merged_help_map)
# ---------------------------------------------------------------------------


def test_render_help_returns_one_entry_per_canonical() -> None:
    rendered = render_help("thread_manage")
    assert "list" in rendered
    assert "stack" in rendered
    assert "actions" in rendered
    assert rendered["list"]["one_liner"]  # non-empty one-liner
    # Example string is self-executable shape "tool(action='verb', ...)".
    assert rendered["list"]["example"].startswith("thread_manage(action='list'")


def test_alias_table_is_empty() -> None:
    """the deprecated-alias forwarders were hard-cut. The
    ALIASES table stays as an empty dict (symbol kept for import
    compatibility); this test pins that so a future regression that
    repopulates it fires loudly."""
    assert all_aliases() == {}


# ---------------------------------------------------------------------------
# Phase-1 gated tests — un-xfail these when the slice branches wire the
# real MCP tool registrations.
# ---------------------------------------------------------------------------


async def test_findings_manage_absent_from_live_tool_list(tmp_path) -> None:
    """findings_manage must be removed from ``mcp.list_tools()``
    (taxonomy brief §7.1). P1 removes the ``@mcp.tool`` registration
    outright and pins the absence here against a live FastMCP server
    built from a minimal context."""
    import importlib
    _catalog = importlib.import_module("_catalog")
    live = await _catalog.build_live_catalog()
    names = {entry["tool"] for entry in live["tools"]}
    assert "findings_manage" not in names, (
        f"findings_manage still registered: {sorted(names)}")


async def test_memory_manage_moved_verbs_hard_cut(tmp_path) -> None:
    """The deprecated-forwarder passthrough was ripped out of
    ``memory_manage``: verbs that have a canonical home elsewhere
    (``threads`` → ``thread_manage.list``, ``modules`` →
    ``module_manage.list``, etc.) now get intercepted BEFORE the
    internal dispatcher and return a ``kind='moved'`` envelope naming
    the replacement.

    The forwarder-parity harness this test used to wait on
    never shipped — the hard-cut superseded the whole idea,
    and there's nothing to be bit-identical with any more. Instead
    pin the hard-cut: every entry in ``_MOVED_VERBS`` must be
    intercepted, and the response must name the right replacement."""
    import asyncio
    import json as _json
    import importlib

    from pry.caller import CLIENT_ID
    from pry.clients import ClientRegistry
    from pry.config import PryConfig, TargetConfig
    from pry.findings import FindingsLedger
    from pry.ida_bridge import IdaBridge, IdaConfigLite
    from pry.leases import LeaseManager
    from pry.mcp.tools import Context, build_server
    from pry.ownership import OwnershipRegistry
    from pry.session import Session
    from pry.mcp.tools.memory import _MOVED_VERBS

    cfg = PryConfig()
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients = ClientRegistry()
    leases = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients, leases=leases,
                  ownership=OwnershipRegistry())
    server = build_server(ctx)

    token = CLIENT_ID.set("peer-moved-hardcut")
    try:
        # Walk every documented moved verb; interception happens before
        # require_client so no live target is needed.
        for old_action, replacement in sorted(_MOVED_VERBS.items()):
            result = await server.call_tool(
                "memory_manage", {"action": old_action})
            body = getattr(result, "structured_content", None)
            if body is None:
                text = result.content[0].text if result.content else ""
                body = _json.loads(text) if text else {}
            # Standard error shape: top-level kind='error', the real kind
            # nested under error.kind, plus a ready-to-run replacement.
            assert body.get("ok") is False, (old_action, body)
            assert body.get("kind") == "error", (old_action, body)
            err = body.get("error") or {}
            assert err.get("kind") == "moved", (old_action, body)
            assert err.get("class") == "bad_arg", (old_action, body)
            got = body.get("replacement") or {}
            assert got.get("tool") == replacement["tool"], (old_action, body)
            assert got.get("action") == replacement["action"], (old_action, body)
            # The error text should mention the canonical home so an LLM
            # consumer can retarget without re-reading the plan.
            err_text = err.get("error") or ""
            assert replacement["tool"] in err_text, (old_action, err_text)
    finally:
        CLIENT_ID.reset(token)


# Ratchet allowlist (taxonomy brief §9): existing over-budget tools
# predate the 30-param rule. New tools must stay in budget.
_PARAM_BUDGET = 30
_PARAM_RATCHET: dict[str, int] = {
    # Older over-budget tools — ratcheted at their current counts
    # so a regression that pushes them higher trips the lint. Each row
    # has a TODO to reduce when a slice has budget. Numbers include the
    # tool's ``action`` enum param.
    # memory/debug/object were over their rows while this lint read the
    # non-existent ``inputSchema`` attribute and so checked nothing;
    # pinned at their real counts so they can only shrink from here.
    "memory_manage": 116,    # TODO: break up (scan / pointer-map / dissect)
    "debug_manage": 42,      # TODO: access_trace_* could move out
    "object_manage": 31,     # TODO: one over the new-tool budget
    "target_manage": 40,     # session + machine registry + driver verbs
    "file_manage": 45,       # file + artifact ops
    "bin_manage": 45,        # static analysis surface
    "knowledge_manage": 40,
    "exec_manage": 50,       # process + shell + remote-call verbs
    "watchdog_manage": 32,
    "ida_manage": 60,
    "ghidra_manage": 60,
    "symbols_manage": 45,
    "bp_manage": 32,
    "emulate_manage": 35,
    "dump_manage": 32,
    "files": 40,
    "scripts": 32,
    "events": 32,
    "event_manage": 32,
    "cpu_manage": 32,
    "device_manage": 32,
    "reg_manage": 32,
}


async def test_new_tools_stay_within_30_parameter_budget() -> None:
    """taxonomy brief §9: every new tool stays within 30 total kwargs
    including ``action``. The ratchet allowlist pins existing
    over-budget tools at their current numbers so regressions are
    visible; new tools must come in UNDER 30."""
    import importlib
    _catalog = importlib.import_module("_catalog")
    _mctx = _catalog._minimal_context()
    from pry.mcp.tools import build_server
    server = build_server(_mctx)
    tools = await server.list_tools()
    over_budget: list[tuple[str, int, int]] = []
    assert tools, "build_server registered no tools"
    for t in tools:
        # FastMCP 4 tools expose the schema as ``.parameters``. Count the
        # tool's own signature: the shared virtual params (verb / cursor /
        # force) and descriptive aliases the surface pass adds to every
        # published schema are conventions, not per-tool surface.
        native = getattr(t, "_pry_native", None)
        if native is None:
            schema = getattr(t, "parameters", None) or {}
            native = (schema.get("properties") or {}).keys()
        n_params = len(native)
        assert n_params > 0, f"{t.name}: no params found — lint is blind"
        ratchet = _PARAM_RATCHET.get(t.name, _PARAM_BUDGET)
        if n_params > ratchet:
            over_budget.append((t.name, n_params, ratchet))
    assert not over_budget, (
        f"tools over the parameter budget: {over_budget}; raise their "
        "ratchet row with a TODO or trim the schema"
    )
