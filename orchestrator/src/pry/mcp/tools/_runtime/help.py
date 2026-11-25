"""Discovery / action-help helpers.

These power each tool's ``action='actions'`` verb and the standard
"unknown action X; expected one of ..." error. Pure compute — call
sites hit them before ``require_client()`` so discovery works with
no target connected.

``_actions_help``, ``_unknown_action``, and the ``tool_index``
grouping consult :mod:`._runtime.capabilities` first — when the
registry has a canonical capability for ``(tool, action)``, its
``help`` string is folded into the one-liner so the registry stays the
single source of truth. The legacy ``help_map`` arg survives as a
fallback for actions the registry hasn't absorbed yet.
"""

from __future__ import annotations

import contextvars
import difflib
import json

from ..._envelope import envelope_err as _envelope_err
from .capabilities import (
    all_capabilities as _all_capabilities,
    canonical as _canonical,
    render_help as _render_registry_help,
    resolve_alias as _resolve_alias,
)
from .response import _j

# ``verb=`` for ``action='actions'``: the call middleware strips the
# param before the tool body runs (tool signatures don't declare it) and
# parks it here for :func:`_actions_help`.
ACTIONS_VERB: contextvars.ContextVar[str] = contextvars.ContextVar(
    "pry_actions_verb", default="")


def _one_line_desc(s: str, cap: int = 120) -> str:
    """First sentence of a tool description, hard-capped at ``cap`` chars.

    Used by ``ida_manage(action='tools')`` to strip the multi-paragraph
    docstrings the vanilla ida-pro-mcp tools carry so the discovery
    call stays inexpensive.
    """
    if not s:
        return ""
    # First paragraph, re-joined across hard wraps, then first sentence
    # ("X. Y" or a trailing period). Splitting on the first newline
    # before the sentence split cut wrapped docstrings mid-clause.
    para = s.strip().split("\n\n", 1)[0]
    para = " ".join(part.strip() for part in para.splitlines())
    line = para.split(". ", 1)[0].rstrip()
    if line.endswith(".") and len(line) > 1:
        line = line[:-1]
    if len(line) > cap:
        return line[: max(cap - 3, 1)] + "..."
    return line


def _parse_ida_schemas_filter(args_json: str) -> set[str]:
    """Return the ``tools`` filter set parsed from ``args_json``.

    Accepts ``{"tools": ["decompile_function", ...]}`` OR
    ``{"tools": "decompile_function"}`` (bare string). Malformed
    JSON or a missing key yields an empty set so the caller keeps
    the pre-C2-1a full-dump behaviour.
    """
    if not args_json:
        return set()
    try:
        parsed = json.loads(args_json)
    except (TypeError, ValueError):
        return set()
    if not isinstance(parsed, dict):
        return set()
    raw = parsed.get("tools")
    if isinstance(raw, list):
        return {str(t) for t in raw if t}
    if isinstance(raw, str) and raw:
        return {raw}
    return set()


def _filter_ida_schemas(schemas: list[dict], wanted: set[str]) -> list[dict]:
    """Project the schema rows down to ``{name, description, inputSchema}``,
    filtered by ``wanted`` when non-empty."""
    return [{"name": t.get("name"),
             "description": t.get("description", ""),
             "inputSchema": t.get("inputSchema", {})}
            for t in schemas
            if not wanted or t.get("name") in wanted]


# tool name -> the action enum published in its schema. Filled by
# ``register_action_enum`` from ``build_server`` once every tool is
# registered; ``_merged_help_map`` hides help rows for verbs the schema
# would reject (MOVED forwarders, registry rows with no handler yet).
_ACTION_ENUMS: dict[str, frozenset[str]] = {}


def register_action_enum(tool: str, actions) -> None:
    """Record ``tool``'s public action enum (``None`` clears it - open
    passthrough tools like ida/ghidra have no enum)."""
    if actions is None:
        _ACTION_ENUMS.pop(tool, None)
    else:
        _ACTION_ENUMS[tool] = frozenset(str(a) for a in actions)


def _merged_help_map(tool: str,
                     fallback: dict[str, dict[str, str]] | None,
                     known=None) -> dict[str, dict[str, str]]:
    """Produce the effective action-help map for ``tool``.

    The tool's hand-written ``*_ACTION_HELP`` rows win: they carry the
    worked examples and the real key args. The capability registry only
    fills fields (and verbs) the hand-written table leaves empty - its
    generated examples are bare ``tool(action='x')`` stubs.

    Verbs outside the tool's public action enum (``known`` when given,
    else the enum recorded by :func:`register_action_enum`) are dropped,
    so help never advertises a verb the schema rejects.
    """
    merged: dict[str, dict[str, str]] = {}
    if fallback:
        for verb, spec in fallback.items():
            merged[verb] = dict(spec)
    for verb, spec in _render_registry_help(tool).items():
        existing = merged.setdefault(verb, {})
        for k, v in spec.items():
            if v and not existing.get(k):
                existing[k] = v
    allowed = (frozenset(known) if known is not None
               else _ACTION_ENUMS.get(tool))
    if allowed:
        merged = {verb: spec for verb, spec in merged.items()
                  if verb in allowed or verb == "actions"}
    return merged


def _unknown_action(tool: str, action: str, known: list[str],
                    help_map: dict[str, dict[str, str]] | None = None) -> str:
    """Standardized 'unknown action' error listing valid alternatives.

    ``help_map`` (the tool's ``*_ACTION_HELP`` dict) inlines the
    per-verb one_liners into the error so a mistyped action answers
    "what should I have called?" in one round trip instead of pointing
    at a second discovery call. An empty ``action`` is treated as a
    help request outright — discovery needs no target connected.

    When ``action`` matches a known alias in the capability
    registry, the hint names the canonical replacement so a caller
    using the pre-rename name learns the new one on the first miss.
    """
    merged = _merged_help_map(tool, help_map, known=known)
    if not (action or "").strip():
        return _actions_help(tool, merged or {k: {} for k in known})
    msg = (f"unknown action {action!r} for {tool}; expected one of: "
           + ", ".join(sorted(set(known))))
    env = _envelope_err(msg, tool=tool, action=action)
    alias_hit = _resolve_alias(tool, action)
    if alias_hit is not None and (alias_hit.tool, alias_hit.action) == (tool, action):
        # A registry row for a verb this tool doesn't dispatch is not an
        # alias - don't tell the caller it is "an alias for itself".
        alias_hit = None
    close = difflib.get_close_matches(str(action), list(known), n=3, cutoff=0.6)
    if isinstance(env.get("error"), dict):
        env["error"]["kind"] = "unknown_action"
        if close:
            env["error"]["did_you_mean"] = close
        if alias_hit is not None:
            env["error"]["hint"] = (
                f"{tool}(action={action!r}) is a deprecated alias for "
                f"{alias_hit.tool}(action={alias_hit.action!r}); call the "
                "canonical name directly to drop the deprecation banner. "
                f"target_manage(action='tool_index') lists every tool")
        else:
            env["error"]["hint"] = (
                (f"did you mean {tool}(action={close[0]!r})? " if close else "")
                + f"call {tool}(action='actions') for per-verb help "
                "(add verb='<verb>' for one verb); "
                "target_manage(action='tool_index') lists every tool")
    if merged:
        env["data"] = {
            "actions": {
                verb: str(spec.get("one_liner", ""))
                for verb, spec in sorted(merged.items())
            },
        }
    return _j(env)


def _actions_help(tool: str, help_map: dict[str, dict[str, str]],
                  verb: str | None = None) -> str:
    """Payload for the per-tool ``action='actions'`` verb.

    Returns a legacy-shape dict ``{ok: true, actions: {verb: {one_liner,
    key_args, example}}, count, hint}`` - ``envelope_from_result`` wraps
    it under ``data`` with ``kind='actions'`` on the way out.

    Pure compute: call sites return this before ``require_client()`` so
    discovery works with no target connected. ``help_map`` is the
    per-tool ``*_ACTION_HELP`` dict, gap-filled from the capability
    registry (see :func:`_merged_help_map`).

    ``verb`` narrows the answer to one verb (the ``verb=`` param every
    tool accepts with ``action='actions'``; the call middleware passes
    it through :data:`ACTIONS_VERB`). An unknown verb returns the close
    matches instead of the full table.
    """
    merged = _merged_help_map(tool, help_map)
    want = (verb if verb is not None else ACTIONS_VERB.get()) or ""
    want = str(want).strip()
    hint = (f"call {tool}(action='<verb>', ...); "
            f"{tool}(action='actions', verb='<verb>') shows one verb; "
            "target_manage(action='tool_index') lists every tool")
    if want:
        if want in merged:
            spec = merged[want]
            return _j({
                "ok": True,
                "count": 1,
                "actions": {want: {
                    "one_liner": spec.get("one_liner", ""),
                    "key_args": spec.get("key_args", ""),
                    "example": spec.get("example", ""),
                }},
                "hint": hint,
            })
        close = difflib.get_close_matches(want, list(merged), n=5, cutoff=0.5)
        return _j({
            "ok": False,
            "kind": "unknown_action",
            "error": f"{tool} has no verb {want!r}",
            "did_you_mean": close,
            "hint": (f"{tool}(action='actions') lists all "
                     f"{len(merged)} verbs"),
        })
    return _j({
        "ok": True,
        "count": len(merged),
        "actions": {
            v: {
                "one_liner": spec.get("one_liner", ""),
                "key_args": spec.get("key_args", ""),
                "example": spec.get("example", ""),
            }
            for v, spec in sorted(merged.items())
        },
        "hint": hint,
    })


def _moved_verb(tool: str, action: str, new_tool: str, new_action: str,
                note: str = "", *, emit: bool = False):
    """Standard error envelope for a verb that moved to another tool.

    Same shape as every other error (``kind='error'``, nested
    ``error.kind='moved'``) plus a ready-to-run ``replacement`` so the
    caller can retarget in one step. Retired verbs stay out of the
    action enum and the help; this is what a stale caller gets back.

    Inside a ``_guard``-ed ``run()`` return the plain JSON (the guard
    finalizes it); a tool body that returns without ``_guard`` passes
    ``emit=True`` to get the finished wire result.
    """
    from .envelope import _emit
    msg = (f"{tool}.{action} moved to {new_tool}(action={new_action!r})"
           + (f" - {note}" if note else ""))
    env = _envelope_err(msg, tool=tool, action=action)
    env["error"]["kind"] = "moved"
    env["error"]["hint"] = (f"call {new_tool}(action={new_action!r}, ...) "
                            f"- {new_tool}(action='actions', "
                            f"verb={new_action!r}) shows its args")
    env["replacement"] = {"tool": new_tool, "action": new_action}
    if emit:
        return _emit(env)
    return json.dumps(env)


def _tool_index_domains() -> dict[str, list[dict[str, Any]]]:
    """Return the ``domains`` grouping used by
    ``target_manage(action='tool_index')``. One list of
    ``{tool, action, canonical, mutating, views, spaces, aliases,
    deprecated}`` entries per capability-registry domain.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    for cap in _all_capabilities():
        row = {
            "tool": cap.tool,
            "action": cap.action,
            "canonical": True,
            "mutating": cap.mutating,
            "gate": cap.gate,
            "views": sorted(cap.views),
            "spaces": sorted(cap.spaces),
            "aliases": [list(a) for a in cap.aliases],
            "deprecated": cap.deprecated,
            "one_liner": cap.help,
        }
        out.setdefault(cap.domain, []).append(row)
    for domain, rows in out.items():
        rows.sort(key=lambda r: (r["tool"], r["action"]))
    return out


# Imported late to avoid pulling typing into the top-level header. Keeps
# the symbol usable from `common.py`'s star-import without a circular.
from typing import Any  # noqa: E402


def _err(tool: str, action: str, exc: Exception, ctx) -> str:
    """Legacy error helper — routes to the unified envelope. Kept for
    call sites that build errors outside `_guard` (e.g. mid-body validation
    that returns before `run()` resolves)."""
    return _j(_envelope_err(exc, tool=tool, action=action, ctx=ctx))


__all__ = [
    "ACTIONS_VERB",
    "_moved_verb",
    "register_action_enum",
    "_one_line_desc",
    "_parse_ida_schemas_filter",
    "_filter_ida_schemas",
    "_unknown_action",
    "_actions_help",
    "_merged_help_map",
    "_tool_index_domains",
    "_err",
]
