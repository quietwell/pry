"""Every call an agent can copy must match the live schema.

Root cause of the 2026-11 help drift: hand-written help examples, key-arg
lists and guide snippets named params the (``additionalProperties:
false``) schema rejects, and nothing checked them. These tests do:

* each verb in ``<tool>(action='actions')`` is in the tool's action enum;
* each help ``example`` is a call to that tool whose kwargs all exist;
* each ``key_args`` token is a real param;
* each ``<tool>_manage(...)`` call in the guides / docs / prompts names a
  real tool, verb and params.

Call-shaped prose that doesn't parse as Python (``tool(action='x', ...)``
fragments with free text) is skipped, not failed.
"""

from __future__ import annotations

import pytest

import _callsites


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


_SURFACE: _callsites.Surface | None = None


async def _surface() -> _callsites.Surface:
    global _SURFACE
    if _SURFACE is None:
        _SURFACE = await _callsites.load_surface()
    return _SURFACE


async def test_help_verbs_are_dispatchable() -> None:
    s = await _surface()
    bad = []
    for tool, rows in s.help.items():
        enum = s.enums.get(tool)
        if enum is None:
            continue
        for verb in rows:
            if verb not in enum:
                bad.append(f"{tool}.{verb}")
    assert not bad, f"help lists verbs the schema rejects: {bad}"


async def test_every_enum_verb_has_help() -> None:
    s = await _surface()
    missing = []
    for tool, enum in s.enums.items():
        if enum is None:
            continue
        rows = s.help.get(tool) or {}
        missing += [f"{tool}.{v}" for v in sorted(enum) if v not in rows]
    assert not missing, f"verbs with no help row: {missing}"


async def test_help_examples_match_schema() -> None:
    s = await _surface()
    problems: list[str] = []
    for tool, rows in s.help.items():
        for verb, row in rows.items():
            if verb.startswith("<"):
                continue  # '<passthrough>' documents forwarded verbs
            example = str(row.get("example") or "")
            if not example:
                problems.append(f"{tool}.{verb}: no example")
                continue
            calls, _ = _callsites.extract_calls(example, f"{tool}.{verb}")
            if not calls:
                problems.append(f"{tool}.{verb}: example does not parse: "
                                f"{example[:120]}")
                continue
            for call in calls:
                problems += _callsites.check_call(s, call)
            first = calls[0]
            if first.tool != tool:
                problems.append(f"{tool}.{verb}: example calls {first.tool}")
            elif first.action != verb:
                problems.append(f"{tool}.{verb}: example uses action="
                                f"{first.action!r}")
    assert not problems, "\n" + "\n".join(problems)


async def test_help_key_args_are_params() -> None:
    s = await _surface()
    problems: list[str] = []
    for tool, rows in s.help.items():
        props = s.props[tool]
        for verb, row in rows.items():
            for tok in _callsites.key_arg_tokens(str(row.get("key_args") or "")):
                if tok not in props:
                    problems.append(f"{tool}.{verb}: key arg {tok!r} is not "
                                    "a param")
    assert not problems, "\n" + "\n".join(problems)


async def test_doc_callsites_match_schema() -> None:
    s = await _surface()
    problems: list[str] = []
    checked = 0
    for path in _callsites.doc_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(_callsites.REPO).as_posix()
        calls, _skipped = _callsites.extract_calls(
            text, rel, python_source=path.suffix == ".py")
        for call in calls:
            checked += 1
            problems += _callsites.check_call(s, call)
    assert checked > 50, f"only {checked} doc call-sites found — extractor broken?"
    assert not problems, "\n" + "\n".join(problems)


async def test_value_manage_examples_execute() -> None:
    """value_manage is pure compute, so its examples can run for real:
    a schema-valid example can still fail on semantics (width in bits
    instead of bytes, a missing from_type)."""
    import ast

    from pry.mcp.tools import build_server

    s = await _surface()
    server = build_server(_callsites._catalog._minimal_context())
    failures = []
    for verb, row in sorted(s.help["value_manage"].items()):
        node = ast.parse(str(row["example"]), mode="eval").body
        kwargs = {k.arg: ast.literal_eval(k.value) for k in node.keywords}
        res = await server.call_tool("value_manage", kwargs)
        body = res.structured_content
        if not body.get("ok"):
            failures.append(f"{verb}: {row['example']} -> {body.get('error')}")
    assert not failures, "\n" + "\n".join(failures)
