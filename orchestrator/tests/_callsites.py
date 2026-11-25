"""Help / doc call-site checker shared by ``test_help_callsites.py``.

The MCP schemas are ``additionalProperties: false``, so a help example or a
guide snippet that names a param the tool doesn't have is a hard failure
for the agent that copies it. This module extracts every
``<tool>_manage(...)`` call from

* each tool's ``action='actions'`` help (``example`` + ``key_args``), and
* the agent guides, docs and prompt templates,

and checks it against the live published schema (action enum + params).
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path

import _catalog

REPO = _catalog.REPO_ROOT

# Files whose call-sites agents copy. The CHANGELOG is deliberately out of
# scope: it describes past surfaces.
DOC_GLOBS = (
    "docs/agents/*.md",
    "docs/*.md",
    "AGENTS.md",
    "GEMINI.md",
    "README.md",
    "orchestrator/src/pry/mcp/prompts/*.py",
)


@dataclass
class Surface:
    props: dict[str, set[str]]           # tool -> published param names
    enums: dict[str, set[str] | None]    # tool -> action enum (None = open)
    help: dict[str, dict[str, dict]]     # tool -> verb -> help row


async def load_surface() -> Surface:
    from pry.mcp.tools import build_server
    server = build_server(_catalog._minimal_context())
    props: dict[str, set[str]] = {}
    enums: dict[str, set[str] | None] = {}
    helps: dict[str, dict[str, dict]] = {}
    for t in await server.list_tools():
        schema = t.parameters or {}
        p = schema.get("properties") or {}
        props[t.name] = set(p)
        enum = (p.get("action") or {}).get("enum")
        enums[t.name] = set(enum) if isinstance(enum, list) else None
        res = await server.call_tool(t.name, {"action": "actions"})
        body = getattr(res, "structured_content", None)
        if not isinstance(body, dict):
            text = res.content[0].text if res.content else "{}"
            body = json.loads(text)
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        helps[t.name] = dict((data or {}).get("actions") or {})
    return Surface(props=props, enums=enums, help=helps)


# ---------------------------------------------------------------------------
# call extraction
# ---------------------------------------------------------------------------

_CALL_START = re.compile(r"\b([a-z]+_manage)\(")


def _balanced(text: str, start: int) -> str | None:
    """``text[start]`` is '('; return the inside up to the matching ')'."""
    depth = 0
    quote = ""
    i = start
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    return None


def _normalize(src: str) -> str:
    src = src.replace("…", "None").replace("...", "None")
    src = re.sub(r"\btrue\b", "True", src)
    src = re.sub(r"\bfalse\b", "False", src)
    src = re.sub(r"\bnull\b", "None", src)
    # Bare placeholders outside quotes: <pid>, <offset of next ptr>.
    out, quote = [], ""
    i = 0
    while i < len(src):
        ch = src[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(src):
                out.append(src[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "<":
            j = src.find(">", i)
            if j == -1:
                out.append(ch)
            else:
                out.append("None")
                i = j
        else:
            out.append(ch)
        i += 1
    return "".join(out)


@dataclass
class Call:
    tool: str
    action: str | None
    kwargs: list[str]
    where: str
    text: str


def extract_calls(text: str, where: str, *, python_source: bool = False
                  ) -> tuple[list[Call], int]:
    """Parseable ``*_manage(...)`` calls in ``text`` + count of skipped
    (prose-shaped) ones. ``python_source``: the text is a .py file whose
    examples sit inside string literals with escaped quotes."""
    calls: list[Call] = []
    skipped = 0
    for m in _CALL_START.finditer(text):
        inner = _balanced(text, m.end() - 1)
        if inner is None:
            skipped += 1
            continue
        # Python sources store examples inside string literals with
        # escaped quotes / implicit concatenation; unescape the common case.
        if python_source:
            inner = inner.replace("\\'", "'").replace('\\"', '"')
        src = _normalize(inner)
        try:
            node = ast.parse(f"f({src})", mode="eval").body
        except SyntaxError:
            skipped += 1
            continue
        if not isinstance(node, ast.Call):
            skipped += 1
            continue
        if node.args and not node.keywords:
            # tool(x) prose / tool() mention, not a call example.
            skipped += 1
            continue
        kw = [k.arg for k in node.keywords if k.arg]
        action = None
        for k in node.keywords:
            if k.arg == "action" and isinstance(k.value, ast.Constant):
                action = str(k.value.value)
        line = text.count("\n", 0, m.start()) + 1
        calls.append(Call(tool=m.group(1), action=action, kwargs=kw,
                          where=f"{where}:{line}",
                          text=f"{m.group(1)}({inner})"[:160]))
    return calls, skipped


def check_call(surface: Surface, call: Call) -> list[str]:
    problems: list[str] = []
    if call.tool not in surface.props:
        return [f"{call.where}: unknown tool {call.tool} in {call.text}"]
    enum = surface.enums.get(call.tool)
    if call.action is not None and enum is not None and call.action not in enum:
        problems.append(f"{call.where}: {call.tool} has no action "
                        f"{call.action!r} in {call.text}")
    props = surface.props[call.tool]
    for k in call.kwargs:
        if k not in props:
            problems.append(f"{call.where}: {call.tool} has no param {k!r} "
                            f"in {call.text}")
    return problems


# ---------------------------------------------------------------------------
# key_args tokens
# ---------------------------------------------------------------------------

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


def key_arg_tokens(key_args: str) -> list[str]:
    s = key_args or ""
    # Drop parentheticals and quoted bits: "tag (4-char or int)", "mode ('a'|'b')".
    for _ in range(3):
        s = re.sub(r"\([^()]*\)", " ", s)
    s = re.sub(r"'[^']*'", " ", s)
    s = re.sub(r"\{[^{}]*\}", " ", s)    # "decode={build_id|source}"
    s = re.sub(r"=[^,|/]*", " ", s)      # "verify_signatures=True"
    tokens: list[str] = []
    for part in re.split(r"[,|/]|\bor\b|\band\b|\+", s):
        part = part.strip().strip(".;:")
        if not part:
            continue
        word = part.split()[0]
        if _IDENT.match(word) and word not in ("none", "all", "any", "etc"):
            tokens.append(word)
    return tokens


def doc_files() -> list[Path]:
    files: list[Path] = []
    for g in DOC_GLOBS:
        files.extend(sorted(REPO.glob(g)))
    return [f for f in files if f.is_file()]
