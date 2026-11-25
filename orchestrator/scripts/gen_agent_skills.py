#!/usr/bin/env python
"""Generate the four agent-facing ``SKILL.md`` copies from one source.

The canonical guide lives in ``docs/agents/pry-skill.md``. Each
platform copy differs only by:

- the YAML frontmatter ``description`` wording, and
- the tool-name prefix used when prose names a tool
  (``mcp__pry__`` for Claude Code / ``.agents`` / ``.devin``,
  ``pry_`` for Kilo). The source uses a ``{{tool_prefix}}``
  placeholder only where a prefixed name is actually needed; call
  examples stay as bare ``memory_manage(...)``.

Usage (from ``orchestrator/``)::

    uv run python scripts/gen_agent_skills.py            # write the copies
    uv run python scripts/gen_agent_skills.py --check     # exit 1 on drift

``--check`` is what ``tests/test_agent_skills_generated.py`` runs
in-process, so regeneration must be byte-idempotent.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
ORCHESTRATOR_DIR = SCRIPTS_DIR.parent
REPO_ROOT = ORCHESTRATOR_DIR.parent

SOURCE_PATH = REPO_ROOT / "docs" / "agents" / "pry-skill.md"

GENERATED_COMMENT = (
    "<!-- Generated from docs/agents/pry-skill.md by "
    "scripts/gen_agent_skills.py. Do not edit directly; edit the source "
    "and re-run the generator. -->"
)

_DESCRIPTION = (
    "Driving the pry authorized-lab security-assessment stack over its "
    "MCP tools ({prefix}*) — connecting kernel/usermode target views, "
    "memory/debug/plugin operations, parity runs, and the safety "
    "constraints. Use whenever a task involves pry MCP tools, kernel or "
    "usermode memory inspection of the lab machine, driver/module recon, or "
    "lab findings."
)


@dataclass(frozen=True)
class Platform:
    """One generated copy: where it lives and how it names tools."""

    key: str
    rel_path: str
    tool_prefix: str

    @property
    def path(self) -> Path:
        return REPO_ROOT / self.rel_path

    @property
    def description(self) -> str:
        return _DESCRIPTION.format(prefix=self.tool_prefix)


PLATFORMS: tuple[Platform, ...] = (
    Platform("claude", ".claude/skills/pry/SKILL.md", "mcp__pry__"),
    Platform("agents", ".agents/skills/pry/SKILL.md", "mcp__pry__"),
    Platform("devin", ".devin/skills/pry/SKILL.md", "mcp__pry__"),
    Platform("kilo", ".kilo/skills/pry/SKILL.md", "pry_"),
)


def _split_frontmatter(text: str) -> tuple[str, str]:
    """Return (frontmatter-block-with-fences, body) for the source doc.

    The frontmatter is the region between the first two lines that are
    exactly ``---``. The returned frontmatter keeps both fences; the body
    is everything after the closing fence.
    """
    lines = text.splitlines(keepends=True)
    fences = [i for i, line in enumerate(lines) if line.strip() == "---"]
    if len(fences) < 2:
        raise ValueError(
            f"{SOURCE_PATH} has no '---' YAML frontmatter block")
    end = fences[1]
    return "".join(lines[: end + 1]), "".join(lines[end + 1 :])


def render(platform: Platform, source_text: str) -> str:
    """The full SKILL.md content for one platform."""
    frontmatter, body = _split_frontmatter(source_text)
    frontmatter = frontmatter.replace("{{description}}", platform.description)
    body = body.replace("{{tool_prefix}}", platform.tool_prefix)
    # Body always starts with a blank line after the frontmatter fence;
    # drop it so the generated comment sits directly under the frontmatter.
    body = body.lstrip("\n")
    return f"{frontmatter}{GENERATED_COMMENT}\n\n{body}"


def _load_source() -> str:
    return SOURCE_PATH.read_text(encoding="utf-8")


def check() -> list[str]:
    """Return a list of human-readable drift messages (empty == clean)."""
    source_text = _load_source()
    problems: list[str] = []
    for platform in PLATFORMS:
        expected = render(platform, source_text)
        if not platform.path.exists():
            problems.append(f"{platform.rel_path}: missing")
            continue
        actual = platform.path.read_text(encoding="utf-8")
        if actual != expected:
            problems.append(f"{platform.rel_path}: out of date")
    return problems


def write() -> list[str]:
    """Write every copy; return the relative paths actually changed."""
    source_text = _load_source()
    changed: list[str] = []
    for platform in PLATFORMS:
        expected = render(platform, source_text)
        current = (
            platform.path.read_text(encoding="utf-8")
            if platform.path.exists()
            else None
        )
        if current == expected:
            continue
        platform.path.parent.mkdir(parents=True, exist_ok=True)
        platform.path.write_text(expected, encoding="utf-8")
        changed.append(platform.rel_path)
    return changed


def main(argv: list[str]) -> int:
    if "--check" in argv:
        problems = check()
        if problems:
            print("agent SKILL.md copies are out of date; run "
                  "`uv run python scripts/gen_agent_skills.py`:")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        print(f"ok: {len(PLATFORMS)} agent SKILL.md copies match the source")
        return 0
    changed = write()
    if changed:
        print(f"wrote {len(changed)} of {len(PLATFORMS)} copies:")
        for rel in changed:
            print(f"  - {rel}")
    else:
        print(f"ok: all {len(PLATFORMS)} copies already current")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
