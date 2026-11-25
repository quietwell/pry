"""The four agent ``SKILL.md`` copies must stay generated from the single
source ``docs/agents/pry-skill.md``.

Runs ``scripts/gen_agent_skills.py --check`` in-process: if any committed
copy differs from what the generator would write, this fails and names the
stale file. Regenerate with::

    uv run python scripts/gen_agent_skills.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import gen_agent_skills  # noqa: E402 — path bootstrap must run first


def test_generated_copies_match_source() -> None:
    problems = gen_agent_skills.check()
    assert not problems, (
        "agent SKILL.md copies drifted from docs/agents/pry-skill.md; "
        "run `uv run python scripts/gen_agent_skills.py`:\n  "
        + "\n  ".join(problems)
    )


def test_render_is_idempotent_and_prefixed() -> None:
    source = gen_agent_skills._load_source()
    for platform in gen_agent_skills.PLATFORMS:
        rendered = gen_agent_skills.render(platform, source)
        # placeholders are fully substituted
        assert "{{tool_prefix}}" not in rendered
        assert "{{description}}" not in rendered
        # the generated-from banner sits right after the frontmatter
        assert gen_agent_skills.GENERATED_COMMENT in rendered
        head = rendered.split(gen_agent_skills.GENERATED_COMMENT, 1)[0]
        assert head.count("---") >= 2, "frontmatter fences missing"
        # the platform prefix reached the permission rule in prose
        assert f"{platform.tool_prefix}*: ask" in rendered


def test_all_four_platforms_present() -> None:
    keys = {p.key for p in gen_agent_skills.PLATFORMS}
    assert keys == {"claude", "agents", "devin", "kilo"}
