# MCP client registration snippets

Pry exposes one streamable-HTTP MCP endpoint (default
`http://127.0.0.1:8765/mcp`). Every MCP-capable LLM front-end takes the same
URL — only the wrapper JSON differs. Drop the matching snippet into the
client's config, restart it, and the pry tool surface shows up.

Anything sensitive (bearer tokens, target IPs) stays in the orchestrator's
`configs/*.yaml` — the client only sees `127.0.0.1:8765`. Do not add auth or
target info here.

## Files

| Client               | File                              | Where it goes                                                                 |
|----------------------|-----------------------------------|-------------------------------------------------------------------------------|
| Claude Code (CLI)    | `claude_code.mcp.json`            | Project root as `.mcp.json` (already committed one layer up); or user scope via `claude mcp add` |
| Claude Desktop       | `claude_desktop.config.json`      | `%APPDATA%\Claude\claude_desktop_config.json` (Win) / `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Kilo                 | `kilo.json`                       | Repo root as `.kilo/kilo.json` (already committed)                            |
| Cursor               | `cursor.mcp.json`                 | Repo root as `.cursor/mcp.json`, or global at `~/.cursor/mcp.json`            |
| Devin                | `devin.mcp_config.json`           | Repo root as `.devin/mcp_config.json` (already committed); or `devin mcp add -s project pry http://127.0.0.1:8765/mcp`; user scope at `%APPDATA%\devin\mcp_config.json` (Win) / `~/.config/devin/mcp_config.json` |
| Antigravity          | `antigravity.mcp_config.json`     | Repo root as `.agents/mcp_config.json` & `.agents/skills/` (already committed); user scope at `~/.gemini/config/mcp_config.json` |
| pi.dev               | `pi.mcp.json`                     | Repo root as `.pi/mcp.json` (already committed; pi prompts for project trust on first use); user scope at `~/.pi/agent/mcp.json`; or `pi mcp add -l`. SSE transport is refused — stick to HTTP streamable or stdio. Skill at `.agents/skills/pry/SKILL.md` is auto-discovered. |
| opencode             | `opencode.json`                   | Repo root as `opencode.json` (already committed) — opencode walks cwd → git root and merges with `~/.config/opencode/opencode.json`. Skill at `.agents/skills/pry/SKILL.md` is auto-discovered (opencode natively honors `.agents/skills/`, `.claude/skills/`, `.opencode/skills/`). |

To add a new client:
1. Drop a template file here matching that client's expected schema.
2. Add a row to the table above.
3. If the client auto-discovers a project-scope file (like Kilo or Claude Code),
   commit the top-level file too (`.<client>/config.json` or `.mcp.json`).
