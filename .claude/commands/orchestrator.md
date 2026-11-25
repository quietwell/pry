---
description: "Start the pry orchestrator and verify the pry MCP endpoint"
---
The pry orchestrator serves the pry MCP server on http://127.0.0.1:8765/mcp.
If it is not running, the pry MCP toggle in the client fails with a connection error.

Do the following:
1. Run `powershell.exe -ExecutionPolicy Bypass -File scripts\start_orchestrator.ps1` from the repo root
   (it no-ops when the orchestrator is already up; logs to orchestrator\orchestrator-start.log).
   Keep the `.exe`: from a PowerShell host a bare `powershell` can resolve to a stray extension-less
   file and silently do nothing (exit 0, no log line).
2. Verify port 8765 is listening and a streamable-HTTP initialize POST to http://127.0.0.1:8765/mcp returns HTTP 200.
3. Report the result. If healthy, remind me that the project-scope pry server is defined in `.mcp.json`
   and Claude Code will prompt to trust it on the next session start (approve once with `/mcp` if needed).
