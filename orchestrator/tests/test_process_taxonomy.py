"""process_manage(action='get') taxonomy fix.

The shared `handle_process_list` helper stamps `tool='memory_manage'`
and `action='process_list'` on the envelope. A caller of
`process_manage(get, pid=…)` now sees `tool='process_manage'` and
`kind='process_info'` instead, matching the canonical taxonomy.
"""
from __future__ import annotations

import json as _json
from typing import Any

import pytest

from test_debug_state_loop import (
    _FakeAgentClient,
    _call,
    _connect,
    _server,
)


class _ProcFakeClient(_FakeAgentClient):
    async def mem_processes(self, with_cmdline: bool = False,
                            full: bool = False) -> dict[str, Any]:
        return {"ok": True, "source": "agent",
                "processes": [
                    {"pid": 4812, "image_name": "notepad.exe",
                     "ppid": 100, "session": 1,
                     "protection_level": 0},
                ]}


async def test_process_get_taxonomy_pins_tool_and_kind(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_ProcFakeClient)
    await _connect(server)

    token_result = await server.call_tool(
        "process_manage", {"action": "get", "pid": 4812})
    body = getattr(token_result, "structured_content", None)
    if body is None:
        text = token_result.content[0].text if token_result.content else ""
        body = _json.loads(text) if text else {}
    assert isinstance(body, dict), body
    assert body.get("tool") == "process_manage", body.get("tool")
    assert body.get("kind") == "process_info", body.get("kind")
