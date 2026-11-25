"""desktop_manage click / type / key dispatch.

The MCP branches call `AgentClient.input_{click,type,key}` on a
umagent-connected client. This test proves the dispatcher wires the
verbs and the capture envelope grows the new scale fields.
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


class _DesktopFakeClient(_FakeAgentClient):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.input_calls: list[dict] = []

    async def input_click(self, **kwargs: Any) -> dict[str, Any]:
        self.input_calls.append({"verb": "click", **kwargs})
        return {"ok": True}

    async def input_type(self, **kwargs: Any) -> dict[str, Any]:
        self.input_calls.append({"verb": "type", **kwargs})
        return {"ok": True}

    async def input_key(self, **kwargs: Any) -> dict[str, Any]:
        self.input_calls.append({"verb": "key", **kwargs})
        return {"ok": True}

    # capture_screen: return a 1920x1080 "native" png; orchestrator
    # resize to max_dimension=1024 gives scale_factor ≈ 0.533
    async def capture_screen(self, mode: str = "desktop",
                             **kwargs: Any) -> dict[str, Any]:
        if mode == "displays":
            return {"ok": True, "windows_json": _json.dumps({
                "displays": [{"device_name": "\\\\.\\DISPLAY1",
                              "primary": True}],
            })}
        # 1x1 png placeholder; _scale_and_compress only runs with
        # Pillow present — the test doesn't depend on the resize path
        # to populate native_* / scale_factor.
        png = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
               b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
               b"\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\xc0"
               b"\xc0\x00\x00\x00\x05\x00\x01\x0d\n-\xb4\x00\x00\x00"
               b"\x00IEND\xaeB`\x82")
        return {"ok": True, "image_data": png,
                "width": 1920, "height": 1080,
                "target_type": "desktop", "target_name": ""}

    async def list_windows(self, **kwargs: Any) -> dict[str, Any]:
        return {"ok": True, "windows_json": _json.dumps({"processes": []})}


async def test_desktop_actions_enum_has_input_verbs(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_DesktopFakeClient)
    tools = {t.name: t for t in await server.list_tools()}
    enum = set(tools["desktop_manage"].parameters["properties"]["action"]["enum"])
    for verb in ("click", "type", "key"):
        assert verb in enum, f"desktop_manage missing {verb}"


async def test_desktop_click_round_trips(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_DesktopFakeClient)
    await _connect(server)

    body = await _call(server, "desktop_manage",
                       {"action": "click", "x": 100, "y": 200})
    assert body.get("ok") is not False, body
    client = ctx.session.require_client("")
    assert client.input_calls
    last = client.input_calls[-1]
    assert last["verb"] == "click"
    assert last["x"] == 100 and last["y"] == 200


async def test_desktop_type_requires_text(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_DesktopFakeClient)
    await _connect(server)

    body = await _call(server, "desktop_manage",
                       {"action": "type"})
    # empty text is a bad_arg
    assert body.get("ok") is False, body


async def test_desktop_key_round_trips(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_DesktopFakeClient)
    await _connect(server)

    body = await _call(server, "desktop_manage",
                       {"action": "key", "key": "Ctrl+A"})
    assert body.get("ok") is not False, body
    client = ctx.session.require_client("")
    assert client.input_calls[-1]["verb"] == "key"
    assert client.input_calls[-1]["key"] == "Ctrl+A"


async def test_capture_envelope_has_scale_fields(tmp_path, monkeypatch):
    """The scale fields moved off the lean default — they ride
    on ``include_details=true`` now (see ``docs/DESKTOP_MCP.md`` §9.2
    for the rationale). Assert both: the lean path omits them (so
    envelope stays small), and the opt-in path brings them back."""
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_DesktopFakeClient)
    await _connect(server)

    from pry.caller import CLIENT_ID
    token = CLIENT_ID.set("peer-A")
    try:
        # Lean default — scale fields absent.
        lean = await server.call_tool("desktop_manage",
                                       {"action": "capture",
                                        "mode": "desktop"})
        # Full detail — scale fields present.
        full = await server.call_tool("desktop_manage",
                                       {"action": "capture",
                                        "mode": "desktop",
                                        "include_details": True})
    finally:
        CLIENT_ID.reset(token)

    def _body(result):
        body = getattr(result, "structured_content", None)
        if body is None:
            text = result.content[0].text if result.content else ""
            body = _json.loads(text) if text else {}
        return body

    lean_body = _body(lean)
    full_body = _body(full)
    lean_data = lean_body.get("data") or lean_body
    full_data = full_body.get("data") or full_body

    SCALE = ("native_width", "native_height", "scale_factor")
    HOUSEKEEPING = ("size_bytes", "sha256", "filename", "scaled")

    for field in SCALE + HOUSEKEEPING:
        assert field not in lean_data, (
            f"lean capture leaked {field!r}: {lean_body}")
    for field in SCALE + HOUSEKEEPING:
        assert field in full_data, (
            f"full-detail capture missing {field!r}: {full_body}")
