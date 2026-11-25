"""desktop_manage window-telemetry lean-by-default.

The agent's ``GetWindowInfo`` / ``GetWindowPlacement`` walk ships
every field it can observe; the orchestrator trims each window dict
to a 15-field lean set by default so a multimodal capture envelope
isn't padded with Win32 plumbing the LLM never reads. This test
pokes the pure projection helpers (no gRPC, no agent) and asserts
that the lean path keeps every LLM-useful field and drops every
plumbing field, while ``include_details=True`` is a pass-through.
"""
from __future__ import annotations

from typing import Any

from pry.mcp.tools.screen import (
    _LEAN_WINDOW_FIELDS,
    _lean_window,
    _project_threads,
    _project_windows_procs,
)


# One window with every observable field populated — the shape the
# Smoke run captured on DESKTOP-0QQHNKH for `brave.exe`.
_FULL_WINDOW: dict[str, Any] = {
    # Lean set (must survive projection).
    "hwnd": "0x302a6",
    "pid": 5060,
    "tid": 9240,
    "process_name": "brave.exe",
    "process_path": "C:\\Program Files\\...\\brave.exe",
    "title": "Dashboard — Example - Brave",
    "class_name": "Chrome_WidgetWin_1",
    "rect": {"x": -8, "y": -8, "width": 1936, "height": 1048},
    "client_rect": {"x": 0, "y": 0, "width": 1920, "height": 1032},
    "z_order": 0,
    "visible": True,
    "is_foreground": True,
    "minimized": False,
    "maximized": True,
    "dpi": 96,
    # Plumbing (must drop on the lean path).
    "style": "0x17cf0000",
    "exstyle": "0x20200900",
    "hinstance": "0x0",
    "window_status": 1,
    "window_type_atom": 49562,
    "cloaked": False,
    "border": {"cx": 8, "cy": 8},
    "show_cmd": 3,
    "normal_pos": {"x": 455, "y": 106, "width": 1344, "height": 1007},
    "parent": "0x1000c",
    "owner": "0x0",
    "topmost": False,
    "layered": False,
    "tool_window": False,
    "enabled": True,
    "is_minimized": False,
}

_PLUMBING_FIELDS = frozenset({
    "style", "exstyle", "hinstance",
    "window_status", "window_type_atom", "cloaked",
    "border", "show_cmd", "normal_pos",
    "parent", "owner",
    "topmost", "layered", "tool_window",
    "enabled", "is_minimized",
    # ``process_path`` is also stripped on the lean path.
    # ``process_name`` on the group dict + ``pid`` on the window dict
    # already name the process; the full path (often a 100+ char
    # WindowsApps Appx path) rides on ``include_details=true``.
    "process_path",
})


def test_lean_field_set_is_stable():
    """The lean set contract is public API — breaking it changes the
    shape every multimodal caller plans against. Lock it down."""
    assert tuple(_LEAN_WINDOW_FIELDS) == (
        "hwnd", "pid", "tid",
        "process_name",
        "title", "class_name",
        "rect", "client_rect",
        "z_order",
        "visible", "is_foreground", "minimized", "maximized", "dpi",
    )
    # 14 fields exactly — if this count changes, docs/DESKTOP_MCP.md §9
    # must change too. ``process_path`` is intentionally outside the
    # lean set (WindowsApps Appx paths are 100+ chars and
    # ``process_name`` + ``pid`` already identify the process).
    assert len(_LEAN_WINDOW_FIELDS) == 14
    assert "process_path" not in _LEAN_WINDOW_FIELDS


def test_lean_window_keeps_every_useful_field():
    lean = _lean_window(_FULL_WINDOW)
    for k in _LEAN_WINDOW_FIELDS:
        assert k in lean, f"lean projection dropped {k!r}"
        assert lean[k] == _FULL_WINDOW[k], f"lean {k} mangled: {lean[k]!r}"


def test_lean_window_drops_plumbing():
    lean = _lean_window(_FULL_WINDOW)
    leaked = _PLUMBING_FIELDS & lean.keys()
    assert not leaked, f"plumbing fields leaked into lean projection: {leaked}"


def test_lean_window_omits_absent_keys_rather_than_defaulting():
    """A window dict missing ``dpi`` (older agent builds) stays missing
    in the projection — keeping the "populated-only" shape."""
    w = {k: v for k, v in _FULL_WINDOW.items() if k != "dpi"}
    lean = _lean_window(w)
    assert "dpi" not in lean


def test_project_windows_procs_lean_default():
    procs = [{"pid": 5060, "process_name": "brave.exe",
              "windows": [dict(_FULL_WINDOW)]}]
    out = _project_windows_procs(procs, include_details=False)
    assert len(out) == 1
    assert out[0]["pid"] == 5060
    assert out[0]["process_name"] == "brave.exe"
    [w] = out[0]["windows"]
    assert "style" not in w
    assert "hwnd" in w and w["hwnd"] == "0x302a6"
    # Group dict is a copy — mutating the projection must not reach
    # back into the caller's input.
    out[0]["windows"].append({"canary": True})
    assert len(procs[0]["windows"]) == 1


def test_project_windows_procs_passthrough_when_include_details():
    procs = [{"pid": 5060, "process_name": "brave.exe",
              "windows": [dict(_FULL_WINDOW)]}]
    out = _project_windows_procs(procs, include_details=True)
    assert out is procs  # verbatim reference on the opt-in path
    assert "style" in out[0]["windows"][0]


def test_project_threads_lean_default():
    threads = [{"tid": 9240, "pid": 5060,
                "process_name": "brave.exe",
                "windows": [dict(_FULL_WINDOW)]}]
    out = _project_threads(threads, include_details=False)
    [w] = out[0]["windows"]
    assert "style" not in w
    assert w["tid"] == 9240


def test_project_threads_passthrough_when_include_details():
    threads = [{"tid": 9240, "pid": 5060,
                "process_name": "brave.exe",
                "windows": [dict(_FULL_WINDOW)]}]
    out = _project_threads(threads, include_details=True)
    assert out is threads
    assert "exstyle" in out[0]["windows"][0]


def test_empty_processes_degrades_safely():
    assert _project_windows_procs([], include_details=False) == []
    assert _project_windows_procs(None, include_details=False) == []  # type: ignore[arg-type]
    assert _project_threads([], include_details=False) == []
    assert _project_threads(None, include_details=False) == []  # type: ignore[arg-type]
