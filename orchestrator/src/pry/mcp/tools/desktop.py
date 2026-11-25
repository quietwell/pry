"""``desktop_manage`` — canonical desktop / window inspection tool.

Taxonomy brief §5.7. Public surface: ``capture``, ``windows``,
``displays``, ``window_props``, ``window_tree``, ``window_by_thread``,
``actions``.

Verb bodies forward through the internal ``desktop_manage`` dispatcher
(``tools/screen.py``) via the module-level ``_DESKTOP_MANAGE_FN`` handle;
on the way out the response has ``tool`` pinned to ``desktop_manage``.
No deprecation banner stamping — the internal dispatcher is no
longer registered as its own MCP tool.
"""

from __future__ import annotations

import json as _json

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .screen import _DESKTOP_ACTIONS_MASTER


DESKTOP_ACTIONS = list(_DESKTOP_ACTIONS_MASTER)


def _rewrite_response(res, action: str):
    """Pin the response envelope's ``tool`` to ``desktop_manage``.

    The internal dispatcher's help table (``screen.py``) is the single
    source for every verb's help, so nothing is overlaid here."""
    def _rewrite_dict(body: dict) -> dict:
        body["tool"] = "desktop_manage"
        return body

    body = getattr(res, "structured_content", None)
    if isinstance(body, dict):
        _rewrite_dict(body)
        return res
    if isinstance(res, str):
        try:
            parsed = _json.loads(res)
        except (ValueError, TypeError):
            return res
        if isinstance(parsed, dict):
            _rewrite_dict(parsed)
            return _j(parsed)
    return res


def register(mcp, ctx: Context) -> None:
    """Register the ``desktop_manage`` tool on *mcp*.

    Forwards every call into ``desktop_manage``'s closure through the
    shared ``_DESKTOP_MANAGE_FN`` handle.
    """

    # click / type / key are actuator-trust gated mutators.
    # READONLY_TRUE still describes the majority of the surface
    # (capture/windows/displays/window_*); the per-action guard in
    # the dispatcher is what actually blocks a trust-undercut call,
    # not this annotation.
    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def desktop_manage(
        action: Annotated[str, Field(json_schema_extra={"enum": DESKTOP_ACTIONS})],
        mode: str = "desktop",
        display_id: str = "",
        hwnd: str = "",
        pid: int = 0,
        tid: int = 0,
        window_title: str = "",
        process_name: str = "",
        query: str = "",
        max_dimension: int = 1920,
        include_hidden: bool = False,
        # default flipped to False; see screen.py's dispatcher
        # for the lean-window projection the capture/windows/window_by_thread
        # envelopes apply when this is off.
        include_details: bool = False,
        include_children: bool = False,
        include_props: bool = False,
        # window_tree depth cap / window_props value decoding.
        max_depth: int = 12,
        include_values: bool = True,
        embed: bool = False,
        # SendInput injection kwargs.
        x: int = -1,
        y: int = -1,
        text: str = "",
        button: str = "left",
        modifiers: int = 0,
        click_count: int = 1,
        delay_ms: int = 0,
        key: str = "",
        repeat: int = 1,
        force: bool = False,
        name: str = "",
    ) -> str:
        """Desktop/window inspection: capture screenshots (desktop via
        DXGI, window via WGC), enumerate windows grouped by process
        with full metadata, inspect display topology. Session-0 service
        can't see the user desktop so everything funnels through the
        session-1 worker on the target; window_props / window_tree /
        window_by_thread walk window properties and hierarchy, and
        click / type / key inject input (actuator-trust gated). Per-verb
        help: desktop_manage(action='actions', verb='<verb>')."""

        from .screen import _DESKTOP_MANAGE_FN
        if _DESKTOP_MANAGE_FN is None:
            return _j({"ok": False, "kind": "internal_error",
                       "error": "desktop_manage: desktop_manage dispatcher "
                                "not yet registered",
                       "hint": "ensure tools._screen.register() ran before "
                               "desktop.register()"})
        res = await _DESKTOP_MANAGE_FN(
            action=action, mode=mode, display_id=display_id, hwnd=hwnd,
            pid=pid, tid=tid, window_title=window_title,
            process_name=process_name,
            query=query, max_dimension=max_dimension,
            include_hidden=include_hidden, include_details=include_details,
            embed=embed, name=name,
            include_children=bool(include_children),
            include_props=bool(include_props),
            max_depth=int(max_depth or 12),
            include_values=bool(include_values),
            # SendInput injection kwargs.
            x=int(x), y=int(y),
            text=str(text or ""),
            button=str(button or "left"),
            modifiers=int(modifiers or 0),
            click_count=int(click_count or 1),
            delay_ms=int(delay_ms or 0),
            key=str(key or ""),
            repeat=int(repeat or 1),
            force=bool(force),
        )
        return _rewrite_response(res, action)
