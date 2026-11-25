"""umagent-only RPCs: input injection.

The session-1 ``umagent`` service already hosts window enumeration and
usermode memory reads behind the common :class:`AgentClient`. This module adds
a third umagent-only surface: :class:`InputMixin` wraps the three
SendInput-backed RPCs (``Input.Click`` / ``Input.Type`` / ``Input.Key``).
A session-0 agent view carries no Input stub; the MCP ``desktop_manage``
dispatcher routes these verbs to the ``name='user'`` view so this mixin
is reached only through the umagent connection.

Returns a plain ``{"ok", "error", "hint"}`` envelope — these RPCs have
no state to echo (the umagent is stateless w.r.t. the input queue; every
call is a one-shot SendInput burst).
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb
from .wire import status_dict


# ---- string → enum mapping tables ----------------------------------------

_BUTTON_ALIASES: dict[str, int] = {
    "left":   0,
    "right":  1,
    "middle": 2,
    "x1":     3,
    "x2":     4,
}

_ACTION_ALIASES: dict[str, int] = {
    "down":  0,
    "up":    1,
    "click": 2,
}


def _coerce_button(v: Any) -> int:
    """Map a string alias to the InputButton enum value.

    Accepts ints untouched so numeric callers keep working."""
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    key = str(v or "left").strip().lower()
    if key not in _BUTTON_ALIASES:
        raise ValueError(
            f"desktop_manage.click: unknown button {v!r} — accepted: "
            f"{sorted(_BUTTON_ALIASES)}")
    return _BUTTON_ALIASES[key]


def _coerce_action(v: Any) -> int:
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    key = str(v or "click").strip().lower()
    if key not in _ACTION_ALIASES:
        raise ValueError(
            f"desktop_manage: unknown action {v!r} — accepted: "
            f"{sorted(_ACTION_ALIASES)}")
    return _ACTION_ALIASES[key]


class InputMixin:
    """umagent SendInput RPCs. Wire the stub as ``self.input`` in
    :meth:`AgentClient.connect` guarded by ``hasattr(pbg, "InputStub")``.
    """

    async def input_click(self, x: int = -1, y: int = -1,
                          button: str = "left", action: str = "click",
                          modifiers: int = 0, click_count: int = 1,
                          force: bool = False) -> dict[str, Any]:
        """Send a mouse click. ``x=-1 y=-1`` operates on the current
        cursor position without moving it. Modifiers is a bitfield:
        1=shift, 2=ctrl, 4=alt, 8=win.

        Raises if the umagent side predates the Input service
        (``self.input is None``); the MCP dispatcher turns the failure
        into a clean envelope through the kit-wide normalization."""
        req_cls = getattr(pb, "InputClickRequest", None)
        if self.input is None or req_cls is None:
            raise RuntimeError(
                "input_click: older umagent — Input service missing; "
                "rebuild and redeploy the umagent")
        req = req_cls(
            x=int(x), y=int(y),
            button=_coerce_button(button),
            action=_coerce_action(action),
            modifiers=int(modifiers or 0),
            click_count=int(click_count or 1) if (click_count or 1) > 0 else 1,
            force=bool(force),
        )
        msg = await self._call(self.input.Click, req)
        return status_dict(msg.status)

    async def input_type(self, text: str, delay_ms: int = 0,
                         force: bool = False) -> dict[str, Any]:
        """Type UTF-8 text. ``delay_ms > 0`` sleeps between characters."""
        req_cls = getattr(pb, "InputTypeRequest", None)
        if self.input is None or req_cls is None:
            raise RuntimeError(
                "input_type: older umagent — Input service missing; "
                "rebuild and redeploy the umagent")
        req = req_cls(
            text=str(text or ""),
            delay_ms=int(delay_ms or 0),
            force=bool(force),
        )
        msg = await self._call(self.input.Type, req)
        return status_dict(msg.status)

    async def input_key(self, key: str, action: str = "click",
                        repeat: int = 1, force: bool = False) -> dict[str, Any]:
        """Send a key chord. ``key`` is a ``"Ctrl+Shift+F5"``-style string;
        ``repeat > 1`` loops the key down+up that many times."""
        req_cls = getattr(pb, "InputKeyRequest", None)
        if self.input is None or req_cls is None:
            raise RuntimeError(
                "input_key: older umagent — Input service missing; "
                "rebuild and redeploy the umagent")
        req = req_cls(
            key=str(key or ""),
            action=_coerce_action(action),
            repeat=int(repeat or 1) if (repeat or 1) > 0 else 1,
            force=bool(force),
        )
        msg = await self._call(self.input.Key, req)
        return status_dict(msg.status)


__all__ = ["InputMixin"]
