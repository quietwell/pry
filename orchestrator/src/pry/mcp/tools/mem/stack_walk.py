"""SI #9 — kernel-stack walk (``memory_manage action='stack_walk'``).

Thin orchestrator-side wrapper that forwards to the agent's
``StackWalk.Walk`` RPC. The driver verb drives
``RtlWalkFrameChain`` via a kernel-mode APC on the target thread
through the existing ``PryRemoteCall`` machinery. Default timeout
500 ms so a frozen target can't wedge the sequential IOCTL queue
(plan README §6).

See ``an internal plan``
Feature 3 for the kernel pattern.
"""

from __future__ import annotations

from typing import Any

from .._runtime.response import _j


_PRY_STACKWALK_MAX_FRAMES = 128
_PRY_STACKWALK_DEFAULT_TIMEOUT_MS = 500

_FLAG_KERNEL = 0x1
_FLAG_USER = 0x2
_FLAG_BOTH = _FLAG_KERNEL | _FLAG_USER
_FLAG_FORCE_APC = 0x4
_FLAG_TIMEOUT_PARTIAL_OK = 0x8

_MODE_TAGS = {
    "kernel": _FLAG_KERNEL,
    "user": _FLAG_USER,
    "both": _FLAG_BOTH,
}


def _resolve_flags(*, mode: str, force_apc: bool, timeout_partial_ok: bool) -> int:
    key = (mode or "both").lower()
    base = _MODE_TAGS.get(key, _FLAG_BOTH)
    if force_apc:
        base |= _FLAG_FORCE_APC
    if timeout_partial_ok:
        base |= _FLAG_TIMEOUT_PARTIAL_OK
    return base


def _agent_missing() -> dict[str, Any]:
    return {
        "ok": False,
        "kind": "agent_version",
        "error": "stack_walk: this agent is too old (StackWalk service missing)",
        "hint": "rebuild + redeploy agent for the SI #9 kernel-stack walk",
    }


async def handle_stack_walk(ctx, c, *, tid: int, mode: str = "both",
                            max_frames: int = 0, timeout_ms: int = 0,
                            force_apc: bool = False,
                            timeout_partial_ok: bool = True,
                            privilege_cookie: int = 0,
                            name: str = "") -> str:
    """Walk ``tid``'s kernel/user stack via ``RtlWalkFrameChain``.

    ``mode`` is ``'kernel' | 'user' | 'both'`` (default both). Frames
    carry ``module_base`` so the orchestrator can correlate against the
    existing MODULES listing for name resolution.
    """
    if not tid:
        return _j({"ok": False, "error": "stack_walk: tid must be non-zero"})
    if max_frames < 0 or max_frames > _PRY_STACKWALK_MAX_FRAMES:
        return _j({"ok": False,
                   "error": f"stack_walk: max_frames must be 1..{_PRY_STACKWALK_MAX_FRAMES} "
                            f"(or 0 for default); got {max_frames}"})
    if (mode or "both").lower() not in _MODE_TAGS:
        return _j({"ok": False,
                   "error": "stack_walk: mode must be 'kernel'|'user'|'both'",
                   "hint": f"got {mode!r}"})
    if not hasattr(c, "stack_walk"):
        return _j(_agent_missing())
    flags = _resolve_flags(mode=mode, force_apc=force_apc,
                           timeout_partial_ok=timeout_partial_ok)
    _timeout = int(timeout_ms) if timeout_ms > 0 else _PRY_STACKWALK_DEFAULT_TIMEOUT_MS
    _max = int(max_frames) if max_frames > 0 else _PRY_STACKWALK_MAX_FRAMES
    try:
        r = await c.stack_walk(tid=int(tid), flags=int(flags),
                               max_frames=_max, timeout_ms=_timeout,
                               privilege_cookie=int(privilege_cookie))
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "error": str(exc)})
    if not isinstance(r, dict):
        return _j({"ok": False, "error": "stack_walk: empty response"})
    r = dict(r)
    r.setdefault("ok", True)
    r.setdefault("tid", int(tid))
    r.setdefault("mode", (mode or "both").lower())
    r.setdefault("timeout_ms", _timeout)
    r.setdefault("flags", int(flags))
    return _j(r)
