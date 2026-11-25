"""SI #6 — handle ops (``handle_dup`` / ``handle_close`` / ``handle_compare``).

Thin orchestrator-side wrappers that forward to the agent's ``HandleOps``
service. The driver IOCTLs
(``PRY_IOCTL_HANDLE_DUP`` / ``_CLOSE_REMOTE`` / ``_COMPARE``) use
documented ``Ob*`` APIs under ``KernelMode`` ``PreviousMode``, so no
``dyn-data`` dependency.

Each verb degrades cleanly when the agent predates the service — older
agents (no ``HandleOps`` stub) get a well-shaped ``agent_version``
envelope so the orchestrator can surface the gap without raising.

See ``an internal plan``
Feature 2 for the kernel pattern.
"""

from __future__ import annotations

from typing import Any

from .._runtime.response import _j


def _agent_missing(action: str) -> dict[str, Any]:
    return {
        "ok": False,
        "kind": "agent_version",
        "error": f"handle_{action}: this agent lacks handle ops (HandleOps service missing)",
        "hint": "rebuild + redeploy agent for the SI #6 handle_ops surface",
    }


async def handle_handle_dup(ctx, c, *, src_pid: int, src_handle: int,
                            desired_access: int, options: int,
                            privilege_cookie: int,
                            name: str = "") -> str:
    """Duplicate a handle from ``src_pid`` into the CALLER's handle table.

    Options is a bitmask of ``PRY_HANDLE_DUP_FLAG_*``; the common
    cases are ``SAME_ACCESS=0x1`` (mirror source rights) and
    ``NO_INHERIT=0x2`` (strip ``OBJ_INHERIT``).
    """
    if not src_pid or not src_handle:
        return _j({"ok": False,
                   "error": "handle_dup: src_pid and src_handle must both be non-zero"})
    if not hasattr(c, "handle_dup"):
        return _j(_agent_missing("dup"))
    try:
        r = await c.handle_dup(src_pid=int(src_pid),
                               src_handle=int(src_handle),
                               desired_access=int(desired_access),
                               options=int(options),
                               privilege_cookie=int(privilege_cookie))
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "error": str(exc)})
    r = dict(r) if isinstance(r, dict) else {"ok": False, "error": "handle_dup: empty response"}
    r.setdefault("ok", True)
    r.setdefault("src_pid", int(src_pid))
    r.setdefault("src_handle", int(src_handle))
    return _j(r)


async def handle_handle_close(ctx, c, *, target_pid: int, target_handle: int,
                              privilege_cookie: int,
                              name: str = "") -> str:
    """Close a handle in ``target_pid`` via ``KeStackAttachProcess`` +
    ``ObCloseHandle``. ``PrivilegeCookie`` is opaque to this verb — the
    orchestrator presents the SI #24 session token when sensitive
    (PID 4 / System) targets need it; the driver gates the call.
    """
    if not target_pid or not target_handle:
        return _j({"ok": False,
                   "error": "handle_close: target_pid and target_handle must both be non-zero"})
    if not hasattr(c, "handle_close_remote"):
        return _j(_agent_missing("close"))
    try:
        r = await c.handle_close_remote(target_pid=int(target_pid),
                                        target_handle=int(target_handle),
                                        privilege_cookie=int(privilege_cookie))
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "error": str(exc)})
    r = dict(r) if isinstance(r, dict) else {"ok": False, "error": "handle_close: empty response"}
    r.setdefault("ok", True)
    r.setdefault("target_pid", int(target_pid))
    r.setdefault("target_handle", int(target_handle))
    return _j(r)


async def handle_handle_compare(ctx, c, *, pid_a: int, handle_a: int,
                                pid_b: int, handle_b: int,
                                privilege_cookie: int,
                                name: str = "") -> str:
    """Compare the kernel object pointer behind ``(pid_a, handle_a)`` to
    the one behind ``(pid_b, handle_b)``. ``same=true`` means the handles
    refer to the same object (pointer identity after ``ObReference``).
    """
    if not (pid_a and handle_a and pid_b and handle_b):
        return _j({"ok": False,
                   "error": "handle_compare: all four (pid_a, handle_a, pid_b, handle_b) must be non-zero"})
    if not hasattr(c, "handle_compare"):
        return _j(_agent_missing("compare"))
    try:
        r = await c.handle_compare(pid_a=int(pid_a), handle_a=int(handle_a),
                                   pid_b=int(pid_b), handle_b=int(handle_b),
                                   privilege_cookie=int(privilege_cookie))
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "error": str(exc)})
    r = dict(r) if isinstance(r, dict) else {"ok": False, "error": "handle_compare: empty response"}
    r.setdefault("ok", True)
    r.setdefault("pid_a", int(pid_a))
    r.setdefault("handle_a", int(handle_a))
    r.setdefault("pid_b", int(pid_b))
    r.setdefault("handle_b", int(handle_b))
    return _j(r)
