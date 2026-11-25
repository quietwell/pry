"""``thread_manage`` — canonical thread-inventory tool.

Taxonomy brief §5.2: ``list``, ``get``, ``stack`` and ``actions``, plus
one verb per ThreadInspect RPC (slice 03 Feature 4): ``wait`` / ``irp``
(driver-backed, kernel view) and ``impersonation`` / ``com`` / ``rpc`` /
``power`` / ``fiber`` (Win32 calls the usermode agent makes, user view).
The same RPCs feed the eight opt-in column kwargs on ``list``
(``include_last_syscall`` / ``include_kernel_stack_usage`` /
``include_pending_irp`` / ``include_impersonation`` /
``include_com_apartment`` / ``include_rpc_usage`` /
``include_power_throttling`` / ``include_fiber``).

``wait`` and ``irp`` answer ``kind='wave_3_pending'`` today: the agent's
WaitInfo / IrpList handlers are placeholders until the driver's dynamic
offsets ship — the same degrade the ``last_syscall`` / ``kernel_stack`` /
``pending_irp`` columns show on ``list``. The other five return real data
on the user view and ``kind='not_supported'`` (hint: ``name='<m>.user'``)
on the kernel view.

Design decision on the opt-in surface (recorded here for the 20-verb /
30-param budget audit): eight individual boolean kwargs instead of a
single ``includes={...}`` dict. The individual-kwarg shape keeps the
schema LLM-discoverable (every include lands in the tool signature so
``action='actions'`` / completion suggests them), stays bit-identical
to how the existing driver-free column kwargs (``with_cmdline`` /
``with_context``) read on ``process_manage(action='list')``, and only
nudges the parameter count to 23 total — comfortably inside the 30-param
budget (``memory_manage`` is the ratchet-allowlist example today). A later
packet can collapse to ``includes={...}`` without a rename if the surface
grows.

Handlers moved from ``mem/threads.py`` and ``mem/stack_walk.py``. The
legacy ``memory_manage`` dispatcher attaches the deprecated banner via
``_stamp_deprecated``.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .mem import stack_walk as _mem_stack_walk
from .mem import threads as _mem_threads


THREAD_ACTIONS = [
    "list", "get", "stack",
    "wait", "irp", "impersonation", "com", "rpc", "power", "fiber",
    "actions",
]


_THREAD_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "thread_manage(action='actions')"},
    "list": {"one_liner": "system-wide thread inventory (NtQSI); "
                          "eight include_* opt-in kwargs add the "
                          "per-thread columns below to every row",
             "key_args": "pid, kernel, with_context, filter, "
                         "include_last_syscall, include_kernel_stack_usage, "
                         "include_pending_irp, include_impersonation, "
                         "include_com_apartment, include_rpc_usage, "
                         "include_power_throttling, include_fiber",
             "example": "thread_manage(action='list', pid=4812)"},
    "get": {"one_liner": "single-thread detail (state + wait + impersonation)",
            "key_args": "tid, with_context",
            "example": "thread_manage(action='get', tid=1234)"},
    "stack": {"one_liner": "APC-delivered kernel + user frame walk (SI #9)",
              "key_args": "tid, mode, max_frames, timeout_s",
              "example": "thread_manage(action='stack', tid=1234)"},
    "wait": {"one_liner": "last_syscall / wait reason / kernel-stack readout "
                          "(kernel view; answers wave_3_pending until the "
                          "driver dyn-data ships)",
             "key_args": "tid",
             "example": "thread_manage(action='wait', tid=1234)"},
    "irp": {"one_liner": "pending IRP walk (kernel view; answers "
                         "wave_3_pending until the driver dyn-data ships)",
            "key_args": "tid",
            "example": "thread_manage(action='irp', tid=1234)"},
    "impersonation": {"one_liner": "OpenThreadToken + user/level readout "
                                   "(user view: name='<machine>.user')",
                      "key_args": "tid",
                      "example": "thread_manage(action='impersonation', "
                                 "tid=1234, name='lab2.user')"},
    "com": {"one_liner": "COM apartment type/flags from the TEB "
                         "(user view: name='<machine>.user')",
            "key_args": "tid",
            "example": "thread_manage(action='com', tid=1234, "
                       "name='lab2.user')"},
    "rpc": {"one_liner": "WCT-driven RPC-wait chain "
                         "(user view: name='<machine>.user')",
            "key_args": "tid",
            "example": "thread_manage(action='rpc', tid=1234, "
                       "name='lab2.user')"},
    "power": {"one_liner": "ThreadPowerThrottlingState readout "
                           "(user view: name='<machine>.user')",
              "key_args": "tid",
              "example": "thread_manage(action='power', tid=1234, "
                         "name='lab2.user')"},
    "fiber": {"one_liner": "TEB.HasFiberData probe "
                           "(user view: name='<machine>.user')",
              "key_args": "tid",
              "example": "thread_manage(action='fiber', tid=1234, "
                         "name='lab2.user')"},
}


_INCLUDE_KWARGS = (
    "include_last_syscall",
    "include_kernel_stack_usage",
    "include_pending_irp",
    "include_impersonation",
    "include_com_apartment",
    "include_rpc_usage",
    "include_power_throttling",
    "include_fiber",
)


# Per-thread ThreadInspect verbs -> (AgentClient wrapper, view kind that
# serves it). wait / irp are driver-backed and ride the kernel (agent)
# view; the other five are Win32 calls only the usermode agent makes.
# The wrong view answers ``not_supported`` / ``no_driver`` and the
# handler turns that into a pointer at the right view.
_INSPECT_VERBS: dict[str, tuple[str, str]] = {
    "wait":          ("thread_wait_info",        "kernel"),
    "irp":           ("thread_irp_list",         "kernel"),
    "impersonation": ("thread_impersonation",    "user"),
    "com":           ("thread_com_apartment",    "user"),
    "rpc":           ("thread_rpc_usage",        "user"),
    "power":         ("thread_power_throttling", "user"),
    "fiber":         ("thread_fiber",            "user"),
}

# Tokens the agents write into ThreadInspect*Response.error (and the
# kinds ThreadInspectMixin._ti_err uses). First match wins; any other
# text surfaces as kind='thread_inspect_failed' with the text intact.
_INSPECT_ERROR_TOKENS = ("wave_3_pending", "no_driver", "not_supported",
                         "no_thread", "no_teb", "access_denied",
                         "wct_timeout", "agent_version")

# The usermode agent reports a failed NtQueryInformationThread as its
# NTSTATUS in hex (e.g. the ``power`` verb); STATUS_ACCESS_DENIED is the
# one worth a real kind.
_NT_ACCESS_DENIED = "0xc0000022"

_INSPECT_HINTS = {
    "wave_3_pending": ("the agent's ThreadInspect WaitInfo / IrpList are "
                       "placeholders until the driver's dynamic offsets "
                       "ship (Wave 3) — nothing to retry"),
    "no_thread": ("thread not found — it may have exited; "
                  "thread_manage(action='list', pid=...) lists live tids"),
    "no_teb": "the thread's TEB could not be read (thread exiting?)",
    "access_denied": ("the thread's process is protected (PP/PPL) or the "
                      "token refused the query"),
    "wct_timeout": "Wait Chain Traversal hit its 2 s budget — retry",
    "agent_version": ("the agent on the target predates ThreadInspect — "
                      "scripts/update_target.py --component agent"),
}


def _view_label(ctx: Context, name: str) -> str:
    """Best-effort view key for messages/hints. ``require_client`` has
    already vouched for the view, so a lookup failure here only costs
    the label."""
    try:
        return ctx.session.resolve_view_name(name)
    except Exception:  # noqa: BLE001 — label only
        return name or str(getattr(ctx.session, "primary", "") or "")


def _other_view(view: str, want: str) -> str:
    """``'lab2.kernel'`` + ``'user'`` -> ``'lab2.user'`` (bare ``kernel``
    / ``user`` keys map to the bare other kind)."""
    base = view.rsplit(".", 1)[0] if "." in view else ""
    return f"{base}.{want}" if base else want


def _hex_fields(obj: Any) -> Any:
    """Render integer ``*_hex`` / ``*_va`` fields as ``'0x…'`` strings so
    the standalone verbs read like the rest of the driver-sourced
    surface (the include_* columns carry them as plain ints)."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if (isinstance(v, int) and not isinstance(v, bool)
                    and (k.endswith("_hex") or k.endswith("_va"))):
                out[k] = hex(v)
            else:
                out[k] = _hex_fields(v)
        return out
    if isinstance(obj, list):
        return [_hex_fields(v) for v in obj]
    return obj


def _inspect_payload(action: str, res: dict[str, Any]) -> dict[str, Any]:
    """Success body for one verb — the same shapes the ``list``
    include_* columns carry, so one parser reads both."""
    if action == "wait":
        return {
            "last_syscall": _mem_threads._column_from_waitinfo(
                "last_syscall", res),
            "kernel_stack": _mem_threads._column_from_waitinfo(
                "kernel_stack_usage", res),
            "wait_reason": int(res.get("wait_reason") or 0),
            "wait_mode": int(res.get("wait_mode") or 0),
            "wait_status": int(res.get("wait_status") or 0),
            "thread_state": int(res.get("thread_state") or 0),
        }
    if action == "irp":
        return dict(_mem_threads._column_from_irp(res) or {})
    if action == "impersonation":
        return dict(_mem_threads._column_from_impersonation(res))
    if action == "com":
        return dict(_mem_threads._column_from_com(res))
    if action == "rpc":
        return dict(_mem_threads._column_from_rpc(res))
    if action == "power":
        return dict(_mem_threads._column_from_power(res))
    return {"has_fiber_data": bool(res.get("has_fiber_data"))}  # fiber


def _inspect_failure(action: str, tid: int, view: str, serves: str,
                     res: dict[str, Any]) -> dict[str, Any]:
    text = str(res.get("error") or "").strip()
    given = str(res.get("kind") or "")
    low = text.lower()
    kind = given if given in _INSPECT_ERROR_TOKENS else next(
        (t for t in _INSPECT_ERROR_TOKENS if t in low),
        "thread_inspect_failed")
    if kind == "thread_inspect_failed" and _NT_ACCESS_DENIED in low:
        kind = "access_denied"
    out: dict[str, Any] = {
        "ok": False, "kind": kind, "action": action, "tid": int(tid),
        "view": view,
        "error": f"thread_manage.{action}: {text or kind}",
    }
    hint = _INSPECT_HINTS.get(kind)
    if kind in ("not_supported", "no_driver"):
        hint = (f"thread_manage.{action} is served by the {serves} view — "
                f"retry with name={_other_view(view, serves)!r}")
    if hint:
        out["hint"] = hint
    return out


async def _run_inspect_verb(ctx: Context, c: Any, action: str, tid: int,
                            name: str) -> Any:
    """``wait`` / ``irp`` / ``impersonation`` / ``com`` / ``rpc`` /
    ``power`` / ``fiber``: one ThreadInspect RPC for one tid."""
    method_name, serves = _INSPECT_VERBS[action]
    view = _view_label(ctx, name)
    if not tid:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"thread_manage.{action}: tid= is required"})
    method = getattr(c, method_name, None)
    if method is None:
        return _j(_inspect_failure(
            action, tid, view, serves,
            {"kind": "agent_version",
             "error": f"client has no {method_name}()"}))
    try:
        res = await method(int(tid))
    except Exception as exc:  # noqa: BLE001 — transport / agent error
        text = str(exc)
        res = {"ok": False, "error": text}
        if "UNIMPLEMENTED" in text:
            res["kind"] = "agent_version"
    if not isinstance(res, dict):
        res = {"ok": False, "error": str(res)}
    if not res.get("ok"):
        return _j(_inspect_failure(action, tid, view, serves, res))
    body: dict[str, Any] = {"ok": True, "action": action, "tid": int(tid),
                            "view": view}
    body.update(_inspect_payload(action, res))
    return _j(_hex_fields(body))


def register(mcp, ctx: Context) -> None:
    """Register the ``thread_manage`` tool on *mcp*."""

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def thread_manage(
        action: Annotated[str, Field(json_schema_extra={"enum": THREAD_ACTIONS})],
        pid: int = 0,
        tid: int = 0,
        kernel: bool = False,
        with_context: bool = False,
        mode: str = "both",
        max_frames: int = 0,
        timeout_s: float = 0.0,
        force_apc: bool = False,
        timeout_partial_ok: bool = False,
        include_last_syscall: bool = False,
        include_kernel_stack_usage: bool = False,
        include_pending_irp: bool = False,
        include_impersonation: bool = False,
        include_com_apartment: bool = False,
        include_rpc_usage: bool = False,
        include_power_throttling: bool = False,
        include_fiber: bool = False,
        filter: Any = "",
        fields: list[str] | None = None,
        summary: bool = False,
        verbosity: str = "normal",
        limit: int = 0,
        offset: int = 0,
        max_results: int = 64,
        name: str = "",
    ) -> str:
        """System-wide thread inventory, per-thread detail, kernel/user
        stack walks, and one verb per ThreadInspect column (wait / irp /
        impersonation / com / rpc / power / fiber; tid= required).
        wait/irp are kernel-view and answer kind='wave_3_pending' until
        the driver ships their offsets; the rest are user-view. ``list``
        takes include_* kwargs that add the same columns to every row.
        Per-verb help: thread_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "pid": pid, "tid": tid, "name": name,
                "verbosity": verbosity, "fields": fields or [],
                "filter": filter}

        async def run() -> Any:
            if action == "actions":
                return _actions_help("thread_manage", _THREAD_ACTION_HELP)
            if action not in THREAD_ACTIONS:
                return _unknown_action("thread_manage", action,
                                       THREAD_ACTIONS, _THREAD_ACTION_HELP)
            c = ctx.session.require_client(name)
            if action in _INSPECT_VERBS:
                return await _run_inspect_verb(ctx, c, action,
                                               int(tid or 0), name)
            if action == "list":
                # forward the eight include_* opt-in columns
                # (slice 03 Feature 4) directly to handle_threads, which
                # fans them out through ThreadInspect / umagent.
                return await _mem_threads.handle_threads(
                    ctx, c, pid=pid, kernel=kernel,
                    with_context=with_context, filter=filter,
                    summary=summary, fields=fields, limit=limit,
                    offset=offset, max_results=max_results,
                    include_last_syscall=include_last_syscall,
                    include_kernel_stack_usage=include_kernel_stack_usage,
                    include_pending_irp=include_pending_irp,
                    include_impersonation=include_impersonation,
                    include_com_apartment=include_com_apartment,
                    include_rpc_usage=include_rpc_usage,
                    include_power_throttling=include_power_throttling,
                    include_fiber=include_fiber,
                )
            if action == "get":
                if not tid:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "thread_manage.get: tid= is required"})
                return await _mem_threads.handle_threads(
                    ctx, c, pid=pid, kernel=kernel,
                    with_context=with_context,
                    filter={"tid": tid},
                    summary=False, fields=fields, limit=0,
                    offset=0, max_results=1,
                )
            if action == "stack":
                if not tid:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "thread_manage.stack: tid= is required"})
                return await _mem_stack_walk.handle_stack_walk(
                    ctx, c, tid=int(tid),
                    mode=(mode or "both").lower(),
                    max_frames=int(max_frames or 0),
                    timeout_ms=int(timeout_s * 1000) if timeout_s > 0 else 0,
                    force_apc=bool(force_apc),
                    timeout_partial_ok=bool(timeout_partial_ok),
                    privilege_cookie=0, name=name,
                )

            return _unknown_action("thread_manage", action,
                                   THREAD_ACTIONS, _THREAD_ACTION_HELP)

        return await _guard(ctx, "thread_manage", action, args, run)
