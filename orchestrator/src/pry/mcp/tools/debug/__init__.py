"""Debug tool registration for the pry MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from .common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

from ..common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from ..context import Context
from ..follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)
# Memory scanner wave 3 P4 (AccessTrace). Four new access_trace_* verbs
# dispatch into this subpackage; each verb body lives alongside the
# Capstone-based x64 memop decoder (`_x64_memop.py`) and the two
# drivers (`_watchhw_driver.py`, `_dbgeng_driver.py`).
from .access_trace import (  # noqa: F401
    at_cancel,
    at_jobs,
    at_start,
    at_status,
    ACCESS_TRACE_HELP,
    ACCESS_TRACE_VERBS,
)


# module-level so the lazy action-enum annotation resolves.
# The order below is the one documented in docs/DEBUG_MCP.md; actions
# added later (`run`, `run_to`, `wait`, `pause`, `status`,
# `step_out`, `disasm`, `resolve`, `dump`, `modules`, `exception`) all
# go through the same dispatcher.
DEBUG_ACTIONS = [
    "launch", "attach", "detach",
    "continue", "step_into", "step_over", "step_out",
    "run", "run_to", "wait", "pause", "status",
    "regs", "set_regs", "threads", "stacktrace",
    "read", "write", "regions", "events", "cmd",
    "disasm", "resolve", "dump", "modules", "exception",
    # SetInterrupt-backed abort for a wedged engine op
    # (symbol-server stall, slow `.reload`, pinned dbgeng internal).
    # Dispatcher also releases the caller's debug lease on success.
    "cancel",
    # Memory scanner wave 3 P4 (AccessTrace) — background job surface. The
    # verbs compose existing agent RPCs; no proto bump.
    *ACCESS_TRACE_VERBS,
    "actions",
]


# 30-second server-side cap on every waiting action
# (``run`` / ``wait`` / ``pause`` / ``run_to`` / ``step_out``). The
# server also enforces this; the clamp here just means the LLM never
# sees a gRPC DEADLINE_EXCEEDED for a legal `timeout_s` value. See the
# "30-second rule" section in docs/DEBUG_MCP.md.
_DEBUG_WAIT_CAP_S = 30
_DEBUG_WAIT_DEFAULT_S = 20


def _clamp_wait_timeout_s(timeout_s: int) -> int:
    """Return the ``timeout_s`` to forward to the agent wrapper.

    ``0`` (the default) picks the 20 s default; any positive value is
    clamped into ``[1, 30]``."""
    t = int(timeout_s or 0)
    if t <= 0:
        return _DEBUG_WAIT_DEFAULT_S
    if t > _DEBUG_WAIT_CAP_S:
        return _DEBUG_WAIT_CAP_S
    return t


def _attach_state(result: dict, inner: Any) -> dict:
    """Mirror the StopInfo echo (from Agent 5's wrappers) onto the
    outbound MCP envelope.

    Agent 5's mutating wrappers return a dict shaped like
    ``{"ok": true, ..., "state": {...}}``; we lift the ``state`` block
    onto ``result`` so every mutating envelope carries ``state``
    (``active`` / ``stopped`` / ``rip`` / ``symbol`` / ``stop_reason``
    / ``seq`` / ...). ``state.rip`` arrives already hex-stringified by
    Agent 5, so no extra hex massaging is needed here."""
    if not isinstance(result, dict):
        return result
    state = inner.get("state") if isinstance(inner, dict) else None
    if state:
        result["state"] = state
    return result




def register(mcp, ctx: Context) -> None:
    """Register the ``debug_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------ debug_manage --

    _DEBUG_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "debug_manage(action='actions')"},
        "launch": {"one_liner": "spawn a process under dbgeng",
                   "key_args": "cmdline, workdir",
                   "example": "debug_manage(action='launch', "
                              "cmdline='C:\\\\lab\\\\target.exe')"},
        "attach": {"one_liner": "attach dbgeng to pid (or image=); "
                                "per-pid lease, busy envelope if held",
                   "key_args": "pid, image, wait_s",
                   "example": "debug_manage(action='attach', pid=1234)"},
        "detach": {"one_liner": "release the debug session (leases freed)",
                   "key_args": "pid",
                   "example": "debug_manage(action='detach')"},
        "continue": {"one_liner": "resume the debugee",
                     "key_args": "none",
                     "example": "debug_manage(action='continue')"},
        "step_into": {"one_liner": "single-step into",
                      "key_args": "count",
                      "example": "debug_manage(action='step_into')"},
        "step_over": {"one_liner": "single-step over calls",
                      "key_args": "count",
                      "example": "debug_manage(action='step_over')"},
        "step_out": {"one_liner": "run until the current frame "
                                   "returns (cap 30s)",
                     "key_args": "timeout_s",
                     "example": "debug_manage(action='step_out', "
                                "timeout_s=10)"},
        "run": {"one_liner": "resume + wait for the next stop "
                             "(default 20s, cap 30s)",
                "key_args": "timeout_s",
                "example": "debug_manage(action='run', timeout_s=10)"},
        "run_to": {"one_liner": "run until address (one-shot sw bp + "
                                 "wait); default 20s, cap 30s",
                   "key_args": "address, timeout_s",
                   "example": "debug_manage(action='run_to', "
                              "address='0x140001000', timeout_s=5)"},
        "wait": {"one_liner": "wait for the next stop without "
                              "resuming (default 20s, cap 30s). "
                              "Monitor mode: only process_exit / "
                              "exception resolves — bp hits "
                              "auto-resume.",
                 "key_args": "timeout_s",
                 "example": "debug_manage(action='wait', timeout_s=10)"},
        "pause": {"one_liner": "break the target into dbgeng "
                                "(cap 30s)",
                  "key_args": "timeout_s",
                  "example": "debug_manage(action='pause', timeout_s=5)"},
        "status": {"one_liner": "state snapshot — never resumes the "
                                 "target",
                   "key_args": "none",
                   "example": "debug_manage(action='status')"},
        "disasm": {"one_liner": "decode N instructions at address "
                                 "(count default 16)",
                   "key_args": "address, count",
                   "example": "debug_manage(action='disasm', "
                              "address='0x140001000', count=16)"},
        "resolve": {"one_liner": "symbol -> address (module!name or "
                                  "module+0xN)",
                    "key_args": "symbol",
                    "example": "debug_manage(action='resolve', "
                               "symbol='ntdll!NtClose')"},
        "dump": {"one_liner": "write a crash-dump of the debugee "
                               "(kind='mini'|'full')",
                 "key_args": "path, kind",
                 "example": "debug_manage(action='dump', "
                            "path='C:\\\\lab\\\\dump.dmp', kind='mini')"},
        "modules": {"one_liner": "list dbgeng-loaded modules for the "
                                  "debugee",
                    "key_args": "none",
                    "example": "debug_manage(action='modules')"},
        "exception": {"one_liner": "set first-chance filter for an "
                                    "exception code "
                                    "(action='break'|'ignore'|"
                                    "'second_chance')",
                      "key_args": "exception_code, exception_action",
                      "example": "debug_manage(action='exception', "
                                 "exception_code=0xC0000005, "
                                 "exception_action='break')"},
        "regs": {"one_liner": "read the register bank",
                 "key_args": "none",
                 "example": "debug_manage(action='regs')"},
        "set_regs": {"one_liner": "write registers from a JSON map",
                     "key_args": "regs_json",
                     "example": "debug_manage(action='set_regs', "
                                "regs_json='{\"rip\":\"0x140001000\"}')"},
        "threads": {"one_liner": "list debugee threads",
                    "key_args": "none",
                    "example": "debug_manage(action='threads')"},
        "stacktrace": {"one_liner": "backtrace the current/all threads",
                       "key_args": "max_frames",
                       "example": "debug_manage(action='stacktrace')"},
        "read": {"one_liner": "read debugee memory (hex)",
                 "key_args": "address, size",
                 "example": "debug_manage(action='read', "
                            "address='0x140001000', size=64)"},
        "write": {"one_liner": "write debugee memory",
                  "key_args": "address, data_hex",
                  "example": "debug_manage(action='write', "
                             "address='0x140001000', data_hex='90 90')"},
        "regions": {"one_liner": "list debugee memory regions",
                    "key_args": "none",
                    "example": "debug_manage(action='regions')"},
        "events": {"one_liner": "dbgeng event history; from_seq= for "
                                "replay",
                   "key_args": "from_seq",
                   "example": "debug_manage(action='events', from_seq=0)"},
        "cmd": {"one_liner": "raw dbgeng command passthrough",
                "key_args": "command",
                "example": "debug_manage(action='cmd', command='!peb')"},
        "cancel": {"one_liner": "abort the in-flight engine op "
                                 "(SetInterrupt + release lease)",
                    "key_args": "pid (default: current session)",
                    "example": "debug_manage(action='cancel')"},
        # Memory scanner wave 3 P4 — merged from access_trace.ACCESS_TRACE_HELP
        # so the single `_DEBUG_ACTION_HELP` dict stays authoritative.
        **ACCESS_TRACE_HELP,
    }

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def debug_manage(action: Annotated[str, Field(json_schema_extra={"enum": DEBUG_ACTIONS})],
                           cmdline: str = "", workdir: str = "", pid: int = 0,
                           image: str = "", kill: bool = False, count: int = 1,
                           regs_json: str = "", address: int | str = 0, size: int = 64,
                           data_hex: str = "", max_frames: int = 32, command: str = "",
                           from_seq: int = 0,
                           # per-pid ownership + lease knobs
                           force: bool = False,
                           wait_s: float = 0.0,
                           # state-loop kwargs
                           timeout_s: int = 0,
                           symbol: str = "",
                           path: str = "",
                           kind: str = "mini",
                           exception_code: int = 0,
                           exception_action: str = "break",
                           tid: int = 0,
                           monitor: bool = False,
                           # opt into StopInfo.regs /
                           # bytes_at_rip_hex on the state echo of
                           # status/wait/run/run_to/step_out/continue/
                           # step/pause. Exception stops fill them
                           # unconditionally; cmd stops default on too
                           # (a `.detach` / `g` / `q` typed after a
                           # crash is the second-most common path to
                           # inspect it).
                           include_context: bool = False,
                           # unified paging (Layer 3)
                           limit: int = 0,
                           offset: int = 0,
                           cursor: str = "",
                           verbosity: str = "normal",
                           fields: list[str] | None = None,
                           filter: Any = "",
                           summary: bool = False,
                           # Legacy alias for `limit` on list-returning actions.
                           max_results: int = 0,
                           # Memory scanner wave 3 P4 (AccessTrace) kwargs. All default
                           # to zero/empty so legacy debug_manage calls stay
                           # wire-compatible. See access_trace.py for the full
                           # story (ring buffer, driver selection, redaction).
                           access: str = "rw",
                           driver: str = "auto",
                           max_hits: int = 4096,
                           symbolize: bool = True,
                           disasm: bool = True,
                           stackwalk: bool = True,
                           redact_regs: bool = True,
                           job_id: str = "",
                           name: str = "") -> str:
        """User-mode debugging via DbgEng: launch/attach, breakpoints via
        bp_manage, run/wait/pause/run_to/step_out (block server-side up to
        timeout_s, default 20 s, max 30 s; a timeout answers
        state.timed_out=true, not an error), regs, memory, stacks, events,
        raw cmd, and access_trace_* data-watch jobs. monitor=True on
        launch/attach auto-resumes bp/exception hits. Mutating responses
        carry a ``state`` block (active / stopped / rip / symbol /
        stop_reason / seq / bp_id / exception_code) - see docs/DEBUG_MCP.md.
        Addresses accept int or '0x...' hex. Per-verb help:
        debug_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "pid": pid, "cmdline": cmdline,
                "address": address,
                # Forward verbosity so finalize honors it (threads/stacktrace/
                # regions row-collapse opt-out via full/raw).
                "verbosity": verbosity}

        async def run() -> str:
            if action not in DEBUG_ACTIONS:
                return _unknown_action("debug_manage", action, DEBUG_ACTIONS, _DEBUG_ACTION_HELP)
            if action == "actions":
                return _actions_help("debug_manage", _DEBUG_ACTION_HELP)
            c = ctx.session.require_client(name)
            # dbgeng attaches to a user pid; module+offset resolves in the
            # attached process's module list.
            addr = await _addr_resolve(address, c, kernel=False,
                                       pid=pid, name="address")
            # helpers for the per-pid ownership gate. The lease resource
            # name is namespaced by view so a peer holding kernel-view pid=1234
            # doesn't spuriously block a user-view attach with the same pid.
            view = ctx.session.resolve_view_name(name)
            owner = current_client_id()

            def _lease_key(target_pid: int) -> str:
                return f"debug:{view}:pid={target_pid}"

            # any debug_manage call on this view by the lease
            # holder counts as use — touch its leases so the reaper's
            # idle_ttl_s is an IDLE timeout, not an absolute one (nothing
            # called LeaseManager.touch before, so an active session lost
            # its lease 10 minutes after attach).
            if ctx.leases is not None:
                for (_v, _p), _h in list(ctx._attach_leases.items()):
                    if _v == view and getattr(_h, "owner", None) == owner:
                        try:
                            await ctx.leases.touch(_h)
                        except Exception:  # noqa: BLE001 — best-effort
                            pass

            def _own_attached_pid() -> int:
                # Any (view, pid) in _attach_leases whose handle we hold is our
                # "currently attached" pid on this view. Zero means no lease —
                # the mutating gate then falls through if the caller passed pid
                # explicitly, or proceeds unguarded (no pid means no key to check).
                if ctx.leases is None:
                    return 0
                for (v, p), h in ctx._attach_leases.items():
                    if v == view and h.owner == owner:
                        return int(p)
                return 0

            async def _gate_mutation(target_pid: int) -> str | None:
                """Return a JSON error string when the caller does not own the
                debug lease on ``target_pid``. Returns ``None`` to proceed.
                No-op when leases are disabled, when force=True, or when the
                target pid is unknown (0) — in that last case we simply have no
                key to check ownership against."""
                if ctx.leases is None or force or target_pid <= 0:
                    return None
                holder = ctx.leases.who_holds(_lease_key(target_pid))
                if holder is None or holder == owner:
                    return None
                return _j({"ok": False, "kind": "foreign_owned",
                           "owner": holder, "pid": target_pid,
                           "resource": _lease_key(target_pid),
                           "hint": "pass force=true to override"})

            if action == "launch":
                # `monitor` is Agent 5's new kwarg. Pass it
                # only when the caller explicitly asked for it so this
                # tool keeps working against an older agent client.
                launch_kwargs = {"break_on_entry": True}
                if monitor:
                    launch_kwargs["monitor"] = True
                result = await c.debug_launch(cmdline, workdir, **launch_kwargs)
                if isinstance(result, dict):
                    _attach_state(result, result)
                launched_pid = result.get("pid") if isinstance(result, dict) else None
                if (ctx.leases is not None and isinstance(launched_pid, int)
                        and launched_pid > 0):
                    # launch just created the pid; no one else can hold it —
                    # a non-blocking acquire is correct and cheap.
                    acq = await ctx.leases.acquire(
                        _lease_key(launched_pid), owner, wait_s=0)
                    if isinstance(acq, BusyInfo):
                        # Extremely unlikely (stale lease from a prior process
                        # id reuse); surface it rather than silently overwrite.
                        result["lease_warning"] = {
                            "held_by": acq.held_by,
                            "since_iso": acq.since_iso,
                        }
                    else:
                        ctx._attach_leases[(view, launched_pid)] = acq
                        result["lease_owner"] = owner
                        if ctx.clients is not None:
                            await ctx.clients.held_attach_add(
                                owner, view, launched_pid)
                return _j(result)
            if action == "attach":
                target_pid = pid
                if not target_pid and image:
                    procs = await c.mem_processes()
                    want = image.lower()
                    matches = [p for p in procs
                               if want in str(p.get("image_name", "")).lower()]
                    if not matches:
                        return _j({"ok": False,
                                   "error": f"no process matches image {image!r}"})
                    if len(matches) > 1:
                        return _j({"ok": False, "error": "ambiguous image name",
                                   "matches": [p.get("pid") for p in matches]})
                    target_pid = int(matches[0].get("pid", 0))
                if not target_pid:
                    return _j({"ok": False,
                               "error": "attach requires pid or image"})
                if ctx.leases is not None:
                    eff_wait = (wait_s if wait_s > 0
                                else ctx.cfg.leases.attach_timeout_s)
                    acq = await ctx.leases.acquire(
                        _lease_key(target_pid), owner, wait_s=eff_wait)
                    if isinstance(acq, BusyInfo):
                        return _j({"ok": False, "kind": "busy",
                                   "held_by": acq.held_by,
                                   "since_iso": acq.since_iso,
                                   "waited_s": acq.waited_s,
                                   "pid": target_pid,
                                   "resource": _lease_key(target_pid)})
                    # release the lease on EVERY failure path,
                    # including an exception from the agent RPC itself
                    # (client-side gRPC DEADLINE_EXCEEDED, CANCELLED,
                    # transport errors). Before this guard the lease
                    # leaked whenever `debug_attach` raised, pinning
                    # the (view,pid) tuple until the idle
                    # reaper caught up ~10 min later — turning a
                    # transient client-side timeout into a long busy
                    # window on every follow-up attach.
                    try:
                        result = await c.debug_attach(target_pid)
                    except BaseException:
                        await ctx.leases.release(acq)
                        raise
                    if isinstance(result, dict):
                        _attach_state(result, result)
                    if isinstance(result, dict) and not result.get("ok", True):
                        # Attach failed on the agent side — release the lease
                        # so we don't leak it against a pid we never actually
                        # attached to.
                        await ctx.leases.release(acq)
                        return _j(result)
                    ctx._attach_leases[(view, target_pid)] = acq
                    if ctx.clients is not None:
                        await ctx.clients.held_attach_add(
                            owner, view, target_pid)
                    if isinstance(result, dict):
                        result["lease_owner"] = owner
                    return _j(result)
                r2 = await c.debug_attach(target_pid)
                if isinstance(r2, dict):
                    _attach_state(r2, r2)
                return _j(r2)
            if action == "detach":
                result = await c.debug_detach(kill)
                if isinstance(result, dict):
                    _attach_state(result, result)
                if ctx.leases is not None:
                    released: list[int] = []
                    for (v, p), h in list(ctx._attach_leases.items()):
                        if v != view or h.owner != owner:
                            continue
                        await ctx.leases.release(h)
                        ctx._attach_leases.pop((v, p), None)
                        if ctx.clients is not None:
                            await ctx.clients.held_attach_remove(owner, v, p)
                        released.append(p)
                    if released and isinstance(result, dict):
                        result["released_pids"] = released
                return _j(result)
            if action == "continue":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                result = await c.debug_continue(include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "step_into":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                result = await c.debug_step(
                    over=False, count=count,
                    include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "step_over":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                result = await c.debug_step(
                    over=True, count=count,
                    include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "step_out":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                eff_ms = _clamp_wait_timeout_s(timeout_s) * 1000
                result = await c.debug_step_out(
                    eff_ms, include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "run":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                eff_ms = _clamp_wait_timeout_s(timeout_s) * 1000
                result = await c.debug_run(
                    eff_ms, include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "run_to":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                if not addr:
                    return _j({"ok": False,
                               "error": "run_to requires 'address'"})
                eff_ms = _clamp_wait_timeout_s(timeout_s) * 1000
                result = await c.debug_run_to(
                    addr, eff_ms, include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "wait":
                # wait is observational (never resumes), but the LLM
                # reasons about it as "the session may transition" so
                # we keep it in the mutation-gate for consistency with
                # run/pause — the lease owner check is cheap.
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                eff_ms = _clamp_wait_timeout_s(timeout_s) * 1000
                result = await c.debug_wait(
                    eff_ms, include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "pause":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                eff_ms = _clamp_wait_timeout_s(timeout_s) * 1000
                result = await c.debug_pause(
                    eff_ms, include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "status":
                # status is pure read: no gate, no mutation. The
                # response is `{"ok": true, "state": {...}}`; when the
                # session is dead, Agent 5's wrapper returns
                # `state.active=false` and no other state fields.
                result = await c.debug_status(
                    include_context=bool(include_context))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "regs":
                regs = await c.debug_regs()
                regs = {k: (hex(v) if isinstance(v, int) else v) for k, v in regs.items()}
                return _hexify_dict(_envelope_ok(
                    regs, kind="regs",
                    tool="debug_manage", action="regs",
                ), add_int_mirror=True)
            if action == "set_regs":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                result = await c.debug_set_regs(**json.loads(regs_json or "{}"))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "threads":
                # debug_threads returns {"current_tid": tid, "threads": [...]}
                # — the previous pass fed the whole dict into _list_envelope,
                # which tried `rows[0:limit]` on a dict and tripped
                # `KeyError: slice(0, 32, None)`. Unwrap the list; carry
                # current_tid in the envelope's data payload via extras=.
                result = await c.debug_threads()
                return _list_envelope(
                    result.get("threads", []),
                    tool="debug_manage", action="threads",
                    kind="threads",
                    limit=limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"current_tid": int(
                        result.get("current_tid", 0) or 0)},
                )
            if action == "stacktrace":
                frames = await c.debug_stacktrace(max_frames)
                # Layer 3: unified list envelope. `max_frames` still
                # accepted as an alias for `limit` for one release.
                eff_limit = limit or max_frames
                return _hexify_dict(_list_envelope(
                    frames, tool="debug_manage", action="stacktrace",
                    kind="backtrace",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                ), add_int_mirror=True)
            if action == "read":
                data = await c.debug_read(addr, size)
                return _j({"address": hex(addr), "hex": data.hex(), "ascii": _ascii(data)})
            if action == "write":
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                result = await c.debug_write(addr, bytes.fromhex(data_hex))
                if isinstance(result, dict):
                    _attach_state(result, result)
                return _j(result)
            if action == "regions":
                rows = await c.debug_regions()
                rows = _decode_list(rows, "region")
                eff_limit = limit or max_results
                return _hexify_dict(_list_envelope(
                    rows, tool="debug_manage", action="regions",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                ), add_int_mirror=True)
            if action == "events":
                # Event is a dataclass, not a dict — the prior
                # `e["data"]` raised TypeError the moment any debug
                # event landed in the bus. Access via attribute.
                # surface pump liveness — a dead pump means "no
                # events" is a lie; restart it when possible.
                if not ctx.event_pump_alive(view):
                    ctx.start_event_pump(view)
                events = [e.data for e in c.bus.recent if e.kind == "debug"]
                if from_seq:
                    events = [e for e in events if int(e.get("seq", 0)) >= from_seq]
                # Layer 3: newest-first + uniform paging envelope.
                # Default limit 64 preserves the historical `events[-64:]`
                # window; callers may raise via `limit=` / `max_results=`.
                events = list(reversed(events))
                eff_limit = limit or max_results
                env = _list_envelope(
                    events, tool="debug_manage", action="events",
                    kind="events",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    default_limit=64,
                )
                env["pump_alive"] = ctx.event_pump_alive(view)
                return _hexify_dict(env, add_int_mirror=True)
            if action == "cmd":
                if not command:
                    return _j({"ok": False, "error": "cmd requires 'command'"})
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                # `debug_cmd` (not the legacy string-returning
                # `dbg_cmd`) returns a dict carrying the B8 state echo so
                # `.detach` / `q` / `g` surface `state.active` without a
                # follow-up `status` round trip.
                #
                # include_context does not thread through
                # ExecuteCommand (the proto doesn't carry the flag on
                # that RPC). Exception stops still auto-fill
                # state.regs / bytes_at_rip_hex in the agent, so
                # `cmd` responses that land on an exception stop get
                # the crash context for free; other cmd stops don't.
                output = await c.debug_cmd(command)
                if isinstance(output, dict):
                    envelope = {"ok": bool(output.get("ok", True)),
                                "output": output.get("output", "")}
                    _attach_state(envelope, output)
                    return _j(envelope)
                return _j({"ok": True, "output": output})
            if action == "disasm":
                if not addr:
                    return _j({"ok": False,
                               "error": "disasm requires 'address'"})
                eff_count = int(count or 16)
                result = await c.debug_disasm(addr, eff_count)
                if not isinstance(result, dict):
                    result = {"lines": list(result) if result else []}
                return _hexify_dict(result, add_int_mirror=True)
            if action == "resolve":
                if not symbol:
                    return _j({"ok": False,
                               "error": "resolve requires 'symbol'"})
                result = await c.debug_resolve(symbol)
                # address arrives as an int; hex-mirror for the LLM.
                return _hexify_dict(result if isinstance(result, dict)
                                    else {"result": result},
                                    add_int_mirror=True)
            if action == "dump":
                if not path:
                    return _j({"ok": False,
                               "error": "dump requires 'path'"})
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                result = await c.debug_dump(path, kind)
                return _j(result)
            if action == "modules":
                result = await c.debug_modules()
                # debug_modules returns a list of ModuleInfo dicts;
                # funnel through _list_envelope for pagination.
                rows = result if isinstance(result, list) else \
                    (result.get("modules", []) if isinstance(result, dict)
                     else [])
                eff_limit = limit or max_results
                return _hexify_dict(_list_envelope(
                    rows, tool="debug_manage", action="modules",
                    kind="modules",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                ), add_int_mirror=True)
            if action == "exception":
                if not exception_code:
                    return _j({"ok": False,
                               "error": "exception requires "
                                        "'exception_code'"})
                if exception_action not in ("break", "ignore",
                                             "second_chance"):
                    return _j({"ok": False,
                               "error": ("exception_action must be "
                                         "'break' | 'ignore' | "
                                         "'second_chance'")})
                gate = await _gate_mutation(pid or _own_attached_pid())
                if gate is not None:
                    return gate
                result = await c.debug_exception(int(exception_code),
                                                 exception_action)
                return _j(result)
            if action == "cancel":
                # SetInterrupt-backed abort for a wedged
                # engine op. Behind the mutation gate like pause: a
                # foreign-owner lease blocks the call (force=true to
                # override). On success, release every lease this
                # caller holds on the resolved view so a wedged
                # orchestrator doesn't pin the pid forever.
                target_pid = pid or _own_attached_pid()
                gate = await _gate_mutation(target_pid)
                if gate is not None:
                    return gate
                result = await c.debug_cancel(target_pid)
                if isinstance(result, dict):
                    _attach_state(result, result)
                if (ctx.leases is not None
                        and isinstance(result, dict)
                        and result.get("ok", False)):
                    released: list[int] = []
                    for (v, p), h in list(ctx._attach_leases.items()):
                        if v != view or h.owner != owner:
                            continue
                        if target_pid and int(p) != int(target_pid):
                            continue
                        await ctx.leases.release(h)
                        ctx._attach_leases.pop((v, p), None)
                        if ctx.clients is not None:
                            await ctx.clients.held_attach_remove(owner, v, p)
                        released.append(int(p))
                    if released:
                        result["released_pids"] = released
                return _j(result)
            # ------------------------------------------------- AccessTrace --
            # Wave 3 P4. The four verbs run against the existing attach /
            # stream / bp surfaces; `access_trace_start` is an actuator
            # (`min_trust_actuator` auto-gate + `allow_hw_bp_hook` check in
            # session/core when driver resolves to watchhw), the rest are
            # pure job-registry reads. Delegated to the subpackage so the
            # dispatcher stays scannable.
            if action == "access_trace_start":
                return _j(await at_start(
                    ctx, c=c, view=view, owner=owner, name=name,
                    pid=pid, address=addr, size=size, access=access,
                    tid=tid, driver=driver, max_hits=max_hits,
                    symbolize=symbolize, disasm=disasm,
                    stackwalk=stackwalk, timeout_s=timeout_s,
                    redact_regs=redact_regs,
                ))
            if action == "access_trace_status":
                return _j(at_status(job_id=job_id, limit=limit,
                                     offset=offset, verbosity=verbosity,
                                     redact_regs=redact_regs))
            if action == "access_trace_stop":
                return _j(await at_cancel(ctx, c=c, job_id=job_id))
            if action == "access_trace_list":
                return _j(at_jobs())
            return _unknown_action("debug_manage", action, DEBUG_ACTIONS, _DEBUG_ACTION_HELP)

        return await _guard(ctx, "debug_manage", action, args, run)
