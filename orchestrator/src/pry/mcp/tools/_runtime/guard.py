"""Tool-call guard rails.

Every ``@mcp.tool`` action funnels through ``_guard`` (or
``_guard_pure`` for compute-only tools). The guard runs the allowlist
gate, enforces the actuator-trust gate for destructive verbs, times
the body, catches exceptions and routes them through the unified
envelope + provenance stamp + target stamp pipeline.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ....allowlist import TargetNotAllowed as TargetNotAllowedError
from ....ghidra_bridge import GhidraBridgeError
from ....ida_bridge import IdaBridgeError
from ....plugins import PluginError
from ....session import AmbiguousTargetError

from .capabilities import (
    _actuator_pairs_from_registry,
    resolve_alias as _resolve_alias,
)
from .envelope import (
    _coerce_to_envelope,
    _emit,
    _envelope_err,
    _opts_from_args,
    _resolve_stamp,
    _stamp_provenance,
    _stamp_target,
)


# actuator verbs checked against machine trust (registry / machines:
# metadata) when security.min_trust_actuator is raised above "untrusted".
#
# the backing set is seeded from the capability registry at
# import time — any ``Capability`` with ``mutating=True`` and a non-None
# ``gate`` lands here automatically. The hand-written entries below are
# the legacy pairs that already shipped (device_manage.ioctl,
# target_manage.driver_* and friends) — kept inline so a registry
# regression never silently drops them.
_LEGACY_ACTUATOR_PAIRS: frozenset[tuple[str, str]] = frozenset({
    ("device_manage", "ioctl"),
    ("target_manage", "driver_load"),
    ("target_manage", "driver_unload"),
    ("target_manage", "boot_recover"),
    # reliable Windows-API reboot verb (InitiateShutdownW).
    # Each mode-alias dispatches through the same handler, so they all
    # need to be gated the same way.
    ("target_manage", "reboot"),
    ("target_manage", "shutdown"),
    ("target_manage", "poweroff"),
    ("target_manage", "logoff"),
    ("target_manage", "reboot_abort"),
    ("exec_manage", "kill_process"),
    ("exec_manage", "call"),
})
_ACTUATOR_PAIRS: frozenset[tuple[str, str]] = (
    _LEGACY_ACTUATOR_PAIRS | _actuator_pairs_from_registry()
)


def _check_actuator_trust(ctx, tool: str, action: str,
                          args: dict) -> None:
    """Machine-trust gate for actuator verbs. Config default
    ('untrusted') disables it entirely; otherwise a machine below
    security.min_trust_actuator is refused unless the call carries
    force=true. Reads are never gated and never annotated.

    The gate check consults the capability registry so a
    legacy caller (``exec_manage.kill_process``) hits the same gate
    as the canonical name (``process_manage.kill``). The hand-rolled
    ``_ACTUATOR_PAIRS`` is kept as a backing set, now seeded from
    the registry — see :func:`capabilities._actuator_pairs_from_registry`.
    """
    is_actuator = (tool, action) in _ACTUATOR_PAIRS
    if not is_actuator:
        # Fall back through the registry so aliases redirect correctly:
        # (memory_manage, process_list) resolves to (process_manage, list)
        # which has no mutating=True; (exec_manage, kill_process)
        # resolves to (process_manage, kill) which does.
        cap = _resolve_alias(tool, action)
        if cap is not None and cap.mutating and cap.gate is not None:
            is_actuator = True
    if not is_actuator:
        return
    # The per-tool ``args`` dict is a hand-picked subset of the call; the
    # call middleware parks the caller's full arguments in CALL_INFO, so
    # ``force=`` / ``name=`` count even when a tool body didn't copy them
    # (exec_manage did not, so its gate checked the focus machine).
    raw = _raw_call_args(tool)
    args = dict(args or {})
    if "force" not in args and "force" in raw:
        args["force"] = raw["force"]
    if not args.get("name") and not args.get("machine"):
        for k in ("name", "machine"):
            if raw.get(k):
                args[k] = raw[k]
                break
    if bool(args.get("force")):
        return
    min_trust = str(getattr(ctx.cfg.security, "min_trust_actuator", "untrusted")
                    or "untrusted").strip().lower()
    if min_trust in ("", "untrusted"):
        return
    sess = getattr(ctx, "session", None)
    if sess is None:
        return
    name = str((args or {}).get("name") or (args or {}).get("machine") or "")
    try:
        key = sess.resolve_view_name(name)
        machine = sess.machine_of(key)
    except Exception:
        machine = name.strip() or "<unknown>"
    try:
        trust = str(ctx.registry.trust_for(machine) or "untrusted").lower()
    except Exception:
        trust = "untrusted"
    from ....config import TRUST_LEVELS
    if TRUST_LEVELS.get(trust, 0) < TRUST_LEVELS.get(min_trust, 0):
        raise TargetNotAllowedError(
            f"{tool}.{action} on machine {machine!r} refused: trust={trust} "
            f"< security.min_trust_actuator={min_trust} — pass force=true "
            f"to override, machines_manage(action='set', machine={machine!r}, "
            "trust=...) to regrade the machine, or lower the config knob")


def _raw_call_args(tool: str) -> dict:
    """The raw arguments of the MCP call being served (see
    :data:`surface.CALL_INFO`), or ``{}`` outside a call. ``tool`` may be
    an internal dispatcher the public tool forwarded to; the caller's
    ``force``/``name`` still apply."""
    try:
        from .surface import CALL_INFO
    except Exception:  # noqa: BLE001 — import cycles during bootstrap
        return {}
    info = CALL_INFO.get()
    if not info:
        return {}
    raw = info.get("args") or {}
    return raw if isinstance(raw, dict) else {}


# T3.3: orchestrator supervision — surface host-death with an actionable
# hint pointing at the start/install scripts. The envelope flows through
# the same {ok, kind, error, tool, action} shape as every other error
# response; `kind='orchestrator_unreachable'` lets callers distinguish
# "the orchestrator is down" from the agent-side `channel_unavailable`
# that `enrich_error` already classifies.
_ORCH_UNREACHABLE_HINT = (
    "MCP host is down. Restart from an elevated PowerShell: "
    "scripts\\start_orchestrator.ps1 (or install as service with "
    "scripts\\install_orchestrator_service.ps1 for auto-restart)."
)


def _classify_orchestrator_dead(exc: BaseException) -> dict | None:
    """Return a `{kind, error, hint}` triple when `exc` indicates the
    orchestrator's own listener / child-process plumbing is dead, else
    None. Catches:

      * ``ConnectionRefusedError`` — raw OSError variant raised by a
        local sub-call (dashboard self-poll, worker proc).
      * ``grpc.RpcError`` whose ``code()`` is ``StatusCode.UNAVAILABLE``
        AND whose detail is the orchestrator's own endpoint — gRPC
        propagates channel-dead with this code.
      * String matches for ``"UNAVAILABLE"`` + loopback markers used by
        the subprocess MCP child when its parent went away.

    Pure classification; never raises. The caller lifts the triple into
    an error envelope via `_envelope_err` + overlay of the fields here.
    """
    if isinstance(exc, ConnectionRefusedError):
        return {
            "kind": "orchestrator_unreachable",
            "error": f"ConnectionRefusedError: {exc}",
            "hint": _ORCH_UNREACHABLE_HINT,
        }
    try:
        import grpc  # local import — tools without grpc on the path still load
        if isinstance(exc, grpc.RpcError):
            code = None
            try:
                code = exc.code()  # grpc.aio.AioRpcError + sync RpcError
            except Exception:  # noqa: BLE001
                code = None
            if code == grpc.StatusCode.UNAVAILABLE:
                return {
                    "kind": "orchestrator_unreachable",
                    "error": f"grpc UNAVAILABLE: {exc}",
                    "hint": _ORCH_UNREACHABLE_HINT,
                }
    except ImportError:
        pass
    return None


#: A call still running after this many seconds gets an in-flight row in
#: the persistent audit sink right away - so a call that hangs (or wedges
#: the target and takes the orchestrator down with it) leaves a trace.
_INFLIGHT_AUDIT_S = 5.0


def _err_text(env: Any) -> str:
    err = env.get("error") if isinstance(env, dict) else None
    if isinstance(err, dict):
        return str(err.get("error") or err.get("kind") or "")
    return str(err or "")


def _audit_final(ctx, tool: str, action: str, args: dict[str, Any],
                 *, ok: bool, error: str, status: str,
                 elapsed_ms: int) -> None:
    """The one tool-log + audit row per call (written in the
    guard's ``finally`` for every outcome - success, error envelope,
    cancellation - with the call's args)."""
    sess = getattr(ctx, "session", None)
    rec = getattr(sess, "record_tool_call", None)
    if rec is None:
        return
    logged = dict(args) if args else {}
    try:
        stamp = _resolve_stamp(ctx, logged)
        if stamp:
            logged["_view"] = stamp["view"]
    except Exception:  # noqa: BLE001 - the stamp is decoration
        pass
    try:
        from ....caller import current_client_id
        logged.setdefault("_current_owner", current_client_id())
    except Exception:  # noqa: BLE001
        pass
    try:
        rec(tool, action, args=logged, ok=ok, error=error,
            extra={"status": status, "elapsed_ms": elapsed_ms})
    except TypeError:
        # Duck-typed test sessions without the ``extra`` kwarg.
        try:
            rec(tool, action, args=logged, ok=ok, error=error)
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001 - audit must never mask the call
        pass


def _arm_inflight_marker(ctx, tool: str, action: str,
                         args: dict[str, Any]):
    """Schedule the in-flight audit row; returns a handle to cancel."""
    sess = getattr(ctx, "session", None)
    write = getattr(sess, "audit_event", None)
    if write is None:
        return None
    try:
        from ....caller import current_client_id
        owner = current_client_id()
        loop = asyncio.get_running_loop()
    except Exception:  # noqa: BLE001
        return None
    import time as _time
    t0 = _time.time()

    def _mark() -> None:
        try:
            write({"tool": tool, "action": action, "args": dict(args or {}),
                   "owner": owner, "phase": "in_flight",
                   "started_ts": t0, "running_s": _INFLIGHT_AUDIT_S})
        except Exception:  # noqa: BLE001
            pass

    return loop.call_later(_INFLIGHT_AUDIT_S, _mark)


async def _guard(ctx, tool: str, action: str, args: dict[str, Any],
                 fn, *, kind: str | None = None) -> str:
    """Every `@mcp.tool` action funnels through here. Runs the allowlist
    gate, executes fn(), and wraps the result in the unified envelope
    (see `_envelope.py`). Exceptions become nested `{error: {error, kind,
    hint}}` failures via `envelope_err`.

    `kind` is the envelope's shape discriminator. Omit to derive from the
    action name (see `KIND_OVERRIDES` in `_envelope.py` for cross-tool
    aliases like `memory_manage|debug_manage|emulate_manage` -> kind="read").
    """
    import time as _time
    started = _time.monotonic()
    # exactly one tool-log/audit row per call, written in the
    # finally below whatever the outcome (ok / error / cancelled). The
    # error envelopes are therefore built with ctx=None (envelope_err would
    # otherwise record a second, args-less row). The lazy view stamp
    # (resolved AFTER fn(), a connect's name= is a new view) is kept.
    outcome: dict[str, Any] = {"ok": False, "error": "cancelled",
                               "status": "cancelled"}
    marker = _arm_inflight_marker(ctx, tool, action, args)
    try:
        return await _guard_body(ctx, tool, action, args, fn, kind=kind,
                                 started=started, outcome=outcome)
    finally:
        if marker is not None:
            marker.cancel()
        _audit_final(ctx, tool, action, args, ok=bool(outcome["ok"]),
                     error=str(outcome["error"] or ""),
                     status=str(outcome["status"]),
                     elapsed_ms=int((_time.monotonic() - started) * 1000))


async def _guard_body(ctx, tool: str, action: str, args: dict[str, Any],
                      fn, *, kind: str | None, started: float,
                      outcome: dict[str, Any]) -> str:
    import time as _time
    try:
        _check_actuator_trust(ctx, tool, action, args)
        ctx.session.assert_allowed(tool, action, args)
        result = await fn()
        outcome.update(ok=True, error="", status="ok")
    except (PermissionError, TargetNotAllowedError, IdaBridgeError,
            GhidraBridgeError, PluginError) as exc:
        env = _envelope_err(exc, tool=tool, action=action,
                            ctx=None, received_args=args)
        outcome.update(ok=False, error=_err_text(env), status="error")
        return _emit(_stamp_target(
            _stamp_provenance(env, tool, action), ctx, args), ctx=ctx)
    except Exception as exc:
        if isinstance(exc, AmbiguousTargetError):
            env = _envelope_err(exc, tool=tool, action=action, ctx=None,
                                received_args=args)
            env["kind"] = exc.kind
            env["machines"] = exc.machines
            env.setdefault("error", {})
            if isinstance(env["error"], dict):
                env["error"]["kind"] = exc.kind
                env["error"].setdefault("hint", exc.hint)
            outcome.update(ok=False, error=_err_text(env), status="error")
            # No view resolved - _stamp_target returns env unchanged.
            return _emit(_stamp_target(_stamp_provenance(env, tool, action),
                                       ctx, args), ctx=ctx)
        # T3.3: ConnectionRefusedError / grpc UNAVAILABLE from the
        # orchestrator-side plumbing surface as a dedicated
        # `orchestrator_unreachable` envelope BEFORE the generic
        # enrich_error path (which would otherwise classify them as
        # `channel_unavailable` and point at the agent).
        orch_dead = _classify_orchestrator_dead(exc)
        if orch_dead is not None:
            env = _envelope_err(exc, tool=tool, action=action, ctx=None,
                                received_args=args)
            if isinstance(env.get("error"), dict):
                env["error"]["kind"] = orch_dead["kind"]
                env["error"]["error"] = orch_dead["error"]
                env["error"]["hint"] = orch_dead["hint"]
            outcome.update(ok=False, error=_err_text(env), status="error")
            return _emit(_stamp_target(
                _stamp_provenance(env, tool, action), ctx, args), ctx=ctx)
        env = _envelope_err(exc, tool=tool, action=action, ctx=None,
                            received_args=args)
        outcome.update(ok=False, error=_err_text(env), status="error")
        return _emit(_stamp_target(
            _stamp_provenance(env, tool, action), ctx, args), ctx=ctx)
    elapsed_ms = int((_time.monotonic() - started) * 1000)
    return _emit(
        _stamp_target(
            _stamp_provenance(
                _coerce_to_envelope(
                    result, tool=tool, action=action, kind=kind,
                    elapsed_ms=elapsed_ms,
                ), tool, action),
            ctx, args),
        ctx=ctx,
        opts=_opts_from_args(args),
        request=args,
    )


async def _guard_pure(ctx, tool: str, action: str,
                      args: dict[str, Any], fn, *, kind: str | None = None) -> str:
    """Like _guard but skips assert_allowed — pure-compute tools have no
    target, so the allowlist gate is meaningless. Errors surface through the
    same unified envelope."""
    import time as _time
    from ...conversions import ConversionError
    started = _time.monotonic()
    try:
        result = await fn()
        ctx.session.record_tool_call(tool, action, args=args, ok=True)
    except ConversionError as exc:
        # ConversionError carries its own {kind, hint}; preserve them by
        # constructing the envelope directly rather than going through
        # `enrich_error` (which classifies from the raw string).
        ctx.session.record_tool_call(tool, action, ok=False, error=str(exc))
        env = {
            "ok": False,
            "kind": "error",
            "tool": tool,
            "action": action,
            "error": {"error": str(exc), "kind": exc.kind, "hint": exc.hint},
        }
        return _emit(_stamp_provenance(env, tool, action), ctx=ctx)
    except Exception as exc:
        # T3.3: pure-compute tools can still raise ConnectionRefusedError
        # if a sub-helper reaches out (e.g. symbols-store fetch); keep the
        # same `orchestrator_unreachable` surface as `_guard`.
        orch_dead = _classify_orchestrator_dead(exc)
        env = _envelope_err(exc, tool=tool, action=action, ctx=ctx,
                            received_args=args)
        if orch_dead is not None and isinstance(env.get("error"), dict):
            env["error"]["kind"] = orch_dead["kind"]
            env["error"]["error"] = orch_dead["error"]
            env["error"]["hint"] = orch_dead["hint"]
        return _emit(_stamp_provenance(env, tool, action), ctx=ctx)
    elapsed_ms = int((_time.monotonic() - started) * 1000)
    return _emit(
        _stamp_provenance(
            _coerce_to_envelope(
                result, tool=tool, action=action, kind=kind,
                elapsed_ms=elapsed_ms,
            ), tool, action),
        ctx=ctx,
        request=args,
    )


__all__ = [
    "_ACTUATOR_PAIRS",
    "_ORCH_UNREACHABLE_HINT",
    "_check_actuator_trust",
    "_classify_orchestrator_dead",
    "_guard",
    "_guard_pure",
]
