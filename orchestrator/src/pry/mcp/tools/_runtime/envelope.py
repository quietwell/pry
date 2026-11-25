"""Envelope coercion / finalize / emit.

Every tool call funnels through ``_emit`` on the way out. These helpers
bridge the per-tool `run()` return shapes (str / dict / scalar) into
the unified envelope, feed finalize + maybe_spill, stamp the
``target:`` view key when the answer is cross-machine, and retain
inventory names for later completion suggestions.
"""

from __future__ import annotations

import json
from typing import Any

from ..._envelope import (
    EnvelopeOpts as _EnvelopeOpts,
    envelope_err as _envelope_err,
    envelope_ok as _envelope_ok,
    envelope_from_result as _envelope_from_result,
    finalize as _envelope_finalize,
    resolve_kind as _resolve_kind,
    list_envelope as _list_envelope,
    warn as _envelope_warn,
)
from ..._spill import maybe_spill as _maybe_spill
from ..._provenance import stamp as _stamp_provenance

from .response import _j


def _coerce_to_envelope(result: Any, *, tool: str, action: str,
                        kind: str | None, elapsed_ms: int | None) -> dict:
    """Turn a tool `run()` result (str/dict/list/scalar) into an envelope.

    Handles the transitional shapes tool bodies still emit:
      * `_j(...)`-produced JSON strings (parsed back to a dict).
      * Legacy `{ok: False, error: "..."}` dicts (routed via envelope_err).
      * Legacy success dicts (wrapped under `data`).
    Once every tool body builds envelopes directly, this coercion is dead
    weight and gets removed."""
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return _envelope_ok(
                {"text": result},
                kind=_resolve_kind(tool, action, kind),
                tool=tool, action=action, elapsed_ms=elapsed_ms,
            )
        result = parsed
    return _envelope_from_result(
        result, tool=tool, action=action, kind=kind, elapsed_ms=elapsed_ms,
    )


def _opts_from_args(args: dict[str, Any] | None) -> _EnvelopeOpts:
    """Build finalize options from the tool call's own kwargs so a caller's
    ``verbosity`` / ``include_*`` / ``fields`` / ``max_bytes`` actually drive
    response shaping (row-collapse, mirror strips, projection, spill budget).

    Before this, ``_guard`` emitted with ``opts=None`` and ``finalize`` always
    ran at the hard-coded default ``verbosity="normal"`` — the per-call
    ``verbosity`` kwarg on every tool was silently ignored, so there was no
    way to opt into ``compact`` (or back out to ``full``/``raw``) through the
    live tool path. Unknown/missing keys fall back to the EnvelopeOpts
    defaults; a bad ``verbosity`` string degrades to ``normal``."""
    a = args or {}
    verb = str(a.get("verbosity") or "normal")
    if verb not in ("compact", "normal", "full", "raw"):
        verb = "normal"
    fields = a.get("fields") if isinstance(a.get("fields"), list) else []
    try:
        max_bytes = int(a.get("max_bytes") or 0)
    except (TypeError, ValueError):
        max_bytes = 0
    return _EnvelopeOpts(
        verbosity=verb,
        max_bytes=max_bytes,
        fields=[str(f) for f in fields],
        filter=a.get("filter") or "",
        include_ascii=bool(a.get("include_ascii")),
        include_int=bool(a.get("include_int")),
        include_decoded=bool(a.get("include_decoded")),
    )


def _emit(env: dict, *, ctx=None,
          opts: _EnvelopeOpts | None = None,
          request: dict | None = None) -> str:
    """Final step: finalize (hex/decode/size), auto-spill oversize payloads,
    then JSON-encode. Every envelope produced by _guard / _guard_pure funnels
    through here on its way out.

    Spill is skipped when ctx is None (the pure builders in tests) or when
    the caller passed `verbosity="raw"` / `max_bytes=-1`.

    Part 3: `request` (the post-binding args from _guard) feeds the
    evidence retention on spill — None on legacy call sites, which keep
    the exact pre-evidence behavior."""
    _envelope_finalize(env, opts=opts)
    if ctx is not None and env.get("kind") != "error":
        cfg = ctx.cfg
        budget = int(opts.max_bytes) if (opts and opts.max_bytes) else cfg.mcp_max_bytes()
        if budget > 0:
            # Evidence retention wiring (Part 3): stub cfgs (tests) may
            # not implement artifacts_dir — then no retention happens.
            _art_dir = getattr(cfg, "artifacts_dir", None)
            _maybe_spill(
                env,
                budget_bytes=budget,
                spill_dir=cfg.spill_dir(),
                preview_bytes=cfg.mcp_preview_bytes(),
                artifacts_root=_art_dir() if callable(_art_dir) else None,
                ledger=getattr(ctx, "ledger", None),
                request=request,
            )
            # Refresh size_bytes after spill.
            try:
                env.setdefault("summary", {})["size_bytes"] = len(
                    json.dumps(env, default=str)
                )
            except (TypeError, ValueError):
                pass
    if ctx is not None and env.get("kind") != "error":
        _retain_inventory_from_env(ctx, env)
    _agent_postprocess(env)
    return _j(env)


# Background-job starts -> the calls that follow them. Every job family
# grew its own verbs (scan_*, find_*, detached_*, follow_*, ...); instead
# of renaming them, each start response carries a ready-to-run ``next``
# block: ``{poll|result|cancel: {tool, action, args}}``. Values:
# (id key in data, poll, result, cancel); each step is (action, param).
_JOB_NEXT: dict[tuple[str, str], tuple] = {
    ("memory_manage", "scan_start"): (
        "scan_id", ("scan_status", "scan_id"), ("scan_result", "scan_id"),
        ("scan_cancel", "scan_id")),
    ("memory_manage", "pointer_map_create"): (
        "map_id", ("pointer_map_status", "map_id"), None,
        ("pointer_map_cancel", "map_id")),
    ("memory_manage", "watch"): (
        "watch_id", ("watch_list", None), None, ("watch_stop", "watch_id")),
    ("object_manage", "find"): (
        "scan_id", ("find_status", "scan_id"), ("find_result", "scan_id"),
        ("find_cancel", "scan_id")),
    ("debug_manage", "access_trace_start"): (
        "job_id", ("access_trace_status", "job_id"), None,
        ("access_trace_stop", "job_id")),
    ("exec_manage", "run_detached"): (
        "handle_id", ("detached_status", "handle_id"),
        ("detached_tail", "handle_id"), ("detached_kill", "handle_id")),
    ("file_manage", "follow_start"): (
        "follow_id", ("follow_poll", "follow_id"), None,
        ("follow_stop", "follow_id")),
    ("script_manage", "submit"): (
        "job_id", ("status", "job_id"), None, ("cancel", "job_id")),
    ("event_manage", "subscribe"): (
        "subscription_id", ("poll", "subscription_id"), None,
        ("unsubscribe", "subscription_id")),
    ("bin_manage", "analyze"): (
        "job_id", ("analyze_status", "job_id"), None, None),
}


def _job_next(tool: str, action: str, data: Any) -> dict | None:
    spec = _JOB_NEXT.get((tool, action))
    if spec is None or not isinstance(data, dict):
        return None
    id_key, *steps = spec
    job_id = data.get(id_key)
    if not job_id or not isinstance(job_id, (str, int)):
        return None
    out: dict[str, dict] = {}
    for label, step in zip(("poll", "result", "cancel"), steps):
        if step is None:
            continue
        verb, param = step
        args: dict[str, Any] = {"action": verb}
        if param:
            args[param] = job_id
        out[label] = {"tool": tool, "action": verb, "args": args}
    return out or None


def _agent_postprocess(env: dict) -> None:
    """Last-step stamps every response gets (never raises):

    * forwarded verbs report the *public* tool/action the caller used
      (``process_manage list`` used to answer as ``memory_manage
      process_list``);
    * error bodies carry a coarse ``class`` + ``retryable`` next to the
      fine-grained ``kind`` (see :mod:`pry.mcp._error_class`);
    * background-job starts carry ``next`` (see :data:`_JOB_NEXT`).
    """
    try:
        from .surface import CALL_INFO
        info = CALL_INFO.get()
    except Exception:  # noqa: BLE001
        info = None
    try:
        if info and info.get("tool") and env.get("tool"):
            if env["tool"] != info["tool"]:
                env["tool"] = info["tool"]
                if info.get("action"):
                    env["action"] = info["action"]
            elif (info.get("action") and env.get("action")
                    and env["action"] != info["action"]):
                # Same public tool, internal verb (process_manage get
                # answered as action='process_list').
                env["action"] = info["action"]
        err = env.get("error")
        if env.get("ok") is False and isinstance(err, dict) and err.get("kind"):
            from ..._error_class import classify
            cls, retryable = classify(str(err["kind"]))
            err.setdefault("class", cls)
            err.setdefault("retryable", retryable)
        if env.get("ok") is True and "next" not in env:
            nxt = _job_next(str(env.get("tool") or ""),
                            str(env.get("action") or ""), env.get("data"))
            if nxt:
                env["next"] = nxt
    except Exception:  # noqa: BLE001 — cosmetic stamps never mask a result
        pass


# (tool, action) -> (completion kind, candidate name fields). When one of
# these actions returns successfully, its row names are stashed on the
# Context so the MCP `completion/complete` handler can suggest them later
# (completions._retained reads ctx._retained_inventories[kind]). An EMPTY
# stash still means "nothing retained", never "does not exist".
_INVENTORY_PRODUCERS: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {
    ("memory_manage", "modules"):        ("module", ("name",)),
    ("memory_manage", "obj_enum"):       ("device", ("name", "path")),
    ("symbols_manage", "enum_info"): ("symbol", ("name",)),
}

# Cap retained names per kind so a huge enumeration can't grow the Context
# without bound; completion caps at 100 anyway.
_RETAIN_CAP = 500


def _retain_inventory_from_env(ctx, env: dict) -> None:
    """Best-effort: stash row names from an inventory-producing action so
    argument completion can suggest them. Never raises — a shape it does
    not recognize (spilled payload, scalar result) is simply skipped."""
    spec = _INVENTORY_PRODUCERS.get((env.get("tool"), env.get("action")))
    if spec is None:
        return
    kind, name_fields = spec
    data = env.get("data")
    rows = data.get("items") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return  # summary=true / spilled payload / unexpected shape
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for f in name_fields:
            v = row.get(f)
            if v:
                names.append(str(v))
                break
    if not names:
        return
    try:
        store = getattr(ctx, "_retained_inventories", None)
        if not isinstance(store, dict):
            store = {}
            ctx._retained_inventories = store
        store[kind] = names[:_RETAIN_CAP]
    except Exception:  # noqa: BLE001 — retention is pure DX, never fatal
        pass


def _resolve_stamp(ctx, args: dict) -> dict | None:
    """Best-effort `session.target_stamp` for the call's ``name=`` arg —
    None on any failure (older test doubles have no ``target_stamp``)."""
    name = str((args or {}).get("name") or "")
    try:
        return ctx.session.target_stamp(name) if ctx.session else None
    except Exception:
        return None


# Tools whose ``name=`` param is not a target view (see param_docs).
_NAME_NOT_VIEW_TOOLS = frozenset({"script_manage", "ida_manage",
                                  "ghidra_manage", "symbols_manage",
                                  "machines_manage"})


def _stamp_target(env: dict, ctx, args: dict) -> dict:
    """Attach the minimal identity stamp: a BARE view key
    ('lab2.kernel'), and only when the answer could be attributed to the
    wrong box (more than one view connected, or not the caller's focus
    machine — see Session.stamp_needed). Single-view sessions carry no
    stamp at all. Full machine identity (trust/purpose/notes/endpoints)
    arrives once per machine on first connect (machine_info) and on
    demand via target_manage(action='machines')."""
    sess = getattr(ctx, "session", None)
    if sess is None:
        return env
    tool = str(env.get("tool") or "")
    if tool in _NAME_NOT_VIEW_TOOLS:
        # name= is a plugin / IDA session / machine there, not a view;
        # stamping it would attribute e.g. a plugin called 'user' to the
        # user view. symbols_manage takes its view as view=.
        if tool != "symbols_manage":
            return env
        name = str((args or {}).get("view") or "")
    else:
        name = str((args or {}).get("name") or "")
        if not name and "name" not in (args or {}):
            # Several tools build a hand-picked args dict without name=
            # (file_manage, exec_manage, ...); without this the stamp fell
            # back to the focus view and could name the wrong one.
            try:
                from .surface import CALL_INFO
                info = CALL_INFO.get() or {}
                if info.get("tool") == tool:
                    name = str((info.get("args") or {}).get("name") or "")
            except Exception:  # noqa: BLE001 — stamping is cosmetic
                name = ""
    try:
        key = sess.resolve_view_name(name)
        if not key or key not in sess.clients:
            return env
        if not sess.stamp_needed(key):
            return env
        env.setdefault("target", key)
    except Exception:
        return env
    return env


__all__ = [
    "_EnvelopeOpts",
    "_envelope_err",
    "_envelope_ok",
    "_envelope_from_result",
    "_envelope_finalize",
    "_resolve_kind",
    "_list_envelope",
    "_envelope_warn",
    "_maybe_spill",
    "_stamp_provenance",
    "_coerce_to_envelope",
    "_opts_from_args",
    "_emit",
    "_INVENTORY_PRODUCERS",
    "_RETAIN_CAP",
    "_retain_inventory_from_env",
    "_resolve_stamp",
    "_stamp_target",
]
