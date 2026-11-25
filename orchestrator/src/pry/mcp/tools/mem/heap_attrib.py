"""HeapAttrib handler for ``memory_manage`` (Memory scanner wave 3 P2).

Composes :meth:`AgentClient.heap_attrib` — the agent-side
``Memory.HeapAttribLookup`` — with:

* a per-call feature gate on
  ``StatusResponse.memory_heap_attrib_version >= 1`` so callers on a
  older agent (or on the umagent view, which has no WalkHeaps
  wiring) see ``kind='feature_unavailable'`` instead of an
  ``UNIMPLEMENTED`` gRPC transport exception;
* orchestrator-side input validation (``pid`` required, ``vas``
  non-empty, ``vas`` within ``HEAPATTRIB_MAX_VAS`` cap) so the
  typical bad-input case never leaves the orchestrator;
* a scalar/``va=`` convenience: callers can pass a single address as
  ``va=`` and the response still comes back record-wise.

See an internal plan §7 for the full
contract.
"""
from __future__ import annotations

import logging
from typing import Any

from .._runtime.response import _hexify_dict, _j


log = logging.getLogger("pry.mcp.tools.mem")

# Mirrors ``agent/src/pe/heap_walker.hpp`` HEAPATTRIB_MAX_VAS. Kept in
# lock-step via this chunk's proto test, which asserts the constant
# against the plan.
HEAPATTRIB_MAX_VAS = 4096

# once-per-session WARN gate for the
# version-cache broad-except fallback — mirrors the
# ``_v17_gate_warn_logged`` pattern in ``pointer_map.py``.
_version_gate_warn_logged = False


def _feature_unavailable_envelope() -> str:
    env = {
        "ok": False,
        "kind": "feature_unavailable",
        "tool": "memory_manage",
        "action": "heap_attrib",
        "error": ("heap_attrib: this view does not advertise "
                  "memory_heap_attrib_version>=1. The verb lives on "
                  "the kernel-agent view; the umagent view has no "
                  "WalkHeaps wiring. Rebuild + redeploy the agent per "
                  "the Wave 3 P2 note in README."),
        "hint": ("flip set_memory_heap_attrib_version to 1 on the "
                 "view(s) with the handler registered after "
                 "build-verify, then redeploy. On umagent, use the "
                 "kernel-agent view instead."),
    }
    return _j(env)


def _heap_attrib_version(ctx, name: str) -> int:
    """Return the cached ``memory_heap_attrib_version`` for a view key
    or bare machine label. 0 means an older agent or the umagent view.

    Mirrors ``_pointer_map_version`` / ``_dissect_version`` structure —
    same broad-except warn-once fallback so a stale session cache
    doesn't silently flip callers to the refusal path with no log
    hint.
    """
    global _version_gate_warn_logged
    try:
        sess = ctx.session
        info_map = sess._machine_info or {}
        view = name or ""
        if not view and hasattr(sess, "focus_view"):
            view = sess.focus_view()
        info = info_map.get(view)
        if info:
            return int(info.get("memory_heap_attrib_version") or 0)
        # Bare-machine-name path — scan every view on the machine for
        # one that advertises the feature. (The handler is kernel-only
        # today, but this future-proofs a hypothetical umagent port.)
        if hasattr(sess, "machine_of") and name:
            machine = sess.machine_of(name)
            for k, v in info_map.items():
                key_machine = (sess.machine_of(k)
                               if hasattr(sess, "machine_of") else k)
                if key_machine == machine:
                    ver = int(
                        (v or {}).get("memory_heap_attrib_version") or 0)
                    if ver >= 1:
                        return ver
        return 0
    except Exception:  # noqa: BLE001 — session cache shape is best-effort
        if not _version_gate_warn_logged:
            log.warning(
                "_heap_attrib_version: session cache lookup raised; "
                "falling back to version=0 (feature_unavailable) for "
                "name=%r. Subsequent occurrences will be silent.",
                name)
            _version_gate_warn_logged = True
        return 0


def _wrap(data: dict[str, Any], *, view: str = "") -> str:
    ok = bool(data.get("ok", True))
    kind: str = "heap_attrib"
    if not ok:
        existing_kind = str(data.get("kind") or "")
        agent_kind = str(data.get("agent_kind") or "")
        if existing_kind:
            kind = existing_kind
        elif agent_kind:
            kind = agent_kind
    env = {
        "ok": ok,
        "kind": kind,
        "tool": "memory_manage",
        "action": "heap_attrib",
        "data": {k: v for k, v in data.items() if k not in ("ok", "kind")},
    }
    if view:
        env["target"] = view
    return _j(_hexify_dict(env, add_int_mirror=True))


def _coerce_va(v: Any) -> int:
    if isinstance(v, bool):  # bool is int — reject before the int coerce
        raise ValueError("va must be an integer, not bool")
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v:
        return int(v, 0)
    raise ValueError(f"va: unparseable value {v!r}")


async def handle_heap_attrib(
    ctx, c,
    *,
    pid: int,
    va: Any = 0,
    vas: list[Any] | None = None,
    refresh: bool = False,
    name: str = "",
) -> str:
    """``memory_manage(action='heap_attrib', ...)`` dispatcher.

    Accepts either a single ``va=`` (scalar) or a ``vas=[...]`` list
    for ergonomic parity — internally always goes to the agent as a
    batch. See the module docstring for the response envelope.
    """
    # ---- input validation (orchestrator-side so the agent never sees
    # the bad-call case, matching the plan's "refuse pid=0 with
    # kind='bad_arg'" clause) ----
    if int(pid or 0) == 0:
        return _wrap({
            "ok": False,
            "kind": "bad_arg",
            "error": "heap_attrib: pid > 0 required",
            "hint": ("pass the target pid; the agent indexes heap "
                     "attribution per-process."),
            "records": [],
        }, view=name)

    # Merge scalar va + list vas into a single input list, deduped in
    # order (repeated VAs are a legitimate caller tactic for cache
    # probes, so we keep them — just reject the empty-batch case).
    merged: list[int] = []
    try:
        if va:
            merged.append(_coerce_va(va))
        if vas:
            for v in vas:
                merged.append(_coerce_va(v))
    except ValueError as exc:
        return _wrap({
            "ok": False,
            "kind": "bad_arg",
            "error": f"heap_attrib: {exc}",
            "records": [],
        }, view=name)

    if not merged:
        return _wrap({
            "ok": False,
            "kind": "bad_arg",
            "error": ("heap_attrib: pass at least one VA via va= or "
                      "vas=[...]"),
            "records": [],
        }, view=name)

    if len(merged) > HEAPATTRIB_MAX_VAS:
        return _wrap({
            "ok": False,
            "kind": "too_many_vas",
            "error": (f"heap_attrib: vas count {len(merged)} exceeds "
                      f"the per-call cap {HEAPATTRIB_MAX_VAS}"),
            "hint": ("page the batch orchestrator-side or raise the "
                     "agent cap (HEAPATTRIB_MAX_VAS in "
                     "heap_walker.hpp)."),
            "records": [],
        }, view=name)

    # ---- feature gate ----
    if _heap_attrib_version(ctx, name) < 1:
        return _feature_unavailable_envelope()

    # ---- happy path ----
    res = await c.heap_attrib(pid=int(pid), vas=merged, refresh=bool(refresh))
    return _wrap(res, view=name)
