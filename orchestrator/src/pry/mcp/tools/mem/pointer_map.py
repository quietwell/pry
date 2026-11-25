"""Pointer map + reverse-scan + diff handlers for ``memory_manage``
(v17, Memory scanner wave 2 Phase G).

Thin orchestrator-side wrappers around :class:`PointerMapMixin`
(``orchestrator/src/pry/agent_client/pointer_map.py``). The
routing + envelope shape mirrors :mod:`.scan`.

Phase B-K agents advertise ``pointer_map_version == 0``; the router
refuses with ``kind='needs_v17'`` so the MCP caller gets a clean,
hint-carrying error instead of an UNIMPLEMENTED gRPC transport
exception. Phase L flips the advert on the live target and routing
reaches the on-target service.
"""
from __future__ import annotations

import logging
from typing import Any

from .._runtime.response import _hexify_dict, _j


log = logging.getLogger("pry.mcp.tools.mem")

# once-per-session WARN gate for
# the v17 cache-lookup broad-except fallback. ``True`` after we've
# logged once so the log tail doesn't drown in repeats.
_v17_gate_warn_logged = False

# Caps mirrored from the agent's plan §2.7. Kept in sync via the
# shared plan doc; the preflight here is conservative.
POINTER_MAP_CANDIDATE_MAX = 268_435_456          # 2^28
POINTER_MAP_SPAN_BYTES_MAX = POINTER_MAP_CANDIDATE_MAX * 8  # plan §5


def _needs_v17_envelope(action: str) -> str:
    env = {
        "ok": False,
        "kind": "needs_v17",
        "tool": "memory_manage",
        "action": action,
        "error": (f"{action}: this view's agent does not advertise "
                  "pointer_map_version>=1 (pre-v17 or Phase C-K build). "
                  "Rebuild + redeploy the agent per README \"ABI v17 "
                  "rebuild\"."),
        "hint": ("Flip services_agent.cpp/um_services.cpp's "
                 "set_pointer_map_version to 1 after build-verify "
                 "(plan §2.3 / §4 Phase L), then redeploy."),
    }
    return _j(env)


def _would_exceed_envelope(action: str, span_total: int,
                           cap: int) -> str:
    """Refuse pointer_map_create when the predicted candidate budget
    would overrun. Plan §5 pins the shape; the operator flips
    machines.<name>.pointer_map.max_candidates to raise the cap."""
    env = {
        "ok": False,
        "kind": "would_exceed",
        "tool": "memory_manage",
        "action": action,
        "error": (f"{action}: span total {span_total} bytes would "
                  f"exceed the predicted candidate budget "
                  f"({cap} bytes). Narrow the scope / sections, or "
                  "raise the cap."),
        "hint": ("tighten scope= / sections= / module= / writable= / "
                 "executable= / mem_types=, or set "
                 "machines.<name>.pointer_map.max_candidates "
                 "(plan §2.7, §2.11)."),
    }
    return _j(env)


def _map_agent_error_kind(err: str, *, agent_kind: str = "") -> str | None:
    """Translate an agent-side ``data.error`` string into a named ``kind=``.

    Returns None when nothing matches (caller leaves ``kind='pointer_map'``).

    A newer agent may set
    ``OpStatus.kind`` directly; the orchestrator trusts the typed slug
    over substring matching whenever it's non-empty. Older agents
    leave it empty and the substring fallback still runs.
    """
    if agent_kind:
        return agent_kind
    if not err:
        return None
    s = err.lower()
    if "too many chains" in s or "too_many_chains" in s:
        return "too_many_chains"
    if "pointer_map_full" in s or "pointer_map full" in s:
        return "pointer_map_full"
    if "map_id already exists" in s:
        return "duplicate_map_id"
    if "map_id already registered" in s:
        return "duplicate_map_id"
    if "map not found" in s:
        return "map_not_found"
    if "map not mmap" in s:
        return "map_not_mmapd"
    if "space mismatch" in s:
        return "wrong_view"
    if "pid mismatch" in s:
        return "pid_mismatch"
    if "size mismatch" in s or "not a multiple of" in s:
        return "corrupted_map"
    if "core file missing" in s:
        return "incomplete_map"
    if "map not terminal" in s:
        return "map_not_ready"
    return None


def _pointer_map_version(ctx, name: str) -> int:
    """Return the cached pointer_map_version for a view key / machine
    label. 0 means pre-v17 or Phase C-K agent. Mirrors
    :func:`_agent_abi_from_session` in value_scan.py."""
    global _v17_gate_warn_logged
    try:
        sess = ctx.session
        info_map = sess._machine_info or {}
        view = name or ""
        if not view and hasattr(sess, "focus_view"):
            view = sess.focus_view()
        info = info_map.get(view)
        if info:
            return int(info.get("pointer_map_version") or 0)
        if hasattr(sess, "machine_of") and name:
            machine = sess.machine_of(name)
            for k, v in info_map.items():
                key_machine = (sess.machine_of(k)
                               if hasattr(sess, "machine_of") else k)
                if key_machine == machine:
                    ver = int((v or {}).get("pointer_map_version") or 0)
                    if ver >= 1:
                        return ver
        return 0
    except Exception:
        # warn once per session
        # on the broad-except fallback. Previously it silently returned 0
        # so operators who tripped a KeyError / stale session saw
        # "fallback mode" with no log hint.
        if not _v17_gate_warn_logged:
            log.warning("_pointer_map_version: session cache lookup raised; "
                        "falling back to version=0 (pre-v17 behaviour) for "
                        "name=%r. Subsequent occurrences will be silent.",
                        name)
            _v17_gate_warn_logged = True
        return 0


def _wrap(action: str, data: dict[str, Any], *, view: str = "") -> str:
    ok = bool(data.get("ok", True))
    kind: str = "pointer_map"
    agent_kind = str(data.get("agent_kind") or "")
    if not ok:
        agent_err = str(data.get("error") or "")
        mapped = _map_agent_error_kind(agent_err, agent_kind=agent_kind)
        if mapped:
            kind = mapped
    # disambiguated truncation
    # cause. The agent sets ``wall_exceeded`` / ``fanout_exceeded``
    # directly; older agents leave both at False and we fall
    # back to the "any truncation = unknown-cause" heuristic (which
    # was the earlier default for everything but wall_ms_actual>0).
    if ok and action in ("pointer_scan", "pointer_map_diff"):
        if bool(data.get("truncated")):
            wall_exceeded = bool(data.get("wall_exceeded"))
            fanout_exceeded = bool(data.get("fanout_exceeded"))
            if wall_exceeded:
                kind = "wall_ms_exceeded"
            elif fanout_exceeded:
                kind = "fanout_exceeded"
            else:
                # Older agent: neither bool is populated, so we
                # cannot safely distinguish the two causes. Emit a
                # neutral kind so callers at least know truncation
                # happened.
                kind = "scan_truncated"
    env = {
        "ok": ok,
        "kind": kind,
        "tool": "memory_manage",
        "action": action,
        "data": {k: v for k, v in data.items() if k not in ("ok",)},
    }
    if view:
        env["target"] = view
    return _j(_hexify_dict(env, add_int_mirror=True))


# -------------------------------------------- pointer_map_create ------------

async def handle_pointer_map_create(ctx, c, *, pid: int,
                                    spans: list[tuple[int, int]],
                                    space: str, name: str,
                                    max_candidates: int = 0,
                                    disk_spill_mode: str = "auto",
                                    map_id: str = "") -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_map_create")
    # Orchestrator-side preflight: refuse early with kind='would_exceed'
    # when the span total is clearly beyond the agent's candidate
    # budget. Matches plan §5's "span total × worst-case-pointer-
    # density > CANDIDATE_MAX × 8" check with worst-case density of
    # 1/8 (every aligned slot is a pointer).
    span_total = sum(int(sz) for _, sz in (spans or []))
    if span_total > POINTER_MAP_SPAN_BYTES_MAX:
        return _would_exceed_envelope("pointer_map_create",
                                       span_total,
                                       POINTER_MAP_SPAN_BYTES_MAX)
    result = await c.pointer_map_create(
        map_id=map_id, pid=pid, space=space, spans=spans,
        max_candidates=max_candidates,
        disk_spill_mode=disk_spill_mode)
    return _wrap("pointer_map_create", result, view=name)


async def handle_pointer_map_status(ctx, c, *, name: str,
                                    map_id: str) -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_map_status")
    result = await c.pointer_map_status(map_id=map_id)
    return _wrap("pointer_map_status", result, view=name)


async def handle_pointer_map_list(ctx, c, *, name: str) -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_map_list")
    result = await c.pointer_map_list()
    return _wrap("pointer_map_list", result, view=name)


async def handle_pointer_map_cancel(ctx, c, *, name: str,
                                    map_id: str) -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_map_cancel")
    result = await c.pointer_map_cancel(map_id=map_id)
    return _wrap("pointer_map_cancel", result, view=name)


async def handle_pointer_map_save(ctx, c, *, name: str,
                                  map_id: str,
                                  remote_path: str) -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_map_save")
    result = await c.pointer_map_save(map_id=map_id,
                                      remote_path=remote_path)
    return _wrap("pointer_map_save", result, view=name)


async def handle_pointer_map_load(ctx, c, *, name: str,
                                  remote_path: str,
                                  map_id: str = "") -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_map_load")
    result = await c.pointer_map_load(remote_path=remote_path,
                                      map_id=map_id)
    return _wrap("pointer_map_load", result, view=name)


async def handle_pointer_map_destroy(ctx, c, *, name: str,
                                     map_id: str,
                                     keep_disk: bool = False) -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_map_destroy")
    result = await c.pointer_map_destroy(map_id=map_id,
                                          keep_disk=keep_disk)
    return _wrap("pointer_map_destroy", result, view=name)


async def _decorate_pointer_scan_chains(
        ctx, *, view: str, pid: int,
        result: dict[str, Any]) -> None:
    """Stamp ``anchor_sym`` on each chain of a ``pointer_scan`` result
    using the SymbolDecorator (plan §5 — single ``lookup_batch`` for
    every anchor_va in the response). In place; never raises — a
    backend failure or missing PDB coverage just leaves the chains
    undecorated. Future ABI versions that materialize per-hop VAs
    (``chain.hops[]``) fold in without a signature change here."""
    if not isinstance(result, dict):
        return
    chains = result.get("chains")
    if not isinstance(chains, list) or not chains:
        return
    if not view:
        return
    try:
        from ._decorate import SymbolDecorator
    except Exception:  # noqa: BLE001 - decoration is advisory
        log.exception("pointer_scan decoration: _decorate import failed")
        return
    anchor_vas: list[int] = []
    for ch in chains:
        if not isinstance(ch, dict):
            continue
        a = ch.get("anchor_va")
        if isinstance(a, int) and a:
            anchor_vas.append(int(a))
        hops = ch.get("hops")
        if isinstance(hops, list):
            for h in hops:
                if isinstance(h, dict):
                    v = h.get("va")
                    if isinstance(v, int) and v:
                        anchor_vas.append(int(v))
    if not anchor_vas:
        return
    try:
        dec = SymbolDecorator(ctx)
        labels = await dec.decorate_vas(view, pid, anchor_vas)
    except Exception:  # noqa: BLE001 - decoration never fails the parent
        log.exception("pointer_scan decoration: decorate_vas raised")
        return
    for ch in chains:
        if not isinstance(ch, dict):
            continue
        a = ch.get("anchor_va")
        if isinstance(a, int) and a:
            lbl = labels.get(int(a))
            if lbl:
                ch["anchor_sym"] = lbl
        hops = ch.get("hops")
        if isinstance(hops, list):
            for h in hops:
                if not isinstance(h, dict):
                    continue
                v = h.get("va")
                if isinstance(v, int) and v:
                    lbl = labels.get(int(v))
                    if lbl:
                        h["hop_sym"] = lbl


async def handle_pointer_scan(ctx, c, *, name: str,
                              map_id: str, target_va: int,
                              max_depth: int = 0, max_offset: int = 0,
                              static_only: bool = True,
                              max_results: int = 0,
                              fanout_per_level: int = 0,
                              wall_ms: int = 0,
                              # Wave 3 Phase D: symbol decoration opt-out.
                              decorate: bool = True,
                              pid: int = 0) -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_scan")
    result = await c.pointer_scan(
        map_id=map_id, target_va=target_va,
        max_depth=max_depth, max_offset=max_offset,
        static_only=static_only, max_results=max_results,
        fanout_per_level=fanout_per_level, wall_ms=wall_ms)
    if decorate and bool(result.get("ok", True)):
        await _decorate_pointer_scan_chains(ctx, view=name, pid=pid,
                                             result=result)
    return _wrap("pointer_scan", result, view=name)


async def handle_pointer_map_diff(ctx, c, *, name: str,
                                  map_id_a: str, map_id_b: str,
                                  static_only: bool = True,
                                  chains: list[dict[str, Any]] | None = None,
                                  ) -> str:
    if _pointer_map_version(ctx, name) < 1:
        return _needs_v17_envelope("pointer_map_diff")
    result = await c.pointer_map_diff(
        map_id_a=map_id_a, map_id_b=map_id_b,
        static_only=static_only, chains=chains)
    return _wrap("pointer_map_diff", result, view=name)
