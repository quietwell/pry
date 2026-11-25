"""``process_manage`` — canonical process-inventory tool.

Taxonomy brief §5.1: ``list``, ``get``, ``mitigations``, ``hidden``,
``kill``, ``suspend``, ``resume``, ``actions``.

Handlers moved from ``mem/processes.py``, ``mem/hidden_proc.py`` and
``exec_.py``'s kill/suspend/resume branches. ``mitigations`` is slice
01 Feature 6 — ``handle_mitigations`` + ``_enrich_mitigations`` below
cover the single-pid readout and the ``verify_mitigations=True``
list-enrichment fan-out.

Capability registry (``_runtime/capabilities.py``) is the single source
of truth for the ``(tool, action)`` matrix; the legacy ``memory_manage`` +
``exec_manage`` dispatch sites forward via the ALIASES table and attach
the ``deprecated: {replacement, remove_in}`` block to the envelope.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .mem import hidden_proc as _mem_hidden_proc
from .mem import processes as _mem_processes
from .._coverage import coverage as _coverage


PROCESS_ACTIONS = [
    "list", "get", "mitigations", "hidden",
    "kill", "suspend", "resume",
    "actions",
]


def _rewrite_process_get_taxonomy(result: Any) -> Any:
    """post-rewrite the ``tool`` / ``kind`` fields on a
    ``handle_process_list`` envelope so ``process_manage(action='get')``
    self-identifies correctly.

    ``handle_process_list`` (the shared single-pid helper) stamps the
    envelope as ``memory_manage / process_list`` since it was pulled
    out of the legacy ``memory_manage`` dispatch tree. Mutating in
    place after the fact keeps the helper single-sourced and the
    taxonomy honest in telemetry + the response envelope.

    Accepts either a FastMCP :class:`ToolResult` (whose
    ``structured_content`` is the live dict) or a JSON-encoded string
    (the ``json.dumps`` branch of :func:`_j`). Unknown shapes are
    passed through unchanged."""
    import json as _json

    def _mutate(body: dict) -> None:
        body["tool"] = "process_manage"
        body["kind"] = "process_info"

    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        _mutate(sc)
        return result
    if isinstance(result, dict):
        _mutate(result)
        return result
    if isinstance(result, str):
        try:
            parsed = _json.loads(result)
        except (ValueError, TypeError):
            return result
        if isinstance(parsed, dict):
            _mutate(parsed)
            return _j(parsed)
    return result


_PROCESS_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "process_manage(action='actions')"},
    "list": {"one_liner": ("process inventory + optional cmdline/context + "
                           "opt-in mitigations enrichment "
                           "(verify_mitigations=true fans out one "
                           "GetProcessMitigationPolicy per row)"),
             "key_args": ("with_cmdline, verify_mitigations, "
                          "mitigations_cache_only, filter, fields, "
                          "summary, limit, offset"),
             "example": "process_manage(action='list', verify_mitigations=True)"},
    "get": {"one_liner": "single-process identity + protection + session + "
                         "signature summary",
            "key_args": "pid",
            "example": "process_manage(action='get', pid=4812)"},
    "mitigations": {"one_liner": ("authoritative GetProcessMitigationPolicy "
                                  "readout (DEP/ASLR/CFG/ShadowStack/...). "
                                  "Older agents degrade to "
                                  "kind='agent_version'. PPL targets on the "
                                  "umagent view surface "
                                  "mitigations_source='denied'; the agent "
                                  "view routes via Wave-1 HANDLE_DUP for "
                                  "coverage asymmetry (slice 01 Feature 6)."),
                    "key_args": "pid, force_recheck, name",
                    "example": "process_manage(action='mitigations', pid=4812)"},
    "hidden": {"one_liner": "hidden-process detection "
                            "(brute/registry/etw modes)",
               "key_args": "modes, pid_max, step, timeout_s",
               "example": "process_manage(action='hidden', "
                          "modes=['brute','registry','etw'])"},
    "kill": {"one_liner": "terminate a process (actuator-trust gated)",
             "key_args": "pid, name",
             "example": "process_manage(action='kill', pid=4812)"},
    "suspend": {"one_liner": "freeze every thread in a process",
                "key_args": "pid, name",
                "example": "process_manage(action='suspend', pid=4812)"},
    "resume": {"one_liner": "unfreeze every thread in a process",
               "key_args": "pid, name",
               "example": "process_manage(action='resume', pid=4812)"},
}


# ----------------------------------------------------------------------
# Feature 6 — mitigations verb body (slice 01)
# ----------------------------------------------------------------------


async def handle_mitigations(ctx, c, *, pid: int,
                             force_recheck: bool = False) -> str:
    """Single-pid mitigation readout. Calls
    ``Mitigations.GetMitigationPolicy`` via the agent_client mixin and
    returns the flattened per-row dict as the response envelope. The
    envelope's ``coverage`` block names the PPL asymmetry when the row
    carries ``mitigations_source='denied'``.
    """
    if not pid or int(pid) <= 0:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "mitigations: pid must be a positive integer",
                   "hint": "pass pid=<target_pid>"})
    res = await c.verify_mitigations([int(pid)],
                                     force_recheck=bool(force_recheck))
    if not res.get("ok"):
        kind = str(res.get("kind") or "verify_mitigations_failed")
        env: dict[str, Any] = {
            "ok": False, "kind": kind,
            "error": res.get("error", "verify_mitigations failed"),
        }
        if res.get("hint"):
            env["hint"] = res["hint"]
        return _j(env)
    rows = res.get("rows") or []
    if not rows:
        return _j({
            "ok": False, "kind": "no_rows",
            "error": "mitigations: agent returned no row for the requested pid",
            "hint": ("the target may have exited between the request and the "
                     "GetProcessMitigationPolicy call"),
        })
    row = rows[0]
    out = dict(row)
    out["ok"] = True
    source = str(row.get("mitigations_source") or "live")
    if source == "denied":
        out["coverage"] = _coverage("mitigations", "partial", "denied_ppl")
    elif row.get("error"):
        out["coverage"] = _coverage("mitigations", "partial",
                                    "mitigations_class_failed")
    else:
        out["coverage"] = _coverage("mitigations", "complete")
    out["summary"] = {
        "cache_hit": bool(row.get("cache_hit")),
        "cache_hits": int(res.get("cache_hits") or 0),
        "probed": int(res.get("probed") or 0),
    }
    return _j(out)


# ----------------------------------------------------------------------
# Feature 6 — list enrichment helper (verify_mitigations=True)
# ----------------------------------------------------------------------


# LRU for the orchestrator-side ``mitigations_cache_only=True`` short-
# circuit. The agent/umagent runs its own in-process LRU; this one is
# purely local so an operator-side "cheap preview" avoids a round trip
# per row. Keyed by (view-key, pid). TTL 60s, cap 256 entries (slice 01).
_LRU_CAP = 256
_LRU_TTL_S = 60.0
_MITIGATIONS_LRU: dict[tuple[str, int], tuple[float, dict[str, Any]]] = {}


def _lru_get(key: tuple[str, int]) -> dict[str, Any] | None:
    import time
    hit = _MITIGATIONS_LRU.get(key)
    if hit is None:
        return None
    ts, row = hit
    if time.monotonic() - ts > _LRU_TTL_S:
        _MITIGATIONS_LRU.pop(key, None)
        return None
    return row


def _lru_put(key: tuple[str, int], row: dict[str, Any]) -> None:
    import time
    _MITIGATIONS_LRU[key] = (time.monotonic(), row)
    if len(_MITIGATIONS_LRU) > _LRU_CAP:
        oldest = min(_MITIGATIONS_LRU, key=lambda k: _MITIGATIONS_LRU[k][0])
        _MITIGATIONS_LRU.pop(oldest, None)


async def _enrich_mitigations(c, procs: list[dict[str, Any]], *,
                              view_key: str, force_recheck: bool,
                              cache_only: bool,
                              concurrency: int = 16
                              ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fan out ``GetMitigationPolicy`` for each row and attach the
    ``mitigations`` sub-dict. Uses ``asyncio.gather`` with a semaphore
    bounded to ``concurrency``. Honors ``mitigations_cache_only=True``
    by returning ``None`` for rows not in the local LRU.
    """
    meta: dict[str, Any] = {
        "ok": True, "cache_hits": 0, "probed": 0,
        "cache_only": bool(cache_only),
        "skipped_rows": 0, "error": "",
    }

    if cache_only:
        for row in procs:
            pid = int(row.get("pid") or 0)
            key = (view_key, pid)
            hit = _lru_get(key) if pid > 0 else None
            if hit is not None:
                row["mitigations"] = hit
                meta["cache_hits"] += 1
            else:
                row["mitigations"] = _empty_mitigations("cache_miss")
                meta["skipped_rows"] += 1
        return procs, meta

    pids = sorted({int(r.get("pid") or 0) for r in procs
                   if int(r.get("pid") or 0) > 0})
    if not pids:
        for row in procs:
            row["mitigations"] = _empty_mitigations("no_pid")
            meta["skipped_rows"] += 1
        return procs, meta

    sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def _one(pid: int) -> tuple[int, dict[str, Any]]:
        async with sem:
            try:
                res = await c.verify_mitigations(
                    [pid], force_recheck=force_recheck)
            except Exception as exc:  # noqa: BLE001
                return pid, {"ok": False,
                             "error": f"{type(exc).__name__}: {exc}"}
            return pid, res

    results = await asyncio.gather(*(_one(p) for p in pids))

    by_pid: dict[int, dict[str, Any]] = {}
    agent_version = False
    for pid, res in results:
        if not res.get("ok"):
            kind = res.get("kind", "")
            if kind == "agent_version":
                agent_version = True
            by_pid[pid] = _empty_mitigations("denied",
                                             error=res.get("error", "") or "")
            continue
        rows = res.get("rows") or []
        if not rows:
            by_pid[pid] = _empty_mitigations("no_rows")
            continue
        r = rows[0]
        by_pid[pid] = r
        _lru_put((view_key, pid), r)
        if r.get("cache_hit"):
            meta["cache_hits"] += 1
        else:
            meta["probed"] += 1

    if agent_version:
        meta["ok"] = False
        meta["error"] = ("verify_mitigations: older agent/umagent "
                         "(Mitigations service missing)")

    for row in procs:
        pid = int(row.get("pid") or 0)
        row["mitigations"] = by_pid.get(pid, _empty_mitigations("no_pid"))
        if row["mitigations"].get("mitigations_source") in ("no_pid",
                                                            "cache_miss"):
            meta["skipped_rows"] += 1
    return procs, meta


def _empty_mitigations(source: str, *, error: str = "") -> dict[str, Any]:
    """Zero-filled mitigations sub-dict carrying only the discriminator
    columns (source + error). Used when the row couldn't be probed."""
    def _zero(fields: tuple[str, ...]) -> dict[str, bool]:
        return {f: False for f in fields}
    return {
        "mitigations_source": source,
        "mitigations_cache_hit": False,
        "mitigations_error": error,
        "cache_hit": False,
        "error": error,
        "dep": _zero(("enable", "atl_thunk_emulation_disable", "permanent")),
        "aslr": _zero(("bottom_up", "force_relocate", "high_entropy",
                       "disallow_stripped_images", "bottom_up_high_entropy",
                       "high_address_space_override")),
        "cfg": _zero(("enable", "strict_mode", "suppress_exports",
                      "export_dynamic_invalidation")),
        "strict_handle_check": False,
        "system_call_disable": _zero(("disable", "allow_win32k_system_calls")),
        "extension_points_disabled": False,
        "dynamic_code": _zero(("prohibit", "allow_thread_opt_out",
                               "allow_remote_downgrade", "audit",
                               "audit_allow_thread_opt_out",
                               "audit_allow_remote_downgrade")),
        "binary_signature": {
            "micro_signed_only": False, "store_signed_only": False,
            "mitigation_opt_in": False, "mitigation_audit_mask": 0,
            "oem_signed_loosened_to_wintcb": False,
        },
        "font_disable": _zero(("disable_non_system_fonts", "audit")),
        "image_load": _zero(("no_remote_images",
                             "no_low_mandatory_label_images",
                             "prefer_system32", "audit_no_remote_images",
                             "audit_no_low_mandatory_label_images",
                             "audit_prefer_system32")),
        "user_shadow_stack": _zero(("enabled", "audit", "strict_mode",
                                    "set_context_ip_validation",
                                    "set_context_ip_validation_relaxed_mode",
                                    "block_non_cet_binaries",
                                    "block_non_cet_binaries_non_ehcont",
                                    "cet_dynamic_apis_out_of_proc_only",
                                    "audit_set_context_ip_validation",
                                    "audit_block_non_cet_binaries")),
        "payload_restriction": _zero((
            "enable_export_address_filter",
            "enable_export_address_filter_plus",
            "audit_export_address_filter",
            "audit_export_address_filter_plus",
            "enable_import_address_filter",
            "audit_import_address_filter",
            "enable_rop_stack_pivot", "audit_rop_stack_pivot",
            "enable_rop_caller_check", "audit_rop_caller_check",
            "enable_rop_sim_exec", "audit_rop_sim_exec")),
        "side_channel_isolation": _zero((
            "smt_branch_target_isolation", "isolate_security_domain",
            "disable_page_combine", "speculative_store_bypass_disable")),
        "redirection_trust": _zero(("enforce", "audit")),
    }


# ----------------------------------------------------------------------
# process_manage.list — mitigations-enrichment-aware list handler.
#
# Extracted as a module-level async function so Feature 6's test suite
# can exercise the fan-out logic end-to-end without going through the
# FastMCP tool registration path.  The register() closure below forwards
# every ``action='list'`` into this function.
# ----------------------------------------------------------------------


async def handle_list(*, ctx, c,
                      with_cmdline: bool,
                      verify_mitigations: bool,
                      mitigations_cache_only: bool,
                      filter: Any, fields: list[str] | None,
                      summary: bool,
                      limit: int, offset: int, max_results: int,
                      force_recheck: bool = False,
                      view_key: str = "<default>") -> Any:
    """``process_manage(action='list')`` body.

    Returns a decoded envelope (``dict``) when the mitigations
    enrichment path is taken, so Feature 6's tests can introspect
    ``body['data']['items'] / body['mitigations']`` directly. The
    non-enrichment path delegates to the legacy ``_mem_processes``
    helper, which returns the already-JSON-serialized envelope string
    the FastMCP wire expects — the test suite never exercises that
    branch."""
    if verify_mitigations or mitigations_cache_only:
        # Feature 6 enrichment path — fetch rows then fan out
        # GetMitigationPolicy per row (bounded concurrency).
        res = await c.mem_processes(
            with_cmdline=with_cmdline, full=True)
        procs = (res.get("processes")
                 if isinstance(res, dict) else res) or []
        procs, meta = await _enrich_mitigations(
            c, list(procs),
            view_key=view_key,
            force_recheck=bool(force_recheck),
            cache_only=bool(mitigations_cache_only),
        )
        eff_limit = limit or max_results
        env = _list_envelope(
            procs, tool="process_manage", action="list",
            limit=eff_limit, offset=offset,
            fields=fields or (),
            filter=filter,
            summary=summary,
            global_cap=(ctx.cfg.mcp_max_items()
                        if ctx is not None else 1000),
            extras={"source": (res.get("source")
                               if isinstance(res, dict)
                               else "agent")},
        )
        env["coverage"] = _coverage("enumeration", "complete")
        env["mitigations"] = meta
        return _hexify_dict(env, add_int_mirror=True)

    return await _mem_processes.handle_process_list(
        ctx, c, with_cmdline=with_cmdline, filter=filter,
        fields=fields, summary=summary, limit=limit,
        offset=offset, max_results=max_results,
    )


# ----------------------------------------------------------------------
# register() — P1 taxonomy dispatcher + P2 Feature 6 glue
# ----------------------------------------------------------------------


def register(mcp, ctx: Context) -> None:
    """Register the ``process_manage`` tool on *mcp*."""

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def process_manage(
        action: Annotated[str, Field(json_schema_extra={"enum": PROCESS_ACTIONS})],
        pid: int = 0,
        with_cmdline: bool = False,
        with_context: bool = False,
        verify_mitigations: bool = False,
        mitigations_cache_only: bool = False,
        force_recheck: bool = False,
        cache_only: bool = False,
        modes: list[str] | None = None,
        pid_max: int = 0,
        step: int = 0,
        timeout_s: float = 0.0,
        filter: Any = "",
        fields: list[str] | None = None,
        summary: bool = False,
        verbosity: str = "normal",
        limit: int = 0,
        offset: int = 0,
        max_results: int = 64,
        name: str = "",
    ) -> str:
        """Process inventory, per-process detail, mitigations
        (verify_mitigations=True on list, or action='mitigations'),
        hidden-process detection, and kill / suspend / resume (actuators,
        pid 0 refused). Per-verb help:
        process_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "pid": pid, "name": name,
                "verbosity": verbosity, "fields": fields or [],
                "filter": filter}

        async def run() -> Any:
            if action == "actions":
                return _actions_help("process_manage", _PROCESS_ACTION_HELP)
            if action not in PROCESS_ACTIONS:
                return _unknown_action("process_manage", action,
                                       PROCESS_ACTIONS, _PROCESS_ACTION_HELP)

            c = ctx.session.require_client(name)

            if action == "mitigations":
                return await handle_mitigations(
                    ctx, c, pid=pid, force_recheck=bool(force_recheck))

            if action == "list":
                return await handle_list(
                    ctx=ctx, c=c,
                    with_cmdline=with_cmdline,
                    verify_mitigations=bool(verify_mitigations),
                    mitigations_cache_only=bool(mitigations_cache_only),
                    force_recheck=bool(force_recheck),
                    filter=filter, fields=fields, summary=summary,
                    limit=limit, offset=offset, max_results=max_results,
                    view_key=str(name or "<default>"),
                )
            if action == "get":
                if not pid:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "process_manage.get: pid= is required"})
                # taxonomy fix. handle_process_list stamps
                # tool="memory_manage" / action="process_list" so a
                # caller of process_manage(get) used to see the wrong
                # tool home in telemetry. Post-rewrite in place; the
                # helper stays shared.
                result = await _mem_processes.handle_process_list(
                    ctx, c, with_cmdline=with_cmdline,
                    filter={"pid": pid}, fields=fields, summary=False,
                    limit=0, offset=0, max_results=1,
                )
                return _rewrite_process_get_taxonomy(result)
            if action == "hidden":
                return await _mem_hidden_proc.handle_hidden_proc(
                    ctx, c, modes=modes,
                    pid_max=int(pid_max or 0),
                    step=int(step or 0),
                    timeout_ms=int(timeout_s * 1000) if timeout_s > 0 else 0,
                    fields=fields, filter=filter, summary=summary,
                    limit=limit, offset=offset,
                    max_results=max_results,
                )
            if action == "kill":
                if not pid:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "process_manage.kill: pid= is required"})
                return _j(await c.kill_process(pid))
            if action == "suspend":
                if not pid:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "process_manage.suspend: pid= is required"})
                return _j(await c.suspend_process(pid))
            if action == "resume":
                if not pid:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "process_manage.resume: pid= is required"})
                return _j(await c.resume_process(pid))

            return _unknown_action("process_manage", action,
                                   PROCESS_ACTIONS, _PROCESS_ACTION_HELP)

        return await _guard(ctx, "process_manage", action, args, run)
