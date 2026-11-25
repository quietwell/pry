"""Service / driver inventory tool.

``svc_manage`` — SCM services + drivers via EnumServicesStatusExW,
with optional signer enrichment via the shared ``verify_signatures``
pattern. Read-only; no start/stop/config/delete.

``name=`` is the target view (like every other tool; default: the focus
machine's ``.user`` view); ``service=`` is the SCM service name for
``get`` / ``dependencies``.

Rows carry a ``kind='service'|'driver'`` discriminator so a caller can
filter without a second type-bitmask parse. Driver-flavor rows get an
optional kernel-view module-base/size join when the ``.kernel`` view is
also connected (handled umagent-side via a cross-channel call —
orchestrator stays view-agnostic here).
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .._coverage import coverage as _coverage


SVC_ACTIONS = ["list", "get", "dependencies", "drivers", "actions"]


_SVC_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "svc_manage(action='actions')"},
    "list": {
        "one_liner": ("EnumServicesStatusExW walk (services + drivers) "
                      "— every row carries kind='service'|'driver'"),
        "key_args": ("service_types, start_types, states, name_contains, "
                     "include_driver_base, verify_signatures, limit"),
        "example": ("svc_manage(action='list', "
                    "states=['RUNNING'], verify_signatures=true, limit=128)"),
    },
    "get": {
        "one_liner": "single-service deep detail",
        "key_args": "service, verify_signatures",
        "example": "svc_manage(action='get', service='Spooler')",
    },
    "dependencies": {
        "one_liner": ("EnumDependentServices + QueryServiceConfigW "
                      "dependencies for one service (either direction)"),
        "key_args": "service, reverse",
        "example": ("svc_manage(action='dependencies', "
                    "service='RpcSs', reverse=True)"),
    },
    "drivers": {
        "one_liner": ("driver-flavor rows only; module base/size filled "
                      "when the kernel view is connected or via "
                      "EnumDeviceDrivers fallback"),
        "key_args": "include_unloaded, verify_signatures",
        "example": "svc_manage(action='drivers')",
    },
}


# Columns the SI #8 enrichment leg merges onto each row. Mirror of
# mem/modules.py:_SIG_COLS so the two surfaces agree on field names
# and tests can import either side.
_SVC_SIG_COLS = (
    "signer", "signing_level", "is_signed", "catalog",
    "signer_cache_hit", "signer_error",
)


def _empty_sig_cols() -> dict:
    return {
        "signer": "",
        "signing_level": "",
        "is_signed": False,
        "catalog": False,
        "signer_cache_hit": False,
        "signer_error": "",
    }


def _row_kind(r: dict) -> str:
    """Normalize the service_type -> kind. Agent fills ``kind=`` directly
    but older umagent builds may leave it empty; derive from
    service_type as a fallback."""
    k = (r.get("kind") or "").strip()
    if k:
        return k
    st = (r.get("service_type") or "").lower()
    return "driver" if "driver" in st else "service"


async def _enrich_svc_signatures(c, items: list[dict], *,
                                  force_recheck: bool
                                  ) -> tuple[list[dict], dict]:
    """Fire one batched ``Signatures.Verify`` RPC against the unique
    image paths in *items* and merge signer columns onto each row.

    Degrades gracefully: when the agent / umagent is an older build (no
    ``Signatures`` service) or the batched call fails, every row gets
    empty signer columns and the returned meta carries the reason.
    """
    paths: list[str] = []
    seen: set[str] = set()
    for row in items:
        p = str(row.get("image_path", "") or "")
        if not p or p in seen:
            continue
        seen.add(p)
        paths.append(p)
    meta: dict = {"ok": True, "cache_hits": 0, "probed": 0,
                  "skipped_rows": 0, "error": ""}
    if not paths:
        for r in items:
            if "signer" not in r or not r.get("signer"):
                r.update(_empty_sig_cols())
            meta["skipped_rows"] += 1
        return items, meta
    try:
        res = await c.verify_signatures(paths, force_recheck=force_recheck)
    except Exception as exc:  # noqa: BLE001 — never fatal
        meta["ok"] = False
        meta["error"] = f"{type(exc).__name__}: {exc}"
        for r in items:
            r.update(_empty_sig_cols())
            meta["skipped_rows"] += 1
        return items, meta
    if not res.get("ok"):
        meta["ok"] = False
        meta["error"] = res.get("error", "verify_signatures failed")
        for r in items:
            r.update(_empty_sig_cols())
            meta["skipped_rows"] += 1
        return items, meta
    by_path: dict[str, dict] = {
        r.get("path", ""): r for r in (res.get("rows") or [])
    }
    for row in items:
        p = str(row.get("image_path", "") or "")
        sig = by_path.get(p)
        if sig is None:
            row.update(_empty_sig_cols())
            meta["skipped_rows"] += 1
            continue
        row["signer"] = sig.get("signer", "") or ""
        row["signing_level"] = sig.get("signing_level", "") or ""
        row["is_signed"] = bool(sig.get("is_signed"))
        row["catalog"] = bool(sig.get("catalog"))
        row["signer_cache_hit"] = bool(sig.get("cache_hit"))
        row["signer_error"] = sig.get("error", "") or ""
    meta["cache_hits"] = int(res.get("cache_hits", 0))
    meta["probed"] = int(res.get("probed", 0))
    return items, meta


def _looks_like_view(ctx, name: str) -> bool:
    """True when ``name`` selects a connected view / machine / view kind
    rather than being an SCM service name."""
    n = (name or "").strip()
    if not n:
        return False
    if "." in n or n.lower() in ("user", "kernel"):
        return True
    try:
        resolved = ctx.session.resolve_view_name(n)
    except Exception:  # noqa: BLE001 — unknown machine etc.
        return False
    return resolved != n or n in getattr(ctx.session, "clients", {})


def _is_kernel_name(name: str) -> bool:
    """Same umagent-only policy as net_manage."""
    n = (name or "").strip().lower()
    return n.endswith(".kernel") or n == "kernel"


def register(mcp, ctx: Context) -> None:
    """Register the ``svc_manage`` tool on *mcp*, using *ctx* for state."""

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def svc_manage(action: Annotated[str, Field(
                              json_schema_extra={"enum": SVC_ACTIONS})],
                         # list filters
                         service_types: list[str] | None = None,
                         start_types: list[str] | None = None,
                         states: list[str] | None = None,
                         name_contains: str = "",
                         include_driver_base: bool = True,
                         verify_signatures: bool = False,
                         force_recheck: bool = False,
                         # single-service verbs
                         service: str = "",
                         reverse: bool = False,
                         # drivers
                         include_unloaded: bool = False,
                         # paging / shaping
                         limit: int = 128,
                         offset: int = 0,
                         cursor: str = "",
                         fields: list[str] | None = None,
                         filter: str = "",
                         summary: bool = False,
                         verbosity: str = "normal",
                         name: str = "",
                         ) -> str:
        """SCM service + driver inventory (umagent .user view only,
        read-only). service= names the SCM service for get/dependencies;
        name= picks the view. Opt into Authenticode signer enrichment
        with ``verify_signatures=True``; ``force_recheck=True`` bypasses
        the signer cache. Per-verb help:
        ``svc_manage(action='actions', verb='<verb>')``."""
        args = {"action": action, "name": name, "service": service,
                "verify_signatures": verify_signatures}

        async def run() -> Any:
            if action not in SVC_ACTIONS:
                return _unknown_action("svc_manage", action,
                                        SVC_ACTIONS, _SVC_ACTION_HELP)
            if action == "actions":
                return _actions_help("svc_manage", _SVC_ACTION_HELP)

            svc_name = service
            view = name
            if (action in ("get", "dependencies") and not svc_name and name
                    and not _looks_like_view(ctx, name)):
                # Pre-service= callers passed the SCM name as name=.
                svc_name, view = name, ""
            if not view:
                view = "user"
            if _is_kernel_name(view):
                return _j({
                    "ok": False, "kind": "bad_arg",
                    "error": ("svc_manage is umagent-only — SCM is a "
                              "user-mode API"),
                    "hint": ("drop the '.kernel' suffix on name= (or "
                             "pass name='<machine>.user'); "
                             "target_manage(action='connect', "
                             "name='<machine>.user') if the view is not "
                             "yet connected"),
                })
            try:
                resolved = ctx.session.resolve_view_name(view)
            except Exception:
                resolved = view
            if _is_kernel_name(resolved):
                return _j({
                    "ok": False, "kind": "no_target",
                    "error": ("svc_manage: no .user view connected on "
                              f"machine {resolved!r}"),
                    "hint": ("connect umagent via "
                             "target_manage(action='connect', "
                             f"name='{resolved.rsplit('.', 1)[0]}.user')"),
                })
            c = ctx.session.require_client(resolved)

            if action == "list":
                res = await c.svc_list(
                    service_types=service_types,
                    start_types=start_types,
                    states=states,
                    name_contains=name_contains,
                    include_driver_base=bool(include_driver_base),
                    # agent-side enrichment is off; orchestrator does it
                    # below so we hit the shared cache + unified path.
                    verify_signatures=False,
                    limit=int(limit or 128),
                )
                if not res.get("ok"):
                    return _j(res)
                items = list(res.get("items", []))
                for r in items:
                    r["kind"] = _row_kind(r)
                sig_meta = None
                if verify_signatures and items:
                    items, sig_meta = await _enrich_svc_signatures(
                        c, items, force_recheck=bool(force_recheck))
                extras: dict = {
                    "truncated_agent": bool(res.get("truncated")),
                    "degraded_rows": int(res.get("degraded_rows", 0)),
                }
                if sig_meta is not None:
                    extras["signer_enrichment"] = sig_meta
                env = _list_envelope(
                    items, tool="svc_manage", action="list",
                    limit=limit, offset=offset, cursor=cursor,
                    fields=fields or (), filter=filter, summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras=extras,
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return env

            if action == "get":
                if not svc_name:
                    return _j({
                        "ok": False, "kind": "bad_arg",
                        "error": "get: service= is required (SCM short name)",
                        "hint": "svc_manage(action='get', service='Spooler')",
                    })
                res = await c.svc_get(name=svc_name)
                if not res.get("ok"):
                    return _j(res)
                item = dict(res.get("item", {}) or {})
                item["kind"] = _row_kind(item)
                if verify_signatures and item.get("image_path"):
                    [item], sig_meta = await _enrich_svc_signatures(
                        c, [item], force_recheck=bool(force_recheck))
                    out = {"ok": True, "item": item,
                           "signer_enrichment": sig_meta}
                else:
                    out = {"ok": True, "item": item}
                return _j(out)

            if action == "dependencies":
                if not svc_name:
                    return _j({
                        "ok": False, "kind": "bad_arg",
                        "error": "dependencies: service= is required",
                        "hint": ("svc_manage(action='dependencies', "
                                 "service='RpcSs')"),
                    })
                res = await c.svc_dependencies(name=svc_name,
                                               reverse=bool(reverse))
                if not res.get("ok"):
                    return _j(res)
                items = list(res.get("items", []))
                for r in items:
                    r["kind"] = _row_kind(r)
                env = _list_envelope(
                    items, tool="svc_manage", action="dependencies",
                    limit=limit, offset=offset, cursor=cursor,
                    fields=fields or (), filter=filter, summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"reverse": bool(reverse), "root": svc_name},
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return env

            if action == "drivers":
                res = await c.svc_drivers(
                    include_unloaded=bool(include_unloaded),
                    # same pattern as list — orchestrator-side enrichment.
                    verify_signatures=False,
                )
                if not res.get("ok"):
                    return _j(res)
                items = list(res.get("items", []))
                for r in items:
                    r["kind"] = "driver"
                sig_meta = None
                if verify_signatures and items:
                    items, sig_meta = await _enrich_svc_signatures(
                        c, items, force_recheck=bool(force_recheck))
                extras: dict = {"include_unloaded": bool(include_unloaded)}
                if sig_meta is not None:
                    extras["signer_enrichment"] = sig_meta
                env = _list_envelope(
                    items, tool="svc_manage", action="drivers",
                    limit=limit, offset=offset, cursor=cursor,
                    fields=fields or (), filter=filter, summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras=extras,
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return env

            return _unknown_action("svc_manage", action,
                                    SVC_ACTIONS, _SVC_ACTION_HELP)

        return await _guard(ctx, "svc_manage", action, args, run)
