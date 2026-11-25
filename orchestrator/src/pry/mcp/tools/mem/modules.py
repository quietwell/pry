"""``modules`` verb body (sparse-list + filter + sections cache).

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
The optional ``verify_signatures`` kwarg: when True
the orchestrator fires one batched ``Signatures.Verify`` RPC after the
module enumeration and merges signer / signing-level / cache-hit
columns onto each row. ``verify_signatures=False`` (the default) is
bit-identical to the original response — the "do-not-break" matrix
(README §7) requires that.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.driver_gate import _require_driver
from .._runtime.envelope import _envelope_ok, _list_envelope
from .._runtime.response import _hexify_dict, _j
from .._runtime.row_filters import _apply_modules_filter


# SI #8 columns the enrichment pass merges onto each module row. Kept in
# one place so the row filter / fields= projection sees the same list
# as this module and tests can import it.
_SIG_COLS = (
    "signer", "signing_level", "is_signed", "catalog",
    "signer_cache_hit", "signer_error",
)


def _empty_sig_cols() -> dict[str, Any]:
    return {
        "signer": "",
        "signing_level": "",
        "is_signed": False,
        "catalog": False,
        "signer_cache_hit": False,
        "signer_error": "",
    }


def _apply_sig_cols(row: dict[str, Any], sig_row: dict[str, Any]) -> None:
    row["signer"] = sig_row.get("signer", "")
    row["signing_level"] = sig_row.get("signing_level", "")
    row["is_signed"] = bool(sig_row.get("is_signed"))
    row["catalog"] = bool(sig_row.get("catalog"))
    row["signer_cache_hit"] = bool(sig_row.get("cache_hit"))
    row["signer_error"] = sig_row.get("error", "") or ""


async def _enrich_signatures(c, mods: list[dict[str, Any]],
                              *, force_recheck: bool
                              ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fire one batched Signatures.Verify RPC for the unique paths in
    *mods* and merge the response columns onto each row. Returns
    (mods, meta) where meta carries ``ok``/``cache_hits``/``probed``/
    ``skipped_rows`` so the envelope can surface the enrichment state.
    """
    paths = []
    seen: set[str] = set()
    for m in mods:
        p = str(m.get("path", "") or "")
        if not p or p in seen:
            continue
        seen.add(p)
        paths.append(p)
    meta: dict[str, Any] = {"ok": True, "cache_hits": 0, "probed": 0,
                            "skipped_rows": 0, "error": ""}
    if not paths:
        for m in mods:
            if "signer" not in m:
                m.update(_empty_sig_cols())
            meta["skipped_rows"] += 1
        return mods, meta
    try:
        res = await c.verify_signatures(paths, force_recheck=force_recheck)
    except Exception as exc:  # noqa: BLE001 — degrade gracefully.
        meta["ok"] = False
        meta["error"] = f"{type(exc).__name__}: {exc}"
        for m in mods:
            m.update(_empty_sig_cols())
            meta["skipped_rows"] += 1
        return mods, meta
    if not res.get("ok"):
        meta["ok"] = False
        meta["error"] = res.get("error", "verify_signatures failed")
        for m in mods:
            m.update(_empty_sig_cols())
            meta["skipped_rows"] += 1
        return mods, meta
    by_path: dict[str, dict[str, Any]] = {
        r.get("path", ""): r for r in (res.get("rows") or [])
    }
    for m in mods:
        p = str(m.get("path", "") or "")
        sig_row = by_path.get(p)
        if sig_row is None:
            m.update(_empty_sig_cols())
            meta["skipped_rows"] += 1
            continue
        _apply_sig_cols(m, sig_row)
    meta["cache_hits"] = int(res.get("cache_hits", 0))
    meta["probed"] = int(res.get("probed", 0))
    return mods, meta


async def handle_modules(ctx, c, *, pid: int, space: str, kernel: bool,
                         name: str, name_regex: str, name_glob: str,
                         path_contains: str, compact: bool, summary: bool,
                         filter: Any, fields: list[str] | None,
                         limit: int, offset: int, max_results: int,
                         verify_signatures: bool = False,
                         force_recheck: bool = False) -> str:
    # `filter` is case-insensitive substring; dict
    # form ANDs {field: value} case-insensitive substring per
    # field. For exact match, pass a compiled regex:
    #   filter={"name": re.compile(r"^tcpip\.sys$")}
    # Prefer the dedicated name_regex / name_glob / path_contains
    # kwargs for modules — they surface named errors on typos.
    use_kernel = kernel or space in ("kernel", "physical")
    if use_kernel:
        guard = await _require_driver(ctx, "memory_manage", "modules", name)
        if guard: return _j(guard)
    mods_all = await c.mem_modules(pid, use_kernel)
    mods = list(mods_all)
    # wire the dedicated typed filters (defined in
    # _apply_modules_filter but never invoked).
    if name_regex or name_glob or path_contains:
        import re as _re_mods
        try:
            mods = _apply_modules_filter(mods, {
                "name_regex": name_regex,
                "name_glob": name_glob,
                "path_contains": path_contains,
            })
        except _re_mods.error as exc:
            return _j({"ok": False,
                       "kind": "invalid_parameter",
                       "error": f"name_regex compile error: {exc}",
                       "hint": "escape metacharacters or drop the "
                               "regex and use name_glob instead"})
    # Layer 3: single uniform list envelope. Old knobs
    # (`filter` str/dict, `fields`, `compact`, `summary`,
    # `max_results`) route through apply_page_opts.
    if compact:
        mods = [{"name": m.get("name", ""),
                 "base": m.get("base"),
                 "size": m.get("size")} for m in mods]
    eff_limit = limit or max_results
    # zero-match diagnostic. When any filter was
    # applied and nothing matched, return an empty items list
    # with filter_matched:false plus a 5-item sample of the
    # available module names so the caller can spot a typo
    # without a follow-up call. `_list_envelope`'s filter still
    # runs after this check when `filter` is the only knob, so
    # we only branch when the pre-envelope filters trimmed the
    # rows or `filter` is set.
    pre_filtered = bool(name_regex or name_glob or path_contains)
    if pre_filtered and not mods:
        all_names = [str(m.get("name", "")) for m in mods_all]
        env = _envelope_ok(
            {"items": [], "filter_matched": False,
             "sample_available_names": all_names[:5],
             "total_available": len(all_names),
             "filter_applied": {
                 "name_regex": name_regex or None,
                 "name_glob": name_glob or None,
                 "path_contains": path_contains or None,
             }},
            kind="filter_no_match", tool="memory_manage",
            action="modules",
            item_count=0, item_total=0,
            coverage=_coverage("enumeration", "complete"),
        )
        return _hexify_dict(env, add_int_mirror=True)
    # SI #8 enrichment — gated by the explicit kwarg so the default
    # response stays bit-identical to the original shape. Runs AFTER
    # row filtering + compact so we only probe the paths we're actually
    # returning (one batched RPC; the agent-side cache keeps repeat
    # calls cheap).
    sig_meta: dict[str, Any] | None = None
    if verify_signatures and mods and not compact:
        mods, sig_meta = await _enrich_signatures(
            c, mods, force_recheck=bool(force_recheck))
    elif verify_signatures and compact:
        # compact drops `path`, so the signer join has nothing to key on.
        sig_meta = {"ok": False,
                    "error": "verify_signatures requires compact=false "
                             "(path is the join key)",
                    "cache_hits": 0, "probed": 0, "skipped_rows": len(mods)}
    env = _list_envelope(
        mods, tool="memory_manage", action="modules",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
    )
    env["coverage"] = _coverage("enumeration", "complete")
    if sig_meta is not None:
        env["signatures"] = sig_meta
    return _hexify_dict(env, add_int_mirror=True)


__all__ = ["handle_modules", "_SIG_COLS", "_enrich_signatures",
           "_apply_sig_cols", "_empty_sig_cols"]
