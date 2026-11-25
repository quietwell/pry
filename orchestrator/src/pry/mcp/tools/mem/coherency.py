"""``coherency`` verb body — SI feature #1 (image coherency scoring).

Scores how closely a loaded module's in-memory image matches its on-disk
file. The C++ fast path (agent + umagent, via the ``ImageCoherency.Score``
RPC) walks the two readers in parallel, skipping bits set in the
exclusion bitmap (relocs, IAT thunks, LoadConfig overrides, CFG tables,
ImageBase in the optional header), and returns a mismatch range list
plus bytes_compared / bytes_mismatched counters. The orchestrator-side
``classify`` helper labels the mismatch set:

    classification ∈ {"clean", "iat_hooked", "inline_hooked",
                      "section_overwritten", "relocs_unresolved",
                      "unknown"}

Driver-free: the umagent path serves this fine; ``memory_manage(action=
'coherency')`` is on the ``_driver_free`` whitelist in
``mem/__init__.py``. On a protected-process target the agent view
routes the mem reads through the driver (PRY_MEM_FLAG_PROTECTED_OK).

The slice doc (04-umagent-orchestrator.md §Feature 1) is the source of
truth for request kwargs, response envelope, and classifier buckets.
"""

from __future__ import annotations

from typing import Any

from ....analysis.coherency import classify as _classify
from ..._coverage import coverage as _coverage
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict, _j


_VALID_MODES = {"quick", "normal", "full"}


async def handle_coherency(ctx, c, *, pid: int, module: str,
                           module_base: int, mode: str, name: str,
                           max_mismatch_ranges: int,
                           include_mismatch_hex: bool,
                           fields: list[str] | None,
                           filter: Any, summary: bool,
                           limit: int, offset: int) -> str:
    """Dispatch ``memory_manage(action='coherency')``.

    * ``module`` basename (or full path) selects the module; 0 for every
      module is NOT supported in this Wave 1 slice — call once per
      module. ``module_base`` overrides the lookup when both are given.
    * ``mode`` ∈ {"quick","normal","full"} controls the budget.
    * ``max_mismatch_ranges`` caps the response list (default 128).
    """
    mode_norm = str(mode or "normal").lower()
    if mode_norm not in _VALID_MODES:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"coherency: mode must be one of "
                            f"{sorted(_VALID_MODES)}; got {mode!r}",
                   "hint": "mode='quick' (fastest), 'normal' (~40 MiB "
                           "cap), 'full' (every byte)"})
    if not module and not module_base:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "coherency: module= or module_base= is "
                            "required",
                   "hint": "memory_manage(action='coherency', pid=1234, "
                           "module='ntdll.dll')"})
    max_r = int(max_mismatch_ranges or 128)
    if max_r < 0:
        max_r = 0

    if getattr(c, "coherency", None) is None:
        return _j({"ok": False, "kind": "agent_version",
                   "error": "coherency: this agent/umagent is too old "
                            "(ImageCoherency service missing)",
                   "hint": "rebuild + redeploy agent and umagent "
                           "(scripts/update_target.py --component "
                           "agent --component umagent)"})
    try:
        res = await c.mem_coherency(
            pid=pid, module=module, module_base=module_base,
            mode=mode_norm, max_ranges=max_r,
            include_mismatch_hex=bool(include_mismatch_hex),
        )
    except Exception as exc:  # noqa: BLE001 — surface as named error
        return _j({"ok": False, "kind": "coherency_failed",
                   "error": f"{type(exc).__name__}: {exc}"})
    if not res.get("ok"):
        return _j({"ok": False, "kind": "coherency_failed",
                   "module": res.get("module", ""),
                   "error": res.get("error", "coherency failed")})

    # Orchestrator-side classifier: pure-Python label on the mismatch set.
    reloc_dir = (int(res.get("reloc_dir_rva") or 0),
                 int(res.get("reloc_dir_size") or 0))
    classification = _classify(
        res.get("mismatches") or [],
        sections=res.get("sections") or [],
        reloc_dir=reloc_dir if reloc_dir[1] else None,
    )

    # Deterministic coverage block: "complete" only for mode='full'.
    status = "complete" if mode_norm == "full" else "partial"
    limits = ("sampling_cap_reached",) if status == "partial" else ()
    if res.get("truncated"):
        limits = limits + ("truncated_at_max_ranges",)
    cov = _coverage("coherency-window", status, *limits)

    source = str(ctx.session.view_kind_of(name) or "driver")
    if source == "user":
        source = "umagent"

    # Build "coherency_excluded_regions" so the parity harness has a
    # list it can skip when cross-checking the two views (slice doc:
    # "parity doesn't flake on relocs/IAT"). Writable sections are
    # excluded by convention; reloc dir rides on top when present.
    excluded: list[dict[str, Any]] = [
        {"name": s["name"], "va": s["va"], "size": s["size"]}
        for s in (res.get("sections") or [])
        if int(s.get("characteristics", 0)) & 0x80000000  # IMAGE_SCN_MEM_WRITE
    ]
    if reloc_dir[1]:
        excluded.append({"name": "relocs",
                         "va": reloc_dir[0], "size": reloc_dir[1]})

    extras: dict[str, Any] = {
        "module": res.get("module", ""),
        "module_base": int(module_base or 0),
        "module_path_disk": res.get("module_path_disk", ""),
        "size_of_image": int(res.get("size_of_image") or 0),
        "bytes_compared": int(res.get("bytes_compared") or 0),
        "bytes_mismatched": int(res.get("bytes_mismatched") or 0),
        "coherency": float(res.get("coherency") or 0.0),
        "classification": classification,
        "sections_total": int(res.get("sections_total") or 0),
        "sections_skipped_relocatable": int(
            res.get("sections_skipped_relocatable") or 0),
        "truncated": bool(res.get("truncated")),
        "mode": mode_norm,
        "source": source,
        "coherency_excluded_regions": excluded,
    }

    env = _list_envelope(
        res.get("mismatches") or [], tool="memory_manage", action="coherency",
        limit=limit or max_r, offset=offset,
        fields=fields or (),
        filter=filter if isinstance(filter, str) else "",
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras=extras,
    )
    env["coverage"] = cov
    return _hexify_dict(env, add_int_mirror=True)


__all__ = ["handle_coherency"]
