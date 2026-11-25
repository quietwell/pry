"""``pool_scan`` verb body (kernel pool enumeration by tag).

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

from typing import Any

from .._runtime.envelope import _list_envelope
from .._runtime.response import _decode_list, _hexify_dict, _j
from ._envelope import _scan_window_cov


async def handle_pool_scan(ctx, c, *, pid: int, size: int, space: str,
                           kernel: bool, pattern: str, pattern_hex: str,
                           mask: str, max_results: int, module: str,
                           protect: int, filter: Any, summary: bool,
                           fields: list[str] | None, limit: int,
                           offset: int,
                           enrich_tags: bool = True) -> str:
    # Tag filter accepted as int or 4-char string ('EDID' etc.).
    # Pattern uses the same IDA-style hex OR raw hex bytes; mask
    # length must equal pattern length (or be empty).
    tag_i = 0
    if pattern:
        from ....sdk import parse_mask
        from ....sdk.reader import PryError as _ScanErr
        try:
            pat_bytes, mask_str = parse_mask(pattern)
        except _ScanErr as exc:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": f"pool_scan: {exc}"})
        if "H" in mask_str or "L" in mask_str:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "pool_scan: nibble wildcards "
                                "('6?'/'?F') aren't supported — "
                                "the driver's pool matcher is "
                                "byte-granular; use '?' for a "
                                "wildcard byte"})
        mask_bytes = mask_str.encode("ascii") if mask_str else b""
    else:
        pat_bytes = bytes.fromhex(pattern_hex) if pattern_hex else b""
        if "H" in mask or "L" in mask:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "pool_scan: mask chars are "
                                "'?' (wildcard) or 'x' (exact) "
                                "— nibble masks ('H'/'L') are "
                                "pattern_scan-only"})
        mask_bytes = mask.encode("ascii") if mask else b""
    # A caller-supplied `module` arg carries the 4-char tag (we
    # already have a `module` field; overloading avoids adding
    # yet another top-level parameter for a single-use scan).
    if module:
        tag = module.strip()
        if len(tag) == 4:
            tag_i = int.from_bytes(tag.encode("ascii", "replace"), "little")
        else:
            try:
                tag_i = int(tag, 0)
            except ValueError:
                return _j({"ok": False,
                           "error": f"pool_scan `module` (tag) must be a "
                                    f"4-char string or an int; got {module!r}"})
    # refuse pattern + size=0 up front. The driver
    # (Pool.c:187-210) silently skips the content-filter branch
    # when span==0 and emits every considered entry with
    # matched_offset=0 — indistinguishable from a real hit at
    # VA 0. Fail fast with a typed error so the caller learns
    # the actual shape instead of trusting fake matches.
    content_span = int(size or 0)
    if pat_bytes and content_span <= 0:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "pool_scan pattern requires size>0 "
                            "(content window)",
                   "hint": "set `size` to the number of bytes to "
                           "read from `offset` into each "
                           "allocation for the pattern match "
                           "(e.g. size=256, offset=0)"})
    content_filter_active = bool(pat_bytes) and content_span > 0
    nonpaged_only = space == "kernel"  # kernel space => non-paged only
    result = await c.pool_scan(
        tag_filter=tag_i,
        nonpaged_only=nonpaged_only or kernel,
        max_results=max_results or 256,
        pattern=pat_bytes, mask=mask_bytes,
        offset=protect,  # reuse `protect` int field for byte offset
        content_span=content_span,
    )
    # Layer 3: single uniform list envelope. `entries` rows
    # get _decoded siblings for pool_tag; `required` / `considered`
    # ride under `data` as extras. finalize strips `_int` mirrors +
    # `_decoded` siblings at the default verbosity.
    entries = _decode_list(result.get("entries", []), "pool")
    # SI feature #4: pool-tag -> driver enrichment. Pure orchestrator-side
    # decoration — zero behaviour change when `enrich_tags=False`, and the
    # driver's `PoolScanResponse` wire shape is untouched regardless. See
    # an internal plan.
    tags_enriched = False
    enrich_hits = 0
    if enrich_tags and entries:
        from ....analysis.pooltag import lookup_pool_tag, pooltag_meta
        tags_enriched = pooltag_meta().get("status") == "loaded"
        if tags_enriched:
            for row in entries:
                key = (row.get("tag_ascii")
                       or row.get("tag_decoded")
                       or row.get("tag"))
                hit = lookup_pool_tag(key) if key is not None else None
                if hit is None:
                    row["owner_driver"] = ""
                    row["tag_description"] = ""
                else:
                    row["owner_driver"] = hit["driver"]
                    row["tag_description"] = hit["description"]
                    enrich_hits += 1
    eff_limit = limit or max_results
    cov = _scan_window_cov(
        {"truncated": len(entries) >= (max_results or 256)},
        ranged=True)
    extras: dict[str, Any] = {
        "required": result.get("required", 0),
        "considered": result.get("considered", 0),
        "content_filter_active": content_filter_active,
    }
    if enrich_tags:
        extras["tags_enriched"] = tags_enriched
        if tags_enriched:
            extras["tags_enriched_hits"] = enrich_hits
    env = _list_envelope(
        entries, tool="memory_manage", action="pool_scan",
        limit=eff_limit, offset=offset,
        fields=fields or (),
        filter=filter,
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras=extras,
    )
    env["coverage"] = cov
    return _hexify_dict(env, add_int_mirror=True)
