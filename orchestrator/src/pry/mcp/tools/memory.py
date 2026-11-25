"""``memory_manage`` - canonical memory R/W + address-space tool.

The canonical surface for the memory / address-space / allocator / scan /
forensics verbs. Verbs with a canonical home elsewhere (``process_list``,
``threads``, ``modules``, ``imports``/``exports``, ``handles``,
``obj_enum``, ``pool_scan``, ``stack_walk``, ``hidden_proc``,
``global_find``, ``coherency``, ``idt``, ``handle_*``) are not in the
public enum; a stale caller gets a ``moved`` error naming the new
``process_manage`` / ``thread_manage`` / ``module_manage`` /
``object_manage`` / ``kernel_manage`` home. The internal dispatcher in
``mem/__init__.py`` still ships them for internal callers.

``heap_info`` (segment-heap walk) is user-space only.

Implementation shortcut: the dispatcher body stays in ``mem/__init__.py``'s
``memory_manage`` closure; this ``memory_manage`` is a thin forwarder that
invokes that closure through the module-level ``_MEMORY_MANAGE_FN`` handle
and rewrites the response's top-level ``tool`` field.
"""

from __future__ import annotations

import json as _json

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .mem import _MEMORY_ACTIONS_MASTER  # action enum shared with the internal memory_manage dispatcher
from .._envelope import envelope_err as _envelope_err


# ``_MOVED_VERBS`` lists the verbs that used to be reachable through
# ``memory_manage`` but have a canonical home elsewhere. Calls with one
# of these verbs are intercepted BEFORE the forward into the internal
# dispatcher and return a ``kind='moved'`` envelope naming the new home.
# The internal dispatcher in ``mem/__init__.py`` still ships them for
# any internal callers, but the public tool no longer advertises or
# dispatches them.
_MOVED_VERBS: dict[str, dict[str, str]] = {
    "process_list":   {"tool": "process_manage", "action": "list"},
    "threads":        {"tool": "thread_manage",  "action": "list"},
    "modules":        {"tool": "module_manage",  "action": "list"},
    "handles":        {"tool": "object_manage",  "action": "handles"},
    "obj_enum":       {"tool": "object_manage",  "action": "enum"},
    "pool_scan":      {"tool": "kernel_manage",  "action": "pool_scan"},
    "stack_walk":     {"tool": "thread_manage",  "action": "stack"},
    "hidden_proc":    {"tool": "process_manage", "action": "hidden"},
    "global_find":    {"tool": "object_manage",  "action": "find"},
    "coherency":      {"tool": "module_manage",  "action": "coherency"},
    "idt":            {"tool": "kernel_manage",  "action": "idt"},
    "handle_dup":     {"tool": "object_manage",  "action": "handle_dup"},
    "handle_close":   {"tool": "object_manage",  "action": "handle_close"},
    "handle_compare": {"tool": "object_manage",  "action": "handle_compare"},
    # Duplicates of module_manage's walkers. module_manage picks kernel
    # space when kernel=true or pid=0 (memory_manage used space=).
    "imports":        {"tool": "module_manage",  "action": "imports",
                       "note": "pass kernel=true (or pid=0) for a kernel module"},
    "exports":        {"tool": "module_manage",  "action": "exports",
                       "note": "pass kernel=true (or pid=0) for a kernel module"},
}


# Advertised enum drops every verb in ``_MOVED_VERBS`` - they are
# unreachable via this tool.
MEMORY_ACTIONS = list(dict.fromkeys(
    a for a in [*_MEMORY_ACTIONS_MASTER, "heap_info"]
    if a not in _MOVED_VERBS))


def _pin_tool_name(res):
    """Pin the response envelope's ``tool`` field to ``memory_manage``.

    The internal dispatcher writes ``tool='memory_manage'`` for historical
    reasons; the public tool surface is ``memory_manage`` so we rewrite
    it on the way out. No deprecation stamping is added.
    """
    body = getattr(res, "structured_content", None)
    if isinstance(body, dict):
        body["tool"] = "memory_manage"
        return res
    if isinstance(res, str):
        try:
            parsed = _json.loads(res)
        except (ValueError, TypeError):
            return res
        if isinstance(parsed, dict):
            parsed["tool"] = "memory_manage"
            return _j(parsed)
    return res


def register(mcp, ctx: Context) -> None:
    """Register the ``memory_manage`` tool on *mcp*.

    Forwards every call into ``memory_manage``'s closure through the shared
    ``_MEMORY_MANAGE_FN`` handle and rewrites the envelope so the canonical
    name surfaces to callers. The underlying dispatcher is used as-is
    (``mem/__init__.py``).
    """

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def memory_manage(
        action: Annotated[str, Field(json_schema_extra={"enum": MEMORY_ACTIONS})],
        pid: int = 0, address: int | str = 0, size: int = 0,
        data_hex: str = "", space: str = "user", protect: int = 0,
        kernel: bool = False, pattern_hex: str = "", mask: str = "",
        pattern: str = "", base: int | str = 0, max_results: int = 64,
        want_names: bool = False, module: str = "",
        filter: Any = "",
        name_regex: str = "",
        name_glob: str = "",
        path_contains: str = "",
        compact: bool = False,
        summary: bool = False,
        fields: list[str] | None = None,
        want_blocks: bool = False, max_blocks: int = 0,
        allow_fault: bool = False, allow_map_write: bool = False,
        allow_mmio: bool = False,
        partial: bool = False,
        timeout_s: float = 0.0,
        # value accepts int / float / str: value_scan coerces via
        # _coerce_number; legacy callers (walk_list / resolve) passed
        # strings and still do.
        value: int | float | str = "",
        bytes_hex: str = "",
        arch: str = "x64",
        syntax: str = "intel",
        count: int = 64,
        detail: bool | str = False,
        resolve_symbols: bool = False,
        code: str = "",
        write_to: int | str = 0,
        dry_run: bool = True,
        limit: int = 0,
        offset: int = 0,
        cursor: str = "",
        verbosity: str = "normal",
        scan_id: str = "",
        verify: bool = False,
        decode: Any = None,
        reads: list[dict] | None = None,
        include_ascii: bool = False,
        from_va: int | str = 0,
        resolve_physical: bool = False,
        min_len: int = 5,
        buckets: int = 64,
        entropy: bool = False,
        path: str = "",
        depth: int = 1,
        all_cpus: bool = False,
        sections: str = "",
        with_cmdline: bool = False,
        with_context: bool = False,
        offsets: list[int] | None = None,
        terminal_size: int = 0,
        expect_ascii: bool = False,
        expect_nonzero: bool = False,
        expect_module: str = "",
        needles: list[str] | None = None,
        scopes: list[str] | None = None,
        enrich_tags: bool = True,
        kinds: list[str] | None = None,
        regex: bool = False,
        want_object_names: bool = True,
        concurrency: int = 8,
        mode: str = "poll",
        access: str = "write",
        tid: int = 0,
        slot: int = 0xFF,
        preempt_ok: bool = False,
        verify_signatures: bool = False,
        force_recheck: bool = False,
        # --- Wave 1 Phase A: region filter for pattern_scan / scan_start ---
        writable: bool = False,
        executable: bool = False,
        cow: bool = False,
        include_guarded: bool = False,
        mem_types: list[str] | None = None,
        scope: str = "",
        # --- Wave 1 Phase G: typed value_scan / next_scan / scan_undo ---
        value_type: str = "",
        op: str = "",
        value_hi: Any = "",
        delta: Any = "",
        tolerance: float = 0.0,
        endian: str = "le",
        encoding: str = "",
        align: Any = "auto",
        confirm_full_space: bool = False,
        # --- v17 Wave 2: pointer map + reverse scan + diff + dissect ---
        map_id: str = "",
        map_id_b: str = "",
        target_va: int | str = 0,
        max_depth: int = 0,
        max_offset: int = 0,
        static_only: bool = True,
        fanout_per_level: int = 0,
        wall_ms: int = 0,
        remote_path: str = "",
        keep_disk: bool = False,
        chains: list[dict] | None = None,
        with_modules: bool = True,
        disk_spill_mode: str = "auto",
        max_candidates: int = 0,
        # Wave 3 Phase D: orchestrator-side symbol decoration on
        # pointer_scan chains + dissect slots. On by default.
        decorate: bool = True,
        # --- Wave 3 P1: DissectCompare ---
        base_vas: list[int] | None = None,
        window_size: int = 0,
        shared_ptr_min_vote: int = 0,
        min_instances_for_class: int = 0,
        # --- HeapAttrib (batched VA -> heap alloc) ---
        vas: list[int] | None = None,
        refresh: bool = False,
        va: int | str = 0,
        name: str = "",
    ) -> str:
        """Canonical memory R/W, allocator, scan + forensics surface.
        ``name='user'`` routes through the usermode umagent view (no
        driver); ``kernel=True`` is a legacy alias for ``space='kernel'``.
        Addresses accept int, '0x…' or 'module+offset'. Per-verb
        help: ``memory_manage(action='actions', verb='<verb>')``."""
        # Hard-cut on the moved forwarders: verbs that have a canonical
        # home elsewhere no longer reach the internal dispatcher via
        # ``memory_manage``. Return a ``kind='moved'`` envelope naming
        # the replacement tool/action so callers can retarget.
        if action in _MOVED_VERBS:
            replacement = _MOVED_VERBS[action]
            return _moved_verb("memory_manage", action,
                               replacement["tool"], replacement["action"],
                               replacement.get("note", ""), emit=True)

        # heap_info is wired via the dispatcher below; keep the user-space
        # narrowing check here since the segment-heap decoder is user-mode
        # only.
        def _space_err(verb: str, msg: str) -> str:
            env = _envelope_err(msg, tool="memory_manage", action=verb)
            # envelope_err lets the classifier guess ``kind`` from the
            # text; the space-narrowing refusal is a bad_arg, pin it.
            env["error"]["kind"] = "bad_arg"
            return _j(env)

        if action == "heap_info" and space not in ("", "user"):
            return _space_err(
                action,
                "memory_manage.heap_info: space must be 'user' "
                "(segment heap is user-mode) — drop space= or pass "
                "space='user'")

        # Space narrowing: brief §5.3 restricts vad / heaps to user.
        if action in ("vad", "heaps") and space not in ("", "user"):
            return _space_err(
                action,
                f"memory_manage.{action}: space must be 'user' (VAD / heap "
                "live in user address space) — drop space= or pass "
                "space='user'")

        from .mem import _MEMORY_MANAGE_FN
        if _MEMORY_MANAGE_FN is None:
            return _j({"ok": False, "kind": "internal_error",
                       "error": "memory_manage: internal memory_manage dispatcher "
                                "not initialised",
                       "hint": "ensure tools._mem.register() ran before "
                               "memory.register()"})
        res = await _MEMORY_MANAGE_FN(
            action=action, pid=pid, address=address, size=size,
            data_hex=data_hex, space=space, protect=protect,
            kernel=kernel, pattern_hex=pattern_hex, mask=mask,
            pattern=pattern, base=base, max_results=max_results,
            want_names=want_names, module=module, filter=filter,
            name_regex=name_regex, name_glob=name_glob,
            path_contains=path_contains, compact=compact, summary=summary,
            fields=fields, want_blocks=want_blocks, max_blocks=max_blocks,
            allow_fault=allow_fault, allow_map_write=allow_map_write,
            allow_mmio=allow_mmio, partial=partial, timeout_s=timeout_s,
            value=value, bytes_hex=bytes_hex, arch=arch, syntax=syntax,
            count=count, detail=detail, resolve_symbols=resolve_symbols,
            code=code, write_to=write_to, dry_run=dry_run, limit=limit,
            offset=offset, cursor=cursor, verbosity=verbosity,
            scan_id=scan_id, verify=verify, decode=decode, reads=reads,
            include_ascii=include_ascii, from_va=from_va,
            resolve_physical=resolve_physical, min_len=min_len,
            buckets=buckets, entropy=entropy, path=path, depth=depth,
            all_cpus=all_cpus, sections=sections,
            with_cmdline=with_cmdline, with_context=with_context,
            offsets=offsets, terminal_size=terminal_size,
            expect_ascii=expect_ascii, expect_nonzero=expect_nonzero,
            expect_module=expect_module, needles=needles, scopes=scopes,
            enrich_tags=enrich_tags, kinds=kinds, regex=regex,
            want_object_names=want_object_names, concurrency=concurrency,
            mode=mode, access=access, tid=tid, slot=slot,
            preempt_ok=preempt_ok, verify_signatures=verify_signatures,
            force_recheck=force_recheck,
            writable=writable, executable=executable, cow=cow,
            include_guarded=include_guarded, mem_types=mem_types,
            scope=scope,
            value_type=value_type, op=op, value_hi=value_hi,
            delta=delta, tolerance=tolerance,
            endian=endian, encoding=encoding, align=align,
            confirm_full_space=confirm_full_space,
            # v17 Wave 2 kwargs forwarded through to mem/__init__.py
            # so the pointer-map + dissect dispatch branches can read
            # them.
            map_id=map_id, map_id_b=map_id_b, target_va=target_va,
            max_depth=max_depth, max_offset=max_offset,
            static_only=static_only, fanout_per_level=fanout_per_level,
            wall_ms=wall_ms, remote_path=remote_path,
            keep_disk=keep_disk, chains=chains,
            with_modules=with_modules, disk_spill_mode=disk_spill_mode,
            max_candidates=max_candidates,
            # Wave 3 Phase D (SymbolDecorate) + Wave 3 P1 (DissectCompare)
            decorate=decorate,
            base_vas=base_vas,
            window_size=window_size,
            shared_ptr_min_vote=shared_ptr_min_vote,
            min_instances_for_class=min_instances_for_class,
            # Wave 3 P2: HeapAttrib kwargs forwarded through.
            vas=vas, refresh=refresh, va=va,
            name=name,
        )
        return _pin_tool_name(res)
