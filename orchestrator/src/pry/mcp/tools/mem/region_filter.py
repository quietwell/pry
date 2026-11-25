"""Region filter facility for memory scans (Wave 1 Phase A).

Resolves a scan's effective ``[(va, size), ...]`` span list by
intersecting three sources:

1. **Base spans** — explicit ``address+size``, ``sections=`` (via the
   existing ``_section_spans``), or whole-space (returned as an
   empty list, letting the caller keep its agent-side fast path).
2. **VAD predicate** — bit tests on ``protect``
   (``writable``/``executable``/``cow``/``include_guarded``) and
   subset on ``vad_type`` (``mem_types=['private','image','mapped']``).
3. **Scope** — union of ranges from ``mem_heaps`` / ``mem_modules`` /
   TEB stacks (``thread_list`` + ``mem_read``) when ``scope=`` is set.

Final spans = intersect(base, vad_filtered, scope). Coalesced.

Return convention matches ``_section_spans``:
``(spans, info, err)`` — ``err`` is a ready-to-return error dict on
failure, else ``None``. ``info`` always carries ``region_filter``
and ``notes``; ``notes`` collects partial-coverage reasons so the
caller can attach them to its ``coverage`` field.

Kernel / physical space: VAD is not available. The filter degrades
to a no-op with a ``notes`` entry ``kernel_space_filter_degraded``.
Follow-up phases wire a kernel VA bitmap via ``phys_ranges`` +
``probe_va`` (plan §3.4).

TEB stack layout is x64-only in Wave 1: StackBase at ``TEB+0x08``,
StackLimit at ``TEB+0x10``. x86 / WOW64 is a follow-up.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable


# ---------------------------------------------------------------- flags ----

_PAGE_READWRITE = 0x04
_PAGE_WRITECOPY = 0x08
_PAGE_EXECUTE = 0x10
_PAGE_EXECUTE_READ = 0x20
_PAGE_EXECUTE_READWRITE = 0x40
_PAGE_EXECUTE_WRITECOPY = 0x80
_PAGE_GUARD = 0x100

_WRITABLE_MASK = (_PAGE_READWRITE | _PAGE_WRITECOPY
                  | _PAGE_EXECUTE_READWRITE | _PAGE_EXECUTE_WRITECOPY)
_EXECUTABLE_MASK = (_PAGE_EXECUTE | _PAGE_EXECUTE_READ
                    | _PAGE_EXECUTE_READWRITE | _PAGE_EXECUTE_WRITECOPY)
_COW_MASK = _PAGE_WRITECOPY | _PAGE_EXECUTE_WRITECOPY


# vad_type label -> int. Short CE-shaped labels first (``private`` /
# ``image``) and the ``Vad*`` names from _decode_enums.VAD_TYPES for
# callers who know the Windows internals terminology.
#
# **No ``mapped`` label in this wave.** Memory-mapped files land in
# ``VadNone`` (0) with a non-null ``ControlArea`` — not in any
# distinct vad_type — so a ``mapped`` label keyed on vad_type would
# either collapse into ``private`` (misleading) or map to
# ``VadDevicePhysicalMemory`` (reserved for AWE, essentially empty
# in user processes). Callers who need the full set pass raw ints
# via ``mem_types=[3,4,5]`` etc.; the real fix lands in Wave 2 when
# the agent enriches VAD rows with a ``has_control_area`` flag.
_VAD_TYPE_LABELS: dict[str, int] = {
    "private": 0,  # VadNone (also where file-mapped views live today)
    "image": 2,  # VadImageMap (PE images / DLLs / EXEs)
    "awe": 3,
    "writewatch": 4,
    "largepages": 5,
    "rotatephysical": 6,
    "largepagesection": 7,
    "vadnone": 0,
    "vaddevicephysicalmemory": 1,
    "vadimagemap": 2,
    "vadawe": 3,
    "vadwritewatch": 4,
    "vadlargepages": 5,
    "vadrotatephysical": 6,
    "vadlargepagesection": 7,
}


# --------------------------------------------------------------- probes ----

def _any_region_flag_set(*, writable: bool, executable: bool, cow: bool,
                         include_guarded: bool,
                         mem_types: list[str] | None,
                         scope: str) -> bool:
    """True iff at least one region-filter kwarg is set to a non-default."""
    return (bool(writable) or bool(executable) or bool(cow)
            or bool(include_guarded) or bool(mem_types)
            or bool(scope and scope.strip().lower() not in ("", "all")))


def _mem_types_to_ints(mem_types: list[str] | None,
                       notes: list[str]) -> set[int] | None:
    if not mem_types:
        return None
    out: set[int] = set()
    for t in mem_types:
        k = str(t).strip().lower()
        if k in _VAD_TYPE_LABELS:
            out.add(_VAD_TYPE_LABELS[k])
            continue
        try:
            out.add(int(k, 0))
        except (ValueError, TypeError):
            notes.append(f"mem_types_unknown:{t}")
    return out or None


def _vad_predicate(*, writable: bool, executable: bool, cow: bool,
                   include_guarded: bool,
                   want_types: set[int] | None) -> Callable[[dict], bool]:
    """Build a VAD-row predicate from the region-filter flags.

    All non-default flags AND together. Unset flags don't filter.
    PAGE_GUARD rows are dropped unless ``include_guarded`` is True.
    """
    def pred(row: dict) -> bool:
        protect = int(row.get("protect", 0))
        if not include_guarded and (protect & _PAGE_GUARD):
            return False
        if writable and not (protect & _WRITABLE_MASK):
            return False
        if executable and not (protect & _EXECUTABLE_MASK):
            return False
        if cow and not (protect & _COW_MASK):
            return False
        if want_types is not None:
            if int(row.get("vad_type", 0)) not in want_types:
                return False
        return True
    return pred


# --------------------------------------------------------------- scopes ----

async def _heap_spans(c, pid: int) -> tuple[list[tuple[int, int]], list[str]]:
    notes: list[str] = []
    try:
        heaps = await c.mem_heaps(pid=pid)
    except Exception as exc:  # noqa: BLE001 - surfaced as a note
        return [], [f"heaps_failed:{type(exc).__name__}"]
    spans: list[tuple[int, int]] = []
    for h in heaps or []:
        base = int(h.get("base") or 0)
        size = int(h.get("committed") or h.get("reserved") or 0)
        if base and size:
            spans.append((base, size))
    if heaps and not spans:
        notes.append("heaps_empty")
    return spans, notes


async def _image_spans(c, pid: int,
                       kernel_lookup: bool) -> tuple[list[tuple[int, int]], list[str]]:
    notes: list[str] = []
    try:
        mods = await c.mem_modules(pid=pid, kernel=kernel_lookup)
    except Exception as exc:  # noqa: BLE001
        return [], [f"modules_failed:{type(exc).__name__}"]
    spans: list[tuple[int, int]] = []
    for m in mods or []:
        base = int(m.get("base") or 0)
        size = int(m.get("size") or 0)
        if base and size:
            spans.append((base, size))
    if mods and not spans:
        notes.append("images_empty")
    return spans, notes


async def _stack_spans(c, pid: int) -> tuple[list[tuple[int, int]], list[str]]:
    """Walk each thread's TEB to extract StackBase/StackLimit.

    x64-only in Wave 1 (TEB layout: StackBase at +0x08, StackLimit at
    +0x10). Per-thread read failures are counted into ``notes``.
    """
    notes: list[str] = []
    try:
        res = await c.thread_list(pid=pid)
    except Exception as exc:  # noqa: BLE001
        return [], [f"thread_list_failed:{type(exc).__name__}"]
    threads = res.get("threads", []) if isinstance(res, dict) else []
    failed = 0
    spans: list[tuple[int, int]] = []
    for t in threads or []:
        teb = int(t.get("teb") or 0)
        if not teb:
            continue
        try:
            data = await c.mem_read(pid, teb + 0x08, 16, "user",
                                    partial=True)
        except Exception:  # noqa: BLE001
            failed += 1
            continue
        if isinstance(data, tuple):  # want_meta=True variant
            data = data[0]
        if not data or len(data) < 16:
            failed += 1
            continue
        base = int.from_bytes(data[0:8], "little")
        limit = int.from_bytes(data[8:16], "little")
        if base <= limit:
            failed += 1
            continue
        spans.append((limit, base - limit))
    if failed:
        notes.append(f"teb_read_failed:{failed}")
    return spans, notes


# -------------------------------------------------------- span algebra ----

def _coalesce(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping / adjacent (va, size) spans. Input may be unsorted."""
    pairs = sorted((s, s + sz) for s, sz in ranges if sz > 0)
    out: list[list[int]] = []
    for s, e in pairs:
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e - s) for s, e in out]


def _intersect(a: list[tuple[int, int]],
               b: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Intersect two (va, size) span lists. Both must be coalesced + sorted."""
    a_pairs = [(s, s + sz) for s, sz in a]
    b_pairs = [(s, s + sz) for s, sz in b]
    i = j = 0
    out: list[tuple[int, int]] = []
    while i < len(a_pairs) and j < len(b_pairs):
        a_lo, a_hi = a_pairs[i]
        b_lo, b_hi = b_pairs[j]
        lo = max(a_lo, b_lo)
        hi = min(a_hi, b_hi)
        if lo < hi:
            out.append((lo, hi - lo))
        if a_hi < b_hi:
            i += 1
        else:
            j += 1
    return out


# ------------------------------------------------------------- public ----

async def resolve_spans(
    c, *,
    pid: int,
    space: str,
    kernel_lookup: bool,
    # base range picker (same conventions as _section_spans + raw window)
    address: int = 0,
    size: int = 0,
    sections: str = "",
    module: str = "",
    # region-filter flags
    writable: bool = False,
    executable: bool = False,
    cow: bool = False,
    include_guarded: bool = False,
    mem_types: list[str] | None = None,
    scope: str = "",
) -> tuple[list[tuple[int, int]], dict[str, Any], dict[str, Any] | None]:
    """Resolve the final ``(va, size)`` spans for a scan.

    Returns ``(spans, info, err)`` matching ``_section_spans``:
    - ``spans`` — coalesced final list; empty when no region flag and
      no explicit base was given (caller's whole-space fast path
      applies).
    - ``info`` — always has ``region_filter`` + ``notes``; when
      ``sections=`` was set, carries the same keys ``_section_spans``
      emits (``module_base``, ``sections``, ``spans``, ``size_of_image``,
      ``sections_unmatched``) so callers that consumed the old shape
      don't need to change.
    - ``err`` — ready-to-return envelope dict on failure, else None.
    """
    # Local import to avoid a circular reference with mem/scan.py.
    from .scan import _section_spans

    notes: list[str] = []
    info: dict[str, Any] = {
        "region_filter": {
            "writable": bool(writable),
            "executable": bool(executable),
            "cow": bool(cow),
            "include_guarded": bool(include_guarded),
            "mem_types": list(mem_types) if mem_types else [],
            "scope": (scope or "").strip().lower() or "all",
        },
        "notes": notes,
    }

    # 1) Base spans ---------------------------------------------------------
    base_spans: list[tuple[int, int]] | None
    if sections:
        spans, sinfo, serr = await _section_spans(
            c, pid, space, sections, module, address, kernel_lookup)
        if serr:
            return [], info, serr
        base_spans = spans
        # Keep _section_spans's flat info keys next to region_filter so
        # existing envelope consumers (pattern_scan path) still work.
        info.update(sinfo)
    elif size:
        base_spans = [(int(address), int(size))]
    else:
        base_spans = None  # whole-space sentinel

    any_region = _any_region_flag_set(
        writable=writable, executable=executable, cow=cow,
        include_guarded=include_guarded, mem_types=mem_types, scope=scope)

    # Pure-base case: no region filter. Return base spans unchanged.
    if not any_region:
        return (base_spans or []), info, None

    # Validate scope eagerly so the error names the offending value.
    sc = (scope or "").strip().lower()
    if sc and sc not in ("all", "heap", "stack", "image"):
        return [], info, {
            "ok": False, "kind": "bad_arg",
            "error": f"region_filter: unknown scope={scope!r}",
            "hint": "scope must be one of: heap, stack, image, all",
        }

    # Kernel / physical: VAD not available — degrade cleanly.
    if space in ("kernel", "physical"):
        notes.append("kernel_space_filter_degraded")
        return (base_spans or []), info, None

    # 2) VAD-filtered spans (user space only) -------------------------------
    try:
        vads = await c.vad_list(pid)
    except Exception as exc:  # noqa: BLE001
        notes.append(f"vad_failed:{type(exc).__name__}")
        return (base_spans or []), info, None

    want_types = _mem_types_to_ints(mem_types, notes)
    pred = _vad_predicate(writable=writable, executable=executable,
                          cow=cow, include_guarded=include_guarded,
                          want_types=want_types)
    vad_ranges: list[tuple[int, int]] = []
    for row in vads or []:
        start_v = row.get("start", 0)
        end_v = row.get("end", 0)
        start_i = int(start_v, 0) if isinstance(start_v, str) else int(start_v)
        end_i = int(end_v, 0) if isinstance(end_v, str) else int(end_v)
        if end_i <= start_i:
            continue
        if pred(row):
            vad_ranges.append((start_i, end_i - start_i))
    vad_ranges = _coalesce(vad_ranges)
    info["vad_match_count"] = len(vad_ranges)

    # 3) Scope spans --------------------------------------------------------
    scope_spans: list[tuple[int, int]] | None
    if not sc or sc == "all":
        scope_spans = None
    elif sc == "heap":
        s, n = await _heap_spans(c, pid)
        notes.extend(n)
        scope_spans = _coalesce(s)
        info["scope_heap_span_count"] = len(scope_spans)
    elif sc == "image":
        s, n = await _image_spans(c, pid, kernel_lookup)
        notes.extend(n)
        scope_spans = _coalesce(s)
        info["scope_image_span_count"] = len(scope_spans)
    elif sc == "stack":
        s, n = await _stack_spans(c, pid)
        notes.extend(n)
        scope_spans = _coalesce(s)
        info["scope_stack_span_count"] = len(scope_spans)
    else:  # pragma: no cover - validated above
        scope_spans = None

    # 4) Intersect ----------------------------------------------------------
    final: list[tuple[int, int]] = vad_ranges
    if scope_spans is not None:
        final = _intersect(final, scope_spans)
    if base_spans is not None:
        final = _intersect(final, _coalesce(base_spans))
    info["final_span_count"] = len(final)

    if not final:
        return [], info, {
            "ok": False, "kind": "no_match",
            "error": "region_filter: no spans match the given filter",
            "hint": ("drop one of writable/executable/cow/mem_types/scope "
                     "or widen address+size"),
        }
    return final, info, None


__all__ = [
    "resolve_spans",
    "_any_region_flag_set",
    "_coalesce",
    "_intersect",
    "_vad_predicate",
    "_mem_types_to_ints",
    "_heap_spans",
    "_image_spans",
    "_stack_spans",
    "_WRITABLE_MASK",
    "_EXECUTABLE_MASK",
    "_COW_MASK",
    "_PAGE_GUARD",
    "_VAD_TYPE_LABELS",
]
