"""SymbolDecorator — orchestrator-side VA -> ``module!Symbol+disp``
enrichment pass for pointer-map chains, dissect slots and access-trace
pages (Memory scanner wave 3 Phase D, plan §5).

The decoration is a *pure wrapper* around the existing PDB cache
exposed by ``symbols_manage``. There is no new RPC, no proto change —
the call chain goes: handler -> ``SymbolDecorator.decorate_vas`` ->
``symbols_manage.lookup_batch`` -> ``symbols.lookup_rva`` (dbghelp).

Design notes (plan §5.2):

* ``decorate_vas`` is the canonical entry point. It dedupes, partitions
  the input against an LRU, issues **one** ``lookup_batch`` for the
  cache misses, warms the LRU with every result (negative cache
  included so a repeat miss doesn't re-RPC), and returns the final
  mapping.
* Labels are only emitted when ``confidence='high'`` and the record
  carries both ``module`` and ``symbol``. ``confidence='low'`` (nearest-
  match guessing past ``max_disp``) and "no containing module"
  resolve to ``None`` so callers can tell the difference from "we
  haven't tried this VA yet" (missing key) and "we tried and it's
  unlabeled" (``None`` value).
* ``decorate_chain``/``decorate_dissect``/``decorate_access_trace_page``
  are convenience wrappers that walk a response shape, pull the VAs,
  ask ``decorate_vas`` for labels, and stamp them back on the dict in
  place. They never raise — a resolver failure just leaves the input
  undecorated, since decoration is advisory.
* No PDB cached => ``decorate_vas`` returns ``{va: None}`` for every
  input and callers see a plain response, same as before Wave 3.
"""
from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any, Awaitable, Callable


log = logging.getLogger("pry.mcp.tools.mem._decorate")


# Sentinel used by the LRU to tell "cache miss" from "cached None".
_MISS = object()


class _LRU:
    """Minimal ordered-dict LRU that also caches ``None`` values.

    Values default to ``str | None`` for this module; ``_MISS`` is only
    ever returned from :meth:`get` as the sentinel the caller passes in.
    """

    __slots__ = ("_cap", "_d")

    def __init__(self, cap: int) -> None:
        self._cap = max(1, int(cap))
        self._d: OrderedDict[int, Any] = OrderedDict()

    def get(self, key: int, sentinel: Any = _MISS) -> Any:
        if key in self._d:
            self._d.move_to_end(key)
            return self._d[key]
        return sentinel

    def put(self, key: int, value: Any) -> None:
        if key in self._d:
            self._d.move_to_end(key)
            self._d[key] = value
            return
        self._d[key] = value
        while len(self._d) > self._cap:
            self._d.popitem(last=False)

    def __contains__(self, key: int) -> bool:  # pragma: no cover - helper
        return key in self._d

    def __len__(self) -> int:
        return len(self._d)


# Type alias for the pluggable lookup backend. Tests inject a mock.
_LookupBatch = Callable[..., Awaitable[dict[int, dict[str, Any] | None]]]


def _default_lookup_backend(
        ctx: Any, *, view: str, pid: int, vas: list[int], max_disp: int
) -> Awaitable[dict[int, dict[str, Any] | None]]:
    """Resolve lazily so a bare import of this module doesn't force
    dbghelp (or the symbols tool) to load. Returns an awaitable that
    maps each input VA to its lookup record or ``None`` when the VA
    doesn't resolve to a known module/symbol."""
    from ..symbols import _lookup_batch_core  # local import — avoids cycle

    return _lookup_batch_core(ctx, view=view, pid=pid, vas=vas,
                              max_disp=max_disp)


class SymbolDecorator:
    """Post-decorate orchestrator-shaped responses with symbol labels.

    One instance per decoration scope is cheap — the LRU is in-process
    and lives for the instance's lifetime. Handlers typically build a
    short-lived decorator per response.
    """

    def __init__(self, ctx: Any, *, max_disp: int = 0x400,
                 cache_size: int = 2048,
                 _lookup_backend: _LookupBatch | None = None) -> None:
        self._ctx = ctx
        self._max_disp = int(max_disp)
        self._cache = _LRU(int(cache_size))
        # Pluggable so tests can inject a fake without monkey-patching
        # the symbols tool module globally.
        self._lookup_backend: _LookupBatch = (
            _lookup_backend or _default_lookup_backend)

    # ------------------------------------------------------- helpers ---------

    @staticmethod
    def _fmt(record: dict[str, Any] | None) -> str | None:
        """``{module, symbol, displacement, confidence}`` ->
        ``'module!Symbol+0xNN'`` (or ``'module!Symbol'`` when
        displacement is zero). Returns ``None`` for low-confidence hits
        or records without a resolved module."""
        if not record:
            return None
        if str(record.get("confidence") or "") == "low":
            return None
        mod = str(record.get("module") or "")
        if not mod:
            return None
        sym = record.get("symbol")
        if not sym:
            return None
        try:
            disp = int(record.get("displacement") or 0)
        except (TypeError, ValueError):
            disp = 0
        return f"{mod}!{sym}+{disp:#x}" if disp else f"{mod}!{sym}"

    @staticmethod
    def _norm_va(v: Any) -> int | None:
        """Coerce an arbitrary chain/slot VA to an int, or ``None`` if
        it doesn't parse. Chains ship ints; slots do too; the extra
        belt-and-braces matches the hex-mirror layer elsewhere in the
        tool surface."""
        if v is None:
            return None
        if isinstance(v, bool):
            return None  # guard against stray booleans passed as ints
        if isinstance(v, int):
            return v if v else None
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return None
            try:
                return int(s, 0)
            except (TypeError, ValueError):
                return None
        return None

    # ------------------------------------------------ public API -------------

    async def decorate_vas(self, view: str, pid: int,
                           vas: list[int]) -> dict[int, str | None]:
        """Return ``{va -> label | None}`` for every unique input VA.

        Dedupes the input, partitions it against the LRU, issues exactly
        one ``lookup_batch`` for the misses, then warms the LRU with the
        resulting labels (``None`` cached as a negative hit).
        """
        unique: list[int] = []
        seen: set[int] = set()
        for raw in (vas or []):
            va = self._norm_va(raw)
            if va is None or va in seen:
                continue
            seen.add(va)
            unique.append(va)
        if not unique:
            return {}

        out: dict[int, str | None] = {}
        misses: list[int] = []
        for va in unique:
            cached = self._cache.get(va)
            if cached is _MISS:
                misses.append(va)
            else:
                out[va] = cached

        if misses:
            try:
                records = await self._lookup_backend(
                    self._ctx, view=view, pid=pid,
                    vas=misses, max_disp=self._max_disp)
            except Exception:  # noqa: BLE001 - decoration never fails the parent
                log.exception("decorate_vas: lookup_batch backend raised; "
                              "returning empty labels for %d VAs", len(misses))
                records = {}
            # Backend contract: dict keyed by int VA; missing keys mean
            # "no containing module / no PDB coverage" -> label is None.
            for va in misses:
                rec = records.get(va) if isinstance(records, dict) else None
                label = self._fmt(rec)
                self._cache.put(va, label)
                out[va] = label

        return out

    async def decorate_chain(self, chain: dict) -> dict:
        """Collect every VA in ``chain.hops[]`` (and the chain's
        ``anchor_va``) into one batch, then stamp ``.hop_sym`` on each
        hop where the lookup succeeded, plus ``anchor_sym`` on the
        chain itself.

        View/pid are read from ``chain['_view']`` / ``chain['_pid']``
        when the caller wires them; absent that, the chain is returned
        unchanged. Handlers that already know ``view`` + ``pid`` should
        prefer :meth:`decorate_vas` and batch across every chain in the
        response to amortize the backend RPC.
        """
        if not isinstance(chain, dict):
            return chain
        view = str(chain.get("_view") or "")
        pid = int(chain.get("_pid") or 0)
        if not view:
            return chain

        anchor_va = self._norm_va(chain.get("anchor_va"))
        vas: list[int] = []
        if anchor_va is not None:
            vas.append(anchor_va)
        hops = chain.get("hops")
        if isinstance(hops, list):
            for h in hops:
                if isinstance(h, dict):
                    va = self._norm_va(h.get("va"))
                    if va is not None:
                        vas.append(va)
        if not vas:
            return chain

        labels = await self.decorate_vas(view, pid, vas)
        if anchor_va is not None:
            lbl = labels.get(anchor_va)
            if lbl:
                chain["anchor_sym"] = lbl
        if isinstance(hops, list):
            for h in hops:
                if not isinstance(h, dict):
                    continue
                va = self._norm_va(h.get("va"))
                if va is None:
                    continue
                lbl = labels.get(va)
                if lbl:
                    h["hop_sym"] = lbl
        return chain

    async def decorate_dissect(self, resp: dict) -> dict:
        """Collect every ``slot.ptr_target_va`` whose ``slot.ptr_module``
        is set and batch them into a single ``lookup_batch``. Stamps
        ``slot.ptr_sym`` on each resolved slot.

        Operates on both the raw agent-shape ``{"slots": [...]}`` and
        the orchestrator envelope ``{"data": {"slots": [...]}, ...}``.
        View/pid are read from the response envelope (``target`` /
        ``_view`` / ``data.pid`` / ``_pid``); absent either, the slots
        are returned unchanged.
        """
        if not isinstance(resp, dict):
            return resp
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        if not isinstance(data, dict):
            return resp
        slots = data.get("slots")
        if not isinstance(slots, list):
            return resp
        view = str(resp.get("target") or resp.get("_view")
                   or data.get("_view") or "")
        pid = int(data.get("pid") or resp.get("_pid") or data.get("_pid") or 0)
        if not view:
            return resp
        vas: list[int] = []
        for s in slots:
            if not isinstance(s, dict):
                continue
            if not s.get("ptr_module"):
                continue
            va = self._norm_va(s.get("ptr_target_va"))
            if va is not None:
                vas.append(va)
        if not vas:
            return resp
        labels = await self.decorate_vas(view, pid, vas)
        for s in slots:
            if not isinstance(s, dict):
                continue
            va = self._norm_va(s.get("ptr_target_va"))
            if va is None:
                continue
            lbl = labels.get(va)
            if lbl:
                s["ptr_sym"] = lbl
        return resp

    async def decorate_access_trace_page(self, page: dict) -> dict:
        """Stamp ``rip_sym`` on each hit in an AccessTrace status page.

        Stub-grade in F1 — AccessTrace lands in Wave 3 Phase G (P4) and
        may extend the enriched fields (stack-frame symbols, memop
        base-reg labels). The minimal implementation here covers the
        single most-wanted field (``hit.rip``) so P4 can start consuming
        it immediately; new fields fold in as the P4 shape settles.
        """
        if not isinstance(page, dict):
            return page
        data = page.get("data") if isinstance(page.get("data"), dict) else page
        if not isinstance(data, dict):
            return page
        hits = data.get("hits")
        if not isinstance(hits, list):
            return page
        view = str(page.get("target") or page.get("_view")
                   or data.get("_view") or "")
        pid = int(data.get("pid") or page.get("_pid") or data.get("_pid") or 0)
        if not view:
            return page
        vas: list[int] = []
        for h in hits:
            if not isinstance(h, dict):
                continue
            va = self._norm_va(h.get("rip"))
            if va is not None:
                vas.append(va)
        if not vas:
            return page
        labels = await self.decorate_vas(view, pid, vas)
        for h in hits:
            if not isinstance(h, dict):
                continue
            va = self._norm_va(h.get("rip"))
            if va is None:
                continue
            lbl = labels.get(va)
            if lbl:
                h["rip_sym"] = lbl
        return page
