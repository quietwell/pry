"""AccessTrace dbgeng driver (fallback path).

Composes the following agent RPCs, per plan §4:

    debug_manage(action='attach', pid, monitor=True)
    bp_manage(action='add', hw=True, access=...)         # bp_id
    Debug.StreamEvents(filter kind=BREAKPOINT_HW
                       && bp_id == our_id)
    GetRegs                                              # per-hit
    Memory.Read(16 bytes at RIP)                         # per-hit
    Stackwalk.Walk(pid, tid, max_frames=8)               # per-hit

No new security flag — the existing ``bp_manage.add(hw=True)`` gate
is unchanged, so AccessTrace with ``driver='dbgeng'`` inherits
whatever controls shipped with dbgeng's hw-bp surface.

The driver share hit decoration with ``_watchhw_driver`` — same
Capstone memop decoder, same batched-symbolize contract, same ring
trim.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

from ._watchhw_driver import _CLASS_BP, _SW_MAX_FRAMES, _consume_events, WatchhwJobCtx


# Debug-event kind strings the agent surfaces for HW breakpoint hits.
# Mirrors agent_client.debug.debug_stream_events which lifts proto
# ``DebugEvent.kind`` into a Python enum spelled "breakpoint_hw" /
# "BREAKPOINT_HW" depending on build. We accept both spellings so the
# driver doesn't tie itself to one shape.
_HW_BP_KINDS: frozenset[str] = frozenset(
    {"BREAKPOINT_HW", "breakpoint_hw", "HW_BREAKPOINT", "hw_breakpoint"}
)


async def _attach_monitor(client, *, pid: int) -> dict[str, Any]:
    """Call ``debug_attach(..., monitor=True)`` with graceful fallback
    for older agents that don't know the kwarg. Returns a status
    dict; the caller gives up on ``ok=False``."""
    try:
        r = await client.debug_attach(int(pid), monitor=True)
    except TypeError:
        # Older wrapper lacks the monitor kwarg.
        r = await client.debug_attach(int(pid))
    return dict(r or {})


async def _bp_add_hw(client, *, address: int, size: int, access: str,
                     pid: int, tid: int) -> dict[str, Any]:
    """Thin ``bp_manage.add(hw=True)`` call. Returns ``{ok, bp_id}``;
    ``bp_id=0`` on failure."""
    try:
        r = await client.bp_add(
            kind="hw", address=int(address), size=int(size),
            access=str(access), pid=int(pid), tid=int(tid),
            via_debugger=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                "bp_id": 0}
    return {"ok": True, "bp_id": int((r or {}).get("bp_id") or 0)}


class _DebugEventStreamAdapter:
    """Shim that turns ``Debug.StreamEvents`` into the (``.events[]``,
    ``.dropped``) chunk shape ``_consume_events`` expects.

    Each raw ``DebugEvent`` becomes a one-event chunk; we filter on
    ``bp_id == our_id`` + ``kind in _HW_BP_KINDS`` so the generic
    loop only sees AccessTrace's own hits.
    """

    def __init__(self, inner_iter, *, bp_id: int) -> None:
        self._inner = inner_iter
        self._bp_id = int(bp_id)

    def __aiter__(self):
        return self

    async def __anext__(self):
        while True:
            try:
                ev = await self._inner.__anext__()
            except StopAsyncIteration:
                raise
            kind_val = getattr(ev, "kind", None)
            kind_str = kind_val.name if hasattr(kind_val, "name") else str(kind_val)
            if kind_str not in _HW_BP_KINDS:
                continue
            if int(getattr(ev, "bp_id", 0) or 0) != self._bp_id:
                continue
            # Normalize the DebugEvent into the EventStream chunk shape
            # ``_consume_events`` expects — kind becomes the _CLASS_BP
            # bit so the generic loop treats it as a BP_HIT, address /
            # pid / tid / seq / dropped flow through unchanged.
            norm = type("E", (), {})()
            norm.kind = _CLASS_BP
            norm.seq = int(getattr(ev, "seq", 0) or 0)
            norm.pid = int(getattr(ev, "pid", 0) or 0)
            norm.tid = int(getattr(ev, "tid", 0) or 0)
            norm.address = int(getattr(ev, "address", 0) or 0)
            norm.dropped = bool(getattr(ev, "dropped", False))
            norm.dr6 = int(getattr(ev, "dr6", 0) or 0)
            norm.bp_id = int(getattr(ev, "bp_id", 0) or 0)
            norm.slot = int(getattr(ev, "slot", 0) or 0)
            norm.access = int(getattr(ev, "access", 0) or 0)
            chunk = type("Chunk", (), {})()
            chunk.events = [norm]
            chunk.dropped = int(getattr(ev, "dropped_count", 0) or 0)
            return chunk


async def run_dbgeng_driver(
    *, ctx, client, job: dict[str, Any], job_ctx: WatchhwJobCtx,
    symbolize_batch: Callable[[list[int]], Awaitable[dict[int, dict | None]]] | None = None,
) -> dict[str, Any]:
    """Arm a hw bp through dbgeng, drain its event stream, release
    on exit. Top-level entry point mirroring ``run_watchhw_driver``.
    """
    att = await _attach_monitor(client, pid=job_ctx.pid)
    if not att.get("ok", True):
        return {"ok": False, "driver": "dbgeng",
                "error": att.get("error") or "debug_attach failed",
                "kind": att.get("kind") or "dbgeng_attach_failed",
                "bp_id": 0}
    bp = await _bp_add_hw(
        client, address=job_ctx.address, size=job_ctx.size,
        access=job_ctx.access, pid=job_ctx.pid, tid=job_ctx.tid,
    )
    if not bp.get("ok"):
        return {"ok": False, "driver": "dbgeng",
                "error": bp.get("error") or "bp_add(hw=True) failed",
                "kind": "dbgeng_bp_add_failed",
                "bp_id": 0}
    bp_id = int(bp["bp_id"])

    deadline_ts = time.monotonic() + max(1, int(job_ctx.timeout_s or 300))
    # Open the dbgeng event stream. The agent exposes a coroutine
    # ``debug_stream_events`` whose return is an async iterator (set
    # at import-time on `client.debug.StreamEvents`); we adapt it to
    # the ``.events[]``/``.dropped`` chunk shape ``_consume_events``
    # consumes.
    try:
        raw_stream = client.debug_stream_events(
            duration_ms=int(max(1, job_ctx.timeout_s) * 1000))
    except Exception as exc:  # noqa: BLE001
        try:
            await client.bp_remove(bp_id)
        except Exception:
            pass
        return {"ok": False, "driver": "dbgeng",
                "error": f"Debug.StreamEvents open failed: {exc}",
                "kind": "dbgeng_stream_open_failed",
                "bp_id": bp_id}
    # Normalize to the consumer's expected shape.
    if hasattr(raw_stream, "__aiter__"):
        adapted = _DebugEventStreamAdapter(raw_stream.__aiter__(), bp_id=bp_id)
    else:
        # Awaitable-returning variant.
        adapted = _DebugEventStreamAdapter(
            (await raw_stream).__aiter__(), bp_id=bp_id)

    def _on_hit(h: dict[str, Any]) -> None:
        job["hits"].append(h)
        cap = int(job.get("ring_cap") or 4096)
        if len(job["hits"]) > cap:
            dropped_here = len(job["hits"]) - cap
            del job["hits"][:dropped_here]
            job["ring_truncated"] = True
        job["hits_so_far"] = int(job.get("hits_so_far", 0)) + 1
        job["last_hit_ts"] = h.get("ts", 0.0)
        h["bp_id"] = bp_id

    def _on_drop(n: int) -> None:
        job["kernel_dropped"] = max(int(job.get("kernel_dropped") or 0), n)

    job_ctx = WatchhwJobCtx(**{**job_ctx.__dict__,
                                "symbolize_batch": symbolize_batch})

    try:
        summary = await _consume_events(
            stream=adapted, job_ctx=job_ctx, client=client,
            on_hit=_on_hit, drop_sink=_on_drop,
            watch_cookie=bp_id, deadline_ts=deadline_ts,
        )
    finally:
        try:
            await client.bp_remove(bp_id)
        except Exception as exc:  # noqa: BLE001
            job["disarm_error"] = f"{type(exc).__name__}: {exc}"
    syms = summary.get("symbols") or {}
    if syms:
        for h in job["hits"]:
            try:
                rip = int(h.get("rip") or 0)
            except Exception:
                continue
            rec = syms.get(rip)
            if rec is not None:
                h["symbol"] = {
                    "module": rec.get("module"),
                    "name": rec.get("symbol"),
                    "displacement": rec.get("displacement"),
                    "confidence": rec.get("confidence"),
                }
    job["kernel_missed"] = int(summary.get("kernel_missed", 0))
    return {"ok": True, "driver": "dbgeng",
            "bp_id": bp_id,
            "total": summary.get("total", 0),
            "last_seq": summary.get("last_seq", 0)}
