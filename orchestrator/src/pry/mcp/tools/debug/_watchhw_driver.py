"""AccessTrace watchhw driver (primary path).

Composes the following agent RPCs, per plan §4:

    WatchHw.Add(preempt_ok=False)        # arm the DR slot
    Events.Stream(kinds_mask=(1<<6),     # drain BP_HIT events
                  dangerous_ok=True)
    GetRegs                              # per-hit live GPR snapshot
    Memory.Read(16 bytes at RIP)         # per-hit Capstone decoder feed
    Stackwalk.Walk(pid, tid,             # per-hit SI #9 kernel+user
                   max_frames=8)         # frames (opt-in)

Each dispatch produces a ``Hit`` record and appends it to the shared
ring on the caller's job. ``run`` is intended to be spawned as a
single asyncio task owned by the ``_ATJOBS`` entry.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable

from ._x64_memop import decode_memop, effective_address

# Driver service name on the agent-side events bus — mirrors
# ``event_manage``'s ``_CLASS_BP = 1 << 6`` (see tools/events.py). This
# is the SUBSCRIPTION MASK bit; a streamed event carries the KIND value.
_CLASS_BP = 1 << 6
# proto EventsKind.EVENTS_KIND_BP_HIT — what PryEvent.kind holds for a
# BP hit. The old filter compared kind against the mask bit (64), so
# every real agent hit was dropped. 64 stays accepted only because the
# dbgeng driver's adapter normalizes its DebugEvents to that marker.
_KIND_BP_HIT = 6
_BP_HIT_KINDS = frozenset({_KIND_BP_HIT, _CLASS_BP})
_BP_HIT_NAMES = frozenset({"EVENTS_KIND_BP_HIT", "KIND_BP_HIT", "BP_HIT"})

# x86 instructions are at most 15 bytes; a data breakpoint is a TRAP, so
# the reported RIP is the instruction AFTER the access and the accessing
# instruction is found by decoding backwards from RIP.
_MAX_INSN = 15
_U64 = (1 << 64) - 1


def _is_bp_hit(kind: Any) -> bool:
    """Event-kind test tolerant of int / enum / proto-name spellings."""
    if isinstance(kind, bool) or kind is None:
        return False
    name = getattr(kind, "name", None)
    if isinstance(name, str) and name.upper() in _BP_HIT_NAMES:
        return True
    if isinstance(kind, str):
        s = kind.strip()
        if s.upper() in _BP_HIT_NAMES:
            return True
        try:
            return int(s, 0) in _BP_HIT_KINDS
        except ValueError:
            return False
    try:
        return int(kind) in _BP_HIT_KINDS
    except (TypeError, ValueError):
        return False


def _reg_int(v: Any) -> int | None:
    """Register value -> int. ``MessageToDict`` renders uint64 fields as
    DECIMAL strings ("140737488355328"); hand-built dicts use ints or
    "0x…" hex. Anything else (warnings list, error text) -> None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v & _U64
    if isinstance(v, str):
        s = v.strip()
        try:
            if s.lower().startswith(("0x", "-0x")):
                return int(s, 16) & _U64
            if s.lstrip("-").isdigit():
                return int(s, 10) & _U64
        except ValueError:
            return None
    return None


def _regs_ints(regs: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for k, v in (regs or {}).items() if isinstance(regs, dict) else ():
        iv = _reg_int(v)
        if iv is not None:
            out[str(k).lower()] = iv
    return out


def _insn_len(code: bytes, addr: int) -> int | None:
    """Length of the single instruction at ``code[0:]`` (capstone)."""
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ImportError:  # pragma: no cover — capstone is a hard dep
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(code, addr, count=1):
        return int(ins.size)
    return None


def _decode_at(code: bytes, addr: int):
    """``(memop, insn_len)`` for the instruction at ``addr``."""
    ln = _insn_len(code, addr)
    if ln is None:
        return None, None
    return decode_memop(code[:ln], rip=addr), ln


def _decode_trap(window: bytes, win_base: int, rip: int, regs: dict[str, int],
                 watch_lo: int, watch_hi: int, want_write: bool):
    """Find the instruction that ENDS at ``rip`` (data-breakpoint trap).

    Every start ``rip-k`` (k = 1..15) whose single decoded instruction is
    exactly ``k`` bytes long and has a memory operand is a candidate.
    Ranking: effective address overlaps the watched range, access kind
    agrees with the armed DR (write vs read), then the longest encoding
    (prefix/REX bytes belong to the real instruction more often than to
    its predecessor). Returns ``(memop, start, ea, n_candidates)`` or
    ``None``. Registers are the post-access snapshot, so an instruction
    that rewrote its own base register resolves approximately.
    """
    cands = []
    for k in range(1, _MAX_INSN + 1):
        start = rip - k
        off = start - win_base
        if off < 0:
            break
        code = window[off:off + _MAX_INSN]
        memop, ln = _decode_at(code, start)
        if ln != k or memop is None:
            continue
        ea = effective_address(memop, regs, rip_next=rip)
        width = max(1, int(memop.size_bytes or 1))
        overlap = ea < watch_hi and ea + width > watch_lo
        kind_ok = (memop.access in ("write", "rw")) if want_write else True
        cands.append(((overlap, kind_ok, k), memop, start, ea))
    if not cands:
        return None
    cands.sort(key=lambda c: c[0], reverse=True)
    _rank, memop, start, ea = cands[0]
    return memop, start, ea, len(cands)

# Rate the symbol-lookup batcher fires at: a batch of 32 RIPs OR a
# 100 ms timer, whichever lands first. Plan §4 (the batched-symbolize
# contract with F1's `symbols_manage.lookup_batch`).
_SYM_BATCH_SIZE = 32
_SYM_BATCH_MS = 100

# Default stackwalk depth for AccessTrace hits.
_SW_MAX_FRAMES = 8


@dataclass
class WatchhwJobCtx:
    """Per-job knobs the driver loop reads.

    Separated from the registry row so unit tests can drive the
    driver with a small struct instead of standing up the full
    ``_ATJOBS`` shape.
    """

    pid: int
    tid: int
    address: int
    size: int
    access: str
    max_hits: int
    disasm: bool
    stackwalk: bool
    symbolize: bool
    timeout_s: int
    # Batched-symbolize hook. Signature: (rips) -> {rip: {module, symbol,
    # displacement, confidence, rva}}. May be None when symbolize=False
    # or when the orchestrator can't reach the view that owns the pid
    # (e.g. a kernel address on a user-view-only lab host).
    symbolize_batch: Callable[[list[int]], Awaitable[dict[int, dict | None]]] | None


async def _read_code(client, pid: int, address: int, size: int) -> bytes:
    """Best-effort code-bytes read for the decoder (never raises)."""
    try:
        raw = await client.mem_read(pid=pid, address=address, size=size,
                                    space="user")
    except Exception:  # noqa: BLE001 — per-hit isolation
        return b""
    if isinstance(raw, tuple):
        raw = raw[0]
    return bytes(raw or b"")


async def _batched_symbolize(
    rips: list[int],
    *,
    batcher: Callable[[list[int]], Awaitable[dict[int, dict | None]]] | None,
    into: dict[int, dict | None],
) -> None:
    if not rips or batcher is None:
        return
    try:
        out = await batcher(list({int(r) for r in rips}))
    except Exception:  # noqa: BLE001 — symbol resolution is advisory
        return
    for rip, rec in (out or {}).items():
        try:
            into[int(rip)] = rec
        except (TypeError, ValueError):
            continue


async def _consume_events(
    *, stream, job_ctx: WatchhwJobCtx,
    client,
    on_hit: Callable[[dict[str, Any]], None],
    drop_sink: Callable[[int], None],
    watch_cookie: int,
    deadline_ts: float,
) -> dict[str, Any]:
    """Drain ``Events.Stream`` chunks until the stream ends or the
    deadline hits. Returns a summary dict (``last_seq``, ``total_hits``,
    ``kernel_dropped`` ...). The orchestrator ring-buffer management
    happens in ``on_hit`` (owned by ``access_trace.py``).

    Mocks replace ``stream`` with a synthetic async iterator yielding
    chunk objects carrying ``.events[]`` + ``.dropped`` counters.
    """
    pending_rips: list[int] = []
    sym_out: dict[int, dict | None] = {}
    sym_batcher = job_ctx.symbolize_batch if job_ctx.symbolize else None
    sym_deadline = time.monotonic()
    total = 0
    last_seq = 0
    kernel_dropped = 0
    kernel_missed = 0
    last_hit_ts = 0.0
    try:
        async for chunk in stream:
            now = time.monotonic()
            # Timeout check happens BEFORE processing so a wedged
            # stream with no data cannot pin the job forever.
            if now >= deadline_ts:
                break
            # Kernel-side loss counters — plan §4.5's
            # `kernel_dropped` accumulates from chunk.dropped,
            # `kernel_missed` from the per-event bit (`dropped=True`
            # on a specific event means "this slot aged out of the
            # driver ring before we could stream it").
            try:
                cd = int(getattr(chunk, "dropped", 0) or 0)
            except Exception:
                cd = 0
            if cd:
                kernel_dropped = max(kernel_dropped, cd)
                drop_sink(cd)
            for e in getattr(chunk, "events", []) or []:
                if not _is_bp_hit(getattr(e, "kind", 0)):
                    continue
                if getattr(e, "dropped", False):
                    kernel_missed += 1
                    continue
                last_seq = int(getattr(e, "seq", 0) or last_seq)
                last_hit_ts = time.time()
                total += 1
                rip = int(getattr(e, "address", 0) or 0)
                hit: dict[str, Any] = {
                    "seq": last_seq,
                    "ts": last_hit_ts,
                    "pid": int(getattr(e, "pid", 0) or 0),
                    "tid": int(getattr(e, "tid", 0) or 0),
                    "rip": rip,
                    "dr6": int(getattr(e, "dr6", 0) or 0),
                    "slot": int(getattr(e, "slot", 0) or 0),
                    "access": int(getattr(e, "access", 0) or 0),
                    "watch_cookie": int(watch_cookie),
                }
                # Fetch regs + the 16 bytes at RIP for the disassembler.
                try:
                    regs = await client.debug_regs(tid=hit["tid"])
                except Exception as exc:  # noqa: BLE001 — isolate per-hit
                    regs = {"error": f"{type(exc).__name__}: {exc}"}
                hit["regs"] = regs
                is_exec = (job_ctx.access or "").lower() in (
                    "x", "exec", "execute")
                rip_bytes = b""
                window = b""
                win_base = rip
                if job_ctx.disasm and rip:
                    # Data watch: the #DB is a trap (RIP is past the
                    # access) — fetch the bytes BEFORE rip too.
                    back = 0 if is_exec else min(_MAX_INSN, rip)
                    window = await _read_code(client, hit["pid"],
                                              rip - back, back + 16)
                    win_base = rip - back
                    if back and len(window) <= back:
                        # Window start unreadable (page boundary) — at
                        # least keep the bytes at RIP for the record.
                        window = await _read_code(client, hit["pid"],
                                                  rip, 16)
                        win_base = rip
                    rip_bytes = window[rip - win_base:rip - win_base + 16]
                hit["bytes_at_rip"] = {
                    "hex": rip_bytes.hex(),
                    "ascii": "".join(
                        chr(b) if 32 <= b < 127 else "."
                        for b in rip_bytes),
                }
                if job_ctx.disasm and window:
                    iregs = _regs_ints(regs)
                    decoded = None
                    if is_exec:
                        memop, ln = _decode_at(rip_bytes, rip)
                        if memop is not None and ln:
                            # rip_next from the decoded length, not +16
                            ea = effective_address(memop, iregs,
                                                   rip_next=rip + ln)
                            decoded = (memop, rip, ea, 1, "fault_at_rip")
                    else:
                        tr = _decode_trap(
                            window, win_base, rip, iregs,
                            job_ctx.address,
                            job_ctx.address + max(1, int(job_ctx.size or 1)),
                            want_write=(job_ctx.access or "").lower()
                            in ("w", "write"))
                        if tr is not None:
                            memop, start, ea, n = tr
                            decoded = (memop, start, ea, n, "trap_backscan")
                    if decoded is not None:
                        memop, insn_va, ea, n_cands, basis = decoded
                        hit["memop"] = {
                            "mnemonic": memop.mnemonic,
                            "base_reg": memop.base_reg,
                            "index_reg": memop.index_reg,
                            "scale": memop.scale,
                            "disp": memop.disp,
                            "size_bytes": memop.size_bytes,
                            "access": memop.access,
                            "rip_relative": memop.rip_relative,
                            "effective_address": ea,
                            "insn_va": insn_va,
                            "decode_basis": basis,
                        }
                        if n_cands > 1:
                            hit["memop"]["candidates"] = n_cands
                if job_ctx.stackwalk:
                    try:
                        sw = await client.stack_walk(
                            tid=hit["tid"], max_frames=_SW_MAX_FRAMES)
                        hit["stack"] = {
                            "kernel_frames": [f.get("rip") for f in
                                              sw.get("kernel_frames", [])],
                            "user_frames": [f.get("rip") for f in
                                            sw.get("user_frames", [])],
                        }
                    except Exception as exc:  # noqa: BLE001
                        hit["stack"] = {"error": str(exc)}
                # Batched-symbolize bookkeeping — queue the RIP, kick
                # the batcher once we hit 32 pending or 100 ms since
                # the last flush.
                if job_ctx.symbolize and sym_batcher is not None and rip:
                    pending_rips.append(rip)
                hit["symbol"] = None  # patched in post-flush
                on_hit(hit)
                if total >= job_ctx.max_hits:
                    break
            # Fire the symbol-lookup batch after each chunk when we
            # cross the size threshold OR when the time budget elapses.
            now2 = time.monotonic()
            if pending_rips and (
                len(pending_rips) >= _SYM_BATCH_SIZE
                or now2 * 1000 - sym_deadline * 1000 >= _SYM_BATCH_MS
            ):
                await _batched_symbolize(pending_rips, batcher=sym_batcher,
                                         into=sym_out)
                pending_rips.clear()
                sym_deadline = now2
            if total >= job_ctx.max_hits:
                break
    except asyncio.CancelledError:
        raise
    # Final symbol flush on exit (job stop / deadline / max_hits).
    if pending_rips:
        await _batched_symbolize(pending_rips, batcher=sym_batcher,
                                 into=sym_out)
    return {"total": total, "last_seq": last_seq,
            "kernel_dropped": kernel_dropped,
            "kernel_missed": kernel_missed,
            "symbols": sym_out}


async def run_watchhw_driver(
    *, ctx, client, job: dict[str, Any], job_ctx: WatchhwJobCtx,
    symbolize_batch: Callable[[list[int]], Awaitable[dict[int, dict | None]]] | None = None,
) -> dict[str, Any]:
    """Arm the watchpoint, drain the stream, disarm on exit.

    Top-level entry point called by the job registry. Expects
    ``client`` to expose the AgentClient surface
    (``bp_hw_watch_add`` / ``events_stream`` / ``debug_regs`` /
    ``mem_read`` / ``stack_walk``). ``job`` is the ``_ATJOBS`` row
    the driver mutates in place for ring + counters.

    Returns a status dict; the caller lifts it into the final
    envelope and flips the job's state.
    """
    from ....agent_client.watchhw import WatchHwWrapper
    wh = WatchHwWrapper(client)
    armed = await wh.add(
        pid=job_ctx.pid, tid=job_ctx.tid, address=job_ctx.address,
        size=job_ctx.size, access=job_ctx.access,
        preempt_ok=False, tag=f"at:{job['job_id']}",
    )
    if not armed.get("ok"):
        return {"ok": False, "driver": "watchhw",
                "error": armed.get("error") or "WatchHw.Add failed",
                "kind": armed.get("kind") or "watchhw_arm_failed",
                "watch_cookie": 0}
    cookie = int(armed.get("watch_cookie") or 0)
    slot = int(armed.get("slot") or 0xFF)
    hvci_fallback = bool(armed.get("hvci_fallback"))

    deadline_ts = time.monotonic() + max(1, int(job_ctx.timeout_s or 300))
    try:
        stream = client.events_stream(
            kinds_mask=_CLASS_BP, dangerous_ok=True,
            duration_s=max(1, int(job_ctx.timeout_s or 300)),
            interval_ms=50,
        )
    except Exception as exc:  # noqa: BLE001
        # Arm succeeded but stream open failed — tear down the DR slot
        # so we don't leak it.
        try:
            await wh.remove(cookie)
        except Exception:
            pass
        return {"ok": False, "driver": "watchhw",
                "error": f"Events.Stream open failed: {exc}",
                "kind": "events_stream_open_failed",
                "watch_cookie": cookie}

    def _on_hit(h: dict[str, Any]) -> None:
        job["hits"].append(h)
        # Ring-buffer trim. _ATJOB_RING_CAP mirrored into job["ring_cap"].
        cap = int(job.get("ring_cap") or 4096)
        if len(job["hits"]) > cap:
            dropped_here = len(job["hits"]) - cap
            del job["hits"][:dropped_here]
            job["ring_truncated"] = True
        job["hits_so_far"] = int(job.get("hits_so_far", 0)) + 1
        job["last_hit_ts"] = h.get("ts", 0.0)

    def _on_drop(n: int) -> None:
        job["kernel_dropped"] = max(int(job.get("kernel_dropped") or 0), n)

    job_ctx = WatchhwJobCtx(**{**job_ctx.__dict__,
                                "symbolize_batch": symbolize_batch})

    try:
        summary = await _consume_events(
            stream=stream, job_ctx=job_ctx, client=client,
            on_hit=_on_hit, drop_sink=_on_drop,
            watch_cookie=cookie, deadline_ts=deadline_ts,
        )
    finally:
        # Disarm no matter why we exited (deadline, cancel, max_hits).
        try:
            await wh.remove(cookie)
        except Exception as exc:  # noqa: BLE001 — surface on job row
            job["disarm_error"] = f"{type(exc).__name__}: {exc}"
    # Patch symbols into the hits now that the batcher is drained.
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
    return {"ok": True, "driver": "watchhw",
            "watch_cookie": cookie, "slot": slot,
            "hvci_fallback": hvci_fallback,
            "total": summary.get("total", 0),
            "last_seq": summary.get("last_seq", 0)}
