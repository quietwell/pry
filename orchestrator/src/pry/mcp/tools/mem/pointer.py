"""``follow_chain`` + ``leak_scan`` verb bodies.

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.response import _j


async def handle_follow_chain(ctx, c, *, pid: int, addr: int, space: str,
                              offsets: list[int] | None,
                              terminal_size: int, expect_ascii: bool,
                              expect_nonzero: bool, expect_module: str,
                              kernel_lookup: bool,
                              allow_fault: bool) -> str:
    # orchestrator-side pointer-chain chase.
    # Loop N-1 derefs (address + offsets[0], read 8 bytes;
    # that is hop 1's VA. address + offsets[1]; etc). After
    # the final offset, optionally read terminal_size bytes
    # instead of deref'ing. Per-hop {hop, va, read_from,
    # value, ok, error?}. Typed failure names the first bad
    # hop. Coverage: 'complete' when every hop succeeded.
    if not offsets:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "follow_chain: offsets=[...] required",
                   "hint": ("offsets[i] is added to the "
                            "value read at hop i-1 before "
                            "the next deref")})
    hops: list[dict] = []
    cur = int(addr)
    failed: dict | None = None
    hop_count = len(offsets)
    for i, off in enumerate(offsets):
        try:
            off_i = int(off, 0) if isinstance(off, str) else int(off)
        except Exception as exc:  # noqa: BLE001
            failed = {"hop": i, "error": f"bad offset: {exc}",
                      "kind": "bad_offset"}
            break
        read_from = (cur + off_i) & 0xFFFF_FFFF_FFFF_FFFF
        is_last = (i == hop_count - 1)
        if is_last and terminal_size:
            # Read terminal_size raw bytes instead of deref.
            try:
                data = await c.mem_read(pid, read_from,
                                        int(terminal_size),
                                        space,
                                        allow_fault=allow_fault)
            except Exception as exc:  # noqa: BLE001
                failed = {"hop": i, "va": read_from,
                          "error": str(exc),
                          "kind": "terminal_read_failed"}
                break
            hop = {"hop": i, "offset": off_i,
                   "read_from": read_from,
                   "terminal_bytes_hex": data.hex(),
                   "terminal_size": len(data)}
            if expect_ascii:
                if not all(32 <= b < 127 or b in (9, 10, 13)
                           for b in data) or not data:
                    hop["ascii_check"] = "failed"
                    failed = {"hop": i, "va": read_from,
                              "error": "terminal bytes are "
                                       "not printable ASCII",
                              "kind": "expect_ascii_failed",
                              "preview": data[:32].hex()}
                    hops.append(hop)
                    break
                hop["ascii"] = data.decode("ascii",
                                          errors="replace")
            hops.append(hop)
            cur = read_from  # terminal VA for return
            break
        # Normal 8-byte deref.
        try:
            data = await c.mem_read(pid, read_from, 8, space,
                                    allow_fault=allow_fault)
        except Exception as exc:  # noqa: BLE001
            failed = {"hop": i, "va": read_from,
                      "error": str(exc),
                      "kind": "hop_read_failed"}
            break
        if len(data) < 8:
            failed = {"hop": i, "va": read_from,
                      "error": (f"deref returned {len(data)} "
                                "bytes, need 8"),
                      "kind": "hop_short_read"}
            break
        hop_value = int.from_bytes(data, "little")
        hops.append({"hop": i, "offset": off_i,
                     "read_from": read_from,
                     "value": hop_value})
        if expect_nonzero and hop_value == 0:
            failed = {"hop": i, "va": read_from,
                      "error": "deref returned NULL",
                      "kind": "expect_nonzero_failed"}
            break
        cur = hop_value
    payload: dict[str, Any] = {
        "action": "follow_chain",
        "start": int(addr),
        "hop_count": len(hops),
        "hops": hops,
        "terminal_va": cur,
    }
    if expect_module and failed is None:
        try:
            mods = await c.mem_modules(pid=pid,
                                       kernel=kernel_lookup)
            rows = mods.get("modules") if isinstance(mods, dict) \
                else (mods or [])
            matched = ""
            for m in (rows or []):
                b = int(m.get("base") or 0)
                s = int(m.get("size") or 0)
                if b and s and b <= cur < b + s:
                    matched = str(m.get("name") or m.get("path")
                                  or "")
                    break
            if expect_module.lower() not in matched.lower():
                failed = {"hop": len(hops) - 1,
                          "va": cur,
                          "error": (f"terminal VA 0x{cur:x} "
                                    f"falls in module "
                                    f"{matched!r}, not "
                                    f"{expect_module!r}"),
                          "kind": "expect_module_failed"}
        except Exception:  # noqa: BLE001 — expect check best-effort
            pass
    if failed is not None:
        payload["ok"] = False
        payload["kind"] = failed.get("kind") or "chain_failed"
        payload["error"] = failed.get("error") or "chain failed"
        payload["failed_at"] = failed
        payload["coverage"] = _coverage(
            "pointer-chain", "partial", "hop_failed")
        return _j(payload)
    payload["ok"] = True
    payload["coverage"] = _coverage("pointer-chain", "complete")
    return _j(payload)


async def handle_leak_scan(ctx, c, *, pid: int, space: str, name: str,
                           needles: list[str] | None,
                           scopes: list[str] | None,
                           max_results: int, kernel_lookup: bool,
                           allow_fault: bool) -> str:
    if not needles:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "leak_scan: needles=[...] required",
                   "hint": "pass byte strings or 'hex:...' "
                           "entries"})
    def _norm_needle(s: str) -> bytes:
        if isinstance(s, bytes):
            return s
        s = str(s)
        if s.startswith("hex:") or s.startswith("0x"):
            hx = s.split(":", 1)[1] if s.startswith("hex:") else s[2:]
            try:
                return bytes.fromhex(hx)
            except ValueError as exc:
                raise ValueError(
                    f"leak_scan: bad hex needle: {exc}")
        return s.encode("utf-8", errors="replace")
    try:
        needle_bytes = [_norm_needle(n) for n in needles]
    except ValueError as exc:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": str(exc)})
    effective_scopes = scopes or ["kernel_pool", "module_data"]
    effective_scopes = [str(s).lower() for s in effective_scopes]
    results: dict[str, Any] = {
        "ok": True,
        "action": "leak_scan",
        "needle_count": len(needle_bytes),
        "scopes": {},
    }
    for sc in effective_scopes:
        scope_out: dict[str, Any] = {
            "scope": sc,
            "hits": [],
            "coverage": _coverage(f"leak-{sc}", "unknown"),
        }
        if sc == "kernel_pool":
            if ctx.session.view_kind_of(name) == "user":
                scope_out["coverage"] = _coverage(
                    f"leak-{sc}", "unknown", "needs_kernel_view")
                scope_out["skipped"] = ("kernel pool scope "
                                        "needs the kernel view")
            else:
                # One pool_scan per needle; cursor-paginate
                # until the driver reports next_cursor = 0.
                total_holes = 0
                total_trunc = 0
                for b in needle_bytes:
                    cursor = 0
                    while True:
                        try:
                            r = await c.pool_scan(
                                pattern=b,
                                content_span=max(len(b) * 2, 256),
                                max_results=max(max_results, 64),
                                cursor=cursor)
                        except Exception as exc:  # noqa: BLE001
                            scope_out["coverage"] = _coverage(
                                f"leak-{sc}", "partial",
                                "pool_scan_failed")
                            scope_out["error"] = str(exc)
                            break
                        for e in r.get("entries", []) or []:
                            scope_out["hits"].append({
                                "needle_hex": b.hex(),
                                "va": e.get("matched_offset")
                                     or e.get("va"),
                                "tag_ascii": e.get("tag_ascii"),
                                "size": e.get("size"),
                            })
                        total_holes += int(r.get("holes") or 0)
                        total_trunc += int(
                            r.get("span_truncated") or 0)
                        nxt = int(r.get("next_cursor") or 0)
                        if not nxt or nxt <= cursor:
                            break
                        cursor = nxt
                if "error" not in scope_out:
                    reasons: list[str] = []
                    if total_holes:
                        reasons.append("pool_read_holes")
                    if total_trunc:
                        reasons.append("span_truncated")
                    scope_out["coverage"] = _coverage(
                        f"leak-{sc}",
                        "partial" if reasons else "complete",
                        *reasons)
                    scope_out["holes"] = total_holes
                    scope_out["span_truncated"] = total_trunc
        elif sc == "module_data":
            # Walk the kernel/user modules list and
            # pattern-scan each module's load range for the
            # needle. Fast path: short needles only (longer
            # ones belong on pattern_scan with sections=).
            try:
                mods = await c.mem_modules(pid=pid,
                                           kernel=kernel_lookup)
                rows = mods.get("modules") if isinstance(
                    mods, dict) else (mods or [])
            except Exception as exc:  # noqa: BLE001
                scope_out["coverage"] = _coverage(
                    f"leak-{sc}", "partial", "modules_failed")
                scope_out["error"] = str(exc)
                rows = []
            read_fail = 0
            read_ok = 0
            for m in (rows or []):
                b_va = int(m.get("base") or 0)
                b_sz = int(m.get("size") or 0)
                if not b_va or not b_sz:
                    continue
                try:
                    buf = await c.mem_read(
                        pid, b_va, min(b_sz, 2 * 1024 * 1024),
                        space if space != "physical" else
                        "kernel",
                        allow_fault=allow_fault)
                    read_ok += 1
                except Exception:  # noqa: BLE001
                    read_fail += 1
                    continue
                for n in needle_bytes:
                    idx = 0
                    while True:
                        at = buf.find(n, idx)
                        if at < 0:
                            break
                        scope_out["hits"].append({
                            "needle_hex": n.hex(),
                            "module": m.get("name"),
                            "va": b_va + at,
                        })
                        idx = at + max(1, len(n))
            if "error" not in scope_out:
                reasons = []
                if read_fail:
                    reasons.append("module_read_failed")
                scope_out["coverage"] = _coverage(
                    f"leak-{sc}",
                    "partial" if reasons else "complete",
                    *reasons)
                scope_out["module_read_failures"] = read_fail
                scope_out["module_count_scanned"] = read_ok
        elif sc == "per_process":
            # Walk every process heap for the needle via
            # mem_scan over the heap range. Honest coverage:
            # per-process iteration is best-effort; failures
            # per pid are counted.
            try:
                procs = await c.mem_processes()
                rows = procs.get("processes") if isinstance(
                    procs, dict) else (procs or [])
            except Exception as exc:  # noqa: BLE001
                scope_out["coverage"] = _coverage(
                    f"leak-{sc}", "partial",
                    "process_list_failed")
                scope_out["error"] = str(exc)
                rows = []
            p_fail = 0
            p_ok = 0
            for p in (rows or [])[:64]:
                tpid = int(p.get("pid") or 0)
                if not tpid or tpid == 4:
                    continue
                try:
                    heaps = await c.mem_heaps(pid=tpid)
                    hrows = heaps.get("heaps") if isinstance(
                        heaps, dict) else (heaps or [])
                    p_ok += 1
                except Exception:  # noqa: BLE001
                    p_fail += 1
                    continue
                for h in (hrows or []):
                    h_base = int(h.get("base") or 0)
                    h_size = int(h.get("committed") or 0)
                    if not h_base or not h_size:
                        continue
                    try:
                        buf = await c.mem_read(
                            tpid, h_base,
                            min(h_size, 2 * 1024 * 1024),
                            "user", allow_fault=False)
                    except Exception:  # noqa: BLE001
                        continue
                    for n in needle_bytes:
                        idx = 0
                        while True:
                            at = buf.find(n, idx)
                            if at < 0:
                                break
                            scope_out["hits"].append({
                                "needle_hex": n.hex(),
                                "pid": tpid,
                                "process": p.get("name"),
                                "va": h_base + at,
                            })
                            idx = at + max(1, len(n))
            if "error" not in scope_out:
                reasons = []
                if p_fail:
                    reasons.append("process_read_failed")
                scope_out["coverage"] = _coverage(
                    f"leak-{sc}",
                    "partial" if reasons else "complete",
                    *reasons)
                scope_out["process_read_failures"] = p_fail
                scope_out["process_count_scanned"] = p_ok
        else:
            scope_out["coverage"] = _coverage(
                f"leak-{sc}", "unknown", "unknown_scope")
            scope_out["skipped"] = f"unknown scope: {sc}"
        results["scopes"][sc] = scope_out
    hit_total = sum(len(v.get("hits") or [])
                     for v in results["scopes"].values())
    results["hit_total"] = hit_total
    return _j(results)
