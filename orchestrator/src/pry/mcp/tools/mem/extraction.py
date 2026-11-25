"""``strings`` / ``iocs`` / ``entropy`` verb bodies.

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..._coverage import coverage as _coverage
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict, _j, _j_hex


async def handle_strings_iocs(ctx, c, *, action: str, pid: int, addr: int,
                              size: int, space: str, min_len: int,
                              allow_fault: bool, partial: bool,
                              timeout_s: float, filter: Any,
                              summary: bool, fields: list[str] | None,
                              limit: int, offset: int,
                              max_results: int) -> str:
    if not addr or not size:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"{action} needs address= and size=",
                   "hint": "memory_manage strings address=0x... size=0x10000 "
                           "min_len=6"})
    n = min(size, 4 * 1024 * 1024 - 0x1000)
    data = await c.mem_read(pid, addr, n, space,
                            allow_fault=allow_fault,
                            partial=partial,
                            timeout=timeout_s or None)
    if isinstance(data, tuple):
        data = data[0]
    from ....analysis.extract import find_iocs, find_strings
    # Up to 4 MiB of TARGET-controlled bytes through the string/IOC
    # scanners: run them in a worker thread, never on the event loop.
    if action == "strings":
        rows = await asyncio.to_thread(find_strings, data,
                                       min_len=max(3, min_len),
                                       utf16=True, base_va=addr)
    else:
        rows = await asyncio.to_thread(find_iocs, data, base_va=addr)
    if size > n:
        cov = _coverage("mem-read", "partial", "size_cap_reached")
    elif len(data) < size:
        cov = _coverage("mem-read", "partial",
                        "read_failed_mid_buffer")
    else:
        cov = _coverage("mem-read", "complete")
    env = _list_envelope(
        rows, tool="memory_manage", action=action,
        limit=limit or max_results, offset=offset,
        fields=fields or (),
        filter=filter if isinstance(filter, str) else "",
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={"source_va": addr, "bytes": len(data),
                "truncated": len(data) < size},
    )
    env["coverage"] = cov
    return _hexify_dict(env, add_int_mirror=True)


async def handle_entropy(ctx, c, *, pid: int, addr: int, size: int,
                         space: str, buckets: int, allow_fault: bool,
                         partial: bool, timeout_s: float, filter: Any,
                         summary: bool, fields: list[str] | None,
                         limit: int, offset: int,
                         max_results: int) -> str:
    from ....analysis.entropy import entropy_map
    if addr and size:
        n = min(size, 4 * 1024 * 1024 - 0x1000)
        data = await c.mem_read(pid, addr, n, space,
                                allow_fault=allow_fault,
                                partial=partial,
                                timeout=timeout_s or None)
        if isinstance(data, tuple):
            data = data[0]
        em = await asyncio.to_thread(entropy_map, data, buckets=buckets)
        em["source_va"] = addr
        em["truncated"] = len(data) < size
        if size > n:
            em["coverage"] = _coverage("mem-read", "partial",
                                       "size_cap_reached")
        elif len(data) < size:
            em["coverage"] = _coverage("mem-read", "partial",
                                       "read_failed_mid_buffer")
        else:
            em["coverage"] = _coverage("mem-read", "complete")
        return _j_hex(em)
    # VAD sweep: score a bounded sample of each
    # private/executable region in the process.
    if not pid:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "entropy sweep needs pid= "
                            "(or address+size for a range)"})
    vads = await c.vad_list(pid)
    rows = []
    skipped = 0
    for e in vads:
        prot = int(e.get("protect", 0))
        start = int(e.get("start", 0))
        end = int(e.get("end", 0))
        if prot & 0xF0 not in (0x10, 0x20, 0x40, 0x80):
            continue  # EXECUTE/_READ/_READWRITE/_WRITECOPY
        try:
            sample = await c.mem_read(
                pid, start, min(end - start, 4096), "user",
                allow_fault=True,
                timeout=timeout_s or None)
        except Exception:
            skipped += 1
            continue
        if isinstance(sample, tuple):
            sample = sample[0]
        if not sample:
            skipped += 1
            continue
        em = entropy_map(sample)
        rows.append({"start": start, "end": end,
                     "protect": prot,
                     "entropy": em["mean_entropy"],
                     "packed": em["packed"],
                     "sampled": len(sample)})
    rows.sort(key=lambda r: -r["entropy"])
    env = _list_envelope(
        rows, tool="memory_manage", action="entropy",
        limit=limit or max_results, offset=offset,
        fields=fields or (),
        filter=filter if isinstance(filter, str) else "",
        summary=summary,
        global_cap=ctx.cfg.mcp_max_items(),
        extras={"mode": "vad_sweep", "pid": pid},
    )
    env["coverage"] = _coverage(
        "enumeration",
        "partial" if skipped else "complete",
        *(["vad_read_skipped"] if skipped else []))
    return _hexify_dict(env, add_int_mirror=True)
