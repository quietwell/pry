"""``write`` verb body (plain write + verify readback).

Phase R5 move — lifted verbatim from ``mem.py``'s ``register()`` closure.
"""

from __future__ import annotations

from typing import Any

from .._runtime.envelope import _envelope_ok
from .._runtime.response import _j


async def handle_write(ctx, c, *, pid: int, addr: int, size: int,
                       space: str, data_hex: str, verify: bool,
                       allow_fault: bool, allow_map_write: bool,
                       timeout_s: float) -> str:
    # Same guard as read: user-space write with pid=0 is a
    # driver-rejected combo — surface the misuse in the tool
    # layer with a named error instead of a bare gle=87.
    if space == "user" and not pid:
        return _j({"ok": False,
                   "error": "user-space write requires pid=<target>; "
                            "use space='kernel' for kernel VAs "
                            "(the driver rejects pid=0 user writes "
                            "with STATUS_INVALID_PARAMETER)"})
    if space == "physical" and not allow_map_write:
        # Fail fast with a named reason instead of a bare
        # gle=5 from the v5 driver's opt-in gate.
        return _j({"ok": False,
                   "error": "physical write requires allow_map_write=true "
                            "(ABI v5: opts into the MmMapIoSpaceEx write "
                            "path; skipped pages surface as written < "
                            "payload size)"})
    data = bytes.fromhex(data_hex)
    n = await c.mem_write(pid, addr, data, space,
                          allow_map_write=allow_map_write)
    if not verify:
        return _j({"ok": True, "written": n})
    # atomic write-then-read-back. Callers who need
    # the classical "write reported success but nothing landed"
    # forensic pair get it in one round trip. verify=true doubles
    # bandwidth, so a warning fires past a 64 KiB payload.
    payload: dict[str, Any] = {"written": n, "verified": None}
    readback_err: str = ""
    try:
        readback = await c.mem_read(pid, addr, len(data), space,
                                    allow_fault=allow_fault,
                                    timeout=timeout_s or None)
    except Exception as exc:  # noqa: BLE001 - readback fault is one of the states we surface
        readback = b""
        readback_err = f"{type(exc).__name__}: {exc}"
    if readback_err:
        payload["verified"] = False
        payload["read_back_error"] = readback_err
        payload["hint"] = (
            "write reported success but readback threw — the "
            "target range may be write-only, fenced, or crossed "
            "an unmapped page. Re-read smaller chunks to isolate "
            "the bad page.")
    elif readback == data:
        payload["verified"] = True
    else:
        diff_off = next((i for i, (a, b) in enumerate(
            zip(readback, data)) if a != b),
                         min(len(readback), len(data)))
        payload["verified"] = False
        payload["diff_offset"] = diff_off
        payload["expected_hex"] = data[diff_off:diff_off + 16].hex()
        payload["actual_hex"] = readback[diff_off:diff_off + 16].hex()
        payload["hint"] = (
            "write reported success but readback differs — check "
            "that the range isn't COW / read-only / device-mapped, "
            "and that another writer didn't race")
    warnings: list[str] = []
    if len(data) > 64 * 1024:
        warnings.append(
            "verify=true doubles bandwidth; disable for large "
            "writes (payload > 64 KiB)")
    env = _envelope_ok(
        payload, kind="write", tool="memory_manage", action="write",
        warnings=warnings,
    )
    return _j(env)
