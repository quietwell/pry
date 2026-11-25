"""Debug-service (and breakpoints) methods split off from AgentClient."""

from __future__ import annotations

from typing import Any, AsyncIterator

from ..generated import pry_pb2 as pb
from .events import Event
from .wire import proto_to_dict, status_dict


# --- state-loop helpers ---------------------------------------------
#
# Every mutating Debug RPC now echoes a `StopInfo` state block (see
# an internal plan §3). The two helpers below are
# the single conversion point so wrappers stay uniform: `_stop_info_to_dict`
# turns a `pb.StopInfo` into the plain dict the MCP layer surfaces (with `rip`
# mirrored as a hex string per the plan's "Hexify rip" bullet), and
# `_attach_state` conditionally splices a `state` key onto an envelope only
# when the response message carries a `state` field. The HasField check
# guards against responses whose proto schema does NOT carry state (e.g.
# `LaunchResponse`, `SetRegsResponse`, `BpAddResponse`).

def _stop_info_to_dict(state: pb.StopInfo) -> dict[str, Any]:
    """Serialize a `pb.StopInfo` into the MCP state-block dict.

    Mirrors `rip` as `"0x…"` per the plan; every other field is passed
    through at its native type so `seq` / `pid` / `tid` remain usable as
    integers downstream.

    When the proto carries ``regs`` / ``bytes_at_rip_hex``
    (filled automatically on exception stops, or when the caller passed
    ``include_context=true``), the dict grows ``state["regs"]`` as a list
    of ``{"name", "value"}`` records and ``state["bytes_at_rip_hex"]`` as
    a lowercase hex string. On an older pb2 the ``hasattr`` guard
    keeps the shape backward-compatible — neither key appears."""
    out: dict[str, Any] = {
        "active": state.active,
        "stopped": state.stopped,
        "timed_out": state.timed_out,
        "pid": state.pid,
        "tid": state.tid,
        "rip": f"0x{state.rip:x}",
        "symbol": state.symbol,
        "stop_reason": state.stop_reason,
        "seq": state.seq,
        "arch": state.arch,
    }
    # exception / BP identifiers were emitted even when
    # they were the default zero / false, which is the common case
    # (any non-exception non-BP stop). Surface them only when they
    # carry signal: non-zero exception_code, non-zero bp_id,
    # first_chance=true (meaningful only on exception stops anyway).
    if state.exception_code:
        out["exception_code"] = state.exception_code
    if state.first_chance:
        out["first_chance"] = True
    if state.bp_id:
        out["bp_id"] = state.bp_id
    if hasattr(state, "regs"):
        regs = list(state.regs)
        if regs:
            out["regs"] = [{"name": r.name, "value": r.value} for r in regs]
    if hasattr(state, "bytes_at_rip_hex"):
        bytes_hex = state.bytes_at_rip_hex
        if bytes_hex:
            out["bytes_at_rip_hex"] = bytes_hex
    return out


def _maybe_set_include_context(req: Any, include_context: bool) -> None:
    """Set ``req.include_context`` when the proto schema carries the field.

    The flag is added to Status/Pause/Wait/Run/RunTo/StepOut/Continue/
    Step; a stale pb2 (an older agent build) has no such field, so we
    use ``hasattr`` to probe the descriptor. Setting to False on a schema
    that has the field is harmless (proto3 default)."""
    if include_context and hasattr(req, "include_context"):
        req.include_context = True


#: Client-side deadline margin for the waiting verbs. The agent
#: blocks up to ``timeout_ms`` (server cap 30 s) before answering
#: ``timed_out=true``; without an explicit deadline ``_call`` fell back to
#: the 10 s client default and lost the StopInfo of every longer wait.
_WAIT_DEADLINE_MARGIN_S = 5.0
_WAIT_SERVER_CAP_MS = 30000


def _wait_deadline_s(timeout_ms: int) -> float:
    """gRPC deadline for a Debug verb that blocks server-side for
    ``timeout_ms`` (0 = the server default, treated as the 30 s cap)."""
    t = int(timeout_ms or 0)
    if t <= 0:
        t = _WAIT_SERVER_CAP_MS
    return t / 1000.0 + _WAIT_DEADLINE_MARGIN_S


def _attach_state(out: dict[str, Any], msg: Any) -> dict[str, Any]:
    """Attach `out["state"]` from `msg.state` when the message schema has it.

    Defensive about the field's existence — several existing Debug responses
    (LaunchResponse, SetRegsResponse, BpAddResponse …) deliberately have no
    `state` field, so a bare `msg.HasField("state")` would raise
    `ValueError` on them. We consult the descriptor instead."""
    desc = getattr(msg, "DESCRIPTOR", None)
    if desc is not None and "state" in desc.fields_by_name:
        out["state"] = _stop_info_to_dict(msg.state)
    return out


# GPR names picked up by `debug_set_regs` to decide `apply_gprs`. Includes
# only the 16 x64 GPRs; x86/WOW64 targets still reach `rax..r15` on the wire
# because the proto is x64-shaped (x86 `eax..edi` would be zero-extended
# into the matching `rax..rdi` field on the server before any write).
_GPR_NAMES = frozenset({
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
})

# Debug-register names used alongside `apply_dr`. dr4/dr5 are architectural
# aliases of dr6/dr7 and are intentionally excluded.
_DR_NAMES = ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")


def _coerce_reg(v: Any) -> int:
    """Accept an int or hex/dec string value for a register field.

    JSON doesn't have a native 64-bit integer type, so callers routinely
    send `"rax": "0xdeadbeef"`. Convert here so the wire layer always sees
    a plain `int`."""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            raise ValueError("empty register value")
        return int(s, 0)
    raise TypeError(f"unsupported register value type: {type(v).__name__}")


class DebugMixin:
    # ---------------------------------------------------------------- Debug ----

    async def debug_launch(
        self,
        cmdline: str,
        workdir: str = "",
        break_on_entry: bool = True,
        monitor: bool = False,
    ) -> dict[str, Any]:
        msg = await self._call(
            self.debug.Launch,
            pb.LaunchRequest(
                cmdline=cmdline,
                working_dir=workdir,
                break_on_entry=break_on_entry,
                monitor=monitor,
            ),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        out: dict[str, Any] = {"pid": msg.pid, "tid": msg.initial_tid}
        # LaunchResponse has no `state` field; `_attach_state` is a
        # no-op here but kept for shape uniformity should the proto grow one.
        return _attach_state(out, msg)

    async def debug_attach(self, pid: int, monitor: bool = False) -> dict[str, Any]:
        msg = await self._call(self.debug.Attach, pb.AttachRequest(pid=pid, monitor=monitor))
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_detach(self, kill: bool = False) -> dict[str, Any]:
        msg = await self._call(self.debug.Detach, pb.DetachRequest(kill=kill))
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_continue(self, include_context: bool = False) -> dict[str, Any]:
        req = pb.ContinueRequest()
        _maybe_set_include_context(req, include_context)
        msg = await self._call(self.debug.Continue, req)
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_step(self, over: bool = False, count: int = 1,
                         include_context: bool = False) -> dict[str, Any]:
        """Generic step shim kept for existing callers.

        New code prefers `debug_step_into` / `debug_step_over` so the
        intent is readable at the call site; both delegate here."""
        req = pb.StepRequest(
            kind=pb.StepRequest.STEP_OVER if over else pb.StepRequest.STEP_INTO,
            count=count,
        )
        _maybe_set_include_context(req, include_context)
        msg = await self._call(self.debug.Step, req)
        # StepResponse wraps OpStatus in `status`; the earlier
        # `status_dict(msg)` tripped on `msg.ok` and surfaced as
        # "AttributeError: ok" even when the step itself succeeded.
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_step_into(self, count: int = 1,
                              include_context: bool = False) -> dict[str, Any]:
        return await self.debug_step(over=False, count=count,
                                     include_context=include_context)

    async def debug_step_over(self, count: int = 1,
                              include_context: bool = False) -> dict[str, Any]:
        return await self.debug_step(over=True, count=count,
                                     include_context=include_context)

    # --- state-aware verbs --------------------------------------

    async def debug_status(self, include_context: bool = False) -> dict[str, Any]:
        """Synchronous status read — returns `{"ok": True/False, "state": {...}}`.

        Non-mutating: safe to call at any time, including with no active
        session (the state block will carry `active=false`). Pass
        ``include_context=True`` to populate ``state.regs`` + ``state.bytes_at_rip_hex``
        on the snapshot."""
        req = pb.DebugStatusRequest()
        _maybe_set_include_context(req, include_context)
        msg = await self._call(self.debug.Status, req)
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_pause(self, timeout_ms: int = 5000,
                          include_context: bool = False) -> dict[str, Any]:
        """Force the target into the stopped state. Server clamps timeout
        to [0, 30000]; on timeout, `state.timed_out=true` with `ok=true`."""
        req = pb.PauseRequest(timeout_ms=timeout_ms)
        _maybe_set_include_context(req, include_context)
        msg = await self._call(self.debug.Pause, req,
                               timeout=_wait_deadline_s(timeout_ms))
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_wait(self, timeout_ms: int = 20000,
                         include_context: bool = False) -> dict[str, Any]:
        """Block until the next stop event or timeout. In monitor mode this
        resolves on `process_exit` / `exception` only (bp hits auto-resume);
        see docs/DEBUG_MCP.md."""
        req = pb.WaitRequest(timeout_ms=timeout_ms)
        _maybe_set_include_context(req, include_context)
        msg = await self._call(self.debug.Wait, req,
                               timeout=_wait_deadline_s(timeout_ms))
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_run(self, timeout_ms: int = 20000,
                        include_context: bool = False) -> dict[str, Any]:
        """Resume and wait for the next stop. Equivalent to `continue` +
        `wait` in one round trip; same 30 s server-side cap."""
        req = pb.RunRequest(timeout_ms=timeout_ms)
        _maybe_set_include_context(req, include_context)
        msg = await self._call(self.debug.Run, req,
                               timeout=_wait_deadline_s(timeout_ms))
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_run_to(
        self, address: int, timeout_ms: int = 20000,
        include_context: bool = False,
    ) -> dict[str, Any]:
        """Arm a one-shot bp at `address`, resume, wait for the stop.
        The agent removes the bp on any stop (RAII), so a timeout or an
        unrelated exception still leaves no leftover bp."""
        req = pb.RunToRequest(address=address, timeout_ms=timeout_ms)
        _maybe_set_include_context(req, include_context)
        msg = await self._call(self.debug.RunTo, req,
                               timeout=_wait_deadline_s(timeout_ms))
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_step_out(self, timeout_ms: int = 20000,
                             include_context: bool = False) -> dict[str, Any]:
        req = pb.StepOutRequest(timeout_ms=timeout_ms)
        _maybe_set_include_context(req, include_context)
        msg = await self._call(self.debug.StepOut, req,
                               timeout=_wait_deadline_s(timeout_ms))
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_cancel(self, pid: int = 0) -> dict[str, Any]:
        """abort the in-flight engine op (``SetInterrupt``).

        Mirrors ``debug_pause``'s envelope shape — returns
        ``{"ok", "state": {...}}`` on success. ``pid=0`` targets the current
        session; a non-zero pid lets the agent sanity-check against the
        attached pid before attempting the interrupt. On a stale pb2 that
        lacks ``CancelRequest`` / ``Debug.Cancel``, surfaces a clean
        ``AttributeError`` the guard renders as a kit-wide error envelope —
        the orchestrator must be rebuilt alongside the agent for this verb."""
        req_cls = getattr(pb, "CancelRequest", None)
        stub_call = getattr(self.debug, "Cancel", None)
        if req_cls is None or stub_call is None:
            # Older pb2 / stub — surface a readable error instead of
            # AttributeError('AgentClient.debug has no attribute Cancel').
            raise RuntimeError(
                "debug_cancel: older agent — Debug.Cancel RPC missing; "
                "rebuild and redeploy the agent to pick up the new verb")
        req = req_cls(pid=pid)
        msg = await self._call(stub_call, req)
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_disasm(self, address: int, count: int = 16) -> dict[str, Any]:
        """Disassemble `count` instructions from `address`. Returns
        `{"ok": True, "lines": [{"address": …, "bytes_hex": …, "text": …}, …]}`."""
        msg = await self._call(
            self.debug.Disasm,
            pb.DisasmRequest(address=address, count=count),
        )
        out = status_dict(msg.status)
        out["lines"] = [proto_to_dict(line) for line in msg.lines]
        return out

    async def debug_resolve(self, symbol: str) -> dict[str, Any]:
        """Resolve `"module!name"` / `"module+0xN"` / bare hex to a VA.
        Returns `{"ok": True, "address": int, "canonical": "mod!sym+0xNN"}`."""
        msg = await self._call(
            self.debug.Resolve, pb.ResolveRequest(symbol=symbol)
        )
        out = status_dict(msg.status)
        out["address"] = msg.address
        out["canonical"] = msg.canonical
        return out

    async def debug_dump(self, path: str, kind: str = "mini") -> dict[str, Any]:
        """Write a `"mini"` / `"full"` crashdump of the current target."""
        msg = await self._call(
            self.debug.DebugDump,
            pb.DebugDumpRequest(path=path, kind=kind),
        )
        out = status_dict(msg.status)
        out["path"] = msg.path
        out["bytes"] = msg.bytes
        return out

    async def debug_modules(self) -> dict[str, Any]:
        """Enumerate loaded modules. Returns
        `{"ok": True, "modules": [{"base":…,"size":…,"name":…,"path":…,"timestamp":…,"loaded":…}, …]}`."""
        msg = await self._call(self.debug.Modules, pb.DebugModulesRequest())
        out = status_dict(msg.status)
        out["modules"] = [proto_to_dict(m) for m in msg.modules]
        return out

    async def debug_exception(self, code: int, action: str) -> dict[str, Any]:
        """Configure the first-chance disposition for exception `code`:
        action is `"break"`, `"ignore"`, or `"second_chance"`."""
        msg = await self._call(
            self.debug.ExceptionFilter,
            pb.ExceptionFilterRequest(code=code, action=action),
        )
        return status_dict(msg.status)

    # --- regs / threads / stack / memory ---------------------------------

    async def debug_regs(self, tid: int = 0) -> dict[str, Any]:
        msg = await self._call(self.debug.GetRegs, pb.GetRegsRequest(tid=tid))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        out = proto_to_dict(msg.regs)
        # B7: surface partial-regs warnings instead of swallowing them.
        if list(msg.warnings):
            out["warnings"] = list(msg.warnings)
        return out

    async def debug_set_regs(self, tid: int = 0, **kwargs: Any) -> dict[str, Any]:
        """Set registers. `apply_gprs` / `apply_rip` / `apply_rflags` /
        `apply_dr` are decided by PRESENCE of the matching kwarg, not
        truthiness — so `set_regs(rax=0)` correctly clears RAX (B1).

        The agent writes the FULL GPR bank (and FULL DR bank) when the
        matching apply-flag is set — proto3 scalar zeros cannot be told
        from unset fields on the wire. To preserve registers the caller
        did not name, we fetch the current bank and merge the caller's
        values on top before sending (B1 integration gap; the target is
        stopped at this point, so there is no race)."""
        fields_desc = pb.Registers.DESCRIPTOR.fields_by_name
        coerced: dict[str, int] = {}
        for k, v in kwargs.items():
            if k not in fields_desc:
                continue
            coerced[k] = _coerce_reg(v)

        apply_gprs = any(k in _GPR_NAMES for k in coerced)
        apply_rip = "rip" in coerced
        apply_rflags = "rflags" in coerced
        apply_dr = any(k in _DR_NAMES for k in coerced)

        merged: dict[str, int] = dict(coerced)
        if apply_gprs or apply_dr:
            # Read the current bank so unset GPRs/DRs survive the write.
            cur_msg = await self._call(
                self.debug.GetRegs, pb.GetRegsRequest(tid=tid)
            )
            if not cur_msg.status.ok:
                raise RuntimeError(cur_msg.status.error)
            cur = cur_msg.regs
            if apply_gprs:
                for name in _GPR_NAMES:
                    merged.setdefault(name, getattr(cur, name))
            if apply_dr:
                for name in _DR_NAMES:
                    merged.setdefault(name, getattr(cur, name))

        msg = await self._call(
            self.debug.SetRegs,
            pb.SetRegsRequest(
                regs=pb.Registers(**merged),
                apply_gprs=apply_gprs,
                apply_rip=apply_rip,
                apply_rflags=apply_rflags,
                apply_dr=apply_dr,
                tid=tid,
            ),
        )
        out = status_dict(msg.status)
        # B7: partial-write warnings mirror GetRegs.
        if list(msg.warnings):
            out["warnings"] = list(msg.warnings)
        # SetRegsResponse has no `state` field, so `_attach_state`
        # is a no-op; left in to keep the mutating-response envelope uniform
        # should the proto grow one.
        return _attach_state(out, msg)

    async def debug_threads(self) -> dict[str, Any]:
        msg = await self._call(self.debug.GetThreads, pb.GetThreadsRequest())
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"current_tid": msg.current_tid, "threads": [proto_to_dict(t) for t in msg.threads]}

    async def debug_stacktrace(
        self, max_frames: int = 32, tid: int = 0
    ) -> list[dict[str, Any]]:
        msg = await self._call(
            self.debug.Stacktrace,
            pb.StacktraceRequest(max_frames=max_frames, tid=tid),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(f) for f in msg.frames]

    async def debug_read(self, address: int, size: int) -> bytes:
        msg = await self._call(self.debug.ReadMemory, pb.DebugReadRequest(address=address, size=size))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return bytes(msg.data)

    async def debug_write(self, address: int, data: bytes) -> dict[str, Any]:
        msg = await self._call(self.debug.WriteMemory, pb.DebugWriteRequest(address=address, data=data))
        # DebugWriteResponse wraps OpStatus under `.status` (like
        # Step/SetRegs); passing the whole response to status_dict
        # tripped on `msg.ok` and surfaced as 'AttributeError: ok'
        # even on successful writes.
        out = status_dict(msg.status)
        return _attach_state(out, msg)

    async def debug_regions(self, pid: int = 0, *,
                            limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        msg = await self._call(
            self.debug.Regions,
            pb.MemoryRegionsRequest(pid=pid, limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(r) for r in msg.regions]

    async def dbg_cmd(self, command: str) -> str:
        """Raw dbgeng command passthrough; returns the engine output text.

        Note: this discards the state echo on the ExecuteCommandResponse —
        callers that need B8's post-cmd state should use `debug_cmd`."""
        msg = await self._call(self.debug.ExecuteCommand,
                               pb.ExecuteCommandRequest(command=command))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return msg.output

    async def debug_cmd(self, command: str) -> dict[str, Any]:
        """Raw dbgeng command with B8 state echo. `g`, `q`, `.detach` and
        friends can silently change the target's execution state; the
        returned `state` block lets the MCP loop resync without a follow-up
        `status` round trip."""
        msg = await self._call(
            self.debug.ExecuteCommand,
            pb.ExecuteCommandRequest(command=command),
        )
        out = status_dict(msg.status)
        out["output"] = msg.output
        return _attach_state(out, msg)

    async def debug_events(self, from_seq: int = 0) -> AsyncIterator[dict[str, Any]]:
        # through _stream — long-lived (no deadline) but errors are
        # normalized like _call and the stream shows in recent_ops.
        async for ev in self._stream(
                self.debug.StreamEvents,
                pb.StreamDebugEventsRequest(from_seq=from_seq)):
            d = proto_to_dict(ev)
            self.bus.publish(Event(kind="debug", data=d))
            yield d

    # ----------------------------------------------------------- Breakpoints ----

    async def bp_add(
        self, kind: str, address: int, slot: int = 0, size: int = 1, access: str = "exec",
        kernel_target: bool = False, pid: int = 0, tid: int = 0,
        global_: bool = False, dangerous_ok: bool = False,
        via_debugger: bool = False,
        # dbgeng SW/DATA bp sweeteners (G6). Each is passed only when
        # it differs from its proto default so old agents' unknown-field skip
        # keeps working.
        condition: str = "",
        commands: str = "",
        pass_count: int = 0,
        one_shot: bool = False,
        match_tid: int = 0,
    ) -> dict[str, Any]:
        # v6: global=True is system-wide HW BP (arms every thread of every
        # process + newborns). Driver caps at 2 concurrent. dangerous_ok
        # is only meaningful with global=True. `global` is a Python
        # keyword, hence the trailing underscore in the kwarg.
        kwargs = dict(
            kind=pb.BpAddRequest.HW if kind == "hw" else pb.BpAddRequest.SW,
            address=address, slot=slot, size=size, access=access,
            kernel_target=kernel_target, pid=pid, tid=tid,
        )
        # Only set when True — keeps compatibility with v5 agents that
        # would ignore unknown proto3 fields but let us stay explicit.
        if global_:
            kwargs["global"] = True
        if dangerous_ok:
            kwargs["dangerous_ok"] = True
        if via_debugger:
            kwargs["via_debugger"] = True
        # dbgeng SW/DATA sweeteners — only pass when non-default so
        # the same wire shape still reaches an older agent (unknown
        # fields are dropped, not rejected, in proto3).
        if condition:
            kwargs["condition"] = condition
        if commands:
            kwargs["commands"] = commands
        if pass_count:
            kwargs["pass_count"] = pass_count
        if one_shot:
            kwargs["one_shot"] = True
        if match_tid:
            kwargs["match_tid"] = match_tid
        msg = await self._call(self.breakpoints.Add, pb.BpAddRequest(**kwargs))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"bp_id": msg.bp_id}

    async def bp_remove(self, bp_id: int) -> dict[str, Any]:
        # the agent uses errno_code=2 as an in-band "already_removed"
        # breadcrumb (retry after MCP deadline, thread-exit auto-prune,
        # double-remove — all land here with ok=true and this hint). Surface
        # it so callers can tell "we cleared it just now" apart from "it was
        # already gone."
        st = await self._call(self.breakpoints.Remove, pb.BpRemoveRequest(bp_id=bp_id))
        d = status_dict(st)
        if d.get("ok") and d.get("errno_code") == 2:
            d["already_removed"] = True
        return d

    # ------------------------------------------------------------ WatchHw ----
    #
    # SI #25 hardware data watchpoints. The agent has served the
    # WatchHw service since ABI v14 (Add arms a DR slot through the driver,
    # Remove releases it); the client never bound the stub, so
    # memory_manage(watch, mode='hw') answered hw_pending and AccessTrace
    # always fell back to dbgeng.

    async def bp_hw_watch_add(self, *, pid: int, tid: int = 0,
                              address: int, size: int,
                              access: str = "write", slot: int = 0xFF,
                              preempt_ok: bool = False,
                              tag: str = "") -> dict[str, Any]:
        """``WatchHw.Add`` — arm a DR0..3 data watchpoint. Returns
        ``{ok, error, watch_cookie, slot, threads_patched, hvci_fallback}``.
        ``hvci_fallback=True``: the DRs armed but the hypervisor refuses
        the driver's int1 hook, so hits never ring."""
        stub = getattr(self, "watch_hw", None)
        req_cls = getattr(pb, "WatchHwAddRequest", None)
        if stub is None or req_cls is None:
            return {"ok": False, "kind": "watchhw_unavailable",
                    "error": "WatchHw service not bound (orchestrator stubs "
                             "predate SI #25)", "watch_cookie": 0}
        msg = await self._call(stub.Add, req_cls(
            pid=int(pid), tid=int(tid), address=int(address),
            size=int(size), access=str(access), slot=int(slot),
            preempt_ok=bool(preempt_ok), tag=str(tag)))
        out = status_dict(msg.status)
        out.update({
            "watch_cookie": int(getattr(msg, "watch_cookie", 0) or 0),
            "slot": int(getattr(msg, "slot", 0) or 0),
            "threads_patched": int(getattr(msg, "threads_patched", 0) or 0),
            "hvci_fallback": bool(getattr(msg, "hvci_fallback", False)),
        })
        return out

    async def bp_hw_watch_remove(self, watch_cookie: int) -> dict[str, Any]:
        """``WatchHw.Remove`` — release the DR slot armed under
        *watch_cookie*. ``errno_code=2`` on ``ok=true`` means the slot was
        already gone (thread exit auto-prune) and is surfaced as
        ``already_removed``."""
        stub = getattr(self, "watch_hw", None)
        req_cls = getattr(pb, "WatchHwRemoveRequest", None)
        if stub is None or req_cls is None:
            return {"ok": False, "kind": "watchhw_unavailable",
                    "error": "WatchHw service not bound (orchestrator stubs "
                             "predate SI #25)"}
        st = await self._call(stub.Remove,
                              req_cls(watch_cookie=int(watch_cookie)))
        d = status_dict(st)
        if d.get("ok") and d.get("errno_code") == 2:
            d["already_removed"] = True
        return d

    async def bp_list(self) -> list[dict[str, Any]]:
        msg = await self._call(self.breakpoints.List, pb.BpListRequest())
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(b) for b in msg.breakpoints]

    async def bp_set_enabled(self, bp_id: int, enabled: bool) -> dict[str, Any]:
        st = await self._call(
            self.breakpoints.SetEnabled, pb.BpSetEnabledRequest(bp_id=bp_id, enabled=enabled)
        )
        return status_dict(st)
