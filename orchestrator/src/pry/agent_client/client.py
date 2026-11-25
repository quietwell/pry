"""Async gRPC client for the target agent. Unary calls + stream pumps feeding
an in-process asyncio event bus."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, AsyncIterator, Awaitable, Callable

import grpc

from ..allowlist import format_hostport
from ..caller import current_client_id
from ..generated import pry_pb2 as pb
from ..generated import pry_pb2_grpc as pbg
from ._errors import AgentRpcError, normalize_aio_errors, to_agent_error
from .cpu import CpuMixin
from .debug import DebugMixin
from .etw import EtwMixin
from .events import EventBus
from .exec import ExecMixin
from .files import FilesMixin
from .handle_ops import HandleOpsMixin
from .host import HostMixin
from .kernel import KernelMixin
from .mem import MemMixin
from .device import DeviceMixin
from .scan import ScanMixin  # v16: Memory scanner wave 1 — ScanService wrappers
from .pointer_map import PointerMapMixin  # v17: Wave 2 — PointerMap + Dissect
# Token + Mitigations mixins.
# Network + Services mixins (umagent-only).
# ThreadInspect mixin (opt-in columns).
# Appended at the end of the import block so parallel slices land cleanly.
from .mitigations import MitigationsMixin
from .net import NetMixin
from .svc import SvcMixin
from .thread_inspect import ThreadInspectMixin
from .token import TokenMixin
from .umagent import InputMixin
from .wire import _summarize_req

_log = logging.getLogger(__name__)

# 64-bit integer proto field types. MessageToDict renders these as decimal
# STRINGS (JSON can't carry uint64 losslessly); the top-level Status/Identify
# fields are coerced back to int where the orchestrator does arithmetic.
_INT64_TYPES = frozenset({3, 4, 6, 16, 18})  # INT64 UINT64 FIXED64 SFIXED64 SINT64


def coerce_int64_fields(msg: Any, d: dict[str, Any]) -> dict[str, Any]:
    """Replace the decimal-string renderings of *msg*'s top-level scalar
    64-bit fields in *d* with Python ints (read straight off the message,
    so no parsing ambiguity)."""
    desc = getattr(msg, "DESCRIPTOR", None)
    if desc is None:
        return d
    for f in desc.fields:
        repeated = getattr(f, "is_repeated", None)     # protobuf >= 5.x
        if repeated is None:
            repeated = getattr(f, "label", 1) == 3     # LABEL_REPEATED
        if f.type in _INT64_TYPES and not repeated and f.name in d:
            try:
                d[f.name] = int(getattr(msg, f.name))
            except (TypeError, ValueError):
                pass
    return d


class AgentClient(MemMixin, DebugMixin, FilesMixin, ExecMixin, KernelMixin, HostMixin, DeviceMixin, CpuMixin, EtwMixin, HandleOpsMixin, MitigationsMixin, NetMixin, SvcMixin, ThreadInspectMixin, TokenMixin, InputMixin, ScanMixin, PointerMapMixin):
    _RING_CAP = 64

    def __init__(self, host: str, port: int, token: str, timeout_ms: int = 10000,
                 max_inflight: int = 16) -> None:
        # asyncio.Semaphore(0) has zero permits, so every _call would
        # block on `async with self._sem` forever with no diagnosable
        # error. Refuse the misconfig up front rather than shipping a
        # client whose every gRPC operation silently hangs.
        if max_inflight < 1:
            raise ValueError(
                f"max_inflight must be >= 1 (got {max_inflight}); use a "
                "positive cap to bound in-flight gRPC calls"
            )
        self._target = format_hostport(host, port)
        self._token = token
        self._timeout = timeout_ms / 1000.0
        self._channel: grpc.aio.Channel | None = None
        # driver soft-fault policy (security.allow_kernel_softfault).
        # False strips allow_fault from every memory read this client sends;
        # the session sets it from config when it stores the client.
        self.allow_softfault: bool = False
        self.agent = None
        self.memory = None
        self.debug = None
        self.breakpoints = None
        self.files = None
        self.exec_ = None
        self.cpu = None
        self.coherency = None
        self.signatures = None
        self.hidden_proc = None
        self.handle_ops = None
        self.pdump = None
        self.stackwalk = None
        self.etw = None
        # Token + Mitigations stubs.
        # Named `token_svc` because the existing `token` property is the
        # auth bearer string; the TokenMixin references `self.token_svc`.
        self.token_svc = None
        self.mitigations = None
        # net_manage + svc_manage (umagent-only). None
        # until connect() wires them against a Network / Services stub.
        self.network = None
        self.services = None
        # ThreadInspect stub (opt-in thread columns).
        self.thread_inspect = None
        # umagent-only Input stub (SendInput-backed desktop input).
        # Agent-side (kernel) views leave this None; the MCP
        # ``desktop_manage(click|type|key)`` dispatcher routes those verbs
        # to ``name='user'`` which reaches the umagent view where the stub
        # is wired.
        self.input = None
        # v16 (Memory scanner wave 1): ScanService stub — bound in connect()
        # when the agent advertises scan_service_version >= 1. A pre-v16
        # orchestrator build or a pre-v16 agent leaves this None; every
        # ScanMixin wrapper returns kind='needs_v16' cleanly in that case.
        self.scan_service = None
        # v17 (Memory scanner wave 2): PointerMapService + DissectService
        # stubs. Same guarding as scan_service — bound in connect() when
        # the orchestrator build has the generated classes; the MCP
        # tool handlers short-circuit on
        # StatusResponse.pointer_map_version == 0 so a Phase C-K agent
        # never reaches the stub.
        self.pointer_map_service = None
        self.dissect_service = None
        # WatchHw (SI #25 hardware data watchpoints) — the agent has
        # served it since ABI v14; the client simply never bound a stub.
        self.watch_hw = None
        self.bus = EventBus()
        # Ring buffer of the last N gRPC calls we sent to the agent.
        # Records what was in flight when the transport dies or the agent
        # SCM-restart budget is exhausted, so the "did the IOCTL complete"
        # question has an answer even if the agent never came back.
        self._recent_ops: list[dict[str, Any]] = []
        # Per-view in-flight concurrency cap. Bulk fan-out (e.g. multi-region
        # scans, VAD-then-read loops) can stampede the agent's single IOCTL
        # thread if left unbounded; the semaphore keeps at most
        # `max_inflight` gRPC calls outstanding at any moment, while the
        # counter is exposed in `recent_ops` so operators can see contention.
        self._max_inflight = max_inflight
        self._sem = asyncio.Semaphore(max_inflight)
        self._inflight_count: int = 0
        # Phase 0.2: last-seen bookkeeping so target_manage(action="targets")
        # can render {endpoint, state, last_seen_ts, last_op_ts} per view for
        # deterministic reconnect after a wedge. last_seen_ts is any successful
        # call; last_op_ts is the last non-Status call.
        self._last_seen_ts: float = 0.0
        self._last_op_ts: float = 0.0
        self._connected_ts: float = 0.0

    @property
    def endpoint(self) -> str:
        return self._target

    @property
    def host(self) -> str:
        h = self._target.rsplit(":", 1)[0]
        return h[1:-1] if h.startswith("[") and h.endswith("]") else h

    @property
    def port(self) -> int:
        return int(self._target.rsplit(":", 1)[1])

    @property
    def token(self) -> str:
        return self._token

    @property
    def timeout_ms(self) -> int:
        return int(self._timeout * 1000)

    @property
    def last_seen_ts(self) -> float:
        return self._last_seen_ts

    @property
    def last_op_ts(self) -> float:
        return self._last_op_ts

    @property
    def connected_ts(self) -> float:
        return self._connected_ts

    async def connect(self, timeout_s: float | None = None) -> None:
        """Open the channel, bind every stub, then wait for the channel to
        become ready (bounded by *timeout_s* when given — a TimeoutError
        then leaves the stubs bound to a channel that keeps trying in the
        background, so the client is never left without a channel).

        No call is made and no credential is sent here: readiness is a
        transport-level handshake only."""
        self._open_channel()
        assert self._channel is not None
        if timeout_s is not None and timeout_s > 0:
            await asyncio.wait_for(self._channel.channel_ready(),
                                   timeout=timeout_s)
        else:
            await self._channel.channel_ready()
        self._connected_ts = time.time()

    def _open_channel(self) -> None:
        # v14: channel keepalive — after a target reboot the TCP channel
        # used to sit half-dead indefinitely, making a stale view look
        # alive until the next call timed out. Pings let the channel's
        # connectivity state actually transition.
        self._channel = grpc.aio.insecure_channel(
            self._target,
            options=[
                ("grpc.keepalive_time_ms", 20000),
                ("grpc.keepalive_timeout_ms", 10000),
                ("grpc.keepalive_permit_without_calls", 1),
                ("grpc.http2.max_pings_without_data", 0),
                # lift message size caps from the gRPC Python 4 MB
                # default — handle tables of busy processes and full module
                # dumps regularly cross it, and the stream close looks
                # indistinguishable from an agent crash. 128 MB matches
                # procdump-sized minidumps round-tripped inline.
                ("grpc.max_receive_message_length", 128 * 1024 * 1024),
                ("grpc.max_send_message_length", 128 * 1024 * 1024),
            ])
        self.agent = pbg.AgentStub(self._channel)
        self.memory = pbg.MemoryStub(self._channel)
        # v16 (Memory scanner wave 1): ScanService — guarded for pre-v16
        # orchestrator builds that regen against an older proto file.
        # On pre-v16 agents (no handlers) calls pass through but return
        # UNIMPLEMENTED at the transport level; the scan router picks the
        # fallback path based on StatusResponse.scan_service_version
        # rather than probing this stub.
        self.scan_service = (pbg.ScanServiceStub(self._channel)
                             if hasattr(pbg, "ScanServiceStub") else None)
        # v17 (Memory scanner wave 2): PointerMap + Dissect stubs. Pre-v17
        # orchestrator builds that regen against an older proto leave
        # these None; the MCP router returns kind='needs_v17'.
        self.pointer_map_service = (
            pbg.PointerMapServiceStub(self._channel)
            if hasattr(pbg, "PointerMapServiceStub") else None)
        self.dissect_service = (
            pbg.DissectServiceStub(self._channel)
            if hasattr(pbg, "DissectServiceStub") else None)
        self.debug = pbg.DebugStub(self._channel)
        self.breakpoints = pbg.BreakpointsStub(self._channel)
        self.files = pbg.FilesStub(self._channel)
        self.exec_ = pbg.ExecStub(self._channel)
        # v4 additions — registry service always registered, physical-ranges /
        # pool-scan live on Memory. Skip gracefully if the target agent
        # predates v4 (RegistryStub / PhysicalRanges / PoolScan will just
        # return UNIMPLEMENTED on call).
        self.registry = pbg.RegistryStub(self._channel) if hasattr(pbg, "RegistryStub") else None
        # v8: driver-backed wedge-detector. Absent on pre-v8 agents; the
        # watchdog_manage MCP tool surfaces "agent < v8" cleanly in that case.
        self.watchdog = (pbg.WatchdogStub(self._channel)
                         if hasattr(pbg, "WatchdogStub") else None)
        # v11: Device.Ioctl (usermode actuator) + Telemetry (ETW query-only).
        # Absent on pre-v11 agents; the MCP tools surface "agent < v11".
        self.device = (pbg.DeviceStub(self._channel)
                       if hasattr(pbg, "DeviceStub") else None)
        self.telemetry = (pbg.TelemetryStub(self._channel)
                          if hasattr(pbg, "TelemetryStub") else None)
        # v11: Events (driver notify ring — the agent's "ears"). Absent on
        # pre-v11 agents; event_manage surfaces "agent < v11" in that case.
        self.events = (pbg.EventsStub(self._channel)
                       if hasattr(pbg, "EventsStub") else None)
        # PR#6 T3.2: Cpu (MSR + CPUID). Absent on pre-PR#6 agents; cpu_manage
        # surfaces "agent < PR#6 (Cpu service missing)" in that case.
        self.cpu = (pbg.CpuStub(self._channel)
                    if hasattr(pbg, "CpuStub") else None)
        # SI Wave 1 feature #1: image coherency scoring. Absent on
        # older agents; memory_manage(action='coherency') surfaces
        # "older agent (ImageCoherency service missing)" cleanly.
        self.coherency = (pbg.ImageCoherencyStub(self._channel)
                          if hasattr(pbg, "ImageCoherencyStub") else None)
        # SI #21: driver self-protection toggle. Absent on
        # older agents; target_manage(action='selfprot_*') surfaces
        # "older agent (SelfProt service missing)" cleanly.
        self.selfprot = (pbg.SelfProtStub(self._channel)
                         if hasattr(pbg, "SelfProtStub") else None)
        # SI Wave 1 feature #8: signer / Authenticode column.
        # Absent on older agents; memory_manage(action='modules',
        # verify_signatures=True) surfaces "older agent (Signatures
        # service missing)" cleanly.
        self.signatures = (pbg.SignaturesStub(self._channel)
                           if hasattr(pbg, "SignaturesStub") else None)
        # SI Wave 1 feature #10: private kernel ETW session.
        # Absent on older agents; event_manage(action='etw_*')
        # surfaces "older agent (EtwTrace service missing)" cleanly.
        self.etw = (pbg.EtwTraceStub(self._channel)
                    if hasattr(pbg, "EtwTraceStub") else None)
        # SI Wave 1 feature #6: handle_dup / handle_close /
        # handle_compare primitives. Absent on older agents; the
        # orchestrator's memory_manage(action='handle_*') verb surfaces
        # "older agent (HandleOps service missing)" cleanly.
        self.handle_ops = (pbg.HandleOpsStub(self._channel)
                           if hasattr(pbg, "HandleOpsStub") else None)
        # SI Wave 1 feature #9: kernel-stack walk via
        # RtlWalkFrameChain delivered under a kernel-mode APC. Absent
        # on older agents; memory_manage(action='stack_walk') surfaces
        # "older agent (StackWalk service missing)" cleanly.
        self.stackwalk = (pbg.StackWalkStub(self._channel)
                          if hasattr(pbg, "StackWalkStub") else None)
        # SI Wave 1 feature #14: process-snapshot minidump via
        # PssCaptureSnapshot + MiniDumpWriteDump with a stepped
        # access-mask ladder. Absent on older agents;
        # dump_manage(action='process_snapshot') surfaces
        # "older agent (ProcessDump service missing)" cleanly.
        # Attribute is spelled `pdump` to leave `process_dump` free as
        # the public async method name on HostMixin (same pattern as
        # self.signatures / verify_signatures).
        self.pdump = (pbg.ProcessDumpStub(self._channel)
                      if hasattr(pbg, "ProcessDumpStub") else None)
        # SI Wave 1 feature #2: hidden-process detection via
        # brute / registry / ETW usermode scanners. Absent on
        # older agents; memory_manage(action='hidden_proc') surfaces
        # "older agent (HiddenProcess service missing)" cleanly.
        self.hidden_proc = (pbg.HiddenProcessStub(self._channel)
                            if hasattr(pbg, "HiddenProcessStub") else None)
        # token_manage view + mutator
        # verbs. Absent on older agents; the TokenMixin wrappers
        # surface "older agent (Token service missing)" cleanly.
        # Attribute spelled ``token_svc`` because ``token`` is the auth
        # bearer string property on this class.
        self.token_svc = (pbg.TokenStub(self._channel)
                          if hasattr(pbg, "TokenStub") else None)
        # mitigation policy readout
        # (process_manage action='mitigations' + verify_mitigations
        # kwarg on action='list'). Absent on older agents.
        self.mitigations = (pbg.MitigationsStub(self._channel)
                            if hasattr(pbg, "MitigationsStub") else None)
        # net_manage (umagent-only).
        # IPHLPAPI snapshot + reverse-DNS LRU + service-tag resolver +
        # SetTcpEntry kill. Agent-side (kernel) views leave this None;
        # the net_manage MCP tool rejects .kernel suffixes with
        # kind='bad_arg' before this is dereferenced.
        self.network = (pbg.NetworkStub(self._channel)
                        if hasattr(pbg, "NetworkStub") else None)
        # svc_manage (umagent-only).
        # EnumServicesStatusExW + trigger/SID/launch-protected decoders;
        # read-only this cycle. net_manage shares the umagent-only
        # routing policy.
        self.services = (pbg.ServicesStub(self._channel)
                         if hasattr(pbg, "ServicesStub") else None)
        # ThreadInspect — seven per-thread
        # enrichment RPCs. Driver-sourced two (WaitInfo / IrpList) ride
        # the agent view; the five umagent-only columns answer on
        # name='user'. Absent on older agents; memory_manage(action=
        # 'threads') surfaces "older agent (ThreadInspect service
        # missing)" cleanly.
        self.thread_inspect = (pbg.ThreadInspectStub(self._channel)
                                if hasattr(pbg, "ThreadInspectStub")
                                else None)
        # Input (umagent-only). Absent on older umagents;
        # the MCP ``desktop_manage(click|type|key)`` dispatcher surfaces
        # "older umagent (Input service missing)" cleanly in that case.
        self.input = (pbg.InputStub(self._channel)
                      if hasattr(pbg, "InputStub") else None)
        # WatchHw — absent only on a pb2 regenerated from a proto
        # that predates SI #25.
        self.watch_hw = (pbg.WatchHwStub(self._channel)
                         if hasattr(pbg, "WatchHwStub") else None)

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()
            self._channel = None

    #: rebind(): per-attempt readiness budget and attempt count. A heal that
    #: cannot reach the new endpoint gives up and restores the old target
    #: instead of awaiting channel_ready() forever.
    REBIND_READY_S: float = 8.0
    REBIND_ATTEMPTS: int = 3

    async def rebind(self, host: str, port: int | None = None, *,
                     ready_timeout_s: float | None = None,
                     attempts: int | None = None) -> None:
        """Re-point this client at another endpoint, in place.

        Used by the session's endpoint self-heal when the machine moved to
        a new DHCP address: keeping the same object means every holder of
        the client (event pumps, follows, auto-kickers, co-owners) picks up
        the new channel instead of talking to a dead one. Anything in
        flight on the old channel is cancelled by ``close()`` (callers see
        a retryable UNAVAILABLE, never a raw "Channel is closed").

        Readiness is bounded (``REBIND_READY_S`` per attempt,
        doubling, ``REBIND_ATTEMPTS`` tries). When every attempt fails the
        client is re-pointed at its OLD endpoint (channel opened, not
        awaited) and ``OSError`` is raised — the view is never left wedged
        on a channel that will not come up.
        """
        new_port = int(port or self.port)
        old_target = self._target
        budget = float(ready_timeout_s or self.REBIND_READY_S)
        tries = max(1, int(attempts or self.REBIND_ATTEMPTS))
        await self.close()
        self._target = format_hostport(host, new_port)
        last: BaseException | None = None
        for i in range(tries):
            try:
                await self.connect(timeout_s=budget)
                return
            except asyncio.CancelledError:
                await self._restore_target(old_target)
                raise
            except (asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001
                last = exc
                await self.close()
                if i + 1 < tries:
                    await asyncio.sleep(min(2.0 * (i + 1), 5.0))
                    budget = min(budget * 2.0, 30.0)
        await self._restore_target(old_target)
        raise OSError(
            None, f"WSAETIMEDOUT rebind to {host}:{new_port} failed after "
                  f"{tries} attempt(s): {last!r}; kept {old_target}")

    async def _restore_target(self, target: str) -> None:
        try:
            await self.close()
        except Exception:  # noqa: BLE001 — best-effort
            pass
        self._target = target
        try:
            self._open_channel()   # lazily connecting; never awaited here
        except Exception:  # noqa: BLE001
            _log.debug("rebind: could not reopen %s", target, exc_info=True)

    def _meta(self) -> list[tuple[str, str]]:
        return [("authorization", f"Bearer {self._token}")] if self._token else []

    def _ring_entry(self, method: str, request: Any,
                    timeout_s: float | None, status: str) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "t_start": time.time(), "method": method, "timeout_s": timeout_s,
            "req_summary": _summarize_req(request), "status": status,
            "inflight_at_start": self._inflight_count,
            "max_inflight": self._max_inflight,
            "client_id": current_client_id(),
        }
        self._recent_ops.append(entry)
        if len(self._recent_ops) > self._RING_CAP:
            del self._recent_ops[: len(self._recent_ops) - self._RING_CAP]
        return entry

    @staticmethod
    def _finish(entry: dict[str, Any], status: str, error: str = "") -> None:
        entry["status"] = status
        if error:
            entry["error"] = error
        entry["t_end"] = time.time()
        entry["latency_s"] = round(entry["t_end"] - entry["t_start"], 3)

    @staticmethod
    def _method_name(fn: Any) -> str:
        method = getattr(fn, "_method", "") or getattr(fn, "__qualname__", str(fn))
        if isinstance(method, bytes):
            method = method.decode("utf-8", "replace")
        return str(method)

    async def _stream(self, fn: Callable[..., Any], request: Any, *,
                      timeout: float | None = None,
                      idle_s: float | None = None,
                      auth: bool = True) -> AsyncIterator[Any]:
        """Server-streaming RPC with the same guarantees as :meth:`_call`.

        * ``timeout`` — overall gRPC deadline (None = no deadline, for
          long-lived event streams);
        * ``idle_s`` — max wait for the NEXT message (a stalled stream
          raises a DEADLINE_EXCEEDED-classified error instead of hanging);
        * transport errors are normalized to :class:`AgentRpcError`;
        * the attempt lands in the recent-ops ring (``streaming`` ->
          ``ok`` / ``error`` / ``cancelled``).
        """
        method = self._method_name(fn)
        entry = self._ring_entry(method, request, timeout, "streaming")
        kwargs: dict[str, Any] = {"metadata": self._meta() if auth else ()}
        if timeout is not None and timeout > 0:
            kwargs["timeout"] = timeout
        call = None
        try:
            call = fn(request, **kwargs)
            it = call.__aiter__()
            while True:
                try:
                    if idle_s is not None and idle_s > 0:
                        msg = await asyncio.wait_for(it.__anext__(), idle_s)
                    else:
                        msg = await it.__anext__()
                except StopAsyncIteration:
                    break
                except asyncio.TimeoutError:
                    code = grpc.StatusCode.DEADLINE_EXCEEDED
                    raise AgentRpcError(
                        kind="deadline",
                        error=f"{method}: no message for {idle_s:.0f}s "
                              "(stream stalled)",
                        hint="the agent stopped streaming — retry, or check "
                             "target_manage(action='status')",
                        code=code) from None
                self._last_seen_ts = time.time()
                yield msg
            self._finish(entry, "ok")
            self._last_op_ts = time.time()
        except (asyncio.CancelledError, GeneratorExit):
            self._finish(entry, "cancelled")
            raise
        except Exception as exc:
            err = to_agent_error(exc)
            self._finish(entry, "error", f"{type(err).__name__}: {err}")
            if err is exc:
                raise
            raise err from exc
        finally:
            if call is not None and entry.get("status") != "ok":
                try:
                    call.cancel()
                except Exception:  # noqa: BLE001
                    pass

    async def identify(self, timeout_s: float = 3.0) -> dict[str, Any] | None:
        """unauthenticated ``Agent.Identify`` — who is this
        endpoint, asked WITHOUT sending the agent token.

        Returns ``{computer_name, boot_epoch_ms (int), agent_instance_id,
        agent_version, view_kind}``; ``None`` when the agent (or this
        orchestrator's generated stubs) predate Identify — UNIMPLEMENTED,
        or an agent whose auth layer refuses the unauthenticated call.
        Other transport failures raise (normalized)."""
        req_cls = getattr(pb, "IdentifyRequest", None)
        fn = getattr(self.agent, "Identify", None) if self.agent is not None else None
        if req_cls is None or fn is None:
            return None
        try:
            msg = await self._call(fn, req_cls(), timeout=timeout_s, auth=False)
        except AgentRpcError as exc:
            if exc.code in (grpc.StatusCode.UNIMPLEMENTED,
                            grpc.StatusCode.UNAUTHENTICATED):
                return None
            raise
        return {
            "computer_name": str(getattr(msg, "computer_name", "") or ""),
            "boot_epoch_ms": int(getattr(msg, "boot_epoch_ms", 0) or 0),
            "agent_instance_id": str(getattr(msg, "agent_instance_id", "") or ""),
            "agent_version": str(getattr(msg, "agent_version", "") or ""),
            "view_kind": str(getattr(msg, "view_kind", "") or ""),
        }

    @normalize_aio_errors
    async def _call(self, fn: Callable[..., Awaitable[Any]], request: Any,
                    timeout: float | None = None, *, auth: bool = True) -> Any:
        """Timeout override: per-call `timeout` (seconds) beats the client default.
        None -> use the client default; 0 -> no timeout (bulk ops on slow paths).

        Also records the attempt in a small ring so post-crash forensics
        (`recent_ops()`) can show what was in flight when the agent died.

        The ``@normalize_aio_errors`` shim re-raises every
        ``grpc.aio.AioRpcError`` as :class:`AgentRpcError`, so no caller sees
        raw transport internals. The guard envelope regex still classifies
        the clean "``UNAVAILABLE: …``" / "``DEADLINE_EXCEEDED: …``" string,
        and callers wanting structured ``{kind, hint}`` access can catch
        :class:`AgentRpcError` and lift ``exc.payload``.
        """
        eff = self._timeout if timeout is None else (timeout if timeout > 0 else None)
        method = self._method_name(fn)
        entry = self._ring_entry(method, request, eff, "pending")
        try:
            await self._sem.acquire()
        except BaseException:
            # cancelled while queued behind max_inflight — the ring
            # used to show this attempt as "pending" forever.
            self._finish(entry, "cancelled", "cancelled before dispatch")
            raise
        try:
            self._inflight_count += 1
            try:
                result = await fn(request, metadata=self._meta() if auth else (),
                                  timeout=eff)
            except Exception as exc:
                self._finish(entry, "error", f"{type(exc).__name__}: {exc}")
                raise
            except BaseException:
                # asyncio.CancelledError (the MCP call was abandoned): record
                # it as such instead of leaving "pending" in recent_ops.
                self._finish(entry, "cancelled")
                raise
            finally:
                self._inflight_count -= 1
            # guard once for the (rare) case where the gRPC awaitable
            # resolves to None — a stream close mid-call, or a stub that was
            # torn down between attach and dispatch. Downstream callers all
            # dereference `.status.ok` on the return value; without this
            # guard they'd surface AttributeError('NoneType' object has no
            # attribute 'status') with no hint about which RPC actually
            # failed. Raise a labelled RuntimeError instead so recent_ops
            # and the caller-facing error tell the same story.
            if result is None:
                entry["status"] = "error"
                entry["error"] = f"agent RPC {method} returned no message"
                entry["t_end"] = time.time()
                entry["latency_s"] = round(entry["t_end"] - entry["t_start"], 3)
                raise RuntimeError(
                    f"agent RPC {method} returned no message; likely a "
                    "stream close mid-call — retry, or check "
                    "target_manage(action='recent_ops') for what was in "
                    "flight")
            self._finish(entry, "ok")
            # Phase 0.2: stamp last-seen (any success) and last-op (non-Status).
            self._last_seen_ts = entry["t_end"]
            if "Status" not in method and "Identify" not in method:
                self._last_op_ts = entry["t_end"]
            return result
        finally:
            self._sem.release()

    def recent_ops(self, limit: int = 32) -> list[dict[str, Any]]:
        """Last-N (default 32, cap 64) gRPC attempts. Use after an agent
        crash to see what was in flight and its latency at wedge time."""
        return list(self._recent_ops[-limit:])
