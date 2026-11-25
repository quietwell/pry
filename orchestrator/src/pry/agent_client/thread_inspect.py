"""ThreadInspect service wrappers.

Seven RPCs that fan-out per-thread columns on
``memory_manage action='threads' include_<x>=True``. Driver-sourced two
(``wait_info`` / ``irp_list``) ride the agent view; the other five run
on the umagent view through Win32 APIs.

Every wrapper returns a plain dict with the slice-doc shape — the
caller never raises on an RPC-level error. Error paths map to:

* ``no_thread`` — PsLookupThreadByThreadId / OpenThread miss (thread
  exited mid-enrichment);
* ``access_denied`` — PP / PPL / impersonation refusal;
* ``wct_timeout`` — the 2s std::future wrap on GetThreadWaitChain fired;
* ``wave_3_pending`` — driver dyn-data not yet shipped (SI #3 WAIT_INFO
  + Feature 4 IRP_LIST both land here until Wave 3);
* ``no_driver`` — the umagent view answered a driver-backed verb;
* ``not_supported`` — the agent view answered an umagent-only verb;
* ``agent_version`` — older bindings missing the service.

The orchestrator-side ``memory_manage action='threads'`` dispatcher uses
these to decide whether a column is populated, ``None`` with an
``error`` sentinel, or dropped.
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb


class ThreadInspectMixin:
    def _ti_stub(self):
        return getattr(self, "thread_inspect", None)

    async def _ti_err(self, kind: str, text: str) -> dict[str, Any]:
        return {"ok": False, "kind": kind, "error": text}

    async def thread_wait_info(self, tid: int) -> dict[str, Any]:
        if self._ti_stub() is None or not hasattr(pb, "ThreadWaitInfoRequest"):
            return await self._ti_err("agent_version",
                                       "thread_wait_info: older agent")
        msg = await self._call(self.thread_inspect.WaitInfo,
                                pb.ThreadWaitInfoRequest(tid=int(tid)))
        err = (msg.error or "").strip()
        return {
            "ok": bool(msg.status.ok and not err),
            "error": err or (msg.status.error if not msg.status.ok else ""),
            "last_syscall_number": int(msg.last_syscall.number),
            "last_syscall_name": str(msg.last_syscall.name or ""),
            "last_syscall_status_hex": str(msg.last_syscall.status_hex or ""),
            "kernel_stack_base_hex": int(msg.kernel_stack.base_hex),
            "kernel_stack_limit": int(msg.kernel_stack.limit),
            "kernel_stack_rsp": int(msg.kernel_stack.rsp),
            "kernel_stack_excursion": int(msg.kernel_stack.excursion),
            "wait_reason": int(msg.wait_reason),
            "wait_mode": int(msg.wait_mode),
            "wait_status": int(msg.wait_status),
            "thread_state": int(msg.thread_state),
        }

    async def thread_irp_list(self, tid: int) -> dict[str, Any]:
        if self._ti_stub() is None or not hasattr(pb, "ThreadIrpListRequest"):
            return await self._ti_err("agent_version",
                                       "thread_irp_list: older agent")
        msg = await self._call(self.thread_inspect.IrpList,
                                pb.ThreadIrpListRequest(tid=int(tid)))
        err = (msg.error or "").strip()
        irps: list[dict[str, Any]] = []
        for e in msg.irps:
            irps.append({
                "irp_va": int(e.irp_va),
                "device_name": str(e.device_name or ""),
                "major_fn": int(e.major_fn),
                "minor_fn": int(e.minor_fn),
                "cancel_routine_va": int(e.cancel_routine_va),
            })
        return {
            "ok": bool(msg.status.ok and not err),
            "error": err or (msg.status.error if not msg.status.ok else ""),
            "pending": bool(msg.pending),
            "irp_count": int(msg.irp_count),
            "irps": irps,
        }

    async def thread_impersonation(self, tid: int) -> dict[str, Any]:
        if self._ti_stub() is None or not hasattr(pb, "ThreadImpersonationRequest"):
            return await self._ti_err("agent_version",
                                       "thread_impersonation: older agent")
        msg = await self._call(self.thread_inspect.Impersonation,
                                pb.ThreadImpersonationRequest(tid=int(tid)))
        err = (msg.error or "").strip()
        return {
            "ok": bool(msg.status.ok and not err),
            "error": err or (msg.status.error if not msg.status.ok else ""),
            "present": bool(msg.present),
            "user": str(msg.user or ""),
            "level": str(msg.level or ""),
            "is_self": bool(msg.is_self),
            "sid": str(msg.sid or ""),
        }

    async def thread_com_apartment(self, tid: int) -> dict[str, Any]:
        if self._ti_stub() is None or not hasattr(pb, "ThreadComApartmentRequest"):
            return await self._ti_err("agent_version",
                                       "thread_com_apartment: older agent")
        msg = await self._call(self.thread_inspect.ComApartment,
                                pb.ThreadComApartmentRequest(tid=int(tid)))
        err = (msg.error or "").strip()
        return {
            "ok": bool(msg.status.ok and not err),
            "error": err or (msg.status.error if not msg.status.ok else ""),
            "type": str(msg.type or ""),
            "flags": list(msg.flags),
            "teb_rfo": int(msg.teb_rfo),
        }

    async def thread_rpc_usage(self, tid: int) -> dict[str, Any]:
        if self._ti_stub() is None or not hasattr(pb, "ThreadRpcUsageRequest"):
            return await self._ti_err("agent_version",
                                       "thread_rpc_usage: older agent")
        msg = await self._call(self.thread_inspect.RpcUsage,
                                pb.ThreadRpcUsageRequest(tid=int(tid)))
        err = (msg.error or "").strip()
        return {
            "ok": bool(msg.status.ok and not err),
            "error": err or (msg.status.error if not msg.status.ok else ""),
            "in_rpc_call": bool(msg.in_rpc_call),
            "server": str(msg.server or ""),
            "chain_length": int(msg.chain_length),
        }

    async def thread_power_throttling(self, tid: int) -> dict[str, Any]:
        if self._ti_stub() is None or not hasattr(pb, "ThreadPowerThrottlingRequest"):
            return await self._ti_err("agent_version",
                                       "thread_power_throttling: older agent")
        msg = await self._call(self.thread_inspect.PowerThrottling,
                                pb.ThreadPowerThrottlingRequest(tid=int(tid)))
        err = (msg.error or "").strip()
        return {
            "ok": bool(msg.status.ok and not err),
            "error": err or (msg.status.error if not msg.status.ok else ""),
            "control_mask": int(msg.control_mask),
            "state_mask": int(msg.state_mask),
        }

    async def thread_fiber(self, tid: int) -> dict[str, Any]:
        if self._ti_stub() is None or not hasattr(pb, "ThreadFiberRequest"):
            return await self._ti_err("agent_version",
                                       "thread_fiber: older agent")
        msg = await self._call(self.thread_inspect.Fiber,
                                pb.ThreadFiberRequest(tid=int(tid)))
        err = (msg.error or "").strip()
        return {
            "ok": bool(msg.status.ok and not err),
            "error": err or (msg.status.error if not msg.status.ok else ""),
            "has_fiber_data": bool(msg.has_fiber_data),
        }
