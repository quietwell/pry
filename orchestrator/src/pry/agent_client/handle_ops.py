"""SI #6 handle ops + SI #9 kernel-stack walk AgentClient mixin.

Split out of ``mem.py`` in Wave 1 to keep ``mem.py`` below the 700-line
per-file cap. The methods forward to the agent's ``HandleOps`` and
``StackWalk`` services; both degrade cleanly when the generated proto
bindings or the gRPC stubs are missing (older agent).
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb


class HandleOpsMixin:
    # ------------------------------------------- SI #6 handle ops --
    # Thin wrappers around the agent's HandleOps RPC (duplicate / close /
    # compare). Each one guards against older agents that lack the
    # proto bindings or stub attribute so the orchestrator surfaces a
    # named ``agent_version`` envelope instead of a traceback.

    def _handle_ops_missing(self, action: str) -> dict[str, Any]:
        return {
            "ok": False,
            "kind": "agent_version",
            "error": (f"handle_{action}: older agent "
                      "(HandleOps service missing)"),
            "hint": ("rebuild + redeploy agent for the SI #6 "
                     "handle_ops surface"),
        }

    async def handle_dup(self, *, src_pid: int, src_handle: int,
                         desired_access: int = 0, options: int = 0,
                         privilege_cookie: int = 0) -> dict[str, Any]:
        if getattr(self, "handle_ops", None) is None:
            return self._handle_ops_missing("dup")
        if not hasattr(pb, "HandleDupRequest"):
            return self._handle_ops_missing("dup")
        req = pb.HandleDupRequest(
            src_pid=int(src_pid), src_handle=int(src_handle),
            desired_access=int(desired_access), options=int(options),
            privilege_cookie=int(privilege_cookie),
        )
        msg = await self._call(self.handle_ops.Duplicate, req)
        return {
            "ok": msg.status.ok,
            "error": msg.status.error if not msg.status.ok else None,
            "new_handle": int(msg.new_handle),
            "object_addr": int(msg.object_addr),
            "granted_access": int(msg.granted_access),
            "type_index": int(msg.type_index),
            "type_name": str(msg.type_name),
        }

    async def handle_close_remote(self, *, target_pid: int,
                                  target_handle: int,
                                  privilege_cookie: int = 0
                                  ) -> dict[str, Any]:
        if getattr(self, "handle_ops", None) is None:
            return self._handle_ops_missing("close")
        if not hasattr(pb, "HandleCloseRemoteRequest"):
            return self._handle_ops_missing("close")
        req = pb.HandleCloseRemoteRequest(
            target_pid=int(target_pid), target_handle=int(target_handle),
            privilege_cookie=int(privilege_cookie),
        )
        msg = await self._call(self.handle_ops.CloseRemote, req)
        return {
            "ok": msg.status.ok,
            "error": msg.status.error if not msg.status.ok else None,
        }

    async def handle_compare(self, *, pid_a: int, handle_a: int,
                             pid_b: int, handle_b: int,
                             privilege_cookie: int = 0) -> dict[str, Any]:
        if getattr(self, "handle_ops", None) is None:
            return self._handle_ops_missing("compare")
        if not hasattr(pb, "HandleCompareRequest"):
            return self._handle_ops_missing("compare")
        req = pb.HandleCompareRequest(
            pid_a=int(pid_a), handle_a=int(handle_a),
            pid_b=int(pid_b), handle_b=int(handle_b),
            privilege_cookie=int(privilege_cookie),
        )
        msg = await self._call(self.handle_ops.Compare, req)
        return {
            "ok": msg.status.ok,
            "error": msg.status.error if not msg.status.ok else None,
            "same": bool(msg.same),
            "object_a": int(msg.object_a),
            "object_b": int(msg.object_b),
            "type_index_a": int(msg.type_index_a),
            "type_index_b": int(msg.type_index_b),
        }

    # ------------------------------------------ SI #9 stack walk --
    # Thin wrapper around the agent's StackWalk.Walk RPC. The driver side
    # drives RtlWalkFrameChain via a kernel-mode APC on the target thread
    # (PryRemoteCall + PRY_RC_FLAG_KERNEL). Default timeout 500 ms
    # keeps the sequential IOCTL queue healthy (plan README §6).

    async def stack_walk(self, *, tid: int, flags: int = 0,
                         max_frames: int = 0, timeout_ms: int = 0,
                         privilege_cookie: int = 0) -> dict[str, Any]:
        if getattr(self, "stackwalk", None) is None:
            return {
                "ok": False, "kind": "agent_version",
                "error": ("stack_walk: older agent "
                          "(StackWalk service missing)"),
                "hint": ("rebuild + redeploy agent for the SI #9 "
                         "kernel-stack walk"),
            }
        if not hasattr(pb, "StackWalkRequest"):
            return {
                "ok": False, "kind": "agent_version",
                "error": ("stack_walk: older agent "
                          "(StackWalkRequest proto missing)"),
                "hint": "regenerate pry_pb2 against proto/pry.proto",
            }
        req = pb.StackWalkRequest(
            tid=int(tid), max_frames=int(max_frames),
            flags=int(flags), timeout_ms=int(timeout_ms),
            privilege_cookie=int(privilege_cookie),
        )
        msg = await self._call(self.stackwalk.Walk, req)

        def _frames(coll):
            return [{
                "rip": int(f.rip),
                "module_tag": int(f.module_tag),
                "module_base": int(f.module_base),
            } for f in coll]
        return {
            "ok": msg.status.ok,
            "error": msg.status.error if not msg.status.ok else None,
            "pid": int(msg.pid),
            "flags": int(msg.flags),
            "rip": int(msg.rip),
            "rsp": int(msg.rsp),
            "kernel_frames": _frames(msg.kernel_frames),
            "user_frames": _frames(msg.user_frames),
        }
