"""ScanService client wrappers (Memory scanner wave 1 Phase B).

Thin pass-through around the generated ``ScanServiceStub``. Every
method follows the existing mixin pattern (``MemMixin``,
``HostMixin``, ...): take typed Python args, build the proto request,
invoke the stub, return a ``proto_to_dict`` of the response.

The stub is attached in :meth:`AgentClient.connect` with the usual
``hasattr(pbg, "ScanServiceStub")`` guard so a pre-v16 orchestrator
build (missing the generated class) degrades to ``None`` rather than
AttributeError.

Phase B ships the proto + wrappers but no agent handlers — every call
reaches the agent and returns ``UNIMPLEMENTED`` at the gRPC transport
level (no C++ shim registered on the agent side). The orchestrator's
scan router (Phase G) short-circuits on
``StatusResponse.scan_service_version == 0`` and never issues these
calls against a Phase-B agent. These wrappers exist so Phase C+
callers can land without a client-side plumbing refactor.
"""
from __future__ import annotations

from typing import Any, AsyncIterator

from ..generated import pry_pb2 as pb
from .wire import proto_to_dict, status_dict


_MEMSPACE = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}
_DISK_SPILL_MODE = {
    "auto": pb.SCAN_SPILL_AUTO,
    "ram_only": pb.SCAN_SPILL_RAM_ONLY,
}


class ScanMixin:
    """Mixin providing ``scan_*`` RPC wrappers on :class:`AgentClient`.

    ``self.scan_service`` is the generated ``ScanServiceStub`` or
    ``None`` when the orchestrator build predates v16.
    """

    async def scan_create(
        self, *,
        scan_id: str,
        pid: int,
        space: str = "user",
        value_type: str,
        endian: str = "le",
        encoding: str = "",
        align: int = 1,
        op: str,
        value_le: bytes = b"",
        value_hi_le: bytes = b"",
        tolerance_bits: int = 0,
        spans: list[tuple[int, int]] | None = None,
        max_results: int = 4096,
        owner_client_id: str = "",
        disk_spill_mode: str = "auto",
    ) -> dict[str, Any]:
        """Create a scan on the target. See
        ``an internal plan`` §3.5 Create.
        """
        if self.scan_service is None:
            return {"ok": False, "kind": "needs_v16",
                    "error": "scan_create: orchestrator build lacks "
                             "ScanServiceStub (pre-v16 pb2_grpc)"}
        req = pb.ScanCreateRequest(
            scan_id=scan_id, pid=int(pid),
            space=_MEMSPACE[space], value_type=value_type,
            endian=endian, encoding=encoding, align=int(align),
            op=op, value_le=bytes(value_le),
            value_hi_le=bytes(value_hi_le),
            tolerance_bits=int(tolerance_bits),
            spans=[pb.ScanSpan(va=int(va), size=int(sz))
                   for va, sz in (spans or [])],
            max_results=int(max_results),
            owner_client_id=owner_client_id,
            disk_spill_mode=_DISK_SPILL_MODE.get(
                disk_spill_mode, pb.SCAN_SPILL_AUTO),
        )
        msg = await self._call(self.scan_service.Create, req)
        return {**status_dict(msg.status),
                "scan_id": msg.scan_id,
                "status": msg.status_s,
                "generation": int(msg.generation),
                "progress": proto_to_dict(msg.progress)}

    async def scan_refine(
        self, *, scan_id: str, op: str,
        value_le: bytes = b"", value_hi_le: bytes = b"",
        delta_le: bytes = b"", tolerance_bits: int = 0,
    ) -> dict[str, Any]:
        if self.scan_service is None:
            return {"ok": False, "kind": "needs_v16",
                    "error": "scan_refine: orchestrator build lacks "
                             "ScanServiceStub"}
        req = pb.ScanRefineRequest(
            scan_id=scan_id, op=op,
            value_le=bytes(value_le), value_hi_le=bytes(value_hi_le),
            delta_le=bytes(delta_le),
            tolerance_bits=int(tolerance_bits))
        msg = await self._call(self.scan_service.Refine, req)
        return {**status_dict(msg.status),
                "scan_id": msg.scan_id,
                "generation": int(msg.generation),
                "hit_count": int(msg.hit_count),
                "dropped": int(msg.dropped),
                "reads_failed": int(msg.reads_failed),
                "status": msg.status_s}

    async def scan_undo(self, scan_id: str) -> dict[str, Any]:
        if self.scan_service is None:
            return {"ok": False, "kind": "needs_v16",
                    "error": "scan_undo: orchestrator build lacks "
                             "ScanServiceStub"}
        msg = await self._call(
            self.scan_service.Undo, pb.ScanUndoRequest(scan_id=scan_id))
        return {**status_dict(msg.status),
                "scan_id": msg.scan_id,
                "generation": int(msg.generation),
                "hit_count": int(msg.hit_count)}

    async def scan_cancel(self, scan_id: str) -> dict[str, Any]:
        if self.scan_service is None:
            return {"ok": False, "kind": "needs_v16",
                    "error": "scan_cancel: orchestrator build lacks "
                             "ScanServiceStub"}
        msg = await self._call(
            self.scan_service.Cancel, pb.ScanCancelRequest(scan_id=scan_id))
        return {**status_dict(msg.status),
                "scan_id": msg.scan_id,
                "status": msg.status_s}

    async def scan_destroy(self, scan_id: str) -> dict[str, Any]:
        if self.scan_service is None:
            return {"ok": False, "kind": "needs_v16",
                    "error": "scan_destroy: orchestrator build lacks "
                             "ScanServiceStub"}
        msg = await self._call(
            self.scan_service.Destroy,
            pb.ScanDestroyRequest(scan_id=scan_id))
        return {**status_dict(msg.status),
                "scan_id": msg.scan_id,
                "disk_bytes_freed": int(msg.disk_bytes_freed),
                "ram_bytes_freed": int(msg.ram_bytes_freed)}

    async def scan_list(self) -> dict[str, Any]:
        if self.scan_service is None:
            return {"ok": False, "kind": "needs_v16",
                    "error": "scan_list: orchestrator build lacks "
                             "ScanServiceStub"}
        msg = await self._call(
            self.scan_service.List, pb.ScanListRequest())
        return {**status_dict(msg.status),
                "entries": [proto_to_dict(e) for e in msg.entries]}

    async def scan_status(self, scan_id: str) -> dict[str, Any]:
        if self.scan_service is None:
            return {"ok": False, "kind": "needs_v16",
                    "error": "scan_status: orchestrator build lacks "
                             "ScanServiceStub"}
        msg = await self._call(
            self.scan_service.Status,
            pb.ScanStatusRequest(scan_id=scan_id))
        return {**status_dict(msg.status),
                "scan_id": msg.scan_id,
                "status": msg.status_s,
                "generation": int(msg.generation),
                "hit_count": int(msg.hit_count),
                "progress": proto_to_dict(msg.progress),
                "error": msg.error}

    async def scan_fetch(
        self, *, scan_id: str, generation: int,
        limit: int = 0, offset: int = 0,
    ) -> AsyncIterator[dict[str, Any]]:
        """Server-streaming Fetch. Yields one dict per chunk with
        ``{ok, generation, rows[{va, raw_value}], eof, total_remaining}``.
        Consumer cancels by breaking out of the iteration.
        """
        if self.scan_service is None:
            yield {"ok": False, "kind": "needs_v16",
                   "error": "scan_fetch: orchestrator build lacks "
                            "ScanServiceStub"}
            return
        req = pb.ScanFetchRequest(
            scan_id=scan_id, generation=int(generation),
            limit=int(limit), offset=int(offset))
        async for chunk in self._stream(
                self.scan_service.Fetch, req,
                idle_s=max(30.0, float(getattr(self, "_timeout", 10.0)) * 3)):
            yield {"ok": bool(chunk.status.ok),
                   "error": chunk.status.error,
                   "generation": int(chunk.generation),
                   "rows": [{"va": int(r.va), "raw": bytes(r.raw_value)}
                            for r in chunk.rows],
                   "eof": bool(chunk.eof),
                   "total_remaining": int(chunk.total_remaining)}
