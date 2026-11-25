"""PointerMapService + DissectService client wrappers (v17, Wave 2).

Thin pass-through around the generated ``PointerMapServiceStub`` and
``DissectServiceStub``. Mirrors :mod:`.scan` (Wave 1). Every method
checks ``self.pointer_map_service`` / ``self.dissect_service`` for the
stub and falls back to ``kind='needs_v17'`` when the orchestrator
build predates the proto bump.

Agent-side routing (``kind='needs_v17'`` for a pre-v17 agent whose
StatusResponse.pointer_map_version == 0) is handled by the Phase G
MCP tool handlers; this layer just talks to whatever stub is attached.
"""
from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb
from .wire import proto_to_dict, status_dict


_MEMSPACE = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}
_DISK_SPILL_MODE = {
    "auto": pb.SCAN_SPILL_AUTO,
    "ram_only": pb.SCAN_SPILL_RAM_ONLY,
}


def _needs_v17(verb: str) -> dict[str, Any]:
    return {"ok": False, "kind": "needs_v17",
            "error": (f"{verb}: orchestrator build lacks "
                      "PointerMapServiceStub (pre-v17 pb2_grpc). "
                      "Rebuild the agent + orchestrator per README "
                      "\"ABI v17 rebuild\".")}


class PointerMapMixin:
    """Mixin providing ``pointer_map_*``, ``pointer_scan``,
    ``pointer_map_diff`` and ``dissect`` RPC wrappers on
    :class:`AgentClient`.

    ``self.pointer_map_service`` / ``self.dissect_service`` are the
    generated stubs or ``None`` when the orchestrator build predates
    v17.
    """

    async def pointer_map_create(
        self, *, map_id: str = "", pid: int,
        space: str = "user",
        spans: list[tuple[int, int]] | None = None,
        max_candidates: int = 0,
        owner_client_id: str = "",
        disk_spill_mode: str = "auto",
    ) -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_map_create")
        req = pb.PointerMapCreateRequest(
            map_id=map_id, pid=int(pid), space=_MEMSPACE[space],
            spans=[pb.ScanSpan(va=int(va), size=int(sz))
                   for va, sz in (spans or [])],
            max_candidates=int(max_candidates),
            owner_client_id=owner_client_id,
            disk_spill_mode=_DISK_SPILL_MODE.get(
                disk_spill_mode, pb.SCAN_SPILL_AUTO),
        )
        msg = await self._call(self.pointer_map_service.Create, req)
        return {**status_dict(msg.status),
                "map_id": msg.map_id,
                "status": msg.status_s,
                "progress": proto_to_dict(msg.progress)}

    async def pointer_map_status(self, map_id: str) -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_map_status")
        msg = await self._call(
            self.pointer_map_service.Status,
            pb.PointerMapStatusRequest(map_id=map_id))
        return {**status_dict(msg.status),
                "map_id": msg.map_id,
                "status": msg.status_s,
                "progress": proto_to_dict(msg.progress),
                "entries": int(msg.entries),
                "disk_bytes": int(msg.disk_bytes),
                "error": msg.error}

    async def pointer_map_list(self) -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_map_list")
        msg = await self._call(
            self.pointer_map_service.List, pb.PointerMapListRequest())
        return {**status_dict(msg.status),
                "entries": [proto_to_dict(e) for e in msg.entries]}

    async def pointer_map_cancel(self, map_id: str) -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_map_cancel")
        msg = await self._call(
            self.pointer_map_service.Cancel,
            pb.PointerMapCancelRequest(map_id=map_id))
        return {**status_dict(msg.status),
                "map_id": msg.map_id,
                "status": msg.status_s}

    async def pointer_map_save(self, *, map_id: str,
                               remote_path: str) -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_map_save")
        msg = await self._call(
            self.pointer_map_service.Save,
            pb.PointerMapSaveRequest(map_id=map_id,
                                      remote_path=remote_path))
        return {**status_dict(msg.status),
                "bytes_written": int(msg.bytes_written)}

    async def pointer_map_load(self, *, remote_path: str,
                               map_id: str = "") -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_map_load")
        msg = await self._call(
            self.pointer_map_service.Load,
            pb.PointerMapLoadRequest(remote_path=remote_path,
                                      map_id=map_id))
        return {**status_dict(msg.status),
                "map_id": msg.map_id,
                "entries": int(msg.entries)}

    async def pointer_map_destroy(self, *, map_id: str,
                                  keep_disk: bool = False) -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_map_destroy")
        msg = await self._call(
            self.pointer_map_service.Destroy,
            pb.PointerMapDestroyRequest(map_id=map_id,
                                         keep_disk=bool(keep_disk)))
        return {**status_dict(msg.status),
                "ram_bytes_freed": int(msg.ram_bytes_freed),
                "disk_bytes_freed": int(msg.disk_bytes_freed)}

    async def pointer_scan(
        self, *, map_id: str, target_va: int,
        max_depth: int = 0, max_offset: int = 0,
        static_only: bool = True,
        max_results: int = 0, fanout_per_level: int = 0,
        wall_ms: int = 0,
    ) -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_scan")
        req = pb.PointerScanRequest(
            map_id=map_id, target_va=int(target_va),
            max_depth=int(max_depth), max_offset=int(max_offset),
            static_only=bool(static_only),
            max_results=int(max_results),
            fanout_per_level=int(fanout_per_level),
            wall_ms=int(wall_ms))
        msg = await self._call(self.pointer_map_service.Scan, req)
        chains = []
        for c in msg.chains:
            chains.append({
                "anchor_va": int(c.anchor_va),
                "anchor_module": c.anchor_module,
                "anchor_module_off": int(c.anchor_module_off),
                "anchor_class": c.anchor_class,
                "offsets": [int(o) for o in c.offsets],
                "static": bool(c.static_),
            })
        return {**status_dict(msg.status),
                "chains": chains,
                "truncated": bool(msg.truncated),
                "wall_ms_actual": int(msg.wall_ms_actual),
                "candidates_examined": int(msg.candidates_examined),
                # disambiguated
                # truncation bools. Older agents leave these at
                # False (proto3 default); mem/pointer_map.py's _wrap
                # falls back to kind='scan_truncated' in that case.
                "wall_exceeded": bool(getattr(msg, "wall_exceeded", False)),
                "fanout_exceeded": bool(
                    getattr(msg, "fanout_exceeded", False))}

    async def pointer_map_diff(
        self, *, map_id_a: str, map_id_b: str,
        static_only: bool = True,
        chains: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if self.pointer_map_service is None:
            return _needs_v17("pointer_map_diff")
        req = pb.PointerMapDiffRequest(
            map_id_a=map_id_a, map_id_b=map_id_b,
            static_only=bool(static_only))
        for c in (chains or []):
            row = req.chains.add()
            row.anchor_va = int(c.get("anchor_va", 0))
            row.anchor_module = str(c.get("anchor_module", ""))
            row.anchor_module_off = int(c.get("anchor_module_off", 0))
            row.anchor_class = str(c.get("anchor_class", ""))
            for off in c.get("offsets", []):
                row.offsets.append(int(off))
            row.static_ = bool(c.get("static", False))
        msg = await self._call(self.pointer_map_service.Diff, req)
        rows = []
        for r in msg.rows:
            rows.append({
                "source_va_a": int(r.source_va_a),
                "source_va_b": int(r.source_va_b),
                "target_va_a": int(r.target_va_a),
                "target_va_b": int(r.target_va_b),
                "canonical_target": r.canonical_target,
                "still_valid": bool(r.still_valid),
                "drift_reason": r.drift_reason,
            })
        return {**status_dict(msg.status),
                "rows": rows,
                "compared_entries": int(msg.compared_entries),
                "truncated": bool(msg.truncated)}

    async def dissect(
        self, *, pid: int, address: int, size: int,
        space: str = "user", with_modules: bool = True,
        decode: list[str] | None = None, align: int = 0,
    ) -> dict[str, Any]:
        """v17 agent-side dissect. Caller falls back to the
        orchestrator-side implementation (``mem/dissect.py``) when the
        agent advertises ``pointer_map_version == 0``."""
        if self.dissect_service is None:
            return _needs_v17("dissect")
        req = pb.DissectRequest(
            pid=int(pid), address=int(address), size=int(size),
            space=_MEMSPACE[space], with_modules=bool(with_modules),
            decode=list(decode or []), align=int(align))
        msg = await self._call(self.dissect_service.Dissect, req)
        slots = []
        for s in msg.slots:
            slots.append({
                "offset": int(s.offset),
                "va": int(s.va),
                "u64_le": int(s.u64_le),
                "i32_le": int(s.i32_le),
                "u32_le": int(s.u32_le),
                "f32_le": float(s.f32_le),
                "f64_le": float(s.f64_le),
                "ptr_target_va": int(s.ptr_target_va),
                "ptr_module": s.ptr_module,
                "ptr_module_off": int(s.ptr_module_off),
                "ptr_classification": s.ptr_classification,
                "ascii_prefix": s.ascii_prefix,
                "utf16_prefix": s.utf16_prefix,
                "probable_type": s.probable_type,
                "score_pointer": int(s.score_pointer),
                "score_utf16": int(s.score_utf16),
                "score_ascii": int(s.score_ascii),
                "score_f64": int(s.score_f64),
                "score_f32": int(s.score_f32),
            })
        return {**status_dict(msg.status), "slots": slots,
                # surface the
                # DISSECT_MAX_ROWS truncation so callers know when they
                # hit the cap vs a short read. Older agents leave
                # both at proto3 defaults (0 / False).
                "total_rows": int(getattr(msg, "total_rows", 0)),
                "truncated": bool(getattr(msg, "truncated", False))}

    async def dissect_compare(
        self, *, pid: int, base_vas: list[int], window_size: int,
        align: int = 4, space: str = "user",
        with_modules: bool = True,
        shared_ptr_min_vote: int = 0,
        min_instances_for_class: int = 0,
    ) -> dict[str, Any]:
        """multi-instance structure
        compare. Caller falls back to a feature_unavailable envelope
        when the agent advertises ``dissect_version < 2``."""
        if self.dissect_service is None:
            return _needs_v17("dissect_compare")
        req = pb.DissectCompareRequest(
            pid=int(pid), window_size=int(window_size),
            align=int(align), space=_MEMSPACE[space],
            with_modules=bool(with_modules),
            shared_ptr_min_vote=int(shared_ptr_min_vote),
            min_instances_for_class=int(min_instances_for_class))
        for va in base_vas or []:
            req.base_vas.append(int(va))
        msg = await self._call(self.dissect_service.Compare, req)
        offsets: list[dict[str, Any]] = []
        for c in msg.offsets:
            offsets.append({
                "offset": int(c.offset),
                "classification": c.classification,
                "distinct_values": int(c.distinct_values),
                "readable_instances": int(c.readable_instances),
                "modal_value": int(c.modal_value),
                "modal_votes": int(c.modal_votes),
                "probable_type": c.probable_type,
                "shared_target_module": c.shared_target_module,
                "shared_target_module_off": int(c.shared_target_module_off),
            })
        per_instance: list[dict[str, Any]] = []
        for inst in msg.per_instance:
            slots: list[dict[str, Any]] = []
            for s in inst.slots:
                slots.append({
                    "offset": int(s.offset),
                    "va": int(s.va),
                    "u64_le": int(s.u64_le),
                    "i32_le": int(s.i32_le),
                    "u32_le": int(s.u32_le),
                    "f32_le": float(s.f32_le),
                    "f64_le": float(s.f64_le),
                    "ptr_target_va": int(s.ptr_target_va),
                    "ptr_module": s.ptr_module,
                    "ptr_module_off": int(s.ptr_module_off),
                    "ptr_classification": s.ptr_classification,
                    "ascii_prefix": s.ascii_prefix,
                    "utf16_prefix": s.utf16_prefix,
                    "probable_type": s.probable_type,
                    "score_pointer": int(s.score_pointer),
                    "score_utf16": int(s.score_utf16),
                    "score_ascii": int(s.score_ascii),
                    "score_f64": int(s.score_f64),
                    "score_f32": int(s.score_f32),
                })
            per_instance.append({
                "base_va": int(inst.base_va),
                "unreadable": bool(inst.unreadable),
                "slots": slots,
            })
        return {**status_dict(msg.status),
                "offsets": offsets,
                "per_instance": per_instance,
                "n_instances": int(msg.n_instances),
                "n_offsets": int(msg.n_offsets)}
