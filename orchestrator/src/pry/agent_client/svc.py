"""Services-service methods (umagent only).

Thin async wrapper around the generated ``pry.Services`` gRPC stub.
Read-only this cycle (no start/stop/config/delete) — the slice doc
explicitly defers service mutation to a later train. Signer enrichment
is driven orchestrator-side on top of this mixin (same ``verify_sigs``
pattern SI #8 uses on ``memory_manage(action='modules')``).
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb


def _entry_to_dict(r: Any) -> dict[str, Any]:
    """Project one ``SvcEntry`` proto message to the flat dict shape the
    orchestrator tool layer consumes. Keeps a single projection in one
    place so ``list`` / ``get`` / ``dependencies`` / ``drivers`` all
    agree on fields and types.
    """
    return {
        "name": r.name,
        "display_name": r.display_name,
        "state": r.state,
        "start_type": r.start_type,
        "service_type": r.service_type,
        "pid": int(r.pid),
        "image_path": r.image_path,
        "description": r.description,
        "service_sid_type": r.service_sid_type,
        "service_sid": r.service_sid,
        "launch_protected_level": r.launch_protected_level,
        "delayed_auto_start": bool(r.delayed_auto_start),
        "logon_account": r.logon_account,
        "dependencies": list(r.dependencies),
        "controls_accepted": list(r.controls_accepted),
        "triggers": [{
            "type": t.type,
            "subtype": t.subtype,
            "action": t.action,
            "data_items": list(t.data_items),
        } for t in r.triggers],
        "failure_actions": [{
            "action": fa.action,
            "delay_ms": int(fa.delay_ms),
            "reboot_message": fa.reboot_message,
            "run_command": fa.run_command,
        } for fa in r.failure_actions],
        "signer": r.signer,
        "signing_level": r.signing_level,
        "is_signed": bool(r.is_signed),
        "catalog": bool(r.catalog),
        "signer_cache_hit": bool(r.signer_cache_hit),
        "signer_error": r.signer_error,
        "module_base": int(r.module_base),
        "module_size": int(r.module_size),
        "module_timestamp": int(r.module_timestamp),
        "warnings": r.warnings,
        "kind": r.kind or ("driver" if r.service_type == "driver" else "service"),
    }


class SvcMixin:
    """gRPC facade over ``pry.Services`` (umagent-only)."""

    def _svc_missing(self, verb: str) -> dict[str, Any]:
        return {
            "ok": False,
            "kind": "agent_version",
            "error": (f"svc_manage {verb}: older agent/umagent "
                      "(Services service missing)"),
            "hint": ("rebuild + redeploy umagent for the "
                     "svc_manage surface"),
        }

    async def svc_list(self, *,
                       service_types: list[str] | None = None,
                       start_types: list[str] | None = None,
                       states: list[str] | None = None,
                       name_contains: str = "",
                       include_driver_base: bool = True,
                       verify_signatures: bool = False,
                       limit: int = 128) -> dict[str, Any]:
        """Enumerate services + drivers via EnumServicesStatusExW. Each
        row carries a ``kind='service'|'driver'`` discriminator so the
        caller can filter without a second type-bitmask parse.
        """
        if getattr(self, "services", None) is None:
            return self._svc_missing("list")
        if not hasattr(pb, "SvcListRequest"):
            return self._svc_missing("list")
        req = pb.SvcListRequest(
            service_types=[str(s) for s in
                            (service_types or ["win32", "driver", "adapter"])],
            start_types=[str(s) for s in (start_types or [])],
            states=[str(s) for s in (states or [])],
            name_contains=str(name_contains or ""),
            include_driver_base=bool(include_driver_base),
            verify_signatures=bool(verify_signatures),
            limit=int(limit or 0),
        )
        msg = await self._call(self.services.List, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "svc_list_failed",
                    "error": msg.status.error, "items": [], "total": 0}
        return {
            "ok": True,
            "items": [_entry_to_dict(r) for r in msg.items],
            "total": int(msg.total),
            "truncated": bool(msg.truncated),
            "degraded_rows": int(msg.degraded_rows),
        }

    async def svc_get(self, *, name: str) -> dict[str, Any]:
        """Single service deep-dive; name is the SCM short name."""
        if getattr(self, "services", None) is None:
            return self._svc_missing("get")
        if not hasattr(pb, "SvcGetRequest"):
            return self._svc_missing("get")
        req = pb.SvcGetRequest(name=str(name or ""))
        msg = await self._call(self.services.Get, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "svc_get_failed",
                    "error": msg.status.error}
        return {"ok": True, "item": _entry_to_dict(msg.item)}

    async def svc_dependencies(self, *, name: str,
                                reverse: bool = False
                                ) -> dict[str, Any]:
        """``reverse=False`` = what this needs; ``True`` = who needs this."""
        if getattr(self, "services", None) is None:
            return self._svc_missing("dependencies")
        if not hasattr(pb, "SvcDependenciesRequest"):
            return self._svc_missing("dependencies")
        req = pb.SvcDependenciesRequest(name=str(name or ""),
                                         reverse=bool(reverse))
        msg = await self._call(self.services.Dependencies, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "svc_dependencies_failed",
                    "error": msg.status.error, "items": []}
        return {"ok": True,
                "items": [_entry_to_dict(r) for r in msg.items]}

    async def svc_drivers(self, *, include_unloaded: bool = False,
                           verify_signatures: bool = False
                           ) -> dict[str, Any]:
        """Driver subset (SERVICE_DRIVER). ``include_unloaded`` surfaces
        installed-but-stopped driver entries alongside loaded ones."""
        if getattr(self, "services", None) is None:
            return self._svc_missing("drivers")
        if not hasattr(pb, "SvcDriversRequest"):
            return self._svc_missing("drivers")
        req = pb.SvcDriversRequest(
            include_unloaded=bool(include_unloaded),
            verify_signatures=bool(verify_signatures),
        )
        msg = await self._call(self.services.Drivers, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "svc_drivers_failed",
                    "error": msg.status.error, "items": []}
        return {"ok": True,
                "items": [_entry_to_dict(r) for r in msg.items]}
