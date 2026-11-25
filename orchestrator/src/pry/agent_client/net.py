"""Network-service methods (umagent only).

Thin async wrapper around the generated ``pry.Network`` gRPC stub.
Mirrors the shape used by ``HostMixin.verify_signatures`` /
``process_dump`` — one coroutine per RPC, early degrade when the agent
view predates the Network service (``self.network is None``), and a flat dict return
so the orchestrator tool layer doesn't need to touch proto types.

Every verb this mixin exposes is umagent-only. The ``net_manage`` MCP
tool enforces that by rejecting ``.kernel`` suffixes with
``kind='bad_arg'`` before ever reaching the client; this mixin is the
same code path either view takes, so a stray call from a kernel view
simply sees ``network is None`` and returns ``kind='agent_version'``.
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb


class NetMixin:
    """gRPC facade over ``pry.Network`` (umagent-only)."""

    def _net_missing(self, verb: str) -> dict[str, Any]:
        return {
            "ok": False,
            "kind": "agent_version",
            "error": (f"net_manage {verb}: older agent/umagent "
                      "(Network service missing)"),
            "hint": ("rebuild + redeploy umagent for the "
                     "net_manage surface"),
        }

    async def net_list(self, *,
                       families: list[str] | None = None,
                       protos: list[str] | None = None,
                       states: list[str] | None = None,
                       pid: int = 0,
                       include_loopback: bool = False,
                       module_resolve: bool = False,
                       include_services: bool = True,
                       resolve_hostnames: bool = False,
                       limit: int = 64) -> dict[str, Any]:
        """One TCP+UDP snapshot. PID/process/service-tag enriched.

        ``include_services``: resolve svchost.exe service tags via
        ``I_QueryTagInformation`` on umagent.
        ``resolve_hostnames``: cache-only reverse DNS; a miss returns
        ``""`` and enqueues a background ``GetNameInfoW``.
        """
        if getattr(self, "network", None) is None:
            return self._net_missing("list")
        if not hasattr(pb, "NetListRequest"):
            return self._net_missing("list")
        req = pb.NetListRequest(
            families=[str(f) for f in (families or ["v4", "v6"])],
            protos=[str(p) for p in (protos or ["tcp", "udp"])],
            states=[str(s) for s in (states or [])],
            pid=int(pid or 0),
            include_loopback=bool(include_loopback),
            module_resolve=bool(module_resolve),
            include_services=bool(include_services),
            resolve_hostnames=bool(resolve_hostnames),
            limit=int(limit or 0),
        )
        msg = await self._call(self.network.List, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "net_list_failed",
                    "error": msg.status.error, "items": [], "total": 0}
        items = [{
            "proto": r.proto,
            "family": r.family,
            "pid": int(r.pid),
            "process": r.process,
            "state": r.state,
            "local": r.local,
            "remote": r.remote,
            "create_time_ms": int(r.create_time_ms),
            "offload": r.offload,
            "scope_id_local": int(r.scope_id_local),
            "scope_id_remote": int(r.scope_id_remote),
            "service_tag": r.service_tag,
            "remote_host": r.remote_host,
            "owning_module_names": list(r.owning_module_names),
        } for r in msg.items]
        return {
            "ok": True, "items": items,
            "total": int(msg.total),
            "truncated": bool(msg.truncated),
            "dns_cache_hits": int(msg.dns_cache_hits),
            "dns_cache_misses": int(msg.dns_cache_misses),
            "dns_cache_size": int(msg.dns_cache_size),
        }

    async def net_interfaces(self, *, include_down: bool = False
                              ) -> dict[str, Any]:
        """GetAdaptersAddresses projection."""
        if getattr(self, "network", None) is None:
            return self._net_missing("interfaces")
        if not hasattr(pb, "NetInterfacesRequest"):
            return self._net_missing("interfaces")
        req = pb.NetInterfacesRequest(include_down=bool(include_down))
        msg = await self._call(self.network.Interfaces, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "net_interfaces_failed",
                    "error": msg.status.error, "items": []}
        return {
            "ok": True,
            "items": [{
                "name": i.name,
                "friendly_name": i.friendly_name,
                "description": i.description,
                "if_index": int(i.if_index),
                "if_type": int(i.if_type),
                "oper_status": i.oper_status,
                "speed_bps": int(i.speed_bps),
                "unicast": list(i.unicast),
                "gateways": list(i.gateways),
                "dns_servers": list(i.dns_servers),
                "mac": i.mac,
            } for i in msg.items],
        }

    async def net_stats(self, *,
                        families: list[str] | None = None,
                        protos: list[str] | None = None
                        ) -> dict[str, Any]:
        """netstat -s equivalent: scalar counters per family/proto."""
        if getattr(self, "network", None) is None:
            return self._net_missing("stats")
        if not hasattr(pb, "NetStatsRequest"):
            return self._net_missing("stats")
        req = pb.NetStatsRequest(
            families=[str(f) for f in (families or [])],
            protos=[str(p) for p in (protos or [])],
        )
        msg = await self._call(self.network.Stats, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "net_stats_failed",
                    "error": msg.status.error, "counters": []}
        return {
            "ok": True,
            "counters": [{"name": c.name, "value": int(c.value)}
                          for c in msg.counters],
        }

    async def net_kill(self, *, local: str, remote: str,
                        state_hint: str = "ESTABLISHED") -> dict[str, Any]:
        """SetTcpEntry(MIB_TCP_STATE_DELETE_TCB) on a chosen row.

        Caller MUST have gated this behind
        ``security.allow_kill_connection`` and ``_check_actuator_trust``.
        The umagent-side RPC refuses on its own if the gate was somehow
        skipped.
        """
        if getattr(self, "network", None) is None:
            return self._net_missing("kill")
        if not hasattr(pb, "NetKillRequest"):
            return self._net_missing("kill")
        req = pb.NetKillRequest(
            local=str(local or ""),
            remote=str(remote or ""),
            state_hint=str(state_hint or ""),
        )
        msg = await self._call(self.network.Kill, req)
        return {
            "ok": bool(msg.status.ok),
            "error": msg.status.error if not msg.status.ok else "",
            "killed": bool(msg.killed),
        }
