"""View enumeration + client-handle mixin for :class:`.core.Session`.

Hosts :meth:`require_client` (the strict-view-lookup helper every
``name=``-aware tool funnels through) and :meth:`all_views` — the
configured-plus-connected view listing that drives
``target_manage(action='targets')``.
"""

from __future__ import annotations

import datetime as _dt
import time
from typing import TYPE_CHECKING, Any

from ..agent_client import AgentClient

if TYPE_CHECKING:
    from ..config import PryConfig


class SessionViewsMixin:
    """``require_client`` + ``all_views`` surface."""

    # State owned by :class:`.core.Session.__init__`.
    cfg: PryConfig
    clients: dict[str, AgentClient]
    primary: str
    _machine_info: dict[str, dict[str, Any]]

    if TYPE_CHECKING:
        # Methods implemented on sibling mixins.
        def resolve_view_name(self, name: str = "",
                              client_id: str | None = None) -> str: ...
        def machine_label(self, view_name: str) -> dict[str, Any]: ...

    def require_client(self, name: str = "") -> AgentClient:
        n = self.resolve_view_name(name)
        client = self.clients.get(n)
        if client is None:
            # enrich dead-view errors with the view's
            # last-known endpoint so the caller sees WHAT to reconnect to,
            # not just WHICH view is dead.
            info = self._machine_info.get(n) or {}
            ep = str(info.get("endpoint") or "")
            ep_bit = f" (last endpoint: {ep})" if ep else ""
            raise RuntimeError(
                f"not connected: target {n!r}{ep_bit} — call "
                f"target_manage(action='connect', name={n!r}) first")
        return client

    def all_views(self) -> list[dict[str, Any]]:
        """Every configured target view (kernel, user, ...) with connection
        state + last-seen timestamps. Used by target_manage(action='targets')
        to make post-reboot reconnect deterministic — configured endpoints
        + last-seen tell the caller which view to reconnect and where.
        """
        rows: list[dict[str, Any]] = []
        # Every view mentioned in config plus any dynamically-connected view.
        cfg_names: set[str] = set()
        for name in getattr(self.cfg, "targets", {}):
            cfg_names.add(name)
        for mname, mcfg in (getattr(self.cfg, "machines", {}) or {}).items():
            views = getattr(mcfg, "views", {}) or {}
            for kind in views or ("kernel", "user"):
                cfg_names.add(f"{mname}.{kind}")
        cfg_names.add(self.primary)
        cfg_names.update(self.clients.keys())
        cfg_names.update(self._machine_info.keys())
        now = time.time()
        for name in sorted(cfg_names):
            try:
                t = self.cfg.target_for(name)
                cfg_endpoint = f"{t.host}:{t.port}"
            except Exception:
                cfg_endpoint = ""
            client = self.clients.get(name)
            machine_info = self.machine_label(name)
            if client is None:
                rows.append({"name": name, "endpoint": cfg_endpoint,
                             "machine": machine_info["machine"],
                             "computer_name": machine_info["computer_name"],
                             "state": "not_connected", "connected": False})
                continue
            last_op = client.last_op_ts
            state = "connected"
            if last_op and (now - last_op) > 60:
                state = "connected_stale"
            row: dict[str, Any] = {
                "name": name,
                "machine": machine_info["machine"],
                "computer_name": machine_info["computer_name"],
                "endpoint": client.endpoint or cfg_endpoint,
                "configured_endpoint": cfg_endpoint,
                "state": state,
                "connected": True,
                "connected_ts": _dt.datetime.utcfromtimestamp(client.connected_ts).isoformat() + "Z"
                                if client.connected_ts else None,
                "last_seen_ts": _dt.datetime.utcfromtimestamp(client.last_seen_ts).isoformat() + "Z"
                                if client.last_seen_ts else None,
                "last_op_ts": _dt.datetime.utcfromtimestamp(client.last_op_ts).isoformat() + "Z"
                              if client.last_op_ts else None,
                "seconds_since_last_op": round(now - last_op, 1) if last_op else None,
                "primary": (name == self.primary),
            }
            rows.append(row)
        return rows
