"""Machine-identity bookkeeping mixin for :class:`.core.Session`.

Resolves ``'<machine>.<kind>'`` view keys to the machine label and
view-kind components, caches the ``computer_name`` / endpoint reported
by HostInfo so a view stays identifiable across IP changes, and
maintains the alias table used by focus / connect to match a caller's
``machine=`` token against connected machines + config aliases.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..config import PRIMARY_TARGET

if TYPE_CHECKING:
    from ..agent_client import AgentClient
    from ..config import PryConfig


class SessionMachinesMixin:
    """Machine label + alias helpers; read-only beyond
    :meth:`note_machine_identity`."""

    # State owned by :class:`.core.Session.__init__`.
    cfg: PryConfig
    clients: dict[str, AgentClient]
    _machine_info: dict[str, dict[str, Any]]

    @staticmethod
    def machine_of(view_name: str) -> str:
        """Machine label out of a ``'<machine>.<kind>'`` view key. Undotted
        keys are their own machine label (raw-name connects)."""
        return view_name.rsplit(".", 1)[0] if "." in view_name else view_name

    @staticmethod
    def view_kind_of(view_name: str) -> str:
        """View-kind suffix of a ``'<machine>.<kind>'`` key ('kernel',
        'user', ...). Undotted keys return the whole name."""
        return view_name.rsplit(".", 1)[1] if "." in view_name else view_name

    def machines(self) -> dict[str, list[str]]:
        """Connected machine label -> sorted view keys, ordered by first
        connect."""
        out: dict[str, list[str]] = {}
        for key in self.clients:
            out.setdefault(self.machine_of(key), []).append(key)
        for views in out.values():
            views.sort()
        return out

    def machine_label(self, view_name: str) -> dict[str, Any]:
        """Identity record for a view's machine: {machine, computer_name,
        endpoint}. Falls back to the key prefix when HostInfo never ran."""
        info = self._machine_info.get(view_name) or {}
        client = self.clients.get(view_name)
        endpoint = getattr(client, "endpoint", "") or info.get("endpoint", "")
        cn = info.get("computer_name") or ""
        if not cn:
            # A view without its own identity (umagent) inherits the
            # computer_name a sibling view on the same machine learned.
            m = self.machine_of(view_name)
            for k, v in self._machine_info.items():
                if self.machine_of(k) == m and v.get("computer_name"):
                    cn = v["computer_name"]
                    break
        return {"machine": info.get("machine") or self.machine_of(view_name),
                "computer_name": cn,
                "endpoint": endpoint}

    def _label_for_host(self, host: str) -> str:
        """Machine label already connected on *host* — the sibling view's
        machine. The umagent doesn't report computer_name, so 'same box'
        is 'same agent host'; this keeps one machine per physical box."""
        for key, c in self.clients.items():
            ep = getattr(c, "endpoint", "") or ""
            if ep.rsplit(":", 1)[0] == host:
                return self.machine_of(key)
        return ""

    def note_machine_identity(self, view_name: str, *,
                              computer_name: str = "",
                              endpoint: str = "",
                              scan_service_version: int = 0,
                              pointer_map_version: int = 0,
                              dissect_version: int = 0) -> None:
        """Cache machine identity for a view key (called after host_info).

        ``scan_service_version`` (v16, Memory scanner wave 1): the value
        the agent echoed on StatusResponse. 0 means pre-v16 or Phase-B
        agent (no ScanService handlers). The scan router (Phase G)
        checks this to pick the on-target vs orchestrator-RAM fallback
        path without a second RPC.

        ``pointer_map_version`` (v17, Memory scanner wave 2): same shape.
        0 means pre-v17 or a Phase C-K agent (service exists in proto
        but the advert is clamped at 0). The pointer-map router
        refuses with ``kind='needs_v17'``; the dissect router falls
        back to the orchestrator-side glue path.

        ``dissect_version``:
        advert for DissectService alone. Older agents left this
        field absent and the Wave 2 dissect router proxied on
        ``pointer_map_version`` — Wave 3 P5 adds the dedicated field so
        a future bump (DissectCompare, Wave 3 P1) has a clean seam.
        """
        info = self._machine_info.setdefault(view_name, {})
        info["machine"] = self.machine_of(view_name)
        if computer_name:
            info["computer_name"] = computer_name
        if endpoint:
            info["endpoint"] = endpoint
        # 0 is a valid cached value (v15 agent) — unconditional store.
        info["scan_service_version"] = int(scan_service_version)
        info["pointer_map_version"] = int(pointer_map_version)
        info["dissect_version"] = int(dissect_version)

    def _machine_candidates(self) -> dict[str, str]:
        """case-insensitive alias -> canonical machine label. Aliases are
        the connected key prefix, the cached computer_name, and config
        ``machines:``/dotted-``targets:`` names."""
        cand: dict[str, str] = {}
        for key in self.clients:
            m = self.machine_of(key)
            cand.setdefault(m.lower(), m)
            cn = (self._machine_info.get(key) or {}).get("computer_name")
            if cn:
                cand.setdefault(str(cn).lower(), m)
        for cfg_name in getattr(self.cfg, "machines", {}) or {}:
            cand.setdefault(cfg_name.lower(), cfg_name)
        for cfg_name in getattr(self.cfg, "targets", {}) or {}:
            if "." in cfg_name:
                cand.setdefault(
                    self.machine_of(cfg_name).lower(), self.machine_of(cfg_name))
        return cand

    def _match_machine(self, token: str) -> str | None:
        """Resolve a machine token (label / computer_name / config alias)
        to a canonical machine label, or None."""
        if not token:
            return None
        return self._machine_candidates().get(token.lower())

    def _default_view_for_machine(self, machine: str) -> str:
        """The view a bare selector on *machine* should hit: its kernel
        view when connected, else the alphabetically-first live view, else
        the canonical kernel key (so the error message names it)."""
        kernel_key = f"{machine}.{PRIMARY_TARGET}"
        if kernel_key in self.clients:
            return kernel_key
        for key in sorted(self.clients):
            if self.machine_of(key) == machine:
                return key
        return kernel_key

    def _view_for(self, machine: str, kind: str) -> str:
        """The connected view key for machine+kind; falls back to the
        canonical '<machine>.<kind>' spelling so callers can report it."""
        want = kind.lower()
        for key in self.clients:
            if self.machine_of(key) == machine and \
                    self.view_kind_of(key).lower() == want:
                return key
        return f"{machine}.{kind}"
