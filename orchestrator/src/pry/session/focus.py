"""Per-caller focus + view-name resolution mixin for
:class:`.core.Session`.

Each MCP caller holds its own ``focus`` (a ``(machine, kind)`` pair set
by ``target_manage(action='use')``) that fills in empty / bare
``name=`` selectors so concurrent chats sit on different machines
without a global default. The resolver turns every accepted selector
shapes into a concrete view key; stamping decides when an envelope has
to carry the key explicitly.

Focus entries expire. An entry unused for ``FOCUS_TTL_S`` (6 h)
is dropped; one held by a connection-scoped anonymous id (a client that
sends no ``Mcp-Session-Id`` — see :mod:`pry.caller`) after
``ANON_FOCUS_TTL_S``. Expiry fails closed: with several machines connected
the caller gets ``ambiguous_target`` and must ``use`` again, never another
chat's machine.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ..caller import current_client_id, is_anonymous_id
from ..config import PRIMARY_TARGET
from ._errors import AmbiguousTargetError
from ._models import VIEW_KINDS

if TYPE_CHECKING:
    from ..agent_client import AgentClient


class SessionFocusMixin:
    """Focus bookkeeping + view-name resolution."""

    # State owned by :class:`.core.Session.__init__`.
    clients: dict[str, AgentClient]
    primary: str
    _focus: dict[str, dict[str, str]]

    #: Idle lifetime of a focus entry (seconds) — session-id callers, and
    #: connection-scoped anonymous ones.
    FOCUS_TTL_S: float = 6 * 3600.0
    ANON_FOCUS_TTL_S: float = 15 * 60.0
    _FOCUS_PRUNE_EVERY_S: float = 60.0

    def _focus_stamps(self) -> dict[str, float]:
        st = self.__dict__.get("_focus_seen")
        if st is None:
            st = self.__dict__["_focus_seen"] = {}
        return st

    def _focus_ttl(self, client_id: str) -> float:
        return self.ANON_FOCUS_TTL_S if is_anonymous_id(client_id) \
            else self.FOCUS_TTL_S

    def _set_focus_entry(self, client_id: str, machine: str,
                         kind: str) -> None:
        self._focus[client_id] = {"machine": machine, "kind": kind}
        self._focus_stamps()[client_id] = time.monotonic()
        self.prune_focus()

    def _focus_get(self, client_id: str | None) -> dict[str, str] | None:
        """The live focus entry for *client_id* (touching it), or None —
        an expired entry is dropped on read."""
        cid = client_id or current_client_id()
        f = self._focus.get(cid)
        if f is None:
            return None
        stamps = self._focus_stamps()
        now = time.monotonic()
        seen = stamps.get(cid)
        if seen is not None and now - seen > self._focus_ttl(cid):
            self._focus.pop(cid, None)
            stamps.pop(cid, None)
            return None
        stamps[cid] = now
        return f

    def prune_focus(self, now: float | None = None) -> list[str]:
        """Drop expired focus entries (rate-limited unless *now* is given).
        Returns the client ids dropped."""
        if now is None:
            now = time.monotonic()
            last = self.__dict__.get("_focus_pruned_at", 0.0)
            if now - last < self._FOCUS_PRUNE_EVERY_S and now >= last:
                return []
        self.__dict__["_focus_pruned_at"] = now
        stamps = self._focus_stamps()
        dropped: list[str] = []
        for cid in list(self._focus):
            seen = stamps.get(cid)
            if seen is None:
                stamps[cid] = now      # entry written directly; start its clock
                continue
            if now - seen > self._focus_ttl(cid):
                self._focus.pop(cid, None)
                stamps.pop(cid, None)
                dropped.append(cid)
        for cid in [c for c in stamps if c not in self._focus]:
            stamps.pop(cid, None)
        return dropped

    if TYPE_CHECKING:
        # Methods implemented on sibling mixins.
        def _match_machine(self, token: str) -> str | None: ...
        def machines(self) -> dict[str, list[str]]: ...
        def _view_for(self, machine: str, kind: str) -> str: ...
        def machine_label(self, view_name: str) -> dict[str, Any]: ...
        def machine_of(self, view_name: str) -> str: ...
        def _default_view_for_machine(self, machine: str) -> str: ...

    def set_focus(self, client_id: str, selector: str) -> dict[str, Any]:
        """Bind *client_id* to a machine (or machine.kind). Raises
        RuntimeError when the selector matches no connected machine —
        focus must point at something live."""
        machine_token, _, kind = (selector or "").partition(".")
        machine = self._match_machine(machine_token)
        if machine is None:
            raise RuntimeError(
                f"use: unknown machine {machine_token!r} — connected "
                f"machines: {', '.join(sorted(self.machines())) or '<none>'}; "
                "connect first with target_manage(action='connect', "
                "machine=...)")
        if kind and kind.lower() not in [k.lower() for k in VIEW_KINDS] and \
                self._view_for(machine, kind) not in self.clients:
            raise RuntimeError(
                f"use: machine {machine!r} has no view kind {kind!r} "
                f"(has: {self.machines().get(machine)})")
        self._set_focus_entry(client_id, machine,
                              kind.lower() or PRIMARY_TARGET)
        return {"machine": machine, "kind": kind.lower() or PRIMARY_TARGET,
                "view": self._view_for(machine, kind.lower() or PRIMARY_TARGET),
                **self.machine_label(
                    self._view_for(machine, kind.lower() or PRIMARY_TARGET))}

    def clear_focus(self, client_id: str) -> bool:
        self._focus_stamps().pop(client_id, None)
        return self._focus.pop(client_id, None) is not None

    def focus_of(self, client_id: str) -> dict[str, str] | None:
        f = self._focus_get(client_id)
        return dict(f) if f else None

    def _default_machine(self, client_id: str | None) -> str | None:
        """Which machine an empty selector lands on for *client_id*:
        their focus, the only connected machine, or AmbiguousTargetError."""
        cid = client_id or current_client_id()
        f = self._focus_get(cid)
        if f is not None:
            return f["machine"]
        machines = self.machines()
        if len(machines) == 1:
            return next(iter(machines))
        if not machines:
            return None
        raise AmbiguousTargetError(sorted(machines))

    def resolve_view_name(self, name: str = "",
                          client_id: str | None = None) -> str:
        """Map a caller's ``name=`` selector to a concrete view key.

        Accepted shapes:
          ''              -> focus machine's focus kind, the only connected
                           machine's kernel view, or AmbiguousTargetError
          '<m>.<kind>'    -> that view (machine matched against label /
                           computer_name / config alias, case-insensitive)
          '<machine>'     -> the machine's kernel view
          '<kind>'        -> that view kind on the caller's focus machine
                           (or the only machine)
          anything else   -> returned verbatim; require_client reports it
                           as not-connected.
        """
        name = (name or "").strip()
        if name in self.clients:
            return name
        if "." in name:
            m_tok, kind = name.rsplit(".", 1)
            machine = self._match_machine(m_tok)
            if machine is None:
                raise RuntimeError(
                    f"unknown machine {m_tok!r} — connected machines: "
                    f"{', '.join(sorted(self.machines())) or '<none>'}")
            key = self._view_for(machine, kind)
            if key not in self.clients:
                views = self.machines().get(machine) or []
                raise RuntimeError(
                    f"view {name!r} not connected — machine {machine!r} "
                    f"has views: {views or '<none>'}")
            return key
        if name:
            machine = self._match_machine(name)
            if machine is not None:
                return self._default_view_for_machine(machine)
            if name.lower() in VIEW_KINDS:
                machine = self._default_machine(client_id)
                if machine is None:
                    return name
                return self._view_for(machine, name.lower())
            return name
        machine = self._default_machine(client_id)
        if machine is None:
            return self.primary
        f = self._focus_get(client_id) or {}
        return self._view_for(machine, f.get("kind") or PRIMARY_TARGET)

    def target_stamp(self, name: str = "") -> dict[str, Any] | None:
        """Best-effort {view, machine, computer_name, endpoint} block for
        envelope stamping â€” never raises; None when nothing resolves."""
        try:
            key = self.resolve_view_name(name)
        except Exception:
            return None
        if key not in self.clients:
            return None
        return {"view": key, **self.machine_label(key)}

    def stamp_needed(self, view_key: str) -> bool:
        """Minimal-envelope stamp policy: responses carry a bare
        ``target: '<machine>.<kind>'`` view key only when the answer could
        be attributed to the wrong box â€” more than one view is connected,
        or the view isn't the caller's focus machine. Single-view sessions
        cost zero stamp context. Full machine identity (trust/purpose/
        endpoints) is delivered once per machine on first connect
        (machine_info) and on demand via target_manage(action='machines')."""
        if len(self.clients) > 1:
            return True
        f = self._focus_get(current_client_id())
        if not f:
            return False
        return (f.get("machine") or "") != self.machine_of(view_key)
