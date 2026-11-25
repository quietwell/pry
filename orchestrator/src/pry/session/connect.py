"""Connect / disconnect / takeover mixin for :class:`.core.Session`.

Hosts the connect-time plumbing — endpoint-candidate ordering, TCP
pre-flight probe fan-out, machine-identity learning after HostInfo,
view-key assembly, and the shared / forced takeover semantics that
keep ``clients`` / ``owners`` / ``refs`` consistent across peers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..config import PRIMARY_TARGET
from ._models import VIEW_KINDS
from .endpoint_heal import STRICT_SOURCES

if TYPE_CHECKING:
    from ..agent_client import AgentClient
    from ..config import PryConfig

# NB: ``AgentClient`` and ``_probe_tcp`` are intentionally NOT imported at
# module scope. Pre-split callers monkey-patched ``pry.session.AgentClient``
# and ``pry.session._probe_tcp`` so the live connect path picked up the
# fake. Resolving these names through ``pry.session`` (the package) at
# call time preserves that fixture surface — the function-local
# ``from . import AgentClient, _probe_tcp`` re-reads whatever the package
# attribute currently points at.


class SessionConnectMixin:
    """Named-target connect/disconnect/takeover."""

    # State owned by :class:`.core.Session.__init__`.
    cfg: PryConfig
    clients: dict[str, AgentClient]
    owners: dict[str, str]
    refs: dict[str, dict[str, int]]
    primary: str
    _focus: dict[str, dict[str, str]]
    _last_good_host: dict[str, str]
    _legacy_label: dict[str, str]

    if TYPE_CHECKING:
        # Methods implemented on sibling mixins / core.Session.
        def check_target(self, host: str | None = None) -> str: ...
        async def check_target_async(self, host: str | None = None) -> str: ...
        def _set_focus_entry(self, client_id: str, machine: str,
                             kind: str) -> None: ...
        def _apply_client_policy(self, client: Any) -> None: ...
        def _observed_hosts_for(self, label: str) -> list[str]: ...
        def stop_boot_monitor(self, name: str | None = None) -> None: ...
        # endpoint_heal.SessionEndpointHealMixin
        def start_link_watch(self, name: str, **kw: Any) -> bool: ...
        def stop_link_watch(self, name: str | None = None) -> None: ...
        def _guess_label_for_host(self, host: str, port: int) -> str: ...
        def _endpoint_candidates(self, **kw: Any) -> list[tuple[str, str]]: ...
        async def _probe_winners(self, usable: Any, port: int,
                                 timeout_s: float) -> Any: ...
        async def _name_phase(self, cand_label: str, port: int,
                              tried: set[str], timeout_s: float) -> Any: ...
        async def _first_verified(self, winners: Any, **kw: Any) -> Any: ...
        def _unreachable(self, probe_err: Any, **kw: Any) -> Exception: ...
        def machine_of(self, view_name: str) -> str: ...
        def view_kind_of(self, view_name: str) -> str: ...
        def machine_label(self, view_name: str) -> dict[str, Any]: ...
        def _label_for_host(self, host: str) -> str: ...
        def _reg(self) -> Any: ...
        def note_boot_identity(self, name: str,
                               status: dict[str, Any]) -> dict[str, Any] | None: ...
        def note_machine_identity(self, view_name: str, *,
                                  computer_name: str = "",
                                  endpoint: str = "",
                                  scan_service_version: int = 0,
                                  pointer_map_version: int = 0,
                                  dissect_version: int = 0) -> None: ...

    def _canonical_machine_label(self, label: str) -> str:
        """The configured key a caller's machine *label* refers to: an exact
        key, else a case-insensitive key match, else the registry alias
        whose learned ``computer_name`` matches (so ``DESKTOP-ABC`` finds
        ``desktop-abc`` or ``lab2``). Unknown labels pass through unchanged
        and fail later with the usual no-endpoint error."""
        machines = getattr(self.cfg, "machines", None) or {}
        if label in machines:
            return label
        low = label.strip().lower()
        for key in machines:
            if str(key).lower() == low:
                return key
        try:
            reg = self._reg()
            alias = reg.find_alias_by_computer_name(label) if reg else None
        except Exception:  # noqa: BLE001 — resolution is best-effort
            alias = None
        if alias:
            for key in machines:
                if str(key).lower() == str(alias).lower():
                    return key
        return label

    def _connect_plan(self, name: str, machine: str | None,
                      host: str | None, port: int | None,
                      token: str | None) -> tuple[str | None, str, "Any"]:
        """Resolve connect args to ``(machine_label_or_None, view_kind,
        TargetConfig)``.

        ``machine='lab2'`` names the box; ``name='lab2.user'`` picks the
        view kind explicitly; bare view kinds ('kernel'/'user') leave the
        label to be learned post-connect (computer_name > config alias >
        host). Other bare names are machine aliases and imply the kernel
        view — ``connect(name='lab2')`` == ``connect(machine='lab2')``.

        Endpoint resolution never crosses machines: with an explicit label
        the endpoint must come from a machine-scoped config entry
        (``machines.lab2`` / ``targets['lab2.kernel']``), a sibling view's
        host (kind-port convention applies), or explicit host=/port= —
        falling back to the default ``target`` endpoint for a named other
        machine is exactly the wrong-machine bug this exists to prevent.
        """
        from ..config import TargetConfig
        requested = (name or "").strip()
        kind = requested.lower() if requested.lower() in VIEW_KINDS else PRIMARY_TARGET
        if machine:
            label: str | None = machine
            if "." in requested:
                kind = requested.rsplit(".", 1)[1]
        elif "." in requested:
            label, kind = requested.rsplit(".", 1)
        elif requested and requested.lower() not in VIEW_KINDS:
            label = requested
        else:
            label = None

        t = None
        if label is not None:
            label = self._canonical_machine_label(label)
            for cand in (f"{label}.{kind}", label):
                try:
                    t = self.cfg.target_for(cand)
                    break
                except KeyError:
                    continue
            if t is None:
                # Same-machine sibling views share a host; the kind's
                # conventional port (50099 kernel / 50075 user) applies
                # unless the caller passes port= explicitly.
                sib_host = ""
                for key, c in self.clients.items():
                    if self.machine_of(key) == label:
                        sib_host = (getattr(c, "endpoint", "") or "") \
                            .rsplit(":", 1)[0]
                        break
                eff_host = host or sib_host
                eff_port = port or (50099 if kind == "kernel" else 50075)
                if eff_host:
                    t = TargetConfig(host=eff_host, port=int(eff_port),
                                     token=token or "")
            if t is None:
                raise KeyError(
                    f"no endpoint known for {label}.{kind} — configure "
                    f"machines.{label} in the config or pass host=/port=")
            return label, kind, t
        for cand in (requested, kind):
            try:
                t = self.cfg.target_for(cand)
                break
            except KeyError:
                continue
        if t is None:
            if not host or not port:
                raise KeyError(
                    f"unknown or incomplete endpoint "
                    f"{requested or kind!r} — pass both host= and port= "
                    "or add it to machines:/targets: in the config")
            t = TargetConfig(host=host, port=int(port), token=token or "")
        return label, kind, t

    async def connect(self, host: str | None = None, port: int | None = None,
                      token: str | None = None, name: str = PRIMARY_TARGET,
                      machine: str | None = None,
                      owner: str | None = None, force: bool = False,
                      focus: bool = True) -> dict[str, Any]:
        """Connect (or attach to an already-connected) named view.

        Sharing semantics:
        - First connector becomes ``primary_owner``; refcount for that owner
          starts at 1.
        - A later connect(owner=same) simply bumps that owner's refcount and
          returns the live client's status with ``shared`` set when other
          owners are also attached.
        - A later connect(owner=different, force=False) attaches the new
          owner as a co-owner (refs[owner]=1); ``shared`` will be True.
        - force=True under a different owner tears the view down and
          rebuilds it (``forced_takeover=True`` in the envelope).

        The stored view key is ``'<machine>.<kind>'``. When the machine
        label can't be derived from the args it is learned post-connect
        (computer_name > config alias > host). If that key is already
        connected — e.g. connect(name='kernel') landing on an existing
        'DESKTOP-ABC.kernel' — the fresh channel is closed and the call
        attaches to the existing view instead of duplicating it.
        """
        # Late-bind ``AgentClient`` / ``_probe_tcp`` through the
        # ``pry.session`` package so tests that monkeypatch
        # ``pry.session.AgentClient`` or ``pry.session._probe_tcp``
        # drive this path — see module-top banner for the rationale.
        from . import AgentClient  # noqa: F401 — resolved late for fixtures
        explicit_host = bool(host)
        label, kind, t = self._connect_plan(name, machine, host, port, token)
        host = host or t.host
        port = port or t.port
        token = token if token is not None else t.token
        configured_host = host
        # Whose beacons / hostname to follow. A labelled connect follows its
        # own machine; a bare connect on the configured (legacy) endpoint
        # follows the machine that stale address belonged to. An operator-
        # typed host= is respected as typed — no guessing around it.
        cand_label = label or ""
        if not label and not explicit_host:
            cand_label = (self._guess_label_for_host(host, port)
                          or self._legacy_label.get(kind, ""))
        # DHCP self-heal: candidates in priority order — the
        # explicit host, the machine's fresh phone-home beacons, the
        # configured host, the last host that worked, observed endpoints,
        # then alt_hosts. Operator-supplied sources (explicit/configured/
        # alt_hosts) abort the connect on an allowlist violation; learned
        # ones (beacons, observations, names) outside it are skipped.
        # names are resolved once, off the event loop; EVERY
        # address must be allowed, and the checked IP literal is what gets
        # dialed (the resolver can't hand gRPC a different answer later).
        usable: list[tuple[str, str]] = []
        for cand_host, src in self._endpoint_candidates(
                label=label, cand_label=cand_label, host=host,
                explicit=explicit_host, t=t):
            try:
                ip = await self.check_target_async(cand_host)
            except Exception:  # noqa: BLE001 — TargetNotAllowed
                if src in STRICT_SOURCES:
                    raise
                continue
            if all(ip != u for u, _ in usable):
                usable.append((ip, src))
        if not usable:
            # Nothing configured anywhere: probe what we have so the caller
            # sees the real network error rather than an empty-list one.
            usable = [(await self.check_target_async(host), "configured")]
        probe_timeout_s = min(3.0, (t.connect_timeout_ms or 3000) / 1000.0)
        # every candidate's TCP SYN fires concurrently so
        # a dead endpoint doesn't block a live one by waiting out its full
        # timeout serially; winners keep their priority order.
        winners, probe_err = await self._probe_winners(
            usable, port, probe_timeout_s)
        name_info: dict[str, Any] = {}
        name_tried = False
        if not winners:
            # Nothing remembered or beaconed answered: ask the OS where the
            # machine's *name* lives (mDNS/LLMNR/DNS) before giving up.
            name_tried = True
            winners, name_info = await self._name_phase(
                cand_label, port, {h for h, _ in usable}, probe_timeout_s)
        if not winners:
            raise self._unreachable(
                probe_err, label=label or "", cand_label=cand_label,
                usable=usable, name_info=name_info, explicit=explicit_host)
        # _last_good_host is recorded only after the identity
        # check below accepted a candidate (a TCP answer proves nothing).
        host = winners[0][0]
        owner_id = owner or "anonymous"
        planned: str | None = f"{label}.{kind}" if label else None
        existing = self.clients.get(planned) if planned else None
        forced = False
        if existing is not None and planned is not None:
            primary_owner = self.owners.get(planned, owner_id)
            refs = self.refs.setdefault(planned, {})
            same_owner = (primary_owner == owner_id) or (owner is None)
            if force and not same_owner:
                # Tear down the existing session; a fresh entry is built
                # below owned by the forcing caller.
                await existing.close()
                self.clients.pop(planned, None)
                self.owners.pop(planned, None)
                self.refs.pop(planned, None)
                self.stop_boot_monitor(planned)
                forced = True
            else:
                # Either same owner (increment) or different owner without
                # force (add as co-owner). Before handing
                # back the live client, verify the channel. A cached attach
                # that answers status() means the view is live; a failure
                # means we're sitting on a stale/wedged client — tear it
                # down and fall through to the fresh-candidate connect so
                # callers like `machines_set` (which rewrote the endpoint)
                # don't get a stale attach.
                try:
                    status = await existing.status()
                except Exception:  # noqa: BLE001 - any channel failure is retryable
                    await existing.close()
                    self.clients.pop(planned, None)
                    self.owners.pop(planned, None)
                    self.refs.pop(planned, None)
                    self.stop_boot_monitor(planned)
                else:
                    refs[owner_id] = refs.get(owner_id, 0) + 1
                    status["shared"] = len(refs) > 1
                    status["primary_owner"] = primary_owner
                    status["view"] = planned
                    status["machine"] = self.machine_label(planned)["machine"]
                    change = self.note_boot_identity(planned, status)
                    if change:
                        status["boot_change"] = change
                    if focus and owner:
                        self._set_focus_entry(owner, self.machine_of(planned),
                                              self.view_kind_of(planned))
                    return status
        # pre-flight TCP probe. gRPC's `channel_ready()` wraps
        # OS-level socket errors in an opaque UNAVAILABLE StatusCode, so a
        # WSAECONNREFUSED / WSAETIMEDOUT bubbles up as a generic
        # "channel_unavailable" hint. Doing a plain socket connect first
        # surfaces the OS error rich enough for the net-layer classifiers
        # (`connect_blocked` / `connect_timeout` / `connect_refused` /
        # `host_unreachable` / `network_unreachable`) to fire, so the
        # caller gets an actionable next step instead of "channel is down".
        # (The probe ran above across the endpoint candidates.) Each
        # answering host is dialed in priority order and *identified*
        # before it is accepted: a recycled DHCP lease now held by a
        # different machine is refused instead of silently attached.
        exp_label = label or cand_label
        exp_view = f"{exp_label}.{kind}" if exp_label else ""
        (client, status, computer_name, chosen_src, host,
         mismatches, first_exc) = await self._first_verified(
            winners, label=exp_label, port=port, token=token, t=t,
            view_key=exp_view)
        if client is None and not name_tried:
            # Every remembered/beaconed answer was the wrong machine or not
            # a working agent — the machine's name may still lead to it.
            name_tried = True
            more, name_info = await self._name_phase(
                cand_label, port, {h for h, _ in usable}, probe_timeout_s)
            if more:
                (client, status, computer_name, chosen_src, host,
                 more_mismatch, more_exc) = await self._first_verified(
                    more, label=exp_label, port=port, token=token, t=t,
                    view_key=exp_view)
                mismatches += more_mismatch
                first_exc = first_exc or more_exc
        if client is None:
            if mismatches:
                raise mismatches[0]
            if first_exc is not None:
                raise first_exc
            raise self._unreachable(
                probe_err, label=label or "", cand_label=cand_label,
                usable=usable, name_info=name_info, explicit=explicit_host)
        self._last_good_host[label or ""] = host
        self._apply_client_policy(client)
        status["endpoint_source"] = chosen_src
        if len(usable) > 1 or chosen_src == "name":
            status["endpoint_fallback"] = {
                "configured": configured_host,
                "tried": [h for h, _ in usable],
                "used": host,
                "source": chosen_src,
            }
        # Machine identity: computer_name was learned by _first_verified
        # (best-effort) so the view key can carry it and later responses
        # can self-label.
        bare = label is None
        if label is None:
            label = (self.cfg.machine_for_endpoint(host, port)
                     or computer_name or self._label_for_host(host) or host)
        if bare:
            self._legacy_label[kind] = label
        key = f"{label}.{kind}"
        existing = self.clients.get(key)
        if existing is not None and existing is not client:
            # Another channel already serves this view (label learned
            # post-connect) — same owner/force semantics as the planned-
            # key path above: force under a different owner tears it down,
            # otherwise attach rather than keep a duplicate channel.
            primary_owner = self.owners.get(key, owner_id)
            same_owner = (primary_owner == owner_id) or (owner is None)
            if force and not same_owner:
                # The fresh channel becomes the replacement; tear down
                # the old one and fall through to the rebuild below.
                await existing.close()
                self.clients.pop(key, None)
                self.owners.pop(key, None)
                self.refs.pop(key, None)
                self.stop_boot_monitor(key)
                forced = True
            else:
                # same liveness check as the planned-key
                # attach path above — a wedged cached view takes the
                # fresh channel's place instead of returning stale state.
                try:
                    status = await existing.status()
                except Exception:  # noqa: BLE001
                    await existing.close()
                    self.clients.pop(key, None)
                    self.owners.pop(key, None)
                    self.refs.pop(key, None)
                    self.stop_boot_monitor(key)
                else:
                    await client.close()
                    refs = self.refs.setdefault(key, {})
                    refs[owner_id] = refs.get(owner_id, 0) + 1
                    status["shared"] = len(refs) > 1
                    status["primary_owner"] = self.owners.get(key, owner_id)
                    status["view"] = key
                    status["machine"] = self.machine_label(key)["machine"]
                    if focus and owner:
                        self._set_focus_entry(owner, self.machine_of(key),
                                              self.view_kind_of(key))
                    return status
        self.clients[key] = client
        self.owners[key] = owner_id
        self.refs[key] = {owner_id: 1}
        self.note_machine_identity(
            key, computer_name=computer_name,
            endpoint=f"{host}:{port}",
            scan_service_version=int(status.get("scan_service_version") or 0),
            pointer_map_version=int(status.get("pointer_map_version") or 0),
            dissect_version=int(status.get("dissect_version") or 0))
        # DHCP self-heal: keep an eye on this view's link so a machine that
        # moves to a new address is re-found without anyone's help.
        self.start_link_watch(key)
        if forced:
            status["forced_takeover"] = True
        status["shared"] = False
        status["primary_owner"] = owner_id
        status["view"] = key
        status["machine"] = label
        if computer_name:
            status["computer_name"] = computer_name
        if self.primary not in self.clients:
            self.primary = key
        # connect auto-focuses the caller on the newly
        # connected view by default (focus=True). Prior behavior
        # ("first connect only") was a footgun — a caller that connected
        # a second machine then issued a bare-name call would land on
        # the first box without warning. focus=False preserves the
        # historical no-op case for callers that manage focus themselves.
        if owner and (focus or owner not in self._focus):
            self._set_focus_entry(owner, label, kind)
        # v14: a forced/fresh connect after a reboot still carries the old
        # view's boot record — flag the epoch change so callers know prior
        # shells/follows/handles were orphaned even though the channel is
        # brand new.
        change = self.note_boot_identity(key, status)
        if change:
            status["boot_change"] = change
        return status

    def drop_view_ref(self, name: str, owner: str) -> bool:
        """remove one owner's ref on a named view WITHOUT closing the
        client. driver_unload uses this to prune refs the ClientRegistry
        says are stale (crashed peer, release_peer leftover) so the
        session-ledger and the peer dashboard stop disagreeing. Returns
        True when a ref was actually dropped."""
        refs = self.refs.get(name)
        if not refs or owner not in refs:
            return False
        refs[owner] -= 1
        if refs[owner] <= 0:
            refs.pop(owner, None)
        return True

    async def disconnect(self, name: str | None = None,
                         owner: str | None = None) -> dict[str, Any]:
        """Release a named target.

        - ``owner=None`` preserves the historical all-close behavior used by
          the process-shutdown path: every named client is closed and its
          ref bookkeeping cleared.
        - ``owner`` given: decrement that owner's refcount on the named
          entry (or every entry when ``name`` is None). The underlying
          client is only closed when every owner has released it.

        Returns ``disconnected`` (names actually torn down) and, when
        owner-scoped, ``partial_release`` (names whose refcount merely
        decremented).
        """
        if owner is None:
            names = [name] if name else list(self.clients)
            for n in names:
                client = self.clients.pop(n, None)
                self.owners.pop(n, None)
                self.refs.pop(n, None)
                self.stop_boot_monitor(n)
                self.stop_link_watch(n)
                if client is not None:
                    await client.close()
            self._repoint_primary()
            return {"ok": True, "disconnected": names}
        targets = [name] if name else list(self.clients)
        closed: list[str] = []
        partial: list[str] = []
        for n in targets:
            refs = self.refs.get(n)
            if refs is None:
                continue
            if owner in refs:
                refs[owner] -= 1
                if refs[owner] <= 0:
                    refs.pop(owner, None)
            if not refs:
                client = self.clients.pop(n, None)
                self.owners.pop(n, None)
                self.refs.pop(n, None)
                self.stop_boot_monitor(n)
                self.stop_link_watch(n)
                if client is not None:
                    await client.close()
                closed.append(n)
            else:
                partial.append(n)
        self._repoint_primary()
        return {"ok": True, "disconnected": closed, "partial_release": partial}

    def _repoint_primary(self) -> None:
        """Keep ``self.primary`` pointing at a live view — prefer a
        '<machine>.kernel' key, else the alphabetically-first view."""
        if self.primary in self.clients:
            return
        for key in sorted(self.clients):
            if self.view_kind_of(key) == PRIMARY_TARGET:
                self.primary = key
                return
        self.primary = next(iter(sorted(self.clients)), PRIMARY_TARGET)

    async def release_by_owner(self, owner: str) -> list[str]:
        """Drop every reference held by ``owner`` and close any entry whose
        refcount thereby reaches zero. Intended for the client-reap path
        when a caller disappears; returns the list of names actually closed.
        The caller is responsible for publishing / logging as needed.
        """
        released: list[str] = []
        self._focus.pop(owner, None)
        for n in list(self.clients):
            refs = self.refs.get(n)
            if refs is None or owner not in refs:
                continue
            refs.pop(owner, None)
            if not refs:
                client = self.clients.pop(n, None)
                self.owners.pop(n, None)
                self.refs.pop(n, None)
                self.stop_boot_monitor(n)
                self.stop_link_watch(n)
                if client is not None:
                    await client.close()
                released.append(n)
        self._repoint_primary()
        return released
