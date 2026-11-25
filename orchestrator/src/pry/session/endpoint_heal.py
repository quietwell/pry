"""Endpoint self-heal mixin for :class:`.core.Session` (DHCP moves).

The lab VM gets a new address on most boots. Three cooperating pieces keep
a view attached to it without an LLM in the loop:

* **candidate sources** — the registry's fresh phone-home beacons and OS
  name resolution (``<alias>``, ``<alias>.local``) join the connect
  candidate list, ahead of stale remembered addresses;
* **identity check** — a host that answers as a *different* computer than
  the machine asked for is refused (a recycled lease must not attach the
  wrong box). A *learned* candidate (beacon / observed / name /
  last-good) is first asked the unauthenticated ``Agent.Identify`` — the
  agent token is only sent once its computer_name or boot epoch proves it
  is the expected machine; an old agent without Identify falls back to the
  token-bearing Status + HostInfo but must still prove a ``match``;
* **link watcher** — one task per connected view notices a dead channel
  and, when a verified fresh address exists, re-points the *same* client
  object at it (:meth:`AgentClient.rebind`), so every holder of the client
  keeps working.

Everything here is best-effort and never raises into a caller: a heal that
cannot prove identity simply does nothing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from ..endpoint_hints import (
    BEACON_FRESH_S,
    link_heal_enabled,
    looks_like_ip,
    name_resolution_enabled,
    resolve_name_hosts,
)
from ._errors import UnverifiedMachineError, WrongMachineError
from ._models import VIEW_KINDS

if TYPE_CHECKING:
    from ..agent_client import AgentClient
    from ..config import PryConfig

_log = logging.getLogger(__name__)

#: Candidate sources whose allowlist violation aborts the connect — the
#: operator typed them, or reviewed config lists them. Learned sources
#: (beacons, observations, name resolution) outside the allowlist are
#: skipped instead: machine-reported data must not be able to poison a
#: connect (a VM also reports its host-only / NAT adapter addresses).
STRICT_SOURCES = frozenset({"explicit", "configured", "alt_host"})


class SessionEndpointHealMixin:
    """Beacon / name candidates, identity verification, link failover."""

    # State owned by :class:`.core.Session.__init__`.
    cfg: PryConfig
    clients: dict[str, AgentClient]
    _boot_ids: dict[str, dict[str, Any]]
    _machine_info: dict[str, dict[str, Any]]
    _last_good_host: dict[str, str]
    pending_boot_notices: dict[str, dict[str, Any]]
    pending_endpoint_notices: dict[str, dict[str, Any]]
    _link_watchers: dict[str, asyncio.Task[None]]
    _registry_provider: Callable[[], Any] | None
    _link_heal_hook: Callable[..., Awaitable[None]] | None

    #: Seconds between link-health checks per view, consecutive failures
    #: before a failover is attempted, and the pause between attempts.
    LINK_WATCH_INTERVAL_S: float = 10.0
    LINK_FAIL_THRESHOLD: int = 3
    LINK_HEAL_COOLDOWN_S: float = 20.0
    LINK_HEAL_COOLDOWN_MAX_S: float = 120.0
    _FAILOVER_PROBE_S: float = 2.0

    if TYPE_CHECKING:
        _BOOT_EPOCH_JITTER_MS: int

        def check_target(self, host: str | None = None) -> str: ...
        def machine_of(self, view_name: str) -> str: ...
        def view_kind_of(self, view_name: str) -> str: ...
        def note_boot_identity(self, name: str,
                               status: dict[str, Any]) -> dict[str, Any] | None: ...
        def note_machine_identity(self, view_name: str, *,
                                  computer_name: str = "",
                                  endpoint: str = "",
                                  scan_service_version: int = 0,
                                  pointer_map_version: int = 0,
                                  dissect_version: int = 0) -> None: ...

    # ------------------------------------------------------------ wiring ----

    def set_registry_provider(self, fn: Callable[[], Any] | None) -> None:
        """Install a zero-arg callable returning the machine registry (or
        None while it is not loaded). A callable — not the registry — so the
        registry can stay lazily loaded. ``fn=None`` clears the hook."""
        self._registry_provider = fn

    def set_link_heal_hook(
            self, fn: Callable[..., Awaitable[None]] | None) -> None:
        """Install ``async fn(view, notice, boot_change)`` run after a view
        was re-pointed to a new endpoint (the Context sweeps orphaned
        state and records the observation there)."""
        self._link_heal_hook = fn

    def _reg(self) -> Any:
        fn = self._registry_provider
        if fn is None:
            return None
        try:
            return fn()
        except Exception:  # noqa: BLE001 — registry is optional for heal
            return None

    # --------------------------------------------- beacon / identity data ----

    def _fresh_beacon_hosts(self, label: str) -> list[str]:
        """Hosts *label*'s agent reported within :data:`BEACON_FRESH_S` —
        its current addresses, newest first."""
        reg = self._reg()
        if reg is None or not label or looks_like_ip(label):
            return []
        try:
            rows = reg.fresh_endpoints(label, BEACON_FRESH_S)
        except Exception:  # noqa: BLE001
            return []
        out: list[str] = []
        for r in rows:
            h = str(r.get("host") or "")
            if h and h not in out:
                out.append(h)
        return out

    def _beacon_overview(self, limit: int = 5) -> list[dict[str, Any]]:
        reg = self._reg()
        if reg is None:
            return []
        try:
            return list(reg.beacon_overview())[:limit]
        except Exception:  # noqa: BLE001
            return []

    def _expected_computer_name(self, label: str) -> str:
        """Who *label* is supposed to be: the registry's stored (operator-
        asserted or learned) name first, else what an earlier connect in
        this process learned for any view of that machine."""
        if not label:
            return ""
        reg = self._reg()
        if reg is not None:
            try:
                cn = reg.computer_name_for(label)
            except Exception:  # noqa: BLE001
                cn = ""
            if cn:
                return cn
        low = label.lower()
        for key, info in self._machine_info.items():
            if self.machine_of(key).lower() == low \
                    and info.get("computer_name"):
                return str(info["computer_name"])
        return ""

    def _guess_label_for_host(self, host: str, port: int) -> str:
        """Which known machine does *host* belong to? Lets a bare
        ``connect()`` whose legacy endpoint went stale find out whose
        beacons to follow. '' when unknown or ambiguous."""
        if not host:
            return ""
        try:
            g = self.cfg.machine_for_endpoint(host, port)
        except Exception:  # noqa: BLE001
            g = ""
        if g:
            return str(g)
        reg = self._reg()
        if reg is not None:
            try:
                return str(reg.alias_for_host(host) or "")
            except Exception:  # noqa: BLE001
                return ""
        return ""

    @staticmethod
    def _label_is_name(label: str) -> bool:
        """Could *label* itself be the machine's computer name? (Not an IP,
        not a bare view kind / the implicit 'default' machine.)"""
        lab = (label or "").strip().lower()
        return bool(lab) and not looks_like_ip(lab) \
            and lab not in VIEW_KINDS and lab != "default"

    def _identity_verdict(self, label: str, observed_name: str,
                          source: str) -> tuple[str, str]:
        """``(verdict, expected)`` — verdict is ``match`` / ``mismatch`` /
        ``unknown``. An operator-typed endpoint is trusted (re-imaged or
        renamed boxes stay reachable by an explicit ``host=``); anything
        else is checked when both names are known. A label that IS the
        observed computer name (``desktop-0qqhnkh`` vs ``DESKTOP-0QQHNKH``)
        counts as a match when nothing else is stored. ``unknown`` is
        accepted only for operator-supplied (configured/alt_host)
        candidates — learned ones must ``match``."""
        if source == "explicit":
            return "unknown", ""
        expected = self._expected_computer_name(label) if label else ""
        obs = (observed_name or "").strip().lower()
        if expected and obs:
            same = expected.strip().lower() == obs
            return ("match" if same else "mismatch"), expected
        if not expected and obs and self._label_is_name(label) \
                and obs == label.strip().lower():
            return "match", label
        return "unknown", expected

    def _same_boot(self, view_key: str, boot_epoch_ms: Any) -> bool:
        """The candidate reports the same OS boot this view was last seen
        on — a different box cannot share a boot epoch."""
        if not view_key:
            return False
        try:
            boot = int(boot_epoch_ms or 0)
        except (TypeError, ValueError):
            return False
        prev = int((self._boot_ids.get(view_key) or {}).get("boot_epoch_ms") or 0)
        return bool(boot and prev
                    and abs(boot - prev) <= self._BOOT_EPOCH_JITTER_MS)

    def _host_vouched(self, label: str, host: str, *,
                      exclude: str = "") -> bool:
        """Another (already verified) view of machine *label* is connected
        at *host*."""
        if not label or not host:
            return False
        for key, c in self.clients.items():
            if key == exclude or self.machine_of(key).lower() != label.lower():
                continue
            if str(getattr(c, "endpoint", "") or "").rpartition(":")[0] \
                    .strip("[]") == host:
                return True
        return False

    @staticmethod
    async def _identify(client: Any) -> dict[str, Any] | None:
        """Unauthenticated ``Agent.Identify`` (no token sent). None when the
        client or the agent predates it — callers then fall back to the
        token-bearing Status + HostInfo path. Transport errors raise."""
        fn = getattr(client, "identify", None)
        if not callable(fn):
            return None
        ident = await fn()
        return ident if isinstance(ident, dict) else None

    def _identify_verdict(self, label: str, ident: dict[str, Any],
                          host: str, view_key: str) -> tuple[str, str]:
        """Verdict for an ``Identify`` answer: computer_name against the
        stored/learned identity (or the label itself), else the boot epoch
        against this view's last boot, else a verified sibling view at the
        same address."""
        verdict, expected = self._identity_verdict(
            label, str(ident.get("computer_name") or ""), "identify")
        if verdict != "unknown":
            return verdict, expected
        if self._same_boot(view_key, ident.get("boot_epoch_ms")) \
                or self._host_vouched(label, host, exclude=view_key):
            return "match", expected
        return "unknown", expected

    async def _fetch_identity(self, client: Any) -> str:
        """computer_name via HostInfo ('' when the view cannot say — the
        umagent has no HostInfo, old agents predate it)."""
        try:
            hi = await client.host_info(include_hardware=False,
                                        include_security_products=False)
        except Exception:  # noqa: BLE001 — host_info is agent-version dependent
            return ""
        if isinstance(hi, dict) and hi.get("ok"):
            return str((hi.get("identity") or {}).get("computer_name") or "")
        return ""

    @staticmethod
    async def _quiet_close(client: Any) -> None:
        try:
            await client.close()
        except Exception:  # noqa: BLE001 — best-effort teardown
            pass

    def _allowed(self, host: str) -> bool:
        try:
            self.check_target(host)
        except Exception:  # noqa: BLE001 — TargetNotAllowed
            return False
        return True

    # ------------------------------------------------- connect candidates ----

    def _endpoint_candidates(self, *, label: str | None, cand_label: str,
                             host: str, explicit: bool,
                             t: Any) -> list[tuple[str, str]]:
        """Ordered ``(host, source)`` connect candidates: the operator's
        explicit host, the machine's fresh beacons, the configured host,
        the last host that worked, observed endpoints, then ``alt_hosts``.
        Beacons outrank the configured host because they are where the
        machine *says* it is right now; the configured one may be a
        months-old lease."""
        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        def add(h: Any, src: str) -> None:
            s = str(h or "").strip()
            if s and s not in seen:
                seen.add(s)
                out.append((s, src))

        if explicit:
            add(host, "explicit")
        for h in self._fresh_beacon_hosts(cand_label):
            add(h, "beacon")
        if not explicit:
            add(host, "configured")
        add(self._last_good_host.get(label or "", ""), "last_good")
        for h in self._observed_hosts_for(cand_label or ""):
            add(h, "observed")
        for h in (getattr(t, "alt_hosts", None) or []):
            add(h, "alt_host")
        return out

    async def _probe_winners(
            self, usable: list[tuple[str, str]], port: int,
            timeout_s: float) -> tuple[list[tuple[str, str]], Exception | None]:
        """TCP-probe every candidate concurrently. Returns the answering
        ``(host, source)`` pairs in priority order plus the first failure
        (the configured/explicit endpoint's, the most informative)."""
        from . import _probe_tcp  # late-bound: fixtures patch the package attr
        if not usable:
            return [], None

        async def _probe(h: str) -> Exception | None:
            try:
                await _probe_tcp(h, port, timeout_s=timeout_s)
            except OSError as exc:
                return exc
            return None

        if len(usable) == 1:
            exc = await _probe(usable[0][0])
            return ([] if exc is not None else [usable[0]]), exc
        results = await asyncio.gather(*(_probe(h) for h, _ in usable))
        winners = [usable[i] for i, e in enumerate(results) if e is None]
        first_err = next((e for e in results if e is not None), None)
        return winners, first_err

    async def _first_verified(
            self, winners: list[tuple[str, str]], *, label: str, port: int,
            token: str, t: Any, view_key: str = "",
    ) -> tuple[Any, dict[str, Any], str, str, str, list[Exception],
               Exception | None]:
        """Dial each answering host in priority order and return the first
        that is a working agent **and** the expected machine:
        ``(client, status, computer_name, source, host, mismatches,
        first_error)``. ``client`` is None when none qualified; then
        *mismatches* lists the hosts refused on identity and *first_error*
        the first transport/gRPC failure (re-raised by the caller, so
        single-candidate behavior is unchanged).

        Order of operations per candidate: open the channel (no
        call), ask the unauthenticated ``Identify`` (no token), refuse a
        mismatch — or, for a learned candidate, anything short of a proven
        match — and only then send the token (Status). Agents without
        Identify take the legacy token-bearing path, where learned
        candidates still need a proven match to be attached."""
        from . import AgentClient  # late-bound: fixtures patch the package attr
        mismatches: list[Exception] = []
        first_exc: Exception | None = None
        budget = max(5.0, (getattr(t, "connect_timeout_ms", 0) or 10000) / 1000.0)
        for cand_host, src in winners:
            learned = src not in STRICT_SOURCES
            c = AgentClient(cand_host, port, token, t.connect_timeout_ms,
                            max_inflight=t.max_inflight)
            ident: dict[str, Any] | None = None
            try:
                try:
                    await asyncio.wait_for(c.connect(), timeout=budget)
                except asyncio.TimeoutError:
                    # TCP answered but the gRPC channel never became ready
                    # (not an agent, or wedged): tag it so it classifies as
                    # a connect timeout instead of an opaque empty error.
                    raise OSError(
                        None, f"WSAETIMEDOUT grpc channel to {cand_host}:"
                              f"{port} not ready after {budget:.0f}s") from None
                if src != "explicit":
                    ident = await self._identify(c)
                if ident is not None:
                    verdict, expected = self._identify_verdict(
                        label, ident, cand_host, view_key)
                    refusal = self._refusal(
                        verdict, learned, host=cand_host, port=port,
                        label=label, expected=expected,
                        answered=str(ident.get("computer_name") or ""),
                        token_withheld=True)
                    if refusal is not None:
                        await self._quiet_close(c)
                        mismatches.append(refusal)
                        continue
                st = await c.status()
                cn = str((ident or {}).get("computer_name") or "") \
                    or await self._fetch_identity(c)
            except asyncio.CancelledError:
                await self._quiet_close(c)
                raise
            except Exception as exc:  # noqa: BLE001 — try the next candidate
                await self._quiet_close(c)
                if first_exc is None:
                    first_exc = exc
                continue
            if ident is None:
                verdict, expected = self._identity_verdict(label, cn, src)
                if verdict == "unknown" and learned and (
                        self._same_boot(view_key, st.get("boot_epoch_ms"))
                        or self._host_vouched(label, cand_host,
                                              exclude=view_key)):
                    verdict = "match"
                refusal = self._refusal(
                    verdict, learned, host=cand_host, port=port, label=label,
                    expected=expected, answered=cn, token_withheld=False)
                if refusal is not None:
                    await self._quiet_close(c)
                    mismatches.append(refusal)
                    continue
            return c, st, cn, src, cand_host, mismatches, first_exc
        return None, {}, "", "", "", mismatches, first_exc

    @staticmethod
    def _refusal(verdict: str, learned: bool, *, host: str, port: int,
                 label: str, expected: str, answered: str,
                 token_withheld: bool) -> Exception | None:
        """The identity error for a candidate, or None to accept it."""
        if verdict == "mismatch":
            return WrongMachineError(host=host, port=port, label=label,
                                     expected=expected, answered=answered)
        if learned and verdict != "match":
            return UnverifiedMachineError(host=host, port=port, label=label,
                                          answered=answered,
                                          token_withheld=token_withheld)
        return None

    async def _name_phase(
            self, cand_label: str, port: int, tried: set[str],
            timeout_s: float) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        """Last resort when no remembered/beaconed address answers: resolve
        the machine's *name* through the OS (mDNS/LLMNR/DNS) and probe what
        comes back. Returns ``(winners, info)``; *info* feeds the failure
        envelope. Skipped for IP labels, view kinds and when disabled."""
        info: dict[str, Any] = {"resolved": []}
        label = (cand_label or "").strip()
        if (not label or looks_like_ip(label)
                or label.lower() in VIEW_KINDS or label.lower() == "default"
                or not name_resolution_enabled()):
            return [], info
        names = [label, f"{label}.local"]
        cn = self._expected_computer_name(label)
        if cn and cn.lower() != label.lower():
            names += [cn, f"{cn}.local"]
        try:
            resolved = await resolve_name_hosts(names)
        except Exception:  # noqa: BLE001
            resolved = []
        info["resolved"] = resolved
        fresh = [(h, "name") for h in resolved
                 if h not in tried and self._allowed(h)]
        if not fresh:
            return [], info
        winners, _err = await self._probe_winners(fresh, port, timeout_s)
        return winners, info

    def _unreachable(self, probe_err: Exception | None, *, label: str,
                     cand_label: str, usable: list[tuple[str, str]],
                     name_info: dict[str, Any], explicit: bool) -> Exception:
        """The probe failure, annotated with what to try next. The original
        exception (and its message — the error classifier keys on the
        WSAExxxx tag in it) is preserved; ``endpoint_info`` rides along for
        the failure envelope."""
        err: Exception = probe_err or OSError("all endpoints unreachable")
        try:
            err.endpoint_info = {  # type: ignore[attr-defined]
                "label": cand_label or label or "",
                "explicit": explicit,
                "tried": [{"host": h, "source": s} for h, s in usable],
                "beacons": self._beacon_overview(),
                "name_resolution": name_info,
            }
        except Exception:  # noqa: BLE001 — never mask the real failure
            pass
        return err

    # ------------------------------------------------------ link watcher ----

    def start_link_watch(self, name: str, *, interval_s: float | None = None,
                         fail_threshold: int | None = None,
                         cooldown_s: float | None = None) -> bool:
        """Spawn (idempotently) the endpoint-failover watcher for a view.
        Returns False when disabled (``PRY_LINK_HEAL=0``), already
        running, or there is no running event loop."""
        if not link_heal_enabled():
            return False
        existing = self._link_watchers.get(name)
        if existing is not None and not existing.done():
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        from ..caller import spawn_background
        self._link_watchers[name] = spawn_background(
            self._link_watch_loop(
                name,
                float(interval_s if interval_s is not None
                      else self.LINK_WATCH_INTERVAL_S),
                int(fail_threshold if fail_threshold is not None
                    else self.LINK_FAIL_THRESHOLD),
                float(cooldown_s if cooldown_s is not None
                      else self.LINK_HEAL_COOLDOWN_S)),
            name=f"pry-linkwatch-{name}", owner="orchestrator:link_watch",
            loop=loop)
        return True

    def stop_link_watch(self, name: str | None = None) -> None:
        """Cancel the watcher for *name* (every view's when None)."""
        for n, task in list(self._link_watchers.items()):
            if name is None or n == name:
                task.cancel()
                self._link_watchers.pop(n, None)

    async def _link_watch_loop(self, name: str, interval_s: float,
                               threshold: int, cooldown_s: float) -> None:
        fails = 0
        retry_at = 0.0
        pause = cooldown_s
        while True:
            await asyncio.sleep(interval_s)
            client = self.clients.get(name)
            if client is None:
                # View gone; Session.connect() re-arms a watcher for it.
                return
            # Recent successful traffic (boot monitor, caller RPCs) already
            # proves the link — don't add a poll of our own.
            seen = float(getattr(client, "last_seen_ts", 0.0) or 0.0)
            if time.time() - seen < interval_s * 0.8:
                fails = 0
                continue
            try:
                await asyncio.wait_for(
                    client.status(), timeout=max(2.0, min(interval_s, 8.0)))
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — a dead link is the signal
                fails += 1
            else:
                fails = 0
                pause = cooldown_s
                continue
            if fails < threshold or time.monotonic() < retry_at:
                continue
            try:
                moved = await self._try_failover(name)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — healing must not die
                _log.debug("link failover for %s raised: %s", name, exc)
                moved = None
            if moved:
                fails = 0
                pause = cooldown_s
                retry_at = 0.0
            else:
                # Nothing to fail over to (machine off, no beacons): back
                # off instead of resolving names every cooldown forever.
                retry_at = time.monotonic() + pause
                pause = min(pause * 2.0, self.LINK_HEAL_COOLDOWN_MAX_S)

    def _sibling_vouches(self, name: str, label: str, host: str) -> bool:
        """Another view of the same machine is already connected at *host*
        — it was verified there by its own failover. This is how the umagent
        (``user``) view, which has no HostInfo and so cannot name itself,
        follows its kernel sibling even when the machine also rebooted."""
        for key, c in self.clients.items():
            if key == name or self.machine_of(key).lower() != label.lower():
                continue
            if str(getattr(c, "endpoint", "") or "").rpartition(":")[0] == host:
                return True
        return False

    def _failover_verdict(self, name: str, label: str, host: str,
                          status: dict[str, Any], observed_name: str) -> str:
        """``accept`` only with positive evidence it is the same machine:
        the same computer_name, the same OS boot (a different box cannot
        share a boot epoch), or a sibling view already verified at that
        address. An explicit name mismatch always rejects."""
        expected = self._expected_computer_name(label)
        name_ok = bool(expected and observed_name
                       and expected.lower() == observed_name.lower())
        name_bad = bool(expected and observed_name and not name_ok)
        if not expected and observed_name and self._label_is_name(label) \
                and observed_name.strip().lower() == label.strip().lower():
            name_ok = True
        prev = self._boot_ids.get(name) or {}
        boot = int(status.get("boot_epoch_ms") or 0)
        prev_boot = int(prev.get("boot_epoch_ms") or 0)
        same_boot = bool(
            boot and prev_boot
            and abs(boot - prev_boot) <= self._BOOT_EPOCH_JITTER_MS)
        if name_bad:
            return "mismatch"
        if name_ok or same_boot or self._sibling_vouches(name, label, host):
            return "accept"
        return "unproven"

    async def _try_failover(self, name: str) -> dict[str, Any] | None:
        """Find a verified new address for view *name* and re-point it.
        Returns the endpoint-moved notice, or None when nothing proved
        out. Never connects to anything it cannot identify."""
        from . import AgentClient, _probe_tcp  # late-bound for fixtures
        client = self.clients.get(name)
        if client is None:
            return None
        label = self.machine_of(name)
        cur_ep = str(getattr(client, "endpoint", "") or "")
        cur_host, _, port_s = cur_ep.rpartition(":")
        if not port_s.isdigit():
            return None
        port = int(port_s)
        cands = [(h, "beacon") for h in self._fresh_beacon_hosts(label)
                 if h != cur_host]
        if not cands:
            named, _info = await self._name_phase(
                label, port, {cur_host}, self._FAILOVER_PROBE_S)
            cands = [c for c in named if c[0] != cur_host]
        token = str(getattr(client, "token", "") or "")
        timeout_ms = int(getattr(client, "timeout_ms", 0) or 10000)
        for host, src in cands:
            if not self._allowed(host):
                continue
            try:
                await _probe_tcp(host, port, timeout_s=self._FAILOVER_PROBE_S)
            except OSError:
                continue
            probe = AgentClient(host, port, token, timeout_ms)
            try:
                budget = max(3.0, timeout_ms / 1000.0)
                await asyncio.wait_for(probe.connect(), timeout=budget)
                # prove identity BEFORE the token goes out.
                ident = await asyncio.wait_for(self._identify(probe),
                                               timeout=budget)
                if ident is not None:
                    pre = self._failover_verdict(
                        name, label, host,
                        {"boot_epoch_ms": ident.get("boot_epoch_ms")},
                        str(ident.get("computer_name") or ""))
                    if pre != "accept":
                        await self._quiet_close(probe)
                        _log.info("link failover %s: %s identified as %r — "
                                  "%s, skipped (token withheld)", name, host,
                                  ident.get("computer_name"), pre)
                        continue
                st = await asyncio.wait_for(probe.status(), timeout=budget)
                observed = str((ident or {}).get("computer_name") or "") \
                    or await self._fetch_identity(probe)
            except asyncio.CancelledError:
                await self._quiet_close(probe)
                raise
            except Exception:  # noqa: BLE001 — not (yet) a working agent
                await self._quiet_close(probe)
                continue
            await self._quiet_close(probe)
            verdict = self._failover_verdict(name, label, host, st, observed)
            if verdict != "accept":
                _log.info("link failover %s: %s answered as %r — %s, skipped",
                          name, host, observed, verdict)
                continue
            return await self._commit_failover(
                name, client, host, port, src, st, token, timeout_ms)
        return None

    async def _commit_failover(self, name: str, client: Any, host: str,
                               port: int, src: str, st: dict[str, Any],
                               token: str, timeout_ms: int) -> dict[str, Any]:
        from . import AgentClient
        old_ep = str(getattr(client, "endpoint", "") or "")
        rebind = getattr(client, "rebind", None)
        if callable(rebind):
            await rebind(host, port)
        else:  # duck-typed clients without rebind: swap the object instead
            new = AgentClient(host, port, token, timeout_ms)
            try:
                await asyncio.wait_for(new.connect(),
                                       timeout=max(5.0, timeout_ms / 1000.0))
            except BaseException:
                await self._quiet_close(new)
                raise
            apply = getattr(self, "_apply_client_policy", None)
            if callable(apply):
                apply(new)
            self.clients[name] = new
            await self._quiet_close(client)
        label = self.machine_of(name)
        self._last_good_host[label] = host
        self.note_machine_identity(
            name, endpoint=f"{host}:{port}",
            scan_service_version=int(st.get("scan_service_version") or 0),
            pointer_map_version=int(st.get("pointer_map_version") or 0),
            dissect_version=int(st.get("dissect_version") or 0))
        change = self.note_boot_identity(name, st)
        real = change if change and change.get("kind") in (
            "new_boot", "agent_restart") else None
        notice: dict[str, Any] = {
            "kind": "endpoint_moved", "view": name,
            "from": old_ep, "to": f"{host}:{port}", "source": src,
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if real is not None:
            notice["boot_change"] = real["kind"]
            self.pending_boot_notices[name] = {**real,
                                               "source": "link_watch"}
        self.pending_endpoint_notices[name] = notice
        _log.info("link failover: view %s moved %s -> %s:%s (%s)",
                  name, old_ep, host, port, src)
        hook = self._link_heal_hook
        if hook is not None:
            try:
                await hook(name, notice, real)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — hook is best-effort
                pass
        return notice
