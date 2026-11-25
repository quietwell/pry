"""Persistent machine registry — purpose / note / trust metadata + endpoint
credentials for target machines.

``artifacts/targets.json`` stores machine entries so boxes can be added at
runtime (``target_manage(action='machines_register')``) without editing the
YAML config or restarting the orchestrator. YAML ``machines:`` stays the
reviewed, committed config; the registry is the runtime layer:

- registry-owned aliases (not in YAML) carry full endpoint/credential data
  and merge into ``cfg.machines`` at load and at register time, so
  ``Session`` view resolution works unchanged;
- YAML aliases can only receive *metadata* overlays (purpose/note/trust/
  tags/operator) — endpoints and tokens of reviewed config are never
  overridden unless ``force=True`` (explicit shadow);
- the reserved alias ``default`` annotates the implicit primary machine
  (the YAML ``target:`` block, which has no alias of its own).

Tokens may be stored as ``${ENV_VAR}`` and are expanded with
``os.path.expandvars`` when merged into config. They are NEVER echoed in
any response (``token_set: true`` instead).
"""

from __future__ import annotations

import copy
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

from .config import TRUST_LEVELS, MachineConfig, PryConfig
from .endpoint_hints import BEACON_FRESH_S, age_s, seen_epoch

REGISTRY_FILENAME = "targets.json"
REGISTRY_VERSION = 1
DEFAULT_ALIAS = "default"

_METADATA_FIELDS = ("trust", "purpose", "note", "operator", "tags")

# observed-endpoint cap per machine (newest first). Keeps
# the registry file small when a box flaps endpoints across sessions.
_OBSERVED_ENDPOINT_CAP = 8

_log = logging.getLogger(__name__)


class RegistryReadOnly(ValueError):
    """The registry file could not be parsed at load, so this process will
    not overwrite it (a parse error used to start an empty registry that the
    next beacon then saved over the operator's machines). Subclasses
    ``ValueError`` so the dashboard / tool paths answer 400 with the reason."""


def _norm_trust(value: Any) -> str:
    v = str(value or "").strip().lower()
    return v if v in TRUST_LEVELS else "untrusted"


def _validate_alias(alias: str) -> str:
    a = str(alias or "").strip()
    if not a:
        raise ValueError("machine alias must be non-empty")
    if any(c.isspace() for c in a):
        raise ValueError(f"machine alias {a!r} must not contain whitespace")
    if len(a) > 64:
        raise ValueError(f"machine alias {a!r} too long (max 64)")
    return a


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _clone_machine(m: MachineConfig) -> MachineConfig:
    return copy.deepcopy(m)


class MachineRegistry:
    """Read/write layer over ``artifacts/targets.json`` + the YAML config."""

    def __init__(self, cfg: PryConfig, path: Path) -> None:
        self.cfg = cfg
        self.path = Path(path)
        # alias (lowercased) -> raw entry dict as persisted
        self._entries: dict[str, dict[str, Any]] = {}
        # aliases defined by the reviewed YAML config (never silently
        # shadowed by registry endpoint/credential data)
        self._yaml_aliases = {str(a).lower() for a in (cfg.machines or {})}
        # pristine YAML MachineConfigs — restoring one after a force-shadow
        # is removed (registry mutations happen on merged copies otherwise)
        self._yaml_snapshot: dict[str, MachineConfig] = {
            str(a): _clone_machine(m) for a, m in (cfg.machines or {}).items()}
        # set when targets.json existed but failed to parse — every
        # save is then refused so the operator's file survives for repair.
        self.read_only_reason: str = ""

    @property
    def read_only(self) -> bool:
        return bool(self.read_only_reason)

    def _check_writable(self) -> None:
        """Operator writes are refused up front (before any in-memory
        change) while the registry is read-only. Passive observations
        (beacons, connects) still update memory so the DHCP self-heal
        keeps working; they are just never saved."""
        if self.read_only_reason:
            raise RegistryReadOnly(self.read_only_reason)

    @property
    def backup_path(self) -> Path:
        return self.path.with_name(self.path.name + ".bak")

    # ------------------------------------------------------------ loading ----

    @classmethod
    def load(cls, cfg: PryConfig) -> "MachineRegistry":
        """Load the registry file (missing = empty) and merge it into
        ``cfg.machines`` so view resolution works unchanged."""
        try:
            base = Path(cfg.artifacts_dir())
        except Exception:
            base = Path("artifacts")
        reg = cls(cfg, base / REGISTRY_FILENAME)
        reg._read()
        reg.merge_into_cfg()
        return reg

    @staticmethod
    def _parse(text: str) -> dict[str, dict[str, Any]]:
        raw = json.loads(text)
        if not isinstance(raw, dict):
            raise ValueError("registry root is not a JSON object")
        machines = raw.get("machines", {})
        if not isinstance(machines, dict):
            raise ValueError("registry 'machines' is not a JSON object")
        return {str(a).lower(): dict(e) for a, e in machines.items()
                if isinstance(e, dict)}

    def _read(self) -> None:
        """Load targets.json. A missing file is an empty registry; a file
        that exists but cannot be read/parsed flips the registry read-only
        (logged loudly) instead of silently starting empty — the previous
        good copy (``targets.json.bak``) is loaded into memory when it
        parses, so connects keep their machines, but nothing is written
        until the operator repairs the file and restarts."""
        main_exists = self.path.is_file()
        if not main_exists and not self.backup_path.is_file():
            return
        if main_exists:
            try:
                self._entries.update(
                    self._parse(self.path.read_text(encoding="utf-8")))
                return
            except (OSError, ValueError) as exc:
                self.read_only_reason = (
                    f"{self.path} failed to parse ({exc}); registry is "
                    "read-only for this process — fix or remove the file "
                    "and restart the orchestrator")
                _log.error("machine registry: %s", self.read_only_reason)
        # Main file corrupt (or missing after a crash mid-replace): fall
        # back to the previous good copy, in memory only.
        try:
            self._entries.update(
                self._parse(self.backup_path.read_text(encoding="utf-8")))
            _log.warning("machine registry: loaded %d entries from %s",
                         len(self._entries), self.backup_path)
        except (OSError, ValueError) as exc:
            if main_exists:
                _log.error("machine registry: backup %s unusable too: %s",
                           self.backup_path, exc)

    def _save(self) -> None:
        """Atomic write: temp file in the same directory, fsync, keep the
        previous version as ``targets.json.bak``, then ``os.replace``.
        Refused (RegistryReadOnly) after a load-time parse failure."""
        if self.read_only_reason:
            raise RegistryReadOnly(self.read_only_reason)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": REGISTRY_VERSION,
                   "machines": {a: e for a, e in sorted(self._entries.items())}}
        data = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        tmp = self.path.with_name(f"{self.path.name}.tmp-{os.getpid()}")
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(data)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            if self.path.is_file():
                try:
                    shutil.copy2(self.path, self.backup_path)
                except OSError as exc:  # a stale .bak is better than no save
                    _log.debug("machine registry: .bak copy failed: %s", exc)
            last: OSError | None = None
            for _ in range(5):
                try:
                    os.replace(tmp, self.path)
                    last = None
                    break
                except PermissionError as exc:  # AV / indexer holds it briefly
                    last = exc
                    time.sleep(0.05)
            if last is not None:
                raise last
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------- config ----

    def merge_into_cfg(self) -> None:
        """Fold registry entries into ``cfg.machines``.

        Registry-owned aliases become full MachineConfig entries (tokens
        env-expanded). YAML aliases get metadata overlays only — endpoint
        fields land there solely for entries registered with force=True
        (explicit shadow)."""
        for lower, ent in self._entries.items():
            alias = str(ent.get("alias") or lower)
            mcfg = self._find_machine(alias)
            is_yaml = lower in self._yaml_aliases
            if is_yaml:
                if mcfg is None:
                    continue
                self._apply_metadata(mcfg, ent)
                if ent.get("shadow"):
                    self._apply_endpoints(mcfg, ent)
                continue
            if mcfg is None:
                mcfg = MachineConfig()
                self.cfg.machines[alias] = mcfg
            self._apply_metadata(mcfg, ent)
            self._apply_endpoints(mcfg, ent)

    def _find_machine(self, alias: str) -> MachineConfig | None:
        machines = getattr(self.cfg, "machines", None) or {}
        if alias in machines:
            return machines[alias]
        low = str(alias).lower()
        for a, m in machines.items():
            if str(a).lower() == low:
                return m
        return None

    @staticmethod
    def _apply_metadata(mcfg: MachineConfig, ent: dict[str, Any]) -> None:
        # Presence-based, not truthiness: an explicit "" / [] in the entry
        # CLEARS the field (the dashboard edit form sends present-but-empty
        # to blank out a note); absent keys leave the config value alone.
        for f in _METADATA_FIELDS:
            if f in ent:
                val = ent[f]
                if val not in (None, "", []):
                    setattr(mcfg, f, ent[f])
                else:
                    setattr(mcfg, f, [] if f == "tags" else "")

    @staticmethod
    def _apply_endpoints(mcfg: MachineConfig, ent: dict[str, Any]) -> None:
        if ent.get("host"):
            mcfg.host = os.path.expandvars(str(ent["host"]))
        if ent.get("token"):
            mcfg.token = os.path.expandvars(str(ent["token"]))
        if ent.get("kernel_port"):
            mcfg.kernel_port = int(ent["kernel_port"])
            mcfg.views.pop("kernel", None)
        if ent.get("user_port"):
            mcfg.user_port = int(ent["user_port"])
            mcfg.views.pop("user", None)
        # alt_hosts on the registry entry feeds the probe set used
        # by wait_agent / rediscover. MachineConfig already carries the
        # field for YAML-side configuration; mirror it here so a registered
        # machine with alt_hosts behaves the same across both sources.
        alt = ent.get("alt_hosts")
        if isinstance(alt, list) and alt:
            mcfg.alt_hosts = [str(h) for h in alt if str(h).strip()]

    # ------------------------------------------------------------ writing ----

    def register(self, alias: str, *, host: str = "", kernel_port: int = 0,
                 user_port: int = 0, token: str = "", trust: str = "",
                 purpose: str = "", note: str = "", operator: str = "",
                 tags: list[str] | None = None,
                 computer_name: str = "",
                 alt_hosts: list[str] | None = None,
                 force: bool = False) -> dict[str, Any]:
        """Add (or replace) a machine entry. Refuses to shadow a YAML
        alias's endpoints/credentials unless ``force=True``.

        ``computer_name`` is the Windows NetBIOS name the agent
        reports in its phone-home beacon; stored on the entry so an
        incoming beacon labelled ``DESKTOP-ABC`` resolves to the
        operator's alias ``lab2`` instead of minting a split-brain shell.
        ``alt_hosts`` seeds the probe set used by wait_agent / rediscover
        when the machine's primary endpoint stops answering (DHCP flap,
        NIC change)."""
        self._check_writable()
        alias = _validate_alias(alias)
        lower = alias.lower()
        has_endpoints = bool(host or kernel_port or user_port or token)
        if lower == DEFAULT_ALIAS and has_endpoints:
            raise ValueError(
                "'default' annotates the implicit primary machine — "
                "metadata only (endpoints come from the YAML target: block)")
        shadow = False
        if lower in self._yaml_aliases and has_endpoints:
            if not force:
                raise ValueError(
                    f"machine {alias!r} is defined by the reviewed YAML "
                    "config — metadata only without force=true")
            shadow = True
        entry: dict[str, Any] = {
            "alias": alias,
            "trust": _norm_trust(trust),
            "purpose": str(purpose or ""),
            "note": str(note or ""),
            "operator": str(operator or ""),
            "tags": [str(t) for t in (tags or []) if str(t).strip()],
            "registered_at": _now(),
        }
        if shadow:
            entry["shadow"] = True
        vals = {"host": host, "kernel_port": kernel_port,
                "user_port": user_port, "token": token}
        for k, v in vals.items():
            if v:
                entry[k] = v
        cn = str(computer_name or "").strip()
        if cn:
            entry["computer_name"] = cn
        ah = [str(h).strip() for h in (alt_hosts or []) if str(h).strip()]
        if ah:
            entry["alt_hosts"] = ah
        self._entries[lower] = entry
        self._save()
        self.merge_into_cfg()
        desc = self.describe(alias)
        assert desc is not None  # alias was validated non-empty above
        return desc

    def set(self, alias: str, *, host: str | None = None,
            kernel_port: int | None = None, user_port: int | None = None,
            token: str | None = None, trust: str | None = None,
            purpose: str | None = None, note: str | None = None,
            operator: str | None = None, tags: list[str] | None = None,
            computer_name: str | None = None,
            alt_hosts: list[str] | None = None,
            force: bool = False) -> dict[str, Any]:
        """Partial update. YAML aliases accept metadata fields only
        (endpoint/credential fields need ``force=True``).
        ``computer_name`` and ``alt_hosts`` are hints only — never
        counted as endpoint writes, so a YAML alias accepts them
        without ``force=True``."""
        self._check_writable()
        alias = _validate_alias(alias)
        lower = alias.lower()
        ent = dict(self._entries.get(lower) or {"alias": alias})
        endpoint_wanted = any(
            v not in (None, "", 0) for v in (host, kernel_port, user_port, token))
        if lower == DEFAULT_ALIAS and endpoint_wanted:
            raise ValueError(
                "'default' annotates the implicit primary machine — "
                "metadata only")
        if lower in self._yaml_aliases and endpoint_wanted and not force:
            raise ValueError(
                f"machine {alias!r} is defined by the reviewed YAML "
                "config — metadata only without force=true")
        for k, v in (("host", host), ("token", token),
                     ("kernel_port", kernel_port), ("user_port", user_port)):
            if v not in (None, "", 0):
                ent[k] = v
        for k, v in (("trust", _norm_trust(trust) if trust is not None else None),
                     ("purpose", purpose), ("note", note), ("operator", operator)):
            if v is not None:
                ent[k] = v
        if tags is not None:
            ent["tags"] = [str(t) for t in tags if str(t).strip()]
        if computer_name is not None:
            cn = str(computer_name).strip()
            if cn:
                ent["computer_name"] = cn
            else:
                ent.pop("computer_name", None)
        if alt_hosts is not None:
            ah = [str(h).strip() for h in alt_hosts if str(h).strip()]
            if ah:
                ent["alt_hosts"] = ah
            else:
                ent.pop("alt_hosts", None)
        if lower in self._yaml_aliases and endpoint_wanted:
            ent["shadow"] = True
        ent.setdefault("registered_at", _now())
        ent["alias"] = alias
        # An operator edit claims a beacon-minted entry: it no longer
        # counts against the beacon creation cap.
        ent.pop("origin", None)
        self._entries[lower] = ent
        self._save()
        self.merge_into_cfg()
        desc = self.describe(alias)
        assert desc is not None  # alias was validated non-empty above
        return desc

    def unregister(self, alias: str, force: bool = False) -> bool:
        """Drop a registry entry. YAML aliases keep their endpoints (they
        live in the YAML file) — only the metadata overlay is removed;
        a force-registered shadow needs ``force=True`` to remove."""
        self._check_writable()
        alias = _validate_alias(alias)
        lower = alias.lower()
        if lower not in self._entries:
            return False
        ent = self._entries[lower]
        if lower in self._yaml_aliases:
            if ent.get("shadow") and not force:
                raise ValueError(
                    f"machine {alias!r} shadows the YAML config — "
                    "force=true to remove the shadow")
            self._entries.pop(lower, None)
            if ent.get("shadow"):
                # restore the pristine reviewed-config MachineConfig
                snap = next((s for a, s in self._yaml_snapshot.items()
                             if str(a).lower() == lower), None)
                if snap is not None:
                    machines = getattr(self.cfg, "machines", None) or {}
                    for a in [a for a in machines if str(a).lower() == lower]:
                        machines[a] = _clone_machine(snap)
            else:
                mcfg = self._find_machine(alias)
                if mcfg is not None:
                    for f in _METADATA_FIELDS:
                        setattr(mcfg, f, [] if f == "tags" else "")
            self._save()
            return True
        self._entries.pop(lower, None)
        machines = getattr(self.cfg, "machines", None)
        if isinstance(machines, dict):
            for a in [a for a in machines if str(a).lower() == lower]:
                machines.pop(a, None)
        self._save()
        return True

    def find_alias_by_computer_name(self, name: str) -> str | None:
        """reverse-lookup for phone-home. Returns the registry
        alias whose stored ``computer_name`` matches *name*
        (case-insensitive), or ``None`` when no entry claims it. Used by
        the ``agent_report`` route so a beacon that lands under its
        NetBIOS label (``DESKTOP-ABC``) is attributed to the operator's
        alias (``lab2``) instead of minting a split-brain shell."""
        wanted = str(name or "").strip().lower()
        if not wanted:
            return None
        for lower, ent in self._entries.items():
            cn = str(ent.get("computer_name") or "").strip().lower()
            if cn and cn == wanted:
                return str(ent.get("alias") or lower)
        return None

    # ----------------------------------------------- observed endpoints ----

    def beacon_minted_count(self) -> int:
        """Registry entries minted by the agent beacon (``origin=beacon``)
        and never claimed by the operator since — what the beacon cap
        (``mcp.beacon_max_new_machines``) counts."""
        return sum(1 for e in self._entries.values()
                   if e.get("origin") == "beacon")

    def is_known_label(self, alias: str, computer_name: str = "") -> bool:
        """Would :meth:`record_observed_endpoint` attribute *alias* to an
        existing machine (registry, YAML, or a stored computer_name)?"""
        a = str(alias or "").strip()
        if not a:
            return False
        if a.lower() in self._entries or self._find_machine(a) is not None:
            return True
        return bool(self.find_alias_by_computer_name(computer_name)
                    or self.find_alias_by_computer_name(a))

    def record_observed_endpoints(self, alias: str, *, hosts: list[str],
                                  port: int, boot_epoch_ms: int = 0,
                                  allow_create: bool = False,
                                  fallback_computer_name: str = "",
                                  origin: str = "") -> bool:
        """Record several hosts for one machine with a single file write
        (the beacon carries every IPv4 of the box at once). Same rules as
        :meth:`record_observed_endpoint`; ``origin`` tags a freshly minted
        entry (``beacon``) so the beacon creation cap can count it."""
        recorded = False
        minted = False
        for h in hosts:
            known_before = self.is_known_label(alias, fallback_computer_name)
            ok = self.record_observed_endpoint(
                alias, host=h, port=port, boot_epoch_ms=boot_epoch_ms,
                allow_create=allow_create,
                fallback_computer_name=fallback_computer_name, save=False)
            recorded = recorded or ok
            minted = minted or (ok and not known_before)
        if minted and origin:
            ent = self._entries.get(str(alias).strip().lower())
            if ent is not None:
                ent.setdefault("origin", origin)
        if recorded:
            try:
                self._save()
            except Exception as exc:  # noqa: BLE001 — never mask the caller
                _log.debug("machine registry: save failed: %s", exc)
        return recorded

    def record_observed_endpoint(self, alias: str, *, host: str, port: int,
                                 boot_epoch_ms: int = 0,
                                 allow_create: bool = False,
                                 fallback_computer_name: str = "",
                                 save: bool = True) -> bool:
        """note that *host:port* answered a gRPC connect
        for the machine *alias*. The newest observation shows first; the
        list is capped at :data:`_OBSERVED_ENDPOINT_CAP` entries. YAML
        aliases participate too (no shadow needed) — this is pure learned
        metadata, never a replacement for reviewed endpoints.

        PR#8: ``allow_create`` gates implicit shell creation. The default
        (``False``) refuses to mint a brand-new entry for an unknown
        alias — passive-discovery call sites (``rediscover`` scans, post-
        failure CIDR auto-expand) use that to avoid littering the
        registry with alias-only shells. Set ``True`` on paths where the
        operator is explicitly minting an alias (``connect`` /
        ``reconnect`` with a user-supplied ``machine=``). Returns
        ``True`` when the observation was recorded, ``False`` when it
        was dropped (empty args, or unknown alias with
        ``allow_create=False``).

        ``fallback_computer_name`` resolves the phone-home
        split-brain. When set and ``alias`` is unknown, the registry
        looks for an entry whose stored ``computer_name`` matches and
        records the observation under THAT alias instead of minting
        a shell labelled with the beacon's NetBIOS name. Only after
        both the direct and reverse lookup miss does ``allow_create``
        gate the final shell-minting step.
        """
        if not alias or not host or not port:
            return False
        alias = str(alias).strip()
        lower = alias.lower()
        if not lower:
            return False
        known = (lower in self._entries) or (self._find_machine(alias) is not None)
        if not known:
            # before the allow_create shell-mint, try to attribute
            # the beacon to a registered alias via its stored
            # computer_name. Hostname is stable across NIC/MAC flaps while
            # the operator-chosen alias is what every other tool keys on.
            resolved = self.find_alias_by_computer_name(fallback_computer_name)
            if resolved is None:
                resolved = self.find_alias_by_computer_name(alias)
            if resolved is not None:
                alias = resolved
                lower = alias.lower()
                known = True
        if not known and not allow_create:
            # PR#8: don't mint an alias-only shell behind the operator's
            # back from a passive-discovery probe.
            return False
        ent = dict(self._entries.get(lower) or {"alias": alias})
        existing = list(ent.get("observed_endpoints") or [])
        tag = f"{host}:{int(port)}"
        # Drop any earlier observation of the same endpoint before pushing
        # the fresh one on top (newest-first); de-dup on host:port.
        existing = [o for o in existing
                    if isinstance(o, dict)
                    and f"{o.get('host')}:{int(o.get('port') or 0)}" != tag]
        new_entry: dict[str, Any] = {
            "host": str(host),
            "port": int(port),
            "seen_at": _now(),
        }
        if boot_epoch_ms:
            new_entry["boot_epoch_ms"] = int(boot_epoch_ms)
        existing.insert(0, new_entry)
        del existing[_OBSERVED_ENDPOINT_CAP:]
        ent["observed_endpoints"] = existing
        ent.setdefault("alias", alias)
        self._entries[lower] = ent
        if save:
            try:
                self._save()
            except Exception:  # noqa: BLE001 — never mask the connect that recorded it
                pass
        return True

    def observed_endpoints(self, alias: str) -> list[dict[str, Any]]:
        """Observed endpoints for *alias*, newest-first. Empty list when
        nothing has been recorded."""
        ent = self._entries.get(str(alias or "").strip().lower()) or {}
        rows = ent.get("observed_endpoints") or []
        return [dict(r) for r in rows if isinstance(r, dict)]

    # ------------------------------------------- beacons / identity (DHCP) ----
    #
    # The agent's phone-home beacon lands in ``observed_endpoints`` every
    # ~30 s, so an entry seen a few seconds ago is the machine's *current*
    # address. Everything below reads that data; none of it writes except
    # ``learn_computer_name``.

    def _is_shell(self, lower: str, ent: dict[str, Any]) -> bool:
        """An alias-only shell: not YAML-defined and carrying no operator
        data. Passive probes and beacons for an unknown label mint these
        (``192.168.2.71``, ``desktop-0qqhnkh-recovery``); they never name a
        real machine, so identity lookups skip them."""
        if lower in self._yaml_aliases:
            return False
        return not any(ent.get(k) for k in (
            "host", "trust", "purpose", "note", "operator", "tags",
            "token", "computer_name"))

    def _resolve_alias(self, label: str) -> str | None:
        """Registry alias (lowercase key) a machine *label* refers to: the
        alias itself, else the alias whose stored ``computer_name`` matches
        (so ``DESKTOP-ABC`` finds ``lab2``). None when neither."""
        lower = str(label or "").strip().lower()
        if not lower:
            return None
        if lower in self._entries:
            return lower
        via_cn = self.find_alias_by_computer_name(lower)
        return via_cn.lower() if via_cn else None

    def fresh_endpoints(self, alias: str, max_age_s: float = BEACON_FRESH_S,
                        *, now: float | None = None) -> list[dict[str, Any]]:
        """Observed endpoints for *alias* seen within *max_age_s* — the
        machine's current addresses — newest first, each with ``age_s``."""
        key = self._resolve_alias(alias)
        if key is None:
            return []
        rows: list[dict[str, Any]] = []
        for o in self.observed_endpoints(key):
            a = age_s(o.get("seen_at"), now)
            if a is None or a > max_age_s:
                continue
            rows.append({**o, "age_s": round(a, 1)})
        return rows

    def computer_name_for(self, alias: str) -> str:
        """The NetBIOS name stored for *alias* ('' when unknown)."""
        key = self._resolve_alias(alias)
        if key is None:
            return ""
        return str((self._entries.get(key) or {}).get("computer_name") or "")

    def learn_computer_name(self, alias: str, name: str) -> bool:
        """Record *name* as the machine's ``computer_name`` — only when the
        alias is already known (registry or YAML) and has none stored. Never
        overwrites: an operator-asserted or earlier-learned identity is
        what later connects are verified against. Returns True on write."""
        name = str(name or "").strip()
        lower = str(alias or "").strip().lower()
        if not name or not lower:
            return False
        canonical = next((str(a) for a in (self.cfg.machines or {})
                          if str(a).lower() == lower), None)
        if lower not in self._entries and canonical is None:
            return False
        ent = dict(self._entries.get(lower)
                   or {"alias": canonical or str(alias).strip()})
        if str(ent.get("computer_name") or "").strip():
            return False
        ent["computer_name"] = name
        ent.setdefault("alias", canonical or str(alias).strip())
        self._entries[lower] = ent
        try:
            self._save()
        except Exception:  # noqa: BLE001 — identity learning is best-effort
            pass
        return True

    def alias_for_host(self, host: str) -> str | None:
        """The one real machine that has ever used *host* (its configured
        host, ``alt_hosts`` or an observed endpoint) — how a bare
        ``connect()`` with a stale legacy endpoint finds out whose
        beacons to follow. None when no machine, or more than one, claims
        it (ambiguity must not guess)."""
        host = str(host or "").strip()
        if not host:
            return None
        hits: dict[str, str] = {}
        for lower, ent in self._entries.items():
            if self._is_shell(lower, ent):
                continue
            pool = {str(ent.get("host") or "")}
            pool.update(str(h) for h in (ent.get("alt_hosts") or []))
            pool.update(str(o.get("host") or "")
                        for o in (ent.get("observed_endpoints") or [])
                        if isinstance(o, dict))
            if host in pool:
                hits[lower] = str(ent.get("alias") or lower)
        for alias, m in (getattr(self.cfg, "machines", None) or {}).items():
            pool = {str(m.host or "")}
            pool.update(str(h) for h in (m.alt_hosts or []))
            pool.update(str(getattr(v, "host", "") or "")
                        for v in (m.views or {}).values())
            if host in pool:
                hits.setdefault(str(alias).lower(), str(alias))
        return next(iter(hits.values())) if len(hits) == 1 else None

    def beacon_overview(self, max_age_s: float = 900.0, *,
                        now: float | None = None) -> list[dict[str, Any]]:
        """Per real machine, where it was last seen and how long ago:
        ``[{machine, computer_name, hosts, seen_at, age_s, fresh}]``,
        newest first, limited to the last *max_age_s*. ``hosts`` is the
        newest beat's address set (a two-NIC box lists both); ``fresh`` is
        True inside :data:`BEACON_FRESH_S`. Attached to connect failures so
        an agent sees where the machines actually are."""
        now = time.time() if now is None else now
        rows: list[dict[str, Any]] = []
        for lower, ent in self._entries.items():
            if self._is_shell(lower, ent):
                continue
            stamped = [
                (seen_epoch(o.get("seen_at")), o)
                for o in (ent.get("observed_endpoints") or [])
                if isinstance(o, dict) and o.get("host")]
            stamped = [(e, o) for e, o in stamped if e is not None]
            if not stamped:
                continue
            newest = max(e for e, _ in stamped)
            age = max(0.0, now - newest)
            if age > max_age_s:
                continue
            hosts: list[str] = []
            for e, o in stamped:
                if newest - e <= 5.0 and str(o["host"]) not in hosts:
                    hosts.append(str(o["host"]))
            seen_at = next(str(o.get("seen_at")) for e, o in stamped
                           if e == newest)
            rows.append({
                "machine": str(ent.get("alias") or lower),
                "computer_name": str(ent.get("computer_name") or ""),
                "hosts": hosts,
                "seen_at": seen_at,
                "age_s": round(age, 1),
                "fresh": age <= BEACON_FRESH_S,
            })
        rows.sort(key=lambda r: r["age_s"])
        return rows

    # ------------------------------------------------------------- pruning ----

    def prune_empty_shells(
            self,
            session_machines: dict[str, Any] | None = None,
            dry_run: bool = False) -> dict[str, Any]:
        """PR#8: drop alias-only shell entries that have no operator
        metadata (``trust`` / ``host`` / ``purpose`` / ``note`` /
        ``operator`` / ``tags`` all blank) and no token. YAML-sourced
        aliases, shadowed entries, and entries with a token are NEVER
        pruned. An alias that is currently connected (``session_machines``
        has it as a key) is held back and reported under
        ``kept_connected`` so the live view keeps its boot/endpoint
        bookkeeping.

        Returns a report
        ``{"removed":[aliases], "kept_connected":[aliases],
           "kept_registered":[aliases], "count_removed": int,
           "dry_run": bool}`` — ``kept_registered`` lists aliases that
        LOOKED empty on first glance but survived (YAML / shadow /
        token). When ``dry_run=False`` the empty shells are actually
        popped and the registry is saved; ``dry_run=True`` returns the
        same shape without mutating state.
        """
        if not dry_run:
            self._check_writable()
        sess = {str(k or "").strip().lower()
                for k in (session_machines or {})}
        removed: list[str] = []
        kept_connected: list[str] = []
        kept_registered: list[str] = []
        for lower, ent in list(self._entries.items()):
            alias = str(ent.get("alias") or lower)
            trust = str(ent.get("trust") or "").strip()
            host = str(ent.get("host") or "").strip()
            purpose = str(ent.get("purpose") or "")
            note = str(ent.get("note") or "")
            operator = str(ent.get("operator") or "")
            tags = ent.get("tags") or []
            looks_empty = (
                trust in ("", None)
                and host in ("", None)
                and purpose == ""
                and note == ""
                and operator == ""
                and not tags
            )
            if not looks_empty:
                continue
            # Hard guards — these alias kinds are NEVER a shell:
            # YAML-sourced metadata overlay, explicit shadow, token
            # set. (``_find_machine`` is NOT a shortcut here: registry
            # entries are merged into ``cfg.machines`` at load time, so
            # every entry looks machine-known. ``_yaml_aliases`` holds
            # the committed YAML surface and is the right source.)
            if lower in self._yaml_aliases:
                kept_registered.append(alias)
                continue
            if bool(ent.get("shadow")):
                kept_registered.append(alias)
                continue
            if bool(ent.get("token")):
                kept_registered.append(alias)
                continue
            if lower in sess:
                kept_connected.append(alias)
                continue
            removed.append(alias)
        if not dry_run and removed:
            cfg_machines = getattr(self.cfg, "machines", None)
            for alias in removed:
                lower = alias.lower()
                self._entries.pop(lower, None)
                # Also clear the in-memory ``cfg.machines`` overlay: the
                # registry merges every entry into it at load time, and
                # ``_machine_rows`` iterates both sides. Without this,
                # pruned aliases ghost in the dashboard until the next
                # orchestrator restart. Mirror of ``unregister``.
                if isinstance(cfg_machines, dict):
                    for a in [a for a in cfg_machines
                              if str(a).lower() == lower]:
                        cfg_machines.pop(a, None)
            try:
                self._save()
            except Exception:  # noqa: BLE001 — don't mask the prune call
                pass
        return {
            "removed": sorted(removed, key=str.lower),
            "kept_connected": sorted(kept_connected, key=str.lower),
            "kept_registered": sorted(kept_registered, key=str.lower),
            "count_removed": len(removed),
            "dry_run": bool(dry_run),
        }

    # ------------------------------------------------------------ reading ----

    def entry(self, alias: str) -> dict[str, Any] | None:
        return self._entries.get(str(alias or "").strip().lower())

    def all(self) -> dict[str, dict[str, Any]]:
        return {str(e.get("alias") or k): dict(e)
                for k, e in sorted(self._entries.items())}

    def trust_for(self, machine_label: str) -> str:
        """Trust level for a machine label — registry entry, then YAML
        ``machines:`` metadata, then the ``default`` overlay for the
        implicit machine, then ``untrusted`` (fail-safe default)."""
        key = str(machine_label or "").strip().lower()
        ent = self._entries.get(key)
        if ent is not None:
            return _norm_trust(ent.get("trust"))
        mcfg = self._find_machine(key)
        if mcfg is not None and mcfg.trust:
            return _norm_trust(mcfg.trust)
        if key not in self._yaml_aliases:
            ent = self._entries.get(DEFAULT_ALIAS)
            if ent is not None:
                return _norm_trust(ent.get("trust"))
        return "untrusted"

    def describe(self, alias: str,
                 cfg: PryConfig | None = None) -> dict[str, Any] | None:
        """The ``machine_info`` block for *alias* — never contains the
        token (``token_set`` flag instead)."""
        cfg = cfg or self.cfg
        key = str(alias or "").strip()
        if not key:
            return None
        lower = key.lower()
        ent = self._entries.get(lower) or {}
        mcfg = self._find_machine(key)
        if ent.get("alias"):
            key = str(ent["alias"])
        # The implicit machine (learned label like a computer name) has no
        # entry of its own — the 'default' overlay supplies metadata, but
        # never endpoints (those come from the YAML target: block).
        meta = ent
        if not meta and mcfg is None and lower != DEFAULT_ALIAS:
            meta = self._entries.get(DEFAULT_ALIAS) or {}
        trust = _norm_trust(ent.get("trust") or meta.get("trust")
                            or (mcfg.trust if mcfg is not None else ""))
        endpoints: dict[str, str] = {}
        if isinstance(mcfg, MachineConfig):
            for kind in (list(mcfg.views) or ["kernel", "user"]):
                try:
                    tc = mcfg.view(kind)
                except Exception:
                    continue
                if tc.host:
                    endpoints[str(kind)] = f"{tc.host}:{tc.port}"
        elif lower == DEFAULT_ALIAS:
            if getattr(cfg.target, "host", ""):
                endpoints["kernel"] = f"{cfg.target.host}:{cfg.target.port}"
            ut = (getattr(cfg, "targets", None) or {}).get("user")
            if ut is not None and ut.host:
                endpoints["user"] = f"{ut.host}:{ut.port}"
        elif ent.get("host"):
            for kind, pkey in (("kernel", "kernel_port"), ("user", "user_port")):
                if ent.get(pkey):
                    endpoints[kind] = (f"{os.path.expandvars(str(ent['host']))}"
                                       f":{int(ent[pkey])}")
        if ent.get("shadow") and isinstance(mcfg, MachineConfig):
            for kind, tc in (mcfg.views or {}).items():
                if getattr(tc, "host", ""):
                    endpoints[str(kind)] = f"{tc.host}:{tc.port}"
        info: dict[str, Any] = {
            "machine": key,
            "trust": trust,
            "purpose": str(ent.get("purpose") or meta.get("purpose")
                           or getattr(mcfg, "purpose", "") or ""),
            "note": str(ent.get("note") or meta.get("note")
                        or getattr(mcfg, "note", "") or ""),
            "operator": str(ent.get("operator") or meta.get("operator")
                            or getattr(mcfg, "operator", "") or ""),
            "tags": [str(t) for t in (ent.get("tags") or meta.get("tags")
                                      or getattr(mcfg, "tags", None) or [])],
            "endpoints": endpoints,
            "source": ("registry" if ent else
                       ("yaml" if mcfg is not None else
                        ("default" if lower == DEFAULT_ALIAS else "adhoc"))),
            "token_set": bool(ent.get("token") or
                              (isinstance(mcfg, MachineConfig)
                               and getattr(mcfg, "token", ""))),
        }
        if ent.get("registered_at"):
            info["registered_at"] = str(ent["registered_at"])
        # expose phone-home identity + probe hints on the
        # machine_info block so the dashboard, machines listings, and
        # the DHCP-flapping recipe can see what's wired up.
        cn = str(ent.get("computer_name") or "").strip()
        if cn:
            info["computer_name"] = cn
        alt = ent.get("alt_hosts") or (
            list(mcfg.alt_hosts) if isinstance(mcfg, MachineConfig) else [])
        if alt:
            info["alt_hosts"] = [str(h) for h in alt if str(h).strip()]
        obs = ent.get("observed_endpoints") or []
        if obs:
            info["observed_endpoints"] = [dict(o) for o in obs
                                          if isinstance(o, dict)]
            # PR#8: when the primary endpoint resolution came up empty but
            # passive discovery has seen the box answer somewhere, surface
            # the newest observation as a stale hint. Dashboard shells
            # ("37 x k-shells all 'no endpoint'") get a visible hint pointing
            # at the last-known host:port so operators know a rediscover /
            # reconnect is the next move. observed_endpoints currently only
            # carries kernel-port observations (connect fan-out), so the
            # view-kind defaults to "kernel".
            if not endpoints:
                newest = next((o for o in obs if isinstance(o, dict)), None)
                if newest and newest.get("host") and newest.get("port"):
                    stale: dict[str, Any] = {
                        "kernel": f"{newest['host']}:{int(newest['port'])}",
                    }
                    if newest.get("seen_at"):
                        stale["when"] = str(newest["seen_at"])
                    info["endpoints_stale"] = stale
        return info
