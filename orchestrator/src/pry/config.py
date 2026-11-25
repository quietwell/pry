"""YAML-driven orchestrator configuration with safe defaults."""

from __future__ import annotations

import dataclasses
import difflib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PRIMARY_TARGET = "kernel"  # the default (kernel agent) view name

# The only view kinds a ``machines.<alias>`` block may carry as a nested
# mapping (``kernel: {port: ...}`` / ``user: {...}``). Any OTHER dict-valued
# key (``scan:``, ``pointer_map:``, a typo) is machine metadata, never a view.
MACHINE_VIEW_KINDS = ("kernel", "user")

_log = logging.getLogger(__name__)

# Machine trust levels (registry / machines: metadata). Ordered —
# an actuator on a machine is allowed when its trust is >= the configured
# security.min_trust_actuator. "untrusted" is the fail-safe default and
# also disables the gate entirely when used as the threshold.
TRUST_LEVELS: dict[str, int] = {
    "untrusted": 0,
    "restricted": 1,
    "lab": 2,
}


def _project_root() -> Path:
    """Repo root in a source checkout (``orchestrator/src/pry/config.py``
    -> ``parents[2]`` is ``orchestrator/``, its parent the repo root),
    else the process cwd for installed-package layouts.

    The anchor for every RELATIVE artifact path — a bare
    ``dir: artifacts`` used to resolve against whatever cwd the server
    launched with, so dumps written under ``<repo>/artifacts`` were
    invisible to a boot running from ``orchestrator/`` (and produced
    a two-store drift for findings.db).
    """
    pkg = Path(__file__).resolve()
    try:
        orch = pkg.parents[2]          # .../orchestrator
        if orch.name == "orchestrator" and (orch / "src" / "pry").is_dir():
            return orch.parent
    except IndexError:
        pass
    return Path.cwd()


@dataclass
class TargetConfig:
    host: str = "127.0.0.1"
    port: int = 50074
    token: str = ""
    connect_timeout_ms: int = 10000
    # Cap on gRPC calls in flight per AgentClient. Prevents a fan-out loop
    # (bulk region reads, IAT walks, plugin sweeps) from stampeding the
    # agent's IOCTL thread pool; the AgentClient enforces this via a
    # semaphore around each _call. Absent-in-yaml stays at the default.
    max_inflight: int = 16
    # NIC lease flap (.167/.196) — extra hosts tried, in order,
    # when the configured host fails the pre-flight TCP probe. The
    # last host that connected is remembered in-memory and retried
    # first on the next connect. Empty list = probe only the configured
    # host (the historical behavior).
    alt_hosts: list[str] = field(default_factory=list)


@dataclass
class MachineConfig:
    """One lab machine's view endpoints, from the ``machines:`` block:

        machines:
          lab2:
            host: 10.0.2.15            # shared by both views
            token: secret              # shared default
            kernel_port: 50099
            user_port: 50075
            # or per-view overrides:
            kernel: {port: 50099, token: other}
            user:   {host: 10.0.2.16, port: 50075}

    Both shapes expand to ``targets['lab2.kernel']`` / ``targets['lab2.user']``
    at load time; ``machine_for_endpoint`` maps a connected host:port back
    to the machine alias so view keys stay human-stable when IPs move.
    """
    host: str = ""
    token: str = ""
    kernel_port: int = 50099
    user_port: int = 50075
    connect_timeout_ms: int = 10000
    max_inflight: int = 16
    # fallback hosts for lease flap (see TargetConfig.alt_hosts).
    alt_hosts: list[str] = field(default_factory=list)
    views: dict[str, "TargetConfig"] = field(default_factory=dict)
    # machine metadata. YAML `machines:` may carry these directly;
    # the runtime registry (registry.py) overlays them for YAML aliases
    # and owns them for registry-registered machines. `trust` is one of
    # TRUST_LEVELS — gates actuator verbs via security.min_trust_actuator.
    purpose: str = ""
    note: str = ""
    trust: str = "untrusted"
    operator: str = ""
    tags: list[str] = field(default_factory=list)
    # v16 (Memory scanner wave 1): per-machine scan policy.
    #
    #   scan.dir              — override the agent's default
    #                           ``<agent_dir>\scans\`` root. Empty =
    #                           default. Must be absolute + writable by
    #                           the agent process.
    #   scan.disk_quota_bytes — agent-side disk cap summed across every
    #                           active scan on that view. 0 disables
    #                           disk spill (RAM-only, 128 MiB cap).
    #                           Defaults to 32 GiB (see scan_service.hpp).
    #   scan.disk_spill       — ``auto`` | ``ram_only`` | ``disabled``.
    #                           ``ram_only`` behaves like
    #                           disk_quota_bytes=0; ``disabled`` refuses
    #                           every snapshot above the RAM budget with
    #                           ``kind='disabled'``. Default ``auto``.
    #
    # Dormant surface until StatusResponse.scan_service_version flips to
    # 1 on the agent — see an internal plan
    # §2.9 for the full contract.
    scan: dict[str, Any] = field(default_factory=dict)
    # v17 (Memory scanner wave 2): pointer-map knobs. Keys mirror ``scan`` —
    #   dir             — overrides <agent_dir>\pointer_maps\ root
    #   disk_quota_bytes — overrides POINTER_MAP_DISK_PER_MACHINE
    #   max_maps        — overrides POINTER_MAP_COUNT_PER_MACHINE
    # Dormant until pointer_map_version flips to 1 on the agent — see
    # an internal plan §2.11.
    pointer_map: dict[str, Any] = field(default_factory=dict)

    def view(self, kind: str) -> "TargetConfig":
        """Effective TargetConfig for view *kind* — explicit per-view
        override wins; machine-level host/token fill fields left at the
        dataclass default."""
        tc = self.views.get(kind)
        if tc is not None:
            dflt = TargetConfig()
            if self.host and tc.host == dflt.host:
                tc = dataclasses.replace(tc, host=self.host)
            if self.token and tc.token == dflt.token:
                tc = dataclasses.replace(tc, token=self.token)
            if self.alt_hosts and not tc.alt_hosts:
                tc = dataclasses.replace(tc, alt_hosts=list(self.alt_hosts))
            return tc
        port = self.kernel_port if kind == "kernel" else self.user_port
        return TargetConfig(host=self.host, port=port, token=self.token,
                            connect_timeout_ms=self.connect_timeout_ms,
                            max_inflight=self.max_inflight,
                            alt_hosts=list(self.alt_hosts))


@dataclass
class SecurityConfig:
    authorized_targets: list[str] = field(default_factory=lambda: ["127.0.0.0/8"])
    allow_delete: bool = False
    allow_driver_unload: bool = True
    allow_driver_load: bool = True
    max_transfer_mb: int = 512
    max_mem_read_mb: int = 8
    # v11: Device.Ioctl is an actuator — a bad IOCTL can bugcheck the
    # target. Off by default; flip on in the lab config when the device
    # under test is known-good.
    allow_ioctl_send: bool = False
    # v11: event subscribe registers PsSet*NotifyRoutine callbacks in the
    # driver — kernel-visible state. Gated like driver_load.
    allow_event_stream: bool = False
    # v15: Exec.CallFunction runs attacker-chosen code in target context —
    # the strongest actuator in the stack. Off by default.
    allow_function_call: bool = False
    # machine-trust gate for actuator verbs (ioctl send,
    # driver_load/unload, boot_recover, kill_process, exec call). A
    # machine whose trust (registry / machines: metadata) is below this
    # threshold gets the actuator refused unless the call passes
    # force=true. "untrusted" (default) = no gating. See TRUST_LEVELS.
    min_trust_actuator: str = "untrusted"
    # gate on token_manage mutators
    # (enable/disable/remove_privilege, set_integrity_level,
    # set_virtualization, impersonate, modify_default_dacl). Off by
    # default; set true in the lab config once the identity-mutator
    # surface is reviewed.
    allow_token_adjust: bool = False
    # net_manage(action='kill') uses
    # SetTcpEntry(MIB_TCP_STATE_DELETE_TCB) to tear down a live TCP
    # connection. Off by default; flip on in the lab config only after
    # confirming the target VM is one you may disrupt.
    allow_kill_connection: bool = False
    # gate on dump_manage.create_kernel_dump
    # (NtSystemDebugControl(SysDbgGetLiveKernelDump)).
    allow_live_kernel_dump: bool = False
    # Memory scanner wave 3 P4 (AccessTrace): gate on the watchhw driver
    # path. The watchhw driver arms a HW breakpoint through the agent's
    # int1 hook, which is PatchGuard-sensitive and lab-only. The dbgeng
    # fallback path is unaffected. Off by default; flip on in the lab
    # config once the agent + driver's hw-bp hook is known-good.
    allow_hw_bp_hook: bool = False
    # target_manage.reboot: gate on the reliable Windows-API
    # reboot verb (InitiateShutdownW from the LocalSystem agent token).
    # Reboot is scarier than an IOCTL, so opt-in is the right default —
    # the verb refuses with ``kind='feature_disabled'`` until a lab
    # config flips this on. The machine-trust gate still applies on top
    # (see min_trust_actuator).
    allow_reboot: bool = False
    # memory_manage(allow_fault=true) sets the
    # driver's PRY_MEM_FLAG_ALLOW_SOFTFAULT, and faulting a non-resident
    # kernel page in from the driver's IOCTL context wedged the lab VM
    # twice. Off by default: memory_manage refuses allow_fault=true with
    # kind='not_allowed', and the agent client strips the flag from every
    # internal read, until a lab config flips this on.
    allow_kernel_softfault: bool = False
    # reconstruct_manage compile (and verify with code=) runs the HOST's
    # C toolchain (MSVC cl/link or clang-cl) on agent-supplied source —
    # source that may come from decompiled, prompt-injected target code.
    # Off by default: compile refuses with kind='not_allowed'. The source
    # guard and flag allowlist apply either way, and build outputs are
    # only ever read as bytes by the emulator, never loaded natively.
    allow_host_compile: bool = False


@dataclass
class McpConfig:
    bind: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"
    # The listener may bind
    # 0.0.0.0 so lab agents can POST /api/agent_report, but every OTHER
    # route (/mcp, /api/*, /ws, dashboard pages, /health) answers only
    # loopback clients and clients inside these CIDRs. Empty = loopback only.
    remote_cidrs: list[str] = field(default_factory=list)
    # Optional shared secret. When set, every request except the agent
    # beacon must carry ``Authorization: Bearer <token>`` (MCP clients:
    # add the header in the client's server config). Browsers may instead
    # open ``/?token=<token>`` once - that sets an HttpOnly SameSite=Strict
    # cookie the dashboard then rides on. ``${ENV}`` is expanded.
    auth_token: str = ""
    # Extra Host-header names accepted besides IP literals, ``localhost``
    # and this machine's own hostname (DNS-rebinding guard). Add the name
    # MCP clients use when it is none of those.
    allowed_hosts: list[str] = field(default_factory=list)
    # Cap on registry entries the unauthenticated agent beacon may mint
    # (beacons for already-known machines are always recorded).
    beacon_max_new_machines: int = 16


@dataclass
class DashboardConfig:
    enabled: bool = True
    bind: str = "127.0.0.1"
    port: int = 8766


@dataclass
class ArtifactsConfig:
    dir: str = "artifacts"
    reports_dir: str = "reports"
    pdb_cache: str = "artifacts/symbols"
    # absolute path to the shared knowledge-base DB. When empty,
    # resolves to `<dir>/findings.db` — but that path is relative to the
    # server's cwd, which is what caused the two-DB drift.
    # Set this in configs/*.yaml to an absolute path to pin the DB
    # regardless of where pry-server is launched from.
    findings_db: str = ""


@dataclass
class IdaConfig:
    enabled: bool = True
    ida_path: str = ""  # local IDA install, e.g. D:\\Apps\\IDA
    command: list[str] = field(default_factory=lambda: ["uv", "run", "idalib-mcp", "--stdio"])
    prefer_gui: bool = False
    open_timeout_s: int = 180


@dataclass
class GhidraConfig:
    # Disabled by default: the bridge only spawns once a Ghidra install +
    # JDK + pyghidra are configured. Enabling without prerequisites makes
    # ghidra_manage report an actionable precheck error at first use.
    enabled: bool = False
    ghidra_dir: str = ""   # Ghidra install root (GHIDRA_INSTALL_DIR)
    java_home: str = ""    # JDK home (JAVA_HOME); empty = rely on PATH
    project_dir: str = ""  # shared Ghidra project dir; default <artifacts>/ghidra_project
    project_name: str = "pry"
    backend_python: str = ""  # interpreter with pyghidra+mcp; empty = auto-detect
    heap_mb: int = 8192    # JVM -Xmx for the one shared backend
    open_timeout_s: int = 300  # JVM+import+analysis can be slower than idalib
    open_soft_deadline_s: float = 10.0
    # Shim command override (tests / exotic layouts). Empty = spawn
    # orchestrator/ghidra_stdio_shim.py with the current interpreter.
    command: list[str] = field(default_factory=list)


@dataclass
class PluginsConfig:
    dir: str = ""  # empty: auto-resolve to repo-root plugins (+ scripts_user overlay)


@dataclass
class SymbolsConfig:
    # PDB-backed kernel symbol resolution (dbghelp). Cache lives at
    # artifacts.pdb_cache in symsrv layout.
    allow_download: bool = True
    servers: list[str] = field(
        default_factory=lambda: ["https://msdl.microsoft.com/download/symbols"])


@dataclass
class LoggingConfig:
    # Root log level (DEBUG/INFO/WARNING/...). `file` is optional: empty
    # means log to stderr only; a path adds a FileHandler alongside it.
    level: str = "INFO"
    file: str = ""


@dataclass
class ClientsConfig:
    # Idle AgentClient reaper: how long a per-target client may sit unused
    # before the caller-side pool tears down its channel. Keeps long sessions
    # from pinning gRPC connections to targets no one is talking to anymore.
    idle_reap_s: float = 300.0


@dataclass
class LeasesConfig:
    # Default wait when a peer tries to attach to a pid that is already
    # attached under someone else's lease. Zero fails fast; larger values
    # let short-lived attaches drain naturally.
    attach_timeout_s: float = 5.0
    # Default wait for driver_load / driver_unload arbitration when multiple
    # agents contend for the driver. Longer than attach_timeout because these
    # operations touch the SCM and can legitimately take seconds.
    driver_timeout_s: float = 10.0
    # background reaper for abandoned debug leases. A lease idle
    # (not touched) for longer than ``idle_ttl_s`` or held in total longer
    # than ``hard_max_s`` is released by the reaper. ``reap_interval_s``
    # is how often the reaper wakes to check.
    idle_ttl_s: float = 600.0        # 10 min
    hard_max_s: float = 3600.0       # 1 hour
    reap_interval_s: float = 60.0


@dataclass
class WatchdogConfig:
    # hands-off wedge protection. When `auto_arm` carries an `id`,
    # target_manage(driver_load|connect-new_boot) re-arms the driver
    # watchdog and attaches an orchestrator-side kicker automatically —
    # protection resumes after a driver load and after a reboot without a
    # manual watchdog_manage(auto_kick) call. Empty dict = disabled.
    # Shape: {id, deadline_ms, interval_ms, bugcheck_code, cookie, label}
    auto_arm: dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitorConfig:
    # Boot-monitor poll interval per connected view (seconds); 0 or a
    # negative value disables the monitor. target_manage's runtime read
    # getattr(cfg, 'monitor'), which the YAML loader populates.
    boot_poll_s: float = 5.0
    # Idle cadence for the folded-in minidump-dir watch.
    dump_scan_idle_s: float = 60.0


@dataclass
class SnapshotsConfig:
    # periodic pre-crash state capture. "Snapshot on heartbeat
    # loss" is impossible — a wedged target can't answer reads — so the
    # pump captures every configured range on an interval while the
    # target is alive; artifacts/snapshots/<boot_epoch_ms>/ survives the
    # BSOD that follows. enabled=false with non-empty ranges leaves the
    # pump off but the config in place.
    enabled: bool = False
    interval_s: float = 30.0
    # Each range: {name, space (user|kernel|physical), address|from_va,
    # size, pid?}. `address` honors module+offset notation resolved once
    # per boot; `from_va` + space=physical translates VA->PA then reads
    # the physical page.
    ranges: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ReconstructConfig:
    # reconstruct_manage (reconstruct-and-verify, slice 1). Host compiles
    # are gated by security.allow_host_compile; these knobs only shape
    # them.
    # Toolchain used when a compile call names none: "msvc" | "clang-cl".
    default_toolchain: str = "msvc"
    # Visual Studio / Build Tools install root (the dir holding VC\).
    # Empty = the newest install under Program Files.
    vs_path: str = ""
    # clang-cl.exe / lld-link.exe overrides. Empty = the VS Llvm
    # component, then Program Files\LLVM, then PATH; lld-link beside
    # clang-cl, else MSVC link.exe.
    clang_cl: str = ""
    lld_link: str = ""
    compile_timeout_s: float = 60.0
    link_timeout_s: float = 30.0
    # Defaults for verify when the call passes none.
    default_cases: int = 256
    max_insns: int = 5_000_000


@dataclass
class PryConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    # named secondary targets (phase 1): e.g. targets.user -> the umagent
    # usermode view. Falls back to `target` for the primary name.
    targets: dict[str, TargetConfig] = field(default_factory=dict)
    # multi-machine: machines.<alias> = {host, token, kernel_port,
    # user_port, views...} — each alias's views are addressable as
    # '<alias>.<kind>' (lab2.kernel). computer_name also resolves.
    machines: dict[str, MachineConfig] = field(default_factory=dict)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    mcp: McpConfig = field(default_factory=McpConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    artifacts: ArtifactsConfig = field(default_factory=ArtifactsConfig)
    ida: IdaConfig = field(default_factory=IdaConfig)
    ghidra: GhidraConfig = field(default_factory=GhidraConfig)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    symbols: SymbolsConfig = field(default_factory=SymbolsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    clients: ClientsConfig = field(default_factory=ClientsConfig)
    leases: LeasesConfig = field(default_factory=LeasesConfig)
    watchdog: WatchdogConfig = field(default_factory=WatchdogConfig)
    snapshots: SnapshotsConfig = field(default_factory=SnapshotsConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    reconstruct: ReconstructConfig = field(default_factory=ReconstructConfig)
    # T2.3 (PR#1): operators who want the pre-PR#1 hex+ascii+text shape on
    # every file_manage(action='read') call set this to 'both' (either
    # via YAML or at runtime). 'auto' emits text-only on text, hex-only
    # on binary.  Call cfg.effective_file_manage_view() to resolve.
    file_manage_default_view: str = "auto"
    # T1.1a (PR#2): aliases that originated in the reviewed YAML config
    # (machines: or dotted targets:). The MachineRegistry merge path
    # adds registry-only aliases to self.machines after load — so
    # `name in self.machines` alone no longer tells us whether the
    # endpoint came from a reviewed YAML entry. ``has_machine(name)``
    # uses this set as the source of truth. ``load_config`` populates
    # it; registry merges leave it untouched.
    _yaml_machines: set[str] = field(default_factory=set)
    # problems found while loading the YAML (unknown keys, wrong
    # value types). Logged at load and surfaced in target_manage(status)
    # warnings so a typo in a security knob can't fail open silently.
    _warnings: list[str] = field(default_factory=list)

    @property
    def config_warnings(self) -> list[str]:
        return list(self._warnings)

    @property
    def target_endpoint(self) -> str:
        return f"{self.target.host}:{self.target.port}"

    def has_machine(self, name: str | None) -> bool:
        """T1.1a (PR#2): True iff ``name`` names a machine (or dotted
        view) that came from the reviewed YAML config — a registry-only
        alias is False even though it lives in ``self.machines`` after
        the registry's merge pass. Case-insensitive."""
        if not name:
            return False
        s = str(name).strip()
        if not s:
            return False
        key = s.rsplit(".", 1)[0] if "." in s else s
        key = key.lower()
        return key in {m.lower() for m in (self._yaml_machines or set())}

    def target_for(self, name: str | None = None) -> TargetConfig:
        if name and name in self.targets:
            return self.targets[name]
        if name and "." in name:
            # '<machine>.<kind>' — resolve inside that machine's scope;
            # never fall back to another machine's endpoint.
            label, kind = name.rsplit(".", 1)
            if label in self.machines:
                return self.machines[label].view(kind)
            if label in self.targets:  # machine-wide shared entry
                return self.targets[label]
            raise KeyError(f"unknown target {name!r}")
        if name and name in self.machines:
            # bare machine alias -> its kernel view
            return self.machines[name].view(PRIMARY_TARGET)
        if name and name != PRIMARY_TARGET:
            raise KeyError(f"unknown target {name!r}")
        return self.target

    def machine_for_endpoint(self, host: str, port: int) -> str:
        """Config alias whose view endpoint matches host:port — lets a
        machine keep a stable label when its IP changes."""
        for alias, m in self.machines.items():
            for kind in (list(m.views) or ["kernel", "user"]):
                tc = m.view(kind)
                if tc.host == host and (not port or tc.port == int(port)):
                    return alias
        for name, tc in self.targets.items():
            if "." not in name:
                continue  # undotted entries are view-kind/default endpoints
            if tc.host == host and (not port or tc.port == int(port)):
                return self.machine_of_key(name)
        return ""

    @staticmethod
    def machine_of_key(view_key: str) -> str:
        return view_key.rsplit(".", 1)[0] if "." in view_key else view_key

    def _anchored(self, raw: str) -> Path:
        """Absolute paths pass through; relative ones anchor at the
        source-checkout repo root so every launch lands on the same
        store regardless of cwd."""
        p = Path(raw)
        if p.is_absolute():
            return p
        return _project_root() / p

    def artifacts_dir(self) -> Path:
        """Canonical artifact root — the ONE namespace shared by every
        producer and consumer (file_manage dumps/ingest, spill,
        store_binary workdirs, bin_manage/ida_manage lookups).

        Precedence matches the IDA shim: PRY_ARTIFACTS_DIR (absolute)
        > artifacts.dir anchored at the repo root."""
        import os
        envd = (os.environ.get("PRY_ARTIFACTS_DIR") or "").strip()
        if envd:
            return Path(envd)
        return self._anchored(self.artifacts.dir)

    def reports_dir(self) -> Path:
        return self._anchored(self.artifacts.reports_dir)

    def pdb_cache_dir(self) -> Path:
        """PDB cache root — anchored like artifacts_dir so dbghelp and
        the IDA shim agree on the same symsrv tree."""
        return self._anchored(self.artifacts.pdb_cache)

    def findings_db(self) -> Path:
        """canonical path to the shared knowledge-base DB.

        Precedence:
          1. artifacts.findings_db (config field, may be absolute).
          2. artifacts.dir/findings.db (relative to cwd — the
             default that caused two DBs to accumulate).
        Pin an absolute path in configs/*.yaml to guarantee every
        orchestrator boot lands on the same DB.
        """
        pinned = (self.artifacts.findings_db or "").strip()
        if pinned:
            return Path(pinned)
        return self.artifacts_dir() / "findings.db"

    def spill_dir(self) -> Path:
        """Auto-spill lives under artifacts_dir/spill/. Content-addressed
        by sha256; identical payloads dedupe naturally. Read back via
        file_manage(action='read_artifact', sha256=...).

        Precedence matches the IDA-shim's `_shim_spill_dir()` so the
        orchestrator and the shim always land on the same directory:
        PRY_MCP_SPILL_DIR (absolute) > PRY_ARTIFACTS_DIR/spill >
        artifacts.dir/spill.
        """
        import os
        envd = os.environ.get("PRY_MCP_SPILL_DIR")
        if envd:
            return Path(envd)
        art = os.environ.get("PRY_ARTIFACTS_DIR")
        if art:
            return Path(art) / "spill"
        return self.artifacts_dir() / "spill"

    # --- MCP response-size envelopes -----------------------------------
    # Env-var overrides let deployments tune spill without touching yaml.

    def mcp_max_bytes(self) -> int:
        """Response byte budget; over this the biggest field in `data` spills.
        Default 32 KiB. Set PRY_MCP_MAX_BYTES to change; -1 disables spill.
        """
        import os
        try:
            return int(os.environ.get("PRY_MCP_MAX_BYTES", "32768"))
        except ValueError:
            return 32768

    def mcp_max_items(self) -> int:
        """Global cap on list-length across every list-returning action.
        Default 256. Set PRY_MCP_MAX_ITEMS to change."""
        import os
        try:
            return int(os.environ.get("PRY_MCP_MAX_ITEMS", "256"))
        except ValueError:
            return 256

    def mcp_preview_bytes(self) -> int:
        """Bytes/chars kept inline as `preview` when a payload spills.
        Default 512. Set PRY_MCP_PREVIEW_BYTES to change."""
        import os
        try:
            return int(os.environ.get("PRY_MCP_PREVIEW_BYTES", "512"))
        except ValueError:
            return 512

    def effective_file_manage_view(self) -> str:
        """T2.3 (PR#1): session-wide default for ``file_manage read``'s
        ``view`` kwarg. Pre-PR#1 behavior was equivalent to ``both``
        (hex + ascii + text when the extension looked text-ish); the new
        default ``auto`` emits text alone when the content sniffs as
        text and hex alone otherwise. Operators who parse `hex` from
        every result can set ``PRY_FILE_MANAGE_DEFAULT_VIEW=both``
        (env var wins) or the ``file_manage_default_view`` config field
        to restore the old shape. Valid values: auto | text | hex |
        both | ascii."""
        import os
        env = os.environ.get("PRY_FILE_MANAGE_DEFAULT_VIEW", "").strip()
        if env:
            return env.lower()
        return (str(getattr(self, "file_manage_default_view", "auto"))
                or "auto").lower()


_FALSE_STR = ("0", "false", "no", "off", "")
_TRUE_STR = ("1", "true", "yes", "on")


def _coerce(current: Any, value: Any, where: str,
            warnings: list[str] | None) -> Any:
    """Best-effort type normalisation for a YAML scalar against the
    dataclass default's type. A value that can't be made to fit keeps the
    default and records a warning (fail-safe: a garbled security knob
    stays at its safe default instead of becoming truthy)."""
    def _warn(msg: str) -> None:
        if warnings is not None:
            warnings.append(f"config key '{where}': {msg}")

    if value is None:
        _warn("empty value ignored (default kept)")
        return current
    if isinstance(current, bool):
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str) and \
                value.strip().lower() in _FALSE_STR + _TRUE_STR:
            return value.strip().lower() in _TRUE_STR
        _warn(f"expected true/false, got {value!r} (default {current} kept)")
        return current
    if isinstance(current, int):
        if isinstance(value, bool):
            _warn(f"expected a number, got {value!r} (default kept)")
            return current
        if isinstance(value, int):
            return value
        try:
            return int(str(value).strip(), 0)
        except (TypeError, ValueError):
            _warn(f"expected an integer, got {value!r} (default kept)")
            return current
    if isinstance(current, float):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        try:
            return float(str(value).strip())
        except (TypeError, ValueError):
            _warn(f"expected a number, got {value!r} (default kept)")
            return current
    if isinstance(current, list):
        if isinstance(value, list):
            return value
        if isinstance(value, (str, int, float)):
            _warn("expected a list - single value wrapped")
            return [value]
        _warn(f"expected a list, got {type(value).__name__} (default kept)")
        return current
    if isinstance(current, dict):
        if isinstance(value, dict):
            return value
        _warn(f"expected a mapping, got {type(value).__name__} (default kept)")
        return current
    if isinstance(current, str):
        if isinstance(value, (dict, list)):
            _warn(f"expected a string, got {type(value).__name__} "
                  "(default kept)")
            return current
        return str(value)
    return value


def _unknown(where: str, key: str, known: list[str],
             warnings: list[str] | None) -> None:
    if warnings is None:
        return
    hint = difflib.get_close_matches(key, known, n=1, cutoff=0.75)
    warnings.append(
        f"unknown config key '{where}.{key}' ignored"
        + (f" (did you mean '{hint[0]}'?)" if hint else ""))


def _merge(dc: Any, data: dict[str, Any] | None, *, where: str = "",
           warnings: list[str] | None = None,
           extra_known: tuple[str, ...] = ()) -> Any:
    """Shallow-merge a dict onto a dataclass instance. Unknown keys are
    ignored but recorded in *warnings* (they used to vanish
    silently, so a typo in a security setting failed open)."""
    if data is None:
        return dc
    if not isinstance(data, dict):
        if warnings is not None:
            warnings.append(
                f"config section '{where or type(dc).__name__}' must be a "
                f"mapping, got {type(data).__name__} - ignored")
        return dc
    fields = {f.name: f for f in dataclasses.fields(dc)
              if not f.name.startswith("_")}
    for key, value in data.items():
        k = str(key)
        if k in fields:
            setattr(dc, k, _coerce(getattr(dc, k), value,
                                   f"{where}.{k}" if where else k, warnings))
        elif k not in extra_known:
            _unknown(where or type(dc).__name__, k,
                     list(fields) + list(extra_known), warnings)
    return dc


#: Top-level YAML sections that map 1:1 onto a PryConfig dataclass field.
_SECTIONS = ("security", "mcp", "dashboard", "artifacts", "ida", "ghidra",
             "plugins", "symbols", "logging", "clients", "leases",
             "watchdog", "snapshots", "monitor", "reconstruct")


def _load_machine(alias: str, data: dict[str, Any],
                  warns: list[str]) -> MachineConfig:
    mc = MachineConfig()
    # View kinds and an explicit `views:` block are handled below; every
    # other key must be a MachineConfig field (scan:, pointer_map: ... are
    # dict-valued metadata, never views).
    flat = {k: v for k, v in data.items()
            if str(k) not in MACHINE_VIEW_KINDS and str(k) != "views"}
    _merge(mc, flat, where=f"machines.{alias}", warnings=warns,
           extra_known=MACHINE_VIEW_KINDS + ("views",))
    mc.views = {}
    blocks: dict[str, Any] = {}
    nested = data.get("views")
    if isinstance(nested, dict):
        blocks.update(nested)
    elif nested is not None:
        warns.append(f"config key 'machines.{alias}.views' must be a "
                     "mapping - ignored")
    for kind in MACHINE_VIEW_KINDS:
        if kind in data:
            blocks[kind] = data[kind]
    for kind, vdata in blocks.items():
        kind_s = str(kind)
        if kind_s not in MACHINE_VIEW_KINDS:
            warns.append(
                f"config key 'machines.{alias}.views.{kind_s}': unknown "
                f"view kind (expected one of {', '.join(MACHINE_VIEW_KINDS)})"
                " - ignored")
            continue
        if not isinstance(vdata, dict):
            warns.append(f"config key 'machines.{alias}.{kind_s}' must be "
                         "a mapping - ignored")
            continue
        tc = TargetConfig()
        _merge(tc, vdata, where=f"machines.{alias}.{kind_s}", warnings=warns)
        mc.views[kind_s] = tc
    return mc


def load_config(path: str | Path | None, *,
                log_warnings: bool = True) -> PryConfig:
    """Load the YAML config. Unknown keys / mistyped values are recorded in
    ``cfg.config_warnings`` and logged (``log_warnings=False`` skips the
    log, for a pre-read whose result is discarded)."""
    cfg = PryConfig()
    if path is None:
        return cfg
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"config root must be a mapping: {path}")
    warns = cfg._warnings
    _merge(cfg.target, raw.get("target"), where="target", warnings=warns)
    raw_targets = raw.get("targets")
    if isinstance(raw_targets, dict):
        for name, data in raw_targets.items():
            tc = TargetConfig()
            _merge(tc, data, where=f"targets.{name}", warnings=warns)
            cfg.targets[str(name)] = tc
    elif raw_targets is not None:
        warns.append("config section 'targets' must be a mapping - ignored")
    raw_machines = raw.get("machines")
    if isinstance(raw_machines, dict):
        for alias, data in raw_machines.items():
            if not isinstance(data, dict):
                warns.append(f"config section 'machines.{alias}' must be a "
                             "mapping - ignored")
                continue
            cfg.machines[str(alias)] = _load_machine(str(alias), data, warns)
            # T1.1a (PR#2): record the alias as YAML-sourced so a later
            # registry merge doesn't make this look registry-only.
            cfg._yaml_machines.add(str(alias))
    elif raw_machines is not None:
        warns.append("config section 'machines' must be a mapping - ignored")
    # Dotted targets: entries ('lab2.kernel') also encode a reviewed
    # endpoint - track their machine prefix as YAML-sourced too.
    if isinstance(raw_targets, dict):
        for name in raw_targets:
            s = str(name)
            if "." in s:
                cfg._yaml_machines.add(s.rsplit(".", 1)[0])
    for section in _SECTIONS:
        _merge(getattr(cfg, section), raw.get(section), where=section,
               warnings=warns)
    if "file_manage_default_view" in raw:
        cfg.file_manage_default_view = _coerce(
            cfg.file_manage_default_view, raw["file_manage_default_view"],
            "file_manage_default_view", warns)
    known_root = ["target", "targets", "machines",
                  "file_manage_default_view", *_SECTIONS]
    for key in raw:
        if str(key) not in known_root:
            _unknown("<root>", str(key), known_root, warns)
    if log_warnings:
        for w in warns:
            _log.warning("config %s: %s", path, w)
    return cfg
