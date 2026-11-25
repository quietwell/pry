"""Host / Agent-service methods (status, driver, host_info, watchdog)."""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb
from .wire import proto_to_dict, status_dict


class HostMixin:
    # ---------------------------------------------------------------- Agent ----

    async def status(self) -> dict[str, Any]:
        msg = await self._call(self.agent.Status, pb.StatusRequest())
        d = proto_to_dict(msg)
        d["ok"] = msg.status.ok
        # MessageToDict renders uint64 (boot_epoch_ms,
        # agent_uptime_ms) as decimal strings; hand callers real ints.
        from .client import coerce_int64_fields
        coerce_int64_fields(msg, d)
        return d

    async def driver_load(self, method: str = "service", image_path: str = "") -> dict[str, Any]:
        req = pb.DriverLoadRequest(
            method=pb.DriverLoadRequest.MANUAL_MAP if method == "manual_map" else pb.DriverLoadRequest.SERVICE,
            image_path=image_path,
        )
        st = await self._call(self.agent.DriverLoad, req)
        return status_dict(st)

    async def driver_unload(self, delete_service: bool = True) -> dict[str, Any]:
        st = await self._call(self.agent.DriverUnload, pb.DriverUnloadRequest(delete_service=delete_service))
        return status_dict(st)

    # reliable Windows-API reboot verb. Thin wrapper over the
    # agent-side InitiateShutdownW (plus ExitWindowsEx for logoff,
    # AbortSystemShutdownW for the abort mode). The agent snapshots
    # the pre-reboot (boot_epoch_ms, agent_instance_id) FIRST and
    # returns them in every response — on success the connection
    # will tear down shortly after.
    async def reboot(self, *, mode: str = "reboot", delay_s: int = 0,
                     force: bool = False, force_if_hung: bool = False,
                     reason: str = "", reason_code: int = 0,
                     wait_pre_shutdown: bool = False) -> dict[str, Any]:
        if not hasattr(pb, "RebootRequest") or not hasattr(self.agent, "Reboot"):
            return {"ok": False, "kind": "agent_version",
                    "error": ("reboot: agent predates the Reboot RPC — "
                              "rebuild + redeploy the agent")}
        _MODE_MAP = {
            "reboot":   pb.RebootRequest.REBOOT,
            "restart":  pb.RebootRequest.REBOOT,   # alias
            "shutdown": pb.RebootRequest.SHUTDOWN,
            "poweroff": pb.RebootRequest.POWEROFF,
            "power_off": pb.RebootRequest.POWEROFF,
            "logoff":   pb.RebootRequest.LOGOFF,
            "abort":    pb.RebootRequest.ABORT,
            "":         pb.RebootRequest.REBOOT,
        }
        mode_key = str(mode or "").strip().lower()
        if mode_key not in _MODE_MAP:
            return {"ok": False, "kind": "bad_arg",
                    "error": (f"reboot: unknown mode {mode!r} — "
                              "expected one of reboot|shutdown|poweroff|"
                              "logoff|abort")}
        req = pb.RebootRequest(
            mode=_MODE_MAP[mode_key],
            delay_s=int(delay_s or 0),
            force=bool(force),
            force_if_hung=bool(force_if_hung),
            reason=str(reason or ""),
            reason_code=int(reason_code or 0),
            wait_pre_shutdown=bool(wait_pre_shutdown),
        )
        msg = await self._call(self.agent.Reboot, req)
        return {
            "ok": bool(msg.ok),
            "boot_epoch_ms_at_issue": int(msg.boot_epoch_ms_at_issue),
            "agent_instance_id_at_issue": str(msg.agent_instance_id_at_issue),
            "win32_error": int(msg.win32_error),
            "message": str(msg.message),
            "mode_applied": int(msg.mode_applied),
            "delay_s_applied": int(msg.delay_s_applied),
        }

    async def self_update(self, service_name: str, exe_path: str, staged_path: str,
                          sha256: str = "", listen_port: str = "") -> dict[str, Any]:
        """Detached swap-and-restart of a service binary on the target. The
        agent spawns an updater script that stops the service, kills any
        process still holding the image, quarantines the old exe under prev/,
        promotes `staged_path`, restarts, port-checks, and rolls back on
        failure. The call returns before the service actually goes away."""
        if not hasattr(pb, "SelfUpdateRequest") or not hasattr(self.agent, "SelfUpdate"):
            return {"ok": False,
                    "error": "self_update: agent predates the SelfUpdate RPC — "
                             "use exec-based swap or rebuild the agent"}
        st = await self._call(self.agent.SelfUpdate, pb.SelfUpdateRequest(
            service_name=service_name, exe_path=exe_path, staged_path=staged_path,
            sha256=sha256, listen_port=listen_port))
        return status_dict(st)

    async def host_info(self, include_security_products: bool = False,
                        include_hardware: bool = True) -> dict[str, Any]:
        """v8: broad target-machine fingerprint. Identity, full OS release
        (product name / UBR / display version), security posture (secure
        boot, VBS, driver blocklist, LSA-PPL, CPU features, kernel
        debugger), optional hardware/hypervisor + WSC security products.

        Every security-posture bit carries a `<name>_source` sibling
        ("driver" > "registry" > "api" > "unknown") so the caller can tell
        confidence apart. `probe_errors` lists probes that couldn't answer.

        Older agents that don't know Agent.HostInfo get a clear
        `{ok:false, error:"agent < v8 ..."}` — a v7 orchestrator survives
        against a v6 agent, and vice versa.
        """
        if not hasattr(pb, "HostInfoRequest") or not hasattr(self.agent, "HostInfo"):
            return {"ok": False,
                    "error": "host_info: agent < v8 (Agent.HostInfo missing)"}
        req = pb.HostInfoRequest(
            include_security_products=include_security_products,
            include_hardware=include_hardware,
        )
        msg = await self._call(self.agent.HostInfo, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        # We don't use proto_to_dict here because the response is deeply
        # non-uniform (grouped identity/OS/posture/hardware/uptime) and
        # the orchestrator's confidence envelope wants raw pairs.
        def _flag(v, src):
            return {"value": bool(v), "source": src or "unknown"}
        return {
            "ok": True,
            "identity": {
                "computer_name": msg.computer_name,
                "dns_hostname": msg.dns_hostname,
                "domain": msg.domain,
                "logged_on_user": msg.logged_on_user,
                "agent_run_as": msg.agent_run_as,
                "is_elevated": msg.is_elevated,
            },
            "os": {
                "product_name": msg.product_name,
                "edition_id": msg.edition_id,
                "display_version": msg.display_version,
                "release_id": msg.release_id,
                "build_major": msg.build_major,
                "build_ubr": msg.build_ubr,
                "full_build_string": msg.full_build_string,
                "install_date": msg.install_date,
                "boot_time": msg.boot_time,
                "timezone": msg.timezone,
                "arch": msg.arch,
            },
            "security": {
                "testsigning": _flag(msg.testsigning, msg.testsigning_source),
                "hvci": _flag(msg.hvci, msg.hvci_source),
                "secureboot": _flag(msg.secureboot, msg.secureboot_source),
                "kernel_debugger": _flag(msg.kernel_debugger, msg.kernel_debugger_source),
                "vbs_enabled": _flag(msg.vbs_enabled, msg.vbs_source),
                "credential_guard": _flag(msg.credential_guard, msg.credential_guard_source),
                "driver_blocklist_on": _flag(msg.driver_blocklist_on, msg.driver_blocklist_source),
                "lsa_protected": _flag(msg.lsa_protected, msg.lsa_protected_source),
                "smep": msg.smep,
                "smap": msg.smap,
                "cet_shstk": msg.cet_shstk,
                "patchguard_state": msg.patchguard_state,
                # KVA shadow (Meltdown mitigation). Only
                # populated when the agent was rebuilt with the probe; older
                # agents leave the proto fields at their defaults (bool
                # false, empty source) so we surface as source='unknown'.
                "kva_shadow": _flag(getattr(msg, "kva_shadow", False),
                                     getattr(msg, "kva_shadow_source", "") or "unknown"),
            },
            "hardware": {
                "cpu_brand": msg.cpu_brand,
                "cpu_cores": msg.cpu_cores,
                "cpu_logical": msg.cpu_logical,
                "phys_mem_bytes": msg.phys_mem_bytes,
                "hypervisor_vendor": msg.hypervisor_vendor,
                "is_vm": msg.is_vm,
            },
            "uptime": {
                "pc_uptime_ms": msg.pc_uptime_ms,
                "agent_uptime_ms": msg.agent_uptime_ms,
                "service_uptime_ms": msg.service_uptime_ms,
            },
            "security_products": [
                {"name": p.name, "state": p.state,
                 "version": p.version, "kind": p.kind}
                for p in msg.security_products
            ],
            "probe_errors": list(msg.probe_errors),
            # adapter list for registry self-heal /
            # rediscover. Empty on agents that predate the field.
            "ipv4": [
                {"adapter": a.adapter, "address": a.address,
                 "prefix_len": a.prefix_len, "origin": a.origin,
                 "gateway": a.gateway, "mac": a.mac, "up": a.up}
                for a in (getattr(msg, "ipv4", None) or [])
            ],
        }

    async def recent_ops_agent(self, limit: int = 32,
                                include_prior: bool = True) -> dict[str, Any]:
        """Read the agent-side persistent breadcrumb ring (v5). `prior`
        entries are from the previous agent lifetime — anything marked
        `wedged` there is a call that was in flight when the agent died.
        """
        if not hasattr(self.agent, "RecentOps"):
            return {"ok": False,
                    "error": "recent_ops_agent: agent < v5 (Agent.RecentOps missing)"}
        req = pb.RecentOpsRequest(limit=limit, include_prior=include_prior)
        msg = await self._call(self.agent.RecentOps, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        def _dump(entries):
            return [{
                "t_start_us": e.t_start_us, "t_end_us": e.t_end_us,
                "latency_us": e.latency_us,
                "ioctl_code": e.ioctl_code, "arg_summary": e.arg_summary,
                "status_code": e.status_code, "status_kind": e.status_kind,
            } for e in entries]
        return {
            "ok": True,
            "agent_start_epoch_ms": msg.agent_start_epoch_ms,
            "now_epoch_ms": msg.now_epoch_ms,
            "current": _dump(msg.current),
            "prior": _dump(msg.prior),
        }

    # ------------------------------------------------------------- Watchdog ----
    # v8: driver-backed wedge-detector. Every call is unary; the actual
    # armed-deadline state lives in the driver. If the agent predates v8 we
    # return a named error so the MCP tool can surface it verbatim.

    def _wdg_missing(self, action: str) -> dict[str, Any]:
        return {"ok": False,
                "error": f"watchdog {action}: agent < v8 (Watchdog service missing)",
                "hint": "rebuild + redeploy agent+driver for the ABI v8 watchdog"}

    async def watchdog_arm(self, wid: int, deadline_ms: int, *,
                           bugcheck_code: int = 0, flags: int = 0,
                           cookie: int = 0, label: str = "") -> dict[str, Any]:
        if self.watchdog is None:
            return self._wdg_missing("arm")
        req = pb.WdgArmRequest(id=int(wid), deadline_ms=int(deadline_ms),
                               bugcheck_code=int(bugcheck_code), flags=int(flags),
                               cookie=int(cookie), label=str(label)[:31])
        st = await self._call(self.watchdog.Arm, req)
        return {"ok": st.status.ok, "error": st.status.error,
                "id": int(wid), "deadline_ms": int(deadline_ms)}

    async def watchdog_kick(self, wid: int, *, deadline_ms: int = 0,
                            cookie: int = 0) -> dict[str, Any]:
        if self.watchdog is None:
            return self._wdg_missing("kick")
        req = pb.WdgKickRequest(id=int(wid), deadline_ms=int(deadline_ms),
                                cookie=int(cookie))
        msg = await self._call(self.watchdog.Kick, req)
        return {"ok": msg.status.ok, "error": msg.status.error,
                "id": int(wid), "kick_count": int(msg.kick_count),
                "last_kick_us": int(msg.last_kick_us),
                "deadline_us": int(msg.deadline_us)}

    async def watchdog_disarm(self, wid: int) -> dict[str, Any]:
        if self.watchdog is None:
            return self._wdg_missing("disarm")
        req = pb.WdgDisarmRequest(id=int(wid))
        st = await self._call(self.watchdog.Disarm, req)
        return {"ok": st.ok, "error": st.error, "id": int(wid)}

    async def watchdog_list(self) -> dict[str, Any]:
        if self.watchdog is None:
            return self._wdg_missing("list")
        msg = await self._call(self.watchdog.List, pb.WdgListRequest())
        entries = []
        for e in msg.entries:
            entries.append({
                "id": int(e.id),
                "bugcheck_code": int(e.bugcheck_code),
                "deadline_us": int(e.deadline_us),
                "last_kick_us": int(e.last_kick_us),
                "kick_count": int(e.kick_count),
                "cookie": int(e.cookie),
                "armed_us": int(e.armed_us),
                "label": str(e.label),
                "remaining_ms": int(e.remaining_ms),
            })
        return {"ok": msg.status.ok, "error": msg.status.error,
                "now_us": int(msg.now_us), "count": len(entries),
                "entries": entries}

    # --------------------------------------------- SI #21 self-protection ----

    def _selfprot_missing(self, action: str) -> dict[str, Any]:
        return {"ok": False,
                "error": f"selfprot {action}: older agent "
                         "(SelfProt service missing)",
                "hint": "rebuild + redeploy agent + driver for the SI #21 "
                        "self-protection toggle"}

    async def selfprot_config(self, enable: int, *, flags: int = 0,
                              process_access_keep: int = 0,
                              thread_access_keep: int = 0,
                              protected_pids: list[int] | None = None,
                              disable_token: int = 0) -> dict[str, Any]:
        """Install/tear-down/refresh the driver's ObRegisterCallbacks pre-op.
        ``enable``: 0 off (needs flag bit1 + matching disable_token when the
        caller PID isn't on the protected list), 1 install, 2 refresh pids.
        See driver/src/SelfProt.c for the flag/keep-mask semantics."""
        if getattr(self, "selfprot", None) is None:
            return self._selfprot_missing("config")
        if not hasattr(pb, "SelfProtConfigRequest"):
            return self._selfprot_missing("config")
        req = pb.SelfProtConfigRequest(
            enable=int(enable),
            flags=int(flags),
            process_access_keep=int(process_access_keep),
            thread_access_keep=int(thread_access_keep),
            disable_token=int(disable_token),
        )
        for p in (protected_pids or []):
            if int(p) > 0:
                req.protected_pids.append(int(p))
        msg = await self._call(self.selfprot.Config, req)
        return {"ok": msg.status.ok,
                "error": msg.status.error if not msg.status.ok else None,
                "state": int(msg.state),
                "installed": bool(msg.installed),
                "altitude": int(msg.altitude),
                "protected_pids": int(msg.protected_pids),
                "disable_token": int(msg.disable_token)}

    async def selfprot_status(self) -> dict[str, Any]:
        if getattr(self, "selfprot", None) is None:
            return self._selfprot_missing("status")
        if not hasattr(pb, "SelfProtStatusRequest"):
            return self._selfprot_missing("status")
        msg = await self._call(self.selfprot.Status, pb.SelfProtStatusRequest())
        return {"ok": msg.status.ok,
                "error": msg.status.error if not msg.status.ok else None,
                "state": int(msg.state),
                "installed": bool(msg.installed),
                "altitude": int(msg.altitude),
                "protected_pids": int(msg.protected_pids),
                "flags": int(msg.flags),
                "process_access_keep": int(msg.process_access_keep),
                "thread_access_keep": int(msg.thread_access_keep),
                "preop_hits": int(msg.preop_hits),
                "stripped": int(msg.stripped),
                "bypassed": int(msg.bypassed)}

    # ------------------------------- SI #8 signer / Authenticode column ----

    async def verify_signatures(self, paths: list[str], *,
                                 force_recheck: bool = False
                                 ) -> dict[str, Any]:
        """Call the agent/umagent's Signatures.Verify RPC for the given
        file paths. Returns a dict with ``rows`` (list of {path, signer,
        issuer, signing_level, is_signed, catalog, cache_timestamp_100ns,
        cache_hit, error}) plus ``cache_hits``/``probed`` counters.
        Older agents (no Signatures service) return
        ``{ok:false, kind:"agent_version", ...}`` so callers can degrade
        gracefully without raising.
        """
        if getattr(self, "signatures", None) is None:
            return {"ok": False, "kind": "agent_version",
                    "error": ("verify_signatures: older agent/umagent "
                              "(Signatures service missing)"),
                    "rows": [], "cache_hits": 0, "probed": 0}
        req = pb.VerifySignaturesRequest(
            paths=[str(p) for p in paths if p],
            force_recheck=bool(force_recheck),
        )
        msg = await self._call(self.signatures.Verify, req)
        if not msg.status.ok:
            return {"ok": False, "kind": "verify_signatures_failed",
                    "error": msg.status.error,
                    "rows": [], "cache_hits": 0, "probed": 0}
        rows = [{
            "path": r.path,
            "signer": r.signer,
            "issuer": r.issuer,
            "signing_level": r.signing_level,
            "is_signed": bool(r.is_signed),
            "catalog": bool(r.catalog),
            "cache_timestamp_100ns": int(r.cache_timestamp_100ns),
            "cache_hit": bool(r.cache_hit),
            "error": r.error,
        } for r in msg.rows]
        return {"ok": True, "rows": rows,
                "cache_hits": int(msg.cache_hits),
                "probed": int(msg.probed)}

    # -------------------------- SI #14 process-snapshot minidump ----

    async def process_dump(self, *, pid: int, flags: int = 0,
                            output_path: str = "",
                            use_snapshot: bool = True) -> dict[str, Any]:
        """Call the agent/umagent's ProcessDump.CreateDump RPC.

        Captures a minidump of ``pid`` via PssCaptureSnapshot +
        MiniDumpWriteDump with a stepped access-mask ladder
        (PROCESS_ALL_ACCESS -> VM_READ|QUERY_INFORMATION|DUP_HANDLE ->
        VM_READ|QUERY_INFORMATION -> QUERY_LIMITED_INFORMATION).

        * ``flags`` — MINIDUMP_TYPE bitmask; 0 means default (full memory
          + thread info + handle data + unloaded modules + full memory
          info + token information).
        * ``output_path`` — absolute Win32 path; empty uses
          ``%TEMP%\\pry\\dumps\\pid_<pid>_<unix-ms>.dmp``.
        * ``use_snapshot`` — true (default) runs the PSS path; false
          runs MiniDumpWriteDump directly on the open handle.

        PP targets (PP/PPL) surface ``kind='pp_target_requires_feature_23'``
        until SI feature #23 lands in Wave 3.

        Older agents (no ProcessDump service) return
        ``{ok:false, kind:"agent_version", ...}`` so callers can degrade
        gracefully without raising.
        """
        if getattr(self, "pdump", None) is None or \
                not hasattr(pb, "ProcessDumpRequest"):
            return {"ok": False, "kind": "agent_version",
                    "error": ("process_dump: older agent/umagent "
                              "(ProcessDump service missing)")}
        req = pb.ProcessDumpRequest(
            pid=int(pid or 0),
            flags=int(flags or 0),
            output_path=str(output_path or ""),
            use_snapshot=bool(use_snapshot),
        )
        msg = await self._call(self.pdump.CreateDump, req)
        return {
            "ok": bool(msg.status.ok),
            "error": msg.status.error if not msg.status.ok else "",
            "kind": getattr(msg, "kind", ""),
            "path": msg.path,
            "size": int(msg.size),
            "sha256": msg.sha256,
            "access_mask_used": int(msg.access_mask_used),
            "snapshot_used": bool(msg.snapshot_used),
        }

    # -------------------- live kernel dump ----

    async def live_kernel_dump(self, *, output_path: str = "",
                               flags: list[str] | None = None,
                               compression: bool = False,
                               allow_cancel: bool = False,
                               ) -> dict[str, Any]:
        """Call ``ProcessDump.CreateLiveKernelDump`` on the agent/umagent view.

        Writes a live kernel dump via
        ``NtSystemDebugControl(SysDbgGetLiveKernelDump)`` to the TARGET's
        disk — the orchestrator only sees ``{path, size, sha256,
        flags_used_mask}``. Umagent-only; the agent-side service
        answers ``kind='not_supported'`` with ``hint='use name=user'``.

        * ``output_path`` — absolute Win32 path on the target; empty uses
          ``%SystemRoot%\\LiveKernelDumps\\pry_<unix-ms>.dmp``.
        * ``flags`` — slice doc §Feature 5 names (``hypervisor_pages`` |
          ``usermode`` | ``stack_only`` | ``compression`` |
          ``page_table_only``). Unknown names echo in ``flags_unknown``.
        * ``compression`` — convenience bit; OR'd with the flag-named
          ``compression`` entry.
        * ``allow_cancel`` — register a cancel event with SysDbg so a
          client disconnect can tear down the capture mid-dump.

        Older agents (no ``CreateLiveKernelDump`` RPC) return
        ``{ok:false, kind:'agent_version'}`` so callers can degrade
        gracefully without raising.
        """
        if getattr(self, "pdump", None) is None or \
                not hasattr(pb, "CreateLiveKernelDumpRequest"):
            return {"ok": False, "kind": "agent_version",
                    "error": ("live_kernel_dump: older agent/umagent "
                              "(ProcessDump.CreateLiveKernelDump missing)")}
        req = pb.CreateLiveKernelDumpRequest(
            output_path=str(output_path or ""),
            flags=list(flags or []),
            compression=bool(compression),
            allow_cancel=bool(allow_cancel),
        )
        msg = await self._call(self.pdump.CreateLiveKernelDump, req)
        return {
            "ok": bool(msg.status.ok),
            "error": msg.status.error if not msg.status.ok else "",
            "kind": getattr(msg, "kind", ""),
            "path": msg.path,
            "size": int(msg.size),
            "sha256": msg.sha256,
            "flags_used_mask": int(getattr(msg, "flags_used_mask", 0)),
            "flags_unknown": list(getattr(msg, "flags_unknown", []) or []),
            "error_detail": str(getattr(msg, "error_detail", "") or ""),
        }

    # ------------------------------------------------------ Screen (v15) ----

    async def capture_screen(self, mode: str = "desktop", display_id: str = "",
                             hwnd: int = 0, pid: int = 0,
                             window_title: str = "", process_name: str = "",
                             query: str = "", max_dimension: int = 1920,
                             include_hidden: bool = False,
                             include_details: bool = True) -> dict[str, Any]:
        """Desktop/window screenshot (PNG bytes inline) + window telemetry JSON."""
        req = pb.ScreenCaptureRequest(
            mode=mode,
            display_id=display_id,
            hwnd=hwnd,
            pid=pid,
            window_title=window_title,
            process_name=process_name,
            query=query,
            max_dimension=max_dimension,
            include_hidden=include_hidden,
            include_details=include_details,
        )
        msg = await self._call(self.agent.CaptureScreen, req)
        return {
            "ok": msg.status.ok,
            "error": msg.status.error if not msg.status.ok else None,
            "target_type": msg.target_type,
            "target_name": msg.target_name,
            "image_data": msg.image_data,
            "width": int(msg.width),
            "height": int(msg.height),
            "timestamp_unix_ms": int(msg.timestamp_unix_ms),
            "windows_json": msg.windows_json,
        }

    async def list_windows(self, pid: int = 0, process_name: str = "",
                           query: str = "", include_hidden: bool = False,
                           include_details: bool = True,
                           include_children: bool = False,
                           include_props: bool = False) -> dict[str, Any]:
        """Window list from the session-1 worker (windows_json is authoritative).

        ``include_children`` recurses
        ``EnumChildWindows`` under every top-level HWND; ``include_props``
        attaches an ``EnumPropsExW`` walk per node. Default off keeps
        the pre-slice-03 wire shape bit-identical.
        """
        req_kwargs: dict[str, Any] = dict(
            pid=pid,
            process_name=process_name,
            query=query,
            include_hidden=include_hidden,
            include_details=include_details,
        )
        if "include_children" in pb.WindowListRequest.DESCRIPTOR.fields_by_name:
            req_kwargs["include_children"] = bool(include_children)
        if "include_props" in pb.WindowListRequest.DESCRIPTOR.fields_by_name:
            req_kwargs["include_props"] = bool(include_props)
        req = pb.WindowListRequest(**req_kwargs)
        msg = await self._call(self.agent.ListWindows, req)
        return {
            "ok": msg.status.ok,
            "error": msg.status.error if not msg.status.ok else None,
            "total_windows": int(msg.total_windows),
            "windows_json": msg.windows_json,
        }

    # ---- EnumPropsExW + window tree ----

    async def list_window_props(self, hwnd: int,
                                 include_values: bool = True,
                                 ) -> dict[str, Any]:
        """Enumerate EnumPropsExW entries on a single HWND."""
        if not hasattr(pb, "ListWindowPropsRequest") or \
                not hasattr(self.agent, "ListWindowProps"):
            return {"ok": False, "kind": "agent_version",
                    "error": ("list_window_props: older agent "
                              "(Agent.ListWindowProps missing)"),
                    "props": []}
        req = pb.ListWindowPropsRequest(hwnd=int(hwnd),
                                         include_values=bool(include_values))
        msg = await self._call(self.agent.ListWindowProps, req)
        return {
            "ok": bool(msg.status.ok),
            "error": msg.status.error if not msg.status.ok else "",
            "hwnd": int(msg.hwnd),
            "props": [proto_to_dict(p) for p in msg.props],
        }

    async def get_window_tree(self, hwnd: int = 0, pid: int = 0,
                               max_depth: int = 12,
                               include_props: bool = False,
                               ) -> dict[str, Any]:
        """Parent/child/owner tree rooted at HWND (0 = GetDesktopWindow())."""
        if not hasattr(pb, "GetWindowTreeRequest") or \
                not hasattr(self.agent, "GetWindowTree"):
            return {"ok": False, "kind": "agent_version",
                    "error": ("get_window_tree: older agent "
                              "(Agent.GetWindowTree missing)"),
                    "root": None}
        req = pb.GetWindowTreeRequest(hwnd=int(hwnd), pid=int(pid),
                                       max_depth=int(max_depth),
                                       include_props=bool(include_props))
        msg = await self._call(self.agent.GetWindowTree, req)
        return {
            "ok": bool(msg.status.ok),
            "error": msg.status.error if not msg.status.ok else "",
            "root": proto_to_dict(msg.root) if msg.HasField("root") else None,
        }
