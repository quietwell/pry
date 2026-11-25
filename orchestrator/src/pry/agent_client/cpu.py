"""CPU (MSR + CPUID) reader client methods.

PR#6 T3.2 (2026-10): per-core MSR / CPUID walk. Pure reads — the driver
pins to each requested logical processor, runs __readmsr / __cpuidex,
and catches #GP on unimplemented MSRs so a bad address surfaces as a
per-row ``nt_status != STATUS_SUCCESS`` instead of a bugcheck.
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb


class CpuMixin:
    # ---------------------------------------------------------------- MSR ----

    async def msr_read(self, msr: int, cores: list[int] | None,
                       all_cores: bool) -> list[dict[str, Any]]:
        """Read ``msr`` on each requested core.

        Returns one dict per core: ``{core, value, nt_status}``. A
        ``nt_status != 0`` row carries ``value = 0`` and typically means
        the MSR is unimplemented on that processor (driver swallowed a
        #GP under ``__try/__except``).

        ``all_cores=True`` overrides ``cores`` and walks every active
        logical processor (capped at the driver's PRY_CPU_MAX_CORES).
        """
        if getattr(self, "cpu", None) is None:
            return [{"ok": False, "error": "agent < PR#6 (Cpu service missing)",
                     "kind": "agent_version",
                     "hint": "rebuild + redeploy the agent"}]
        req = pb.MsrReadRequest(msr=int(msr) & 0xFFFFFFFF,
                                cores=[int(c) for c in (cores or [])],
                                all_cores=bool(all_cores))
        msg = await self._call(self.cpu.MsrRead, req)
        if not msg.status.ok:
            return [{"ok": False, "error": msg.status.error,
                     "kind": "read_failed"}]
        return [{"core": int(v.core), "value": int(v.value),
                 "nt_status": int(v.nt_status)}
                for v in msg.values]

    # -------------------------------------------------------------- CPUID ----

    async def cpuid(self, leaf: int, subleaf: int = 0,
                    cores: list[int] | None = None,
                    all_cores: bool = False) -> list[dict[str, Any]]:
        """Execute CPUID(leaf, subleaf) on each requested core.

        Returns one dict per core: ``{core, eax, ebx, ecx, edx}``. CPUID
        never faults on a legal operand so no nt_status surface — the
        __try/__except in the driver is defensive only.
        """
        if getattr(self, "cpu", None) is None:
            return [{"ok": False, "error": "agent < PR#6 (Cpu service missing)",
                     "kind": "agent_version",
                     "hint": "rebuild + redeploy the agent"}]
        req = pb.CpuidRequest(leaf=int(leaf) & 0xFFFFFFFF,
                              subleaf=int(subleaf) & 0xFFFFFFFF,
                              cores=[int(c) for c in (cores or [])],
                              all_cores=bool(all_cores))
        msg = await self._call(self.cpu.CpuidRead, req)
        if not msg.status.ok:
            return [{"ok": False, "error": msg.status.error,
                     "kind": "read_failed"}]
        return [{"core": int(v.core), "eax": int(v.eax), "ebx": int(v.ebx),
                 "ecx": int(v.ecx), "edx": int(v.edx)}
                for v in msg.values]
