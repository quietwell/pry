"""CPU tool registration for the pry MCP server (PR#6 T3.2).

``cpu_manage`` — per-core MSR + CPUID reader for firmware / hv debugging.
Pure reads: the driver pins to each requested logical processor via
``KeSetSystemGroupAffinityThread``, runs ``__readmsr`` / ``__cpuidex``,
and catches ``#GP`` on unimplemented MSRs with ``__try/__except`` so a
bad address surfaces as a per-row ``nt_status != STATUS_SUCCESS``
instead of a bugcheck.
"""

from __future__ import annotations

from typing import Any

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context

from ...cpu_consts import (
    KNOWN_MSRS,
    decode_cpuid,
    msr_name,
    msr_resolve,
)


CPU_ACTIONS = ["msr_read", "cpuid", "list_known_msrs", "actions"]


# Per-verb help for action='actions'. Same shape every other tool uses.
_CPU_ACTION_HELP = {
    "actions": {
        "one_liner": "this list — per-verb help",
        "key_args": "none",
        "example": "cpu_manage(action='actions')",
    },
    "msr_read": {
        "one_liner": "RDMSR on one or more cores; #GP surfaces as "
                     "per-row nt_status != STATUS_SUCCESS",
        "key_args": "msr (int|hex|name), cores ([0,1]|'all')",
        "example": "cpu_manage(action='msr_read', msr='0xC0010114', "
                   "cores='all')",
    },
    "cpuid": {
        "one_liner": "CPUID(leaf, subleaf) on one or more cores; "
                     "well-known leaves decoded (hv_present, "
                     "vmx_available, svm_available, vendor)",
        "key_args": "leaf (int|hex), subleaf, cores ([0,1]|'all')",
        "example": "cpu_manage(action='cpuid', leaf=1, cores='all')",
    },
    "list_known_msrs": {
        "one_liner": "pretty-printable MSR lookup table used by msr_read",
        "key_args": "none",
        "example": "cpu_manage(action='list_known_msrs')",
    },
}


# NTSTATUS 0 — accept both bare success and the aliased symbol in the
# response so test fixtures stay stable even when the agent surfaces a
# WARNING-shaped success later.
_STATUS_SUCCESS = 0


def _coerce_cores(cores: Any) -> tuple[list[int] | None, bool, str | None]:
    """Normalise ``cores`` into (list_or_None, all_cores, err_msg).

    Accepts: ``None`` / omitted (-> all=False, no explicit cores — the
    driver uses an empty set and the walk returns ``kind='bad_arg'``);
    the string ``"all"`` / ``"ALL"``; a list of ints; or a single int.
    Returns a human error string in the last tuple slot on bad input."""
    if cores is None or cores == "":
        return [], False, None
    if isinstance(cores, str):
        if cores.strip().lower() == "all":
            return None, True, None
        try:
            return [int(cores, 0)], False, None
        except Exception:
            return None, False, f"cores: not parseable ({cores!r})"
    if isinstance(cores, int):
        return [int(cores)], False, None
    if isinstance(cores, (list, tuple)):
        out: list[int] = []
        for c in cores:
            try:
                out.append(int(c))
            except Exception:
                return None, False, f"cores: not parseable element ({c!r})"
        return out, False, None
    return None, False, f"cores: unsupported type ({type(cores).__name__})"


def _format_msr_rows(msr_addr: int, rows: list[dict[str, Any]]
                     ) -> list[dict[str, Any]]:
    name = msr_name(msr_addr)
    out: list[dict[str, Any]] = []
    for r in rows:
        if "ok" in r and r.get("ok") is False:
            # Agent-side failure row (e.g. agent_version). Pass through
            # untouched so callers can branch on `kind`.
            out.append(r)
            continue
        entry = {
            "core": int(r.get("core", 0)),
            "value": int(r.get("value", 0)),
            "nt_status": int(r.get("nt_status", 0)),
        }
        if name:
            entry["msr_name"] = name
        if entry["nt_status"] != _STATUS_SUCCESS:
            entry["read_ok"] = False
        else:
            entry["read_ok"] = True
        out.append(entry)
    return out


def _format_cpuid_rows(leaf: int, subleaf: int,
                       rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        if "ok" in r and r.get("ok") is False:
            out.append(r)
            continue
        eax = int(r.get("eax", 0))
        ebx = int(r.get("ebx", 0))
        ecx = int(r.get("ecx", 0))
        edx = int(r.get("edx", 0))
        entry = {
            "core": int(r.get("core", 0)),
            "eax": eax, "ebx": ebx, "ecx": ecx, "edx": edx,
        }
        decoded = decode_cpuid(leaf, subleaf, eax, ebx, ecx, edx)
        if decoded:
            entry["decoded"] = decoded
        out.append(entry)
    return out


def register(mcp, ctx: Context) -> None:
    """Register the ``cpu_manage`` tool on *mcp*, using *ctx* for state."""

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def cpu_manage(action: Annotated[str, Field(json_schema_extra={"enum": CPU_ACTIONS})],
                         msr: Any = 0,
                         leaf: Any = 0,
                         subleaf: int = 0,
                         cores: Any = None,
                         name: str = "") -> str:
        """Per-core MSR + CPUID reader (firmware/hv debug surface).

        ``msr_read`` accepts an int, hex string ('0xC0010114'), or
        well-known name ('VM_CR'); unknown MSRs read normally but
        without a pretty name. ``cores`` is a list of logical-processor
        indices or the string 'all'. ``#GP`` on an unimplemented MSR
        surfaces as per-row ``nt_status != STATUS_SUCCESS`` — never a
        bugcheck. Per-verb help: cpu_manage(action='actions')."""
        args = {"action": action}

        async def run() -> Any:
            if action not in CPU_ACTIONS:
                return _unknown_action("cpu_manage", action, CPU_ACTIONS,
                                       _CPU_ACTION_HELP)
            if action == "actions":
                return _actions_help("cpu_manage", _CPU_ACTION_HELP)

            if action == "list_known_msrs":
                # Pure compute — no agent needed. Returns the lookup table
                # so callers can see what msr_read will pretty-print.
                table = {name_: f"0x{addr:08X}"
                         for addr, name_ in sorted(
                             KNOWN_MSRS.items(), key=lambda kv: kv[0])}
                return _j({
                    "ok": True,
                    "known_msrs": table,
                    "count": len(table),
                    "hint": ("cpu_manage(action='msr_read', msr='VM_CR', "
                             "cores='all') decodes the row's msr_name "
                             "automatically; any MSR not listed here still "
                             "reads normally"),
                })

            c = ctx.session.require_client(name)
            cores_list, all_cores, cerr = _coerce_cores(cores)
            if cerr is not None:
                return _j({"ok": False, "kind": "bad_arg", "error": cerr})

            if action == "msr_read":
                try:
                    msr_addr = msr_resolve(msr)
                except ValueError as exc:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": str(exc)})
                if not all_cores and not cores_list:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": ("cpu_manage msr_read: need cores="
                                         "[0,...] or cores='all'"),
                               "hint": ("cpu_manage(action='msr_read', "
                                        "msr='VM_CR', cores='all')")})
                rows = await c.msr_read(msr_addr, cores_list, all_cores)
                # Agent-side top-level error (one dict with ok=False and
                # kind set — mirrors the AgentClient error shape).
                if (isinstance(rows, list) and len(rows) == 1
                        and isinstance(rows[0], dict)
                        and rows[0].get("ok") is False):
                    return _j({**rows[0],
                               "msr": msr_addr, "msr_name": msr_name(msr_addr)})
                formatted = _format_msr_rows(msr_addr, rows)
                return _j_hex({
                    "ok": True,
                    "msr": msr_addr,
                    "msr_name": msr_name(msr_addr),
                    "cores_count": len(formatted),
                    "rows": formatted,
                })

            if action == "cpuid":
                try:
                    leaf_i = int(msr_resolve(leaf))
                except ValueError as exc:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"leaf: {exc}"})
                subleaf_i = int(subleaf) & 0xFFFFFFFF
                if not all_cores and not cores_list:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": ("cpu_manage cpuid: need cores="
                                         "[0,...] or cores='all'"),
                               "hint": ("cpu_manage(action='cpuid', "
                                        "leaf=1, cores='all')")})
                rows = await c.cpuid(leaf_i, subleaf_i, cores_list,
                                     all_cores)
                if (isinstance(rows, list) and len(rows) == 1
                        and isinstance(rows[0], dict)
                        and rows[0].get("ok") is False):
                    return _j({**rows[0], "leaf": leaf_i,
                               "subleaf": subleaf_i})
                formatted = _format_cpuid_rows(leaf_i, subleaf_i, rows)
                return _j_hex({
                    "ok": True,
                    "leaf": leaf_i,
                    "subleaf": subleaf_i,
                    "cores_count": len(formatted),
                    "rows": formatted,
                })

            return _unknown_action("cpu_manage", action, CPU_ACTIONS,
                                   _CPU_ACTION_HELP)

        return await _guard(ctx, "cpu_manage", action, args, run)
