"""mitigation policy readout tests.

Covers:
- ``process_manage(action='mitigations', pid=…)`` happy path returns
  the flattened dict shape documented in slice 01 Feature 6.
- ``verify_mitigations=True`` on ``action='list'`` fans out one RPC per
  row with concurrency cap 16 and attaches the ``mitigations`` sub-dict
  per row + a sibling meta block with cache_hits/probed counters.
- ``mitigations_cache_only=True`` short-circuits non-cached rows.
- PPL target on umagent view surfaces ``mitigations_source='denied'``.
- An older agent (no MitigationsStub) returns ``kind='agent_version'``.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from pry.mcp.tools import process as _process_tool


_SEED_PIDS = [1000, 1001, 1002]


class _FakeAgentFull:
    """Full-feature fake: mitigations stub present, happy decoder."""

    def __init__(self) -> None:
        self.mitigations = object()
        self.last_pids: list[int] = []
        # Per-pid canned rows the fake returns.
        self._rows: dict[int, dict[str, Any]] = {}
        for p in _SEED_PIDS:
            self._rows[p] = {
                "pid": p, "create_time_100ns": 132_000_000_000_000_000 + p,
                "error": "", "cache_hit": False,
                "mitigations_source": "live",
                "mitigations_cache_hit": False,
                "mitigations_error": "",
                "dep": {"enable": True,
                        "atl_thunk_emulation_disable": False,
                        "permanent": True},
                "aslr": {"bottom_up": True, "force_relocate": False,
                         "high_entropy": True,
                         "disallow_stripped_images": False,
                         "bottom_up_high_entropy": True,
                         "high_address_space_override": False},
                "cfg": {"enable": True, "strict_mode": False,
                        "suppress_exports": False,
                        "export_dynamic_invalidation": False},
                "strict_handle_check": True,
                "system_call_disable": {"disable": False,
                                        "allow_win32k_system_calls": False},
                "extension_points_disabled": False,
                "dynamic_code": {"prohibit": False, "allow_thread_opt_out": False,
                                 "allow_remote_downgrade": False, "audit": False,
                                 "audit_allow_thread_opt_out": False,
                                 "audit_allow_remote_downgrade": False},
                "binary_signature": {"micro_signed_only": False,
                                     "store_signed_only": False,
                                     "mitigation_opt_in": False,
                                     "mitigation_audit_mask": 0,
                                     "oem_signed_loosened_to_wintcb": False},
                "font_disable": {"disable_non_system_fonts": False,
                                 "audit": False},
                "image_load": {"no_remote_images": True,
                               "no_low_mandatory_label_images": True,
                               "prefer_system32": True,
                               "audit_no_remote_images": False,
                               "audit_no_low_mandatory_label_images": False,
                               "audit_prefer_system32": False},
                "user_shadow_stack": {"enabled": True,
                                      "audit": False,
                                      "strict_mode": False,
                                      "set_context_ip_validation": True,
                                      "set_context_ip_validation_relaxed_mode": False,
                                      "block_non_cet_binaries": True,
                                      "block_non_cet_binaries_non_ehcont": False,
                                      "cet_dynamic_apis_out_of_proc_only": False,
                                      "audit_set_context_ip_validation": False,
                                      "audit_block_non_cet_binaries": False},
                "payload_restriction": {
                    "enable_export_address_filter": False,
                    "enable_export_address_filter_plus": False,
                    "audit_export_address_filter": False,
                    "audit_export_address_filter_plus": False,
                    "enable_import_address_filter": False,
                    "audit_import_address_filter": False,
                    "enable_rop_stack_pivot": False,
                    "audit_rop_stack_pivot": False,
                    "enable_rop_caller_check": False,
                    "audit_rop_caller_check": False,
                    "enable_rop_sim_exec": False,
                    "audit_rop_sim_exec": False},
                "side_channel_isolation": {
                    "smt_branch_target_isolation": False,
                    "isolate_security_domain": False,
                    "disable_page_combine": False,
                    "speculative_store_bypass_disable": False},
                "redirection_trust": {"enforce": False, "audit": False},
            }

    async def verify_mitigations(self, pids, *, force_recheck: bool = False):
        self.last_pids.append(list(pids))
        rows = [self._rows[p] for p in pids if p in self._rows]
        return {"ok": True, "rows": rows,
                "cache_hits": 0, "probed": len(rows)}

    async def mem_processes(self, with_cmdline: bool, full: bool):
        return {"processes": [{"pid": p, "image_name": f"proc-{p}.exe"}
                              for p in _SEED_PIDS],
                "source": "fake-agent"}


class _FakeAgentNoStub:
    """Older agent: no mitigations stub (verify_mitigations degrades)."""

    def __init__(self) -> None:
        self.mitigations = None

    async def verify_mitigations(self, pids, *, force_recheck: bool = False):
        return {"ok": False, "kind": "agent_version",
                "error": ("verify_mitigations: older agent/umagent "
                          "(Mitigations service missing)"),
                "rows": [], "cache_hits": 0, "probed": 0}

    async def mem_processes(self, with_cmdline: bool, full: bool):
        return {"processes": [{"pid": p, "image_name": f"proc-{p}.exe"}
                              for p in _SEED_PIDS],
                "source": "fake-agent"}


class _FakeAgentPpl:
    """A target where every row surfaces source='denied' (umagent-PPL)."""

    def __init__(self) -> None:
        self.mitigations = object()

    async def verify_mitigations(self, pids, *, force_recheck: bool = False):
        rows = []
        for p in pids:
            r = {"pid": p, "create_time_100ns": 0,
                 "error": "denied_ppl: open failed",
                 "cache_hit": False,
                 "mitigations_source": "denied",
                 "mitigations_cache_hit": False,
                 "mitigations_error": "denied_ppl: open failed",
                 "dep": {"enable": False, "atl_thunk_emulation_disable": False,
                         "permanent": False},
                 "aslr": {"bottom_up": False, "force_relocate": False,
                          "high_entropy": False,
                          "disallow_stripped_images": False,
                          "bottom_up_high_entropy": False,
                          "high_address_space_override": False},
                 "cfg": {"enable": False, "strict_mode": False,
                         "suppress_exports": False,
                         "export_dynamic_invalidation": False}}
            rows.append(r)
        return {"ok": True, "rows": rows, "cache_hits": 0, "probed": 0}

    async def mem_processes(self, with_cmdline: bool, full: bool):
        return {"processes": [{"pid": p, "image_name": f"proc-{p}.exe"}
                              for p in _SEED_PIDS],
                "source": "fake-agent"}


def _run(coro):
    return asyncio.run(coro)


# -----------------------------------------------------------------------
# handle_mitigations — happy path
# -----------------------------------------------------------------------


def test_mitigations_happy_path() -> None:
    out = _run(_process_tool.handle_mitigations(
        ctx=None, c=_FakeAgentFull(), pid=1000))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["pid"] == 1000
    assert r["dep"]["enable"] is True
    assert r["aslr"]["high_entropy"] is True
    assert r["cfg"]["enable"] is True
    assert r["user_shadow_stack"]["enabled"] is True
    assert r["mitigations_source"] == "live"
    assert r["coverage"]["status"] == "complete"


# -----------------------------------------------------------------------
# handle_mitigations — older agent degrades
# -----------------------------------------------------------------------


def test_mitigations_agent_version_degrades() -> None:
    out = _run(_process_tool.handle_mitigations(
        ctx=None, c=_FakeAgentNoStub(), pid=1000))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "agent_version"
    assert "Mitigations service missing" in r["error"]


# -----------------------------------------------------------------------
# handle_mitigations — PPL fallback (umagent view)
# -----------------------------------------------------------------------


def test_mitigations_ppl_marks_partial_coverage() -> None:
    out = _run(_process_tool.handle_mitigations(
        ctx=None, c=_FakeAgentPpl(), pid=1000))
    r = json.loads(out)
    assert r["ok"] is True
    assert r["mitigations_source"] == "denied"
    assert r["coverage"]["status"] == "partial"
    assert "denied_ppl" in r["coverage"].get("limits", [])


# -----------------------------------------------------------------------
# handle_mitigations — bad pid
# -----------------------------------------------------------------------


def test_mitigations_rejects_zero_pid() -> None:
    out = _run(_process_tool.handle_mitigations(
        ctx=None, c=_FakeAgentFull(), pid=0))
    r = json.loads(out)
    assert r["ok"] is False
    assert r["kind"] == "bad_arg"


# -----------------------------------------------------------------------
# verify_mitigations=True list enrichment
# -----------------------------------------------------------------------


class _FakeCtx:
    """Minimal ctx with just the mcp_max_items shim."""
    class _Cfg:
        def mcp_max_items(self):
            return 1000
    cfg = _Cfg()


def _rows_of(body):
    data = body.get("data") or {}
    return data.get("items") or body.get("items") or []


def test_list_verify_mitigations_fanout_attaches_rows() -> None:
    fake = _FakeAgentFull()
    body = _run(_process_tool.handle_list(
        ctx=_FakeCtx(), c=fake,
        with_cmdline=False, verify_mitigations=True,
        mitigations_cache_only=False,
        filter=None, fields=None, summary=False,
        limit=0, offset=0, max_results=100))
    rows = _rows_of(body)
    assert len(rows) == len(_SEED_PIDS)
    for r in rows:
        assert "mitigations" in r
        assert r["mitigations"]["dep"]["enable"] is True
        assert r["mitigations"]["mitigations_source"] == "live"
    meta = body.get("mitigations")
    assert meta is not None
    assert meta["ok"] is True
    assert meta["probed"] == 3
    # One batched RPC per pid.
    assert len(fake.last_pids) == 3


def test_list_verify_mitigations_cache_only_skips_wire() -> None:
    fake = _FakeAgentFull()
    # Fresh LRU so cache_only genuinely misses.
    _process_tool._MITIGATIONS_LRU.clear()
    body = _run(_process_tool.handle_list(
        ctx=_FakeCtx(), c=fake,
        with_cmdline=False, verify_mitigations=True,
        mitigations_cache_only=True,
        filter=None, fields=None, summary=False,
        limit=0, offset=0, max_results=100))
    rows = _rows_of(body)
    for r in rows:
        assert r["mitigations"]["mitigations_source"] == "cache_miss"
    # Zero RPCs made since cache was empty + cache_only honored.
    assert fake.last_pids == []


def test_list_verify_mitigations_agent_missing_marks_meta_not_ok() -> None:
    fake = _FakeAgentNoStub()
    body = _run(_process_tool.handle_list(
        ctx=_FakeCtx(), c=fake,
        with_cmdline=False, verify_mitigations=True,
        mitigations_cache_only=False,
        filter=None, fields=None, summary=False,
        limit=0, offset=0, max_results=100))
    meta = body.get("mitigations")
    assert meta is not None
    assert meta["ok"] is False
    assert "Mitigations service missing" in (meta.get("error") or "")
    rows = _rows_of(body)
    for r in rows:
        # Row still carries a mitigations dict (zero-filled) with the
        # 'denied' discriminator.
        assert r["mitigations"]["mitigations_source"] == "denied"


# -----------------------------------------------------------------------
# AgentClient mixin flattener (unit)
# -----------------------------------------------------------------------


def test_row_to_dict_flattens_proto_shape() -> None:
    from pry.agent_client.mitigations import _row_to_dict
    from pry.generated import pry_pb2 as pb
    row = pb.MitigationRow()
    row.pid = 2048
    row.create_time_100ns = 132_000_000_000_000_000
    row.cache_hit = True
    row.dep.enable = True
    row.aslr.high_entropy = True
    row.cfg.strict_mode = True
    row.user_shadow_stack.enabled = True
    out = _row_to_dict(row)
    assert out["pid"] == 2048
    assert out["cache_hit"] is True
    assert out["mitigations_source"] == "cache"
    assert out["dep"]["enable"] is True
    assert out["aslr"]["high_entropy"] is True
    assert out["cfg"]["strict_mode"] is True
    assert out["user_shadow_stack"]["enabled"] is True
