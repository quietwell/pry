"""target_manage.reboot: reliable InitiateShutdownW + wait-back.

Covers:
- happy path: reboot(mode='reboot', wait=True) → status flips →
  ``kind='boot_recovered'`` with pre != post.
- resume path: first call hits a short caller deadline → returns
  ``kind='reboot_timeout'``; a second call with ``wait=False``
  returns ``kind='pending_boot'`` carrying a ``resume_token`` that
  itself resumes the wait loop to completion on a third call.
- security gate: ``allow_reboot=False`` → ``kind='feature_disabled'``.
- trust gate: machine trust < min_trust_actuator → refused unless
  ``force=True`` (same rails as every other actuator).
- abort mode: skips the wait loop entirely.
- feature-off message mentions the config flag by name.
"""
from __future__ import annotations

import asyncio
import json as _json
from typing import Any

from pry.caller import CLIENT_ID
from pry.clients import ClientRegistry
from pry.config import PryConfig, TargetConfig
from pry.findings import FindingsLedger
from pry.ida_bridge import IdaBridge, IdaConfigLite
from pry.leases import LeaseManager
from pry.mcp.tools import Context, build_server
from pry.ownership import OwnershipRegistry
from pry.session import Session


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _RebootClient:
    """Scripted status-sequence + Reboot RPC capture."""

    def __init__(self, statuses: list[dict], reboot_result: dict | None = None,
                 reboot_raises: Exception | None = None) -> None:
        self._statuses = list(statuses)
        self._idx = 0
        self.status_calls = 0
        self.reboot_calls: list[dict] = []
        self.last_op_ts = 1.0
        self.last_seen_ts = 0.0
        self.connected_ts = 0.0
        self.endpoint = "lab:50051"
        self._reboot_result = reboot_result or {
            "ok": True,
            "boot_epoch_ms_at_issue": 0,  # filled from current status
            "agent_instance_id_at_issue": "",
            "win32_error": 0,
            "message": "",
            "mode_applied": 1,
            "delay_s_applied": 0,
        }
        self._reboot_raises = reboot_raises

    async def status(self) -> dict[str, Any]:
        self.status_calls += 1
        row = self._statuses[min(self._idx, len(self._statuses) - 1)]
        if self._idx < len(self._statuses) - 1:
            self._idx += 1
        return dict(row)

    async def reboot(self, **kwargs: Any) -> dict[str, Any]:
        self.reboot_calls.append(dict(kwargs))
        if self._reboot_raises is not None:
            raise self._reboot_raises
        return dict(self._reboot_result)

    async def host_info(self, **_kw: Any) -> dict:
        return {"ok": False, "error": "no host_info on the fake"}

    async def recent_ops_agent(self, limit: int = 32,
                               include_prior: bool = True) -> dict:
        return {"ok": True, "agent_start_epoch_ms": 1_800_000_000_000,
                "ops": []}

    async def file_tail(self, path: str, bytes_wanted: int = 0,
                        line_align: bool = True) -> dict:
        return {"ok": True, "tail": ""}

    def recent_ops(self, n: int) -> list[dict]:
        return []

    async def file_list_dir(self, path: str,
                            recursive: bool = False) -> list[dict]:
        return []

    async def mem_modules(self, pid: int, kernel: bool) -> list[dict]:
        return []

    async def driver_load(self, method: str = "service",
                          image_path: str = "") -> dict:
        return {"ok": True, "driver_state": "DRIVER_SERVICE"}


def _status(boot: int, inst: str = "inst-1",
            drv: str = "DRIVER_SERVICE") -> dict:
    return {"ok": True, "boot_epoch_ms": boot,
            "agent_instance_id": inst, "driver_state": drv}


async def _build_ctx(tmp_path, monkeypatch, *, allow_reboot: bool = True,
                     min_trust_actuator: str = "untrusted"):
    async def _noop_probe(host, p, timeout_s: float = 3.0) -> None:
        return None
    monkeypatch.setattr("pry.session._probe_tcp", _noop_probe)
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.security.allow_reboot = bool(allow_reboot)
    cfg.security.min_trust_actuator = min_trust_actuator
    cfg.target = TargetConfig(host="127.0.0.1", port=50051)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg,
                  leases=LeaseManager(
                      publish_event=lambda ev: asyncio.create_task(
                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-reboot")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    if not isinstance(body, dict):
        return body
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


async def test_reboot_happy_path_flips_identity(tmp_path, monkeypatch):
    """pre_boot=1111, status after RPC flips to 99999 → boot_recovered."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    fake = _RebootClient(
        # The first status() call is the pre snapshot; the next flip.
        [_status(1111), _status(99999)],
        reboot_result={
            "ok": True,
            "boot_epoch_ms_at_issue": 1111,
            "agent_instance_id_at_issue": "inst-1",
            "win32_error": 0,
            "message": "",
            "mode_applied": 1,
            "delay_s_applied": 0,
        })
    ctx.session.clients["kernel"] = fake
    body = await _call(server, "target_manage",
                       {"action": "reboot", "force": True,
                        "wait": True, "recover": False,
                        "wait_timeout_s": 5.0})
    assert body["ok"] is True, body
    assert body["kind"] == "boot_recovered", body
    assert body["pre"]["boot_epoch_ms"] == 1111
    assert body["post"]["boot_epoch_ms"] == 99999
    # One Reboot RPC, with mode=reboot.
    assert len(fake.reboot_calls) == 1
    assert fake.reboot_calls[0]["mode"] == "reboot"


async def test_reboot_resume_token_round_trip(tmp_path, monkeypatch):
    """A short caller deadline returns kind=reboot_timeout (hard stop).
    Then wait=False issues a fresh RPC and returns a resume_token,
    which a third call uses to block to completion without re-RPC."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    # Status answers that keep returning the old identity — the first
    # call's wait loop runs out.
    stale_fake = _RebootClient(
        [_status(1111), _status(1111), _status(1111)],
        reboot_result={
            "ok": True,
            "boot_epoch_ms_at_issue": 1111,
            "agent_instance_id_at_issue": "inst-1",
            "win32_error": 0,
            "message": "",
            "mode_applied": 1,
            "delay_s_applied": 0,
        })
    ctx.session.clients["kernel"] = stale_fake
    body = await _call(server, "target_manage",
                       {"action": "reboot", "force": True,
                        "wait": True, "recover": False,
                        "wait_timeout_s": 0.6})
    assert body["ok"] is False, body
    assert body["kind"] == "reboot_timeout", body
    assert body["pre"]["boot_epoch_ms"] == 1111

    # Second call: wait=False → returns a resume_token immediately
    # after the RPC. The RPC call count grows by 1.
    pre_calls = len(stale_fake.reboot_calls)
    body2 = await _call(server, "target_manage",
                        {"action": "reboot", "force": True,
                         "wait": False, "recover": False})
    assert body2["ok"] is True, body2
    assert body2["kind"] == "pending_boot", body2
    assert "resume_token" in body2 and body2["resume_token"], body2
    assert len(stale_fake.reboot_calls) == pre_calls + 1

    # Third call: resume_token WITHOUT issuing a new RPC. Now flip the
    # fake status to a new boot — the resume path's inner wait loop
    # picks it up and returns boot_recovered.
    pre_calls = len(stale_fake.reboot_calls)
    stale_fake._statuses = [_status(99999)]
    stale_fake._idx = 0
    body3 = await _call(server, "target_manage",
                        {"action": "reboot", "force": True,
                         "wait": True, "recover": False,
                         "wait_timeout_s": 5.0,
                         "resume_token": body2["resume_token"]})
    assert body3["ok"] is True, body3
    assert body3["kind"] == "boot_recovered", body3
    assert body3["post"]["boot_epoch_ms"] == 99999
    assert len(stale_fake.reboot_calls) == pre_calls, (
        "resume_token should skip the Reboot RPC")


async def test_reboot_feature_disabled(tmp_path, monkeypatch):
    """allow_reboot=False refuses with kind=feature_disabled regardless
    of force=True."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch,
                                    allow_reboot=False)
    ctx.session.clients["kernel"] = _RebootClient([_status(1111)])
    body = await _call(server, "target_manage",
                       {"action": "reboot", "force": True})
    assert body["ok"] is False, body
    assert body["kind"] == "feature_disabled", body
    assert "allow_reboot" in body.get("hint", ""), body


async def test_reboot_trust_gate_refuses_without_force(
        tmp_path, monkeypatch):
    """min_trust_actuator='lab' and machine trust unset ('untrusted')
    → refused unless force=True. The shared actuator guard owns this
    check; the handler just needs the capability pair registered."""
    ctx, server = await _build_ctx(
        tmp_path, monkeypatch,
        allow_reboot=True, min_trust_actuator="lab")
    fake = _RebootClient([_status(1111), _status(99999)])
    ctx.session.clients["kernel"] = fake
    # Without force=True the guard refuses the call before the
    # handler ever runs, so the fake never sees the Reboot RPC.
    body = await _call(server, "target_manage",
                       {"action": "reboot", "wait": False})
    assert body["ok"] is False, body
    assert fake.reboot_calls == [], ("gate should refuse before the "
                                     "handler sees the call")
    # force=True bypasses the trust gate; the verb runs and returns
    # wait=False's pending_boot.
    body_force = await _call(server, "target_manage",
                             {"action": "reboot", "force": True,
                              "wait": False})
    assert body_force["ok"] is True, body_force
    assert body_force["kind"] == "pending_boot", body_force
    assert len(fake.reboot_calls) == 1


async def test_reboot_abort_skips_wait(tmp_path, monkeypatch):
    """mode='abort' (or action='reboot_abort') returns on RPC success
    without polling for a boot flip."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    fake = _RebootClient(
        [_status(1111)],
        reboot_result={
            "ok": True,
            "boot_epoch_ms_at_issue": 1111,
            "agent_instance_id_at_issue": "inst-1",
            "win32_error": 0,
            "message": "",
            "mode_applied": 5,
            "delay_s_applied": 0,
        })
    ctx.session.clients["kernel"] = fake
    body = await _call(server, "target_manage",
                       {"action": "reboot_abort", "force": True,
                        "wait": True, "wait_timeout_s": 5.0})
    assert body["ok"] is True, body
    assert body["kind"] == "shutdown_cancelled", body
    assert fake.reboot_calls[0]["mode"] == "abort"
    # Only two status calls allowed: the pre-snapshot. Not the wait loop.
    assert fake.status_calls <= 1, (
        f"abort should NOT enter the wait loop ({fake.status_calls} probes)")


async def test_reboot_privilege_absent_surface(tmp_path, monkeypatch):
    """Agent returns ok=False with message starting 'privilege_absent'
    → kind='privilege_absent' (not the generic reboot_refused)."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    fake = _RebootClient(
        [_status(1111)],
        reboot_result={
            "ok": False,
            "boot_epoch_ms_at_issue": 1111,
            "agent_instance_id_at_issue": "inst-1",
            "win32_error": 1314,  # ERROR_PRIVILEGE_NOT_HELD
            "message": ("privilege_absent: SeShutdownPrivilege not in "
                        "the agent service token"),
            "mode_applied": 1,
            "delay_s_applied": 0,
        })
    ctx.session.clients["kernel"] = fake
    body = await _call(server, "target_manage",
                       {"action": "reboot", "force": True, "wait": False})
    assert body["ok"] is False, body
    assert body["kind"] == "privilege_absent", body
    assert body["win32_error"] == 1314


async def test_reboot_unimplemented_kernel_view_is_agent_version(
        tmp_path, monkeypatch):
    """A kernel agent with no Reboot RPC answers UNIMPLEMENTED. The verb
    says so (kind=agent_version) instead of faking an accepted reboot and
    waiting for a boot flip that cannot come."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    fake = _RebootClient(
        [_status(1111)],
        reboot_raises=RuntimeError("UNIMPLEMENTED: method Reboot"))
    ctx.session.clients["kernel"] = fake
    body = await _call(server, "target_manage",
                       {"action": "reboot", "force": True,
                        "wait": True, "wait_timeout_s": 5.0})
    assert body["ok"] is False, body
    assert body["kind"] == "agent_version", body
    assert "update_target" in body.get("hint", ""), body
    assert len(fake.reboot_calls) == 1
    assert fake.status_calls <= 1, "must not enter the boot-flip wait loop"


async def test_reboot_unimplemented_user_view_is_not_supported(
        tmp_path, monkeypatch):
    """The usermode agent never implements Reboot (only the LocalSystem
    kernel agent can call InitiateShutdownW): not_supported + a pointer at
    the kernel view."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    fake = _RebootClient(
        [_status(1111)],
        reboot_raises=RuntimeError("UNIMPLEMENTED: method Reboot"))
    ctx.session.clients["user"] = fake
    body = await _call(server, "target_manage",
                       {"action": "reboot", "name": "user", "force": True,
                        "wait": True, "wait_timeout_s": 5.0})
    assert body["ok"] is False, body
    assert body["kind"] == "not_supported", body
    assert "name='kernel'" in body.get("hint", ""), body
    assert fake.status_calls <= 1, "must not enter the boot-flip wait loop"


async def test_reboot_dropped_channel_still_waits_for_the_flip(
        tmp_path, monkeypatch):
    """Any other RPC error at delay_s=0 is the shutdown tearing the channel
    down mid-call: assume accepted and let the boot flip prove it."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    fake = _RebootClient(
        [_status(1111), _status(99999)],
        reboot_raises=RuntimeError("socket closed"))
    ctx.session.clients["kernel"] = fake
    body = await _call(server, "target_manage",
                       {"action": "reboot", "force": True,
                        "wait": True, "recover": False,
                        "wait_timeout_s": 5.0})
    assert body["ok"] is True, body
    assert body["kind"] == "boot_recovered", body
    assert len(fake.reboot_calls) == 1


async def test_reboot_client_refusal_keeps_its_explanation(
        tmp_path, monkeypatch):
    """The client-side 'agent predates the RPC' refusal carries ``error`` /
    ``kind`` but no ``message``; the envelope keeps both."""
    ctx, server = await _build_ctx(tmp_path, monkeypatch)
    fake = _RebootClient(
        [_status(1111)],
        reboot_result={"ok": False, "kind": "agent_version",
                       "error": ("reboot: agent predates the Reboot RPC — "
                                 "rebuild + redeploy the agent")})
    ctx.session.clients["kernel"] = fake
    body = await _call(server, "target_manage",
                       {"action": "reboot", "force": True, "wait": False})
    assert body["ok"] is False, body
    assert body["kind"] == "agent_version", body
    assert "agent predates" in body["error"], body
