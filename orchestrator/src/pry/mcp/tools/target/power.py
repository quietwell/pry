"""``target_manage.reboot`` — one-call reliable reboot + wait-back.

The LLM calls this verb instead of ``exec_manage(run_cmd,
command='shutdown /r /t 0 /f')`` plus the hand-written three-step
choreography (``wait_connectable`` → ``wait_boot_change`` →
``boot_recover``). The agent-side path is a direct
``InitiateShutdownW`` call under the LocalSystem service token;
the orchestrator side handles the post-reboot wait loop and the
``resume_token`` re-entry when the MCP host's 60s deadline would
otherwise kill the call.

Modes:
  * ``reboot``   (default) — SHUTDOWN_RESTART
  * ``shutdown`` — SHUTDOWN_NOREBOOT (power stays on)
  * ``poweroff`` — SHUTDOWN_POWEROFF (ACPI off)
  * ``logoff``   — ExitWindowsEx(EWX_LOGOFF)
  * ``abort``    — AbortSystemShutdownW cancels a pending one

Gates:
  * ``security.allow_reboot`` must be true (default off — opt-in per
    the slice doc; refused with ``kind='feature_disabled'``).
  * Actuator-trust gate (``security.min_trust_actuator``) is enforced
    by the shared guard around every alias. Pass ``force=True`` to
    bypass trust gating — the shutdown API itself still requires
    SeShutdownPrivilege in the service token.

Resume:
  When ``wait=True`` (default), the handler blocks until the view's
  (boot_epoch_ms, agent_instance_id) flips. If the MCP host's
  deadline would be reached first, the response carries::

      { ok: true, kind: 'pending_boot',
        resume_token: '<view>:<pre_boot_epoch>:<pre_instance>',
        hint: 'call target_manage.reboot(resume_token=...) to continue' }

  A second call with the same ``resume_token`` skips the fresh
  ``Reboot`` RPC and continues the inner wait.
"""

from __future__ import annotations

import time as _t
from typing import Any

from ..common import *  # noqa: F401,F403 — _j, asyncio, _enrich_error, ...

from ._runtime import _auto_arm_after_load, _auto_arm_cfg_status
from . import reboot as _reboot_waits
from . import recover as _recover


# Modes the handler accepts at the MCP layer. The umagent-side wrapper
# also understands ``restart`` / ``power_off`` as aliases; the
# orchestrator keeps the canonical spellings to match dispatch aliases.
_MODES = frozenset({"reboot", "shutdown", "poweroff", "logoff", "abort"})


def _norm_mode(mode: str, action: str) -> str:
    """Canonicalize the mode. ``action='reboot_abort'`` forces abort."""
    if action == "reboot_abort":
        return "abort"
    if action in ("shutdown", "poweroff", "logoff"):
        return action
    m = str(mode or "").strip().lower()
    if m in ("", "restart"):
        return "reboot"
    if m == "power_off":
        return "poweroff"
    return m


def _parse_resume_token(token: str) -> tuple[str, int, str] | None:
    """``'<view>:<boot_epoch_ms>:<agent_instance_id>'`` — plain, no
    server state. Returns None on any malformed input (the caller
    treats that as "ignore the token and run from scratch")."""
    if not token:
        return None
    try:
        view, boot_raw, inst = token.split(":", 2)
    except ValueError:
        return None
    if not view or not inst:
        return None
    try:
        boot = int(boot_raw)
    except ValueError:
        return None
    return view, boot, inst


def _reboot_unimplemented(action: str, view: str) -> dict[str, Any]:
    """Envelope for a Reboot RPC answered UNIMPLEMENTED.

    Usermode view: by design — only the LocalSystem kernel agent can call
    InitiateShutdownW, so point at that view. Kernel view: the agent on
    the target predates the verb and needs the update.
    """
    if view.rsplit(".", 1)[-1] == "user":
        base = view.rsplit(".", 1)[0] if "." in view else ""
        other = f"{base}.kernel" if base else "kernel"
        return {
            "ok": False, "kind": "not_supported", "action": action,
            "view": view,
            "error": (f"target_manage.{action}: the usermode agent has no "
                      "Reboot RPC (UNIMPLEMENTED) — nothing was issued"),
            "hint": (f"retry with name={other!r}; only the LocalSystem "
                     "kernel agent can call InitiateShutdownW"),
        }
    return {
        "ok": False, "kind": "agent_version", "action": action,
        "view": view,
        "error": (f"target_manage.{action}: this agent has no Reboot RPC "
                  "(UNIMPLEMENTED) — nothing was issued"),
        "hint": ("the agent on the target predates the reboot verb — "
                 "scripts/update_target.py --component agent"),
    }


async def do_reboot(ctx, *, action: str, name: str, mode: str,
                    delay_s: int, force: bool, reason: str,
                    wait: bool, recover: bool, wait_timeout_s: float,
                    resume_token: str) -> str:
    """One-call reboot + wait-back. See the module docstring."""
    cid = current_client_id()
    # ------------------------------------------------------------- gates
    if not bool(getattr(ctx.cfg.security, "allow_reboot", False)):
        return _j({
            "ok": False,
            "kind": "feature_disabled",
            "action": action,
            "error": ("target_manage.reboot refused: "
                      "security.allow_reboot is false (default)"),
            "hint": "set security.allow_reboot: true in configs/*.yaml "
                    "to enable the reboot verb for this orchestrator",
        })
    mode_norm = _norm_mode(mode, action)
    if mode_norm not in _MODES:
        return _j({
            "ok": False,
            "kind": "bad_arg",
            "action": action,
            "error": (f"target_manage.reboot: unknown mode {mode!r} — "
                      "expected one of reboot|shutdown|poweroff|"
                      "logoff|abort"),
        })

    # ------------------------------------------------------------- resume
    resume = _parse_resume_token(resume_token)
    if resume is not None:
        view, pre_boot, pre_inst = resume
        # If the view isn't connected yet, we just carry the resume
        # identity into the wait loop — _wait_for_flip will do its own
        # client lookup each poll.
    else:
        view = ctx.session.resolve_view_name(name) if name \
            else ctx.session.primary
        # The agent needs to be reachable to receive the Reboot RPC;
        # a wait-for-flip resume path doesn't need a live client.
        client = ctx.session.clients.get(view)
        if client is None:
            return _j({
                "ok": False,
                "kind": "not_connected",
                "action": action,
                "view": view,
                "error": (f"target_manage.reboot: view {view!r} is not "
                          "connected — target_manage(action='connect') "
                          "first, then re-issue"),
            })
        # Snapshot pre-reboot identity via a status() probe so the
        # response always reports (pre, post). An error here still
        # permits the Reboot call — we fall back to ``''`` / ``0``
        # and tell the caller via a note.
        pre_boot = 0
        pre_inst = ""
        pre_note = ""
        try:
            st = await client.status()
            ctx.session.note_boot_identity(view, st)
            pre_boot = int(st.get("boot_epoch_ms") or 0)
            pre_inst = str(st.get("agent_instance_id") or "")
        except Exception as exc:  # noqa: BLE001 — degrade cleanly
            pre_note = f"pre-status probe failed: {exc}"

        # ------------------------------------------------------------- RPC
        try:
            rpc = await client.reboot(
                mode=mode_norm, delay_s=int(delay_s or 0),
                force=bool(force), reason=str(reason or ""))
        except Exception as exc:  # noqa: BLE001
            # UNIMPLEMENTED means the agent on this view has no Reboot
            # RPC (the usermode agent, or a kernel agent older than the
            # reboot verb). The handler never ran, so nothing was issued —
            # say so instead of faking an accepted reboot below and then
            # waiting for a boot flip that cannot come.
            if "UNIMPLEMENTED" in str(exc):
                return _j(_reboot_unimplemented(action, view))
            # delay_s==0 + a successful shutdown can tear the channel
            # down before the response flushes; caller should retry
            # via resume_token in that case.
            if int(delay_s or 0) <= 0 and mode_norm != "abort":
                # Fabricate an "ok=True, assume accepted" result so
                # the wait loop still runs — the real proof is the
                # boot identity flip.
                rpc = {
                    "ok": True,
                    "boot_epoch_ms_at_issue": pre_boot,
                    "agent_instance_id_at_issue": pre_inst,
                    "win32_error": 0,
                    "message": f"rpc_dropped_mid_call: {exc}",
                    "mode_applied": 0,
                    "delay_s_applied": int(delay_s or 0),
                }
            else:
                return _j({
                    "ok": False,
                    "kind": "reboot_refused",
                    "action": action,
                    "view": view,
                    "error": f"reboot RPC failed: {exc}",
                })

        if not rpc.get("ok"):
            # Discriminate the "no SeShutdownPrivilege" case explicitly —
            # the system_power helper tags its hard failure that way.
            # ``error`` carries the client-side refusal text (the local
            # stub lacks the RPC); ``message`` is the agent's own.
            msg = str(rpc.get("message") or rpc.get("error") or "")
            kind = "reboot_refused"
            if msg.startswith("privilege_absent"):
                kind = "privilege_absent"
            elif rpc.get("kind") in ("agent_version", "bad_arg"):
                kind = str(rpc["kind"])
            return _j({
                "ok": False,
                "kind": kind,
                "action": action,
                "view": view,
                "win32_error": int(rpc.get("win32_error") or 0),
                "message": msg,
                "error": (f"target_manage.reboot: agent refused — {msg}"
                          if msg else "target_manage.reboot: agent refused"),
                "pre": {"boot_epoch_ms": pre_boot,
                        "agent_instance_id": pre_inst},
            })

        # mode='abort' is a terminal success — nothing to wait for.
        if mode_norm == "abort":
            return _j({
                "ok": True,
                "kind": "shutdown_cancelled",
                "action": action,
                "view": view,
                "pre": {"boot_epoch_ms": pre_boot,
                        "agent_instance_id": pre_inst},
                "mode_applied": int(rpc.get("mode_applied") or 0),
            })

        # Agent snapshot wins over the probe — they should match, but if
        # the pre-status call failed the RPC's own snapshot fills in.
        if pre_boot == 0:
            pre_boot = int(rpc.get("boot_epoch_ms_at_issue") or 0)
        if not pre_inst:
            pre_inst = str(rpc.get("agent_instance_id_at_issue") or "")

        # ``wait=False`` → return immediately with accepted + pre identity.
        if not wait:
            return _j({
                "ok": True,
                "kind": "pending_boot",
                "action": action,
                "view": view,
                "pre": {"boot_epoch_ms": pre_boot,
                        "agent_instance_id": pre_inst},
                "resume_token": f"{view}:{pre_boot}:{pre_inst}",
                "mode_applied": int(rpc.get("mode_applied") or 0),
                "delay_s_applied": int(rpc.get("delay_s_applied") or 0),
                "note": pre_note or "",
                "hint": ("wait=False returned before the boot flip — "
                         "call target_manage(action='reboot', "
                         "resume_token=...) to block until the view "
                         "reconnects, or wait_boot_change manually"),
            })

    # ------------------------------------------------------------- wait
    # Shared post-RPC loop: poll the view until (boot_epoch_ms,
    # agent_instance_id) flips, bounded by min(wait_timeout_s,
    # MCP deadline - 5s). On a successful flip, optionally run
    # boot_recover (reconnect + sweep + driver_load + watchdog
    # re-arm + minidump pull).
    started = _t.monotonic()
    # 55s keeps a safety margin under the 60s MCP host deadline.
    hard_deadline_s = 55.0
    budget_s = float(wait_timeout_s) if wait_timeout_s and wait_timeout_s > 0 \
        else hard_deadline_s
    budget_s = min(budget_s, hard_deadline_s)
    deadline = started + budget_s
    delay = 0.5
    attempts = 0
    last_err = ""
    while _t.monotonic() < deadline:
        attempts += 1
        try:
            c = ctx.session.clients.get(view)
            if c is None:
                # Not connected yet — try a cheap TCP + gRPC probe via
                # wait_connectable (short timeout, one shot).
                remaining = max(1.0, deadline - _t.monotonic())
                probe_budget = min(5.0, remaining)
                probe = await _reboot_waits.do_wait_connectable(
                    ctx, name=view, host="", port=0, token="",
                    timeout_s=probe_budget, hosts=None, cidr="")
                import json as _json
                try:
                    probed = _json.loads(probe)
                except Exception:  # noqa: BLE001
                    probed = {}
                if isinstance(probed, dict):
                    if (isinstance(probed.get("data"), dict) and
                            probed["data"].get("ok")):
                        probed = probed["data"]
                    elif isinstance(probed.get("structured_content"), dict):
                        probed = probed["structured_content"]
                if not (isinstance(probed, dict) and probed.get("ok")):
                    # Still not reachable — keep polling.
                    last_err = "view not reconnectable yet"
                    await asyncio.sleep(min(delay, max(0.05, deadline - _t.monotonic())))
                    delay = min(delay * 1.7, 3.0)
                    continue
                # Reconnected via connect side-effect of boot_recover; drop
                # into the status check below on next iteration.
                last_err = ""
                continue

            st = await c.status()
            change = ctx.session.note_boot_identity(view, st)
            flipped = False
            if change is not None and change.get("kind") in (
                    "new_boot", "agent_restart"):
                flipped = True
            else:
                # Also accept a straight (boot_epoch_ms, agent_instance_id)
                # difference against the pre snapshot; this catches the
                # "first status after reconnect" case where the identity
                # had already been set on the Session (first_connect).
                post_boot = int(st.get("boot_epoch_ms") or 0)
                post_inst = str(st.get("agent_instance_id") or "")
                if post_boot and (post_boot != pre_boot or
                                   (post_inst and post_inst != pre_inst)):
                    flipped = True
            if flipped:
                post_boot = int(st.get("boot_epoch_ms") or 0)
                post_inst = str(st.get("agent_instance_id") or "")
                out: dict[str, Any] = {
                    "ok": True,
                    "kind": "boot_recovered",
                    "action": action,
                    "view": view,
                    "pre": {"boot_epoch_ms": pre_boot,
                            "agent_instance_id": pre_inst},
                    "post": {"boot_epoch_ms": post_boot,
                             "agent_instance_id": post_inst,
                             "driver_state": st.get("driver_state")},
                    "attempts": attempts,
                    "elapsed_ms": int(
                        (_t.monotonic() - started) * 1000),
                }
                if recover:
                    try:
                        rec = await _recover.do_boot_recover(
                            ctx, name=view, host="", port=0, token="",
                            load_driver=True, method="service",
                            include_dump=False)
                        import json as _json
                        try:
                            parsed = _json.loads(rec)
                        except Exception:  # noqa: BLE001
                            parsed = rec
                        out["recover"] = parsed
                    except Exception as exc:  # noqa: BLE001
                        out["recover_error"] = str(exc)
                return _j(out)
            last_err = "boot identity unchanged"
        except Exception as exc:  # noqa: BLE001 — target mid-reboot
            last_err = f"status probe raised: {exc}"
        remaining = deadline - _t.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(delay, max(0.05, remaining)))
        delay = min(delay * 1.7, 3.0)

    # Deadline reached. If the caller passed wait_timeout_s explicitly
    # AND we hit it (not the MCP safety deadline), say so with
    # kind='reboot_timeout' — this is a hard stop, no resume suggested.
    # Otherwise hand back a resume_token so the LLM can loop.
    elapsed_s = round(_t.monotonic() - started, 3)
    hit_caller_deadline = (
        wait_timeout_s and wait_timeout_s > 0
        and budget_s >= float(wait_timeout_s))
    if hit_caller_deadline:
        return _j({
            "ok": False,
            "kind": "reboot_timeout",
            "action": action,
            "view": view,
            "attempts": attempts,
            "elapsed_s": elapsed_s,
            "pre": {"boot_epoch_ms": pre_boot,
                    "agent_instance_id": pre_inst},
            "error": (f"target_manage.reboot: no boot-identity flip after "
                      f"{attempts} poll(s) over {elapsed_s}s (caller's "
                      f"wait_timeout_s={wait_timeout_s:g} exhausted)"),
            "last_probe": last_err or "unknown",
        })
    return _j({
        "ok": True,
        "kind": "pending_boot",
        "action": action,
        "view": view,
        "attempts": attempts,
        "elapsed_s": elapsed_s,
        "pre": {"boot_epoch_ms": pre_boot,
                "agent_instance_id": pre_inst},
        "resume_token": f"{view}:{pre_boot}:{pre_inst}",
        "hint": ("MCP host deadline approaching — call "
                 "target_manage(action='reboot', resume_token=...) "
                 "to continue blocking until the view reconnects"),
        "last_probe": last_err or "unknown",
    })
