"""Device tool registration for the pry MCP server.

``device_manage`` — the actuator half of the driver-surface loop:
``bin_manage ioctl_surface`` finds a driver's CTL_CODEs, this tool sends
them. Also hosts the read-only ETW telemetry inventory (providers +
active trace sessions), which has no better home.

``ioctl`` is an ACTUATOR: a bad code can bugcheck the target. It is
double-gated — ``security.allow_ioctl_send`` (default false) in the
orchestrator config, plus the destructive-gate approval path via
``READONLY_FALSE``.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context


DEVICE_ACTIONS = ["ioctl", "actions"]

# Retired duplicates: the ETW inventory lives on event_manage.
_DEVICE_MOVED: dict[str, tuple[str, str]] = {
    "etw_providers": ("event_manage", "etw_providers"),
    "etw_sessions": ("event_manage", "etw_sessions"),
}

# per-verb help for action='actions' (module-level so tests can
# import it without building a server).
_DEVICE_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "device_manage(action='actions')"},
    "ioctl": {"one_liner": "send a CTL_CODE to a device (ACTUATOR — "
                           "gated by security.allow_ioctl_send)",
              "key_args": "device, code, in_hex, out_size, timeout_ms",
              "example": "device_manage(action='ioctl', "
                         "device='\\\\Device\\\\X', code='0x222003', "
                         "in_hex='...', out_size=4096)"},
}


def register(mcp, ctx: Context) -> None:
    """Register the ``device_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------ device_manage --

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def device_manage(action: Annotated[str, Field(json_schema_extra={"enum": DEVICE_ACTIONS})],
                            device: str = "",
                            code: Any = 0,
                            in_hex: str = "",
                            out_size: int = 4096,
                            timeout_ms: int = 0,
                            name: str = "") -> str:
        """Target-side device surface: ioctl (send a CTL_CODE — actuator,
        gated by security.allow_ioctl_send). ETW inventory lives on
        event_manage. Pair with bin_manage ioctl_surface +
        value_manage ioctl_encode. Per-verb help:
        device_manage(action='actions', verb='<verb>')."""
        args = {"action": action, "device": device}

        async def run() -> Any:
            if action in _DEVICE_MOVED:
                new_tool, new_action = _DEVICE_MOVED[action]
                return _moved_verb("device_manage", action, new_tool,
                                   new_action)
            if action not in DEVICE_ACTIONS:
                return _unknown_action("device_manage", action, DEVICE_ACTIONS, _DEVICE_ACTION_HELP)
            if action == "actions":
                return _actions_help("device_manage", _DEVICE_ACTION_HELP)
            c = ctx.session.require_client(name)

            if action == "ioctl":
                if not getattr(ctx.cfg.security, "allow_ioctl_send", False):
                    return _j({"ok": False, "kind": "not_allowed",
                               "error": ("device ioctl: send is disabled "
                                         "(security.allow_ioctl_send=false) — "
                                         "a bad code can bugcheck the target"),
                               "hint": ("enable security.allow_ioctl_send in "
                                        "the orchestrator config once the "
                                        "device under test is known-good")})
                if not device:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "ioctl: device= is required",
                               "hint": ("device_manage(action='ioctl', "
                                        "device='\\\\.\\Name', code='0x222003', "
                                        "in_hex='...')")})
                code_i = _addr(code, "code") if code not in ("", 0, None) else 0
                if not code_i or code_i < 0x10000:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": ("ioctl: code must be a CTL_CODE "
                                         "(>= 0x10000)")})
                in_bytes = bytes.fromhex(in_hex.replace(" ", "")) if in_hex else b""
                res = await c.device_ioctl(device, code_i, in_bytes,
                                           out_size=max(0, out_size),
                                           timeout_ms=max(0, timeout_ms))
                out_b = res.get("out", b"") or b""
                return _j_hex({
                    "ok": res.get("ok", False), "error": res.get("error", ""),
                    "device": device,
                    "code": code_i,
                    "bytes_returned": res.get("bytes_returned", 0),
                    "last_error": res.get("last_error", 0),
                    "out_hex": out_b.hex() if out_b else "",
                    "out_preview": out_b[:64].hex(),
                })

            if action == "etw_providers":
                # canonical home is event_manage. Forward to the
                # same agent-client call and stamp the alias banner so a
                # caller sees the migration on the response.
                res = await c.etw_providers(name_filter=name_filter)
                dep = {"tool": "device_manage", "action": "etw_providers",
                       "replacement": {"tool": "event_manage",
                                       "action": "etw_providers"},
                       "remove_in": "a future release"}
                if isinstance(res, dict):
                    res = dict(res)
                    res["deprecated"] = dep
                return _j(res)

            if action == "etw_sessions":
                res = await c.etw_sessions(name_filter=name_filter)
                dep = {"tool": "device_manage", "action": "etw_sessions",
                       "replacement": {"tool": "event_manage",
                                       "action": "etw_sessions"},
                       "remove_in": "a future release"}
                if isinstance(res, dict):
                    res = dict(res)
                    res["deprecated"] = dep
                return _j(res)

            return _unknown_action("device_manage", action, DEVICE_ACTIONS, _DEVICE_ACTION_HELP)

        return await _guard(ctx, "device_manage", action, args, run)
