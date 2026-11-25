"""Screen tool registration for the pry MCP server — v15.

``desktop_manage`` is the visual-inspection surface of the target:

- ``capture`` — desktop (DXGI duplication) or window (WGC) screenshot as PNG.
  Bytes land under ``artifacts/screenshots/``; the envelope carries the path,
  dimensions, sha256 and (opt-in) inline base64. Pillow scales to
  ``max_dimension`` when importable; without it the raw agent PNG passes
  through untouched.
- ``windows`` — Z-ordered window list grouped by process with full per-window
  metadata (class, style/exstyle, status, rects, placement, owner/parent,
  pid/tid, process path, hinstance, flags, DPI). ``include_hidden=True`` opts
  into invisible/cloaked/untitled windows (default: visible only).
- ``displays`` — attached monitor topology.

All three funnel through the session-1 worker on the target (a Session-0
service cannot see the user desktop), so they require a connected target view.
"""

from __future__ import annotations

import base64

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context

_DESKTOP_ACTIONS_MASTER = ["capture", "windows", "displays",
                  # EnumPropsExW + tree +
                  # per-thread grouping. Read-only; session-1-only.
                  "window_props", "window_tree", "window_by_thread",
                  # SendInput injection (umagent Input
                  # service). Actuator-trust gated; session-1-only.
                  "click", "type", "key",
                  "actions"]

# shared closure reference so ``desktop_manage`` (new canonical
# tool in ``tools/desktop.py``) can forward through desktop_manage's
# full dispatcher. Set during :func:`register`.
_DESKTOP_MANAGE_FN = None

SCREENSHOT_SUBDIR = "screenshots"

_DESKTOP_ACTION_HELP_INTERNAL = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "desktop_manage(action='actions')"},
    "capture": {"one_liner": "screenshot the desktop or one window (PNG)",
                "key_args": "mode, display_id, hwnd, pid, window_title, "
                            "process_name, max_dimension, embed, "
                            "include_hidden, include_details",
                "example": "desktop_manage(action='capture', pid=4812)"},
    "windows": {"one_liner": "enumerate windows grouped by process with "
                             "full metadata (class, style/exstyle, status, "
                             "rects, placement, z-order, pid/tid, flags, "
                             "dpi); include_children recurses "
                             "EnumChildWindows, include_props attaches "
                             "an EnumPropsExW walk per node",
                "key_args": "pid, process_name, query, include_hidden, "
                            "include_details, include_children, "
                            "include_props",
                "example": "desktop_manage(action='windows', "
                           "include_hidden=True)"},
    "displays": {"one_liner": "list attached displays (device name, "
                              "primary, active, rects)",
                 "key_args": "none",
                 "example": "desktop_manage(action='displays')"},
    "window_props": {"one_liner": "EnumPropsExW walk on one HWND; "
                                   "message-free, safe against hung UI "
                                   "threads",
                      "key_args": "hwnd, include_values",
                      "example": "desktop_manage(action='window_props', "
                                 "hwnd='0x10234')"},
    "window_tree": {"one_liner": "parent/child/owner tree rooted at "
                                  "hwnd (0 = GetDesktopWindow()), "
                                  "depth-capped (max_depth=12). Child "
                                  "cycles are broken by an HWND visited "
                                  "set.",
                     "key_args": "hwnd, pid, max_depth, include_props",
                     "example": "desktop_manage(action='window_tree', "
                                "pid=1234, max_depth=4)"},
    "window_by_thread": {"one_liner": "windows grouped by tid instead "
                                       "of pid (orchestrator-side "
                                       "regrouping of the ListWindows "
                                       "RPC — same wire payload)",
                          "key_args": "pid, process_name, query, "
                                      "include_hidden",
                          "example": "desktop_manage(action="
                                     "'window_by_thread', pid=1234)"},
    "click": {"one_liner": "SendInput mouse click at (x,y) in screen "
                            "space; x=-1,y=-1 uses the current cursor "
                            "position (session-1, actuator-trust gated)",
               "key_args": "x, y, button, mode ('click'|'down'|'up'), "
                            "modifiers, click_count, force",
               "example": "desktop_manage(action='click', x=100, y=200)"},
    "type": {"one_liner": "SendInput text entry via VkKeyScanW "
                           "(session-1, actuator-trust gated)",
              "key_args": "text, delay_ms, force",
              "example": "desktop_manage(action='type', text='hello')"},
    "key": {"one_liner": "SendInput key / chord like 'Ctrl+C' "
                          "(session-1, actuator-trust gated)",
             "key_args": "key, repeat, force",
             "example": "desktop_manage(action='key', key='Ctrl+A')"},
}


def _scale_and_compress(raw: bytes, max_dim: int) -> tuple[bytes, int, int]:
    """Aspect-ratio preserving bounding-box clamp, PNG re-encode.

    Returns (png_bytes, width, height). Without Pillow (not importable) the
    raw agent PNG passes through with its native size untouched.
    """
    try:
        import io

        from PIL import Image
    except Exception:
        return raw, 0, 0
    img = Image.open(io.BytesIO(raw))
    orig_w, orig_h = img.size
    largest = max(orig_w, orig_h)
    if largest > max_dim:
        s = max_dim / float(largest)
        img = img.resize((max(1, round(orig_w * s)), max(1, round(orig_h * s))),
                         Image.Resampling.LANCZOS)
    out = io.BytesIO()
    img.save(out, format="PNG", optimize=True)
    return out.getvalue(), img.width, img.height


def _parse_windows_json(res: dict) -> dict:
    """Telemetry arrives as raw JSON from the session-1 worker; parse it
    defensively — a truncated/empty blob degrades to an empty list, never an
    exception (the pixels are still deliverable)."""
    raw = res.get("windows_json") or "{}"
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


# lean window projection. The agent's GetWindowInfo /
# GetWindowPlacement walk ships every field it can observe (style /
# exstyle / hinstance / window_status / window_type_atom / cloaked /
# border / show_cmd / normal_pos / parent / owner / topmost / layered /
# tool_window / enabled / is_minimized). A multimodal caller mapping
# image-space clicks back to pixel space needs only identity (hwnd /
# pid / tid / names), geometry (rect / client_rect), stacking order,
# and the visible/foreground/minimized/maximized flags — the Win32
# plumbing is noise in the default path and padded capture envelopes
# by 8–12 KB on a busy desktop. ``include_details=True`` opts back
# into the full dump for a window-manager debugging session.
_LEAN_WINDOW_FIELDS: tuple[str, ...] = (
    "hwnd", "pid", "tid",
    "process_name",
    "title", "class_name",
    "rect", "client_rect",
    "z_order",
    "visible", "is_foreground", "minimized", "maximized", "dpi",
    # ``process_path`` is intentionally absent: the WindowsApps Appx
    # path is 100+ chars and ``process_name`` + ``pid`` already name
    # the process for the LLM. Opt back in via ``include_details=true``.
)


def _lean_window(w: dict) -> dict:
    """Return a copy of ``w`` restricted to :data:`_LEAN_WINDOW_FIELDS`.

    Keys absent in ``w`` are omitted (not defaulted) so the serialized
    envelope keeps the same "populated-only" shape it had before,
    apart from the dropped Win32-plumbing fields."""
    return {k: w[k] for k in _LEAN_WINDOW_FIELDS if k in w}


def _project_windows_procs(procs: list, include_details: bool) -> list:
    """Project the ``processes[].windows[]`` shape (``capture`` /
    ``windows`` response). ``include_details=True`` passes the agent
    payload through unchanged; ``False`` trims each window dict down
    to :data:`_LEAN_WINDOW_FIELDS`."""
    if include_details:
        return procs or []
    out: list = []
    for group in procs or ():
        g = dict(group)
        g["windows"] = [_lean_window(w)
                        for w in (group.get("windows") or ())]
        out.append(g)
    return out


def _project_threads(threads: list, include_details: bool) -> list:
    """Project the ``threads[].windows[]`` shape (``window_by_thread``
    response). Same rule as :func:`_project_windows_procs` but for the
    tid-grouped shape."""
    if include_details:
        return threads or []
    out: list = []
    for group in threads or ():
        g = dict(group)
        g["windows"] = [_lean_window(w)
                        for w in (group.get("windows") or ())]
        out.append(g)
    return out


def register(mcp, ctx: Context) -> None:
    """Build the internal ``desktop_manage`` dispatcher and publish it as
    :data:`_DESKTOP_MANAGE_FN` so ``desktop_manage`` can forward verb
    bodies through it.

    No longer registered as an MCP tool. The ``mcp`` argument is
    kept for signature compatibility with ``build_server`` but is unused
    here."""
    del mcp  # unused

    async def desktop_manage(action: Annotated[str, Field(json_schema_extra={"enum": _DESKTOP_ACTIONS_MASTER})],
                            mode: str = "desktop",
                            display_id: str = "",
                            hwnd: str = "",
                            pid: int = 0,
                            window_title: str = "",
                            process_name: str = "",
                            query: str = "",
                            max_dimension: int = 1920,
                            include_hidden: bool = False,
                            # default flipped to False so the
                            # capture / windows / window_by_thread envelopes
                            # carry the lean field set by default. True opts
                            # back into the full Win32 dump.
                            include_details: bool = False,
                            embed: bool = False,
                            include_children: bool = False,
                            include_props: bool = False,
                            max_depth: int = 12,
                            include_values: bool = True,
                            tid: int = 0,
                            # SendInput injection kwargs.
                            # x = -1 && y = -1 → operate on the
                            # current cursor without moving it.
                            x: int = -1,
                            y: int = -1,
                            text: str = "",
                            button: str = "left",
                            modifiers: int = 0,
                            click_count: int = 1,
                            delay_ms: int = 0,
                            key: str = "",
                            repeat: int = 1,
                            force: bool = False,
                            name: str = "") -> str:
        """Visual screen inspection of the target: capture screenshots
        (desktop via DXGI, window via WGC) for multimodal analysis, enumerate
        windows grouped by process with full metadata (class, style/exstyle,
        status, rects, placement, z-order, pid/tid, flags, dpi —
        include_hidden=True also lists hidden windows), and inspect display
        topology. Everything runs in the target's interactive session; a
        locked/logged-off box answers with an explicit error. Per-verb help:
        desktop_manage(action='actions')."""
        args = {"action": action, "mode": mode, "name": name,
                # forwarded to the actuator-trust gate so a
                # force=true override on an untrusted machine reaches
                # _check_actuator_trust.
                "force": bool(force)}

        async def run() -> str:
            if action == "actions":
                return _actions_help("desktop_manage", _DESKTOP_ACTION_HELP_INTERNAL)

            c = ctx.session.require_client(name)

            if action == "windows":
                # always ask the agent for the full dump;
                # the orchestrator's lean projection below keeps only
                # _LEAN_WINDOW_FIELDS by default. Letting the agent
                # strip first would double-strip and leave the caller
                # with 5 fields per window even on the lean path
                # (observed: an older agent's lean path drops
                # pid/tid/class_name/dpi/visible).
                res = await c.list_windows(
                    pid=pid, process_name=process_name,
                    query=query,
                    include_hidden=include_hidden,
                    include_details=True,
                    include_children=bool(include_children),
                    include_props=bool(include_props))
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "error",
                               "error": res.get("error") or "list_windows_failed"})
                data = _parse_windows_json(res)
                procs = _project_windows_procs(
                    data.get("processes") or [], include_details)
                total = sum(len(g.get("windows") or []) for g in procs)
                return _j({"ok": True, "kind": "windows",
                           "total_windows": total,
                           "include_hidden": include_hidden,
                           "include_details": include_details,
                           "include_children": bool(include_children),
                           "include_props": bool(include_props),
                           "processes": procs})
            if action == "window_props":
                # EnumPropsExW walk on one
                # HWND. Message-free (GetProp), safe against hung UI
                # threads per slice doc §Edge cases.
                hwnd_val = int(hwnd, 0) if hwnd else 0
                if hwnd_val == 0:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "window_props: hwnd required"})
                res = await c.list_window_props(
                    hwnd=hwnd_val, include_values=bool(include_values))
                if not res.get("ok"):
                    env = {"ok": False,
                           "kind": res.get("kind") or "window_props_failed",
                           "error": res.get("error") or "window_props failed",
                           "hwnd": hwnd_val}
                    if env["kind"] == "agent_version":
                        env["hint"] = ("rebuild + redeploy the agent "
                                        "(Agent.ListWindowProps is a "
                                        "newer RPC)")
                    return _j(env)
                return _j({"ok": True, "kind": "window_props",
                           "hwnd": int(res.get("hwnd") or hwnd_val),
                           "props": res.get("props") or []})
            if action == "window_tree":
                # parent/child/owner tree
                # builder. hwnd=0 roots at GetDesktopWindow();
                # max_depth caps the EnumChildWindows recursion
                # (default 12, slice doc §Feature 8).
                hwnd_val = int(hwnd, 0) if hwnd else 0
                res = await c.get_window_tree(
                    hwnd=hwnd_val, pid=pid,
                    max_depth=int(max_depth or 12),
                    include_props=bool(include_props))
                if not res.get("ok"):
                    env = {"ok": False,
                           "kind": res.get("kind") or "window_tree_failed",
                           "error": res.get("error") or "window_tree failed"}
                    if env["kind"] == "agent_version":
                        env["hint"] = ("rebuild + redeploy the agent "
                                        "(Agent.GetWindowTree is a "
                                        "newer RPC)")
                    return _j(env)
                return _j({"ok": True, "kind": "window_tree",
                           "root_hwnd": hwnd_val,
                           "pid": pid,
                           "max_depth": int(max_depth or 12),
                           "include_props": bool(include_props),
                           "root": res.get("root")})
            if action == "window_by_thread":
                # orchestrator-side regrouping
                # of ListWindows by tid. Pure Python — no new RPC.
                res = await c.list_windows(
                    pid=pid, process_name=process_name,
                    query=query, include_hidden=include_hidden,
                    include_details=True,
                    include_children=bool(include_children),
                    include_props=bool(include_props))
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "error",
                               "error": res.get("error") or "list_windows_failed"})
                data = _parse_windows_json(res)
                procs = data.get("processes") or []
                by_tid: dict[int, dict] = {}
                for g in procs:
                    g_pid = int(g.get("pid") or 0)
                    for w in g.get("windows") or []:
                        wtid = int(w.get("tid") or 0)
                        if tid and wtid != int(tid):
                            continue
                        slot = by_tid.setdefault(
                            wtid, {"tid": wtid, "pid": g_pid,
                                   "process_name": g.get("process_name"),
                                   "windows": []})
                        slot["windows"].append(w)
                threads = sorted(by_tid.values(),
                                 key=lambda s: (s["pid"], s["tid"]))
                total = sum(len(t["windows"]) for t in threads)
                threads = _project_threads(threads, include_details)
                return _j({"ok": True, "kind": "window_by_thread",
                           "total_windows": total,
                           "threads": threads,
                           "include_hidden": include_hidden,
                           "include_details": include_details,
                           "include_children": bool(include_children)})

            if action == "displays":
                res = await c.capture_screen(mode="displays")
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "error",
                               "error": res.get("error") or "displays_failed"})
                data = _parse_windows_json(res)
                return _j({"ok": True, "kind": "displays",
                           "displays": data.get("displays") or []})

            if action == "capture":
                hwnd_val = int(hwnd, 0) if hwnd else 0
                # process_name also selects window mode (worker resolves the
                # topmost visible window of that exe).
                capture_mode = ("window" if (hwnd_val or pid or window_title
                                             or process_name) else "desktop")
                # always ask the agent for full window telemetry;
                # the orchestrator's `_project_windows_procs` trims below.
                # See the matching comment on the `windows` branch.
                res = await c.capture_screen(
                    mode=capture_mode, display_id=display_id, hwnd=hwnd_val,
                    pid=pid, window_title=window_title,
                    process_name=process_name, query=query,
                    include_hidden=include_hidden,
                    include_details=True)
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "error",
                               "error": res.get("error") or "capture_failed"})

                raw = res.get("image_data") or b""
                if not raw:
                    return _j({"ok": False, "kind": "error",
                               "error": "capture: empty image payload"})
                scaled, w, h = _scale_and_compress(raw, max(1, int(max_dimension)))
                if not w:   # Pillow unavailable: keep native agent dims
                    w, h = int(res.get("width") or 0), int(res.get("height") or 0)

                from datetime import datetime
                now = datetime.now().strftime("%Y%m%d_%H%M%S")
                if pid:
                    target = f"pid_{pid}"
                elif hwnd_val:
                    target = f"hwnd_{hwnd_val:x}"
                elif display_id:
                    target = display_id
                else:
                    target = "primary"
                art_dir = Path(ctx.cfg.artifacts_dir()) / SCREENSHOT_SUBDIR
                art_dir.mkdir(parents=True, exist_ok=True)
                art_path = art_dir / f"screen_{target}_{now}.png"
                art_path.write_bytes(scaled)

                native_w = int(res.get("width") or 0)
                native_h = int(res.get("height") or 0)
                env: dict = {
                    "ok": True,
                    "kind": "screenshot",
                    "capture_mode": capture_mode,
                    "target_type": res.get("target_type") or capture_mode,
                    "target_name": res.get("target_name") or "",
                    "width": w,
                    "height": h,
                    "artifact_path": str(art_path),
                }
                # housekeeping fields ride on the full-detail
                # path only. A caller that just wants to look at the
                # frame doesn't need the on-disk hash, the pre-resize
                # dimensions, or the resize boolean; a caller mapping
                # image-space coords back to pixel space passes
                # ``include_details=true`` and gets the scale math
                # back alongside the full Win32 window dump.
                if include_details:
                    env["size_bytes"] = len(scaled)
                    env["sha256"] = hashlib.sha256(scaled).hexdigest()
                    env["filename"] = art_path.name
                    env["scaled"] = bool(w and (w != native_w))
                    env["native_width"] = native_w
                    env["native_height"] = native_h
                    env["scale_factor"] = (round(w / native_w, 6)
                                            if (w and native_w) else 1.0)
                if embed:
                    env["image_base64"] = base64.b64encode(scaled).decode("ascii")
                # Window telemetry always rides along when the worker sent it.
                data = _parse_windows_json(res)
                procs = _project_windows_procs(
                    data.get("processes") or [], include_details)
                if procs:
                    env["total_windows"] = sum(len(g.get("windows") or [])
                                               for g in procs)
                    env["processes"] = procs
                return _j(env)

            # SendInput injection. Trust gating runs inside
            # _guard (`_check_actuator_trust` consults the capability
            # registry), so the branches below trust that a request
            # that reached them is already approved.
            if action == "click":
                res = await c.input_click(
                    x=int(x), y=int(y),
                    button=str(button or "left"),
                    action=str(mode) if mode in (
                        "down", "up", "click") else "click",
                    modifiers=int(modifiers or 0),
                    click_count=int(click_count or 1),
                    force=bool(force),
                )
                if not isinstance(res, dict):
                    res = {"ok": False, "error": "input_click: no response"}
                env = {"ok": bool(res.get("ok", False)),
                       "kind": "input_ack",
                       "action": "click",
                       "x": int(x), "y": int(y),
                       "button": str(button or "left"),
                       "click_count": int(click_count or 1)}
                if not env["ok"]:
                    env["error"] = res.get("error") or "input_click failed"
                    if res.get("hint"):
                        env["hint"] = res["hint"]
                return _j(env)
            if action == "type":
                if not text:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "type: text= required"})
                res = await c.input_type(
                    text=str(text),
                    delay_ms=int(delay_ms or 0),
                    force=bool(force),
                )
                if not isinstance(res, dict):
                    res = {"ok": False, "error": "input_type: no response"}
                env = {"ok": bool(res.get("ok", False)),
                       "kind": "input_ack",
                       "action": "type",
                       "chars": len(str(text)),
                       "delay_ms": int(delay_ms or 0)}
                if not env["ok"]:
                    env["error"] = res.get("error") or "input_type failed"
                    if res.get("hint"):
                        env["hint"] = res["hint"]
                return _j(env)
            if action == "key":
                if not key:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "key: key= required"})
                res = await c.input_key(
                    key=str(key),
                    action="click",
                    repeat=int(repeat or 1),
                    force=bool(force),
                )
                if not isinstance(res, dict):
                    res = {"ok": False, "error": "input_key: no response"}
                env = {"ok": bool(res.get("ok", False)),
                       "kind": "input_ack",
                       "action": "key",
                       "key": str(key),
                       "repeat": int(repeat or 1)}
                if not env["ok"]:
                    env["error"] = res.get("error") or "input_key failed"
                    if res.get("hint"):
                        env["hint"] = res["hint"]
                return _j(env)

            return _unknown_action("desktop_manage", action, _DESKTOP_ACTIONS_MASTER,
                                   _DESKTOP_ACTION_HELP_INTERNAL)

        return await _guard(ctx, "desktop_manage", action, args, run)

    # Expose the dispatcher so ``desktop_manage`` can forward through
    # the same body.
    global _DESKTOP_MANAGE_FN
    _DESKTOP_MANAGE_FN = desktop_manage
