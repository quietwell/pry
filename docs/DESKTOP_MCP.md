# desktop_manage — screen inspection and input injection

The `desktop_manage` surface drives the target's interactive desktop.
Every verb funnels through the session-1 worker — the agent service
runs in session 0 and cannot see or touch the user desktop, so a
locked / logged-off box answers with an explicit error.

## 1. Verb map

| Verb | Mutating | Trust gate | Purpose |
|------|----------|-----------|---------|
| `capture` | no | — | DXGI / WGC screenshot of a display or window. |
| `displays` | no | — | Enumerate attached monitors. |
| `windows` | no | — | Window list grouped by process. |
| `window_props` | no | — | `EnumPropsExW` walk on one HWND. |
| `window_tree` | no | — | Parent / child / owner tree. |
| `window_by_thread` | no | — | Windows grouped by tid (post-fetch regroup). |
| `click` | yes | `min_trust_actuator` | `SendInput` mouse click. |
| `type` | yes | `min_trust_actuator` | `SendInput` text entry. |
| `key` | yes | `min_trust_actuator` | `SendInput` key / chord ('Ctrl+C'). |

`click`, `type` and `key` are the injection verbs. They
route to umagent's `Input` service (umagent runs in session 1, so
`SendInput` reaches the user desktop). The session-0 agent service
never serves them.

## 2. Trust gate (click / type / key)

Input injection is an actuator in the same sense as
`process_manage(action='kill')`: it drives the target. The gate is
`security.min_trust_actuator`; below that trust level a call is
refused unless `force=true` is set.

```text
# untrusted machine, no override → refused
desktop_manage(action='click', x=100, y=200)
  → { ok:false, kind:'trust_refused',
      error:'desktop_manage.click on machine ... refused: '
             'trust=untrusted < security.min_trust_actuator=observe',
      hint:'pass force=true to override, '
           "machines_manage(action='set', trust=...) "
           'to regrade the machine, or lower the config knob' }

# force override
desktop_manage(action='click', x=100, y=200, force=True)
  → { ok:true, kind:'input_ack', action:'click', ... }
```

## 3. Session guard

umagent runs in the active interactive session — session 1 on a
typical lab box, higher on multi-user hosts. `SendInput` only
reaches a session's input queue from within it, so umagent refuses
when its own session differs from `WTSGetActiveConsoleSessionId()`:

```text
→ { ok:false, kind:'input_refused',
    error:'input: umagent not in active session',
    hint:'reconnect umagent to the interactive session' }
```

This is the same guard that already protects `capture` / `windows` —
no new config knob.

## 4. `click` — mouse

```text
desktop_manage(action='click',
               x=100, y=200,          # screen space; -1,-1 = cursor as-is
               button='left',         # 'left'|'right'|'middle'|'x1'|'x2'
               click_count=1,         # 2 → double-click
               modifiers=0,           # bitfield: 1 shift, 2 ctrl, 4 alt, 8 win
               force=False)
  → { ok:true, kind:'input_ack', action:'click',
      x:100, y:200, button:'left', click_count:1 }
```

Behind the gate: a `click_count=2` emits `down+up+down+up` with
inter-event delays bounded by `GetDoubleClickTime()`. Modifier keys
are emitted as keyboard events wrapping the mouse events.

## 5. `type` — text entry

```text
desktop_manage(action='type',
               text='hello world',
               delay_ms=0,           # optional per-character sleep
               force=False)
  → { ok:true, kind:'input_ack', action:'type',
      chars:11, delay_ms:0 }
```

`SendInput` iterates the UTF-16 code points; each is translated via
`VkKeyScanW` to a VK + modifier pair and emitted as
`down-of-modifier + down+up-of-key + up-of-modifier`. Code points
outside the current keyboard layout are sent as `KEYEVENTF_UNICODE`
pairs so arbitrary Unicode makes it through.

## 6. `key` — key / chord

```text
desktop_manage(action='key', key='Ctrl+Shift+F5', force=False)
desktop_manage(action='key', key='Escape')
desktop_manage(action='key', key='Enter', repeat=3)
  → { ok:true, kind:'input_ack', action:'key',
      key:'Ctrl+Shift+F5', repeat:1 }
```

Parses `"Ctrl+Shift+F5"`-style strings into modifier VKs + one key
VK. `repeat > 1` loops the down+up that many times.

## 7. `capture` envelope — scale fields

Three scale fields describe how the orchestrator resized the
agent-side PNG — needed by any caller mapping image-space clicks
back to pixel space:

| Field | Type | Meaning |
|-------|------|---------|
| `native_width` | int | Width of the agent-side PNG before orchestrator resize. |
| `native_height` | int | Height of the agent-side PNG. |
| `scale_factor` | float | `width / native_width`, rounded to 6 decimals. `1.0` means the orchestrator did not resize. |

These fields are returned only on the full-detail path — see §9.2.
Pass `include_details=true` to get them back on an envelope you
plan to do coordinate math against. `scaled: bool` moves with
them.

## 8. Example — walk a crash dialog

```text
# Find the dialog (lean windows[] default).
desktop_manage(action='windows', process_name='target.exe',
               include_hidden=False)

# Capture it for visual inspection (the LLM looks at it).
desktop_manage(action='capture', mode='window', hwnd='0x00050234')

# Click the "Close" button at image-space (320, 180) — needs the
# scale math, so use include_details=true.
res = desktop_manage(action='capture', mode='window', hwnd='0x00050234',
                     max_dimension=1024, include_details=True)
sx = round(320 / res.scale_factor)
sy = round(180 / res.scale_factor)
desktop_manage(action='click', x=sx, y=sy)
```

## 9. Lean defaults — per-window + envelope

Two layers of lean on the `capture` / `windows` / `window_by_thread`
default path. Both switch on the same `include_details` opt-in.

### 9.1 Per-window field projection

Lean set — every field a multimodal caller needs to interpret the
frame and reason about windows:

| Field | Purpose |
|-------|---------|
| `hwnd` | Reuse with `window_props` / `window_tree`. |
| `pid`, `tid` | Caller correlation. |
| `process_name` | Human identification (on the group dict). |
| `title`, `class_name` | Tell windows apart. |
| `rect`, `client_rect` | Position + size; `client_rect` for drawing-area math. |
| `z_order` | Stacking order within the capture. |
| `visible`, `is_foreground`, `minimized`, `maximized` | Visibility state. |
| `dpi` | Per-window DPI for coordinate translation. |

Dropped on the lean path, restored by `include_details=true`:
`process_path` (100+ char WindowsApps Appx paths), `style`, `exstyle`,
`hinstance`, `window_status`, `window_type_atom`, `cloaked`, `border`,
`show_cmd`, `normal_pos`, `parent`, `owner`, `topmost`, `layered`,
`tool_window`, `enabled`, `is_minimized`.

### 9.2 `capture` envelope housekeeping

The lean default keeps the envelope fields a caller actually reads:

| Field | Purpose |
|-------|---------|
| `kind`, `capture_mode`, `target_type`, `target_name` | Routing. |
| `width`, `height` | Pixel dimensions of the returned PNG. |
| `artifact_path` | Where to re-read the image from. |
| `total_windows`, `processes` | Window telemetry. |

Dropped on the lean path, restored by `include_details=true`:
`size_bytes` (duplicate of the on-disk file size), `sha256` (needed
only for cache keys), `filename` (duplicate of `artifact_path`'s
basename), `scaled`, `native_width`, `native_height`, `scale_factor`.
The resize trio ships on the full-detail path because that's when a
caller mapping image-space clicks back to pixel space needs it:

```text
res = desktop_manage(action='capture', max_dimension=1024,
                     include_details=True)
# image-space (ix, iy), screen-space (sx, sy):
sx = round(ix / res.scale_factor)
sy = round(iy / res.scale_factor)
desktop_manage(action='click', x=sx, y=sy)
```

### 9.3 Budget

A busy desktop capture (10+ processes, 30+ windows) drops from
~8–12 KB of per-window telemetry + ~200 B of envelope housekeeping
to ~2–3 KB in the default path. The agent still ships full details
over the wire; the orchestrator trims before the envelope, so
existing agent builds need no change.

```text
# Lean default
desktop_manage(action='capture')
  → 14-field windows[]; no sha256/size_bytes/filename/scale fields

# Opt back into the full dump (both layers)
desktop_manage(action='capture', include_details=true)
  → every field the agent observed + the envelope housekeeping
```

## 10. Non-goals

- No session argument. umagent's session is implicit — always the
  active interactive session.
- No raw `SendInput` passthrough. The three verbs above are the
  whole surface; a future expansion lives in a separate plan.
- No scheduled / timed macros. A caller that wants a multi-step
  recipe orchestrates it on its side.
