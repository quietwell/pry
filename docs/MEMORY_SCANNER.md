# Memory scanner

Memory scanner for `memory_manage`. Lets you do an
interactive **first-scan → mutate → next-scan** loop, keep an undo
stack of generations, and snapshot every aligned slot of a region
(unknown-initial-value).

Covers four gaps vs CE: typed value scans, region filters, iterative
`next_scan`, and `op='unknown'` snapshots. Full design in
`an internal plan`.

## Quick workflow

```
# 1) Find every writable heap int32 that equals 100
memory_manage(action='value_scan',
              pid=1234, value_type='int32', op='eq', value=100,
              scope='heap', writable=True)
→ {ok: true, data: {scan_id: 'v0001', hit_count: 42,
                    items: [{va: '0x...', value: 100}, ...]}}

# 2) Player loses health in the target. Narrow.
memory_manage(action='next_scan', scan_id='v0001',
              op='decreased')
→ {ok: true, hit_count: 7, dropped: 35,
   hits: [{va: '0x...', prev_value: 100, curr_value: 87}, ...]}

# 3) Repeat until you have a handful of candidates.
memory_manage(action='next_scan', scan_id='v0001', op='decreased')
memory_manage(action='next_scan', scan_id='v0001', op='decreased')

# 4) Wrong direction? Pop the last refine.
memory_manage(action='scan_undo', scan_id='v0001')

# 5) Done. Free the snapshot.
memory_manage(action='scan_destroy', scan_id='v0001')
```

## Verbs

| verb | summary |
|------|---------|
| `value_scan`    | first-scan a typed value in a region. Returns `scan_id` + hits. |
| `next_scan`     | refine a scan against current memory. Compares against the stored prev value per hit. |
| `scan_undo`     | pop the top undo frame; restore the previous generation. |
| `scan_destroy`  | free the snapshot (RAM + disk). |
| `scan_list`     | show every live scan on the orchestrator (works on both pattern and value scans). |
| `scan_status`   | progress / state of one scan. |
| `scan_cancel`   | stop a running scan. |
| `scan_result`   | fetch rows from a finished scan (pagination). |

## Value types + ops

**types**: `int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`,
`int64`, `uint64`, `float`, `double`, `string`, `utf16`.

**first-scan ops**: `eq`, `lt`, `gt`, `between`, `unknown`.

**next-scan ops**: `eq`, `lt`, `gt`, `between`, `changed`,
`unchanged`, `increased`, `decreased`, `increased_by`,
`decreased_by`.

### Key kwargs

- `endian`: `le` (default) or `be`. Ignored for strings — use
  `encoding` instead.
- `encoding` (strings only): `ascii`, `utf8`, `utf16le`, `utf16be`.
- `align`: `1`, `2`, `4`, `8`, or `auto` (default). Relative to span
  start, not absolute VA.
- `tolerance`: float/double only. Defaults to `1e-4` for `float`,
  `1e-7` for `double`. Strict equality for every other type.
- `confirm_full_space`: required for `op='unknown'` over the whole
  address space. Narrow with `scope='heap'`/`writable=True`/`sections=`
  instead when you can.
- `scope`: `heap` / `stack` / `image` / `all` (default). Combines with
  region flags (AND semantics) and with `sections=`.

## Region filter (shared with `pattern_scan`)

| flag | effect |
|------|--------|
| `writable=True`        | drop read-only pages |
| `executable=True`      | keep only PAGE_EXECUTE* |
| `cow=True`             | keep only `PAGE_WRITECOPY` / `PAGE_EXECUTE_WRITECOPY` |
| `include_guarded=True` | include `PAGE_GUARD` pages (default: skip) |
| `mem_types=['private','image']` | filter by VAD type (short labels; the Vad* names and raw ints also accepted; no `mapped` label this wave — see region_filter.py) |
| `scope='heap'`         | union with `mem_heaps` ranges |
| `scope='image'`        | union with loaded-module ranges |
| `scope='stack'`        | union with TEB stack ranges (x64) |

See `orchestrator/src/pry/mcp/tools/mem/region_filter.py` for the
predicate implementation.

## Where the snapshot lives

Today (`scan_service_version == 0` on every agent), the snapshot lives
in **orchestrator RAM**. One scan is capped at 128 MiB (plan §2.7
v15-fallback cap). Undo stack depth 4. The v15 path works against the
current live agent — no rebuild required.

When the agent rebuild lands with `scan_service_version` flipped to 1,
the snapshot moves to the **target** under
`<agent_dir>\scans\<view>\<scan_id>\`. Disk spill kicks in above
256 MiB RAM; the agent-side cap is 8 GiB per scan and 32 GiB per
machine (overridable via `targets.json` — see §Per-machine policy below).

## Per-machine policy

`MachineConfig.scan` (dataclass field on the machine config):

```yaml
machines:
  lab2:
    host: 10.0.2.15
    kernel_port: 50099
    scan:
      dir: ""                      # default <agent_dir>\scans
      disk_quota_bytes: 34359738368  # 32 GiB
      disk_spill: "auto"            # auto | ram_only | disabled
```

`disk_spill: "ram_only"` is equivalent to `disk_quota_bytes: 0`:
snapshots that would spill return `kind='would_exceed'`.

## Error-kind reference

| kind | when |
|------|------|
| `bad_arg`           | unknown value_type / op / endian / encoding; tolerance on non-float; `between` without `value_hi`; `unknown` with `value` set |
| `too_wide`          | sync `value_scan` span total > 64 MiB — call `scan_start` or narrow |
| `would_exceed`      | pre-flight proves snapshot cap would blow |
| `no_match`          | region filter resolved to zero spans |
| `unknown_scan`      | `scan_id` not in registry |
| `foreign_owned`     | another `client_id` owns the scan |
| `not_ready`         | underlying scan still running |
| `no_undo`           | undo stack empty |
| `busy`              | `scan_destroy` called on a running scan |
| `needs_v16`         | orchestrator build predates v16 pb2_grpc |

## Gaps

- **Agent-side on-target path**: scaffold is in
  `agent/src/scan/scan_service.{hpp,cpp}` but compiled dormant. Enable
  by setting `scan_service_version(1)` in `services_agent.cpp` +
  `um_services.cpp` after a build + e2e pass against the toy target.
- **Reverse pointer scanner**: Wave 2.
- **Group / struct scan**: Wave 2.
- **Dissect data + address list**: Wave 3.
- **Freeze**: Wave 4.

# Memory scanner (Wave 2)

Persisted pointer maps, reverse pointer scanner, pointer-map diff, and
a one-shot typed dissector. Requires an agent at ABI v17
(`pointer_map_version >= 1` in `StatusResponse`); pre-v17 agents return
`kind='needs_v17'` with the ABI rebuild recipe named in the hint. Full
design in `an internal plan`.

Pointer maps are **immutable** after creation — unlike Wave 1 scans
there is no `next_scan` / `undo`. The ritual is scan → do thing →
rescan → diff.

## Quick workflow

```
# 1) Snapshot every aligned pointer in a running process.
memory_manage(action='pointer_map_create',
              pid=1234, scope='all', writable=True)
→ {ok: true, data: {map_id: 'pm_a1b2_0001', status: 'running'}}

memory_manage(action='pointer_map_status', map_id='pm_a1b2_0001')
→ {ok: true, data: {status: 'done', entries: 2814271,
                    disk_bytes: 56285420}}

# 2) Reverse-walk from a known-live VA (e.g. the current health slot).
memory_manage(action='pointer_scan',
              map_id='pm_a1b2_0001',
              target_va=0x1a2b3c4d5000,
              max_depth=4, static_only=True)
→ {ok: true, data: {chains: [...], truncated: false,
                    wall_ms: 412, candidates_examined: 1218}}

# 3) Save the map to disk before you touch the target.
memory_manage(action='pointer_map_save',
              map_id='pm_a1b2_0001',
              remote_path='D:/scans/game_boot1.map')

# 4) Bounce the service / reboot the target. Reconnect, remap.
memory_manage(action='pointer_map_create',
              pid=5678, scope='all', writable=True)
→ {ok: true, data: {map_id: 'pm_c3d4_0001', status: 'running'}}

# 5) Load the pre-reboot map back into the registry.
memory_manage(action='pointer_map_load',
              remote_path='D:/scans/game_boot1.map')
→ {ok: true, data: {map_id: 'pm_a1b2_0002', entries: 2814271}}

# 6) Diff — which chains still resolve?
memory_manage(action='pointer_map_diff',
              map_id='pm_a1b2_0002',
              map_id_b='pm_c3d4_0001',
              static_only=True)
→ {ok: true, data: {rows: [...], compared_entries: 2814271}}
```

## Verbs

| verb | summary |
|------|---------|
| `pointer_map_create`  | scan a process for every aligned pointer. Returns `map_id`; runs async, poll with `pointer_map_status`. |
| `pointer_map_status`  | progress + final entry count / disk bytes. |
| `pointer_map_list`    | every live map on the connected view. |
| `pointer_map_cancel`  | abort an in-flight sweep. |
| `pointer_map_save`    | copy the on-disk mirror to a named remote path. Keeps the live `map_id`. |
| `pointer_map_load`    | mmap a previously saved map. Returns a fresh `map_id`. |
| `pointer_map_destroy` | free registry entry + disk mirror (`keep_disk=True` keeps the mirror). |
| `pointer_scan`        | reverse-BFS from `target_va` → `base + offs[]` chains. |
| `pointer_map_diff`    | diff two maps; emit which sources still resolve to the same `module!offset`. |
| `dissect`             | one-shot per-slot typed decode of a memory window. |

## Pointer-map create recipes

| caller intent | `memory_manage(action='pointer_map_create', ...)` args | notes |
|---|---|---|
| scan everything (CE default)   | `pid=1234, scope='all', writable=True`                    | every committed writable VAD plus image R-X pages — pointers live in `.data` / `.rdata` too. |
| only heap + stack              | `pid=1234, scope=['heap','stack']`                        | typical game object graph; cheap. |
| only image data                | `pid=1234, scope='image', sections='.data,.rdata'`        | finds global pointers. CE "static only" source set. |

`sections=` and region flags (`writable`, `executable`, `include_guarded`,
`mem_types=`) are honoured byte-for-byte; no silent widening.

## Pointer-scan tuning

| preset | `max_depth` | `fanout_per_level` | `wall_ms` | expected chains | when to use |
|---|---|---|---|---|---|
| tight   | 2 | 256   | 3_000  | ~tens       | fast triage — does anything at all reach the target? |
| default | 4 | 2048  | 15_000 | ~hundreds   | normal CE-style search. Matches plan §2.7 defaults. |
| broad   | 7 | 4096  | 30_000 | ~thousands  | nothing survived at default; cast a wider net. |

Exact chain counts depend on process size and pointer-graph density.
A dense game heap at depth 7 can saturate `max_results=4096` in under a
second; a sparse service process at the same settings may return a
handful. Caps enforced agent-side: `POINTER_SCAN_MAX_DEPTH=7`,
`POINTER_SCAN_MAX_RESULTS=4096`, `POINTER_SCAN_MAX_OFFSET=0x1000` per
hop. Breaches return `kind='fanout_exceeded'` or `kind='wall_ms_exceeded'`
with the knob named in the hint.

`static_only=True` prunes chains that don't terminate in an image
section — the chains worth keeping across reboots.

## Diff across reboots

Static anchors survive reboots because `module!offset` is ASLR-stable;
heap anchors don't. The diff path canonicalises each anchor to
`ToLowerAscii(basename(module)) + offset` before comparing, so the
mixed casing Windows `GetModuleFileNameW` variants return doesn't
break matches.

```
# Before the reboot.
memory_manage(action='pointer_map_create',
              pid=1234, scope='all', writable=True)
→ {map_id: 'pm_pre_0001', status: 'running'}
memory_manage(action='pointer_map_save',
              map_id='pm_pre_0001',
              remote_path='D:/scans/pre.map')

# ... reboot the target ...

# After the reboot, same process, new pid, new ASLR.
memory_manage(action='pointer_map_create',
              pid=9012, scope='all', writable=True)
→ {map_id: 'pm_post_0001', status: 'running'}
memory_manage(action='pointer_map_load',
              remote_path='D:/scans/pre.map')
→ {map_id: 'pm_pre_0002', entries: 2814271}

memory_manage(action='pointer_map_diff',
              map_id='pm_pre_0002',
              map_id_b='pm_post_0001',
              static_only=True)
→ {rows: [
     {source_va_a: 0x..., source_va_b: 0x..., target_va_a: 0x...,
      target_va_b: 0x..., canonical_target: 'kernel32.dll!0x2000',
      still_valid: true,  drift_reason: ''},
     {source_va_a: 0x..., source_va_b: 0x..., target_va_a: 0x...,
      target_va_b: 0,     canonical_target: '',
      still_valid: false, drift_reason: 'target_unmapped'},
     ...
   ]}
```

`drift_reason` values: `''` (still valid), `'target_unmapped'` (the
target VA is no longer committed), `'module_unloaded'` (the anchor
module is gone), `'value_changed'` (both sides resolve but to a
different `module!offset`).

Pass `chains=[...]` from an earlier `pointer_scan` to filter the diff
to just those chains — the common "I saved a chain, does it still
work?" workflow.

## Dissect

One-shot typed decode of a memory window. No state, no `scan_id`.

```
memory_manage(action='dissect',
              pid=1234, address=0x7ff000000000, size=256,
              with_modules=True)
→ {ok: true, data: {slots: [
     {offset: 24, va: '0x7ff000000018',
      u64_hex: '0x00007ff8ab004c00',
      i32_le: 2868674048, u32_le: 2868674048,
      f32_le: -1.4267e30, f64_le: 1.31e-310,
      pointer: {target_va: '0x7ff8ab004c00',
                symbol: 'ntdll.dll+0x4c00',
                classification: 'code'},
      ascii_prefix: null, utf16_prefix: 'Program',
      probable_type: 'pointer'},
     ...
   ]}}
```

Row fields:

- `offset` — byte offset from `address`.
- `va` — absolute VA of the slot.
- `u64_hex` — raw 8-byte LE value, hex.
- `i32_le` / `u32_le` — slot decoded as little-endian int32 / uint32.
- `f32_le` / `f64_le` — slot decoded as little-endian float / double.
- `pointer` — present when `u64_hex` lands on a committed region;
  `{target_va, symbol, classification}`. `with_modules=True` resolves
  `symbol` to `module.dll+0xOFFS`. `classification` is one of
  `image_text`, `image_rdata`, `image_data`, `heap`, `stack`,
  `image_unknown`, `code`, `other`.
- `ascii_prefix` / `utf16_prefix` — short printable prefix when the
  slot starts a plausible string; `null` otherwise.
- `probable_type` — best guess; tiebreak order
  **pointer > utf16 > ascii > f64 > f32 > i32**.

Caps: `DISSECT_MAX_BYTES=65_536`, `DISSECT_MAX_ROWS=4096`.

`dissect` has a v16 fallback: when `pointer_map_version=0` the
orchestrator runs the decode itself via the existing `mem.read`
path. Slower, and pointer targets don't get the deep module-symbol
annotation an on-target dissector produces, but the row shape is
identical.

## Error-kind reference (Wave 2 additions)

| kind | when | hint |
|------|------|------|
| `needs_v17`          | agent `pointer_map_version < 1` — v16 or older. Pointer-map and reverse-scan verbs have no orchestrator fallback. | rebuild agent per README "ABI v17 rebuild" |
| `pointer_map_full`   | `POINTER_MAP_COUNT_PER_MACHINE` (default 8) reached; `pointer_map_destroy` an old map or raise the cap. | raise `machines.<name>.pointer_map.max_maps` |
| `wall_ms_exceeded`   | reverse scan hit the wall-clock budget before `max_results`. Partial chains returned with `truncated=true`. | raise `wall_ms` or lower `max_depth` / `fanout_per_level` |
| `fanout_exceeded`    | a BFS depth level produced more candidates than `fanout_per_level`. | lower `max_depth` or raise `fanout_per_level` |
| `drift_detected`     | informational — diff returned rows whose target moved. Not a failure; check `drift_reason` per row. | — |
