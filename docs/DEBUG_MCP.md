# debug_manage / bp_manage — the state loop

A guide for driving the pry user-mode debugger from an LLM.
Replaces the older pattern of "`continue` then poll `events`" —
the live surface is now a state loop: every mutating verb returns a
`state` block (the `StopInfo` snapshot), and the waiting verbs block
server-side until the target actually stops.

> See `an internal plan` for the design
> doc, and `docs/E2E_SCENARIO.md` for the lab-VM walk-through.

---

## 1. The cookbook — launch, break, inspect, resume

```text
# 1) Spawn the target; it stops at the entry point.
debug_manage(action='launch', cmdline='C:\\lab\\victim.exe')
  → { ok:true, pid:1234, state:{ active:true, stopped:true,
                                  stop_reason:'launch',
                                  rip:'0x7ff6...', arch:'x64',
                                  seq:1, ... } }

# 2) Arm a conditional breakpoint on a function of interest. Otherwise an
#    LLM would have had to resume + poll events; here the bp
#    itself does the filtering.
bp_manage(action='add', kind='sw',
          address='victim.exe!main',
          condition='@rcx == 0',
          one_shot=True,
          pid=1234)

# 3) Resume and wait for the next stop. `run` is `continue` + wait; the
#    response is the StopInfo for the next break.
debug_manage(action='run', timeout_s=10)
  → { ok:true, state:{ active:true, stopped:true,
                       stop_reason:'bp_sw', bp_id:3,
                       rip:'0x7ff6...', symbol:'victim!main+0x0',
                       pid:1234, tid:5678, seq:7, arch:'x64',
                       timed_out:false } }

# 4) Read registers, flip rax, resume. `set_regs` now round-trips 0
#    (B1); in older builds `rax=0` was a silent no-op.
debug_manage(action='regs')
debug_manage(action='set_regs', regs_json='{"rax":"0"}')
debug_manage(action='run', timeout_s=10)
  → { ok:true, state:{ stop_reason:'process_exit', active:false, ...} }
```

Every mutating response in the loop carries `state`; there is no
`events` polling anywhere in this sequence.

---

## 2. The `StopInfo` field catalogue

Returned under `state` on every mutating envelope. All ints that
represent addresses are hex-stringified by the agent client; the
integer form is available on an `_int` mirror key where the response
has been through `_hexify_dict` (that's how the rest of the pry
tools expose hex values).

| Field | Type | Meaning |
|-------|------|---------|
| `active` | bool | Session is live. False after `process_exit` or `detach`. |
| `stopped` | bool | Target is parked in the debugger. False when `active` but running (monitor mode). |
| `timed_out` | bool | The waiting call (`run`, `wait`, `pause`, `run_to`, `step_out`) hit its deadline before the target stopped. The response is still `ok:true` — the LLM retries or does something else. |
| `pid` | int | Debugee process id. |
| `tid` | int | Thread id that caused the stop. 0 when no stop yet. |
| `rip` | hex-string | Instruction pointer at stop (or `eip` for x86). |
| `symbol` | str | `"module!name+0xNN"`; empty if dbgeng cannot resolve. |
| `stop_reason` | str | One of `"bp_sw"`, `"bp_hw"`, `"step"`, `"pause"`, `"exception"`, `"process_exit"`, `"attach"`, `"launch"`, `"monitor_hit"`, `"none"`. |
| `seq` | int | Session-wide monotonic counter. Use as an idempotency / staleness key: two calls that returned the same `seq` saw the same stop. |
| `arch` | str | `"x64"` | `"x86"` | `"wow64"`. The MCP never crashes on an x86 session, but register display downgrades to the detected arch. |
| `exception_code` | int | NTSTATUS on `stop_reason == "exception"`; 0 otherwise. |
| `first_chance` | bool | True on the first-chance notification for an exception. |
| `bp_id` | int | The bp whose hit produced this stop; 0 outside `bp_sw` / `bp_hw`. |

A `status` response is the one place `state` appears outside a
mutation. Pure read, no gate, no side effect:

```text
debug_manage(action='status')
  → { ok:true, state:{ active:true, stopped:true, stop_reason:'bp_sw',
                       rip:'0x7ff6...', seq:7, arch:'x64', ... } }
```

On an inactive session, `status` returns `state.active=false` and
elides every other field.

---

## 3. The 30-second rule

`run`, `wait`, `pause`, `run_to`, and `step_out` are the waiting
verbs. They accept a `timeout_s: int = 0` kwarg (default 20 s, hard
max 30 s). The server enforces the cap too; a `timeout_s=60` arrives
clamped to 30 s. On timeout the response is `{ok:true, state:{...,
timed_out:true, stopped:false}}` — never a gRPC
`DEADLINE_EXCEEDED` surfaced as an MCP error.

```text
# Target in a tight loop. 1s timeout surfaces timed_out, not failure.
debug_manage(action='run', timeout_s=1)
  → { ok:true, state:{ timed_out:true, stopped:false, active:true, seq:8 } }

# Park it from the other side.
debug_manage(action='pause', timeout_s=5)
  → { ok:true, state:{ stopped:true, stop_reason:'pause', rip:... } }
```

The cap keeps the MCP host from killing the request; it has nothing
to do with symbol-load latency or dbgeng's internal 50 ms post-
`Continue` pump (which is a separate, deliberate idle to let int3
patches commit before the first wait). See §1 of the plan file for
the nuance.

---

## 4. Monitor mode — `wait` resolves on exit / exception only

When `launch` or `attach` is called with `monitor=True`, the engine
loop auto-resumes on bp / exception hits. This is what
`bp_manage(events, mode='auto')` relies on to observe HW bps without
parking the target.

In monitor mode `wait` does *not* resolve on a bp hit (the engine
already resumed it). It resolves only on `process_exit` or an
unhandled exception. `run` can still be used, but behaves like a
no-op because the target is already running — prefer `wait` for a
clean "when does this process end?" primitive.

```text
debug_manage(action='attach', pid=1234, monitor=True)
debug_manage(action='wait', timeout_s=30)
  → { ok:true, state:{ stop_reason:'process_exit', active:false, ...} }
```

A bp hit in monitor mode shows up in the debug event ring instead —
`debug_manage(action='events')` for history, or
`bp_manage(action='events', mode='auto')` for the HW-bp hit feed.

**Caveat** (known issue): dbgeng's
event pump does not always surface `EXIT_PROCESS` through
`WaitForEvent` when the target is killed externally
(`TerminateProcess` from another process, `.kill` + resume races,
very short-lived victims). In those cases `wait` returns
`{timed_out:true, state:{active:true, ...}}` even though the OS has
reaped the pid. Confirm with `process_manage(action='get', pid=...)`
— an empty `items` list means the target is dead and you can
`detach` to clean up.

---

## 5. Worked examples

### 5a. Breakpoint with `condition` + `one_shot`

```text
bp_manage(action='add', kind='sw',
          address='kernel32.dll!CreateFileW',
          condition='poi(@rcx) == 0x5C',   # dbgeng expression: first char == '\\'
          one_shot=True,
          pid=1234)
  → { ok:true, bp_id:5 }

debug_manage(action='run', timeout_s=30)
  → { ok:true, state:{ stop_reason:'bp_sw', bp_id:5,
                       symbol:'kernel32!CreateFileW', rip:'0x7ff...',
                       stopped:true, active:true } }
```

Under the hood the condition becomes dbgeng's `j (…) 'gc'; 'gc'` — the
engine evaluates the expression on every hit, continues silently when
it is false, and parks the target when it is true. `one_shot`
appends `; bc 5; gc` to the post-hit command list so the bp removes
itself after breaking once. Combining `condition` with `commands`:
the command list runs first, then the j-expression.

### 5b. Flipping `rax` and resuming — the round-trip fix (B1)

```text
debug_manage(action='run', timeout_s=10)
  → stops at bp
debug_manage(action='regs')
  → { rax:'0x1', rip:'0x...', ... }

# Older builds: silent no-op — `if (vals[i] && ...)` skipped the
# zero. Writes every GPR unconditionally.
debug_manage(action='set_regs', regs_json='{"rax":"0"}')
debug_manage(action='regs')
  → { rax:'0x0', ... }   # confirmed
```

### 5c. `cmd` that changes session state (B8)

Any raw dbgeng command that resumes or detaches the session now
echoes the resulting `StopInfo`. The LLM sees `state.active=false`
on `.detach`, `state.active=false` on `q`, and `state.stopped=true`
on `bp` / `~.` etc.

```text
debug_manage(action='cmd', command='.detach')
  → { ok:true, output:'…', state:{ active:false, stopped:false } }

debug_manage(action='cmd', command='g')
  → { ok:true, output:'…', state:{ active:true, stopped:false } }
    # target is now running — follow with `wait` to catch the next stop.
```

### 5d. `run_to` — a one-shot sw bp wrapped in a wait

```text
debug_manage(action='run_to',
             address='victim.exe!cleanup',
             timeout_s=30)
  → { ok:true, state:{ stop_reason:'bp_sw', bp_id:<temp>,
                       symbol:'victim!cleanup', rip:'0x...' } }
```

The temporary bp is removed on any stop (even a non-matching one),
so there is nothing to clean up afterwards.

---

## 6. Action reference

### Non-mutating (no gate, no state transition)

- `status` — return the cached StopInfo without touching the target.
- `regs`, `threads`, `stacktrace`, `read`, `regions`, `events`,
  `modules`, `disasm`, `resolve`, `actions`.

### Mutating (gated through the per-pid lease)

- `launch`, `attach`, `detach`.
- `continue`, `step_into`, `step_over`, `step_out`.
- `run`, `run_to`, `wait`, `pause`.
- `set_regs`, `write`.
- `cmd` (may transition state — see §5c).
- `dump` (writes a file on the target).
- `exception` (changes a filter; long-lived state).
- `cancel` (see §6b).

Every mutating response carries `state`. `wait` is observational but
gated for consistency — the lease owner check is cheap.

---

## 6b. Cancel — abort a wedged engine op

`debug_manage(action='cancel')` sends `IDebugControl3::SetInterrupt`
on the engine thread, waits up to ~2 s for the break to land, and
releases the caller's lease on success. Use it when a non-waiting
verb has wedged (symbol-server stall, slow `.reload`, dbgeng
internal) — the 30-second rule only caps waiting verbs.

```text
# Session is alive but stuck inside a `.reload` the LLM started.
debug_manage(action='cancel')
  → { ok:true, state:{ active:true, stopped:true,
                        stop_reason:'pause', rip:'0x...',
                        seq:N, ... },
      released_pids:[1234] }
```

Notes:

- `pid` defaults to the current session. Pass `pid=…` to narrow which
  lease to release on multi-pid callers.
- Idle session: returns `ok:true` with `state.stopped=false`.
- Behind the per-pid lease like every other mutator; pass
  `force=true` to break a foreign-owner lease.

## 6c. Crash context in one call

Exception stops fill `state.regs` (GPR snapshot) and
`state.bytes_at_rip_hex` (16 bytes at `rip`, lowercase hex) by
default. The two reads are best-effort — a `GetRegs` or
`ReadVirtual` failure leaves the respective field empty and never
fails the call.

For non-exception stops, opt in per call with
`include_context=true`:

```text
debug_manage(action='run', include_context=True)
  → { ok:true, state:{ stop_reason:'bp_sw', bp_id:3,
                        rip:'0x7ff6...', ...,
                        regs:{ rax:'0x1', rcx:'0x2', ... },
                        bytes_at_rip_hex:'4883ec28488b0d...' } }
```

The flag threads through `status`, `wait`, `run`, `run_to`,
`step_out`, `continue`, `step_into`, `step_over`, and `pause`. On
exception stops the context arrives regardless. `cmd` does not carry
the flag through the wire, but a `cmd` call that lands on an
exception stop still gets the auto-filled context (same engine path).

## 6d. Crash triage quickstart

The four-line recipe for "what killed it":

```text
# 1) Launch under the debugger.
debug_manage(action='launch', cmdline='C:\\lab\\crasher.exe')

# 2) Run. Exception → regs + 16 bytes at rip are auto-filled.
debug_manage(action='run', timeout_s=20)
  → { state:{ stop_reason:'exception',
              exception_code:0xC0000005,
              rip:'0x7ff6...', symbol:'crasher!main+0x42',
              regs:{...},
              bytes_at_rip_hex:'488b00...' } }

# 3) Grab a minidump next to the source for later post-mortem.
debug_manage(action='dump', kind='mini',
             path='C:\\lab\\crash.dmp')

# 4) Decode the faulting instruction + the eight that follow.
memory_manage(action='disasm',
              address=state.rip,
              bytes_hex=state.bytes_at_rip_hex,
              count=8)
```

No extra `regs` / `read` round trips. The recipe runs against both
`launch` + `run` and a live `attach` + `run`.

---

## 7. Breakpoint extensions (sw only)

`bp_manage(action='add')` gains:

| Kwarg | Maps to | Semantics |
|-------|---------|-----------|
| `condition: str` | dbgeng `j ( … ) 'gc'; 'gc'` on hit | Target resumes silently unless the expression is true. |
| `commands: str` | dbgeng command list | Runs on every hit (before `condition`'s evaluation). |
| `hit_count: int` | proto `pass_count` | Ignores the first `N-1` hits, breaks on the Nth. |
| `one_shot: bool` | appends `; bc <id>; gc` | Auto-remove on the first break. |
| `tid: int` | proto `match_tid` (when `kind='sw'`) | Break only when the hitting engine tid matches. |

HW bps keep the original semantics; the plan explicitly scopes the
extensions to sw bps. Mix freely:

```text
bp_manage(action='add', kind='sw',
          address='ws2_32.dll!send', pid=1234,
          condition='@rdx > 0',
          hit_count=10,
          one_shot=True)
```
