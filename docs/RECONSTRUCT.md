# Reconstruct-and-verify (`reconstruct_manage`)

`reconstruct_manage` checks a C reconstruction of one function against the original binary. Both versions run under Unicorn on the same inputs, and every declared output is compared.

A pass means only this: the two behaved the same on the tested inputs, with the reported coverage. It is never a proof that the C is equivalent to the original. Say so whenever you record or report a pass.

Slice 1 is **behavioral** and covers:

- **Arches and conventions:** x64 (Win64) and x86 (`cdecl`, `stdcall`, `fastcall`, `thiscall`).
- **Compilers:** MSVC, and clang-cl when it is installed.

Slice 2 adds coverage-guided inputs (see "Inputs" below). Exact-byte matching (recompiling to the original's bytes) comes later in slice 2; see [the slice 2 plan](plans/2026-11-25-reconstruct-verify-slice2.md).

## Workflow

1. Decompile the target function with `ida_manage` or `ghidra_manage`.
2. Declare the prototype as a signature, and confirm it by running the original once:

   ```text
   reconstruct_manage(action='call', sha256='<64 hex>', func='RtlComputeCrc32',
                      signature_json='{"ret":"u32","cc":"stdcall","params":[{"name":"crc","type":"u32"},{"name":"buf","type":"buf_in","size":[0,4096]},{"name":"len","type":"u32","len_of":"buf"}]}',
                      args_json='{"crc":0,"buf":"68656c6c6f"}')
   ```

3. Write the C and compile it. This needs `security.allow_host_compile=true`.

   ```text
   reconstruct_manage(action='compile', code='#include "pry_recon.h"\nu32 PRY_STDCALL crc(u32 c, const u8 *p, u32 n) { ... }',
                      exports=['crc'], arch='x86')
   ```

4. Verify the build against the original:

   ```text
   reconstruct_manage(action='verify', sha256='<64 hex>', func='RtlComputeCrc32',
                      build_id='<16 hex>', export='crc', signature_json='<as above>',
                      cases=1000, seed=7, min_coverage=0.8)
   ```

5. Then iterate:
   - Fix the first mismatch, recompile, and verify again.
   - If blocks stay uncovered, raise `cases` or change `seed` first. Guided inputs (the default) often reach them on their own, and the report's `inputs` block shows the corpus, edges and compare sites.
   - Aim explicit cases (`cases_json`) at the blocks that are still uncovered.
   - Replay an earlier run with `cases_path='reconstruct/runs/<run_id>/inputs.jsonl'`. The response's `next.replay` holds the full call.
6. Record the verdict with `knowledge_manage(action='record', title='<function> reconstructed', severity='info')`. Include the case counts, the seed, the coverage, the run ID, and the bound.

`verify` also accepts `code=` instead of `build_id=`. It then compiles first, and the compile gate applies. The `reconstruct_function` MCP prompt walks through the same loop.

## Actions

| Action | Does | Gate |
|---|---|---|
| `actions` | Per-verb help | — |
| `toolchains` | Detected compilers, the default, the gate state, and whether Unicorn is installed | — |
| `compile` | Builds C into a DLL under `artifacts/reconstruct/builds/<build_id>/` | `security.allow_host_compile` |
| `call` | Runs the original, the reconstruction, or both once with explicit `args_json` | None (pure emulation) |
| `verify` | Differential run over explicit, boundary and coverage-guided inputs (`options_json` `inputs='random'` for seeded random) | Only with `code=` |

How the original is given:

- It takes the same sources `bin_manage` does: `sha256=`, `path=`, or `source='memory'` with `module=` or `address=` for a live image.
- A `source='memory'` original is read again on every call. Its writable sections can change between reads, so the report records the sha256 of the snapshot that ran. To use the same original every time, dump the module first with `file_manage(action='dump_module')`.
- `func` is a VA, `'module+0xRVA'`, or an export name.
- A raw blob without a PE header maps at `0x140000000` (x64) or `0x10000000` (x86), and a numeric `func` is an offset into it.

## Signature spec

```json
{"ret": "u32",
 "cc": "stdcall",
 "params": [
   {"name": "crc", "type": "u32"},
   {"name": "buf", "type": "buf_in", "size": [0, 4096]},
   {"name": "len", "type": "u32", "len_of": "buf"}
 ],
 "stubs": {"kernel32!GetTickCount": [1000, 1016], "Sleep": {"ret": 0, "argc": 1}},
 "ignore": ["api"],
 "float_ulps": 0}
```

| Field | Meaning |
|---|---|
| `ret` | A scalar type, or `void` |
| `params` | At most 8 params. Each has a `name` (a C identifier) and a `type`. |
| Scalar types | `i8 u8 i16 u16 i32 u32 i64 u64 bool ptr f32 f64`. Integer params take `range: [lo, hi]` and `values: [...]` (an extra pool); float params take `values`. |
| `buf_in`, `buf_out`, `buf_inout` | A pointer to bytes the harness owns. Takes `size` (an int or `[min, max]`, up to 1 MiB), `size_multiple`, `align` (default 1), and `fill` (`random`, `zero`, or `bytes` plus `fill_hex`). A `buf_out` starts out holding canary bytes. |
| `cstr`, `wstr` | NUL-terminated, printable by default. `size` is the character range. |
| `len_of` | Ties an integer param to a buffer's byte length (or a string's character count), divided by `len_scale` |
| `cc` | x86 only: `cdecl` (default), `stdcall`, `fastcall` or `thiscall`. x64 always uses Win64. |
| `stubs` | Per-import return values, keyed by function name (a DLL prefix is ignored). A list is consumed one value per call. `argc` is the dword count an x86 `stdcall` callee pops. |
| `ignore` | Outputs to leave out of the comparison: `ret`, `api`, `cleanup`, or a buffer or string name |
| `float_ulps` | Float tolerance. `0` (the default) compares bits exactly. Above 0, any NaN equals any NaN. |

**Errors.** Mistakes come back as `bad_arg`, naming the field and, where it can, the closest valid spelling.

**`thiscall` under MSVC.** MSVC C has no `__thiscall` for free functions. Declare the reconstruction as `PRY_FASTCALL method(void *self, int unused_edx, ...)` and verify it with `cc='thiscall'`. `self` arrives in ECX, the dummy parameter takes EDX, and the remaining arguments sit on the stack where `thiscall` puts them.

## Inputs

Every run uses these input sets, in this order:

1. **Explicit cases** (`cases_json`).
2. **Replayed cases** (`cases_path`).
3. **The boundary set.** It covers:
   - integers: 0, ±1, min, max, and powers of two ±1, clipped to any declared `range`
   - floats: ±0, ±inf, NaN, denormals, and the extreme finite values
   - buffers: sizes 0, 1, odd sizes, and the size limits, plus all-zero and all-0xFF contents
4. **Generated cases**: `cases`, default 256 and capped at 10,000. Duplicates are skipped. How they are made depends on `options_json.inputs`:
   - **`guided`** (the default) is coverage-guided. The sets above run first and seed a corpus.
     - A case joins the corpus when it reaches a new edge of the original (a block-to-block transition) or a new outcome class.
     - A quarter of the generated cases are fresh random ones. The rest mutate a corpus entry.
   - **`random`** gives slice 1's seeded random cases.

**Guided generation** uses two signals from the original:

- **A dictionary**, read statically from the function:
  - compare and arithmetic immediates
  - `lea` offsets
  - range checks: `lea ecx, [r9 - 0x30]` then `cmp cl, 9` gives 0x30..0x39 and the byte just past it

  Integers draw from it. Strings and buffers get its values as bytes and as little-endian tokens.
- **Compare feedback.** The harness hooks every `cmp <operand>, imm` in the original and logs the value it saw.
  - Half the mutations of an entry are input-to-state: take a compare that failed (it saw X and expected K), and write K where X sits in the inputs.
  - When a string compare read the terminator, K is appended to the string.

The other mutations stay within the signature's sizes:

- **Integers:** a dictionary value, a `values` entry, a boundary value, a small step, or a bit flip.
- **Buffers and strings:** bit flips, byte sets, inserts, deletes, tokens, splices and resizes.

Guided mutation can put any non-NUL byte in a string. To keep strings printable, use `inputs='random'`.

The seed is always echoed. The same seed, signature and original reproduce the same cases. `inputs.jsonl` is bit-exact (floats are stored as their IEEE bits and buffers as hex), so a replay needs no guidance.

The report's `inputs` block gives the mode and the case counts by origin. For guided runs, it also gives the corpus size, the edges reached, the dictionary size and the number of compare sites.

Each JSON value form takes these input formats:

| Value | Accepted forms |
|---|---|
| Integer | A number, or a hex string |
| Float | A number, `"nan"`, `"inf"`, or `{"f64": "0x<bits>"}` |
| Buffer | A hex string, `{"hex": ...}`, `{"text": ...}`, or a byte list. A `buf_out` takes only its size, or `{"size": N}`. |
| String | Plain text, or `{"hex": ...}` |

## Harness

Both sides run under identical, private conditions.

### Engine and memory

- **Separate engines.** Each side has its own Unicorn engine, so image bases cannot collide.
- **Images.** Every section is mapped at its full virtual size: `.bss` is zero-filled, and the headers are mapped read-only.
- **The arena.** Both sides share one synthetic address range, chosen clear of both images. It holds the stack, the fake TEB and PEB, the stubs and the buffers. Buffer pointers are therefore identical on both sides.
- **Buffer layout.** Each buffer ends at a page boundary followed by an unmapped guard page, so a one-byte overrun faults. Canary bytes before the buffer show underruns.

### Calls

**Win64:**

- Arguments go in RCX, RDX, R8 and R9 (XMM0–3 for floats). The rest go on the stack above a 32-byte shadow space.
- RSP ≡ 8 (mod 16) at entry.

**x86:**

- Arguments follow the declared convention.
- A float return comes back through an `fstp` trampoline.
- A 64-bit return comes back in EDX:EAX.
- The bytes the callee popped are measured.

**Both arches:**

- Narrow integer arguments carry garbage in their unused upper bits. The ABI does not promise those bits, so code must not rely on them.
- GS (x64) or FS (x86) points at a zeroed fake TEB with valid self, PEB and stack fields.

### Imports and CFG

Every IAT and delay-IAT slot points at a stub, matched by function name regardless of DLL.

**Semantic stubs** implement these routines:

- the memory and string routines: `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`, `strlen`, `strnlen`, `wcslen`, `wcsnlen`, `strcmp`, `strncmp`, `wcscmp`, `wcsncmp`, `strcpy` and `wcscpy`
- the Rtl routines: `RtlZeroMemory`, `RtlFillMemory`, `RtlMoveMemory`, `RtlCopyMemory` and `RtlCompareMemory`
- the x86 64-bit math helpers: `_alldiv`, `_aulldiv`, `_allrem`, `_aullrem`, `_allmul`, `_alldvrm`, `_aulldvrm`, `_allshl`, `_allshr` and `_aullshr`

Semantic stub calls are counted but not compared. An original that inlines `memcpy` still matches a reconstruction that imports it.

**Any other import** is logged, returns its `stubs` value (default 0), and marks the case `api_stubbed`. The order of these calls is compared.

**CFG.** The load-config CFG check and dispatch pointer slots point at `ret` and `jmp rax` stubs.

### Detection and coverage

**The uninitialized-read probe.** Each case runs twice per side, with different stack contents, register values and upper-bit garbage. The two sides always see the same fills.

- If the reconstruction's outputs change between its two runs, the case is a `stability` mismatch: the C reads an uninitialized local or register.
- If the original's outputs change, the case is `unstable` and never counts as a match. The signature may be missing a parameter.

**Coverage.** Static blocks of the original come from the analysis engine (the x64 or x86 decoder, bounded by `.pdata` and the exports). They are made disjoint first: each block ends where the next one starts. Then a shared tail, such as a `ret` that several paths fall into, cannot mark those paths as covered. A block counts as covered when an executed block overlaps it. The report lists each uncovered block with its first instruction.

### Outcomes

Each run ends in one of these classes:

- `returned`
- `fault:read`, `fault:write`, `fault:fetch`
- `cpu_exception`, with a detail such as `divide_error`, `invalid_opcode`, `int3`, `fastfail` or `hlt`
- `unsupported:syscall`, from `syscall`, `sysenter` or `int 0x2e`
- `unsupported:opcode`, for an instruction Unicorn cannot run (AVX ymm forms, for example)
- `unresolved_call`, for a fetch outside every mapped region
- `cap`, when the instruction limit (`options_json.max_insns`, default 5,000,000) is reached

The `unsupported:*`, `unresolved_call` and `cap` outcomes never count as a match.

## Comparison and verdicts

Each case compares these outputs, in this order:

1. The outcome class. Two runs that fault the same way compare on the class alone.
2. The return value, masked to the declared width.
3. Every buffer and string, byte for byte, including the canary bytes on either side. An overrun therefore shows up at an offset past the end.
4. The order of stubbed API calls.
5. On x86, the bytes the callee popped. This catches `stdcall` against `cdecl`.

These are reported but not compared:

- writes into the image (globals)
- raw API arguments
- callee-saved register preservation (`abi`)
- instruction counts

**Verdicts:**

- **`mismatch`**: at least one case differs. The first five mismatches carry their inputs, the differing field, and a hex window around the first differing offset. All recorded mismatches are in `mismatches.jsonl`.
- **`inconclusive`**: there was no mismatch, but `reasons` lists what could not be vouched for. The possible reasons are:
  - unsupported constructs
  - unstable original cases
  - nothing comparable
  - every case faulting on both sides
  - coverage under `min_coverage`
  - the time budget (`timeout_s`, default 60) running out
- **`equivalent_on_tested_inputs`**: everything that was compared matched.

Runs are synchronous. A run that stops early comes back with `partial: true`.

## Toolchains and the compile step

| Toolchain | Needs | Notes |
|---|---|---|
| `msvc` | A Visual Studio or Build Tools install with the C++ workload | x64 uses the `vcvarsall amd64` environment and x86 uses `amd64_x86`. The environment is captured once per process (about 1 s). |
| `clang-cl` | `clang-cl`, plus a Visual Studio install for the CRT and SDK. It is found in the `reconstruct.clang_cl` override, the Visual Studio "C++ Clang tools for Windows" component, `Program Files\LLVM`, a per-user `%LOCALAPPDATA%\Programs\LLVM`, or on PATH. | It uses the same flag profile plus `--target`, and links with `lld-link` (or with `link` when no `lld-link` is present). A reconstruction that behaves differently under the two compilers depends on undefined behavior. `lld-link` also links the CRT's load-config object, so these DLLs carry a load config (security cookie, CFG pointers) and, on x64, an unused `memcpy` import. The harness stubs both. |
| `mingw-gcc` | — | Detected but not supported in slice 1 |

**Compile profile:**

- Compile: `/TC /GS- /Gy /MD /W3`, an optimization level, an FP model, `/Oi` unless turned off, strict-regex defines, and on x86 an optional `/arch:IA32|SSE|SSE2`.
- Link: `/DLL /NOENTRY /DYNAMICBASE:NO /BASE:<fixed>`, one `/EXPORT:` per export, and the CRT import libraries named explicitly.

**Advanced knobs.** These go in one `options_json` object, checked key by key:

| Group | Key | Values | Default |
|---|---|---|---|
| compile | `opt` | `Od`, `O1`, `O2` | `O2` |
| compile | `fp` | `precise`, `strict`, `fast` | `precise` |
| compile | `intrinsics` | `true` or `false` (`/Oi`) | `true` |
| compile | `defines` | `["NAME", "NAME=VALUE"]` | none |
| compile | `x86_arch` | `IA32`, `SSE`, `SSE2` (x86 only) | none |
| run | `boundary` | `true` or `false`: include the boundary set | `true` |
| run | `probe` | `true` or `false`: the uninitialized-read probe | `true` |
| run | `max_insns` | per-run instruction cap | `5000000` |

For example: `reconstruct_manage(action='compile', code='<C>', exports=['f'], options_json={'opt': 'Od', 'defines': ['DEBUG']})`.

**Source guard.** It runs before any tool does, after line splices and comments are removed. It allows only:

- angle-bracket includes of plain relative header names, plus `"pry_recon.h"`
- an allowlist of preprocessor directives and pragmas

It rejects:

- absolute or `..` include paths
- `#pragma comment`
- `#embed`, `#import` and `#include_next`
- the `_Pragma` and `__pragma` operators
- trigraphs and digraph directives

**`pry_recon.h`** ships with the tool. It provides fixed-width types, decompiler aliases (`_DWORD` and similar), rotate and byte macros, and the `PRY_EXPORT`, `PRY_CDECL`, `PRY_STDCALL` and `PRY_FASTCALL` macros.

**Build IDs.** A build ID is content-addressed over the source, the header, the flags, the exports, the toolchain and the arch, so an identical compile is a cache hit. The limits are 60 s for a compile, 30 s for a link, 16 MiB per DLL, and 512 KiB of source.

**Hard rule.** Build outputs are only ever read as bytes by the emulator's mapper. Nothing loads them natively on the host, and a test enforces this.

## Files

| Path | Contents |
|---|---|
| `artifacts/reconstruct/builds/<build_id>/` | `source.c`, `pry_recon.h`, `build.log`, `recon.dll`, `meta.json` |
| `artifacts/reconstruct/runs/<run_id>/` | `report.json`, `inputs.jsonl`, `mismatches.jsonl` |

## Config

```yaml
security:
  allow_host_compile: false     # compile, and verify with code=
reconstruct:
  default_toolchain: msvc       # msvc | clang-cl
  vs_path: ""                   # VS install root; empty = newest under Program Files
  clang_cl: ""                  # clang-cl.exe override (default: VS Llvm, LLVM, PATH)
  lld_link: ""                  # lld-link.exe override
  compile_timeout_s: 60
  link_timeout_s: 30
  default_cases: 256
  max_insns: 5000000
```

## Known limits (slice 1)

**Unicorn 2.1.4:**

- AVX `ymm` instructions don't run. They are classified `unsupported:opcode`.
- `syscall` and `sysenter` are never emulated.
- `rdtsc` cannot be hooked and varies between runs, so the probe reports it as instability.
- `hlt` stops the emulator. It is classified as a `cpu_exception`.

**Inputs and environment:**

- There are no `malloc` or `free` semantics, so allocators return their `stubs` value.
- Global state is not compared.
- There is no struct field typing: a struct is a buffer.
- There are no callbacks.

**Unknown x86 imports.** For an x86 `stdcall` import that is not in the built-in table, set `stubs.<name>.argc`. Without it the caller's stack drifts after the call.

**Coverage.** Coverage counts only the named function's blocks. On x86, which has no `.pdata`, a tail jump can add the callee's blocks. That only lowers the reported ratio.
