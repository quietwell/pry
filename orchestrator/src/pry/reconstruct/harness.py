"""Function-call harness: one private Unicorn instance per side.

A :class:`Harness` maps one image (the original, or the reconstruction
DLL) at its base, an *arena* of synthetic regions at the same VA on
both sides (stack, fake TEB/PEB, buffers, stubs), and calls one
function with one case's inputs per :meth:`Harness.run`.

Isolation: the two sides never share an engine, so image bases cannot
collide; the arena is chosen clear of both images and is identical on
both sides, so pointers into buffers compare equal.

Per run the CPU context is restored from a pristine snapshot, dirty
image/TEB pages are restored, the stack is refilled with the run's fill
pattern, and buffers are rewritten — so one engine (and its translation
cache) serves every case.

Calling conventions:

* x64 Win64 — RCX, RDX, R8, R9 by position (XMM0–3 for floats), the
  rest on the stack above a 32-byte shadow space; RSP ≡ 8 (mod 16) at
  entry; the return address is the arena's end sentinel.
* x86 — ``cdecl`` / ``stdcall`` (all on the stack), ``fastcall`` (the
  first two DWORD-or-smaller args in ECX, EDX), ``thiscall`` (``this``
  in ECX). Floats return through an ``fstp`` trampoline in the arena;
  64-bit ints in EDX:EAX. The bytes the callee popped are measured.

Narrow integer arguments get case-seeded garbage in their unused upper
bits (the ABI does not promise them), and the two fills of the
uninitialized-read probe use different garbage, stack contents and
volatile registers — identical on both sides.
"""

from __future__ import annotations

import bisect
import random
import struct
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

from ..analysis.engine import ImageView
from ..analysis.image_map import image_regions
from ..codegen import _load_unicorn
from .errors import ReconError
from .signature import FLOAT_TYPES, Param, Signature
from .stubs import (KNOWN_X86_ARGC, MAX_STUB_BYTES, StubCpuException,
                    StubFault, StubLimit, semantic_for)

PAGE = 0x1000
MASK52 = (1 << 52) - 1
MASK64 = (1 << 64) - 1

# Arena layout — offsets from the arena base.
OFF_SENTINEL = 0x000000
OFF_STUBS = 0x001000
STUB_STRIDE = 16
MAX_STUBS = 0x10000
OFF_DATA = 0x200000
OFF_STACK = 0x300000
STACK_SIZE = 0x80000
OFF_BUFFERS = 0x400000
ARENA_SPAN = 0x1000000
# Sentinel page.
S_END = 0x000
S_TRAMP_F32 = 0x010
S_TRAMP_F64 = 0x020
S_CFG_CHECK = 0x040
S_CFG_DISPATCH = 0x048
# Data area.
D_TEB = 0x0000          # 0x2000 bytes
D_PEB = 0x2000
D_GDT = 0x3000
D_RETSLOT = 0x4000
DATA_SIZE = 0x5000
PRE_WINDOW = 64         # canary bytes compared before each buffer
CMP_LOG_MAX = 64        # distinct compare observations kept per run

ARENA_CANDIDATES: dict[str, tuple[int, ...]] = {
    "x64": (0x0000_7E00_0000_0000, 0x0000_0E00_0000_0000,
            0x0000_4000_0000_0000, 0x0000_0002_0000_0000),
    "x86": (0x2000_0000, 0x3000_0000, 0x0100_0000, 0x5000_0000,
            0x6000_0000, 0x0800_0000),
}

OUTCOMES = ("returned", "fault:read", "fault:write", "fault:fetch",
            "cpu_exception", "cap", "unsupported:syscall",
            "unsupported:opcode", "unresolved_call")
#: Outcomes the emulator cannot vouch for — never a match.
UNSUPPORTED = frozenset({"cap", "unsupported:syscall", "unsupported:opcode",
                         "unresolved_call"})

_X64_SAVED = ("rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15")
_X86_SAVED = ("ebx", "esi", "edi", "ebp")
_X64_VOLATILE = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
_X86_VOLATILE = ("eax", "ecx", "edx")
_X64_ARGREGS = ("rcx", "rdx", "r8", "r9")


@dataclass
class Side:
    """One side of a comparison: an image view and a function in it."""

    label: str                  # "original" | "reconstruction"
    view: ImageView
    func_va: int
    arch: str                   # "x64" | "x86"

    def span(self) -> tuple[int, int]:
        """[lo, hi) of the image in Unicorn (masked) address space."""
        img = self.view.img
        base = self.view.base_va
        if img is None:
            size = sum(e - s for s, e in self.view.exec_ranges())
        else:
            size = img.size_of_image
        if img is not None and img.sections:
            size = max(size, max(s.va + max(s.vsize, s.raw_size)
                                 for s in img.sections))
        lo = (base & MASK52) & ~0xFFF
        return lo, ((base & MASK52) + max(size, 1) + 0xFFF) & ~0xFFF


@dataclass
class Placed:
    va: int
    nbytes: int
    win_lo: int
    win_hi: int


@dataclass
class RunResult:
    outcome: str
    detail: str = ""
    fault_va: int | None = None
    ret: int | None = None
    buffers: dict[str, bytes] = field(default_factory=dict)
    windows: dict[str, tuple[int, int]] = field(default_factory=dict)
    initial: dict[str, bytes] = field(default_factory=dict)
    api: tuple[str, ...] = ()
    api_semantic: dict[str, int] = field(default_factory=dict)
    cleanup: int | None = None
    abi_clobbered: tuple[str, ...] = ()
    image_writes: int = 0
    image_write_rvas: tuple[int, ...] = ()
    end_pc: int = 0
    elapsed_s: float = 0.0


@dataclass
class _Stub:
    name: str
    dll: str
    delayed: bool
    semantic: tuple[Callable[["Harness"], int], int] | None


def choose_arena(arch: str, spans: list[tuple[int, int]]) -> int:
    """First arena candidate clear of every image span (masked)."""
    for base in ARENA_CANDIDATES[arch]:
        lo, hi = base, base + ARENA_SPAN
        if all(hi <= s or lo >= e for s, e in spans):
            return base
    raise ReconError("layout_conflict",
                     "no arena placement clear of both images",
                     hint="the images cover every candidate arena range; "
                          "report this layout")


def _round_up(v: int, a: int = PAGE) -> int:
    return (v + a - 1) & ~(a - 1)


class Harness:
    """Call one function of one image, case after case."""

    def __init__(self, side: Side, sig: Signature, arena: int, *,
                 seed: int = 0, max_insns: int = 5_000_000) -> None:
        if side.arch != sig.arch:
            raise ReconError("bad_arg",
                             f"{side.label} is {side.arch} but the "
                             f"signature was parsed for {sig.arch}")
        uc = _load_unicorn()
        self._u = uc
        self._X = uc.x86_const
        self.side = side
        self.sig = sig
        self.arch = side.arch
        self.x64 = side.arch == "x64"
        self.ptr = 8 if self.x64 else 4
        self.mask = MASK52 if self.x64 else 0xFFFFFFFF
        self.seed = seed
        self.max_insns = max_insns
        self.arena = arena
        self.end_va = arena + OFF_SENTINEL + S_END
        self.stack_lo = arena + OFF_STACK
        self.stack_hi = self.stack_lo + STACK_SIZE
        self.data_va = arena + OFF_DATA
        self.stubs_lo = arena + OFF_STUBS
        self.notes: list[str] = []
        self.kernel = side.view.base_va > MASK52
        self.mu = uc.Uc(uc.UC_ARCH_X86,
                        uc.UC_MODE_64 if self.x64 else uc.UC_MODE_32)
        self._regs_cache: dict[str, int] = {}
        self._stop: tuple[str, int | None, str] | None = None
        self.api_calls: list[str] = []
        self.api_semantic: Counter[str] = Counter()
        self._api_counts: Counter[str] = Counter()
        self._dirty: set[int] = set()
        self._img_writes = 0
        self._img_write_rvas: set[int] = set()
        self.tbs: dict[int, int] = {}
        # (previous block, block) pairs inside the coverage range; 0 is
        # "entered the range" — the guided input generator's signal.
        self.edges: set[tuple[int, int]] = set()
        self._prev_tb = 0
        # (observed, expected, width) per logged compare site this run,
        # in input terms — the generator's input-to-state signal.
        self.cmp_log: list[tuple[int, int, int]] = []
        self._cmp_hooks: list[Any] = []
        self._initial: dict[str, bytes] = {}
        self._cov_hook: Any = None
        self._cov_range: tuple[int, int] | None = None

        self._map_image()
        self.stub_table: list[_Stub] = []
        self._collect_stubs()
        self._map_arena()
        self._map_buffer_slots()
        self._patch_imports()
        self._patch_cfg()
        self._setup_teb()
        self._install_hooks()
        self._regions = sorted((b, e, p) for b, e, p in self.mu.mem_regions())
        self._region_starts = [r[0] for r in self._regions]
        self._snapshot_pristine()
        fill_a = random.Random("pry-recon-stack-0").randbytes(STACK_SIZE)
        fill_b = random.Random("pry-recon-stack-1").randbytes(STACK_SIZE)
        self._stack_fill = (fill_a, fill_b)
        self.ctx0 = self.mu.context_save()

    # ------------------------------------------------------------- setup --

    def _prot(self, prot: str) -> int:
        u = self._u
        p = u.UC_PROT_READ
        if "w" in prot:
            p |= u.UC_PROT_WRITE
        if "x" in prot:
            p |= u.UC_PROT_EXEC
        return p

    def _map_image(self) -> None:
        view = self.side.view
        regions = image_regions(view, full_vsize=True)
        if not regions:
            raise ReconError("bad_arg", f"{self.side.label}: nothing to map "
                                        "(empty image)")
        pages: dict[int, int] = {}
        for r in regions:
            lo = (r.va & self.mask) & ~0xFFF
            hi = _round_up((r.va & self.mask) + max(r.size, len(r.data), 1))
            p = self._prot(r.prot)
            for pg in range(lo, hi, PAGE):
                pages[pg] = pages.get(pg, 0) | p
        runs: list[tuple[int, int, int]] = []
        for pg in sorted(pages):
            p = pages[pg]
            if runs and runs[-1][1] == pg and runs[-1][2] == p:
                runs[-1] = (runs[-1][0], pg + PAGE, p)
            else:
                runs.append((pg, pg + PAGE, p))
        for lo, hi, p in runs:
            self.mu.mem_map(lo, hi - lo, p)
        for r in regions:
            if r.data:
                self.mu.mem_write(r.va & self.mask, r.data)
        self.image_lo = runs[0][0]
        self.image_hi = runs[-1][1]
        self._writable_runs = [(lo, hi) for lo, hi, p in runs
                               if p & self._u.UC_PROT_WRITE]

    def _collect_stubs(self) -> None:
        img = self.side.view.img
        if img is None:
            return
        for d in img.imports:
            for e in d["entries"]:
                if len(self.stub_table) >= MAX_STUBS:
                    self.notes.append(f"over {MAX_STUBS} imports: the rest "
                                      "keep their original slot values")
                    return
                name = e["name"] or f"#{e['ordinal']}"
                sem = semantic_for(e["name"], self.arch) if e["name"] \
                    else None
                self.stub_table.append(_Stub(name=name, dll=d["dll"],
                                             delayed=bool(d["delayed"]),
                                             semantic=sem))

    def _map_arena(self) -> None:
        mu, u = self.mu, self._u
        rx = u.UC_PROT_READ | u.UC_PROT_EXEC
        rw = u.UC_PROT_READ | u.UC_PROT_WRITE
        sent = self.arena + OFF_SENTINEL
        mu.mem_map(sent, PAGE, rx)
        page = bytearray(b"\xF4" * PAGE)
        page[S_CFG_CHECK] = 0xC3                      # ret
        page[S_CFG_DISPATCH:S_CFG_DISPATCH + 2] = b"\xFF\xE0"   # jmp rax
        if not self.x64:
            slot = self.data_va + D_RETSLOT
            for off, op in ((S_TRAMP_F32, 0xD9), (S_TRAMP_F64, 0xDD)):
                # fstp dword/qword [slot]; jmp END
                code = bytes([op, 0x1D]) + struct.pack("<I", slot)
                rel = (sent + S_END) - (sent + off + 6 + 5)
                code += b"\xE9" + struct.pack("<i", rel)
                page[off:off + len(code)] = code
        mu.mem_write(sent, bytes(page))
        n = max(1, len(self.stub_table))
        stub_bytes = _round_up(n * STUB_STRIDE)
        mu.mem_map(self.stubs_lo, stub_bytes, rx)
        mu.mem_write(self.stubs_lo, b"\xF4" * stub_bytes)
        self.stubs_hi = self.stubs_lo + stub_bytes
        mu.mem_map(self.data_va, _round_up(DATA_SIZE), rw)
        mu.mem_map(self.stack_lo, STACK_SIZE, rw)

    def _map_buffer_slots(self) -> None:
        self.slots: dict[str, tuple[int, int]] = {}
        cur = self.arena + OFF_BUFFERS
        rw = self._u.UC_PROT_READ | self._u.UC_PROT_WRITE
        for p in self.sig.params:
            if not p.is_memory:
                continue
            span = _round_up(p.max_bytes() + p.align + PRE_WINDOW + 1)
            if cur + span + PAGE > self.arena + ARENA_SPAN:
                raise ReconError("bad_arg", "buffers exceed the harness "
                                            "arena", field="signature.params")
            self.mu.mem_map(cur, span, rw)
            self.slots[p.name] = (cur, cur + span)
            cur += span + PAGE                 # guard page stays unmapped

    def _write_ptr(self, va: int, value: int) -> bool:
        try:
            self.mu.mem_write(va & self.mask,
                              struct.pack("<Q" if self.x64 else "<I",
                                          value & (MASK64 if self.x64
                                                   else 0xFFFFFFFF)))
            return True
        except self._u.UcError:
            return False

    def _patch_imports(self) -> None:
        img = self.side.view.img
        if img is None:
            return
        base = self.side.view.base_va
        idx = 0
        bad = 0
        for d in img.imports:
            for e in d["entries"]:
                if idx >= len(self.stub_table):
                    return
                stub_va = self.stubs_lo + idx * STUB_STRIDE
                if not self._write_ptr(base + e["thunk_rva"], stub_va):
                    bad += 1
                idx += 1
        if bad:
            self.notes.append(f"{bad} import slot(s) outside the mapped "
                              "image were not stubbed")

    def _to_live(self, va: int) -> int | None:
        """A header VA (preferred base) → this view's VA, or None."""
        img = self.side.view.img
        base = self.side.view.base_va
        if img is None or not va:
            return None
        size = img.size_of_image
        if base <= va < base + size:
            return va
        if img.image_base <= va < img.image_base + size:
            return va - img.image_base + base
        return None

    def _patch_cfg(self) -> None:
        img = self.side.view.img
        if img is None or not img.load_config:
            return
        sent = self.arena + OFF_SENTINEL
        pairs = [("guard_cf_check_va", S_CFG_CHECK)]
        if self.x64:
            pairs.append(("guard_cf_dispatch_va", S_CFG_DISPATCH))
        for key, off in pairs:
            live = self._to_live(int(img.load_config.get(key) or 0))
            if live is not None and self._write_ptr(live, sent + off):
                self.notes.append(f"CFG {key.split('_')[2]} slot → stub")

    def _setup_teb(self) -> None:
        mu, X = self.mu, self._X
        teb = self.data_va + D_TEB
        peb = self.data_va + D_PEB
        base = self.side.view.base_va
        if self.x64:
            for off, v in ((0x08, self.stack_hi), (0x10, self.stack_lo),
                           (0x30, teb), (0x60, peb)):
                mu.mem_write(teb + off, struct.pack("<Q", v))
            mu.mem_write(peb + 0x10, struct.pack("<Q", base & MASK64))
            mu.reg_write(X.UC_X86_REG_GS_BASE, teb)
            return
        for off, v in ((0x00, 0xFFFFFFFF), (0x04, self.stack_hi),
                       (0x08, self.stack_lo), (0x18, teb), (0x30, peb)):
            mu.mem_write(teb + off, struct.pack("<I", v))
        mu.mem_write(peb + 0x08, struct.pack("<I", base & 0xFFFFFFFF))
        gdt = self.data_va + D_GDT
        entries = [0, _gdt_entry(0, 0xFFFFF, 0x9B, 0xC),
                   _gdt_entry(0, 0xFFFFF, 0x93, 0xC),
                   _gdt_entry(teb, 0x1FFF, 0x93, 0x4)]
        mu.mem_write(gdt, b"".join(struct.pack("<Q", e) for e in entries))
        mu.reg_write(X.UC_X86_REG_GDTR, (0, gdt, len(entries) * 8 - 1, 0))
        # FS → the fake TEB. SS (and DS/ES) must come from the same GDT
        # once FS is loaded, or every push faults (Phase 0).
        mu.reg_write(X.UC_X86_REG_FS, 3 << 3)
        mu.reg_write(X.UC_X86_REG_SS, 2 << 3)
        mu.reg_write(X.UC_X86_REG_DS, 2 << 3)
        mu.reg_write(X.UC_X86_REG_ES, 2 << 3)

    def _install_hooks(self) -> None:
        mu, u, X = self.mu, self._u, self._X
        mu.hook_add(u.UC_HOOK_CODE, self._on_stub, begin=self.stubs_lo,
                    end=self.stubs_hi - 1)
        mu.hook_add(u.UC_HOOK_INTR, self._on_intr)
        for ins in ((X.UC_X86_INS_SYSCALL, X.UC_X86_INS_SYSENTER)
                    if not self.x64 else (X.UC_X86_INS_SYSCALL,)):
            try:
                mu.hook_add(u.UC_HOOK_INSN, self._on_syscall, None, 1, 0, ins)
            except u.UcError:  # pragma: no cover - engine build specific
                self.notes.append(f"syscall hook {ins} unavailable")
        mu.hook_add(u.UC_HOOK_MEM_INVALID, self._on_fault)
        mu.hook_add(u.UC_HOOK_MEM_WRITE, self._on_img_write,
                    begin=self.image_lo, end=self.image_hi - 1)
        mu.hook_add(u.UC_HOOK_MEM_WRITE, self._on_data_write,
                    begin=self.data_va, end=self.data_va + DATA_SIZE - 1)
        self._access = {}
        for const, label in (("UC_MEM_READ", "read"), ("UC_MEM_WRITE", "write"),
                             ("UC_MEM_FETCH", "fetch"),
                             ("UC_MEM_READ_UNMAPPED", "read"),
                             ("UC_MEM_WRITE_UNMAPPED", "write"),
                             ("UC_MEM_FETCH_UNMAPPED", "fetch"),
                             ("UC_MEM_READ_PROT", "read"),
                             ("UC_MEM_WRITE_PROT", "write"),
                             ("UC_MEM_FETCH_PROT", "fetch")):
            v = getattr(u, const, None)
            if v is not None:
                self._access[v] = label

    def _snapshot_pristine(self) -> None:
        self._pristine: dict[int, bytes] = {}
        spans = list(self._writable_runs) + [(self.data_va,
                                              self.data_va + DATA_SIZE)]
        for lo, hi in spans:
            for pg in range(lo & ~0xFFF, _round_up(hi), PAGE):
                try:
                    self._pristine[pg >> 12] = bytes(self.mu.mem_read(pg, PAGE))
                except self._u.UcError:
                    pass

    # ------------------------------------------------------------- hooks --

    def _on_img_write(self, mu: Any, access: int, address: int, size: int,
                      value: int, ud: Any) -> None:
        self._dirty.add(address >> 12)
        self._dirty.add((address + size - 1) >> 12)
        self._img_writes += 1
        if len(self._img_write_rvas) < 8:
            self._img_write_rvas.add(address - (self.side.view.base_va &
                                                self.mask))

    def _on_data_write(self, mu: Any, access: int, address: int, size: int,
                       value: int, ud: Any) -> None:
        self._dirty.add(address >> 12)
        self._dirty.add((address + size - 1) >> 12)

    def _on_fault(self, mu: Any, access: int, address: int, size: int,
                  value: int, ud: Any) -> bool:
        if self._stop is None:
            label = self._access.get(access, "read")
            self._stop = (f"fault:{label}", address, "")
        return False

    def _pc(self) -> int:
        X = self._X
        return int(self.mu.reg_read(X.UC_X86_REG_RIP if self.x64
                                    else X.UC_X86_REG_EIP))

    def _on_intr(self, mu: Any, intno: int, ud: Any) -> None:
        if self._stop is None:
            names = {0: "divide_error", 1: "debug", 3: "int3", 4: "overflow",
                     5: "bound", 6: "invalid_opcode",
                     13: "general_protection", 0x29: "fastfail",
                     0x2C: "assertion", 0x2D: "debug_service"}
            if intno == 0x2E:
                self._stop = ("unsupported:syscall", self._pc(), "int 0x2e")
            else:
                self._stop = ("cpu_exception", self._pc(),
                              names.get(intno, f"int {intno:#x}"))
        mu.emu_stop()

    def _on_syscall(self, mu: Any, ud: Any) -> None:
        if self._stop is None:
            self._stop = ("unsupported:syscall", self._pc(),
                          "syscall" if self.x64 else "sysenter/syscall")
        mu.emu_stop()

    def _on_block(self, mu: Any, address: int, size: int, ud: Any) -> None:
        a = address & MASK52
        if self._cov_range is not None:
            lo, hi = self._cov_range
            if not lo <= a < hi:
                return
        self.tbs[a] = size
        self.edges.add((self._prev_tb, a))
        self._prev_tb = a

    def _on_stub(self, mu: Any, address: int, size: int, ud: Any) -> None:
        idx = ((address & self.mask) - self.stubs_lo) // STUB_STRIDE
        if not 0 <= idx < len(self.stub_table) or \
                ((address & self.mask) - self.stubs_lo) % STUB_STRIDE:
            self._stop = ("fault:fetch", address, "inside the stub page")
            mu.emu_stop()
            return
        st = self.stub_table[idx]
        pop = 0
        try:
            if st.semantic is not None:
                fn, argc = st.semantic
                ret = fn(self)
                pop = argc * 4 if not self.x64 else 0
                self.api_semantic[st.name] += 1
            else:
                ret, pop = self._default_stub(st.name)
            self._return_from_stub(ret, pop)
        except StubFault as f:
            self._stop = (f"fault:{f.access}", f.va, f"in {st.name}")
            mu.emu_stop()
        except StubCpuException as e:
            self._stop = ("cpu_exception", address, f"{e.detail} in {st.name}")
            mu.emu_stop()
        except StubLimit:
            self._stop = ("cap", address, f"runaway length in {st.name}")
            mu.emu_stop()

    def _default_stub(self, name: str) -> tuple[int, int]:
        spec = self.sig.stubs.get(name)
        n = self._api_counts[name]
        rets = spec.rets if spec is not None else (0,)
        ret = rets[min(n, len(rets) - 1)]
        if spec is not None and spec.argc is not None:
            argc = spec.argc
        else:
            argc = KNOWN_X86_ARGC.get(name, 0)
        self.api_calls.append(name)
        self._api_counts[name] += 1
        return ret, (argc * 4 if not self.x64 else 0)

    def _return_from_stub(self, ret: int, pop: int) -> None:
        X = self._X
        if self.x64:
            rsp = self.reg("rsp")
            ra = struct.unpack("<Q", self.read_mem(rsp, 8))[0]
            self.set_reg("rsp", rsp + 8)
            self.set_reg("rax", ret & MASK64)
            self.mu.reg_write(X.UC_X86_REG_RIP, ra)
            return
        esp = self.reg("esp")
        ra = struct.unpack("<I", self.read_mem(esp, 4))[0]
        self.set_reg("esp", esp + 4 + pop)
        self.set_reg("eax", ret & 0xFFFFFFFF)
        self.set_reg("edx", (ret >> 32) & 0xFFFFFFFF)
        self.mu.reg_write(X.UC_X86_REG_EIP, ra)

    # ---------------------------------------------- stub-facing helpers --

    def _rid(self, name: str) -> int:
        rid = self._regs_cache.get(name)
        if rid is None:
            rid = getattr(self._X, f"UC_X86_REG_{name.upper()}")
            self._regs_cache[name] = rid
        return rid

    def reg(self, name: str) -> int:
        return int(self.mu.reg_read(self._rid(name)))

    def set_reg(self, name: str, value: int) -> None:
        self.mu.reg_write(self._rid(name), value)

    def arg(self, n: int) -> int:
        """Argument *n* at a stub's entry (cdecl/stdcall on x86)."""
        if self.x64:
            if n < 4:
                return self.reg(_X64_ARGREGS[n])
            rsp = self.reg("rsp")
            return struct.unpack("<Q", self.read_mem(
                rsp + 8 + 0x20 + 8 * (n - 4), 8))[0]
        esp = self.reg("esp")
        return struct.unpack("<I", self.read_mem(esp + 4 + 4 * n, 4))[0]

    def arg_size(self, n: int) -> int:
        return self.arg(n) & (MASK64 if self.x64 else 0xFFFFFFFF)

    def _check(self, va: int, n: int, need: int, access: str) -> None:
        cur = va & self.mask
        end = cur + n
        while cur < end:
            i = bisect.bisect_right(self._region_starts, cur) - 1
            if i < 0 or self._regions[i][1] < cur or \
                    not self._regions[i][2] & need:
                raise StubFault(access, cur)
            cur = self._regions[i][1] + 1

    def read_mem(self, va: int, n: int) -> bytes:
        if n <= 0:
            return b""
        self._check(va, n, self._u.UC_PROT_READ, "read")
        if n > MAX_STUB_BYTES:
            raise StubLimit()
        return bytes(self.mu.mem_read(va & self.mask, n))

    def write_mem(self, va: int, data: bytes) -> None:
        if not data:
            return
        self._check(va, len(data), self._u.UC_PROT_WRITE, "write")
        if len(data) > MAX_STUB_BYTES:
            raise StubLimit()
        lo = va & self.mask
        self.mu.mem_write(lo, data)
        # Memory-API writes bypass the write hooks: keep the dirty set
        # (and the image-write report) right by hand.
        if self.image_lo <= lo < self.image_hi:
            self._on_img_write(None, 0, lo, len(data), 0, None)
        elif self.data_va <= lo < self.data_va + DATA_SIZE:
            self._on_data_write(None, 0, lo, len(data), 0, None)
        if len(data) > PAGE and (self.image_lo <= lo < self.image_hi or
                                 self.data_va <= lo < self.data_va
                                 + DATA_SIZE):
            for pg in range(lo >> 12, ((lo + len(data) - 1) >> 12) + 1):
                self._dirty.add(pg)

    def mapped(self, va: int) -> bool:
        a = va & self.mask
        i = bisect.bisect_right(self._region_starts, a) - 1
        return i >= 0 and self._regions[i][1] >= a

    # ---------------------------------------------------------- coverage --

    def set_coverage(self, on: bool,
                     rng: tuple[int, int] | None = None) -> None:
        """Record executed blocks (``self.tbs``: masked addr → size)."""
        u = self._u
        if on and self._cov_hook is None:
            if rng is not None and not self.kernel:
                self._cov_range = None
                self._cov_hook = self.mu.hook_add(
                    u.UC_HOOK_BLOCK, self._on_block, begin=rng[0],
                    end=rng[1] - 1)
            else:
                self._cov_range = (rng[0] & MASK52, rng[1] & MASK52) \
                    if rng is not None else None
                self._cov_hook = self.mu.hook_add(u.UC_HOOK_BLOCK,
                                                  self._on_block)
        elif not on and self._cov_hook is not None:
            self.mu.hook_del(self._cov_hook)
            self._cov_hook = None

    def set_cmp_sites(self, sites: Any) -> None:
        """Log what each ``cmp <operand>, imm`` site sees (``cmp_log``).
        Kernel images run at masked addresses, so they are not hooked."""
        for h in self._cmp_hooks:
            self.mu.hook_del(h)
        self._cmp_hooks = []
        if self.kernel:
            return
        for s in sites:
            self._cmp_hooks.append(self.mu.hook_add(
                self._u.UC_HOOK_CODE, self._on_cmp, s, begin=s.va,
                end=s.va))

    def _on_cmp(self, mu: Any, address: int, size: int, site: Any) -> None:
        if len(self.cmp_log) >= CMP_LOG_MAX:
            return
        try:
            if site.reg:
                v = self.reg(site.reg)
            else:
                ea = site.disp
                if site.base:
                    ea += self.reg(site.base)
                if site.index:
                    ea += self.reg(site.index) * site.scale
                ea &= MASK64 if self.x64 else 0xFFFFFFFF
                v = int.from_bytes(mu.mem_read(ea, site.width), "little")
        except Exception:   # unreadable operand: nothing to learn
            return
        m = (1 << (8 * site.width)) - 1
        pair = ((v + site.bias) & m, (site.imm + site.bias) & m, site.width)
        if pair[0] != pair[1] and pair not in self.cmp_log:
            self.cmp_log.append(pair)

    # --------------------------------------------------------------- run --

    def _restore(self) -> None:
        mu = self.mu
        mu.context_restore(self.ctx0)
        for pg in self._dirty:
            data = self._pristine.get(pg)
            if data is not None:
                mu.mem_write(pg << 12, data)
        self._dirty.clear()
        self._img_writes = 0
        self._img_write_rvas = set()
        self._stop = None
        self.api_calls = []
        self.api_semantic = Counter()
        self._api_counts = Counter()
        self._prev_tb = 0
        self.cmp_log = []

    def _place_buffers(self, values: dict[str, Any],
                       crng: random.Random) -> dict[str, Placed]:
        placed: dict[str, Placed] = {}
        for p in self.sig.params:
            if not p.is_memory:
                continue
            data = values[p.name]
            if p.is_string:
                blob = bytes(data) + b"\0" * p.char_size
            elif p.type == "buf_out":
                blob = crng.randbytes(len(data))       # the canary
            else:
                blob = bytes(data)
            n = len(blob)
            lo, hi = self.slots[p.name]
            va = (hi - n) & ~(p.align - 1)
            win_lo = max(lo, va - PRE_WINDOW)
            pre = crng.randbytes(va - win_lo)
            post = crng.randbytes(hi - (va + n))
            window = pre + blob + post
            self.mu.mem_write(win_lo, window)
            placed[p.name] = Placed(va, n, win_lo, hi)
            self._initial[p.name] = window
        return placed

    def _scalar(self, p: Param, v: int, garbage: int) -> tuple[int, int]:
        """(register value with garbage upper bits, width bytes)."""
        if p.is_memory:
            return v, self.ptr
        if p.is_float:
            w = FLOAT_TYPES[p.type]
            return v, w
        width, _signed = self.sig.int_spec(p.type)
        m = (1 << (width * 8)) - 1
        full = MASK64 if self.x64 else 0xFFFFFFFF
        if width >= self.ptr:
            return v & m, width
        return ((garbage & full) & ~m) | (v & m), width

    def _arg_values(self, values: dict[str, Any],
                    placed: dict[str, Placed]) -> list[int]:
        out = []
        for p in self.sig.params:
            if p.is_memory:
                out.append(placed[p.name].va)
            else:
                out.append(int(values[p.name]))
        return out

    def run(self, values: dict[str, Any], case_index: int,
            fill: int) -> RunResult:
        mu = self.mu
        self._restore()
        mu.mem_write(self.stack_lo, self._stack_fill[fill & 1])
        rng = random.Random(f"{self.seed}:{case_index}:{fill}")
        crng = random.Random(f"{self.seed}:{case_index}:canary")
        self._initial = {}
        placed = self._place_buffers(values, crng)
        args = self._arg_values(values, placed)
        saved: dict[str, int] = {}
        if self.x64:
            entry_sp, float_ret = self._setup_x64(args, rng, saved)
        else:
            entry_sp, float_ret = self._setup_x86(args, rng, saved)
        t0 = time.perf_counter()
        err: Exception | None = None
        try:
            # No Unicorn timeout: on Windows its watchdog thread costs a
            # timer quantum (~15 ms) per call (Phase 0). Runs are bounded
            # by the instruction count; the caller budgets wall time
            # between runs.
            mu.emu_start(self.side.func_va, self.end_va, timeout=0,
                         count=self.max_insns)
        except self._u.UcError as exc:
            err = exc
        elapsed = time.perf_counter() - t0
        res = self._classify(err)
        res.elapsed_s = elapsed
        res.api = tuple(self.api_calls)
        res.api_semantic = dict(self.api_semantic)
        res.image_writes = self._img_writes
        res.image_write_rvas = tuple(sorted(self._img_write_rvas))
        for name, pl in placed.items():
            try:
                res.buffers[name] = bytes(mu.mem_read(pl.win_lo,
                                                      pl.win_hi - pl.win_lo))
            except self._u.UcError:  # pragma: no cover - slots stay mapped
                res.buffers[name] = b""
            res.windows[name] = (pl.va - pl.win_lo, pl.nbytes)
        res.initial = dict(self._initial)
        if res.outcome == "returned":
            res.ret = self._read_ret(float_ret)
            res.abi_clobbered, res.cleanup = self._abi(saved, entry_sp)
        return res

    def _setup_x64(self, args: list[int], rng: random.Random,
                   saved: dict[str, int]) -> tuple[int, bool]:
        mu, X = self.mu, self._X
        params = self.sig.params
        nstack = max(0, len(params) - 4)
        top = (self.stack_hi - PAGE) & ~0xF
        pad = 8 if nstack % 2 else 0
        entry_sp = top - pad - (0x20 + 8 * nstack) - 8
        regs: dict[str, int] = {}
        for r in _X64_VOLATILE + _X64_SAVED:
            regs[r] = rng.getrandbits(64)
        xmm = [rng.getrandbits(128) for _ in range(16)]
        stack_args: list[bytes] = []
        for i, (p, v) in enumerate(zip(params, args)):
            g = rng.getrandbits(64)
            val, width = self._scalar(p, v, g)
            if i < 4:
                if p.is_float:
                    keep = (1 << (width * 8)) - 1
                    xmm[i] = (xmm[i] & ~keep) | (val & keep)
                else:
                    regs[_X64_ARGREGS[i]] = val
            else:
                if p.is_float:
                    keep = (1 << (width * 8)) - 1
                    val = (g & ~keep) | (val & keep)
                stack_args.append(struct.pack("<Q", val & MASK64))
        shadow = rng.randbytes(0x20)
        blob = struct.pack("<Q", self.end_va) + shadow + b"".join(stack_args)
        mu.mem_write(entry_sp, blob)
        for r, v in regs.items():
            mu.reg_write(self._rid(r), v & MASK64)
        for i, v in enumerate(xmm):
            mu.reg_write(getattr(X, f"UC_X86_REG_XMM{i}"), v)
        mu.reg_write(X.UC_X86_REG_RSP, entry_sp)
        mu.reg_write(X.UC_X86_REG_RFLAGS, 0x202)
        for r in _X64_SAVED:
            saved[r] = regs[r] & MASK64
        for i in range(6, 16):
            saved[f"xmm{i}"] = xmm[i]
        return entry_sp, False

    def _setup_x86(self, args: list[int], rng: random.Random,
                   saved: dict[str, int]) -> tuple[int, bool]:
        mu, X = self.mu, self._X
        params = self.sig.params
        cc = self.sig.cc
        regs: dict[str, int] = {r: rng.getrandbits(32)
                                for r in _X86_VOLATILE + _X86_SAVED}
        reg_slots: list[str] = []
        if cc == "fastcall":
            reg_slots = ["ecx", "edx"]
        elif cc == "thiscall":
            reg_slots = ["ecx"]
        stack: list[bytes] = []
        for i, (p, v) in enumerate(zip(params, args)):
            g = rng.getrandbits(32)
            val, width = self._scalar(p, v, g)
            eligible = (p.is_memory or (p.is_int and width <= 4))
            if reg_slots and eligible and (cc == "fastcall" or i == 0):
                regs[reg_slots.pop(0)] = val & 0xFFFFFFFF
                continue
            if width == 8:
                stack.append(struct.pack("<Q", val & MASK64))
            else:
                stack.append(struct.pack("<I", val & 0xFFFFFFFF))
        float_ret = self.sig.ret in FLOAT_TYPES
        if float_ret:
            ret_addr = self.arena + OFF_SENTINEL + (
                S_TRAMP_F32 if FLOAT_TYPES[self.sig.ret] == 4 else S_TRAMP_F64)
        else:
            ret_addr = self.end_va
        args_bytes = sum(len(s) for s in stack)
        args_start = ((self.stack_hi - PAGE) - args_bytes) & ~0xF
        entry_sp = args_start - 4
        mu.mem_write(entry_sp, struct.pack("<I", ret_addr) + b"".join(stack))
        for r, v in regs.items():
            mu.reg_write(self._rid(r), v & 0xFFFFFFFF)
        for i in range(8):
            mu.reg_write(getattr(X, f"UC_X86_REG_XMM{i}"), rng.getrandbits(128))
        mu.reg_write(X.UC_X86_REG_ESP, entry_sp)
        mu.reg_write(X.UC_X86_REG_EFLAGS, 0x202)
        for r in _X86_SAVED:
            saved[r] = regs[r] & 0xFFFFFFFF
        return entry_sp, float_ret

    def _read_ret(self, float_ret: bool) -> int | None:
        rt = self.sig.ret
        if rt == "void":
            return None
        if rt in FLOAT_TYPES:
            w = FLOAT_TYPES[rt]
            if self.x64:
                return int(self.mu.reg_read(self._X.UC_X86_REG_XMM0)) & \
                    ((1 << (w * 8)) - 1)
            raw = bytes(self.mu.mem_read(self.data_va + D_RETSLOT, w))
            return int.from_bytes(raw, "little")
        width, _ = self.sig.int_spec(rt)
        m = (1 << (width * 8)) - 1
        if self.x64:
            return self.reg("rax") & m
        if width == 8:
            return (self.reg("eax") & 0xFFFFFFFF) | \
                ((self.reg("edx") & 0xFFFFFFFF) << 32)
        return self.reg("eax") & m

    def _abi(self, saved: dict[str, int],
             entry_sp: int) -> tuple[tuple[str, ...], int | None]:
        bad: list[str] = []
        for r, v in saved.items():
            if r.startswith("xmm"):
                cur = int(self.mu.reg_read(getattr(self._X,
                                                   f"UC_X86_REG_{r.upper()}")))
            else:
                cur = self.reg(r)
            if cur != v:
                bad.append(r)
        if self.x64:
            if self.reg("rsp") != entry_sp + 8:
                bad.append("rsp")
            return tuple(bad), None
        return tuple(bad), self.reg("esp") - (entry_sp + 4)

    def _classify(self, err: Exception | None) -> RunResult:
        pc = self._pc()
        if self._stop is not None:
            outcome, va, detail = self._stop
            if outcome == "fault:fetch" and va is not None and \
                    not self.mapped(va):
                outcome = "unresolved_call"
                detail = detail or "fetch outside every mapped region"
            return RunResult(outcome=outcome, detail=detail, fault_va=va,
                             end_pc=pc)
        if err is not None:
            return self._classify_error(err, pc)
        if (pc & self.mask) == (self.end_va & self.mask):
            return RunResult(outcome="returned", end_pc=pc)
        try:
            prev = bytes(self.mu.mem_read((pc - 1) & self.mask, 1))
        except self._u.UcError:
            prev = b""
        if prev == b"\xF4":
            return RunResult(outcome="cpu_exception", detail="hlt",
                             end_pc=pc)
        return RunResult(outcome="cap",
                         detail=f"instruction limit ({self.max_insns})",
                         end_pc=pc)

    def _classify_error(self, err: Exception, pc: int) -> RunResult:
        u = self._u
        code = getattr(err, "errno", None)
        if code == u.UC_ERR_INSN_INVALID:
            text = self._decode_at(pc)
            if text and text.split(" ", 1)[0] not in ("ud2", "ud1", "ud0"):
                return RunResult(outcome="unsupported:opcode",
                                 detail=f"{text} (not emulated)", end_pc=pc,
                                 fault_va=pc)
            return RunResult(outcome="cpu_exception", detail="invalid_opcode",
                             end_pc=pc, fault_va=pc)
        fetch = {getattr(u, n, -1) for n in ("UC_ERR_FETCH_UNMAPPED",
                                             "UC_ERR_FETCH_PROT")}
        read = {getattr(u, n, -1) for n in ("UC_ERR_READ_UNMAPPED",
                                            "UC_ERR_READ_PROT",
                                            "UC_ERR_READ_UNALIGNED")}
        write = {getattr(u, n, -1) for n in ("UC_ERR_WRITE_UNMAPPED",
                                             "UC_ERR_WRITE_PROT",
                                             "UC_ERR_WRITE_UNALIGNED")}
        if code in fetch:
            return RunResult(outcome="unresolved_call" if not self.mapped(pc)
                             else "fault:fetch", detail=str(err), end_pc=pc,
                             fault_va=pc)
        if code in read:
            return RunResult(outcome="fault:read", detail=str(err), end_pc=pc)
        if code in write:
            return RunResult(outcome="fault:write", detail=str(err),
                             end_pc=pc)
        return RunResult(outcome="cpu_exception", detail=str(err), end_pc=pc)

    def _decode_at(self, pc: int) -> str:
        try:
            from ..codegen import _load_capstone
            cs = _load_capstone()
            data = bytes(self.mu.mem_read(pc & self.mask, 15))
            md = cs.Cs(cs.CS_ARCH_X86,
                       cs.CS_MODE_64 if self.x64 else cs.CS_MODE_32)
            for ins in md.disasm(data, pc):
                return f"{ins.mnemonic} {ins.op_str}".strip()
        except Exception:
            return ""
        return ""


def _gdt_entry(base: int, limit: int, access: int, flags: int) -> int:
    d = limit & 0xFFFF
    d |= (base & 0xFFFFFF) << 16
    d |= (access & 0xFF) << 40
    d |= ((limit >> 16) & 0xF) << 48
    d |= (flags & 0xF) << 52
    d |= ((base >> 24) & 0xFF) << 56
    return d


__all__ = ["ARENA_SPAN", "Harness", "OUTCOMES", "Placed", "RunResult",
           "Side", "UNSUPPORTED", "choose_arena"]
