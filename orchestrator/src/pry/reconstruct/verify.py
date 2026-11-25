"""The differential loop: run both sides on every case, compare, judge.

Per case, each side runs twice (fills A and B of the uninitialized-read
probe). A side whose outputs change between its two fills read state the
inputs do not determine:

* the original → the case is ``unstable`` (the signature may be missing
  a parameter, or the original reads garbage); it never counts as a
  match;
* the reconstruction (original stable) → a ``stability`` mismatch: the
  reconstruction reads an uninitialized local or register.

Verdicts — a pass is bounded by its inputs and its coverage, never more:

* ``mismatch`` — at least one case differs; the report names the first
  differing output of each mismatching case;
* ``inconclusive`` — no mismatch, but something the emulator or the
  inputs cannot vouch for: unsupported constructs (syscalls, unresolved
  calls, opcodes Unicorn lacks, the instruction cap), unstable
  original cases, nothing comparable, every case faulting on both
  sides, coverage under ``min_coverage``, or the time budget;
* ``equivalent_on_tested_inputs`` — everything compared matched.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from . import HARNESS_VERSION
from .compare import Diff, compare_runs, show_ret
from .coverage import coverage, static_function
from .errors import bad_arg
from .harness import UNSUPPORTED, Harness, RunResult, Side, choose_arena
from .inputs import (INPUT_MODES, Case, GuidedGen, case_key, encode_case,
                     generate_cases, preview_value)
from .signature import Signature

MAX_REPORTED_MISMATCHES = 5

NOT_COMPARED = (
    "writes to image memory (globals) — counted under image_writes",
    "raw API arguments — only the order of stubbed calls is compared",
    "callee-saved register preservation — reported under abi",
    "instruction counts",
)


@dataclass
class VerifyOptions:
    cases: int = 256
    seed: int = 1
    explicit: list[dict[str, Any]] = field(default_factory=list)
    replay: list[dict[str, Any]] = field(default_factory=list)
    boundary: bool = True
    timeout_s: float = 60.0
    min_coverage: float = 0.0
    probe: bool = True
    max_insns: int = 5_000_000
    max_mismatches: int = 100
    inputs: str = "guided"          # guided | random (slice 1)


@dataclass
class _SideStats:
    outcomes: Counter[str] = field(default_factory=Counter)
    details: Counter[str] = field(default_factory=Counter)
    abi_runs: int = 0
    abi_regs: set[str] = field(default_factory=set)
    image_write_runs: int = 0
    image_write_rvas: set[int] = field(default_factory=set)
    api: Counter[str] = field(default_factory=Counter)
    semantic: Counter[str] = field(default_factory=Counter)
    cleanup: Counter[int] = field(default_factory=Counter)

    def add(self, r: RunResult) -> None:
        self.outcomes[r.outcome] += 1
        if r.detail and r.outcome != "returned":
            self.details[f"{r.outcome}: {r.detail}"] += 1
        if r.abi_clobbered:
            self.abi_runs += 1
            self.abi_regs.update(r.abi_clobbered)
        if r.image_writes:
            self.image_write_runs += 1
            if len(self.image_write_rvas) < 16:
                self.image_write_rvas.update(r.image_write_rvas)
        self.api.update(r.api)
        self.semantic.update(r.api_semantic)
        if r.cleanup is not None:
            self.cleanup[r.cleanup] += 1

    def to_json(self, arch: str) -> dict[str, Any]:
        out: dict[str, Any] = {"outcomes": dict(self.outcomes)}
        if self.details:
            out["outcome_details"] = dict(self.details.most_common(8))
        out["abi"] = ({"ok": True} if not self.abi_runs else
                      {"ok": False, "runs_clobbering": self.abi_runs,
                       "registers": sorted(self.abi_regs)})
        if self.image_write_runs:
            out["image_writes"] = {
                "runs": self.image_write_runs,
                "sample_rvas": [f"0x{r:x}" for r in
                                sorted(self.image_write_rvas)[:16]]}
        if self.api:
            out["api_stubbed"] = dict(self.api.most_common(16))
        if self.semantic:
            out["semantic_stubs"] = dict(self.semantic.most_common(16))
        if arch == "x86" and self.cleanup:
            out["stack_cleanup_bytes"] = {str(k): v for k, v in
                                          self.cleanup.most_common(4)}
        return out


def _preview_inputs(sig: Signature, case: Case) -> dict[str, Any]:
    return {p.name: preview_value(sig, p, case.values[p.name])
            for p in sig.params}


def _mismatch_row(sig: Signature, case: Case, diffs: list[Diff],
                  full: bool) -> dict[str, Any]:
    first = diffs[0]
    row: dict[str, Any] = {"case": case.index, "origin": case.origin,
                           **first.to_json()}
    row["inputs"] = (encode_case(sig, case)["inputs"] if full
                     else _preview_inputs(sig, case))
    if len(diffs) > 1:
        row["other_fields"] = [d.field for d in diffs[1:]]
    return row


def _verdict(*, mismatches: int, unsupported: int, unstable: int,
             compared: int, matched_returned: int, cov_ratio: float,
             min_coverage: float, partial: bool, done: int, total: int,
             unsupported_why: Counter[str]) -> tuple[str, list[str]]:
    if mismatches:
        return "mismatch", []
    reasons: list[str] = []
    if unsupported:
        top = ", ".join(f"{k} ×{v}" for k, v in
                        unsupported_why.most_common(3))
        reasons.append(f"{unsupported} case(s) hit constructs the emulator "
                       f"cannot vouch for ({top}); they never count as a "
                       "match — narrow the inputs or stub the path")
    if unstable:
        reasons.append(f"{unstable} case(s): the original's outputs changed "
                       "with uninitialized state (stack/registers) — the "
                       "signature may be missing a parameter")
    if compared == 0:
        reasons.append("no case could be compared")
    elif matched_returned == 0:
        reasons.append("every compared case faulted or trapped on both "
                       "sides — nothing returned normally")
    if min_coverage and cov_ratio < min_coverage:
        reasons.append(f"coverage {cov_ratio:.0%} is under min_coverage "
                       f"{min_coverage:.0%} — target the uncovered blocks "
                       "with cases_json")
    if partial:
        reasons.append(f"the time budget ran out after {done} of {total} "
                       "cases")
    return ("inconclusive" if reasons else "equivalent_on_tested_inputs"), \
        reasons


def run_verify(original: Side, recon: Side, sig: Signature,
               opts: VerifyOptions) -> dict[str, Any]:
    """Differential run → report dict (plus ``_cases``/``_mismatches``
    for the on-disk files; the caller strips the underscored keys)."""
    t0 = time.monotonic()
    arena = choose_arena(sig.arch, [original.span(), recon.span()])
    ho = Harness(original, sig, arena, seed=opts.seed,
                 max_insns=opts.max_insns)
    hr = Harness(recon, sig, arena, seed=opts.seed, max_insns=opts.max_insns)
    if opts.inputs not in INPUT_MODES:
        raise bad_arg(f"inputs: {' | '.join(INPUT_MODES)}", field="inputs",
                      given=str(opts.inputs), valid=INPUT_MODES)
    sf = static_function(original.view, original.func_va,
                         bits=64 if sig.arch == "x64" else 32)
    guided = opts.inputs == "guided"
    # Guided: the fixed sets run first and seed the corpus; the `cases`
    # budget is then spent by GuidedGen, fed by each case's novelty.
    fixed = generate_cases(sig, seed=opts.seed,
                           count=0 if guided else opts.cases,
                           explicit=opts.explicit, replay=opts.replay,
                           boundary=opts.boundary)
    ho.set_coverage(True, (sf.lo, sf.hi) if sf.blocks else None)
    if guided:
        ho.set_cmp_sites(sf.cmp_sites)
    executed: dict[int, int] = {}
    edges: set[tuple[int, int]] = set()
    outcomes_seen: set[str] = set()
    cov_on = True
    deadline = t0 + max(0.1, opts.timeout_s)
    st_o, st_r = _SideStats(), _SideStats()
    status: Counter[str] = Counter()
    unsupported_why: Counter[str] = Counter()
    mismatch_rows: list[dict[str, Any]] = []
    mismatch_full: list[dict[str, Any]] = []
    unstable_rows: list[dict[str, Any]] = []
    ran: list[Case] = []
    matched_returned = 0
    api_cases = 0
    partial = False
    stopped_early = False

    def collect() -> bool:
        """Merge the original's last run into coverage → True when it
        reached a new edge."""
        if not cov_on:
            return False
        executed.update(ho.tbs)
        ho.tbs.clear()
        n = len(edges)
        edges.update(ho.edges)
        ho.edges.clear()
        return len(edges) > n

    last_log: list[tuple[int, int, int]] = []

    def run_case(case: Case) -> tuple[bool, bool]:
        """Run, compare and count one case → (stop, novel); the
        original's compare log is left in ``last_log``."""
        nonlocal matched_returned, api_cases
        o0 = ho.run(case.values, case.index, 0)
        last_log[:] = ho.cmp_log
        novel = collect()
        r0 = hr.run(case.values, case.index, 0)
        o1 = r1 = None
        if opts.probe:
            o1 = ho.run(case.values, case.index, 1)
            novel = collect() or novel
            r1 = hr.run(case.values, case.index, 1)
        if o0.outcome not in outcomes_seen:
            outcomes_seen.add(o0.outcome)
            novel = True
        ran.append(case)
        st_o.add(o0)
        st_r.add(r0)
        if o0.api or r0.api:
            api_cases += 1
        runs = [("original", o0), ("reconstruction", r0)]
        if o1 is not None and r1 is not None:
            runs += [("original", o1), ("reconstruction", r1)]
        bad = [(who, r) for who, r in runs if r.outcome in UNSUPPORTED]
        if bad:
            status["unsupported"] += 1
            who, r = bad[0]
            unsupported_why[f"{who}: {r.outcome}"
                            + (f" ({r.detail})" if r.detail else "")] += 1
        elif o1 is not None and compare_runs(sig, o0, o1):
            status["unstable"] += 1
            if len(unstable_rows) < MAX_REPORTED_MISMATCHES:
                d = compare_runs(sig, o0, o1)
                unstable_rows.append({"case": case.index,
                                      "fields": [x.field for x in d],
                                      "inputs": _preview_inputs(sig, case)})
        else:
            diffs: list[Diff] = []
            if r1 is not None:
                inst = compare_runs(sig, r0, r1)
                if inst:
                    diffs = [Diff("stability",
                                  "stable across both fills",
                                  f"changed with uninitialized state: "
                                  f"{', '.join(x.field for x in inst)}",
                                  detail="the reconstruction reads an "
                                         "uninitialized local or "
                                         "register")]
            if not diffs:
                diffs = compare_runs(sig, o0, r0)
            if diffs:
                status["mismatch"] += 1
                if len(mismatch_rows) < MAX_REPORTED_MISMATCHES:
                    mismatch_rows.append(_mismatch_row(sig, case, diffs,
                                                       False))
                if len(mismatch_full) < opts.max_mismatches:
                    mismatch_full.append(_mismatch_row(sig, case, diffs, True))
                if status["mismatch"] >= opts.max_mismatches:
                    return True, novel
            else:
                status["match"] += 1
                if o0.outcome == "returned":
                    matched_returned += 1
        return False, novel

    gen = GuidedGen(sig, seed=opts.seed, constants=sf.constants) \
        if guided else None
    for case in fixed:
        if time.monotonic() > deadline:
            partial = True
            break
        stop, novel = run_case(case)
        if gen is not None and novel:
            gen.add(case.values, last_log)
        if stop:
            stopped_early = True
            break
        # Random mode drops the coverage hook once every block is hit;
        # guided mode keeps it, since edges still steer generation.
        if not guided and cov_on and len(ran) % 16 == 0 and sf.blocks:
            c = coverage(sf, executed)
            if c["blocks_hit"] == c["blocks_total"]:
                ho.set_coverage(False)
                cov_on = False
    planned = len(fixed)
    if gen is not None:
        planned += opts.cases
        seen = {case_key(sig, c.values) for c in fixed}
        for _ in range(opts.cases if not (partial or stopped_early) else 0):
            if time.monotonic() > deadline:
                partial = True
                break
            vals: dict[str, Any] | None = None
            origin = ""
            for _try in range(4):     # a few draws for a case not yet run
                cand, origin = gen.next()
                key = case_key(sig, cand)
                if key not in seen:
                    seen.add(key)
                    vals = cand
                    break
            if vals is None:
                continue
            case = Case(index=len(ran), origin=origin, values=vals)
            stop, novel = run_case(case)
            if novel:
                gen.add(vals, last_log)
            if stop:
                stopped_early = True
                break
    done = len(ran)
    if guided:
        total = planned if (partial or stopped_early) else done
    else:
        total = len(fixed)
    inputs_block: dict[str, Any] = {
        "mode": opts.inputs,
        "by_origin": dict(Counter(c.origin for c in ran))}
    if gen is not None:
        inputs_block.update(corpus=len(gen.corpus), edges=len(edges),
                            dictionary=len(sf.constants),
                            cmp_sites=len(sf.cmp_sites))
    cov: dict[str, Any] = coverage(sf, executed) if sf.blocks else {
        "blocks_hit": 0, "blocks_total": 0, "ratio": 0.0, "uncovered": [],
        "note": "no static blocks recovered for the original function"}
    compared = status["match"] + status["mismatch"]
    verdict, reasons = _verdict(
        mismatches=status["mismatch"], unsupported=status["unsupported"],
        unstable=status["unstable"], compared=compared,
        matched_returned=matched_returned, cov_ratio=float(cov["ratio"]),
        min_coverage=opts.min_coverage, partial=partial, done=done,
        total=total, unsupported_why=unsupported_why)
    not_compared = list(NOT_COMPARED)
    for item in sorted(sig.ignore):
        not_compared.append(f"{item} (ignored by the signature)")
    if not opts.probe:
        not_compared.append("uninitialized-state probe (probe=false)")
    report: dict[str, Any] = {
        "ok": True,
        "verdict": verdict,
        "cases_total": total,
        "cases_run": done,
        "matched": status["match"],
        "mismatched": status["mismatch"],
        "unsupported": status["unsupported"],
        "unstable": status["unstable"],
        "cases_with_stubbed_api": api_cases,
        "mismatches": mismatch_rows,
        "coverage": cov,
        "inputs": inputs_block,
        "original": st_o.to_json(sig.arch),
        "reconstruction": st_r.to_json(sig.arch),
        "not_compared": not_compared,
        "seed": opts.seed,
        "arch": sig.arch,
        "cc": sig.cc,
        "harness_version": HARNESS_VERSION,
        "elapsed_s": round(time.monotonic() - t0, 3),
    }
    if reasons:
        report["reasons"] = reasons
    if unstable_rows:
        report["unstable_cases"] = unstable_rows
    if unsupported_why:
        report["unsupported_detail"] = dict(unsupported_why.most_common(8))
    if partial or stopped_early:
        report["partial"] = True
        if stopped_early:
            report["stopped_early"] = (f"stopped after {opts.max_mismatches}"
                                       " mismatches")
    notes = [n for n in ho.notes] + [n for n in hr.notes
                                     if n not in ho.notes]
    if sig.warnings:
        notes += list(sig.warnings)
    if notes:
        report["notes"] = notes
    report["_cases"] = [encode_case(sig, c) for c in ran]
    report["_mismatches"] = mismatch_full
    return report


def run_call(sides: list[Side], sig: Signature, values: dict[str, Any], *,
             seed: int = 1, max_insns: int = 5_000_000) -> dict[str, Any]:
    """One explicit case on one or both sides (no probe, no coverage)."""
    arena = choose_arena(sig.arch, [s.span() for s in sides])
    case = Case(index=0, origin="explicit", values=values)
    results: list[tuple[Side, RunResult]] = []
    for side in sides:
        h = Harness(side, sig, arena, seed=seed, max_insns=max_insns)
        results.append((side, h.run(values, 0, 0)))
    out: dict[str, Any] = {"ok": True, "arch": sig.arch, "cc": sig.cc,
                           "inputs": _preview_inputs(sig, case)}
    for side, r in results:
        out[side.label] = _render_run(sig, r)
    if len(results) == 2:
        diffs = compare_runs(sig, results[0][1], results[1][1])
        out["match"] = not diffs
        out["diffs"] = [d.to_json() for d in diffs]
    if sig.warnings:
        out["notes"] = list(sig.warnings)
    return out


def _render_run(sig: Signature, r: RunResult) -> dict[str, Any]:
    row: dict[str, Any] = {"outcome": r.outcome}
    if r.detail:
        row["detail"] = r.detail
    if r.fault_va is not None:
        row["fault_va"] = f"0x{r.fault_va:x}"
    if r.outcome == "returned" and sig.ret != "void":
        row["ret"] = show_ret(sig, r.ret)
    bufs: dict[str, Any] = {}
    for p in sig.params:
        if not p.is_memory or p.name not in r.buffers:
            continue
        pre, n = r.windows[p.name]
        data = r.buffers[p.name]
        init = r.initial.get(p.name, b"")
        body = data[pre:pre + n]
        row_b: dict[str, Any] = {"hex": body[:256].hex(), "bytes": n}
        if n > 256:
            row_b["truncated"] = True
        if init:
            if data[:pre] != init[:pre]:
                row_b["underrun"] = True
            if data[pre + n:] != init[pre + n:]:
                row_b["overrun"] = True
            if p.type == "buf_out":
                row_b["unwritten"] = sum(1 for i in range(n)
                                         if body[i] == init[pre + i])
        bufs[p.name] = row_b
    if bufs:
        row["buffers"] = bufs
    if r.api:
        row["api"] = list(r.api[:64])
    if r.api_semantic:
        row["semantic_stubs"] = r.api_semantic
    if r.cleanup is not None:
        row["stack_cleanup_bytes"] = r.cleanup
    if r.abi_clobbered:
        row["abi_clobbered"] = list(r.abi_clobbered)
    if r.image_writes:
        row["image_writes"] = {"count": r.image_writes,
                               "sample_rvas": [f"0x{x:x}" for x in
                                               r.image_write_rvas]}
    return row


__all__ = ["NOT_COMPARED", "VerifyOptions", "run_call", "run_verify"]
