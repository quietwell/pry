"""Reconstruct-and-verify: check a C reconstruction of one function
against the original binary by running both under Unicorn.

Slice 1 is *behavioral*: both sides run the same generated inputs in
private, identical emulated environments, and the comparison covers the
declared outputs (return value, every buffer, the order of stubbed API
calls, x86 stack cleanup). A pass means "behaved the same on these
inputs, with this coverage" and never more — see ``docs/RECONSTRUCT.md``.

Modules:

* :mod:`.signature` — the declared prototype (types, buffers, links).
* :mod:`.inputs`    — explicit, boundary, and coverage-guided (or
  seeded-random) cases.
* :mod:`.dictionary` — constants and compare sites read off the
  original, for the guided generator.
* :mod:`.harness`   — one Unicorn instance per side; Win64 / x86 calls.
* :mod:`.stubs`     — semantic CRT/Rtl stubs and the default API stub.
* :mod:`.coverage`  — static blocks of the original vs executed blocks.
* :mod:`.compare`   — per-case comparison.
* :mod:`.verify`    — the differential loop, verdict and report.
* :mod:`.toolchain` / :mod:`.compile` — MSVC and clang-cl builds.

Hard rule: build outputs are only ever *read as bytes* by the mapper.
Nothing in this package loads a build output natively on the host.
"""

from __future__ import annotations

from .errors import ReconError

HARNESS_VERSION = "1"

__all__ = ["HARNESS_VERSION", "ReconError"]
