"""On-disk run records: ``artifacts/reconstruct/runs/<run_id>/``.

* ``report.json``     — the full report (what the response summarizes);
* ``inputs.jsonl``    — every case run, bit-exact; replay with
  ``cases_path='reconstruct/runs/<run_id>/inputs.jsonl'``;
* ``mismatches.jsonl`` — every recorded mismatch with full inputs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

RUN_RE = re.compile(r"r(\d{4,})\Z")


def reconstruct_root(artifacts_dir: str | Path) -> Path:
    return Path(artifacts_dir) / "reconstruct"


def builds_root(artifacts_dir: str | Path) -> Path:
    return reconstruct_root(artifacts_dir) / "builds"


def runs_root(artifacts_dir: str | Path) -> Path:
    return reconstruct_root(artifacts_dir) / "runs"


def new_run_dir(root: Path) -> tuple[str, Path]:
    """Next ``rNNNN`` directory, created exclusively (race-safe)."""
    root.mkdir(parents=True, exist_ok=True)
    nums = [int(m.group(1)) for p in root.iterdir()
            if (m := RUN_RE.match(p.name))]
    n = max(nums, default=0) + 1
    for _ in range(1000):
        run_id = f"r{n:04d}"
        path = root / run_id
        try:
            path.mkdir()
            return run_id, path
        except FileExistsError:
            n += 1
    raise RuntimeError("could not allocate a run directory")


def write_run(path: Path, report: dict[str, Any]) -> dict[str, str]:
    """Write the three files; returns their artifacts-relative names."""
    cases = report.pop("_cases", [])
    mismatches = report.pop("_mismatches", [])
    (path / "report.json").write_text(json.dumps(report, indent=1,
                                                 default=str),
                                      encoding="utf-8")
    with (path / "inputs.jsonl").open("w", encoding="utf-8") as fh:
        for row in cases:
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    with (path / "mismatches.jsonl").open("w", encoding="utf-8") as fh:
        for row in mismatches:
            fh.write(json.dumps(row, separators=(",", ":"), default=str)
                     + "\n")
    return {"report": "report.json", "inputs": "inputs.jsonl",
            "mismatches": "mismatches.jsonl"}


__all__ = ["builds_root", "new_run_dir", "reconstruct_root", "runs_root",
           "write_run"]
