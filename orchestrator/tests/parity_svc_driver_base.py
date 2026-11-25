"""Shape-level parity harness: svc_manage drivers vs module_manage drivers.

A ``svc_manage(action='drivers')`` row and a ``module_manage(action='list',
space='kernel')`` row describe the same loaded kernel module from two
different sources. This harness asserts the overlapping fields (module
basename, image path, module_base, module_size) match on both views,
and that the ``kind='driver'`` discriminator is set on the svc side.

Byte-exact equality is NOT required: the module_manage path reads from
the driver's kernel-module IOCTL, while svc_manage carries SCM-sourced
image paths plus an EnumDeviceDrivers fallback for base/size. Prefixes,
casing, and path spelling may differ (``C:\\Windows\\System32\\drivers\\``
vs ``\\SystemRoot\\System32\\drivers\\``), so the harness folds both to
basename-plus-base comparison.

Imported but not auto-collected by the pytest run — Phase 2 lab
smoketest harness drives it. ``_build_shape_bucket`` is the pure helper
every call site uses so the parity logic stays testable without a lab
VM in the loop.
"""

from __future__ import annotations

import os
from typing import Any, Iterable


def _basename_lower(p: str) -> str:
    if not p:
        return ""
    # Strip \SystemRoot\ -> windir, lowercase, basename.
    sr = os.environ.get("SystemRoot", "C:\\Windows")
    if not sr.endswith("\\"):
        sr += "\\"
    if p[:12].lower() == "\\systemroot\\":
        p = sr + p[12:]
    if p[:4] == "\\??\\":  # strip NT-prefix on driver paths
        p = p[4:]
    p = p.replace("/", "\\")
    base = p.rsplit("\\", 1)[-1]
    return base.lower()


def _as_int(x: Any) -> int:
    if isinstance(x, int):
        return x
    if isinstance(x, str) and x.startswith(("0x", "0X")):
        try:
            return int(x, 16)
        except ValueError:
            return 0
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


def _build_shape_bucket(rows: Iterable[dict], *,
                        source: str) -> dict[str, dict[str, Any]]:
    """Project a list of raw rows into ``{basename -> shape}`` so the
    parity verifier can key both views on a single comparable id.

    * svc_manage drivers rows have ``image_path`` + ``module_base`` +
      ``module_size`` (and the ``kind='driver'`` discriminator).
    * module_manage(space='kernel') rows have ``path`` + ``base`` +
      ``size`` and no ``kind`` field.
    """
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        path = r.get("image_path") or r.get("path") or ""
        base = _basename_lower(path)
        if not base:
            continue
        out[base] = {
            "source": source,
            "basename": base,
            "image_path": path,
            "module_base": _as_int(r.get("module_base")
                                    or r.get("base") or 0),
            "module_size": _as_int(r.get("module_size")
                                    or r.get("size") or 0),
            "kind": r.get("kind") or "",
        }
    return out


def run_parity(svc_rows: Iterable[dict],
                mod_rows: Iterable[dict]) -> dict[str, Any]:
    """Compute shape-parity report. Returns::

        {
          "overlap": [{basename, svc, mod, match_base}],
          "svc_only": [basename],
          "mod_only": [basename],
          "mismatches": [{basename, field, svc, mod}],
          "svc_count": N, "mod_count": M,
          "ok": bool,                 # no mismatches, kind='driver' on all svc rows
        }
    """
    svc_bucket = _build_shape_bucket(svc_rows, source="svc_manage")
    mod_bucket = _build_shape_bucket(mod_rows, source="module_manage")
    overlap_keys = sorted(set(svc_bucket) & set(mod_bucket))
    svc_only = sorted(set(svc_bucket) - set(mod_bucket))
    mod_only = sorted(set(mod_bucket) - set(svc_bucket))

    overlap = []
    mismatches = []
    for k in overlap_keys:
        s = svc_bucket[k]
        m = mod_bucket[k]
        match_base = (s["module_base"] == m["module_base"]
                      and s["module_base"] != 0)
        overlap.append({"basename": k, "svc": s, "mod": m,
                        "match_base": match_base})
        # Driver kind must be set on the svc side.
        if s["kind"] != "driver":
            mismatches.append({"basename": k, "field": "kind",
                                "svc": s["kind"], "mod": "<n/a>"})
        # Base must match when both sides report a non-zero value.
        if (s["module_base"] and m["module_base"] and
                s["module_base"] != m["module_base"]):
            mismatches.append({"basename": k, "field": "module_base",
                                "svc": s["module_base"],
                                "mod": m["module_base"]})

    return {
        "overlap": overlap,
        "svc_only": svc_only,
        "mod_only": mod_only,
        "mismatches": mismatches,
        "svc_count": len(svc_bucket),
        "mod_count": len(mod_bucket),
        "ok": not mismatches,
    }


# -----------------------------------------------------------------------
# Unit tests exercising the pure helper. The lab smoketest runs the full
# parity report against live rows; this file keeps the shape logic honest
# under pytest without a lab in the loop.
# -----------------------------------------------------------------------


def test_build_shape_bucket_normalises_systemroot_prefix() -> None:
    sr = os.environ.get("SystemRoot", "C:\\Windows")
    rows = [{"image_path": r"\SystemRoot\System32\drivers\disk.sys",
             "module_base": 0x1000, "module_size": 0x100, "kind": "driver"}]
    bucket = _build_shape_bucket(rows, source="svc_manage")
    assert "disk.sys" in bucket
    assert bucket["disk.sys"]["module_base"] == 0x1000
    assert bucket["disk.sys"]["image_path"].startswith((sr, r"\SystemRoot"))


def test_run_parity_full_match() -> None:
    svc = [{"image_path": r"C:\Windows\System32\drivers\disk.sys",
            "module_base": 0xFFFFF80700000000, "module_size": 0x40000,
            "kind": "driver"}]
    mod = [{"path": r"\SystemRoot\System32\drivers\disk.sys",
            "base": 0xFFFFF80700000000, "size": 0x40000}]
    report = run_parity(svc, mod)
    assert report["ok"] is True
    assert report["overlap"][0]["match_base"] is True
    assert report["svc_only"] == []
    assert report["mod_only"] == []


def test_run_parity_detects_base_mismatch() -> None:
    svc = [{"image_path": r"C:\Windows\System32\drivers\disk.sys",
            "module_base": 0xFFFFF80700000000, "kind": "driver"}]
    mod = [{"path": r"\SystemRoot\System32\drivers\disk.sys",
            "base": 0xFFFFF80700100000}]
    report = run_parity(svc, mod)
    assert report["ok"] is False
    assert any(m["field"] == "module_base" for m in report["mismatches"])


def test_run_parity_detects_missing_kind() -> None:
    svc = [{"image_path": r"C:\Windows\System32\drivers\disk.sys",
            "module_base": 1, "kind": "service"}]  # wrong!
    mod = [{"path": r"C:\Windows\System32\drivers\disk.sys", "base": 1}]
    report = run_parity(svc, mod)
    assert report["ok"] is False
    assert any(m["field"] == "kind" for m in report["mismatches"])


def test_run_parity_tracks_svc_only_and_mod_only() -> None:
    svc = [{"image_path": r"C:\d\A.sys", "module_base": 1, "kind": "driver"}]
    mod = [{"path": r"C:\d\B.sys", "base": 2}]
    report = run_parity(svc, mod)
    assert report["svc_only"] == ["a.sys"]
    assert report["mod_only"] == ["b.sys"]
    assert report["overlap"] == []
