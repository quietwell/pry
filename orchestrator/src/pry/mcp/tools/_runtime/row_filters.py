"""Filter / summary helpers for memory_manage list-returning actions.

Each ``_<kind>_summary(rows)`` returns an aggregate dict and
``_apply_<kind>_filter(rows, filter_dict)`` applies the per-call
``filter=`` to narrow the row list before the summary is computed.
"""

from __future__ import annotations


def _modules_summary(rows: list[dict]) -> dict:
    by_signer: dict[str, int] = {}
    total_size = 0
    for r in rows:
        signer = str(r.get("signer") or r.get("path") or "unknown")
        by_signer[signer] = by_signer.get(signer, 0) + 1
        try:
            total_size += int(r.get("size", 0)) if not isinstance(r.get("size"), str) \
                          else int(r.get("size", "0"), 0)
        except Exception:
            pass
    return {"total": len(rows), "by_signer": by_signer, "total_size": total_size}


def _apply_modules_filter(rows: list[dict], f: dict) -> list[dict]:
    import re, fnmatch
    out = rows
    if f.get("name_regex"):
        pat = re.compile(f["name_regex"], re.I)
        out = [r for r in out if pat.search(str(r.get("name", "")))]
    if f.get("name_glob"):
        gl = str(f["name_glob"]).lower()
        out = [r for r in out
                if fnmatch.fnmatch(str(r.get("name", "")).lower(), gl)]
    if f.get("min_size"):
        min_size = int(f["min_size"])
        def _sz(r):
            s = r.get("size", 0)
            return int(s, 0) if isinstance(s, str) else int(s)
        out = [r for r in out if _sz(r) >= min_size]
    if f.get("path_contains"):
        s = str(f["path_contains"]).lower()
        out = [r for r in out if s in str(r.get("path", "")).lower()]
    return out


def _vad_summary(rows: list[dict]) -> dict:
    from ..._decode_enums import decode_protect, decode_vad_type
    by_protect: dict[str, int] = {}
    by_vad_type: dict[str, int] = {}
    total_commit = 0
    for r in rows:
        p = decode_protect(r.get("protect", 0))
        v = decode_vad_type(r.get("vad_type", 0))
        by_protect[p] = by_protect.get(p, 0) + 1
        by_vad_type[v] = by_vad_type.get(v, 0) + 1
        try:
            total_commit += int(r.get("commit_charge", 0))
        except Exception:
            pass
    return {"total": len(rows), "by_protect": by_protect,
            "by_vad_type": by_vad_type, "total_commit_charge": total_commit}


def _apply_vad_filter(rows: list[dict], f: dict) -> list[dict]:
    from ..._decode_enums import decode_protect
    out = rows
    if f.get("protect"):
        want = f["protect"]
        wants = set(want) if isinstance(want, list) else {want}
        # Accept both the raw int and the decoded string.
        wants_upper = {str(x).upper() for x in wants}
        def _matches_protect(r):
            raw = r.get("protect", 0)
            dec = decode_protect(raw).upper()
            return (str(raw) in wants_upper or hex(int(raw) if not isinstance(raw, str)
                                                    else int(raw, 0)).upper() in wants_upper
                    or any(w in dec for w in wants_upper))
        out = [r for r in out if _matches_protect(r)]
    if f.get("vad_type") is not None:
        vt = f["vad_type"]
        wants = {int(x) for x in (vt if isinstance(vt, list) else [vt])}
        out = [r for r in out if int(r.get("vad_type", 0)) in wants]
    if f.get("min_size"):
        min_size = int(f["min_size"])
        def _extent(r):
            s = int(r.get("start", 0), 0) if isinstance(r.get("start"), str) else int(r.get("start", 0))
            e = int(r.get("end", 0), 0) if isinstance(r.get("end"), str) else int(r.get("end", 0))
            return max(0, e - s)
        out = [r for r in out if _extent(r) >= min_size]
    return out


def _handles_summary(rows: list[dict]) -> dict:
    by_type: dict[str, int] = {}
    for r in rows:
        t = str(r.get("type_name") or r.get("type") or "unknown")
        by_type[t] = by_type.get(t, 0) + 1
    return {"total": len(rows), "by_type": by_type}


def _apply_handles_filter(rows: list[dict], f: dict) -> list[dict]:
    import re
    out = rows
    if f.get("type_name"):
        want = f["type_name"]
        wants = {str(x).lower() for x in (want if isinstance(want, list) else [want])}
        out = [r for r in out if str(r.get("type_name", "")).lower() in wants]
    if f.get("name_regex"):
        pat = re.compile(f["name_regex"], re.I)
        out = [r for r in out if pat.search(str(r.get("name", "")))]
    if f.get("name_substring"):
        s = str(f["name_substring"]).lower()
        out = [r for r in out if s in str(r.get("name", "")).lower()]
    if f.get("granted_access_and"):
        mask = int(f["granted_access_and"])
        out = [r for r in out if (int(r.get("granted_access", 0)) & mask) == mask]
    return out


def _processes_summary(rows: list[dict]) -> dict:
    by_parent: dict[int, int] = {}
    for r in rows:
        pp = int(r.get("parent_pid", 0))
        by_parent[pp] = by_parent.get(pp, 0) + 1
    return {"total": len(rows), "by_parent": by_parent}


def _apply_processes_filter(rows: list[dict], f: dict) -> list[dict]:
    import re
    out = rows
    if f.get("image_regex"):
        pat = re.compile(f["image_regex"], re.I)
        out = [r for r in out if pat.search(str(r.get("image_name", "")))]
    if f.get("parent_pid") is not None:
        pp = int(f["parent_pid"])
        out = [r for r in out if int(r.get("parent_pid", 0)) == pp]
    if f.get("pid_range"):
        lo, hi = f["pid_range"]
        out = [r for r in out if int(lo) <= int(r.get("pid", 0)) <= int(hi)]
    return out


__all__ = [
    "_modules_summary",
    "_apply_modules_filter",
    "_vad_summary",
    "_apply_vad_filter",
    "_handles_summary",
    "_apply_handles_filter",
    "_processes_summary",
    "_apply_processes_filter",
]
