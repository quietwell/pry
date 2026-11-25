"""``global_find`` verb — system-wide handle/module name search.

Feature #7 of the System-Informer adoption plan (slice doc:
``an internal plan``,
numbered #5 inside the slice, #7 in the master README). Mirrors the
existing ``scan_*`` job state machine so a wide fan-out doesn't blow
the MCP deadline: ``global_find`` with no ``scan_id`` kicks off a
background fan-out and returns a ``scan_id`` immediately; the caller
polls progress / fetches results / cancels via the same lifecycle,
keyed into a SEPARATE ``_GLOBAL_FINDS`` registry so a scan_cancel
can't confuse pattern scans with find jobs.

Zero driver dependency: enumerates processes via ``mem_processes``,
then fans out to ``mem_modules`` / ``handle_list``. Handle search
requires driver (umagent handle enum is a separate stretch goal per
the slice doc) — surfaced as a per-PID error, not a job failure.
"""

from __future__ import annotations

import asyncio
import logging
import re as _re
import time as _t
from typing import Any

from ....caller import current_client_id
from .._runtime.envelope import _list_envelope
from .._runtime.response import _hexify_dict, _j


log = logging.getLogger("pry.mcp.tools.mem.global_find")


# Orchestrator-side registry of active global_find jobs. Keyed into a
# SEPARATE map from the scan registry so a stray ``scan_cancel`` can't
# tear down a find job (and vice versa). Entry shape:
#   {find_id, owner, task, hits: list[dict], errors: dict[pid, msg],
#    progress: {pids_total, pids_scanned, hits_so_far},
#    status: 'running'|'done'|'cancelled'|'error',
#    error?: str, args: {...for observability}, started_ts,
#    finished_ts?, cancel: asyncio.Event}
_GLOBAL_FINDS: dict[str, dict[str, Any]] = {}
_GLOBAL_FIND_SEQ = [0]


# -------------------------------------------------------- validation ------

_VALID_KINDS = ("module", "handle")


def _parse_kinds(kinds: list[str] | None) -> list[str] | dict[str, Any]:
    if not kinds:
        return list(_VALID_KINDS)
    bad = [k for k in kinds if k not in _VALID_KINDS]
    if bad:
        return {
            "ok": False, "kind": "bad_arg",
            "error": f"global_find: unknown kinds={bad}",
            "hint": f"valid kinds are {list(_VALID_KINDS)}",
        }
    # Preserve order, drop dupes.
    return list(dict.fromkeys(kinds))


def _compile_matcher(pattern: str, regex: bool):
    if regex:
        try:
            rx = _re.compile(pattern, _re.IGNORECASE)
        except _re.error as exc:
            return None, {
                "ok": False, "kind": "bad_arg",
                "error": f"global_find: bad regex: {exc}",
                "hint": "escape metacharacters or set regex=False",
            }
        return rx.search, None
    needle = pattern.lower()

    def _substr(s: str) -> bool:
        return needle in (s or "").lower()
    return _substr, None


# -------------------------------------------------------- runner ----------

async def _global_find_runner(entry: dict[str, Any], c,
                              pattern: str, kinds: list[str],
                              regex: bool, want_object_names: bool,
                              max_results: int, concurrency: int) -> None:
    """Fan out across PIDs, filter module/handle rows against ``pattern``.

    Writes incremental results into ``entry['hits']`` and errors into
    ``entry['errors']``. Honours ``entry['cancel']``.
    """
    cancel: asyncio.Event = entry["cancel"]
    hits: list[dict[str, Any]] = entry["hits"]
    errors: dict[int, str] = entry["errors"]

    match, err = _compile_matcher(pattern, regex)
    if err is not None:
        entry["status"] = "error"
        entry["error"] = err["error"]
        return

    try:
        res = await c.mem_processes(limit=0, full=True)
        procs = (res.get("processes") if isinstance(res, dict) else res) or []
    except Exception as exc:  # noqa: BLE001
        entry["status"] = "error"
        entry["error"] = f"process enumeration failed: {exc}"
        return

    entry["progress"]["pids_total"] = len(procs)

    sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def _one_pid(proc: dict[str, Any]) -> None:
        if cancel.is_set() or len(hits) >= max_results:
            return
        pid = int(proc.get("pid") or 0)
        pname = str(proc.get("image_name") or "")
        async with sem:
            if cancel.is_set() or len(hits) >= max_results:
                return
            if "module" in kinds:
                try:
                    mods = await c.mem_modules(pid, False)
                except Exception as exc:  # noqa: BLE001 — per-pid non-fatal
                    errors[pid] = f"modules: {exc}"
                else:
                    for m in mods:
                        if len(hits) >= max_results:
                            break
                        name = str(m.get("name") or "")
                        path = str(m.get("path") or "")
                        if match(name) or match(path):
                            hits.append({
                                "pid": pid, "process_name": pname,
                                "kind": "module",
                                "name": name,
                                "extra": {"module_path": path,
                                           "base": m.get("base"),
                                           "size": m.get("size")},
                            })
            if "handle" in kinds and len(hits) < max_results:
                try:
                    handles = await c.handle_list(
                        pid, want_names=want_object_names)
                except Exception as exc:  # noqa: BLE001 — per-pid non-fatal
                    errors[pid] = f"handles: {exc}"
                else:
                    for h in handles:
                        if len(hits) >= max_results:
                            break
                        hname = str(h.get("name") or "")
                        htype = str(h.get("type_name") or "")
                        # Match against the object name primarily; fall
                        # back to the type-name so a search for "File"
                        # still works when want_object_names=False.
                        if match(hname) or (not hname and match(htype)):
                            hits.append({
                                "pid": pid, "process_name": pname,
                                "kind": "handle",
                                "name": hname,
                                "extra": {
                                    "handle_type": htype,
                                    "handle": h.get("handle"),
                                    "granted_access": h.get("granted_access"),
                                },
                            })
            entry["progress"]["pids_scanned"] += 1
            entry["progress"]["hits_so_far"] = len(hits)

    tasks = [asyncio.create_task(_one_pid(p)) for p in procs]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        raise
    if cancel.is_set():
        entry["status"] = "cancelled"
    elif entry["status"] == "running":
        entry["status"] = "done"


# -------------------------------------------------------- state entry pts --

async def _global_find_start(ctx, c, *, pattern: str,
                              kinds: list[str] | None,
                              regex: bool, want_object_names: bool,
                              max_results: int,
                              concurrency: int) -> dict[str, Any]:
    if not pattern:
        return {"ok": False, "kind": "bad_arg",
                "error": "global_find: pattern= is required"}
    kinds_resolved = _parse_kinds(kinds)
    if isinstance(kinds_resolved, dict):
        return kinds_resolved
    # Early regex compile so a syntax error surfaces synchronously
    # instead of as a background-job error_status.
    _probe, probe_err = _compile_matcher(pattern, regex)
    if probe_err is not None:
        return probe_err
    max_r = int(max_results or 1024)
    _GLOBAL_FIND_SEQ[0] += 1
    find_id = f"g{_GLOBAL_FIND_SEQ[0]:04d}"
    owner = current_client_id()
    cancel_evt = asyncio.Event()
    entry: dict[str, Any] = {
        "find_id": find_id, "owner": owner, "task": None,
        "hits": [], "errors": {},
        "progress": {"pids_total": 0, "pids_scanned": 0,
                      "hits_so_far": 0},
        "status": "running",
        "args": {"pattern": pattern, "kinds": kinds_resolved,
                  "regex": bool(regex),
                  "want_object_names": bool(want_object_names),
                  "max_results": max_r,
                  "concurrency": int(concurrency or 8)},
        "started_ts": _t.time(), "finished_ts": None,
        "cancel": cancel_evt,
    }
    _GLOBAL_FINDS[find_id] = entry

    async def _runner_wrap() -> None:
        try:
            await _global_find_runner(
                entry, c, pattern=pattern, kinds=kinds_resolved,
                regex=regex, want_object_names=want_object_names,
                max_results=max_r,
                concurrency=int(concurrency or 8))
        except Exception as exc:  # noqa: BLE001
            entry["status"] = "error"
            entry["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            entry["finished_ts"] = _t.time()

    entry["task"] = asyncio.create_task(
        _runner_wrap(), name=f"pry-global-find-{find_id}")
    return {"ok": True, "find_id": find_id, "scan_id": find_id,
            "status": "running", "owner": owner,
            "hint": "poll memory_manage(action='global_find', "
                    f"scan_id={find_id!r}) for progress and results"}


def _global_find_status(find_id: str) -> dict[str, Any]:
    entry = _GLOBAL_FINDS.get(find_id)
    if entry is None:
        return {"ok": False, "kind": "unknown_find",
                "error": f"find_id {find_id!r} not found",
                "hint": "memory_manage(action='global_find') with no scan_id "
                        "starts a new job"}
    current = current_client_id()
    return {"ok": True,
            "find_id": find_id, "scan_id": find_id,
            "status": entry["status"],
            "progress": dict(entry["progress"]),
            "hits_so_far": len(entry["hits"]),
            "errors": dict(entry["errors"]),
            "started_ts": entry["started_ts"],
            "finished_ts": entry.get("finished_ts"),
            "owner": entry["owner"],
            "foreign": entry["owner"] != current,
            "error": entry.get("error")}


def _global_find_result(ctx, find_id: str, *, limit: int,
                        offset: int) -> dict[str, Any] | str:
    entry = _GLOBAL_FINDS.get(find_id)
    if entry is None:
        return {"ok": False, "kind": "unknown_find",
                "error": f"find_id {find_id!r} not found"}
    status = entry["status"]
    hits = list(entry["hits"])
    # Partial results are useful — don't block the caller while running,
    # but mark coverage so they know it's incomplete.
    coverage_status = "complete" if status in ("done",) else "partial"
    extras = {
        "find_id": find_id, "scan_id": find_id, "status": status,
        "progress": dict(entry["progress"]),
        "errors": dict(entry["errors"]),
        "started_ts": entry["started_ts"],
        "finished_ts": entry.get("finished_ts"),
        "owner": entry["owner"],
        "args": entry["args"],
    }
    if status == "error":
        extras["error"] = entry.get("error")
    env = _list_envelope(
        hits, tool="memory_manage", action="global_find",
        limit=limit or 0, offset=offset,
        fields=(), filter="", summary=False,
        global_cap=ctx.cfg.mcp_max_items(),
        extras=extras,
    )
    env["coverage"] = {"status": coverage_status, "kind": "fanout"}
    return _hexify_dict(env, add_int_mirror=True)


async def _global_find_cancel(find_id: str) -> dict[str, Any]:
    entry = _GLOBAL_FINDS.get(find_id)
    if entry is None:
        return {"ok": False, "kind": "unknown_find",
                "error": f"find_id {find_id!r} not found"}
    current = current_client_id()
    if entry["owner"] != current:
        return {"ok": False, "kind": "foreign_owned",
                "error": f"find {find_id!r} owned by {entry['owner']!r}",
                "hint": "ask the peer to cancel"}
    entry["cancel"].set()
    return {"ok": True, "find_id": find_id, "scan_id": find_id,
            "status": entry["status"],
            "hint": "poll global_find status until status == 'cancelled'"}


def _global_find_list(current: str) -> dict[str, Any]:
    rows = []
    for fid, entry in _GLOBAL_FINDS.items():
        rows.append({
            "find_id": fid, "scan_id": fid,
            "status": entry["status"],
            "hits_so_far": len(entry["hits"]),
            "progress": dict(entry["progress"]),
            "started_ts": entry["started_ts"],
            "owner": entry["owner"],
            "foreign": entry["owner"] != current,
            "args": entry["args"],
        })
    rows.sort(key=lambda r: -r["started_ts"])
    return {"ok": True, "count": len(rows), "finds": rows}


# -------------------------------------------------------- public entry ----

async def handle_global_find(ctx, c, *, pattern: str,
                             kinds: list[str] | None,
                             regex: bool, want_object_names: bool,
                             max_results: int,
                             concurrency: int,
                             scan_id: str,
                             limit: int, offset: int,
                             cancel: bool = False,
                             list_jobs: bool = False) -> str:
    """Single entry point for every global_find lifecycle operation.

    - ``cancel=True`` + ``scan_id`` -> cancel the job.
    - ``list_jobs=True`` -> enumerate all find jobs.
    - ``scan_id`` and running job -> return current progress + hits so far.
    - ``scan_id`` and finished job -> return final hits.
    - no ``scan_id`` -> start a new fan-out.
    """
    if list_jobs:
        return _j(_global_find_list(current_client_id()))
    if cancel:
        if not scan_id:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "global_find cancel requires scan_id="})
        return _j(await _global_find_cancel(scan_id))
    if scan_id:
        # Status + partial results in one shot — if the job is still
        # running, we return the envelope with coverage=partial so a
        # caller can poll by just repeating the same call.
        res = _global_find_result(ctx, scan_id,
                                   limit=limit, offset=offset)
        return res if isinstance(res, str) else _j(res)
    # No scan_id: start a new job and return its id.
    out = await _global_find_start(
        ctx, c, pattern=pattern, kinds=kinds,
        regex=regex, want_object_names=want_object_names,
        max_results=max_results, concurrency=concurrency)
    return _j(out)
