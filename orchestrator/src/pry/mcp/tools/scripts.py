"""Scripts tool registration for the pry MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from .common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

import tempfile
import time
import uuid
from collections import OrderedDict

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)
from ...plugins import (  # noqa: F401 — load_meta/plugin_dir for params verb,
    PluginTimeoutError,       # noqa: F401 — subclass of PluginError (re-exported)
    load_meta,
    plugin_dir,
)


# module-level so the lazy action-enum annotation resolves — the
# schema enum + _unknown_action share this one source of truth.
# T1.2a/T1.2b: `params` reads one plugin's schema, `submit/status/cancel/
# jobs` form the async job surface (mirrors bin_manage's _AJOBS pattern).
SCRIPT_ACTIONS = ["list", "run", "history", "actions",
                  "params", "submit", "status", "cancel", "jobs"]


# ---------------------------------------------------------------------------
# Plugin job registry (T1.2b). Mirrors bin_engine._AJOBS precisely: same
# OrderedDict with a hard cap, same sequence counter, same `task.name`
# convention (`pry-plugin-{jid}` for distinct provenance), same status
# surface shape. Progress breadcrumbs are carried in a per-job sidecar
# file written by sdk.progress(); the status verb lazy-reads it so the
# parent task never blocks on IPC.
# ---------------------------------------------------------------------------

_PJOBS: "OrderedDict[str, dict]" = OrderedDict()
_PJOB_SEQ = [0]
_PJOB_CAP = 32


def _pjob_progress_path(jid: str) -> Path:
    """Per-job sidecar path. UUID-suffixed so a crashed test or an
    orphaned job can't collide with a fresh one."""
    stem = f"pry-plugin-progress-{jid}-{uuid.uuid4().hex[:8]}.json"
    return Path(tempfile.gettempdir()) / stem


def _pjob_read_progress(path: str) -> dict | None:
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _pjob_env(job: dict, current: str) -> dict:
    """Shared projection used by `status` and `jobs` so both verbs render
    a given job the same way."""
    progress = _pjob_read_progress(job.get("progress_file", "")) \
        or job.get("progress")
    out: dict[str, Any] = {
        "job_id": job["job_id"],
        "state": job["state"],
        "plugin": job["plugin"],
        "owner": job["owner"],
        "foreign": job["owner"] != current,
        "started_at": job["started_ts"],
        "finished_at": job.get("finished_ts"),
        "timeout_s": job.get("timeout_s"),
        "progress": progress,
    }
    if job.get("error"):
        out["error"] = job["error"]
    return out


def _pjob_status(job_id: str, current: str) -> dict:
    job = _PJOBS.get(job_id)
    if job is None:
        return {"ok": False, "kind": "unknown_job",
                "error": f"job_id {job_id!r} not found",
                "hint": "script_manage(action='jobs') to see jobs"}
    env = {"ok": True, **_pjob_env(job, current)}
    if job.get("result") is not None:
        env["result"] = job["result"]
    if job.get("filed"):
        env["filed"] = job["filed"]
    if job["state"] == "timeout":
        if job.get("partial_stdout"):
            env["partial_stdout"] = job["partial_stdout"]
        if job.get("partial_stderr"):
            env["partial_stderr"] = job["partial_stderr"]
        if job.get("finding_id"):
            env["finding_id"] = job["finding_id"]
    return env


def _pjob_list(current: str, limit: int) -> dict:
    rows = [_pjob_env(j, current) for j in _PJOBS.values()]
    rows.reverse()  # most recent first
    if limit > 0:
        rows = rows[:limit]
    return {"ok": True, "count": len(rows), "jobs": rows}


def _pjob_cancel(job_id: str) -> dict:
    job = _PJOBS.get(job_id)
    if job is None:
        return {"ok": False, "kind": "unknown_job",
                "error": f"job_id {job_id!r} not found"}
    if job["state"] in ("ready", "error", "timeout", "cancelled"):
        return {"ok": True, "job_id": job_id, "state": job["state"],
                "note": "already finished"}
    # Cancel the task: run_plugin's finally kills the runner's whole
    # process tree (taskkill /T needs the parent alive to find the
    # grandchildren, so the direct child must NOT be killed first).
    # With no live task the tree kill is scheduled here instead.
    proc = job.get("proc")
    task = job.get("task")
    if task is not None and not task.done():
        task.cancel()
    elif proc is not None and getattr(proc, "returncode", 0) is None:
        from ...plugins import kill_process_tree
        try:
            asyncio.get_running_loop().create_task(kill_process_tree(proc))
        except RuntimeError:
            try:
                proc.kill()
            except Exception:
                pass
    job["state"] = "cancelled"
    return {"ok": True, "job_id": job_id, "state": "cancelled"}


def _pjob_submit(ctx: Context, name: str, params: dict,
                 timeout_s: float, owner: str, session_id: str) -> dict:
    """Create the job record, schedule the background task, return the
    record. Does NOT await the subprocess — the slow steps
    (``session.require_client('kernel').status()``, subprocess spawn,
    communicate) all happen inside the task so submit stays sub-100ms."""
    _PJOB_SEQ[0] += 1
    jid = f"p{_PJOB_SEQ[0]:04d}"
    progress_file = str(_pjob_progress_path(jid))
    started_ts = time.time()
    job: dict[str, Any] = {
        "job_id": jid, "plugin": name, "params": params,
        "state": "running", "owner": owner,
        "started_ts": started_ts, "finished_ts": None,
        "result": None, "error": "",
        "progress": None, "progress_file": progress_file,
        "task": None, "proc": None,
        "filed": None, "finding_id": "",
        "partial_stdout": "", "partial_stderr": "",
        "timeout_s": float(timeout_s),
        "session_id_at_submit": session_id,
    }

    def _set_proc(p: Any) -> None:
        job["proc"] = p

    async def _run() -> None:
        from ...plugins import run_plugin as _run_plugin
        try:
            # Re-read the session id at run-time so a session that gets
            # started mid-flight (first run) still files under it.
            cid = owner
            sid = session_id or ctx.get_current_session_id(cid)
            result = await _run_plugin(
                ctx.cfg, ctx.session, ctx.ledger, sid, name, params,
                timeout_s=float(timeout_s),
                progress_file=progress_file,
                proc_sink=_set_proc,
            )
            # Auto-file as the sync `run` verb does. Ledger failures
            # here are logged but do not flip the job to error — the
            # subprocess did its work.
            try:
                filed = file_result(ctx.ledger, sid, name, result)
                job["filed"] = filed
                if not sid:
                    ctx.set_current_session_id(cid, filed["session_id"])
            except Exception as exc:  # noqa: BLE001
                log.debug("submit filing dropped: %s", exc)
            try:
                _script_run_breadcrumb(
                    ctx, name=name,
                    target=ctx.session.cfg.target_endpoint,
                    params_json=json.dumps(params),
                )
            except Exception as _bc_exc:  # pragma: no cover
                log.debug("submit breadcrumb dropped: %s", _bc_exc)
            job["result"] = result
            job["state"] = "ready"
        except PluginTimeoutError as exc:
            job["state"] = "timeout"
            job["error"] = str(exc)
            job["partial_stdout"] = exc.partial_stdout
            job["partial_stderr"] = exc.partial_stderr
            job["finding_id"] = exc.finding_id
        except asyncio.CancelledError:
            job["state"] = "cancelled"
            raise
        except Exception as exc:  # noqa: BLE001 — surfaced via status
            job["state"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            job["finished_ts"] = time.time()
            # Snapshot the last progress blob so later readers survive
            # the sidecar file disappearing.
            final_progress = _pjob_read_progress(job.get("progress_file", ""))
            if final_progress is not None:
                job["progress"] = final_progress
            try:
                Path(job["progress_file"]).unlink(missing_ok=True)
            except OSError:
                pass
            # Trim history to the cap, FIFO.
            while len(_PJOBS) > _PJOB_CAP:
                _PJOBS.popitem(last=False)

    _PJOBS[jid] = job
    job["task"] = asyncio.create_task(_run(), name=f"pry-plugin-{jid}")
    return job


def register(mcp, ctx: Context) -> None:
    """Register the ``script_manage`` tool on *mcp*, using *ctx* for state."""
    # ---------------------------------------------------------- script_manage --

    _SCRIPT_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "script_manage(action='actions')"},
        "list": {"one_liner": "enumerate plugins under plugins/ "
                              "(bad manifests surface under bad_plugins)",
                 "key_args": "none",
                 "example": "script_manage(action='list')"},
        "run": {"one_liner": "run a plugin in a subprocess with the SDK "
                             "injected; result auto-filed as evidence",
                "key_args": "name, params_json",
                "example": "script_manage(action='run', name='pidddb_scan', "
                           "params_json='{\"recipe\":\"mm_unloaded_drivers\","
                           "\"source\":\"pdb\"}')"},
        "history": {"one_liner": "list past plugin findings (filter by "
                                 "name=)",
                    "key_args": "name, limit/offset/fields/summary",
                    "example": "script_manage(action='history')"},
        "params": {"one_liner": "one plugin's param schema (type/required/"
                                "default/enum) — cheaper than full `list`",
                   "key_args": "name",
                   "example": "script_manage(action='params', "
                              "name='sigscan')"},
        "submit": {"one_liner": "launch a plugin in the background; returns "
                                "job_id (poll status / cancel / jobs)",
                   "key_args": "name, params_json, timeout_s",
                   "example": "script_manage(action='submit', "
                              "name='sigscan', params_json='{...}')"},
        "status": {"one_liner": "poll a submit() job: running+progress → "
                                "ready+result → error/timeout",
                   "key_args": "job_id",
                   "example": "script_manage(action='status', "
                              "job_id='p0001')"},
        "cancel": {"one_liner": "kill a running plugin subprocess + set "
                                "state='cancelled'",
                   "key_args": "job_id",
                   "example": "script_manage(action='cancel', "
                              "job_id='p0001')"},
        "jobs": {"one_liner": "list recent submit() jobs (most recent first)",
                 "key_args": "limit",
                 "example": "script_manage(action='jobs', limit=20)"},
    }

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def script_manage(action: Annotated[str, Field(json_schema_extra={"enum": SCRIPT_ACTIONS})],
                            name: str = "", params_json: str = "{}",
                            # unified paging (Layer 3)
                            limit: int = 0,
                            offset: int = 0,
                            max_results: int = 0,
                            cursor: str = "",
                            verbosity: str = "normal",
                            fields: list[str] | None = None,
                            filter: Any = "",
                            summary: bool = False,
                            # T1.2b async job surface
                            job_id: str = "",
                            timeout_s: float = 600.0) -> str:
        """Run user plugins (plugins/<name>): list available plugins, run one
        (SDK injected in a subprocess, result auto-filed as finding evidence),
        inspect one plugin's param schema (params), submit it as a background
        job (submit/status/cancel/jobs), or list past plugin findings."""
        args = {"action": action, "name": name}

        async def run() -> str:
            if action not in SCRIPT_ACTIONS:
                return _unknown_action("script_manage", action, SCRIPT_ACTIONS, _SCRIPT_ACTION_HELP)
            if action == "actions":
                return _actions_help("script_manage", _SCRIPT_ACTION_HELP)
            if action == "list":
                # discover() no longer raises on a malformed
                # manifest; the plugin is skipped and the parse error
                # is surfaced in `bad_plugins` so the caller sees what
                # was excluded without losing the whole listing.
                from pry.plugins import bad_manifests
                metas = discover(ctx.cfg)
                bad = bad_manifests()
                out = {"ok": True,
                       "plugins": [meta_dict(m) for m in metas]}
                if bad:
                    out["bad_plugins"] = bad
                return _j(out)
            if action == "params":
                # T1.2a: one plugin's schema — cheap, discoverable via
                # action='actions'. Does NOT require a connected view.
                if not name:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "params: name= required"})
                meta = load_meta(plugin_dir(ctx.cfg, name))
                if meta is None:
                    return _j({"ok": False, "kind": "unknown_plugin",
                               "error": f"plugin {name!r} has no plugin.yaml"})
                return _j({
                    "ok": True,
                    "plugin": meta.name,
                    "description": meta.description,
                    "target_kind": meta.target,
                    "params": meta.params,
                })
            if action == "run":
                params = json.loads(params_json or "{}")
                cid = current_client_id()
                cur_sid = ctx.get_current_session_id(cid)
                result = await run_plugin(ctx.cfg, ctx.session, ctx.ledger,
                                          cur_sid, name, params)
                filed = file_result(ctx.ledger, cur_sid, name, result)
                if not cur_sid:
                    ctx.set_current_session_id(cid, filed["session_id"])
                try:
                    _script_run_breadcrumb(
                        ctx, name=name,
                        target=ctx.session.cfg.target_endpoint,
                        params_json=params_json or "{}",
                    )
                except Exception as _bc_exc:  # pragma: no cover
                    log.debug("script_manage breadcrumb dropped: %s", _bc_exc)
                return _j({"ok": True, "plugin": name, "result": result, **filed})
            if action == "submit":
                # T1.2b: fire-and-forget launch. Everything slow happens
                # in the task — submit returns immediately.
                if not name:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "submit: name= required"})
                try:
                    params = json.loads(params_json or "{}")
                except json.JSONDecodeError as exc:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"submit: params_json invalid: "
                                        f"{exc}"})
                cid = current_client_id()
                cur_sid = ctx.get_current_session_id(cid)
                try:
                    job = _pjob_submit(ctx, name=name, params=params,
                                       timeout_s=float(timeout_s),
                                       owner=cid,
                                       session_id=cur_sid or "")
                except Exception as exc:  # noqa: BLE001
                    return _j({"ok": False,
                               "kind": "submit_failed",
                               "error": f"{type(exc).__name__}: {exc}"})
                return _j({"ok": True,
                           "job_id": job["job_id"],
                           "state": job["state"],
                           "plugin": job["plugin"],
                           "started_at": job["started_ts"],
                           "timeout_s": job["timeout_s"],
                           "hint": "poll script_manage(action='status', "
                                   f"job_id='{job['job_id']}')"})
            if action == "status":
                if not job_id:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "status: job_id= required"})
                return _j(_pjob_status(job_id, current_client_id()))
            if action == "cancel":
                if not job_id:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "cancel: job_id= required"})
                return _j(_pjob_cancel(job_id))
            if action == "jobs":
                eff_limit = int(limit or max_results or 20)
                return _j(_pjob_list(current_client_id(), eff_limit))
            if action == "history":
                rows = [f.__dict__ for f in ctx.ledger.list_findings(None, None)
                        if f.refs.startswith("plugin:")]
                if name:
                    rows = [r for r in rows if r["refs"] == f"plugin:{name}"]
                eff_limit = limit or max_results
                return _j(_list_envelope(
                    rows, tool="script_manage", action="history",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                ))
            return _unknown_action("script_manage", action, SCRIPT_ACTIONS, _SCRIPT_ACTION_HELP)

        return await _guard(ctx, "script_manage", action, args, run)
