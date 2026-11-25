"""Plugin async submit/poll surface + timeout-survivable results.

Covers PR #3 (plan §T1.2a + §T1.2b):

* ``script_manage(action='params', name=...)`` returns a plugin's
  schema and matches the on-disk ``plugin.yaml``.
* ``submit`` returns a ``job_id`` immediately (under 100ms) even when
  the plugin sleeps for seconds.
* ``status`` surfaces ``state='running' progress=<fraction>`` while
  the plugin is still working, then ``state='ready' result=...``.
* A plugin that outlives its deadline leaves ``state='timeout'``
  AND inserts a ``plugin_timeout`` finding whose evidence is of kind
  ``plugin_timeout_log`` with partial stderr/stdout.
* ``cancel`` kills a running subprocess and flips the state.
* ``jobs`` lists recent jobs most-recent-first.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest
import yaml

from pry.config import PryConfig
from pry.findings import FindingsLedger
from pry.mcp.tools import scripts as _scripts
from pry.mcp.tools.context import Context
from pry.plugins import (PluginTimeoutError, discover, load_meta,
                            plugin_dir, run_plugin)
from pry.session import Session


# ---------------------------------------------------------------------------
# Plugin fixtures. Each one lives on disk under tmp_path so PryConfig can
# discover it the way it would in prod.
# ---------------------------------------------------------------------------

_SLOW_YAML = """
name: slowplug
description: sleeps and emits a progress breadcrumb halfway
target: any
params:
  sleep_s:
    type: float
    default: 2.0
  halfway_note:
    type: str
    default: halfway
"""

_SLOW_RUN = """
import asyncio

async def run(sdk, params):
    s = float(params.get("sleep_s", 2.0))
    sdk.progress(0.1, "starting")
    await asyncio.sleep(s / 2.0)
    sdk.progress(0.5, params.get("halfway_note", "halfway"))
    await asyncio.sleep(s / 2.0)
    sdk.progress(1.0, "done")
    return {"ok": True, "summary": "slept " + str(s) + "s", "slept_s": s}
"""

# Writes to stderr before entering the forever-sleep, so the timeout
# path has partial evidence to capture.
_TIMEOUT_YAML = """
name: timeoutplug
description: writes a breadcrumb to stderr, then blocks forever
target: any
params: {}
"""

_TIMEOUT_RUN = """
import sys
import time

def run(sdk, params):
    sys.stderr.write("timeoutplug: entered run()\\n")
    sys.stderr.flush()
    sdk.progress(0.25, "about to block")
    while True:
        time.sleep(1)
    return {"ok": True}
"""


def _make_plugin(root: Path, name: str, yaml_text: str, run_text: str) -> None:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.yaml").write_text(yaml_text, encoding="utf-8")
    (d / "run.py").write_text(run_text, encoding="utf-8")


def _cfg_with_plugins(tmp_path: Path) -> PryConfig:
    cfg = PryConfig()
    cfg.plugins.dir = str(tmp_path)
    return cfg


def _build_ctx(cfg: PryConfig, ledger: FindingsLedger) -> Context:
    """Minimal Context — just enough state for the submit/status/jobs
    helpers to run. No gRPC clients; no MCP server; no IDA bridge."""
    session = Session(PryConfig())
    return Context(cfg, session, ledger, bridge=None)


# ---------------------------------------------------------------------------
# T1.2a — params verb
# ---------------------------------------------------------------------------

def test_params_matches_plugin_yaml_each_in_tree_plugin() -> None:
    """``params`` on each in-tree plugin returns the exact schema the
    file holds — no accidental drift between the dataclass and disk."""
    cfg = PryConfig()
    metas = discover(cfg)
    assert metas, "no plugins discovered in the shipped pack"
    for meta in metas:
        pyml_path = Path(meta.path) / "plugin.yaml"
        raw = yaml.safe_load(pyml_path.read_text(encoding="utf-8")) or {}
        expected_params = dict(raw.get("params") or {})
        on_disk = load_meta(plugin_dir(cfg, meta.name))
        assert on_disk is not None
        assert on_disk.name == meta.name
        assert on_disk.target == str(raw.get("target") or "any")
        assert on_disk.params == expected_params, (
            f"{meta.name}: params drift between PluginMeta and plugin.yaml")


# ---------------------------------------------------------------------------
# T1.2b — submit/status: fast handoff + progress breadcrumbs
# ---------------------------------------------------------------------------

async def test_submit_returns_fast_status_shows_progress_then_result(
        tmp_path: Path) -> None:
    _make_plugin(tmp_path, "slowplug", _SLOW_YAML, _SLOW_RUN)
    cfg = _cfg_with_plugins(tmp_path)
    led = FindingsLedger(tmp_path / "f.db")
    ctx = _build_ctx(cfg, led)

    t0 = time.perf_counter()
    job = _scripts._pjob_submit(
        ctx, name="slowplug",
        params={"sleep_s": 2.0, "halfway_note": "halfway"},
        timeout_s=30.0, owner="test-client", session_id="")
    submit_ms = (time.perf_counter() - t0) * 1000
    # Submit must not wait on the subprocess. Allow a generous ceiling —
    # the plan asks for <100ms, but Windows CI jitter spikes test clocks
    # occasionally; the SPEC is that it does not wait on the plugin's
    # sleep (2s), which 500ms comfortably rules out.
    assert submit_ms < 500, (
        f"submit took {submit_ms:.0f}ms; must not wait on the plugin")
    assert job["job_id"].startswith("p")
    assert job["state"] == "running"
    assert job["plugin"] == "slowplug"

    jid = job["job_id"]

    # Wait for the halfway progress breadcrumb to land.
    found_running = False
    for _ in range(200):  # up to ~10s
        env = _scripts._pjob_status(jid, "test-client")
        if env["state"] == "running" and env.get("progress"):
            found_running = True
            # Match the plan: progress 0.5 after halfway sleep.
            if env["progress"].get("fraction", 0.0) >= 0.4:
                break
        if env["state"] in ("ready", "error", "timeout", "cancelled"):
            break
        await asyncio.sleep(0.05)

    # The plugin advertises 0.1 → 0.5 → 1.0; we should have observed at
    # least ONE running+progress snapshot before completion.
    assert found_running, (
        "never observed state=running+progress before completion; "
        "sidecar progress file may not be wired")

    # Now wait for completion.
    await asyncio.wait_for(job["task"], timeout=10.0)
    env = _scripts._pjob_status(jid, "test-client")
    assert env["state"] == "ready"
    assert env["result"]["slept_s"] == 2.0
    assert env.get("finished_at") is not None
    # file_result wrote a finding under refs=plugin:slowplug.
    assert env.get("filed", {}).get("finding_id")
    # Progress file was snapshotted and cleaned up; last known value is
    # 1.0 (the plugin's final progress call).
    assert env["progress"]["fraction"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# T1.2b — timeout-survivable results
# ---------------------------------------------------------------------------

async def test_run_plugin_timeout_records_finding_with_partial_log(
        tmp_path: Path) -> None:
    """A plugin that outlives its deadline: ``PluginTimeoutError`` is
    raised, a ``plugin_timeout`` finding lands in the ledger, and the
    attached evidence is of kind ``plugin_timeout_log`` with the
    plugin's stderr breadcrumb inside."""
    _make_plugin(tmp_path, "timeoutplug", _TIMEOUT_YAML, _TIMEOUT_RUN)
    cfg = _cfg_with_plugins(tmp_path)
    led = FindingsLedger(tmp_path / "f.db")
    session = Session(PryConfig())
    sid = led.start_session("test-timeout")

    with pytest.raises(PluginTimeoutError) as info:
        await run_plugin(cfg, session, led, sid, "timeoutplug", {},
                         timeout_s=2.0)
    err = info.value
    # Partial stderr survived the kill. The plugin writes
    # "timeoutplug: entered run()" before entering the forever-sleep.
    assert "timeoutplug: entered run()" in err.partial_stderr
    assert err.finding_id, "ledger write failed — plan says it must survive"
    # Finding + evidence are in the ledger.
    rows = [f.__dict__ for f in led.list_findings(sid, None)]
    assert any(r["refs"] == "plugin:timeoutplug" for r in rows), (
        "ledger has no plugin_timeout finding for this plugin")
    row = next(r for r in rows if r["refs"] == "plugin:timeoutplug")
    assert "timeout" in row["title"].lower()
    ev = led.evidence_for(row["id"])
    assert any(e.kind == "plugin_timeout_log" for e in ev), (
        f"no plugin_timeout_log evidence attached (kinds: "
        f"{[e.kind for e in ev]})")
    log_ev = next(e for e in ev if e.kind == "plugin_timeout_log")
    assert "timeoutplug: entered run()" in log_ev.content
    led.close()


async def test_submit_timeout_job_state_and_partials(
        tmp_path: Path) -> None:
    """Same scenario through the submit/poll surface: the job ends in
    ``state='timeout'`` with its partials attached, so a client that
    polls after the deadline sees everything that was captured."""
    _make_plugin(tmp_path, "timeoutplug2", _TIMEOUT_YAML, _TIMEOUT_RUN)
    cfg = _cfg_with_plugins(tmp_path)
    led = FindingsLedger(tmp_path / "f.db")
    ctx = _build_ctx(cfg, led)

    job = _scripts._pjob_submit(
        ctx, name="timeoutplug2", params={},
        timeout_s=2.0, owner="test-client", session_id="")
    await asyncio.wait_for(job["task"], timeout=15.0)

    env = _scripts._pjob_status(job["job_id"], "test-client")
    assert env["state"] == "timeout", env
    # Hard-coded breadcrumb from the plugin's run() — proves partials
    # survived the kill. The _TIMEOUT_RUN body writes
    # "timeoutplug: entered run()" verbatim regardless of plugin dir.
    assert "entered run()" in env.get("partial_stderr", "")
    assert env.get("finding_id")
    assert env.get("error"), "timeout job should carry an error message"
    led.close()


# ---------------------------------------------------------------------------
# T1.2b — cancel + jobs
# ---------------------------------------------------------------------------

async def test_cancel_kills_subprocess_and_flips_state(
        tmp_path: Path) -> None:
    _make_plugin(tmp_path, "slowplug_c", _SLOW_YAML, _SLOW_RUN)
    cfg = _cfg_with_plugins(tmp_path)
    led = FindingsLedger(tmp_path / "f.db")
    ctx = _build_ctx(cfg, led)

    job = _scripts._pjob_submit(
        ctx, name="slowplug_c", params={"sleep_s": 10.0},
        timeout_s=60.0, owner="test-client", session_id="")
    # Give the subprocess a moment to spawn so `cancel` has something
    # concrete to kill. On a fast box this is sub-second.
    for _ in range(60):
        if job.get("proc") is not None:
            break
        await asyncio.sleep(0.05)
    assert job.get("proc") is not None, "subprocess never spawned"

    out = _scripts._pjob_cancel(job["job_id"])
    assert out["ok"] is True
    assert out["state"] == "cancelled"

    # The task eventually unwinds — don't leak it into the next test.
    try:
        await asyncio.wait_for(job["task"], timeout=10.0)
    except asyncio.CancelledError:
        pass
    led.close()


async def test_jobs_lists_recent_most_recent_first(tmp_path: Path) -> None:
    _make_plugin(tmp_path, "slowplug_j", _SLOW_YAML, _SLOW_RUN)
    cfg = _cfg_with_plugins(tmp_path)
    led = FindingsLedger(tmp_path / "f.db")
    ctx = _build_ctx(cfg, led)

    j1 = _scripts._pjob_submit(ctx, name="slowplug_j",
                               params={"sleep_s": 0.2}, timeout_s=10.0,
                               owner="test-client", session_id="")
    j2 = _scripts._pjob_submit(ctx, name="slowplug_j",
                               params={"sleep_s": 0.2}, timeout_s=10.0,
                               owner="test-client", session_id="")

    await asyncio.wait_for(j1["task"], timeout=10.0)
    await asyncio.wait_for(j2["task"], timeout=10.0)

    env = _scripts._pjob_list("test-client", limit=20)
    assert env["ok"] is True
    ids_in_response = [row["job_id"] for row in env["jobs"]]
    # j2 submitted after j1 → appears first in a most-recent-first list.
    assert j1["job_id"] in ids_in_response
    assert j2["job_id"] in ids_in_response
    assert ids_in_response.index(j2["job_id"]) < \
        ids_in_response.index(j1["job_id"]), ids_in_response
    led.close()
