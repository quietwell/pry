#!/usr/bin/env python
"""Scripted LLM-free end-to-end scenario (docs/E2E_SCENARIO.md).

Safe by default: without --target it only prints the plan. With --target it
runs the full sequence against the configured agent: connect, driver load,
process/module recon, upload+launch, breakpoint, dump, IDA open+decompile,
findings report. Requires a snapshot-reset lab VM and a passing driver gate.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

# this script now relies on Agent 5's agent_client wrappers
# (`debug_run`, `debug_wait`) and on the MCP-side `run` / `wait` /
# `status` actions. On an orchestrator that predates the state loop,
# the script's bp-hit golden path short-circuits: the `run` call will
# surface `kind: 'unknown'` instead of a StopInfo. The integrator runs
# this end-to-end once every agent has landed.


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    ap.add_argument("--target", action="store_true")
    ap.add_argument("--victim", default=r"C:\pry\victim.exe")
    args = ap.parse_args()

    if not args.target:
        print(__doc__)
        return 0

    from fastmcp import Client

    failures: list[str] = []

    async def call(client, tool: str, arguments: dict):
        res = await client.call_tool(tool, arguments)
        text = res.content[0].text if res.content else "{}"
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}

    async with Client(args.url) as client:
        status = await call(client, "target_manage", {"action": "status"})
        print("status:", json.dumps(status)[:300])
        if not status.get("ok"):
            return 1

        load = await call(client, "target_manage", {"action": "driver_load", "method": "service"})
        print("driver_load:", load)
        if not load.get("ok"):
            failures.append(f"driver_load: {load.get('error')}")

        procs = await call(client, "mem_rw", {"action": "process_list"})
        print(f"process_list: {len(procs.get('processes', []))} processes")
        kmods = await call(client, "mem_rw", {"action": "modules", "kernel": True})
        print(f"kernel modules: {len(kmods.get('modules', []))}")

        # Use run / wait instead of continue + sleep.
        # Golden path: launch (breaks on entry) → run (hits the bp we
        # just armed) → regs → continue → wait (resolves on the bp or
        # process_exit) → detach.
        launch = await call(client, "debug_manage",
                            {"action": "launch", "cmdline": args.victim})
        print("launch:", launch)
        if not launch.get("pid"):
            failures.append("launch failed")
            print("failures:", failures)
            return 1
        pid = launch["pid"]

        regs = await call(client, "debug_manage", {"action": "regs"})
        entry = regs.get("rip")
        bp = await call(client, "bp_manage", {"action": "add", "kind": "sw", "address": entry})
        print("bp add:", bp)

        # Resume and wait for the first bp hit — the response carries
        # the StopInfo in `state`; no event-ring polling needed.
        run = await call(client, "debug_manage",
                         {"action": "run", "timeout_s": 20})
        print("run:", run)
        state = (run.get("state") or {}) if isinstance(run, dict) else {}
        if not state.get("stopped") or state.get("stop_reason") not in (
                "bp_sw", "bp_hw", "launch"):
            failures.append(
                f"first run did not stop at a breakpoint: state={state}")

        # Second hop — continue to the next stop (likely process_exit
        # for a trivial victim). `continue` already carries a StopInfo
        # (within the 50 ms post-resume pump) but `wait` is how the LLM
        # confirms the final state when the target is long-running.
        await call(client, "debug_manage", {"action": "continue"})
        done = await call(client, "debug_manage",
                          {"action": "wait", "timeout_s": 20})
        print("wait:", done)
        done_state = (done.get("state") or {}) if isinstance(done, dict) else {}
        if not (done_state.get("stop_reason") == "process_exit"
                or done_state.get("stopped")):
            failures.append(
                f"wait never resolved to a stop or process_exit: "
                f"state={done_state}")

        dump = await call(client, "file_manage",
                          {"action": "dump_module", "pid": pid, "module": args.victim.split("\\")[-1]})
        print("dump:", {k: dump.get(k) for k in ("path", "bytes", "sha256")})
        if dump.get("path"):
            opened = await call(client, "ida_manage", {"action": "open", "path": dump["path"]})
            print("ida open:", str(opened)[:200])
            dec = await call(client, "ida_manage",
                             {"action": "decompile", "name": args.victim.split("\\")[-1]})
            print("decompile:", str(dec)[:200])

        await call(client, "findings_manage", {
            "action": "record", "severity": "high", "title": "E2E scenario finding",
            "description": f"bp hit at rip={entry}; dump sha256={dump.get('sha256')}",
        })
        rep = await call(client, "findings_manage", {"action": "generate_report"})
        print("report:", rep)

        await call(client, "debug_manage", {"action": "detach", "kill": True})

    if failures:
        print("\nE2E FAILED:")
        for f in failures:
            print(" -", f)
        return 1
    print("\nE2E OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
