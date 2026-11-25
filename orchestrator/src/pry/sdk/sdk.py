"""PrySDK: façade handed to plugins; composes the per-domain API
objects on top of the connected view clients."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from ..agent_client import AgentClient
from .apis.codegen import CodegenApi
from .apis.dbg import DbgApi
from .apis.emu import EmuApi
from .apis.findings import FindingsApi
from .apis.mem import MemApi
from .apis.mods import ModsApi
from .apis.procs import ProcsApi
from .apis.symbols import SymbolsApi
from .apis.yara import YaraApi
from .reader import PRIMARY_VIEW, PryError


class PrySDK:
    """Facade handed to plugins. Holds the connected view clients plus the
    findings ledger; APIs are plain attributes so scripts stay flat."""

    def __init__(self, clients: dict[str, AgentClient] | None = None, ledger: Any = None,
                 session_id: str = "", nt_build: int = 0,
                 symbols: SymbolsApi | None = None,
                 artifacts_dir: str = "",
                 progress_file: str = "") -> None:
        self.clients: dict[str, AgentClient] = clients or {}
        self.nt_build = nt_build
        self.symbols = symbols or SymbolsApi()
        # Canonical artifact root passed down from the orchestrator config.
        # Falls back to cwd-relative so ad-hoc SDK use still lands somewhere
        # predictable — plugins must prefer this over Path.cwd()/artifacts.
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir \
            else Path.cwd() / "artifacts"
        # Sidecar progress-breadcrumb file (set by the submit/poll surface).
        # When empty, ``progress()`` is a no-op so plugins can call it
        # unconditionally.
        self.progress_file = str(progress_file or "")
        self.mem = MemApi(self)
        self.mods = ModsApi(self)
        self.procs = ProcsApi(self)
        self.dbg = DbgApi(self)
        self.findings = FindingsApi(ledger, session_id)
        self.yara = YaraApi()
        self.codegen = CodegenApi()
        self.emu = EmuApi()
        kernel = self.clients.get(PRIMARY_VIEW)
        if kernel is not None:
            self.yara.bind(kernel)

    async def close(self) -> None:
        for c in self.clients.values():
            await c.close()

    def progress(self, fraction: float, note: str = "") -> None:
        """Write a progress breadcrumb picked up by
        ``script_manage(action='status')``.

        Best-effort: no-op if the SDK was constructed without a
        ``progress_file`` (ad-hoc / test use), and silent on write errors
        so a plugin never crashes because its progress sink went away.
        ``fraction`` is clamped to [0, 1].
        """
        if not self.progress_file:
            return
        try:
            f = float(fraction)
        except (TypeError, ValueError):
            return
        if f < 0.0:
            f = 0.0
        elif f > 1.0:
            f = 1.0
        try:
            body = json.dumps({
                "fraction": f, "note": str(note or ""),
                "ts": time.time(),
            })
        except (TypeError, ValueError):
            return
        tmp = self.progress_file + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(body)
            os.replace(tmp, self.progress_file)
        except OSError:
            # Progress breadcrumbs are a convenience — if the FS is
            # read-only or the parent dir vanished, drop the update.
            try:
                os.unlink(tmp)
            except OSError:
                pass

    async def parity(self, pid: int, samples: int = 16, read_bytes: int = 4096,
                     seed: int = 0) -> dict[str, Any]:
        from ..parity import run_parity

        k = self.clients.get(PRIMARY_VIEW)
        u = self.clients.get("user")
        if k is None or u is None:
            raise PryError("parity needs both the kernel and user views connected")
        return await run_parity(k, u, pid, samples=samples, read_bytes=read_bytes, seed=seed)
