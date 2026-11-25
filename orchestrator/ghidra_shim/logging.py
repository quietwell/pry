"""Shim-local logging helpers: stderr line writer and log-file tail.

Same contract as ``idalib_shim.logging``.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _tail_log(path: Path, lines: int = 20) -> str:
    """Return the last N lines of the backend log for embedding in an
    error message."""
    try:
        with open(path, "rb") as fh:
            # Only the end matters — never slurp a multi-MB log.
            try:
                fh.seek(-64 * 1024, os.SEEK_END)
            except OSError:
                fh.seek(0)
            data = fh.read()
        text = data.decode("utf-8", "replace")
        got = text.splitlines()
        if len(got) < lines:
            # just rotated (_BoundedLog): the rest of the tail is in .1
            prev = Path(str(path) + ".1")
            try:
                with open(prev, "rb") as fh:
                    try:
                        fh.seek(-64 * 1024, os.SEEK_END)
                    except OSError:
                        fh.seek(0)
                    got = fh.read().decode("utf-8", "replace").splitlines() + got
            except OSError:
                pass
        tail = "\n".join(got[-lines:])
        return f"log tail ({path.name}):\n{tail}" if tail else f"log {path.name} empty"
    except OSError as exc:
        return f"log {path.name} unreadable: {exc}"


# --------------------------------------------------------- env redaction --
# The startup env dump lands in %TEMP% (world-readable on most hosts) and
# used to carry every variable verbatim — agent tokens included. Values
# are kept only for an allowlist of diagnostic keys that do not look like
# secrets; everything else is listed by name only.
_SAFE_ENV_RE = re.compile(
    r"^(PATH|PATHEXT|COMSPEC|SYSTEMROOT|WINDIR|TEMP|TMP|OS|"
    r"NUMBER_OF_PROCESSORS|PROCESSOR_\w+|PYTHON\w*|VIRTUAL_ENV|CONDA_\w+|"
    r"IDA\w*|GHIDRA\w*|JAVA_HOME|JDK_HOME|PRY_\w+)$", re.I)
_SECRET_RE = re.compile(r"TOKEN|SECRET|PASS|PWD|KEY|AUTH|CRED|COOKIE|SESSION",
                        re.I)


def _env_dump_lines(env=None) -> list[str]:
    env = os.environ if env is None else env
    out = []
    for k in sorted(env):
        if _SAFE_ENV_RE.match(k) and not _SECRET_RE.search(k):
            out.append(f"  {k}={env[k]}")
        else:
            out.append(f"  {k}=<redacted>")
    return out


def _prune_old_dumps(directory: Path, prefix: str, keep: int = 5) -> None:
    """Startup dumps are per-pid; keep only the newest ``keep``."""
    try:
        dumps = sorted(directory.glob(prefix + "*.txt"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return
    for p in dumps[keep:]:
        try:
            p.unlink()
        except OSError:
            pass


# ---------------------------------------------------------- bounded logs --
LOG_MAX_BYTES = 16 * 1024 * 1024


class _BoundedLog:
    """Append-only binary log file that rotates to ``<name>.1`` once it
    passes ``cap`` bytes (one backup kept), so a chatty or long-lived
    backend can no longer grow its %TEMP% log without bound. Drop-in for
    the ``open(path, "ab")`` handle the session code writes/flushes."""

    def __init__(self, path: Path, cap: int = LOG_MAX_BYTES) -> None:
        self.path = Path(path)
        self.cap = int(cap)
        self._rotate_if_big()
        self._fh = open(self.path, "ab")

    def _rotate_if_big(self) -> None:
        try:
            if self.path.stat().st_size >= self.cap:
                os.replace(self.path, self.path.with_name(self.path.name + ".1"))
        except OSError:
            pass

    def write(self, data: bytes) -> int:
        n = self._fh.write(data)
        if self._fh.tell() >= self.cap:
            self._fh.close()
            self._rotate_if_big()
            self._fh = open(self.path, "ab")
        return n

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    @property
    def closed(self) -> bool:
        return self._fh.closed


def _open_bounded_log(path: Path, cap: int = LOG_MAX_BYTES) -> _BoundedLog:
    return _BoundedLog(path, cap)
