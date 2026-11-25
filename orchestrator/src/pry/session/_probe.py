"""TCP pre-flight probe helpers used by :mod:`.connect`.

Split out of ``session.py`` so the probe helpers can be imported in
isolation (``from pry.session import _probe_tcp`` /
``probe_hosts_concurrent`` are used directly by ``target.py`` and the
test suite).
"""

from __future__ import annotations

import asyncio
import socket as _socket


async def _probe_tcp(host: str, port: int, timeout_s: float = 3.0) -> None:
    """Complete a TCP handshake to ``(host, port)`` or raise ``OSError``.

    Runs the blocking connect in the default executor so the caller can
    ``await`` it from an async path. Raises a *rich* ``OSError`` — the
    WSAExxxx / errno tag is embedded in the message so the
    ``_error_enrich.HINT_RULES`` net-layer classifiers fire
    correctly and the caller sees ``kind="connect_refused"`` etc. rather
    than the generic ``channel_unavailable`` that gRPC-level failures
    map to.

    The timeout is short (<= 3s by default) — the intent is a pre-flight
    check, not a wait loop. ``target_manage(action='wait_connectable')``
    (F-1c) drives a retry loop on top of this helper.
    """
    loop = asyncio.get_event_loop()

    def _try() -> None:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            s.connect((host, port))

    try:
        await loop.run_in_executor(None, _try)
    except _socket.timeout as exc:
        # ``socket.timeout`` (which is ``TimeoutError`` in 3.10+) is raised
        # by ``settimeout()`` when the OS's TCP stack neither refuses nor
        # completes within the window. Winerror/errno are both None on this
        # path, so tag manually as WSAETIMEDOUT so ``connect_timeout``
        # classifies correctly.
        rich = (f"WSAETIMEDOUT tcp probe to {host}:{port} failed: "
                f"connection timed out after {timeout_s:.1f}s")
        raise OSError(None, rich) from exc
    except OSError as exc:
        # Preserve the original errno/winerror on the raised exception so
        # code that inspects errno still works, while making the *message*
        # rich enough that the regex classifiers in _error_enrich match.
        winerr = getattr(exc, "winerror", None)
        errno_ = getattr(exc, "errno", None)
        # POSIX errno values worth surfacing symbolically so the
        # HINT_RULES fire cross-platform. On Windows winerror wins.
        _POSIX_TAGS = {
            111: "ECONNREFUSED",
            110: "ETIMEDOUT",
            113: "EHOSTUNREACH",
            101: "ENETUNREACH",
            13:  "EACCES",
        }
        if winerr:
            tag = f"WSAE{winerr}"
        elif errno_ in _POSIX_TAGS:
            tag = _POSIX_TAGS[errno_]
        elif errno_:
            tag = f"errno={errno_}"
        else:
            tag = ""
        detail = exc.strerror or str(exc)
        # Attach the resolved endpoint for triage without leaking auth data.
        rich = f"{tag} tcp probe to {host}:{port} failed: {detail}".strip()
        raise OSError(exc.errno, rich) from exc


async def probe_hosts_concurrent(
    candidates: list[str], port: int, timeout_s: float,
    limit: int = 16,
) -> list[tuple[str, int, bool, float]]:
    """T1.1b (PR#2): fan out a TCP SYN probe over every host in
    *candidates* to the same *port*, capped at *limit* in flight.
    Returns a list of ``(host, port, ok, latency_ms)`` rows ordered by
    the input candidate list.

    Each per-host probe uses ``_probe_tcp`` so the rich WSAExxxx/errno
    tags survive for the HINT_RULES classifiers upstream. A probe that
    succeeds reports its wall-clock latency in milliseconds; a failure
    reports latency 0.0. No exception escapes — the per-row ``ok``
    boolean is the signal.
    """
    import time as _time
    # Late-bind ``_probe_tcp`` through the ``pry.session`` package so
    # tests that monkeypatch ``pry.session._probe_tcp`` drive this
    # path too (pre-split, both lived in the same module namespace).
    from . import _probe_tcp as _probe
    if not candidates:
        return []
    sem = asyncio.Semaphore(max(1, int(limit)))

    async def _one(h: str) -> tuple[str, int, bool, float]:
        async with sem:
            t0 = _time.monotonic()
            try:
                await _probe(h, port, timeout_s=timeout_s)
            except Exception:
                return (h, port, False, 0.0)
            return (h, port, True,
                    round((_time.monotonic() - t0) * 1000.0, 3))

    results = await asyncio.gather(
        *(_one(h) for h in candidates), return_exceptions=False)
    return list(results)
