"""Top-level ``parse_dump`` entry — stat/sniff/dispatch to the right body
parser (kernel x64 / kernel x86 / MDMP).

Reads are lazy/random-access so a multi-GB MEMORY.DMP doesn't get
slurped for a header answer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .kernel import _parse_kernel_dump, _parse_kernel_dump32
from .mdmp import _parse_mdmp
from .offsets import MDMP_SIG, PAGE_SIG, VALID_32, VALID_64


def parse_dump(path: str | Path) -> dict[str, Any]:
    """Parse a crash dump into the stable WP1 shape (module docstring).

    Never raises: failures come back as ``{ok: False, kind: ...}`` —
    ``not_found`` for a missing file, ``bad_dump`` for unrecognized or
    truncated content. Reads are lazy/random-access so a multi-GB
    MEMORY.DMP doesn't get slurped for a header answer.
    """
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        return {"ok": False, "kind": "not_found",
                "error": f"{path}: {exc}", "path": str(p)}
    try:
        with open(p, "rb") as fh:
            head = fh.read(8)
            if head[:4] == PAGE_SIG and head[4:8] == VALID_64:
                out = _parse_kernel_dump(fh, size, str(p))
            elif head[:4] == PAGE_SIG and head[4:8] == VALID_32:
                out = _parse_kernel_dump32(fh, size, str(p))
            elif head[:4] == MDMP_SIG:
                out = _parse_mdmp(fh, size, str(p))
            else:
                return {"ok": False, "kind": "bad_dump",
                        "error": f"{path}: not a crash dump "
                                 f"(magic {head!r})",
                        "path": str(p)}
    except OSError as exc:
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: {exc}", "path": str(p)}
    except Exception as exc:  # noqa: BLE001 — contract: never raises
        # Truncated / hostile headers surface as struct.error, IndexError,
        # ValueError, OverflowError or MemoryError (a u32 length field
        # driving a huge read) from the body parsers.
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: malformed dump "
                         f"({type(exc).__name__}: {exc})",
                "path": str(p)}
    if not isinstance(out, dict):
        return {"ok": False, "kind": "bad_dump",
                "error": f"{path}: parser returned no result", "path": str(p)}
    out["size"] = size
    out["path"] = str(p)
    return out
