"""Response-shape helpers used by every tool closure.

``_j`` / ``_j_hex`` / ``_j_hex_decoded`` / ``_ascii`` are the terminal
"return this to FastMCP" helpers; the imports from ``.._hex_addresses``,
``.._decode_enums`` and ``.._error_enrich`` are kept here so the shim's
``from .common import *`` keeps re-exporting the historical names.
"""

from __future__ import annotations

import json
from typing import Any

# Three response utilities.
#   _hex_addresses    render every address/size as '0x...' with `_int` mirror
#   _decode_enums     attach `<field>_decoded` (PAGE_EXECUTE_READ, ...) siblings
#   _error_enrich     classify raw error strings into {kind, hint} pairs
from ..._hex_addresses import hexify_dict as _hexify_dict, hexify as _hexify
from ..._decode_enums import attach_decoded_list as _decode_list, attach_decoded as _decode
from ..._error_enrich import (
    enrich_error as _enrich_error,
    enrich_win32 as _enrich_win32_v2,
    classify as _classify,
)
# Common Win32 error codes surfaced by the driver / agent as raw
# "DeviceIoControl gle=87" strings. Enriching in one place keeps the
# messages readable without touching every call site. Table lives in
# error_maps.py so `type_convert err_lookup` shares the same source of
# truth (extended there with the top ~120 NTSTATUS + HRESULT decomposers).
from ...error_maps import WIN32_ERRORS as _WIN32_ERRORS


def _j(data: Any) -> Any:
    # A-1: finalized envelopes go out as a FastMCP ``ToolResult``
    # with ``content=[]`` and ``structured_content=data`` so the same
    # payload no longer ships on the wire twice (once as
    # ``content[0].text`` and again as ``structuredContent.result``).
    #
    # Discriminator: ``_envelope.finalize`` always stamps
    # ``summary.size_bytes`` on a finalized envelope — no inner
    # ``run()`` site sets that key, and no legacy pre-envelope shape
    # produces it. That keeps every other ``_j(...)`` call site
    # (ledger evidence writes at ~1414/3676 with parity reports and
    # yara-match lists; and inner ``run()`` bodies that build a raw
    # envelope-shaped dict and rely on ``_coerce_to_envelope`` to
    # re-wrap it) on the historical ``json.dumps`` path.
    #
    # ``PRY_MCP_LEGACY_DUAL_CONTENT=1`` restores the pre-A-1
    # dual-emit shape for one release; see ``_envelope.to_tool_result``.
    if (
        isinstance(data, dict)
        and "ok" in data
        and isinstance(data.get("summary"), dict)
        and "size_bytes" in data["summary"]
    ):
        from ..._envelope import to_tool_result as _to_tool_result
        return _to_tool_result(data)
    return json.dumps(data, indent=2, default=str)


def _j_hex(data: Any) -> str:
    """Return-shape helper: JSON-encode data with every address/size field
    rendered as a '0x...' hex string (with `_int` mirror for arithmetic).
    Use for every tool response that touches driver-side data."""
    return _j(_hexify_dict(data))


def _j_hex_decoded(data: Any, context: str) -> str:
    """Like _j_hex() but also attaches enum-decoded siblings for the given
    context ('vad' | 'service' | 'handle' | 'pool' | 'region')."""
    return _j(_hexify_dict(_decode(data, context=context)))


def _ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:256])


__all__ = [
    "_j",
    "_j_hex",
    "_j_hex_decoded",
    "_ascii",
    "_hexify",
    "_hexify_dict",
    "_decode",
    "_decode_list",
    "_enrich_error",
    "_enrich_win32_v2",
    "_classify",
    "_WIN32_ERRORS",
]
