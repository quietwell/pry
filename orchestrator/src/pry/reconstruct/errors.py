"""The one error type the reconstruct package raises at its callers."""

from __future__ import annotations

import difflib
from typing import Any, Iterable


class ReconError(Exception):
    """Failure with an envelope ``kind`` (``bad_arg``, ``not_allowed``,
    ``toolchain_missing``, ``compile_failed``, ...).

    ``field`` names the offending input (``signature.params[1].type``);
    ``closest`` lists the valid names nearest to a misspelled one."""

    def __init__(self, kind: str, message: str, *, hint: str = "",
                 field: str = "", closest: Iterable[str] = (),
                 extra: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.hint = hint
        self.field = field
        self.closest = list(closest)
        self.extra = dict(extra or {})

    def envelope(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": False, "kind": self.kind,
                               "error": str(self)}
        if self.hint:
            out["hint"] = self.hint
        if self.field:
            out["field"] = self.field
        if self.closest:
            out["closest"] = self.closest
        out.update(self.extra)
        return out


def bad_arg(message: str, *, field: str = "", hint: str = "",
            given: str = "", valid: Iterable[str] = ()) -> ReconError:
    """``bad_arg`` naming the valid values closest to *given*."""
    valid = list(valid)
    closest = difflib.get_close_matches(given, valid, n=3, cutoff=0.5) \
        if given else []
    if not hint and valid and len(valid) <= 24:
        hint = "valid: " + ", ".join(valid)
    return ReconError("bad_arg", message, hint=hint, field=field,
                      closest=closest)
