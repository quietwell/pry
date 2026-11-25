"""Response-redaction helpers.

AccessTrace (Wave 3 P4) is the first caller: hit records carry the
full GPR bank + the 16 bytes at RIP so the LLM can reason about the
access, which also makes it the one place in the orchestrator where
a hot kernel loop's memory would pour through a reply channel. The
plan calls for:

  * default `redact_regs=True` masks GPR values and the 16-byte RIP
    bytes (replaced with ``"<redacted>"``) so a user running
    AccessTrace against a loop processing their password doesn't
    accidentally funnel the plaintext into the reply.
  * `verbosity='full'` opts back in.
  * credential-shape regexes (long base64, hex blobs resembling tokens)
    are redacted even at ``full`` — the plan's rationale is "never
    accidentally exfiltrate a plausible key, even on opt-in."

The regex list is deliberately narrow (false positives are more
annoying than false negatives at this layer — the real safety net is
``redact_regs=True`` as the default).
"""

from __future__ import annotations

import re
from typing import Any

# Credential-shape heuristics. Each pattern returns a match that's
# replaced with ``REDACTION_TOKEN`` in the ascii preview of a hit's
# bytes-at-rip. The list mirrors the "obvious credential token" group
# the Memory scanner plan calls out.
_CRED_RX: tuple[re.Pattern[str], ...] = (
    # Base64-ish, 32+ chars (AWS keys, GH tokens, generic session blobs)
    re.compile(r"[A-Za-z0-9+/=]{32,}"),
    # Hex-ish, 32+ chars (SHA1/SHA256-shaped, generic key material)
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
    # JWTs
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    # Bearer tokens in printed strings
    re.compile(r"Bearer\s+\S{8,}", re.IGNORECASE),
)

REDACTION_TOKEN = "<redacted>"


def redact_credentials_in_text(text: str) -> str:
    """Apply the credential-shape regexes to *text*. Used on the
    ascii preview of a hit's bytes-at-rip even when the caller set
    ``verbosity='full'`` — so a plaintext API key that happens to be
    on the stack still gets scrubbed."""
    if not text:
        return text
    out = text
    for rx in _CRED_RX:
        out = rx.sub(REDACTION_TOKEN, out)
    return out


# GPR names the Capstone decoder emits (mirrors Capstone's X86_REG_*
# spelling). Keep only the integer bank — the FPU/SSE state is not
# relevant to AccessTrace and the proto doesn't carry it anyway.
_GPR_NAMES: frozenset[str] = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags",
    # 32/16/8-bit aliases Capstone may spell on narrower operands.
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "ah", "bh", "ch", "dh",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
})


def redact_regs(regs: dict[str, Any] | None,
                 keep: tuple[str, ...] = ("rip",),
                 ) -> dict[str, Any]:
    """Return a copy of *regs* with every GPR value masked.

    *keep* names registers that are kept in the clear (``rip`` is the
    default — AccessTrace hit records anchor on RIP, redacting it
    makes the record useless for correlating with disassembly).
    Non-GPR keys are passed through unchanged (mnemonic, flags, etc.).
    """
    if not regs:
        return {}
    keep_s = {k.lower() for k in keep}
    out: dict[str, Any] = {}
    for k, v in regs.items():
        kl = k.lower()
        if kl in _GPR_NAMES and kl not in keep_s:
            out[k] = REDACTION_TOKEN
        else:
            out[k] = v
    return out


def redact_bytes_at_rip(hex_text: str, *, ascii_preview: str = "") -> dict:
    """Mask the raw bytes at RIP.

    AccessTrace's hit record carries bytes-at-rip as a 16-byte hex
    string + an ascii preview. The default redaction replaces the hex
    string with the token (so even disassembly isn't leaked) and
    scrubs credential-shaped sequences out of the ascii preview.
    """
    return {
        "hex": REDACTION_TOKEN if hex_text else "",
        "ascii": redact_credentials_in_text(ascii_preview),
    }


def apply_hit_redaction(hit: dict[str, Any], *,
                         verbosity: str = "normal",
                         redact: bool = True) -> dict[str, Any]:
    """Project a hit record for the caller.

    * ``redact=True`` (default) masks the GPR bank and the raw
      bytes-at-rip hex; the ASCII preview is scrubbed of credential-
      shaped substrings.
    * ``verbosity='full'`` keeps the GPR bank and the bytes-at-rip
      hex intact but still runs the credential-shape scrubber on the
      ASCII preview (the "never accidentally exfiltrate" rule).
    * ``redact=False`` + ``verbosity='full'`` returns the hit record
      verbatim — the caller has explicitly opted in to the raw reply.
    """
    if not redact and verbosity == "full":
        return hit
    out = dict(hit)
    if "regs" in out and isinstance(out["regs"], dict):
        if verbosity == "full":
            # Keep the regs but still scrub credential-shaped ASCII
            # if any reg was spelled as a string (unusual, but we
            # don't want to leak on a type surprise).
            out["regs"] = {
                k: (redact_credentials_in_text(v) if isinstance(v, str) else v)
                for k, v in out["regs"].items()
            }
        else:
            out["regs"] = redact_regs(out["regs"])
    if "bytes_at_rip" in out:
        bar = out["bytes_at_rip"]
        if isinstance(bar, dict):
            if verbosity == "full":
                out["bytes_at_rip"] = {
                    "hex": bar.get("hex", ""),
                    "ascii": redact_credentials_in_text(
                        bar.get("ascii", "")),
                }
            else:
                out["bytes_at_rip"] = redact_bytes_at_rip(
                    bar.get("hex", ""),
                    ascii_preview=bar.get("ascii", ""),
                )
    return out
