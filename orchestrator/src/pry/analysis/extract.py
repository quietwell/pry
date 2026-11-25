"""String and IOC extraction over raw byte buffers.

Pure compute — usable on an artifact on disk (``bin_manage``) or a live
memory read result (``memory_manage strings``). All limits are hard caps: a
hostile blob cannot grow output unboundedly.
"""

from __future__ import annotations

import re

MAX_STRINGS = 20_000
MAX_IOCS = 4_096
MIN_LEN_FLOOR = 3
MIN_LEN_CAP = 256

_ASCII_MIN_RUN = 3  # internal floor regardless of caller min_len


def find_strings(data: bytes, *, min_len: int = 5,
                 utf16: bool = True, cap: int = MAX_STRINGS,
                 base_va: int = 0) -> list[dict]:
    """Extract ASCII and aligned UTF-16LE strings with file offsets.

    Returns ``[{offset, kind:"ascii"|"utf16", value}]`` sorted by offset,
    capped at *cap* entries. ``truncated`` is implied by len == cap.
    When *base_va* is non-zero each row also gets ``va`` = base_va+offset
    (live-range scans).
    """
    min_len = max(MIN_LEN_FLOOR, min(int(min_len or 5), MIN_LEN_CAP))
    out: list[dict] = []
    # Maximal printable runs via the C regex engine — byte-identical to
    # the old per-byte loop, ~50x faster on multi-MB buffers.
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        if len(out) >= cap:
            break
        out.append({"offset": m.start(), "kind": "ascii",
                    "value": m.group().decode("ascii")})
    if utf16 and len(out) < cap:
        # UTF-16LE ASCII range: printable byte followed by NUL, aligned on
        # even offsets (the PE/loader convention knife follows). An
        # odd-offset run can never share a byte with an even-offset one
        # (a byte cannot be both printable and NUL), so scanning every
        # offset and keeping the even starts finds exactly the
        # even-aligned maximal runs the old stride-2 loop found.
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
            if len(out) >= cap:
                break
            if m.start() & 1:
                continue
            out.append({"offset": m.start(), "kind": "utf16",
                        "value": m.group()[::2].decode("ascii")})
    out.sort(key=lambda r: r["offset"])
    if base_va:
        for r in out:
            r["va"] = base_va + r["offset"]
    return out


# ---------------------------------------------------------------------------
# IOC extraction — patterns are deliberately conservative; a plausible-shape
# match beats a permissive one (knife's plausibility-filtered approach).
# ---------------------------------------------------------------------------

_RE_URL = re.compile(
    r"\b(?:https?|ftp|socks[45]?)://[^\s\"'<>\)\]]{4,}", re.I)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
# Domains / emails are NOT matched by one big regex any more: the old
# ``\b(?:label\.)+(?:tld)\b`` and ``\b[local]+@...`` patterns backtrack
# quadratically on target-controlled input ("a.a.a.a…" with no TLD took
# ~64 s for 40 KB — on the event loop). Instead a linear candidate pass
# (maximal ``[A-Za-z0-9.-]`` runs / ``@`` anchors) feeds a Python check
# that reproduces the old regexes' leftmost-greedy semantics exactly
# (pinned by a differential test against the old patterns).
_DOMAIN_TLDS = frozenset((
    "com", "net", "org", "io", "info", "biz", "ru", "cn", "su", "cc", "pw",
    "top", "xyz", "onion", "co", "uk", "de", "jp", "br", "in", "me", "tv",
    "ws", "name", "pro", "gov", "mil", "edu"))
_RE_DOMAIN_RUN = re.compile(r"[A-Za-z0-9.\-]+")
_MAX_LABEL = 63
_RE_EMAIL_DOMAIN = re.compile(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_EMAIL_LOCAL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-")


def _is_word(ch: str) -> bool:
    """``\\b`` word-char test (matches ``re``'s str-pattern definition)."""
    return ch == "_" or ch.isalnum()


def _domains_in_run(text: str, rs: int, re_: int) -> list[tuple[int, int]]:
    """Domain matches inside one maximal ``[A-Za-z0-9.-]`` run
    ``text[rs:re_]``. Linear in the run length."""
    run = text[rs:re_]
    if "." not in run:
        return []
    before_word = rs > 0 and _is_word(text[rs - 1])
    after_word = re_ < len(text) and _is_word(text[re_])
    # Segment table: seg j spans [a[j], b[j]) in run coordinates; b[j] is
    # the '.' that ends it (len(run) for the last segment).
    a: list[int] = []
    b: list[int] = []
    start = 0
    while True:
        dot = run.find(".", start)
        a.append(start)
        if dot < 0:
            b.append(len(run))
            break
        b.append(dot)
        start = dot + 1
    m = len(a) - 1
    # valid[j]: whole segment j is a label followed by '.'.
    valid = [False] * (m + 1)
    tld_end = [-1] * (m + 1)     # run-index end of the TLD word, or -1
    for j in range(m + 1):
        sa, sb = a[j], b[j]
        if j < m and 0 < sb - sa <= _MAX_LABEL and run[sa].isalnum() \
                and run[sb - 1].isalnum():
            valid[j] = True
        hy = run.find("-", sa, sb)
        we = sb if hy < 0 else hy
        if we > sa and run[sa:we].lower() in _DOMAIN_TLDS:
            # \b after the TLD: '-' / '.' are non-word; the run end
            # borders a non-run char (word only when it is '_').
            if we < sb or j < m or not after_word:
                tld_end[j] = we
    # R[j]: first index >= j whose segment is NOT a valid label.
    R = [m] * (m + 2)
    for j in range(m, -1, -1):
        R[j] = R[j + 1] if (valid[j] and j < m) else j
    # last_tld[x]: largest i <= x with a usable TLD, else -1.
    last_tld = [-1] * (m + 1)
    cur = -1
    for j in range(m + 1):
        if tld_end[j] >= 0:
            cur = j
        last_tld[j] = cur
    seg_of = [0] * len(run)
    for j in range(m + 1):
        for k in range(a[j], b[j] + (1 if j < m else 0)):
            seg_of[k] = j
    out: list[tuple[int, int]] = []
    resume = 0
    for p in range(len(run)):
        if p < resume or not run[p].isalnum():
            continue
        if p == 0:
            if before_word:
                continue
        elif run[p - 1] not in ".-":
            continue
        j = seg_of[p]
        if j >= m:
            continue  # no '.' after the first label
        sb = b[j]
        if sb - p > _MAX_LABEL or not run[sb - 1].isalnum():
            continue
        best = last_tld[R[j + 1]]
        if best < j + 1:
            continue
        end = tld_end[best]
        out.append((rs + p, rs + end))
        resume = end
    return out


def _find_domains(text: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for m in _RE_DOMAIN_RUN.finditer(text):
        if m.end() - m.start() >= 4:          # shortest hit: "a.co"
            out.extend(_domains_in_run(text, m.start(), m.end()))
    return out


def _find_emails(text: str) -> list[tuple[int, int]]:
    """Email matches with the old regex's semantics, linear time: anchor
    on each '@', match the domain forward, walk the local part back."""
    out: list[tuple[int, int]] = []
    if "@" not in text:
        return out
    pos = 0
    k = text.find("@")
    while k != -1:
        dm = _RE_EMAIL_DOMAIN.match(text, k + 1)
        if dm is not None:
            lo = k
            while lo > pos and text[lo - 1] in _EMAIL_LOCAL:
                lo -= 1
            start = -1
            for q in range(lo, k):
                prev_w = q > 0 and _is_word(text[q - 1])
                if prev_w != _is_word(text[q]):
                    start = q
                    break
            if start >= 0:
                out.append((start, dm.end()))
                pos = dm.end()
                k = text.find("@", pos)
                continue
        k = text.find("@", k + 1)
    return out


class _SpanFinder:
    """``finditer``-shaped adapter so the IOC loop treats the linear
    domain/email scanners like the remaining (safe) regexes."""

    def __init__(self, fn) -> None:
        self._fn = fn

    def finditer(self, text: str):
        for s, e in self._fn(text):
            yield _Span(text, s, e)


class _Span:
    __slots__ = ("_t", "_s", "_e")

    def __init__(self, text: str, s: int, e: int) -> None:
        self._t, self._s, self._e = text, s, e

    def group(self, _n: int = 0) -> str:
        return self._t[self._s:self._e]


_RE_DOMAIN = _SpanFinder(_find_domains)
_RE_EMAIL = _SpanFinder(_find_emails)
_RE_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
# Registry keys — both hive-letter and full-hive spellings.
_RE_REGKEY = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)"
    r"(?:\\[^\s\"'<>|]{1,200})+")
# Win paths: drive-letter or UNC with at least one directory component.
_RE_WINPATH = re.compile(
    r"(?:\b[A-Za-z]:\\|\\\\[^\s\"'<>|]{1,64}\\)[^\s\"'<>|]{1,200}")
# Unix paths: absolute, >= 2 components, common roots only (noise floor).
_RE_UNIXPATH = re.compile(
    r"\b(?:/(?:etc|usr|var|tmp|opt|home|root|bin|sbin|lib|proc|sys|dev|run|mnt)"
    r"(?:/[^\s\"'<>|]{0,120}){1,4})")
_RE_GUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b")


def _plausible_ipv4(ip: str) -> bool:
    if ip in ("0.0.0.0", "255.255.255.255"):
        return False
    parts = ip.split(".")
    # 127.* loopback and link-local are uninteresting as IOCs; version-
    # shaped strings (e.g. "4.0.30319.1" sneaking past) get filtered by the
    # regex already, but reject the all-zeros and broadcast edges here.
    if parts[0] == "0" or parts[0] == "255":
        return False
    return True


def defang(value: str) -> str:
    """Make an indicator safe to paste: hxxp://, [.], @→[at]."""
    out = re.sub(r"^https?", lambda m: m.group(0).replace("ttp", "xxp"),
                 value, flags=re.I)
    out = out.replace(".", "[.]").replace("@", "[at]")
    return out


def find_iocs(data: bytes, *, cap: int = MAX_IOCS,
              include_strings_scan: bool = True,
              base_va: int = 0) -> list[dict]:
    """Extract indicators of compromise from *data*.

    Scans the decoded string surface (ASCII + UTF-16) rather than raw
    bytes so wide-char payloads are covered. Returns
    ``[{kind, value, defanged, offset, count}]`` — duplicates collapse
    into ``count``. Order: first-seen.
    """
    strings = find_strings(data, min_len=4) if include_strings_scan else []
    seen: dict[tuple[str, str], dict] = {}
    for s in strings:
        text = s["value"]
        for kind, rx in (
            ("url", _RE_URL), ("ipv4", _RE_IPV4), ("domain", _RE_DOMAIN),
            ("email", _RE_EMAIL), ("btc_wallet", _RE_BTC),
            ("registry_key", _RE_REGKEY), ("win_path", _RE_WINPATH),
            ("unix_path", _RE_UNIXPATH), ("guid", _RE_GUID),
        ):
            for m in rx.finditer(text):
                val = m.group(0)
                if kind == "ipv4" and not _plausible_ipv4(val):
                    continue
                if kind == "domain" and val.lower().endswith(
                        (".dll", ".exe", ".sys")):
                    continue  # filenames, not domains
                key = (kind, val)
                row = seen.get(key)
                if row is None:
                    if len(seen) >= cap:
                        return list(seen.values())
                    row = {"kind": kind, "value": val,
                           "defanged": defang(val), "offset": s["offset"],
                           "count": 0}
                    seen[key] = row
                row["count"] += 1
    rows = list(seen.values())
    if base_va:
        for r in rows:
            r["va"] = base_va + r["offset"]
    return rows
