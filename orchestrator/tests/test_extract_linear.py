"""IOC extraction: the linear domain/email scanners must agree with the
old (quadratic) regexes, and stay fast on adversarial input."""

from __future__ import annotations

import random
import re
import time

from pry.analysis import extract as ex

# The pre-fix patterns, kept verbatim as the reference semantics.
_OLD_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|info|biz|ru|cn|su|cc|pw|top|xyz|onion|"
    r"co|uk|de|jp|br|in|me|tv|ws|name|pro|gov|mil|edu)\b", re.I)
_OLD_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

_ALPHABET = list("aboc.m-_ @x1Z") + ["co", "com", "ru", "uk", ".", "."]


def _rand_text(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(n))


def test_domain_scanner_matches_old_regex_fuzz() -> None:
    rng = random.Random(1234)
    for _ in range(4000):
        t = _rand_text(rng, rng.randint(0, 40))
        old = [m.group(0) for m in _OLD_DOMAIN.finditer(t)]
        new = [m.group(0) for m in ex._RE_DOMAIN.finditer(t)]
        assert new == old, t


def test_email_scanner_matches_old_regex_fuzz() -> None:
    rng = random.Random(99)
    for _ in range(4000):
        t = _rand_text(rng, rng.randint(0, 40))
        old = [m.group(0) for m in _OLD_EMAIL.finditer(t)]
        new = [m.group(0) for m in ex._RE_EMAIL.finditer(t)]
        assert new == old, t


def test_domain_scanner_long_labels_and_edges() -> None:
    cases = [
        "x" * 63 + ".com", "x" * 64 + ".com", "-foo.com", "foo-.com",
        "a_foo.com", "foo.com_", "foo.community", "example.com-foo",
        "www.example.com.evil", "example.co.uk", "a" * 70 + "-b.ru",
        "foo..bar.com", "FOO.COM", "x.onion.", ".a.io", "1.2.co",
    ]
    for t in cases:
        old = [m.group(0) for m in _OLD_DOMAIN.finditer(t)]
        new = [m.group(0) for m in ex._RE_DOMAIN.finditer(t)]
        assert new == old, t


def test_find_iocs_adversarial_is_linear() -> None:
    # Was ~72 s (domain) / ~35 s (email) for 40 KB before the rewrite.
    for blob in (b"a." * 20000, b"ab." * 13333 + b"@",
                 b"a.a@" * 10000):
        t0 = time.perf_counter()
        ex.find_iocs(blob)
        assert time.perf_counter() - t0 < 2.0


def test_find_strings_regex_matches_reference() -> None:
    def ref(data: bytes, min_len: int) -> list[dict]:
        out: list[dict] = []
        n, i = len(data), 0
        while i < n:
            if 0x20 <= data[i] < 0x7F:
                s = i
                while i < n and 0x20 <= data[i] < 0x7F:
                    i += 1
                if i - s >= min_len:
                    out.append({"offset": s, "kind": "ascii",
                                "value": data[s:i].decode()})
                continue
            i += 1
        i = 0
        while i + 3 < n:
            if (0x20 <= data[i] < 0x7F and data[i + 1] == 0
                    and 0x20 <= data[i + 2] < 0x7F and data[i + 3] == 0):
                s, chars = i, bytearray()
                while i + 1 < n and 0x20 <= data[i] < 0x7F and data[i + 1] == 0:
                    chars.append(data[i])
                    i += 2
                if len(chars) >= min_len:
                    out.append({"offset": s, "kind": "utf16",
                                "value": chars.decode()})
                continue
            i += 2
        out.sort(key=lambda r: r["offset"])
        return out

    rng = random.Random(7)
    pool = [0, 0, 0x41, 0x42, 0x20, 0x7E, 0x7F, 0x0A, 0x61]
    for _ in range(400):
        data = bytes(rng.choice(pool) for _ in range(rng.randint(0, 80)))
        for ml in (3, 4, 5):
            assert ex.find_strings(data, min_len=ml) == ref(data, ml), data
