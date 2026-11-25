"""mechanics-audit 2026-11-24 — data / analysis subsystem regressions.

Artifact sha index, path sanitizing, PE import amplification, minidump
rank table + never-raise contract, findings dedupe / FTS / SQLite mode,
PDB cache hygiene, evidence + spill retention, gadget cache keying,
analysis-job pruning, masked pattern scan, YARA include refusal.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import random
import struct
import sys
import time
import types
from pathlib import Path

import pytest

from pry.config import PryConfig
from pry.findings import FindingsLedger
from pry.mcp import _artifacts as art


def _cfg(tmp_path: Path) -> PryConfig:
    cfg = PryConfig()
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    return cfg


# --------------------------------------------------------- artifact index --

def test_sha_prefix_validation_blocks_glob_and_path_tricks(tmp_path):
    cfg = _cfg(tmp_path)
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"x")
    for bad in ("../..", "..\\..", "c:", "C:\\", "*", "a/b", "zz", "", " "):
        assert art.valid_sha_prefix(bad) is None
        assert art.find_artifact_by_sha(cfg, bad) is None
    assert art.valid_sha_prefix("ABCdef01") == "abcdef01"


def test_find_by_sha_uses_index_not_rehash(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    led = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    d = tmp_path / "artifacts" / "dumps"
    d.mkdir()
    blobs = []
    for i in range(5):
        data = os.urandom(4096) + bytes([i])
        (d / f"m{i}.sys").write_bytes(data)
        blobs.append(hashlib.sha256(data).hexdigest())
    # First lookup walks + hashes and persists the index (an unknown sha
    # walks the whole store, so every file gets indexed).
    hit = art.find_artifact_by_sha(cfg, blobs[3], ledger=led)
    assert hit is not None and hit[1] == blobs[3]
    assert art.find_artifact_by_sha(cfg, "f" * 64, ledger=led) is None
    assert all(led.artifact_paths_for(s) for s in blobs)
    # Simulate a restart: empty process index, re-seed from the ledger;
    # no file may be hashed again.
    art._INDEX.clear()
    art._SEEDED.discard(led)
    calls = []
    real = hashlib.sha256

    def _counting(*a, **k):
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr(art.hashlib, "sha256", _counting)
    for sha in blobs:
        got = art.find_artifact_by_sha(cfg, sha, ledger=led)
        assert got is not None and got[1] == sha
    assert calls == [], "indexed artifacts were re-hashed"
    # Unknown sha: a stat walk, still no hashing of known files.
    assert art.find_artifact_by_sha(cfg, "0" * 64, ledger=led) is None
    assert calls == []
    led.close()


def test_index_detects_changed_file(tmp_path):
    cfg = _cfg(tmp_path)
    p = tmp_path / "artifacts" / "ingested" / "x.bin"
    p.parent.mkdir()
    p.write_bytes(b"one")
    sha1 = hashlib.sha256(b"one").hexdigest()
    assert art.find_artifact_by_sha(cfg, sha1)[1] == sha1
    p.write_bytes(b"two!")
    os.utime(p, (time.time() + 5, time.time() + 5))
    assert art.find_artifact_by_sha(cfg, sha1) is None
    sha2 = hashlib.sha256(b"two!").hexdigest()
    assert art.find_artifact_by_sha(cfg, sha2)[1] == sha2


async def test_find_by_sha_async_runs_off_loop(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    seen = []
    real = art._lookup_sync

    def _spy(*a, **k):
        import threading
        seen.append(threading.current_thread().name)
        return real(*a, **k)

    monkeypatch.setattr(art, "_lookup_sync", _spy)
    await art.find_artifact_by_sha_async(cfg, "ab" * 32)
    import threading
    assert seen and seen[0] != threading.main_thread().name


def test_safe_basename():
    for raw, want in (("..\\..\\evil.dmp", "evil.dmp"), ("C:evil.dmp", "evil.dmp"),
                      ("/etc/passwd", "passwd"), ("..", "file.bin"),
                      ("Mini 1.dmp", "Mini 1.dmp"), ("a:b?c.dmp", "b_c.dmp"),
                      ("NUL.dmp", "_NUL.dmp"), ("x.dmp. ", "x.dmp")):
        assert art.safe_basename(raw) == want, raw


class _DumpFake:
    """file_list_dir/file_download fake for dump_manage latest."""

    def __init__(self, names):
        self.names = names
        self.downloads: list[str] = []

    async def file_list_dir(self, d, recursive=False):
        return [{"name": n, "dir": False, "mtime_unix": 100 - i, "size": 10}
                for i, n in enumerate(self.names)]

    async def file_download(self, remote, local, offset=0, length=0):
        self.downloads.append(local)
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        Path(local).write_bytes(b"PAGEDU64" + b"\0" * 64)
        return {"bytes": 72}


async def test_latest_dump_sanitizes_target_name_and_probe(tmp_path):
    from pry.mcp.tools import dump as dump_mod
    ctx = types.SimpleNamespace(cfg=_cfg(tmp_path))
    c = _DumpFake(["..\\..\\..\\pwned.dmp"])
    got = await dump_mod._latest_minidump(ctx, c)
    assert got is not None
    dumps = (tmp_path / "artifacts" / "dumps").resolve()
    assert Path(got["local_path"]).resolve().parent == dumps
    assert Path(got["local_path"]).name == "pwned.dmp"
    assert not (tmp_path / "pwned.dmp").exists()
    # per-call probe names, cleaned up afterwards
    probes = [p for p in c.downloads if ".latest_probe." in p]
    assert probes and not any(Path(p).exists() for p in probes)


# ------------------------------------------------------------ PE imports --

def _pe_shared_ilt(n_desc: int, n_thunks: int, *, distinct_iat: bool) -> bytes:
    e_lfanew, opt_size = 0x40, 0xF0
    imp_rva = 0x1000
    ilt_rva = imp_rva + (n_desc + 1) * 20 + 0x100
    name_rva = ilt_rva + (n_thunks + 1) * 8 + 0x10
    size = name_rva + 0x100
    buf = bytearray(size)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, e_lfanew + 4, 0x8664, 1, 0, 0, 0,
                     opt_size, 0x22)
    opt = e_lfanew + 24
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<Q", buf, opt + 24, 0x140000000)
    struct.pack_into("<I", buf, opt + 56, size)
    struct.pack_into("<I", buf, opt + 108, 16)
    struct.pack_into("<II", buf, opt + 120, imp_rva, (n_desc + 1) * 20)
    s = e_lfanew + 24 + opt_size
    buf[s:s + 8] = b".all\0\0\0\0"
    struct.pack_into("<IIII", buf, s + 8, size, 0, size, 0)
    struct.pack_into("<I", buf, s + 36, 0x60000020)
    for i in range(n_desc):
        iat = ilt_rva + (i * 8 if distinct_iat else 0)
        struct.pack_into("<IIIII", buf, imp_rva + i * 20, ilt_rva, 0, 0,
                         name_rva, iat)
    buf[name_rva:name_rva + 8] = b"evil.dll"
    hint = name_rva + 0x20
    buf[hint + 2:hint + 6] = b"Func"
    for j in range(n_thunks):
        struct.pack_into("<Q", buf, ilt_rva + j * 8, hint)
    return bytes(buf)


def test_pe_import_amplification_is_capped():
    from pry.analysis import pe
    t0 = time.perf_counter()
    img = pe.parse(_pe_shared_ilt(512, 65536, distinct_iat=True),
                   layout="image")
    dt = time.perf_counter() - t0
    total = sum(len(d["entries"]) for d in img.imports)
    assert total <= pe.MAX_IMPORT_ENTRIES
    assert img.imports_truncated is True
    assert dt < 5.0, f"import walk took {dt:.1f}s"
    # byte-identical duplicate descriptors collapse to one
    img2 = pe.parse(_pe_shared_ilt(64, 100, distinct_iat=False),
                    layout="image")
    assert len(img2.imports) == 1 and len(img2.imports[0]["entries"]) == 100
    assert img2.imports_truncated is False


def test_pe_normal_imports_unchanged():
    import _pefixture as fx
    from pry.analysis import pe
    img = pe.parse(fx.build_pe(imports={"KERNEL32.dll": ["CreateFileW",
                                                         "ReadFile"],
                                        "ntdll.dll": ["NtClose"]}))
    names = {(d["dll"], e["name"]) for d in img.imports for e in d["entries"]}
    assert ("KERNEL32.dll", "ReadFile") in names
    assert ("ntdll.dll", "NtClose") in names
    assert img.imports_truncated is False


# ------------------------------------------------------------- minidump ----

def test_bitmap_rank_table_matches_naive():
    from pry.minidump.phys import _PhysReader
    rng = random.Random(11)
    for _ in range(20):
        bm = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 1500)))
        r = _PhysReader(io.BytesIO(b""), bitmap=bm, data_start=0)
        for _ in range(100):
            pfn = rng.randrange(len(bm) * 8)
            nb, rem = divmod(pfn, 8)
            ref = sum(bin(b).count("1") for b in bm[:nb])
            if rem:
                ref += bin(bm[nb] & ((1 << rem) - 1)).count("1")
            assert r._bitmap_rank(pfn) == ref


def test_bitmap_rank_is_fast_on_16gib():
    from pry.minidump.phys import _PhysReader
    bm = b"\xff" * (4 * 1024 * 1024 // 8)
    r = _PhysReader(io.BytesIO(b""), bitmap=bm, data_start=0x2000)
    t0 = time.perf_counter()
    for i in range(500):
        r.pa_to_file((len(bm) * 8 - 1 - i) * 0x1000)
    assert time.perf_counter() - t0 < 1.0


def test_parse_dump_never_raises(tmp_path, monkeypatch):
    from pry.minidump import parse as parse_mod
    p = tmp_path / "x.dmp"
    p.write_bytes(b"PAGEDU64" + b"\0" * 16)          # truncated header
    out = parse_mod.parse_dump(p)
    assert out["ok"] is False and out["kind"] == "bad_dump"

    def _boom(*a, **k):
        raise MemoryError("huge u32 length")

    monkeypatch.setattr(parse_mod, "_parse_kernel_dump", _boom)
    out = parse_mod.parse_dump(p)
    assert out["ok"] is False and "MemoryError" in out["error"]


# -------------------------------------------------------------- findings ----

def test_dedupe_only_for_anchored_and_full_signature():
    led = FindingsLedger(":memory:")
    sid = led.start_session("t")
    a, dup = led.record_ex(sid, "info", "pool tag owner", "d1",
                           module="a.sys")
    b, dup2 = led.record_ex(sid, "info", "pool tag owner", "d2",
                            module="b.sys")
    assert dup is None and dup2 is None and a != b   # unanchored: both kept
    c, _ = led.record_ex(sid, "info", "t", "x", artifact_sha="s1",
                         module="m", function="f1")
    d, dupd = led.record_ex(sid, "info", "t", "x", artifact_sha="s1",
                            module="m", function="f2")
    assert dupd is None and c != d                   # different function
    e, dupe = led.record_ex(sid, "info", "t", "x", artifact_sha="s1",
                            module="m", function="f1")
    assert dupe == c                                 # true duplicate


def test_fts_search_punctuation_filters_and_rank():
    led = FindingsLedger(":memory:")
    sid = led.start_session("t")
    for i in range(30):
        led.record(sid, "info", f"noise ntoskrnl.exe {i}", "x",
                   agent_id="other")
    led.record(sid, "info", "ntoskrnl.exe target", "nt!ExAllocatePool2",
               agent_id="me", artifact_sha="abc123")
    for q in ("ntoskrnl.exe", "nt!ExAllocatePool2", "sha:abc123", "foo-bar",
              "ntos*", "a(b", '"unbalanced'):
        led.search(q)                                 # never raises
    # agent filter applies BEFORE limit (old code: LIMIT 5 then filter -> [])
    hits = led.search("ntoskrnl.exe", agent="me", limit=5)
    assert [h["agent_id"] for h in hits] == ["me"]
    assert led.search("nt!ExAllocatePool2")[0]["source_title"] == \
        "ntoskrnl.exe target"
    assert led.search("ntoskrnl.exe", since=time.time() + 60) == []


def test_ledger_wal_busy_timeout_and_rollback(tmp_path):
    led = FindingsLedger(tmp_path / "f.db")
    mode = led._conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
    assert led._conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 1000
    # a failed write must not leave an open transaction behind
    led._conn.execute("CREATE TABLE boom(x UNIQUE)")
    led._conn.execute("INSERT INTO boom VALUES (1)")
    led._conn.commit()
    led._conn.execute("CREATE TRIGGER failer BEFORE INSERT ON tool_events "
                      "BEGIN SELECT RAISE(ABORT, 'nope'); END")
    led._conn.commit()
    assert led.event("t", "a") == ""
    assert not led._conn.in_transaction
    led.close()


# ----------------------------------------------------------- PDB cache ----

_MINI_PDB = (b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
             + (512).to_bytes(4, "little") + (1).to_bytes(4, "little")
             + (2).to_bytes(4, "little")).ljust(1024, b"\x00")


def test_pdb_name_sanitized_and_guid_validated():
    from pry import symbols as sym
    info = sym.PdbInfo(name="D:\\agent\\_work\\1\\..\\..\\evil.pdb",
                       guid="ab" * 16, age=3)
    assert info.name == "evil.pdb"
    assert info.store_rel == f"evil.pdb/{'AB' * 16}3/evil.pdb"
    assert sym.PdbInfo(name="a b<c>.pdb", guid="0" * 32, age=1).name == \
        "a_b_c_.pdb"
    with pytest.raises(sym.SymbolError):
        sym.PdbInfo(name="x.pdb", guid="../../" + "0" * 26, age=1)
    with pytest.raises(sym.SymbolError):
        sym.PdbInfo(name="..", guid="0" * 32, age=1)


def test_truncated_cached_pdb_not_trusted(tmp_path, monkeypatch):
    from pry import symbols as sym
    info = sym.PdbInfo(name="ci.pdb", guid="1" * 32, age=1)
    cache = tmp_path / "cache"
    final = cache / info.store_rel
    final.parent.mkdir(parents=True)
    final.write_bytes(_MINI_PDB[:600])               # claims 1024 bytes
    with pytest.raises(sym.SymbolError, match="truncated"):
        sym.ensure_pdb("unused", cache, allow_download=False, pdb_info=info)

    class _Resp:
        headers = {"Content-Length": str(len(_MINI_PDB))}

        def read(self):
            return _MINI_PDB

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(sym.urllib.request, "urlopen",
                        lambda req, timeout=0: _Resp())
    got = sym.ensure_pdb("unused", cache, allow_download=True,
                         servers=["http://sym.invalid"], pdb_info=info)
    assert got == final and got.read_bytes() == _MINI_PDB
    assert not list(final.parent.glob("*.tmp"))


# ------------------------------------------------------- evidence/spill ----

def test_evidence_retain_serializes_record_once(tmp_path, monkeypatch):
    from pry.mcp.evidence import store
    big = {"rows": [{"i": i, "v": "x" * 50} for i in range(2000)]}
    calls = {"n": 0}
    real = store.json.dumps

    def _counting(obj, *a, **k):
        if obj is big or (isinstance(obj, dict) and obj.get("data") is big):
            calls["n"] += 1
        return real(obj, *a, **k)

    monkeypatch.setattr(store.json, "dumps", _counting)
    led = FindingsLedger(":memory:")
    rec, block = store.retain_record(request={"action": "x"}, data=big,
                                     artifacts_root=tmp_path, ledger=led,
                                     tool="t", action="x")
    assert calls["n"] == 1, calls
    # id formula unchanged
    assert block["evidence_id"] == store.record_id(rec, {"action": "x"})
    assert store.load(block["evidence_id"], artifacts_root=tmp_path) == rec


def test_evidence_sweep_size_cap_and_ttl(tmp_path):
    from pry.mcp.evidence import store
    now = time.time()
    ids = []
    for i in range(6):
        ev = "ev_" + f"{i:032x}"
        p = store._write_blob(ev, "x" * 1000, tmp_path)
        os.utime(p, (now - (10 - i) * 86400, now - (10 - i) * 86400))
        ids.append(ev)
    removed = store.sweep(tmp_path, ttl_s=0, max_bytes=3000, now=now)
    assert removed == ids[:3]                       # oldest first
    removed = store.sweep(tmp_path, ttl_s=5.5 * 86400, max_bytes=0, now=now)
    assert removed == ids[3:5]                       # TTL (days 7, 6 old)


def test_spill_atomic_and_lru_sweep(tmp_path):
    from pry.mcp import _spill
    env = {"ok": True, "data": {"rows": [{"i": i, "pad": "y" * 40}
                                          for i in range(500)]}}
    _spill.maybe_spill(env, budget_bytes=1000, spill_dir=tmp_path)
    sha = env["artifact"]["sha256"]
    assert (tmp_path / f"{sha}.jsonl").exists()
    assert (tmp_path / f"{sha}.idx").exists()
    assert not list(tmp_path.glob("*.tmp"))
    now = time.time()
    names = []
    for i in range(4):
        h = f"{i:064x}"
        p = tmp_path / f"{h}.bin"
        p.write_bytes(b"z" * 1000)
        os.utime(p, (now - 100 + i, now - 100 + i))
        names.append(p.name)
    # LRU: reading the oldest keeps it
    _spill.read_slice(f"{0:064x}", tmp_path)
    gone = _spill.sweep_spill(tmp_path, max_bytes=3000, ttl_s=0)
    assert names[0] not in gone and names[1] in gone
    # the .jsonl and its .idx leave together
    if f"{sha}.jsonl" in gone:
        assert f"{sha}.idx" in gone


# --------------------------------------------------------- bin engine ----

def test_gadget_cache_key_includes_budget_and_running_jobs_survive(
        monkeypatch):
    from pry.mcp.tools import bin_engine as be
    built = []

    class _Idx:
        ranges, bytes_scanned, terminators, decode_attempts = [], 0, 0, 0
        scan_s, gadgets, truncated = 0.0, [], False

    fake_rop = types.SimpleNamespace(
        DEFAULT_MAX_BYTES=16, DEFAULT_BUDGET=1000,
        parse_bad_bytes=lambda s: b"", ending_selector=lambda s: None,
        build_index=lambda view, max_bytes, budget: (built.append(
            (max_bytes, budget)) or _Idx()),
        query=lambda idx, **k: [])
    import pry.analysis as _an_pkg
    monkeypatch.setitem(sys.modules, "pry.analysis.rop", fake_rop)
    # `from ...analysis import rop` prefers the package attribute once
    # the real module was imported by an earlier test
    monkeypatch.setattr(_an_pkg, "rop", fake_rop, raising=False)
    monkeypatch.setattr(be, "_GADGET_CACHE", be.OrderedDict())
    view = types.SimpleNamespace(base_va=0x1000)
    ctx = types.SimpleNamespace(cfg=types.SimpleNamespace(
        mcp_max_items=lambda: 1000))
    kw = dict(list_kw={"tool": "bin_manage", "action": "gadgets",
                       "limit": 0, "offset": 0, "fields": (),
                       "filter": "", "summary": False, "global_cap": 1000},
              target="", chain="", expected_json="", ending="",
              category="", reg="", bad_bytes="", max_len=0, unique=False,
              refresh=False)
    be._rop_dispatch(ctx, view, "gadgets", b"\xc3" * 16, 0x1000,
                     max_gadget_bytes=0, scan_budget=0, **kw)
    be._rop_dispatch(ctx, view, "gadgets", b"\xc3" * 16, 0x1000,
                     max_gadget_bytes=0, scan_budget=50_000, **kw)
    be._rop_dispatch(ctx, view, "gadgets", b"\xc3" * 16, 0x1000,
                     max_gadget_bytes=0, scan_budget=0, **kw)
    assert built == [(16, 1000), (16, 50_000)]       # 3rd call: cache hit

    monkeypatch.setattr(be, "_AJOBS", be.OrderedDict())
    monkeypatch.setattr(be, "_AJOB_CAP", 2)
    be._AJOBS["a1"] = {"status": "running"}
    be._AJOBS["a2"] = {"status": "ready"}
    be._AJOBS["a3"] = {"status": "error"}
    be._AJOBS["a4"] = {"status": "running"}
    be._prune_ajobs()
    assert list(be._AJOBS) == ["a1", "a4"]


# --------------------------------------------------------------- scans ----

def test_masked_pattern_scan_matches_reference():
    from pry.sdk.scan import pattern_scan

    def ref(data, pat, mask):
        hits = []
        for i in range(len(data) - len(pat) + 1):
            for j, b in enumerate(pat):
                m = mask[j]
                if m == "?":
                    continue
                v = data[i + j]
                if (m == "H" and (v & 0xF0) != b) or \
                        (m == "L" and (v & 0x0F) != b) or \
                        (m not in "?HL" and v != b):
                    break
            else:
                hits.append(i)
        return hits

    rng = random.Random(3)
    pool = [0, 1, 0x10, 0x11, 0x5C, 0x2E, 0x0A, 0xFF, 0x0F, 0xF0]
    for _ in range(1500):
        data = bytes(rng.choice(pool) for _ in range(rng.randint(0, 50)))
        n = rng.randint(1, 5)
        pat = bytes(rng.choice(pool) for _ in range(n))
        mask = "".join(rng.choice("x?HL") for _ in range(n))
        assert pattern_scan(data, pat, mask) == ref(data, pat, mask)


# ---------------------------------------------------------------- yara ----

def test_yara_compiles_without_includes(monkeypatch):
    from pry import yara as ymod
    seen = {}

    def _compile(**kw):
        seen.update(kw)
        return types.SimpleNamespace(match=lambda data: [])

    monkeypatch.setattr(ymod, "_yara", types.SimpleNamespace(compile=_compile))
    assert ymod.yara_scan_blob(b"abc", "rule r { condition: true }") == []
    assert seen.get("includes") is False


async def test_yara_remote_name_sanitized_and_off_loop(tmp_path, monkeypatch):
    from pry import yara as ymod

    monkeypatch.setattr(ymod, "_yara", types.SimpleNamespace(
        compile=lambda **kw: types.SimpleNamespace(match=lambda data: [])))

    class _C:
        async def file_download(self, remote, local):
            Path(local).write_bytes(b"data")
            return {}

    matches, err = await ymod.yara_scan_remote_file(
        _C(), "C:\\x\\..\\..\\..\\evil.sys", "rule r {condition: true}",
        tmp_path)
    assert err == "" and matches == []
    assert (tmp_path / "yara" / "evil.sys").exists()
    assert not list((tmp_path / "yara").glob("*.tmp"))
    assert not (tmp_path / "evil.sys").exists()


def test_ioc_json_roundtrip_smoke():
    from pry.analysis.extract import find_iocs
    rows = find_iocs(b"see http://evil.example.com/x admin@corp.example.co.uk")
    kinds = {r["kind"] for r in rows}
    assert {"url", "domain", "email"} <= kinds
    json.dumps(rows)
    assert asyncio.iscoroutinefunction(art.find_artifact_by_sha_async)
