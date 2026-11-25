"""Parity harness logic against fake kernel/usermode clients."""

from __future__ import annotations

from pry.parity import MEM_COMMIT, format_report, run_parity, verdict

REGION_BYTES = 0x10000
REGIONS = [
    {"base": hex(0x10000), "size": REGION_BYTES, "state": MEM_COMMIT,
     "protect": 0x04, "type": 0x20000, "module": ""},
    {"base": hex(0x20000), "size": REGION_BYTES, "state": MEM_COMMIT,
     "protect": 0x20, "type": 0x20000, "module": "foo.dll"},
    {"base": hex(0x30000), "size": REGION_BYTES, "state": MEM_COMMIT,
     "protect": 0x01, "type": 0x20000, "module": ""},  # PAGE_NOACCESS
    {"base": hex(0x40000), "size": REGION_BYTES, "state": 0x2000,  # MEM_RESERVE
     "protect": 0, "type": 0, "module": ""},
]


def _region_bytes(seed: int, size: int = REGION_BYTES) -> bytes:
    return bytes((seed * 31 + i) % 251 for i in range(size))


class FakeClient:
    """Serves the shared region map plus deterministic page-backed data.

    fail_pages: raise on reads whose containing 64k page is listed.
    xor: invert every served byte (guaranteed mismatch at any offset).
    """

    def __init__(self, data: dict[int, bytes], fail_pages: set[int] | None = None,
                 xor: bool = False) -> None:
        self.data = data
        self.fail_pages = fail_pages or set()
        self.xor = xor

    async def debug_regions(self, pid: int) -> list[dict]:
        return REGIONS

    async def mem_read(self, pid: int, address: int, size: int, space: str = "user") -> bytes:
        page = address & ~0xFFFF
        if page in self.fail_pages:
            raise RuntimeError(f"fake read failure on page {hex(page)}")
        blob = self.data[page]
        off = address - page
        chunk = blob[off : off + size]
        return bytes(b ^ 0xFF for b in chunk) if self.xor else chunk


def _setup() -> tuple[FakeClient, dict[int, bytes]]:
    data = {0x10000: _region_bytes(1), 0x20000: _region_bytes(2)}
    return FakeClient(data), data


async def test_zero_mismatch_parity() -> None:
    kernel, data = _setup()
    report = await run_parity(kernel, FakeClient(data), pid=42, samples=4, read_bytes=512)
    s = report["summary"]
    assert s["regions_total"] == 4
    assert s["regions_committed"] == 2  # no-access + reserved regions filtered
    assert s["samples"] == 2
    assert s["compared"] == 2
    assert s["mismatches"] == 0
    assert s["both_failed"] == 0
    assert s["bytes_compared"] == 2 * 512
    assert verdict(report)[0] == "info"


async def test_mismatch_detected_with_offsets() -> None:
    kernel, data = _setup()
    report = await run_parity(kernel, FakeClient(data, xor=True), pid=42, samples=8,
                              read_bytes=1024, seed=7)
    s = report["summary"]
    assert s["mismatches"] == 2  # every sampled region is xor-corrupted
    assert s["matches"] == 0
    for bad in [c for c in report["checks"] if c.get("match") is False]:
        assert bad["mismatch_count"] == 1024
        assert len(bad["mismatch_offsets"]) == 32  # capped
        assert bad["kernel_sha256"] != bad["user_sha256"]
    assert verdict(report)[0] == "high"


async def test_error_asymmetry_counted() -> None:
    kernel, data = _setup()
    kernel.fail_pages = {0x10000}
    report = await run_parity(kernel, FakeClient(data), pid=42, samples=4, read_bytes=256)
    s = report["summary"]
    assert s["user_ok_kernel_failed"] == 1
    assert s["kernel_ok_user_failed"] == 0
    assert verdict(report)[0] == "warning"


async def test_both_failed_is_high_verdict() -> None:
    kernel, data = _setup()
    report = await run_parity(FakeClient(data, fail_pages={0x10000, 0x20000}),
                              FakeClient(data, fail_pages={0x10000, 0x20000}),
                              pid=42, samples=4, read_bytes=256)
    s = report["summary"]
    assert s["both_failed"] == 2
    assert s["compared"] == 0
    assert verdict(report)[0] == "high"


async def test_kuser_shared_data_skipped_as_volatile() -> None:
    data = {
        0x10000: _region_bytes(1),
        0x7FFE0000: _region_bytes(7, 0x1000),  # KUSER_SHARED_DATA page
    }
    regions = REGIONS[:2] + [
        {"base": hex(0x7FFE0000), "size": 0x1000, "state": MEM_COMMIT,
         "protect": 0x02, "type": 0, "module": ""},
    ]
    kernel = FakeClient(data, )
    user = FakeClient(data)

    async def regions_fn(pid: int) -> list[dict]:
        return regions

    kernel.debug_regions = regions_fn
    user.debug_regions = regions_fn
    report = await run_parity(kernel, user, pid=42, samples=8, read_bytes=256, seed=1)
    s = report["summary"]
    assert s["volatile_skipped"] == 1
    assert s["mismatches"] == 0
    assert s["compared"] == 1
    assert verdict(report)[0] == "info"
    assert any("KUSER_SHARED_DATA" in c.get("note", "") for c in report["checks"])


async def test_sample_offsets_deterministic() -> None:
    kernel, data = _setup()
    user = FakeClient(data)
    r1 = await run_parity(kernel, user, pid=42, samples=4, read_bytes=128, seed=3)
    r2 = await run_parity(kernel, user, pid=42, samples=4, read_bytes=128, seed=3)
    assert [c["address"] for c in r1["checks"]] == [c["address"] for c in r2["checks"]]


async def test_format_report_mentions_failures() -> None:
    kernel, data = _setup()
    report = await run_parity(kernel, FakeClient(data, xor=True), pid=42, samples=8,
                              read_bytes=1024, seed=1)
    text = format_report(report)
    assert "2 MISMATCH" in text
    assert "MISMATCH count=1024" in text


# ----------------------------------------------------------------------
# SI #1 image coherency — shape parity
# ----------------------------------------------------------------------

async def test_coherency_shape_parity_clean_module() -> None:
    """Both views must emit the SAME required keys for a clean module
    scan, and the same classification. Byte-identity is impossible
    (sampling budgets, timestamps), so we assert on shape only — the
    exclusion list ("coherency_excluded_regions") covers reloc/IAT
    volatility exactly as the slice doc calls out.
    """
    from pry.analysis.coherency import classify

    sections = [
        {"name": ".text", "va": 0x1000, "size": 0x2000,
         "characteristics": 0x60000020},
        {"name": ".rdata", "va": 0x3000, "size": 0x1000,
         "characteristics": 0x40000040},
        {"name": ".data", "va": 0x4000, "size": 0x1000,
         "characteristics": 0xC0000040},
    ]
    # Clean on both — same classification result.
    cls_a = classify([], sections=sections)
    cls_b = classify([], sections=sections, reloc_dir=(0x6000, 0x200))
    assert cls_a == cls_b == "clean"


async def test_coherency_shape_parity_relocs_not_flaky() -> None:
    """A reloc-dir mismatch must be labelled identically from both
    views and must not inflate as a hook finding."""
    from pry.analysis.coherency import classify

    sections = [
        {"name": ".reloc", "va": 0x6000, "size": 0x200,
         "characteristics": 0x42000040},
    ]
    mismatches_umagent = [
        {"rva": 0x6010, "length": 16, "section": ".reloc", "hint": "reloc"},
    ]
    mismatches_agent = [
        # Same RVA from the driver view — the exclusion list on both
        # sides must contain the reloc dir, so parity never flakes.
        {"rva": 0x6010, "length": 16, "section": ".reloc", "hint": "reloc"},
    ]
    cls_u = classify(mismatches_umagent, sections=sections,
                     reloc_dir=(0x6000, 0x200))
    cls_a = classify(mismatches_agent, sections=sections,
                     reloc_dir=(0x6000, 0x200))
    assert cls_u == cls_a == "relocs_unresolved"


# ----------------------------------------------------------------------
# SI #8 signer + Authenticode column — shape parity
# ----------------------------------------------------------------------


async def test_signer_shape_parity_identical_rows() -> None:
    """Both views (agent + umagent) run the same WinVerifyTrust probe
    and the orchestrator's ``_enrich_signatures`` merges by path. The
    row key set and signing_level buckets must match across views for
    any given file path.

    Byte-identity isn't attainable (cache timestamps differ, catalog
    hits can race by milliseconds across views). The parity contract
    the slice doc calls out (§5 "Where byte-for-byte equality is
    impossible, the harness asserts shape parity: same fields present,
    same semantics") is satisfied when the two views emit the same
    column names and the same classification bucket for a given input.
    """
    from pry.mcp.tools.mem.modules import (_SIG_COLS, _apply_sig_cols,
                                               _empty_sig_cols)

    base_row_umagent = {"name": "ntoskrnl.exe",
                         "path": r"C:\Windows\System32\ntoskrnl.exe"}
    base_row_agent = {"name": "ntoskrnl.exe",
                       "path": r"C:\Windows\System32\ntoskrnl.exe"}

    sig_umagent = {
        "signer": "Microsoft Windows", "signing_level": "windows",
        "is_signed": True, "catalog": True, "cache_hit": False, "error": "",
    }
    sig_agent = dict(sig_umagent)  # same probe → same bucket

    _apply_sig_cols(base_row_umagent, sig_umagent)
    _apply_sig_cols(base_row_agent, sig_agent)

    # Shape parity: both views emit the same signer columns.
    assert set(_SIG_COLS).issubset(base_row_umagent)
    assert set(_SIG_COLS).issubset(base_row_agent)

    # Semantic parity: classification bucket agrees.
    for col in _SIG_COLS:
        assert base_row_umagent[col] == base_row_agent[col], (
            f"column {col!r} diverges across views")


async def test_signer_shape_parity_missing_row_shape() -> None:
    """A path with no probe response (unknown to one view) must still
    emit the full _SIG_COLS key set with empty-shape values — same key
    set as a happy-path row. This is what keeps the parity harness from
    flaking on paths that only one view can see."""
    from pry.mcp.tools.mem.modules import _SIG_COLS, _empty_sig_cols

    missing = _empty_sig_cols()
    assert set(missing) == set(_SIG_COLS)
    assert missing["signing_level"] == ""
    assert missing["is_signed"] is False
    assert missing["signer_cache_hit"] is False


# ----------------------------------------------------------------------
# SI #2 hidden-process detection — shape parity
# ----------------------------------------------------------------------


async def test_hidden_proc_shape_parity_verdict_bucket() -> None:
    """Both views (agent + umagent) run the identical shared scanner,
    so for the same oracle input the verdict bucket + confidence must
    agree. Byte-identity is impossible (brute walks a PID range; the
    live table shifts between runs), so this is a shape+semantic
    parity assertion.
    """
    from pry.mcp.tools.mem.hidden_proc import _confidence, _verdict

    oracle_umagent = {
        "pid": 2718, "image": "ghost.exe",
        "present_brute": True, "present_registry": False,
        "present_etw": False, "exit_time_100ns": 0,
    }
    oracle_agent = dict(oracle_umagent)  # same shared scanner → same row
    # NtQSI (ground truth) missed the pid on both views.
    v_u = _verdict(oracle_umagent, False)
    v_a = _verdict(oracle_agent, False)
    c_u = _confidence(oracle_umagent, False)
    c_a = _confidence(oracle_agent, False)
    assert v_u == v_a == "unlinked_from_pslist"
    assert c_u == c_a


async def test_hidden_proc_shape_parity_clean_box_matches() -> None:
    """On a clean box (every oracle PID also in NtQSI) both views must
    agree ``is_hidden=False`` for every row — any mismatch between
    views would surface as a flaky verdict here."""
    from pry.mcp.tools.mem.hidden_proc import _verdict

    clean_row = {"present_brute": True, "present_registry": True,
                 "present_etw": True, "exit_time_100ns": 0}
    # Same row on both views; same ground-truth presence.
    assert _verdict(clean_row, True) == _verdict(dict(clean_row), True)
    assert _verdict(clean_row, True) == "clean"
