"""Well-known MSR / CPUID metadata for ``cpu_manage`` pretty-printing.

PR#6 T3.2 (2026-10). Kept in its own module so the MCP tool can import
cheaply and tests can introspect the catalog without spinning the server.

The MSR table is intentionally short — the kit's reach-for list for
firmware/hv debugging on the lab AMD box. CPUID leaf metadata focuses on
the "is this a VM / can we SVM?" slice that drives the hv-load decision.
"""

from __future__ import annotations

# MSR number -> symbolic name. The orchestrator pretty-prints every row
# whose ``msr`` matches an entry here; unknown MSRs still return bytes
# untouched, just without a name.
KNOWN_MSRS: dict[int, str] = {
    # Intel VMX / common
    0x0000003A: "IA32_FEATURE_CONTROL",
    0x00000174: "IA32_SYSENTER_CS",
    0x00000175: "IA32_SYSENTER_ESP",
    0x00000176: "IA32_SYSENTER_EIP",
    0x000000FE: "MTRRCAP",
    0x00000480: "IA32_VMX_BASIC",
    0x00000481: "IA32_VMX_PINBASED_CTLS",
    0x00000482: "IA32_VMX_PROCBASED_CTLS",
    0x00000483: "IA32_VMX_EXIT_CTLS",
    0x00000484: "IA32_VMX_ENTRY_CTLS",
    0x00000485: "IA32_VMX_MISC",
    # Common x86 / x64 LME / NX plumbing (EFER lives at the same address on
    # Intel and AMD).
    0xC0000080: "IA32_EFER",
    0xC0000081: "IA32_STAR",
    0xC0000082: "IA32_LSTAR",
    0xC0000083: "IA32_CSTAR",
    0xC0000084: "IA32_FMASK",
    0xC0000100: "IA32_FS_BASE",
    0xC0000101: "IA32_GS_BASE",
    0xC0000102: "IA32_KERNEL_GS_BASE",
    # AMD SVM
    0xC0010114: "VM_CR",
    0xC0010115: "IGNNE",
    0xC0010117: "VM_HSAVE_PA",
    0xC0010140: "OSVW_ID_LENGTH",
    0xC0010141: "OSVW_STATUS",
}


# Convenience inverse: name (uppercase, underscore) -> int. Lets callers
# say ``msr="VM_CR"`` without memorising hex.
MSR_BY_NAME: dict[str, int] = {name: addr for addr, name in KNOWN_MSRS.items()}


def msr_name(msr: int) -> str:
    """Return the symbolic name for ``msr`` or ``""`` when unknown."""
    return KNOWN_MSRS.get(int(msr) & 0xFFFFFFFF, "")


def msr_resolve(msr: int | str) -> int:
    """Accept a raw int, hex string (``'0xC0010114'``), or well-known name
    (``'VM_CR'``) and return the integer MSR address.

    Raises ``ValueError`` on an unparseable string so the MCP tool can
    convert it into a clean ``kind='bad_arg'`` response.
    """
    if isinstance(msr, int):
        return msr & 0xFFFFFFFF
    s = str(msr).strip()
    if not s:
        raise ValueError("msr: empty value")
    # Well-known name — allow lower-case for ergonomics
    hit = MSR_BY_NAME.get(s.upper())
    if hit is not None:
        return hit
    # Hex or decimal — accept both since RDMSR docs use both forms
    try:
        if s.lower().startswith("0x"):
            return int(s, 16) & 0xFFFFFFFF
        if any(c in "abcdefABCDEF" for c in s):
            return int(s, 16) & 0xFFFFFFFF
        return int(s, 0) & 0xFFFFFFFF
    except Exception as exc:
        raise ValueError(f"msr: not parseable as int/hex/known name: {s!r}") from exc


# ---------------------------------------------------------------- CPUID ----

def decode_cpuid(leaf: int, subleaf: int, eax: int, ebx: int, ecx: int,
                 edx: int) -> dict[str, object]:
    """Decode well-known CPUID leaves into named flag dicts.

    Covers the "is this a VM / can we SVM?" questions that drive the
    hv-load decision (leaf 1 ECX bit 2 Intel VMX, 0x80000001 ECX bit 2
    AMD SVM, leaf 1 ECX bit 31 hypervisor present) plus the vendor
    strings at leaf 0 and leaf 0x40000000.
    """
    out: dict[str, object] = {}
    L = int(leaf) & 0xFFFFFFFF

    if L == 0:
        # Vendor string from EBX, EDX, ECX (in that order on x86).
        out["vendor"] = _three_regs_ascii(ebx, edx, ecx)
        out["max_basic_leaf"] = int(eax)
    elif L == 1:
        # Feature flags we care about. Full decode would be hundreds of
        # bits; the "firmware / hv debug" slice is small.
        out["hypervisor_present"] = bool(ecx & (1 << 31))
        out["vmx_available"] = bool(ecx & (1 << 5))     # Intel VMX
        out["smx_available"] = bool(ecx & (1 << 6))
        out["xsave"] = bool(ecx & (1 << 26))
        out["osxsave"] = bool(ecx & (1 << 27))
        out["avx"] = bool(ecx & (1 << 28))
        # Standard EDX feature bits — tiny slice.
        out["sse"] = bool(edx & (1 << 25))
        out["sse2"] = bool(edx & (1 << 26))
    elif L == 0x80000001:
        # AMD SVM lives here (ECX bit 2 per APM volume 3).
        out["svm_available"] = bool(ecx & (1 << 2))
        out["lahf_lm"] = bool(ecx & (1 << 0))
    elif L == 0x40000000:
        # Hypervisor leaf — vendor string in EBX, ECX, EDX. Empty / zero
        # when leaf 1 bit 31 is clear.
        out["hypervisor_vendor"] = _three_regs_ascii(ebx, ecx, edx)
        out["max_hv_leaf"] = int(eax)
    elif 0x80000002 <= L <= 0x80000004:
        # Processor brand-string triplet (EAX, EBX, ECX, EDX each leaf).
        out["brand_part"] = _four_regs_ascii(eax, ebx, ecx, edx)

    return out


def _three_regs_ascii(a: int, b: int, c: int) -> str:
    return _reg_ascii(a) + _reg_ascii(b) + _reg_ascii(c)


def _four_regs_ascii(a: int, b: int, c: int, d: int) -> str:
    return (_reg_ascii(a) + _reg_ascii(b)
            + _reg_ascii(c) + _reg_ascii(d))


def _reg_ascii(v: int) -> str:
    """Little-endian 4-byte ASCII slice from a 32-bit register value,
    with NULs stripped. CPUID vendor strings are packed this way."""
    v &= 0xFFFFFFFF
    b = bytes([v & 0xFF, (v >> 8) & 0xFF,
               (v >> 16) & 0xFF, (v >> 24) & 0xFF])
    return b.rstrip(b"\x00").decode("ascii", errors="replace")
