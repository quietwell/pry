// pry_comm CPU reader: agent-side wrappers for the PR#6 T3.2 MSR +
// CPUID driver IOCTLs. Fixed-size (PRY_CPU_MAX_CORES) input and output
// buffers — no multi-call pagination needed for the per-core walk.
#include "pry_comm_internal.hpp"

#include <cstring>
#include <cstdint>
#include <vector>

namespace pry {

static void FillCoreList(const std::vector<UINT32>& cores, bool allCores,
                         UINT32* outCount, UINT32* outAll,
                         UINT32 outArr[PRY_CPU_MAX_CORES])
{
    for (size_t i = 0; i < PRY_CPU_MAX_CORES; i++) {
        outArr[i] = 0;
    }
    if (allCores) {
        *outAll = 1;
        *outCount = 0;
        return;
    }
    *outAll = 0;
    UINT32 n = 0;
    for (UINT32 c : cores) {
        if (n >= PRY_CPU_MAX_CORES) break;
        outArr[n++] = c;
    }
    *outCount = n;
}

bool Driver::MsrRead(UINT32 msr, const std::vector<UINT32>& cores, bool allCores,
                     std::vector<MsrRow>& out)
{
    PRY_MSR_READ_IN in{};
    in.Msr = msr;
    FillCoreList(cores, allCores, &in.CoreCount, &in.AllCores, in.Cores);

    std::vector<BYTE> buf(sizeof(PRY_MSR_READ_HDR)
                          + (size_t)PRY_CPU_MAX_CORES * sizeof(PRY_MSR_VALUE), 0);
    ULONG ret = 0;
    if (!Call(PRY_IOCTL_MSR_READ, &in, sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<PRY_MSR_READ_HDR*>(buf.data());
    if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW) {
        return FailNt("MSR_READ", hdr->Status);
    }
    if (!RowsFit("MSR_READ", ret, buf.size(), sizeof(*hdr), sizeof(PRY_MSR_VALUE), hdr->Count)) {
        return false;
    }
    auto* e = reinterpret_cast<PRY_MSR_VALUE*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        MsrRow r{};
        r.Core = e[i].Core;
        r.NtStatus = e[i].NtStatus;
        r.Value = e[i].Value;
        out.push_back(r);
    }
    return true;
}

bool Driver::CpuidRead(UINT32 leaf, UINT32 subleaf, const std::vector<UINT32>& cores,
                       bool allCores, std::vector<CpuidRow>& out)
{
    PRY_CPUID_IN in{};
    in.Leaf = leaf;
    in.Subleaf = subleaf;
    FillCoreList(cores, allCores, &in.CoreCount, &in.AllCores, in.Cores);

    std::vector<BYTE> buf(sizeof(PRY_CPUID_HDR)
                          + (size_t)PRY_CPU_MAX_CORES * sizeof(PRY_CPUID_VALUE), 0);
    ULONG ret = 0;
    if (!Call(PRY_IOCTL_CPUID_READ, &in, sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<PRY_CPUID_HDR*>(buf.data());
    if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW) {
        return FailNt("CPUID_READ", hdr->Status);
    }
    if (!RowsFit("CPUID_READ", ret, buf.size(), sizeof(*hdr), sizeof(PRY_CPUID_VALUE),
                 hdr->Count)) {
        return false;
    }
    auto* e = reinterpret_cast<PRY_CPUID_VALUE*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        CpuidRow r{};
        r.Core = e[i].Core;
        r.Eax = e[i].Eax;
        r.Ebx = e[i].Ebx;
        r.Ecx = e[i].Ecx;
        r.Edx = e[i].Edx;
        out.push_back(r);
    }
    return true;
}

} // namespace pry
