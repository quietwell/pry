// pry_comm breakpoints: SW (INT3 patch), HW (DR0-DR3 per-thread), listing.
// Split from pry_comm.cpp (Phase 7c).
#include "pry_comm_internal.hpp"

#include <cstddef>
#include <vector>

namespace pry {

bool Driver::BpSwSet(UINT32 pid, UINT64 addr, UINT32* id, UCHAR* origByte)
{
    PRY_BP_SW_SET_IN in{pid, addr};
    PRY_BP_SW_SET_OUT out{};
    if (!Call(PRY_IOCTL_BP_SW_SET, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("BP_SW_SET", out.Status);
    }
    *id = out.Id;
    *origByte = out.OrigByte;
    return true;
}

bool Driver::BpSwClear(UINT32 pid, UINT64 addr, UINT32 id)
{
    PRY_BP_SW_CLEAR_IN in{pid, addr, id, 0};
    PRY_USER_FREE_OUT out{};
    if (!Call(PRY_IOCTL_BP_SW_CLEAR, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("BP_SW_CLEAR", out.Status);
    }
    return true;
}

bool Driver::BpHwSet(UINT32 pid, UINT64 tid, UINT64 addr, UINT32 slot, UINT32 len, UINT32 access,
                     UINT32* id, UINT32* patched, UINT32 flags)
{
    PRY_BP_HW_SET_IN in{pid, tid, addr, slot, len, access, flags};
    PRY_BP_HW_SET_OUT out{};
    if (!Call(PRY_IOCTL_BP_HW_SET, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("BP_HW_SET", out.Status);
    }
    *id = out.Id;
    *patched = out.ThreadsPatched;
    return true;
}

bool Driver::BpHwClear(UINT32 pid, UINT64 tid, UINT32 slot, UINT32* patched)
{
    PRY_BP_HW_CLEAR_IN in{pid, tid, slot, 0};
    PRY_BP_HW_CLEAR_OUT out{};
    if (!Call(PRY_IOCTL_BP_HW_CLEAR, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("BP_HW_CLEAR", out.Status);
    }
    *patched = out.ThreadsPatched;
    return true;
}

bool Driver::BpList(std::vector<BpRecord>& out)
{
    UINT32 capacity = PRY_MAX_BP;
    for (;;) {
        std::vector<BYTE> buf(sizeof(PRY_BP_LIST_HDR) + (size_t)capacity * sizeof(PRY_BP_ENTRY), 0);
        ULONG ret = 0;
        if (!Call(PRY_IOCTL_BP_LIST, nullptr, 0, buf.data(), (ULONG)buf.size(), &ret)) {
            return false;
        }
        auto* hdr = reinterpret_cast<PRY_BP_LIST_HDR*>(buf.data());
        if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW) {
            return FailNt("BP_LIST", hdr->Status);
        }
        if (hdr->Status == PRY_STATUS_BUFFER_OVERFLOW && hdr->Required > capacity) {
            if (hdr->Required > PRY_COMM_MAX_ROWS) {
                return FailNt("BP_LIST Required over cap", PRY_STATUS_INFO_LENGTH_MISMATCH);
            }
            capacity = hdr->Required;
            continue;
        }
        if (!RowsFit("BP_LIST", ret, buf.size(), sizeof(PRY_BP_LIST_HDR), sizeof(PRY_BP_ENTRY),
                     hdr->Count)) {
            return false;
        }
        auto* e = reinterpret_cast<PRY_BP_ENTRY*>(buf.data() + sizeof(PRY_BP_LIST_HDR));
        for (UINT32 i = 0; i < hdr->Count; i++) {
            out.push_back({e[i].Id, e[i].Kind, e[i].Pid, e[i].Tid, e[i].Slot,
                           e[i].Length, e[i].Access, e[i].Enabled, e[i].Address, e[i].OrigByte});
        }
        return true;
    }
}

} // namespace pry
