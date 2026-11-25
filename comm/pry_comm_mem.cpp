// pry_comm memory operations: read/write across User/Kernel/Physical,
// user-mode alloc/free/protect, kernel pool alloc/free, and the module +
// process listings. Split from pry_comm.cpp (Phase 7c).
#include "pry_comm_internal.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace pry {

bool Driver::MemRead(Space space, UINT32 pid, UINT64 addr, void* buf, SIZE_T len, SIZE_T* got, UINT32 flags)
{
    PRY_MEM_REQ req{pid, addr, len, flags, 0};
    ULONG ret = 0;
    if (!Call(IoctlFor(space, PRY_IOCTL_USER_MEM_READ, PRY_IOCTL_KERNEL_MEM_READ, PRY_IOCTL_PHYS_MEM_READ),
              &req, sizeof(req), buf, (ULONG)len, &ret)) {
        return false;
    }
    // v6: driver's *Done propagates through DeviceIoControl's bytesReturned
    // (WdfRequestCompleteWithInformation). The driver completes a
    // partial read as STATUS_SUCCESS with a short byte count — a warning
    // NTSTATUS (STATUS_PARTIAL_COPY) fails DeviceIoControl outright and
    // the prefix never arrives. ok=true + got<len signals a partial read
    // to the caller. Before v6 we clobbered got=len and callers couldn't
    // tell.
    if (got) {
        *got = ret ? (SIZE_T)ret : len;
    }
    return true;
}

bool Driver::MemWrite(Space space, UINT32 pid, UINT64 addr, const void* buf, SIZE_T len, SIZE_T* written,
                      UINT32 flags, UINT64 cr3, UINT32 flags2, UINT8* writePath)
{
    if (writePath) {
        *writePath = PRY_MEM_WRITE_PATH_UNKNOWN;
    }
    ULONG ioctl = IoctlFor(space, PRY_IOCTL_USER_MEM_WRITE, PRY_IOCTL_KERNEL_MEM_WRITE,
                           PRY_IOCTL_PHYS_MEM_WRITE);
    // v12 wire shape decision. The extended header is ONLY safe when the
    // driver is v12+ — a v11 driver parses the first 32 bytes as
    // PRY_MEM_REQ and would write the ext tail (Cr3/Flags2) as payload.
    // abiVersion_ is cached by Ping(); when a caller actually needs a v12
    // feature (cr3/flags2) and we haven't probed yet, ping once now so the
    // refusal is explicit instead of a silent legacy downgrade.
    bool wantExt = (cr3 != 0) || (flags2 != 0);
    if (abiVersion_ == 0 && wantExt) {
        PingInfo p{};
        if (Ping(&p)) {
            abiVersion_ = p.AbiVersion;
        }
    }
    if (abiVersion_ >= 12) {
        PRY_MEM_WRITE_IN req{};
        req.Pid = pid;
        req.Address = addr;
        req.Size = len;
        req.Flags = flags;
        req.ExtLayout = PRY_MEM_WRITE_EXT_MAGIC;
        req.Cr3 = cr3;
        req.Flags2 = flags2;
        std::vector<BYTE> combined(sizeof(req) + len, 0);
        memcpy(combined.data(), &req, sizeof(req));
        if (len) {
            memcpy(combined.data() + sizeof(req), buf, len);
        }
        PRY_MEM_WRITE_OUT out{};
        ULONG ret = 0;
        if (!Call(ioctl, combined.data(), (ULONG)combined.size(), &out, sizeof(out), &ret)) {
            return false;
        }
        if (ret < sizeof(out)) {
            // v12 driver must answer with the full out record; anything
            // shorter means a shaped-input mismatch (defensive — treat as
            // transport failure rather than trusting a partial parse).
            return FailNt("MEM_WRITE short out", PRY_STATUS_INFO_LENGTH_MISMATCH);
        }
        if (writePath) {
            *writePath = out.WritePath;
        }
        if (out.Status != 0) {
            if (written) {
                *written = (SIZE_T)out.Done;
            }
            return FailNt("MEM_WRITE", out.Status);
        }
        if (written) {
            *written = (SIZE_T)out.Done;
        }
        return true;
    }
    if (wantExt) {
        // Caller asked for cr3/strict on a pre-v12 driver. Refusing here
        // matters for STRICT_VA in particular: a legacy send would run the
        // remap fallback while the caller believes strictness held.
        return FailNt("MEM_WRITE ext (cr3/flags2 requires driver ABI >= 12)",
                      PRY_STATUS_NOT_SUPPORTED);
    }
    // METHOD_BUFFERED combined layout: [PRY_MEM_REQ header][payload...]
    // no out-buffer: the driver-side NTSTATUS surfaces via DeviceIoControl
    PRY_MEM_REQ req{pid, addr, len, flags, 0};
    std::vector<BYTE> combined(sizeof(req) + len, 0);
    memcpy(combined.data(), &req, sizeof(req));
    if (len) {
        memcpy(combined.data() + sizeof(req), buf, len);
    }
    if (!Call(ioctl, combined.data(), (ULONG)combined.size(), nullptr, 0, nullptr)) {
        return false;
    }
    if (written) {
        *written = len;
    }
    return true;
}
bool Driver::UserAlloc(UINT32 pid, UINT64 size, UINT32 protect, UINT64* addr)
{
    PRY_USER_ALLOC_IN in{pid, size, protect, 0};
    PRY_USER_ALLOC_OUT out{};
    if (!Call(PRY_IOCTL_USER_ALLOC, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("USER_ALLOC", out.Status);
    }
    *addr = out.Address;
    return true;
}

bool Driver::UserFree(UINT32 pid, UINT64 addr)
{
    PRY_USER_FREE_IN in{pid, addr};
    PRY_USER_FREE_OUT out{};
    if (!Call(PRY_IOCTL_USER_FREE, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("USER_FREE", out.Status);
    }
    return true;
}

bool Driver::UserProtect(UINT32 pid, UINT64 addr, UINT64 size, UINT32 protect, UINT32* oldProtect)
{
    PRY_USER_PROTECT_IN in{pid, addr, size, protect, 0};
    PRY_USER_PROTECT_OUT out{};
    if (!Call(PRY_IOCTL_USER_PROTECT, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("USER_PROTECT", out.Status);
    }
    *oldProtect = out.OldProtect;
    return true;
}

bool Driver::KmemAlloc(UINT64 size, UINT64* addr)
{
    PRY_KMEM_ALLOC_IN in{size};
    PRY_KMEM_ALLOC_OUT out{};
    if (!Call(PRY_IOCTL_KMEM_ALLOC, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("KMEM_ALLOC", out.Status);
    }
    *addr = out.Address;
    return true;
}

bool Driver::KmemFree(UINT64 addr)
{
    PRY_KMEM_FREE_IN in{addr};
    PRY_KMEM_FREE_OUT out{};
    if (!Call(PRY_IOCTL_KMEM_FREE, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("KMEM_FREE", out.Status);
    }
    return true;
}

bool Driver::UserModules(UINT32 pid, std::vector<ModuleEntry>& out, bool wow64)
{
    UINT32 capacity = 32;
    std::vector<BYTE> buf;
    for (;;) {
        PRY_MODULES_IN in{pid, capacity, 0, wow64 ? PRY_MOD_FLAG_WOW64 : 0u, 0};
        buf.assign(sizeof(PRY_MODULES_HDR) + (size_t)capacity * sizeof(PRY_MODULE_ENTRY), 0);
        ULONG ret = 0;
        if (!Call(PRY_IOCTL_USER_MODULES, &in, sizeof(in), buf.data(), (ULONG)buf.size(), &ret)) {
            return false;
        }
        auto* hdr = reinterpret_cast<PRY_MODULES_HDR*>(buf.data());
        if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW &&
            hdr->Status != PRY_STATUS_PARTIAL_COPY) {
            return FailNt(wow64 ? "USER_MODULES(wow64)" : "USER_MODULES", hdr->Status);
        }
        if (hdr->Status == PRY_STATUS_BUFFER_OVERFLOW && hdr->Required > capacity) {
            if (hdr->Required > PRY_COMM_MAX_ROWS) {
                return FailNt("MODULES Required over cap", PRY_STATUS_INFO_LENGTH_MISMATCH);
            }
            capacity = hdr->Required;
            continue;
        }
        if (!RowsFit("MODULES", ret, buf.size(), sizeof(PRY_MODULES_HDR),
                     sizeof(PRY_MODULE_ENTRY), hdr->Count)) {
            return false;
        }
        auto* e = reinterpret_cast<PRY_MODULE_ENTRY*>(buf.data() + sizeof(PRY_MODULES_HDR));
        for (UINT32 i = 0; i < hdr->Count; i++) {
            e[i].Name[PRY_MOD_NAME_CCH - 1] = L'\0';
            e[i].Path[PRY_MOD_PATH_CCH - 1] = L'\0';
            out.push_back({e[i].Base, e[i].Size, std::wstring(e[i].Name), std::wstring(e[i].Path)});
        }
        return true;
    }
}

bool Driver::KernelModules(std::vector<ModuleEntry>& out)
{
    UINT32 capacity = 128;
    std::vector<BYTE> buf;
    for (;;) {
        PRY_MODULES_IN in{0, capacity, 1};
        buf.assign(sizeof(PRY_MODULES_HDR) + (size_t)capacity * sizeof(PRY_MODULE_ENTRY), 0);
        ULONG ret = 0;
        if (!Call(PRY_IOCTL_KERNEL_MODULES, &in, sizeof(in), buf.data(), (ULONG)buf.size(), &ret)) {
            return false;
        }
        auto* hdr = reinterpret_cast<PRY_MODULES_HDR*>(buf.data());
        if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW) {
            return FailNt("KERNEL_MODULES", hdr->Status);
        }
        if (hdr->Status == PRY_STATUS_BUFFER_OVERFLOW && hdr->Required > capacity) {
            if (hdr->Required > PRY_COMM_MAX_ROWS) {
                return FailNt("MODULES Required over cap", PRY_STATUS_INFO_LENGTH_MISMATCH);
            }
            capacity = hdr->Required;
            continue;
        }
        if (!RowsFit("MODULES", ret, buf.size(), sizeof(PRY_MODULES_HDR),
                     sizeof(PRY_MODULE_ENTRY), hdr->Count)) {
            return false;
        }
        auto* e = reinterpret_cast<PRY_MODULE_ENTRY*>(buf.data() + sizeof(PRY_MODULES_HDR));
        for (UINT32 i = 0; i < hdr->Count; i++) {
            e[i].Name[PRY_MOD_NAME_CCH - 1] = L'\0';
            e[i].Path[PRY_MOD_PATH_CCH - 1] = L'\0';
            out.push_back({e[i].Base, e[i].Size, std::wstring(e[i].Name), std::wstring(e[i].Path)});
        }
        return true;
    }
}

bool Driver::ProcessList(std::vector<ProcessEntry>& out)
{
    UINT32 capacity = 256;
    std::vector<BYTE> buf;
    for (;;) {
        buf.assign(sizeof(PRY_PROC_LIST_HDR) + (size_t)capacity * sizeof(PRY_PROC_ENTRY), 0);
        ULONG ret = 0;
        if (!Call(PRY_IOCTL_PROCESS_LIST, nullptr, 0, buf.data(), (ULONG)buf.size(), &ret)) {
            return false;
        }
        auto* hdr = reinterpret_cast<PRY_PROC_LIST_HDR*>(buf.data());
        if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW) {
            return FailNt("PROCESS_LIST", hdr->Status);
        }
        if (hdr->Status == PRY_STATUS_BUFFER_OVERFLOW && hdr->Required > capacity) {
            if (hdr->Required > PRY_COMM_MAX_ROWS) {
                return FailNt("PROCESS_LIST Required over cap", PRY_STATUS_INFO_LENGTH_MISMATCH);
            }
            capacity = hdr->Required;
            continue;
        }
        if (!RowsFit("PROCESS_LIST", ret, buf.size(), sizeof(PRY_PROC_LIST_HDR),
                     sizeof(PRY_PROC_ENTRY), hdr->Count)) {
            return false;
        }
        auto* e = reinterpret_cast<PRY_PROC_ENTRY*>(buf.data() + sizeof(PRY_PROC_LIST_HDR));
        for (UINT32 i = 0; i < hdr->Count; i++) {
            e[i].ImageName[_countof(e[i].ImageName) - 1] = L'\0';
            out.push_back({e[i].Pid, e[i].ParentPid, std::wstring(e[i].ImageName)});
        }
        return true;
    }
}

} // namespace pry
