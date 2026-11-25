// pry_comm notify + kernel enumeration: agent-side wrappers for the
// v10 notify event ring (SUBSCRIBE/READ/DISABLE/STATS) and the kernel
// object-directory / thread-list walks. Split from the core TUs (v10).
#include "pry_comm_internal.hpp"

#include <cstring>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace pry {

bool Driver::NotifySubscribe(UINT32 classes, UINT32 flags, UINT32* registered)
{
    PRY_NOTIFY_SUBSCRIBE_IN in{classes, flags};
    PRY_NOTIFY_SUBSCRIBE_OUT out{};
    if (!Call(PRY_IOCTL_NOTIFY_SUBSCRIBE, &in, sizeof(in), &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("NOTIFY_SUBSCRIBE", out.Status);
    }
    if (registered) *registered = out.Registered;
    return true;
}

bool Driver::NotifyRead(UINT32 max, std::vector<PryEventRec>& out,
                        UINT64* dropped, UINT64* lastSeq)
{
    PRY_NOTIFY_READ_IN in{max, 0};
    std::vector<BYTE> buf(sizeof(PRY_NOTIFY_READ_HDR)
                          + (size_t)PRY_EVT_RING * sizeof(PRY_EVT), 0);
    ULONG ret = 0;
    if (!Call(PRY_IOCTL_NOTIFY_READ, &in, sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<PRY_NOTIFY_READ_HDR*>(buf.data());
    if (hdr->Status != 0) {
        return FailNt("NOTIFY_READ", hdr->Status);
    }
    // v14 grew PRY_EVT by 8 bytes: an older driver's rows would be read
    // shifted by 8*i bytes. The byte count the driver returned is the tell.
    if (!RowsFit("NOTIFY_READ", ret, buf.size(), sizeof(*hdr), sizeof(PRY_EVT), hdr->Count)) {
        return false;
    }
    auto* e = reinterpret_cast<PRY_EVT*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        PryEventRec ev{};
        ev.Seq       = e[i].Seq;
        ev.TsMs      = e[i].TsMs;
        ev.Kind      = e[i].Kind;
        ev.Pid       = e[i].Pid;
        ev.ParentPid = e[i].ParentPid;
        ev.Tid       = e[i].Tid;
        ev.ImageBase = e[i].ImageBase;
        ev.ImageSize = e[i].ImageSize;
        e[i].Image[PRY_EVT_IMAGE_CCH - 1] = L'\0';
        ev.Image = e[i].Image;
        ev.Address   = e[i].Address;
        ev.Dr6       = e[i].Dr6;
        ev.BpId      = e[i].BpId;
        ev.Slot      = e[i].Slot;
        ev.Access    = e[i].Access;
        ev.Irql      = e[i].Irql;
        out.push_back(std::move(ev));
    }
    if (dropped) *dropped = hdr->Dropped;
    if (lastSeq)  *lastSeq  = hdr->LastSeq;
    return true;
}

bool Driver::NotifyDisable(UINT32* registered)
{
    // DISABLE takes no input; the driver answers with the stats layout so
    // the caller learns what was unregistered in the same round trip.
    PRY_NOTIFY_STATS_OUT out{};
    if (!Call(PRY_IOCTL_NOTIFY_DISABLE, nullptr, 0, &out, sizeof(out), nullptr)) {
        return false;
    }
    if (out.Status != 0) {
        return FailNt("NOTIFY_DISABLE", out.Status);
    }
    if (registered) *registered = out.Registered;
    return true;
}

bool Driver::NotifyStats(PryNotifyStats* out)
{
    PRY_NOTIFY_STATS_OUT o{};
    if (!Call(PRY_IOCTL_NOTIFY_STATS, nullptr, 0, &o, sizeof(o), nullptr)) {
        return false;
    }
    if (o.Status != 0) {
        return FailNt("NOTIFY_STATS", o.Status);
    }
    out->Registered  = o.Registered;
    out->ProcVariant = o.ProcVariant;
    out->BpTrapMissed = o.BpTrapMissed;
    out->Buffered    = o.Buffered;
    out->Dropped     = o.Dropped;
    out->Seq         = o.Seq;
    out->Total       = o.Total;
    return true;
}

bool Driver::ObjEnum(const std::wstring& path, UINT32 depth, UINT32 maxEntries,
                     std::vector<ObjEntryRec>& out, UINT32* required, UINT32* truncated)
{
    PRY_OBJ_ENUM_IN in{};
    size_t n = path.size();
    if (n >= PRY_OBJ_PATH_CCH) n = PRY_OBJ_PATH_CCH - 1;
    memcpy(in.Path, path.c_str(), n * sizeof(WCHAR));
    in.Depth = depth;
    in.MaxEntries = maxEntries;

    std::vector<BYTE> buf(sizeof(PRY_OBJ_HDR)
                          + (size_t)PRY_OBJ_MAX_ENTRIES * sizeof(PRY_OBJ_ENTRY), 0);
    ULONG ret = 0;
    if (!Call(PRY_IOCTL_OBJ_ENUM, &in, sizeof(in), buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<PRY_OBJ_HDR*>(buf.data());
    if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW) {
        return FailNt("OBJ_ENUM", hdr->Status);
    }
    if (!RowsFit("OBJ_ENUM", ret, buf.size(), sizeof(*hdr), sizeof(PRY_OBJ_ENTRY), hdr->Count)) {
        return false;
    }
    auto* e = reinterpret_cast<PRY_OBJ_ENTRY*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        ObjEntryRec o{};
        e[i].Name[PRY_OBJ_NAME_CCH - 1] = L'\0';
        e[i].TypeName[PRY_OBJ_NAME_CCH - 1] = L'\0';
        o.Name = e[i].Name;
        o.Type = e[i].TypeName;
        o.IsDirectory = e[i].IsDirectory;
        // body VA from the ObReferenceObjectByName walk.
        o.Address = e[i].Address;
        o.TypeIndex = e[i].TypeIndex;
        o.Source = (e[i].Source == 1) ? "walk" : "zwquery";
        out.push_back(std::move(o));
    }
    if (required)  *required  = hdr->Required;
    if (truncated) *truncated = hdr->Truncated;
    return true;
}

bool Driver::ThreadList(UINT32 pid, std::vector<ThreadRow>& out,
                        UINT32* required)
{
    PRY_THREADLIST_IN in{pid, 0};
    std::vector<BYTE> buf(sizeof(PRY_THREAD_HDR)
                          + (size_t)PRY_THREADLIST_MAX * sizeof(PRY_THREAD_ENTRY), 0);
    ULONG ret = 0;
    if (!Call(PRY_IOCTL_THREAD_LIST, &in, sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<PRY_THREAD_HDR*>(buf.data());
    if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW) {
        return FailNt("THREAD_LIST", hdr->Status);
    }
    if (!RowsFit("THREAD_LIST", ret, buf.size(), sizeof(*hdr), sizeof(PRY_THREAD_ENTRY),
                 hdr->Count)) {
        return false;
    }
    auto* e = reinterpret_cast<PRY_THREAD_ENTRY*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        ThreadRow t{};
        t.Tid          = e[i].Tid;
        t.Pid          = e[i].Pid;
        t.State        = e[i].State;
        t.WaitReason   = e[i].WaitReason;
        t.BasePriority = e[i].BasePriority;
        t.Flags        = e[i].Flags;
        t.StartVa      = e[i].StartVa;
        t.Win32StartVa = e[i].Win32StartVa;
        t.Teb          = e[i].Teb;
        out.push_back(std::move(t));
    }
    if (required) *required = hdr->Required;
    return true;
}

// v12: per-CPU IDT dump. Same hdr+rows OUT_DIRECT shape as the other
// kernel enumerations; the driver does the __sidt + KIDTENTRY64 decode.
bool Driver::IdtList(bool allCpus, std::vector<IdtRow>& out,
                     UINT64* idtBase, UINT32* idtLimit)
{
    PRY_IDT_LIST_IN in{allCpus ? 1u : 0u, 0};
    std::vector<BYTE> buf(sizeof(PRY_IDT_LIST_HDR)
                          + (size_t)PRY_IDT_MAX_ENTRIES * sizeof(PRY_IDT_ENTRY_ROW), 0);
    ULONG ret = 0;
    if (!Call(PRY_IOCTL_IDT_LIST, &in, sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    auto* hdr = reinterpret_cast<PRY_IDT_LIST_HDR*>(buf.data());
    if (hdr->Status != 0 && hdr->Status != PRY_STATUS_BUFFER_OVERFLOW) {
        return FailNt("IDT_LIST", hdr->Status);
    }
    if (!RowsFit("IDT_LIST", ret, buf.size(), sizeof(*hdr), sizeof(PRY_IDT_ENTRY_ROW),
                 hdr->Count)) {
        return false;
    }
    auto* e = reinterpret_cast<PRY_IDT_ENTRY_ROW*>(buf.data() + sizeof(*hdr));
    out.clear();
    out.reserve(hdr->Count);
    for (UINT32 i = 0; i < hdr->Count; i++) {
        IdtRow r{};
        r.Cpu       = e[i].Cpu;
        r.Vector    = e[i].Vector;
        r.HandlerVa = e[i].HandlerVa;
        r.Selector  = e[i].Selector;
        r.Ist       = e[i].Ist;
        r.Dpl       = e[i].Dpl;
        r.Type      = e[i].Type;
        r.Present   = e[i].Present;
        r.IdtBase   = e[i].IdtBase;
        out.push_back(std::move(r));
    }
    if (idtBase)  *idtBase  = hdr->IdtBase;
    if (idtLimit) *idtLimit = hdr->IdtLimit;
    return true;
}

// ------------------------------------------------- SI #21 self-protection ----
// Both verbs are METHOD_BUFFERED one-shots; the driver side lives in
// driver/src/dispatch_selfprot.c. Status is read-only; Config may install,
// tear down, or refresh depending on in.Enable.
bool Driver::SelfProtConfig(const PRY_SELFPROT_CONFIG_IN& in,
                            PRY_SELFPROT_CONFIG_OUT* out)
{
    PRY_SELFPROT_CONFIG_OUT scratch{};
    if (!Call(PRY_IOCTL_SELFPROT_CONFIG,
              const_cast<PRY_SELFPROT_CONFIG_IN*>(&in), sizeof(in),
              &scratch, sizeof(scratch), nullptr)) {
        return false;
    }
    if (scratch.Status != 0) {
        if (out) *out = scratch;
        return FailNt("SELFPROT_CONFIG", scratch.Status);
    }
    if (out) *out = scratch;
    return true;
}

bool Driver::SelfProtStatus(PRY_SELFPROT_STATUS_OUT* out)
{
    PRY_SELFPROT_STATUS_OUT scratch{};
    if (!Call(PRY_IOCTL_SELFPROT_STATUS, nullptr, 0,
              &scratch, sizeof(scratch), nullptr)) {
        return false;
    }
    if (scratch.Status != 0) {
        return FailNt("SELFPROT_STATUS", scratch.Status);
    }
    if (out) *out = scratch;
    return true;
}

// ------------------------------------------------- SI #6 handle ops ----
bool Driver::HandleDup(const PRY_HANDLE_DUP_IN& in,
                       PRY_HANDLE_DUP_OUT* out)
{
    PRY_HANDLE_DUP_OUT scratch{};
    if (!Call(PRY_IOCTL_HANDLE_DUP,
              const_cast<PRY_HANDLE_DUP_IN*>(&in), sizeof(in),
              &scratch, sizeof(scratch), nullptr)) {
        return false;
    }
    if (out) *out = scratch;
    if (scratch.Status != 0) {
        return FailNt("HANDLE_DUP", scratch.Status);
    }
    return true;
}

bool Driver::HandleCloseRemote(const PRY_HANDLE_CLOSE_IN& in,
                               PRY_HANDLE_CLOSE_OUT* out)
{
    PRY_HANDLE_CLOSE_OUT scratch{};
    if (!Call(PRY_IOCTL_HANDLE_CLOSE_REMOTE,
              const_cast<PRY_HANDLE_CLOSE_IN*>(&in), sizeof(in),
              &scratch, sizeof(scratch), nullptr)) {
        return false;
    }
    if (out) *out = scratch;
    if (scratch.Status != 0) {
        return FailNt("HANDLE_CLOSE_REMOTE", scratch.Status);
    }
    return true;
}

bool Driver::HandleCompare(const PRY_HANDLE_CMP_IN& in,
                           PRY_HANDLE_CMP_OUT* out)
{
    PRY_HANDLE_CMP_OUT scratch{};
    if (!Call(PRY_IOCTL_HANDLE_COMPARE,
              const_cast<PRY_HANDLE_CMP_IN*>(&in), sizeof(in),
              &scratch, sizeof(scratch), nullptr)) {
        return false;
    }
    if (out) *out = scratch;
    if (scratch.Status != 0) {
        return FailNt("HANDLE_COMPARE", scratch.Status);
    }
    return true;
}

// ---------------------------------------------- SI #9 kernel-stack walk ----
bool Driver::StackWalk(const PRY_STACKWALK_IN& in,
                       PRY_STACKWALK_HDR* hdr,
                       void* framesBuf, size_t framesBytes,
                       SIZE_T* bytesReturned)
{
    const size_t needed = sizeof(PRY_STACKWALK_HDR) + framesBytes;
    std::vector<BYTE> buf(needed, 0);
    ULONG ret = 0;
    if (!Call(PRY_IOCTL_STACKWALK,
              const_cast<PRY_STACKWALK_IN*>(&in), sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    if (hdr) {
        *hdr = *reinterpret_cast<PRY_STACKWALK_HDR*>(buf.data());
    }
    if (framesBuf && framesBytes) {
        size_t copy = std::min<size_t>(framesBytes,
                                        (ret > sizeof(PRY_STACKWALK_HDR))
                                            ? ret - sizeof(PRY_STACKWALK_HDR)
                                            : 0);
        if (copy) {
            memcpy(framesBuf, buf.data() + sizeof(PRY_STACKWALK_HDR), copy);
        }
    }
    if (bytesReturned) *bytesReturned = ret;
    auto* h = reinterpret_cast<PRY_STACKWALK_HDR*>(buf.data());
    if (h->Status != 0 && h->Status != (UINT32)STATUS_TIMEOUT) {
        return FailNt("STACKWALK", h->Status);
    }
    return true;
}

// ---------------------------------------------- SI #3 analyze-wait ----
bool Driver::WaitInfo(const PRY_WAIT_INFO_IN& in,
                      PRY_WAIT_INFO_HDR* hdr,
                      void* trailerBuf, size_t trailerBytes,
                      SIZE_T* bytesReturned)
{
    const size_t needed = sizeof(PRY_WAIT_INFO_HDR) + trailerBytes;
    std::vector<BYTE> buf(needed, 0);
    ULONG ret = 0;
    if (!Call(PRY_IOCTL_THREAD_WAIT_INFO,
              const_cast<PRY_WAIT_INFO_IN*>(&in), sizeof(in),
              buf.data(), (ULONG)buf.size(), &ret)) {
        return false;
    }
    if (hdr) {
        *hdr = *reinterpret_cast<PRY_WAIT_INFO_HDR*>(buf.data());
    }
    if (trailerBuf && trailerBytes) {
        size_t copy = std::min<size_t>(trailerBytes,
                                        (ret > sizeof(PRY_WAIT_INFO_HDR))
                                            ? ret - sizeof(PRY_WAIT_INFO_HDR)
                                            : 0);
        if (copy) {
            memcpy(trailerBuf, buf.data() + sizeof(PRY_WAIT_INFO_HDR), copy);
        }
    }
    if (bytesReturned) *bytesReturned = ret;
    auto* h = reinterpret_cast<PRY_WAIT_INFO_HDR*>(buf.data());
    // STATUS_NOT_SUPPORTED (0xC00000BB) is the expected pre-dyn-data
    // return — the caller sees it in hdr->Status and degrades to
    // kind='not_supported' without the whole call failing. Same for
    // STATUS_INVALID_CID (0xC000000B, vanished TID) and
    // STATUS_INVALID_PARAMETER (0xC000000D, bad input). Hex constants
    // because ntstatus.h isn't pulled by windows.h in this TU.
    const UINT32 kStatusNotSupported     = 0xC00000BBu;
    const UINT32 kStatusInvalidCid       = 0xC000000Bu;
    const UINT32 kStatusInvalidParameter = 0xC000000Du;
    if (h->Status != 0 &&
        h->Status != kStatusNotSupported &&
        h->Status != kStatusInvalidCid &&
        h->Status != kStatusInvalidParameter) {
        return FailNt("WAIT_INFO", h->Status);
    }
    return true;
}

} // namespace pry
