// agent/src/etw/etw_consumer.cpp — SI #10 ETW consumer + SPSC ring.
//
// Producer (ETW EventRecordCallback) runs on ProcessTrace's dedicated
// worker thread and is non-blocking; consumer drains in bulk from
// gRPC call threads. Overflow policy is overwrite-oldest with a
// monotonic drop counter — same shape as the driver notify ring and
// as the ETW buffer-loss accounting (EventsLost).
//
// All event decoding (TdhGetEventInformation + TdhGetProperty) runs
// here, on the producer side, so Python never sees the per-event cost.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>   // must come before <windows.h> for ws2ipdef types
#include <ws2ipdef.h>
#include <in6addr.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include "etw_consumer.hpp"
#include "etw_session.hpp"
#include "etw_registry.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace pry::etw {

namespace {

constexpr uint32_t kMinCapacity = 128;
constexpr uint32_t kMaxCapacity = 1u << 20;  // 1 MiB rows upper bound

uint32_t RoundUpPow2(uint32_t v)
{
    if (v < kMinCapacity) return kMinCapacity;
    if (v > kMaxCapacity) return kMaxCapacity;
    uint32_t p = 1;
    while (p < v) p <<= 1;
    return p;
}

std::string Utf16ToUtf8(const wchar_t* s, size_t wchars)
{
    if (!s || wchars == 0) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, s, (int)wchars, nullptr, 0,
                                   nullptr, nullptr);
    if (n <= 0) return {};
    std::string out((size_t)n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s, (int)wchars, out.data(), n,
                          nullptr, nullptr);
    return out;
}

std::string GuidToString(const GUID& g)
{
    char buf[40];
    std::snprintf(buf, sizeof(buf),
                  "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                  (unsigned long)g.Data1, g.Data2, g.Data3,
                  g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
                  g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

std::string FormatHex64(uint64_t v)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return buf;
}

std::string FormatUint(uint64_t v)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    return buf;
}

std::string FormatInt(int64_t v)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%lld", (long long)v);
    return buf;
}

// Minimal TDH decoder: name + value pairs. Non-fatal — any property
// that we can't shape stays out of the map rather than failing the
// whole record. Covers the integer/string/pointer/GUID/filetime
// shapes we actually see in the kernel providers; the rare blob types
// turn into a short hex preview.
void DecodeProperties(EVENT_RECORD* rec, std::map<std::string, std::string>* out)
{
    ULONG buf_size = 0;
    ULONG rc = ::TdhGetEventInformation(rec, 0, nullptr, nullptr, &buf_size);
    if (rc != ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<uint8_t> buf(buf_size, 0);
    auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(buf.data());
    rc = ::TdhGetEventInformation(rec, 0, nullptr, info, &buf_size);
    if (rc != ERROR_SUCCESS) return;

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
        if (p.Flags & PropertyStruct) continue;  // skip nested structs
        const wchar_t* nameW =
            reinterpret_cast<const wchar_t*>((uint8_t*)info + p.NameOffset);
        std::string name = Utf16ToUtf8(nameW, wcslen(nameW));
        if (name.empty()) continue;

        PROPERTY_DATA_DESCRIPTOR desc{};
        desc.PropertyName = reinterpret_cast<ULONGLONG>(nameW);
        desc.ArrayIndex = 0;

        ULONG prop_size = 0;
        if (::TdhGetPropertySize(rec, 0, nullptr, 1, &desc, &prop_size)
                != ERROR_SUCCESS || prop_size == 0 || prop_size > 1 << 16) {
            continue;
        }
        std::vector<uint8_t> pbuf(prop_size, 0);
        if (::TdhGetProperty(rec, 0, nullptr, 1, &desc, prop_size,
                              pbuf.data()) != ERROR_SUCCESS) {
            continue;
        }
        const uint8_t* d = pbuf.data();
        std::string val;
        switch (p.nonStructType.InType) {
            case TDH_INTYPE_UNICODESTRING: {
                size_t wchars = prop_size / 2;
                val = Utf16ToUtf8(reinterpret_cast<const wchar_t*>(d), wchars);
                while (!val.empty() && val.back() == '\0') val.pop_back();
                break;
            }
            case TDH_INTYPE_ANSISTRING: {
                val.assign(reinterpret_cast<const char*>(d), prop_size);
                while (!val.empty() && val.back() == '\0') val.pop_back();
                break;
            }
            case TDH_INTYPE_INT8:   val = FormatInt(*(int8_t*)d); break;
            case TDH_INTYPE_UINT8:  val = FormatUint(*(uint8_t*)d); break;
            case TDH_INTYPE_INT16:  val = FormatInt(*(int16_t*)d); break;
            case TDH_INTYPE_UINT16: val = FormatUint(*(uint16_t*)d); break;
            case TDH_INTYPE_INT32:  val = FormatInt(*(int32_t*)d); break;
            case TDH_INTYPE_UINT32: val = FormatUint(*(uint32_t*)d); break;
            case TDH_INTYPE_HEXINT32:
                val = FormatHex64(*(uint32_t*)d); break;
            case TDH_INTYPE_INT64:  val = FormatInt(*(int64_t*)d); break;
            case TDH_INTYPE_UINT64: val = FormatUint(*(uint64_t*)d); break;
            case TDH_INTYPE_HEXINT64:
                val = FormatHex64(*(uint64_t*)d); break;
            case TDH_INTYPE_POINTER:
                val = FormatHex64(prop_size == 8 ? *(uint64_t*)d
                                                  : *(uint32_t*)d); break;
            case TDH_INTYPE_FILETIME: {
                FILETIME ft = *(FILETIME*)d;
                ULARGE_INTEGER u{};
                u.LowPart = ft.dwLowDateTime;
                u.HighPart = ft.dwHighDateTime;
                val = FormatUint(u.QuadPart);
                break;
            }
            case TDH_INTYPE_GUID: {
                if (prop_size >= sizeof(GUID))
                    val = GuidToString(*(GUID*)d);
                break;
            }
            default: {
                // Short hex preview for the odd blob type.
                size_t take = std::min<size_t>(prop_size, 32);
                val.reserve(take * 2);
                static const char* kHex = "0123456789abcdef";
                for (size_t j = 0; j < take; ++j) {
                    val.push_back(kHex[(d[j] >> 4) & 0xF]);
                    val.push_back(kHex[d[j] & 0xF]);
                }
                if (take < prop_size) val += "...";
                break;
            }
        }
        if (!val.empty()) (*out)[name] = std::move(val);
    }
}

void WINAPI EventRecordCb(EVENT_RECORD* rec)
{
    if (!rec || !rec->UserContext) return;
    auto* self = reinterpret_cast<EtwConsumer*>(rec->UserContext);
    self->OnEvent(rec);
}

ULONG WINAPI BufferCb(EVENT_TRACE_LOGFILEW* logfile)
{
    if (!logfile || !logfile->Context) return TRUE;
    auto* self = reinterpret_cast<EtwConsumer*>(logfile->Context);
    self->OnBuffer(logfile);
    return TRUE;  // keep consuming
}

}  // namespace

// -------------------------------------------------------------- SpscRing --

SpscRing::SpscRing(uint32_t capacity)
    : cap_(RoundUpPow2(capacity ? capacity : 16384)),
      mask_(cap_ - 1),
      slots_(std::make_unique<EtwEvent[]>(cap_)) {}

uint32_t SpscRing::used() const
{
    uint64_t h = head_.load(std::memory_order_acquire);
    uint64_t t = tail_.load(std::memory_order_acquire);
    uint64_t diff = h - t;
    return diff > cap_ ? cap_ : (uint32_t)diff;
}

void SpscRing::Push(EtwEvent evt)
{
    uint64_t h = head_.load(std::memory_order_relaxed);
    uint64_t t = tail_.load(std::memory_order_acquire);
    if (h - t >= cap_) {
        // Overflow: advance tail by one slot (overwrite-oldest) and
        // count the drop. The consumer may be mid-drain; the drain
        // lock serializes the tail bump with the consumer's own tail
        // advance, so this never corrupts the drain window.
        std::lock_guard<std::mutex> g(drain_lock_);
        t = tail_.load(std::memory_order_relaxed);
        if (h - t >= cap_) {
            tail_.store(t + 1, std::memory_order_release);
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    evt.seq = seq_.fetch_add(1, std::memory_order_relaxed) + 1;
    slots_[(size_t)(h & mask_)] = std::move(evt);
    head_.store(h + 1, std::memory_order_release);
    total_.fetch_add(1, std::memory_order_relaxed);
}

std::vector<EtwEvent> SpscRing::Drain(uint32_t limit, uint64_t since_seq,
                                       uint64_t* out_last_seq)
{
    std::vector<EtwEvent> out;
    std::lock_guard<std::mutex> g(drain_lock_);
    uint64_t h = head_.load(std::memory_order_acquire);
    uint64_t t = tail_.load(std::memory_order_relaxed);
    uint64_t have = h - t;
    if (have == 0) {
        if (out_last_seq) *out_last_seq = 0;
        return out;
    }
    uint32_t take_cap = limit ? std::min<uint32_t>(limit, cap_) : cap_;
    uint64_t last = 0;
    for (uint64_t i = 0; i < have && out.size() < take_cap; ++i) {
        EtwEvent& slot = slots_[(size_t)((t + i) & mask_)];
        if (slot.seq > since_seq) {
            out.push_back(slot);
            last = slot.seq;
        }
    }
    tail_.store(t + have, std::memory_order_release);
    if (out_last_seq) *out_last_seq = last;
    return out;
}

// ------------------------------------------------------------ EtwConsumer --

EtwConsumer::EtwConsumer() = default;

EtwConsumer::~EtwConsumer() { Stop(); }

bool EtwConsumer::Start(EtwSession* session, uint32_t ring_capacity,
                         std::string* err)
{
    session_ = session;
    ring_ = std::make_unique<SpscRing>(ring_capacity);
    stopping_.store(false, std::memory_order_release);
    running_.store(true, std::memory_order_release);

    worker_ = std::thread([this]() {
        EVENT_TRACE_LOGFILEW lf{};
        std::wstring wname;
        wname.reserve(session_->name().size());
        for (char c : session_->name()) wname.push_back((wchar_t)(uint8_t)c);
        lf.LoggerName = const_cast<wchar_t*>(wname.c_str());
        lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
                               | PROCESS_TRACE_MODE_EVENT_RECORD;
        lf.EventRecordCallback = &EventRecordCb;
        lf.BufferCallback = &BufferCb;
        lf.Context = this;

        TRACEHANDLE th = ::OpenTraceW(&lf);
        if (th == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
            running_.store(false, std::memory_order_release);
            return;
        }
        trace_handle_ = (uint64_t)th;
        ::ProcessTrace(&th, 1, nullptr, nullptr);
        trace_handle_ = 0;
        running_.store(false, std::memory_order_release);
    });
    (void)err;
    return true;
}

void EtwConsumer::Stop()
{
    bool expected = false;
    if (!stopping_.compare_exchange_strong(expected, true)) {
        // Already stopping; just wait for the worker.
        if (worker_.joinable()) worker_.join();
        return;
    }
    // Session stop issued ControlTraceW(STOP) which makes
    // ProcessTrace return — join the worker.
    if (worker_.joinable()) worker_.join();
    running_.store(false, std::memory_order_release);
}

void EtwConsumer::OnEvent(const void* record_vp)
{
    const EVENT_RECORD* rec = static_cast<const EVENT_RECORD*>(record_vp);
    EtwEvent evt;
    evt.ts_100ns = (uint64_t)rec->EventHeader.TimeStamp.QuadPart;
    evt.provider_guid = GuidToString(rec->EventHeader.ProviderId);
    evt.event_id = rec->EventHeader.EventDescriptor.Id;
    evt.pid = rec->EventHeader.ProcessId;
    evt.tid = rec->EventHeader.ThreadId;
    evt.opcode = rec->EventHeader.EventDescriptor.Opcode;
    evt.version = rec->EventHeader.EventDescriptor.Version;
    evt.level = rec->EventHeader.EventDescriptor.Level;
    evt.keywords = rec->EventHeader.EventDescriptor.Keyword;
    evt.kind = ProviderKind(evt.provider_guid);
    DecodeProperties(const_cast<EVENT_RECORD*>(rec), &evt.fields);
    ring_->Push(std::move(evt));
}

void EtwConsumer::OnBuffer(const void* logfile_vp)
{
    const EVENT_TRACE_LOGFILEW* lf =
        static_cast<const EVENT_TRACE_LOGFILEW*>(logfile_vp);
    events_lost_.store(lf->LogfileHeader.EventsLost,
                        std::memory_order_relaxed);
    buffers_written_.store(lf->LogfileHeader.BuffersWritten,
                            std::memory_order_relaxed);
    buffers_lost_.store(lf->LogfileHeader.BuffersLost,
                         std::memory_order_relaxed);
}

}  // namespace pry::etw
