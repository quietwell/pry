// agent/src/etw/etw_session.cpp — SI #10 ETW session lifecycle.
//
// Thin wrapper over StartTraceW + EnableTraceEx2. Each session owns
// its own EVENT_TRACE_PROPERTIES block (payload buffer carries the
// LoggerName suffix per the ETW ABI), its logger handle, and the
// provider list it enabled; Stop() tears those down even on partial
// failure.
//
// The companion EtwConsumer owns ProcessTrace on a worker thread
// (etw_consumer.cpp). See an internal plan
// 04-umagent-orchestrator.md §Feature 8.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>   // IIDFromString
#include <evntrace.h>
#include <evntcons.h>

#include "etw_session.hpp"
#include "etw_consumer.hpp"
#include "etw_registry.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace pry::etw {

namespace {

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                   nullptr, 0);
    if (n <= 0) return {};
    std::wstring out((size_t)n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

bool StrToGuid(const std::string& guid_str, GUID* out)
{
    // Accept both "{...}" and bare 36-char GUID forms. ::IIDFromString
    // wants wide + braces.
    std::string s = guid_str;
    if (s.empty()) return false;
    if (s.front() != '{') s.insert(0, "{");
    if (s.back() != '}') s.push_back('}');
    std::wstring ws = Utf8ToWide(s);
    IID iid{};
    HRESULT hr = ::IIDFromString(ws.c_str(), &iid);
    if (hr != S_OK) return false;
    *out = iid;
    return true;
}

}  // namespace

// --------------------------------------------------------------- EtwSession --

EtwSession::EtwSession() = default;

EtwSession::~EtwSession() { Stop(); }

bool EtwSession::Start(const StartParams& p, StartResult* result,
                        std::string* err)
{
    if (running_) {
        if (err) *err = "etw: session already running";
        return false;
    }
    if (p.session_name.empty()) {
        if (err) *err = "etw: session_name required";
        return false;
    }
    if (p.providers.empty()) {
        if (err) *err = "etw: at least one provider required";
        return false;
    }

    name_ = p.session_name;
    std::wstring wname = Utf8ToWide(name_);
    size_t name_bytes = (wname.size() + 1) * sizeof(wchar_t);
    size_t total = sizeof(EVENT_TRACE_PROPERTIES) + name_bytes;
    props_buf_.assign(total, 0);
    auto* props =
        reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf_.data());
    props->Wnode.BufferSize = (ULONG)total;
    props->Wnode.ClientContext = 1;  // QPC
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE
                         | EVENT_TRACE_USE_LOCAL_SEQUENCE;
    props->FlushTimer = 1;
    if (p.buffer_size_kb) props->BufferSize = p.buffer_size_kb;
    if (p.min_buffers)    props->MinimumBuffers = p.min_buffers;
    if (p.max_buffers)    props->MaximumBuffers = p.max_buffers;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    std::memcpy(props_buf_.data() + props->LoggerNameOffset, wname.c_str(),
                name_bytes);

    TRACEHANDLE handle = 0;
    ULONG rc = ::StartTraceW(&handle, wname.c_str(), props);
    if (rc == ERROR_ALREADY_EXISTS) {
        // Stop a stale one and try again — SI's model is "unique by
        // name"; a prior crash can leave an orphan logger.
        ::ControlTraceW(0, wname.c_str(), props,
                         EVENT_TRACE_CONTROL_STOP);
        std::memset(props_buf_.data(), 0, total);
        props->Wnode.BufferSize = (ULONG)total;
        props->Wnode.ClientContext = 1;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE
                             | EVENT_TRACE_USE_LOCAL_SEQUENCE;
        props->FlushTimer = 1;
        if (p.buffer_size_kb) props->BufferSize = p.buffer_size_kb;
        if (p.min_buffers)    props->MinimumBuffers = p.min_buffers;
        if (p.max_buffers)    props->MaximumBuffers = p.max_buffers;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        std::memcpy(props_buf_.data() + props->LoggerNameOffset,
                    wname.c_str(), name_bytes);
        rc = ::StartTraceW(&handle, wname.c_str(), props);
    }
    if (rc != ERROR_SUCCESS) {
        if (err) *err = "etw: StartTraceW failed, gle="
                        + std::to_string(rc);
        return false;
    }
    session_handle_ = (uint64_t)handle;

    for (const auto& ps : p.providers) {
        std::string e;
        if (EnableProvider_(ps, &e)) {
            enabled_.push_back(ps);
            if (result) result->started.push_back(ps.guid);
        } else {
            if (result) result->failed.push_back(ps.guid);
        }
    }
    if (enabled_.empty()) {
        if (err) *err = "etw: no provider could be enabled";
        ::ControlTraceW((TRACEHANDLE)session_handle_, nullptr, props,
                         EVENT_TRACE_CONTROL_STOP);
        session_handle_ = 0;
        return false;
    }

    consumer_ = std::make_unique<EtwConsumer>();
    std::string cerr;
    if (!consumer_->Start(this, p.ring_capacity, &cerr)) {
        if (err) *err = "etw: consumer start failed: " + cerr;
        ::ControlTraceW((TRACEHANDLE)session_handle_, nullptr, props,
                         EVENT_TRACE_CONTROL_STOP);
        consumer_.reset();
        session_handle_ = 0;
        return false;
    }
    running_ = true;
    if (result) {
        result->session_handle = session_handle_;
        result->ring_capacity = consumer_->ring().capacity();
    }
    return true;
}

bool EtwSession::EnableProvider_(const ProviderSpec& ps, std::string* err)
{
    GUID g{};
    if (!StrToGuid(ps.guid, &g)) {
        if (err) *err = "bad GUID: " + ps.guid;
        return false;
    }
    uint8_t level = (uint8_t)(ps.level ? ps.level : TRACE_LEVEL_VERBOSE);
    ULONG rc = ::EnableTraceEx2((TRACEHANDLE)session_handle_, &g,
                                 EVENT_CONTROL_CODE_ENABLE_PROVIDER, level,
                                 ps.keywords_any, ps.keywords_all,
                                 0, nullptr);
    if (rc != ERROR_SUCCESS) {
        if (err) *err = "EnableTraceEx2 failed, gle="
                        + std::to_string(rc);
        return false;
    }
    return true;
}

void EtwSession::Stop()
{
    if (!running_ && !session_handle_) return;
    // Disable each enabled provider — best effort, ignore errors.
    for (const auto& ps : enabled_) {
        GUID g{};
        if (!StrToGuid(ps.guid, &g)) continue;
        ::EnableTraceEx2((TRACEHANDLE)session_handle_, &g,
                          EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0,
                          nullptr);
    }
    enabled_.clear();
    if (session_handle_ && !props_buf_.empty()) {
        auto* props =
            reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf_.data());
        ::ControlTraceW((TRACEHANDLE)session_handle_, nullptr, props,
                         EVENT_TRACE_CONTROL_STOP);
    }
    session_handle_ = 0;
    if (consumer_) {
        consumer_->Stop();
        consumer_.reset();
    }
    running_ = false;
}

// ----------------------------------------------------------- SessionRegistry --

SessionRegistry& SessionRegistry::Instance()
{
    static SessionRegistry inst;
    return inst;
}

bool SessionRegistry::Start(const StartParams& p, StartResult* result,
                             std::string* err)
{
    std::lock_guard<std::mutex> g(lock_);
    auto it = sessions_.find(p.session_name);
    if (it != sessions_.end() && it->second->running()) {
        if (err) *err = "etw: session '" + p.session_name
                        + "' already running";
        return false;
    }
    auto s = std::make_unique<EtwSession>();
    if (!s->Start(p, result, err)) {
        return false;
    }
    sessions_[p.session_name] = std::move(s);
    return true;
}

bool SessionRegistry::Stop(const std::string& name, uint64_t* total,
                             uint64_t* dropped, std::string* err)
{
    std::unique_ptr<EtwSession> owned;
    {
        std::lock_guard<std::mutex> g(lock_);
        auto it = sessions_.find(name);
        if (it == sessions_.end()) {
            if (err) *err = "etw: session '" + name + "' not found";
            return false;
        }
        owned = std::move(it->second);
        sessions_.erase(it);
    }
    if (owned && owned->consumer()) {
        if (total)   *total = owned->consumer()->ring().total();
        if (dropped) *dropped = owned->consumer()->ring().dropped();
    }
    // Destruction stops the session.
    return true;
}

EtwSession* SessionRegistry::Get(const std::string& name)
{
    std::lock_guard<std::mutex> g(lock_);
    auto it = sessions_.find(name);
    return it == sessions_.end() ? nullptr : it->second.get();
}

std::vector<std::string> SessionRegistry::Names()
{
    std::vector<std::string> out;
    std::lock_guard<std::mutex> g(lock_);
    out.reserve(sessions_.size());
    for (const auto& kv : sessions_) out.push_back(kv.first);
    return out;
}

void SessionRegistry::StopAll()
{
    std::vector<std::unique_ptr<EtwSession>> drained;
    {
        std::lock_guard<std::mutex> g(lock_);
        for (auto& kv : sessions_) drained.push_back(std::move(kv.second));
        sessions_.clear();
    }
    // Each session's destructor stops its own trace + consumer.
}

}  // namespace pry::etw
