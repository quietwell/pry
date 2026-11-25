#pragma once
// agent/src/etw/etw_session.hpp — SI #10 ETW session lifecycle.
//
// Thin RAII wrapper over StartTraceW + EnableTraceEx2. Each session
// owns its ETW_TRACE_PROPERTIES block, its logger handle, and the
// provider list it enabled; stopping the session also issues
// ControlTraceW(STOP) and disables every provider it enabled. The
// companion EtwConsumer owns the ProcessTrace worker thread and the
// SPSC ring. Both land on the agent and are vendored into umagent via
// CMake (same pattern as img_coherency / sig_verify) so the two views
// speak identically. See an internal plan
// 04-umagent-orchestrator.md §Feature 8.

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace pry::etw {

class EtwConsumer;

struct ProviderSpec {
    std::string guid;    // "{xxxxxxxx-....}" (any case; braces optional)
    uint64_t keywords_any = 0;
    uint64_t keywords_all = 0;
    uint32_t level = 0;  // TRACE_LEVEL_* (0 => VERBOSE)
};

struct StartParams {
    std::string session_name;
    std::vector<ProviderSpec> providers;
    uint32_t buffer_size_kb = 0;
    uint32_t min_buffers = 0;
    uint32_t max_buffers = 0;
    uint32_t ring_capacity = 0;  // 0 => 16384
};

struct StartResult {
    std::vector<std::string> started;  // provider GUID strings
    std::vector<std::string> failed;
    uint64_t session_handle = 0;
    uint32_t ring_capacity = 0;
};

class EtwSession {
public:
    EtwSession();
    ~EtwSession();

    // Starts the ETW logger and the matching ProcessTrace consumer
    // thread. On failure the session is left stopped and `err`
    // explains why. Partial provider failures are not fatal — they
    // land in `result.failed`.
    bool Start(const StartParams& p, StartResult* result, std::string* err);

    // ControlTraceW(STOP) + joins the consumer thread. Idempotent.
    void Stop();

    bool running() const { return running_; }
    const std::string& name() const { return name_; }
    uint32_t providers_count() const { return (uint32_t)enabled_.size(); }
    EtwConsumer* consumer() { return consumer_.get(); }
    uint64_t session_handle() const { return session_handle_; }

private:
    bool EnableProvider_(const ProviderSpec& ps, std::string* err);

    std::string name_;
    bool running_ = false;
    uint64_t session_handle_ = 0;
    std::vector<uint8_t> props_buf_;  // EVENT_TRACE_PROPERTIES + session name
    std::vector<ProviderSpec> enabled_;
    std::unique_ptr<EtwConsumer> consumer_;
};

// Process-wide session registry. Keyed by session_name; both the
// agent and the umagent register one of these so each process can
// host multiple concurrent sessions.
class SessionRegistry {
public:
    static SessionRegistry& Instance();

    bool Start(const StartParams& p, StartResult* result, std::string* err);
    bool Stop(const std::string& name, uint64_t* total, uint64_t* dropped,
               std::string* err);
    EtwSession* Get(const std::string& name);
    std::vector<std::string> Names();

    // Called at service shutdown; stops every live session.
    void StopAll();

private:
    SessionRegistry() = default;
    std::mutex lock_;
    std::unordered_map<std::string, std::unique_ptr<EtwSession>> sessions_;
};

}  // namespace pry::etw
