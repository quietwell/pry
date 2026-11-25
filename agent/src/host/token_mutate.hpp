// agent/src/host/token_mutate.hpp — shared with umagent.
//
// Token mutators: AdjustTokenPrivileges / SetTokenInformation /
// Impersonate / ModifyDefaultDacl. Each returns true on success or
// soft-success (ERROR_NOT_ALL_ASSIGNED surfaces as ok=true with
// state='absent'); hard failures populate `*err`.

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <memory>

namespace pry::host {

struct AdjustPrivilegeResult {
    bool ok = false;
    std::string previous_state;   // "enabled" | "disabled" | "default" | "absent"
    std::string new_state;
    uint32_t luid_low = 0;
    uint32_t luid_high = 0;
    std::string err;
};

// `action` ∈ {"enable", "disable", "remove"}. Pass `privilege_name` or
// a specific LUID (0,0 means fall back to privilege_name).
AdjustPrivilegeResult AdjustPrivilege(
    uint32_t pid, uint32_t tid, const std::string& privilege_name,
    uint32_t luid_low, uint32_t luid_high, const std::string& action);


struct SetIntegrityResult {
    bool ok = false;
    uint32_t previous_rid = 0;
    uint32_t new_rid = 0;
    std::string err;
};

SetIntegrityResult SetIntegrityLevel(uint32_t pid, uint32_t tid,
                                      uint32_t rid,
                                      const std::string& name);


struct SetVirtualizationResult {
    bool ok = false;
    bool previous = false;
    bool new_value = false;
    std::string err;
};

SetVirtualizationResult SetVirtualization(uint32_t pid, uint32_t tid,
                                           bool enable);


struct DaclAceRow {
    std::string sid;
    uint32_t access_mask = 0;
    std::string type;   // "allow" | "deny"
    uint32_t flags = 0;
};

struct ModifyDaclResult {
    bool ok = false;
    uint32_t ace_count_before = 0;
    uint32_t ace_count_after = 0;
    std::string err;
};

ModifyDaclResult ModifyDefaultDacl(uint32_t pid, uint32_t tid,
                                    const std::vector<DaclAceRow>& aces,
                                    bool replace);


// Impersonation lifecycle: dedicated worker thread per session,
// tombstone timer (30s default; 300s with persist=true). The destructor
// sweeps every live entry so a crashed orchestrator can't leak elevated
// context on the agent (slice 01 §Impersonation lifecycle).
struct ImpersonateResult {
    bool ok = false;
    std::string impersonation_id;
    uint32_t agent_thread_id = 0;
    std::string level_granted;
    std::string err;
};

ImpersonateResult StartImpersonation(uint32_t source_pid, uint32_t source_tid,
                                      bool persist,
                                      const std::string& impersonation_level);

// Clears a prior impersonation (SetThreadToken(NULL) + close dup token).
bool StopImpersonation(const std::string& impersonation_id, std::string* err);


// Shared state between the registry and the impersonation worker thread
// (defined in token_mutate.cpp). Stop is a condition-variable signal — the
// worker reverts its token and frees everything itself; the registry
// never TerminateThread()s it (that leaked the duplicated token + the
// context and could leave the CV mutex owned by a dead thread).
struct ImpersonationWorker;

class ImpersonationRegistry {
public:
    struct Entry {
        void* dup_token = nullptr;      // HANDLE (owned by the worker)
        void* worker_thread = nullptr;  // HANDLE (owned by the registry)
        uint32_t agent_tid = 0;
        std::chrono::steady_clock::time_point tombstone_at{};
        bool persist = false;
        std::shared_ptr<ImpersonationWorker> worker;
    };

    std::string Register(void* dup_token, void* worker_thread,
                         uint32_t agent_tid, bool persist,
                         std::shared_ptr<ImpersonationWorker> worker = nullptr);
    bool Clear(const std::string& id, std::string* err);
    // Tombstone sweep — call periodically. Returns the number swept.
    size_t SweepExpired();
    // Destructor sweep on agent shutdown.
    void ClearAll();
    size_t Size();
    bool HasId(const std::string& id);
    // Expose the per-id entry (for parity testing).
    bool Peek(const std::string& id, Entry* out);

private:
    std::mutex mu_;
    std::unordered_map<std::string, Entry> live_;
};

ImpersonationRegistry& GlobalImpersonationRegistry();

}  // namespace pry::host
