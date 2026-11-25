// agent/src/scan/scan_service.hpp
//
// v16 (Memory scanner wave 1): on-target typed scanner — ScanService
// gRPC handlers + per-process scan registry.
//
// Shipped as scaffolding: the orchestrator currently keeps
// StatusResponse.scan_service_version = 0 so every call still lands
// on the v15 orchestrator-RAM fallback. Flipping this file's handler
// surface on is a one-line edit in services_agent.cpp (set
// scan_service_version(1)) once the build + an e2e pass confirms
// parity with the fallback. See
// an internal plan §2.4 / §4 Phase L.
//
// Design brief
// ------------
// * Per-process state: ``_SCANS[scan_id] -> ScanEntry`` guarded by a
//   shared mutex. Each entry carries packed VA + raw-value arrays,
//   undo stack, cancel flag, owner id, progress counters.
// * Memory reads delegate to ``MemReadFn`` (configured at service
//   construction). Kernel agent injects a driver-backed reader;
//   umagent injects ReadProcessMemory. Scan service doesn't know
//   which it got.
// * Disk spill: when snapshot RAM crosses SCAN_RAM_BUDGET, the entry
//   writes `raw.bin` to <scan_dir>\<view>\<scan_id>\ and keeps only
//   VAs in RAM. Hot reads re-open the file; GC removes stale dirs.
// * Scan dir default: <agent_dir>\scans\<view>. Resolved at service
//   construction via GetModuleFileNameW; overridable via a config
//   knob the orchestrator passes down (targets.json scan.dir).
//
// NOT yet wired: streaming Fetch beyond a single chunk; unknown-mode
// snapshotting every aligned slot of a whole-space (orchestrator
// pre-flight refuses that today anyway); cross-process shared spill
// quotas; TLS auth metadata enforcement (inherits from the agent
// server's builder-level credentials). Each is a known gap documented
// at the call site.

#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>

#include "pry.grpc.pb.h"

namespace pry::scan {

// --- caps (mirror the plan §2.7) -------------------------------------------

inline constexpr std::uint64_t SCAN_RAM_BUDGET         = 256ULL * 1024 * 1024;
inline constexpr std::uint64_t SCAN_DISK_MAX_BYTES     = 8ULL   * 1024 * 1024 * 1024;
inline constexpr std::uint32_t SCAN_UNDO_DEPTH         = 4;
inline constexpr std::uint64_t SCAN_UNDO_DISK_TOTAL    = 16ULL  * 1024 * 1024 * 1024;
inline constexpr std::uint64_t SCAN_DISK_TOTAL_PER_MACHINE = 32ULL * 1024 * 1024 * 1024;
inline constexpr std::uint32_t SCAN_COUNT_PER_MACHINE  = 16;

// --- memory reader callback (agent vs umagent inject different ones) ------

using MemReadFn = std::function<bool(
    std::uint32_t pid, std::uint64_t va,
    void* buf, std::size_t size,
    pry::MemSpace space,
    std::size_t* out_read)>;

// --- entry state (per scan) ------------------------------------------------

enum class ScanStatus : std::uint8_t {
    Running,
    Done,
    Cancelled,
    Error,
    Interrupted,
    Capped,
    TimedOut,
};

struct ScanProgressSnapshot {
    std::uint64_t bytes_scanned{};
    std::uint64_t bytes_total{};
    std::uint64_t chunks_read{};
    std::uint64_t chunks_skipped{};
    std::uint64_t hits_so_far{};
    std::uint64_t reads_failed{};
};

struct UndoFrame {
    // Each frame is ``(vas, raw)``; captured on a successful Refine
    // before the snapshot is overwritten. Stored as owned byte vectors
    // so mmap-backed raw.bin never surfaces here.
    std::vector<std::uint64_t> vas;
    std::vector<std::uint8_t>  raw;
};

struct ScanEntry {
    std::string scan_id;
    std::string owner_client_id;
    std::string view;             // "kernel" | "user"
    std::uint32_t pid{};
    pry::MemSpace space{pry::USER};
    std::string value_type;
    std::string endian = "le";
    std::string encoding;
    std::uint32_t align{1};
    std::uint32_t width{0};
    std::string op;
    std::vector<std::uint8_t> value_le;
    std::vector<std::uint8_t> value_hi_le;
    std::uint64_t tolerance_bits{0};
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    std::uint64_t max_results{4096};
    std::uint32_t generation{0};
    ScanStatus status{ScanStatus::Running};
    std::string error;
    ScanProgressSnapshot progress;
    std::atomic<bool> cancel{false};
    std::uint64_t created_ts_ms{0};
    std::uint64_t touched_ts_ms{0};
    // Snapshot (current generation)
    std::vector<std::uint64_t> vas;
    std::vector<std::uint8_t>  raw;
    // Undo stack (newest at back); capped per plan §2.6
    std::vector<UndoFrame> undo;
    std::uint64_t undo_bytes{0};
    // Disk spill
    std::filesystem::path spill_dir;
    bool spilled{false};
    std::uint64_t disk_bytes{0};

    // Each entry owns a mutex so RPCs on the same scan serialize
    // without blocking the global registry.
    mutable std::mutex m;

    ScanEntry() = default;
    ScanEntry(const ScanEntry&) = delete;
    ScanEntry& operator=(const ScanEntry&) = delete;
};

// --- registry --------------------------------------------------------------

class ScanRegistry {
public:
    ScanRegistry();
    ~ScanRegistry();

    void Configure(std::filesystem::path scan_root, std::string view,
                   MemReadFn reader);

    std::shared_ptr<ScanEntry> Create(const pry::ScanCreateRequest& req,
                                       std::string& err);
    std::shared_ptr<ScanEntry> Lookup(const std::string& scan_id) const;
    bool Destroy(const std::string& scan_id, std::uint64_t* ram_freed,
                 std::uint64_t* disk_freed);
    std::vector<std::shared_ptr<ScanEntry>> Snapshot() const;
    std::uint64_t TotalDiskBytes() const;
    void StopGc();

    // Executes ``e->cancel`` then waits (best-effort) for the worker
    // thread to observe it. Non-blocking after the signal.
    void Cancel(const std::shared_ptr<ScanEntry>& e);

private:
    void GcLoop();

    mutable std::mutex m_;
    std::unordered_map<std::string, std::shared_ptr<ScanEntry>> scans_;
    std::filesystem::path scan_root_;
    std::string view_;
    MemReadFn reader_;
    std::atomic<bool> gc_stop_{false};
    std::thread gc_thread_;
    std::condition_variable gc_cv_;
    std::mutex gc_m_;
};

// --- first-scan / refine runners ------------------------------------------

void RunFirstScan(std::shared_ptr<ScanEntry> e,
                  const MemReadFn& reader);
void RunRefine(std::shared_ptr<ScanEntry> e,
               const pry::ScanRefineRequest& req,
               const MemReadFn& reader,
               std::uint64_t* dropped_out,
               std::uint64_t* reads_failed_out,
               std::string* err);

// --- service class ---------------------------------------------------------

class ScanServiceImpl final : public pry::ScanService::Service {
public:
    explicit ScanServiceImpl(std::string view);

    // Configure once at startup. Idempotent.
    void Configure(std::filesystem::path scan_root, MemReadFn reader);

    grpc::Status Create(grpc::ServerContext* ctx,
                        const pry::ScanCreateRequest* req,
                        pry::ScanCreateResponse* resp) override;
    grpc::Status Refine(grpc::ServerContext* ctx,
                        const pry::ScanRefineRequest* req,
                        pry::ScanRefineResponse* resp) override;
    grpc::Status Undo(grpc::ServerContext* ctx,
                      const pry::ScanUndoRequest* req,
                      pry::ScanUndoResponse* resp) override;
    grpc::Status Fetch(grpc::ServerContext* ctx,
                       const pry::ScanFetchRequest* req,
                       grpc::ServerWriter<pry::ScanFetchChunk>* writer) override;
    grpc::Status Cancel(grpc::ServerContext* ctx,
                        const pry::ScanCancelRequest* req,
                        pry::ScanCancelResponse* resp) override;
    grpc::Status Destroy(grpc::ServerContext* ctx,
                         const pry::ScanDestroyRequest* req,
                         pry::ScanDestroyResponse* resp) override;
    grpc::Status List(grpc::ServerContext* ctx,
                      const pry::ScanListRequest* req,
                      pry::ScanListResponse* resp) override;
    grpc::Status Status(grpc::ServerContext* ctx,
                        const pry::ScanStatusRequest* req,
                        pry::ScanStatusResponse* resp) override;

    ScanRegistry& Registry() { return registry_; }

private:
    ScanRegistry registry_;
    std::string view_;
    MemReadFn reader_;  // cached for Refine path (RunRefine takes the fn)
};

// --- helpers (exposed for tests + the probe builder) ----------------------

std::uint32_t WidthOf(const std::string& value_type,
                      std::size_t value_le_size);
std::filesystem::path DefaultScanRoot();

// --- registration ---------------------------------------------------------

// Instantiates a process-lifetime ScanServiceImpl (view-labelled,
// configured with ``DefaultScanRoot()`` + the caller-supplied reader)
// and wires it into the gRPC ServerBuilder. Kernel agent passes a
// driver-backed reader; umagent passes a ReadProcessMemory one.
void RegisterScanService(grpc::ServerBuilder& builder,
                         std::string view,
                         MemReadFn reader);

}  // namespace pry::scan
