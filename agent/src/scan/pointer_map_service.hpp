// agent/src/scan/pointer_map_service.hpp
//
// v17 (Memory scanner wave 2): on-target pointer map snapshot + reverse
// pointer scanner + map-vs-map diff. Mirrors the ScanService layout
// so one agent registration helper per view plugs into the same
// gRPC ServerBuilder flow (services_agent.cpp /
// umagent/src/um_services.cpp).
//
// Shipped as scaffolding: the orchestrator currently keeps
// StatusResponse.pointer_map_version = 0 so every call falls back
// (dissect) / refuses with needs_v17 (pointer map). Flipping this
// on is a one-line edit in services_agent.cpp + um_services.cpp
// (set pointer_map_version(1)) once build + e2e confirm parity.
// See an internal plan §2.3 and §4 Phase L.
//
// Design brief
// ------------
// * Per-view state: ``_MAPS[map_id] -> PointerMapEntry`` guarded by a
//   shared mutex. Each entry carries progress counters, a module
//   snapshot captured at Create time, and two mmap'd on-disk arrays
//   (map.bin by source_va, by_target.idx by target_va). Map data is
//   NEVER held in RAM beyond the mmap window — a 50 MiB map is 50 MiB
//   of mapped pages, not 50 MiB of heap.
// * Memory reads delegate to ``MemReadFn`` (shared with ScanService).
//   Module enumeration delegates to a ``ModuleEnumFn`` the registrar
//   injects; kernel agent uses ``ListUserModules`` (driver-first,
//   toolhelp fallback), umagent uses the toolhelp path directly.
// * Disk mirror — <scan_root>\pointer_maps\<view>\<map_id>\:
//     map.bin         packed [ (u64 source_va, u64 target_va) * N ],
//                     sorted asc by source_va
//     by_target.idx  packed [ u32 index_into_map_bin * N ],
//                     sorted asc by target_va via the map entry's target
//     modules.json   [ {name, path, base, size, timestamp_ms} ]
//     meta.json      { map_id, pid, view, scope, created_ts, entries,
//                       pointer_map_version }
// * Immutable after Create — no refine, no undo. Rescan + diff is the
//   workflow (plan §2.8).

#pragma once

#include <atomic>
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

#include "pry.grpc.pb.h"
#include "scan_service.hpp"   // reuse MemReadFn from Wave 1

namespace pry::scan {

// --- caps (mirror plan §2.7; overridable via machines.<name>.pointer_map) ---

inline constexpr std::uint64_t POINTER_MAP_RAM_BUDGET        = 256ULL * 1024 * 1024;
inline constexpr std::uint64_t POINTER_MAP_DISK_MAX_BYTES    = 16ULL  * 1024 * 1024 * 1024;
inline constexpr std::uint64_t POINTER_MAP_DISK_PER_MACHINE  = 64ULL  * 1024 * 1024 * 1024;
inline constexpr std::uint32_t POINTER_MAP_COUNT_PER_MACHINE = 8;
inline constexpr std::uint64_t POINTER_MAP_READ_BATCH_BYTES  = 256ULL * 1024;
inline constexpr std::uint64_t POINTER_MAP_CANDIDATE_MAX     = 268ULL * 1024 * 1024;  // 2^28
inline constexpr std::uint32_t POINTER_SCAN_MAX_DEPTH        = 7;
inline constexpr std::uint32_t POINTER_SCAN_MAX_OFFSET       = 0x1000;
inline constexpr std::uint32_t POINTER_SCAN_MAX_RESULTS      = 4096;
inline constexpr std::uint32_t POINTER_SCAN_FANOUT_PER_LEVEL = 2048;
inline constexpr std::uint32_t POINTER_SCAN_WALL_MS          = 15'000;

// --- module snapshot (captured at Create) -----------------------------------

struct ModuleInfo {
    std::string name;      // UTF-8 basename (e.g. "ntdll.dll")
    std::string path;      // UTF-8 full path
    std::uint64_t base{0};
    std::uint64_t size{0};
    std::uint64_t timestamp_ms{0};
};

// Enumerate the pid's loaded modules; implementation injected by the
// registrar so the shared TU doesn't pull DriverMgr. Returns false on
// hard failure (no modules at all); an empty vector is a soft failure.
using ModuleEnumFn = std::function<bool(std::uint32_t pid,
                                        std::vector<ModuleInfo>* out)>;

// --- progress + status ------------------------------------------------------

// Progress counters are written by the sweep worker (no lock) and
// read by Status / List under the entry mutex. Making each counter
// std::atomic makes those reads safe without serializing the sweep
// hot loop. The "snapshot" isn't atomically coherent across fields —
// that's by design; polls are observational.
struct PointerMapProgressSnapshot {
    std::atomic<std::uint64_t> regions_scanned{0};
    std::uint64_t regions_total{0};  // set once at Create
    std::atomic<std::uint64_t> bytes_scanned{0};
    std::uint64_t bytes_total{0};    // set once at Create
    std::atomic<std::uint64_t> candidates_so_far{0};
    std::atomic<std::uint64_t> chunks_skipped{0};
};

enum class PointerMapStatus : std::uint8_t {
    Running,
    Done,
    Cancelled,
    Error,
    Interrupted,
    Capped,
    TimedOut,
};

// --- entry state (per map) --------------------------------------------------

struct PointerMapEntry {
    std::string map_id;
    std::string owner_client_id;
    std::string view;            // "kernel" | "user"
    std::uint32_t pid{0};
    pry::MemSpace space{pry::USER};
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;  // source spans
    std::uint64_t max_candidates{POINTER_MAP_CANDIDATE_MAX};
    PointerMapStatus status{PointerMapStatus::Running};
    std::string error;
    PointerMapProgressSnapshot progress;
    std::atomic<bool> cancel{false};
    std::uint64_t created_ts_ms{0};
    std::uint64_t touched_ts_ms{0};

    // module snapshot captured at Create time
    std::vector<ModuleInfo> modules;

    // on-disk mirror
    std::filesystem::path spill_dir;
    // true = spill_dir is this registry's own folder under the spill root
    // (Create / DiscoverFromDisk) and Destroy(keep_disk=false) may delete
    // it. Load maps a CALLER's folder in place: owned=false, so Destroy
    // never deletes a saved map (mechanics audit P0 #2).
    bool owned{true};
    std::uint64_t entries{0};
    std::uint64_t disk_bytes{0};

    // mmap handles (populated by Load, by in-worker finalize on Create,
    // and dropped by Destroy). Windows HANDLE kept as void* so this
    // header stays grpc.pb-only on the include side.
    void* map_file_h{nullptr};     // CreateFileW handle for map.bin
    void* map_mapping_h{nullptr};  // CreateFileMappingW handle
    const void* map_view{nullptr}; // MapViewOfFile pointer
    std::uint64_t map_bytes{0};    // size of the mapped view

    void* idx_file_h{nullptr};
    void* idx_mapping_h{nullptr};
    const void* idx_view{nullptr};
    std::uint64_t idx_bytes{0};

    mutable std::mutex m;

    PointerMapEntry() = default;
    PointerMapEntry(const PointerMapEntry&) = delete;
    PointerMapEntry& operator=(const PointerMapEntry&) = delete;
};

// Packed map row — the on-wire + on-disk shape.
#pragma pack(push, 1)
struct PointerMapRow {
    std::uint64_t source_va;
    std::uint64_t target_va;
};
#pragma pack(pop)
static_assert(sizeof(PointerMapRow) == 16,
              "PointerMapRow must be 16 bytes for the packed on-disk layout");

// --- registry ---------------------------------------------------------------

class PointerMapRegistry {
public:
    PointerMapRegistry();
    ~PointerMapRegistry();

    void Configure(std::filesystem::path scan_root, std::string view,
                   MemReadFn reader, ModuleEnumFn enumerate);

    // Launches the sweep worker. Caller fills request fields; returns
    // the entry (or nullptr on reject with ``err``).
    std::shared_ptr<PointerMapEntry> Create(
        const pry::PointerMapCreateRequest& req, std::string& err);

    std::shared_ptr<PointerMapEntry> Lookup(const std::string& map_id) const;
    bool Destroy(const std::string& map_id, bool keep_disk,
                 std::uint64_t* ram_freed, std::uint64_t* disk_freed);
    std::vector<std::shared_ptr<PointerMapEntry>> Snapshot() const;
    std::uint64_t TotalDiskBytes() const;

    void Cancel(const std::shared_ptr<PointerMapEntry>& e);

    // Discovery pass: walk <scan_root>/pointer_maps/<view>/ and
    // reconstruct lightweight metadata rows without mmap'ing the big
    // files. Called once at Configure.
    void DiscoverFromDisk();

    // Register an entry built outside Create (e.g. by Load). Fails if
    // the id is already present. Does NOT launch a sweep worker; the
    // entry's status must already be terminal.
    bool RegisterLoaded(std::shared_ptr<PointerMapEntry> e);

    // Mint a fresh map_id ("pm<nonce>_NNNN"); used by Load when the
    // caller didn't supply one.
    std::string MintMapId();

    // Return the configured spill root (scan_root/pointer_maps/view).
    std::filesystem::path SpillRoot() const;

private:
    void SweepWorker(std::shared_ptr<PointerMapEntry> e);

    mutable std::mutex m_;
    std::unordered_map<std::string, std::shared_ptr<PointerMapEntry>> maps_;
    std::filesystem::path scan_root_;
    std::string view_;
    MemReadFn reader_;
    ModuleEnumFn enumerate_;
    // joinable sweep workers.
    // Replaces the previous ``std::thread(...).detach()`` pattern so
    // ``~PointerMapRegistry`` can cancel + join every outstanding worker
    // instead of racing a detached thread against registry teardown.
    // Guarded by ``workers_m_`` so an in-flight ``Create`` (which pushes
    // here while holding only ``m_``) doesn't collide with reaping or
    // dtor-time join. Entries are reaped opportunistically in Create;
    // the dtor reaps the rest.
    std::mutex workers_m_;
    std::vector<std::thread> workers_;
};

// --- free helpers used by the sweep + reverse scan + tests -----------------

// x64 canonical user-space VA test: bit 47 sign-extended to the upper
// 16 bits, and non-zero. Kernel space (space == KERNEL) relaxes this
// to accept canonical kernel VAs too.
bool IsCanonicalUserVA(std::uint64_t va);
bool IsCanonicalKernelVA(std::uint64_t va);

// Reverse-lookup binary-search helpers over the mmap'd map.bin /
// by_target.idx pair. Finds [lo, hi) range of rows whose target_va
// is in [target_lo, target_hi]. Thread-safe (read-only mmap).
void ReverseLookupTargetRange(const PointerMapRow* rows,
                              const std::uint32_t* by_target_idx,
                              std::size_t count,
                              std::uint64_t target_lo,
                              std::uint64_t target_hi,
                              std::size_t* out_lo,
                              std::size_t* out_hi);

// Classify a source VA against a module snapshot. Returns:
//   "image_text" | "image_rdata" | "image_data" | "image_unknown"
//   when `va` lands inside a module's range (section walk skipped
//   in v17 Phase D — "image_unknown" is the catch-all).
//   "" otherwise (caller fills "heap"/"stack"/"other" from VAD info).
// requires ``modules`` sorted
// by ``base`` ASC; ``PointerMapRegistry::Create`` and umagent/kernel
// enumerators guarantee this.
std::string ClassifyAnchor(std::uint64_t va,
                           const std::vector<ModuleInfo>& modules,
                           std::uint64_t* out_module_off,
                           std::string* out_module_name);

// O(log n) module lookup.
// Returns the module whose ``[base, base + size)`` contains ``va``,
// or ``nullptr`` on miss. ``modules`` MUST be sorted by ``base`` ASC —
// every path that produces a ``std::vector<ModuleInfo>`` above sorts
// at construction time. Zero-size rows are ignored.
const ModuleInfo* FindModuleByVA(std::uint64_t va,
                                 const std::vector<ModuleInfo>& modules);

// UTF-8 lowercased basename of a module path (for canonical module!
// offset equivalence across reboots; §2.12 and §4 Phase E).
std::string ModuleBasenameLower(const std::string& path_or_name);

// --- service class ----------------------------------------------------------

class PointerMapServiceImpl final
    : public pry::PointerMapService::Service {
public:
    explicit PointerMapServiceImpl(std::string view);

    void Configure(std::filesystem::path scan_root, MemReadFn reader,
                   ModuleEnumFn enumerate);

    grpc::Status Create(grpc::ServerContext* ctx,
                        const pry::PointerMapCreateRequest* req,
                        pry::PointerMapCreateResponse* resp) override;
    grpc::Status Status(grpc::ServerContext* ctx,
                        const pry::PointerMapStatusRequest* req,
                        pry::PointerMapStatusResponse* resp) override;
    grpc::Status List(grpc::ServerContext* ctx,
                      const pry::PointerMapListRequest* req,
                      pry::PointerMapListResponse* resp) override;
    grpc::Status Cancel(grpc::ServerContext* ctx,
                        const pry::PointerMapCancelRequest* req,
                        pry::PointerMapCancelResponse* resp) override;
    grpc::Status Save(grpc::ServerContext* ctx,
                      const pry::PointerMapSaveRequest* req,
                      pry::PointerMapSaveResponse* resp) override;
    grpc::Status Load(grpc::ServerContext* ctx,
                      const pry::PointerMapLoadRequest* req,
                      pry::PointerMapLoadResponse* resp) override;
    grpc::Status Destroy(grpc::ServerContext* ctx,
                         const pry::PointerMapDestroyRequest* req,
                         pry::PointerMapDestroyResponse* resp) override;
    grpc::Status Scan(grpc::ServerContext* ctx,
                      const pry::PointerScanRequest* req,
                      pry::PointerScanResponse* resp) override;
    grpc::Status Diff(grpc::ServerContext* ctx,
                      const pry::PointerMapDiffRequest* req,
                      pry::PointerMapDiffResponse* resp) override;

    PointerMapRegistry& Registry() { return registry_; }

private:
    PointerMapRegistry registry_;
    std::string view_;
    MemReadFn reader_;
    ModuleEnumFn enumerate_;
};

// --- registration -----------------------------------------------------------

// Instantiates a process-lifetime PointerMapServiceImpl (view-labelled,
// configured with the Wave 1 DefaultScanRoot() + the caller-supplied
// reader + module enumerator) and wires it into the gRPC ServerBuilder.
void RegisterPointerMapService(grpc::ServerBuilder& builder,
                               std::string view,
                               MemReadFn reader,
                               ModuleEnumFn enumerate);

}  // namespace pry::scan
