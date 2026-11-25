// agent/src/scan/dissect_service.hpp
//
// v17 (Memory scanner wave 2 Phase F): one-shot per-slot typed decode of
// a memory window. Shares MemReadFn + ModuleEnumFn with the pointer
// map service; no new on-target state. See
// an internal plan §3.3 and §3.5.
//
// Not wired to the v16 fallback path — that glue lives in
// orchestrator/src/pry/mcp/tools/mem/dissect.py and runs per
// aligned slot via memory_manage(action='read', decode=...). The
// agent-side implementation is the fast path once the orchestrator
// routes on StatusResponse.pointer_map_version >= 1.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>

#include "pry.grpc.pb.h"
#include "scan_service.hpp"           // MemReadFn
#include "pointer_map_service.hpp"    // ModuleInfo + ModuleEnumFn

namespace pry::scan {

inline constexpr std::uint32_t DISSECT_MAX_BYTES = 65'536;
inline constexpr std::uint32_t DISSECT_MAX_ROWS  = 4'096;

// DissectCompare caps. See plan §3.3.
//
// * MAX_INSTANCES bounds the N in the compare — above 32, the response
//   starts eating the wire budget and the per-offset classification
//   loses the signal/noise margin that makes `shared_pointer` /
//   `per_instance_ptr` legible.
// * MAX_BYTES_PER reuses the single-dissect window cap so the window
//   math downstream (``align``, ``buf_size``) is the same.
// * SHARED_VOTE is the default lower bound on how many instances must
//   agree on a pointer before we promote `noisy` → `shared_pointer`.
inline constexpr std::uint32_t DISSECT_COMPARE_MAX_INSTANCES = 32;
inline constexpr std::uint32_t DISSECT_COMPARE_MAX_BYTES_PER = DISSECT_MAX_BYTES;
inline constexpr std::uint32_t DISSECT_COMPARE_SHARED_VOTE   = 2;
inline constexpr std::uint32_t DISSECT_COMPARE_MIN_INSTANCES_FOR_CLASS = 3;

// Score weights — plan §3.3. Fixed so Python mocks can mirror.
inline constexpr std::uint32_t DISSECT_SCORE_PTR_MOD_EXEC   = 50;
inline constexpr std::uint32_t DISSECT_SCORE_PTR_MAPPED_ANY = 10;
inline constexpr std::uint32_t DISSECT_SCORE_UTF16_16W      = 40;
inline constexpr std::uint32_t DISSECT_SCORE_UTF16_8W       = 20;
inline constexpr std::uint32_t DISSECT_SCORE_ASCII_16B      = 30;
inline constexpr std::uint32_t DISSECT_SCORE_ASCII_8B       = 15;
inline constexpr std::uint32_t DISSECT_SCORE_F64            =  5;
inline constexpr std::uint32_t DISSECT_SCORE_F32            =  5;

// Decode one aligned slot of `buf` at `off`. `buf_size` is the window
// length; the helper reads up to 16 bytes past `off` for the ASCII /
// UTF-16 prefix (clamped at `buf_size`). Pointer classification is
// populated only when `modules` is non-empty. Deterministic — the
// same (buf, modules) always produces the same probable_type via
// a tie-broken max-score (pointer > utf16 > ascii > f64 > f32 > i32).
void DecodeSlot(const std::uint8_t* buf,
                std::size_t buf_size,
                std::size_t off,
                std::uint64_t base_va,
                const std::vector<ModuleInfo>& modules,
                bool with_modules,
                pry::DissectSlot* out);

class DissectServiceImpl final : public pry::DissectService::Service {
public:
    DissectServiceImpl(std::string view, MemReadFn reader,
                       ModuleEnumFn enumerate);

    grpc::Status Dissect(grpc::ServerContext* ctx,
                         const pry::DissectRequest* req,
                         pry::DissectResponse* resp) override;

    // multi-instance structure compare.
    // Decodes each ``base_vas[i]`` window with ``DecodeSlot``, then
    // classifies every aligned offset by variability class (see plan
    // §3.3 taxonomy). Per-instance unreadable bails cleanly; nested
    // slot rows (``DissectInstanceSlots``) preserve per-instance
    // alignment so one bad instance doesn't desync downstream readers.
    grpc::Status Compare(grpc::ServerContext* ctx,
                         const pry::DissectCompareRequest* req,
                         pry::DissectCompareResponse* resp) override;

    // re-register after a driver
    // reconnect hands us fresh callables; the process-static svcs map
    // in ``RegisterDissectService`` keeps the same service instance so
    // we can't drop and rebuild.
    void Rebind(MemReadFn reader, ModuleEnumFn enumerate);

private:
    std::string view_;
    MemReadFn reader_;
    ModuleEnumFn enumerate_;
};

void RegisterDissectService(grpc::ServerBuilder& builder,
                            std::string view,
                            MemReadFn reader,
                            ModuleEnumFn enumerate);

}  // namespace pry::scan
