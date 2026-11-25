// agent/src/scan/scan_service.cpp
//
// v16 (Memory scanner wave 1): on-target typed scanner implementation.
//
// See scan_service.hpp for the architecture + plan references. This
// translation unit is compiled into the agent and (via link) the
// umagent; the two processes bring their own MemReadFn.
//
// Status: full implementation of Create/Refine/Undo/Fetch/Cancel/
// Destroy/List/Status + first-scan match loop + next_scan refine
// + undo stack + disk spill (write to <scan_dir>/<view>/<scan_id>/
// raw.bin when snapshot > SCAN_RAM_BUDGET) + orphan GC thread.
// Phase C–J scope in one TU.
//
// SCAFFOLDING NOTE: StatusResponse.scan_service_version is currently
// 0 for both agents (services_agent.cpp / um_services.cpp). The
// orchestrator keeps using the v15 fallback until those are flipped
// to 1 after build-verification. Flipping is a one-line edit — the
// code here handles real traffic the moment it fires.

#include "scan_service.hpp"

#include "disk_spill.hpp"
#include "scan_ids.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <numeric>  // std::iota (review M6)
#include <optional>
#include <random>
#include <sstream>

#include <windows.h>

namespace pry::scan {

namespace {

std::uint64_t NowMs()
{
    using namespace std::chrono;
    return (std::uint64_t)duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

// ---------------- typed probe + refine helpers -------------------------

template <typename T>
bool EqNumeric(const std::uint8_t* buf, const std::uint8_t* needle)
{
    T a, b;
    std::memcpy(&a, buf, sizeof(T));
    std::memcpy(&b, needle, sizeof(T));
    return a == b;
}

template <typename T>
bool LtNumeric(const std::uint8_t* buf, const std::uint8_t* needle)
{
    T a, b;
    std::memcpy(&a, buf, sizeof(T));
    std::memcpy(&b, needle, sizeof(T));
    return a < b;
}

template <typename T>
bool GtNumeric(const std::uint8_t* buf, const std::uint8_t* needle)
{
    T a, b;
    std::memcpy(&a, buf, sizeof(T));
    std::memcpy(&b, needle, sizeof(T));
    return a > b;
}

template <typename T>
bool BetweenNumeric(const std::uint8_t* buf, const std::uint8_t* lo,
                    const std::uint8_t* hi)
{
    T a, l, h;
    std::memcpy(&a, buf, sizeof(T));
    std::memcpy(&l, lo, sizeof(T));
    std::memcpy(&h, hi, sizeof(T));
    if (l > h) std::swap(l, h);
    return a >= l && a <= h;
}

bool EqFloat(const std::uint8_t* buf, const std::uint8_t* needle,
             double tol)
{
    float a, b;
    std::memcpy(&a, buf, 4);
    std::memcpy(&b, needle, 4);
    return std::abs((double)a - (double)b) <= tol;
}

bool EqDouble(const std::uint8_t* buf, const std::uint8_t* needle,
              double tol)
{
    double a, b;
    std::memcpy(&a, buf, 8);
    std::memcpy(&b, needle, 8);
    return std::abs(a - b) <= tol;
}

bool EqBytes(const std::uint8_t* buf, const std::uint8_t* needle,
             std::size_t n)
{
    return std::memcmp(buf, needle, n) == 0;
}

double TolFromBits(std::uint64_t bits, const std::string& value_type)
{
    if (value_type == "float") {
        float f;
        std::uint32_t low = (std::uint32_t)(bits & 0xffffffffULL);
        std::memcpy(&f, &low, 4);
        return (double)f;
    }
    if (value_type == "double") {
        double d;
        std::memcpy(&d, &bits, 8);
        return d;
    }
    return 0.0;
}

// Returns a predicate over (buf, off) that evaluates the first-scan op.
// The returned closure captures value_le/value_hi_le by reference, so the
// caller keeps them alive for the duration of the scan.
using InnerProbe = std::function<bool(const std::uint8_t*)>;

InnerProbe BuildFirstScanProbe(const std::string& value_type,
                                const std::string& op,
                                const std::vector<std::uint8_t>& value_le,
                                const std::vector<std::uint8_t>& value_hi_le,
                                std::uint64_t tolerance_bits,
                                std::string* err)
{
    auto fail = [&](const char* m) -> InnerProbe {
        if (err) *err = m;
        return {};
    };
    if (op == "unknown") {
        return [](const std::uint8_t*) { return true; };
    }
    if (value_type == "string" || value_type == "utf16") {
        if (op != "eq") return fail("string op must be eq");
        auto needle = value_le;  // captured
        auto n = needle.size();
        return [needle = std::move(needle), n](const std::uint8_t* p) {
            return std::memcmp(p, needle.data(), n) == 0;
        };
    }
    auto needle = value_le;
    auto needle_hi = value_hi_le;
    double tol = TolFromBits(tolerance_bits, value_type);
    const bool is_float = (value_type == "float");
    const bool is_double = (value_type == "double");

    if (op == "eq") {
        if (is_float) return [n = std::move(needle), tol](const std::uint8_t* p) {
            return EqFloat(p, n.data(), tol);
        };
        if (is_double) return [n = std::move(needle), tol](const std::uint8_t* p) {
            return EqDouble(p, n.data(), tol);
        };
        auto sz = needle.size();
        return [n = std::move(needle), sz](const std::uint8_t* p) {
            return std::memcmp(p, n.data(), sz) == 0;
        };
    }

#define CMP_BRANCH(FUNC)                                                    \
    do {                                                                    \
        if (value_type == "int8")   return [n = std::move(needle)](const std::uint8_t* p) { return FUNC<std::int8_t>(p, n.data()); };   \
        if (value_type == "uint8")  return [n = std::move(needle)](const std::uint8_t* p) { return FUNC<std::uint8_t>(p, n.data()); };  \
        if (value_type == "int16")  return [n = std::move(needle)](const std::uint8_t* p) { return FUNC<std::int16_t>(p, n.data()); };  \
        if (value_type == "uint16") return [n = std::move(needle)](const std::uint8_t* p) { return FUNC<std::uint16_t>(p, n.data()); }; \
        if (value_type == "int32")  return [n = std::move(needle)](const std::uint8_t* p) { return FUNC<std::int32_t>(p, n.data()); };  \
        if (value_type == "uint32") return [n = std::move(needle)](const std::uint8_t* p) { return FUNC<std::uint32_t>(p, n.data()); }; \
        if (value_type == "int64")  return [n = std::move(needle)](const std::uint8_t* p) { return FUNC<std::int64_t>(p, n.data()); };  \
        if (value_type == "uint64") return [n = std::move(needle)](const std::uint8_t* p) { return FUNC<std::uint64_t>(p, n.data()); }; \
        if (value_type == "float")  return [n = std::move(needle)](const std::uint8_t* p) { float a, b; std::memcpy(&a, p, 4); std::memcpy(&b, n.data(), 4); return FUNC<float>((const std::uint8_t*)&a, (const std::uint8_t*)&b); }; \
        if (value_type == "double") return [n = std::move(needle)](const std::uint8_t* p) { double a, b; std::memcpy(&a, p, 8); std::memcpy(&b, n.data(), 8); return FUNC<double>((const std::uint8_t*)&a, (const std::uint8_t*)&b); }; \
        return fail("unsupported value_type for cmp");                       \
    } while (0)

    if (op == "lt") { CMP_BRANCH(LtNumeric); }
    if (op == "gt") { CMP_BRANCH(GtNumeric); }
    if (op == "between") {
        auto nhi = needle_hi;
        if (value_type == "int32") return [n = std::move(needle), nhi = std::move(nhi)](const std::uint8_t* p) { return BetweenNumeric<std::int32_t>(p, n.data(), nhi.data()); };
        if (value_type == "uint32") return [n = std::move(needle), nhi = std::move(nhi)](const std::uint8_t* p) { return BetweenNumeric<std::uint32_t>(p, n.data(), nhi.data()); };
        if (value_type == "int64") return [n = std::move(needle), nhi = std::move(nhi)](const std::uint8_t* p) { return BetweenNumeric<std::int64_t>(p, n.data(), nhi.data()); };
        if (value_type == "uint64") return [n = std::move(needle), nhi = std::move(nhi)](const std::uint8_t* p) { return BetweenNumeric<std::uint64_t>(p, n.data(), nhi.data()); };
        if (value_type == "float") return [n = std::move(needle), nhi = std::move(nhi)](const std::uint8_t* p) { return BetweenNumeric<float>(p, n.data(), nhi.data()); };
        if (value_type == "double") return [n = std::move(needle), nhi = std::move(nhi)](const std::uint8_t* p) { return BetweenNumeric<double>(p, n.data(), nhi.data()); };
        return fail("unsupported value_type for between");
    }
#undef CMP_BRANCH
    return fail("unsupported first-scan op");
}

// --------------------------- disk spill helpers ------------------------
//
// Wave 2 (v17): WriteRawToDisk moved to disk_spill.hpp so
// pointer_map_service.cpp shares the same atomic-rename discipline.
// This TU just uses the header-inlined version.

}  // namespace

// ------------------------- WidthOf / DefaultScanRoot --------------------

std::uint32_t WidthOf(const std::string& value_type,
                      std::size_t value_le_size)
{
    if (value_type == "int8" || value_type == "uint8") return 1;
    if (value_type == "int16" || value_type == "uint16") return 2;
    if (value_type == "int32" || value_type == "uint32" ||
        value_type == "float") return 4;
    if (value_type == "int64" || value_type == "uint64" ||
        value_type == "double") return 8;
    if (value_type == "string" || value_type == "utf16")
        return (std::uint32_t)value_le_size;
    return 0;
}

std::filesystem::path DefaultScanRoot()
{
    wchar_t buf[MAX_PATH]{};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (!n || n == MAX_PATH) {
        // fall back to %SystemRoot%\Temp
        wchar_t sr[MAX_PATH]{};
        DWORD got = GetEnvironmentVariableW(L"SystemRoot", sr, MAX_PATH);
        auto base = (got && got < MAX_PATH)
            ? std::filesystem::path(sr) / L"Temp"
            : std::filesystem::path(L"C:\\Windows\\Temp");
        return base / L"pry-scans";
    }
    return std::filesystem::path(buf).parent_path() / L"scans";
}

// ------------------------- ScanRegistry ---------------------------------

ScanRegistry::ScanRegistry() = default;

ScanRegistry::~ScanRegistry()
{
    StopGc();
}

void ScanRegistry::StopGc()
{
    gc_stop_.store(true);
    gc_cv_.notify_all();
    if (gc_thread_.joinable()) gc_thread_.join();
}

void ScanRegistry::Configure(std::filesystem::path scan_root,
                              std::string view,
                              MemReadFn reader)
{
    std::lock_guard<std::mutex> lk(m_);
    scan_root_ = std::move(scan_root);
    view_ = std::move(view);
    reader_ = std::move(reader);
    if (!gc_thread_.joinable()) {
        gc_thread_ = std::thread([this] { this->GcLoop(); });
    }
}

std::shared_ptr<ScanEntry> ScanRegistry::Create(
    const pry::ScanCreateRequest& req, std::string& err)
{
    if (req.scan_id().empty()) {
        err = "scan_id empty";
        return nullptr;
    }
    // The id becomes a directory under scan_root_/view_ and Destroy
    // remove_all()s it as SYSTEM: no separators, dots, drive letters or
    // absolute paths (path / "C:\\x" REPLACES the whole path).
    if (!ValidId(req.scan_id())) {
        err = "invalid scan_id: must match [A-Za-z0-9_-]{1,64}";
        return nullptr;
    }
    auto e = std::make_shared<ScanEntry>();
    e->scan_id = req.scan_id();
    e->owner_client_id = req.owner_client_id();
    e->pid = req.pid();
    e->space = req.space();
    e->value_type = req.value_type();
    e->endian = req.endian().empty() ? "le" : req.endian();
    e->encoding = req.encoding();
    e->align = std::max<std::uint32_t>(1, req.align());
    e->op = req.op();
    e->value_le.assign(req.value_le().begin(), req.value_le().end());
    e->value_hi_le.assign(req.value_hi_le().begin(), req.value_hi_le().end());
    e->tolerance_bits = req.tolerance_bits();
    e->max_results = req.max_results() ? req.max_results() : 4096;
    e->width = WidthOf(e->value_type, e->value_le.size());
    if (!e->width) {
        err = "value_scan: unknown value_type";
        return nullptr;
    }
    e->spans.reserve(req.spans_size());
    std::uint64_t total = 0;
    for (const auto& s : req.spans()) {
        e->spans.emplace_back(s.va(), s.size());
        total += s.size();
    }
    e->progress.bytes_total = total;
    e->created_ts_ms = e->touched_ts_ms = NowMs();
    e->view = view_;
    e->spill_dir = scan_root_ / view_ / e->scan_id;

    {
        std::lock_guard<std::mutex> lk(m_);
        if (scans_.find(e->scan_id) != scans_.end()) {
            err = "scan_id already exists";
            return nullptr;
        }
        if (scans_.size() >= SCAN_COUNT_PER_MACHINE) {
            err = "per-machine scan cap reached";
            return nullptr;
        }
        scans_[e->scan_id] = e;
    }

    // Launch the first-scan match loop on a detached worker. The entry
    // carries its own cancel atomic; destruction blocks until the thread
    // observes it.
    std::weak_ptr<ScanEntry> weak_e = e;
    MemReadFn reader = reader_;
    std::thread([weak_e, reader] {
        if (auto s = weak_e.lock()) {
            RunFirstScan(s, reader);
        }
    }).detach();
    return e;
}

std::shared_ptr<ScanEntry> ScanRegistry::Lookup(const std::string& scan_id) const
{
    std::lock_guard<std::mutex> lk(m_);
    auto it = scans_.find(scan_id);
    if (it == scans_.end()) return nullptr;
    return it->second;
}

bool ScanRegistry::Destroy(const std::string& scan_id,
                            std::uint64_t* ram_freed,
                            std::uint64_t* disk_freed)
{
    std::shared_ptr<ScanEntry> e;
    std::filesystem::path root;
    {
        std::lock_guard<std::mutex> lk(m_);
        root = scan_root_ / view_;
        auto it = scans_.find(scan_id);
        if (it == scans_.end()) return false;
        e = it->second;
        if (e->status == ScanStatus::Running) {
            // signal cancel; caller may retry Destroy after Cancel
            e->cancel.store(true);
            return false;
        }
        scans_.erase(it);
    }
    std::uint64_t ram = e->vas.size() * sizeof(std::uint64_t) + e->raw.size();
    for (const auto& f : e->undo) ram += f.vas.size() * sizeof(std::uint64_t) + f.raw.size();
    std::uint64_t disk = e->disk_bytes;
    std::error_code ec;
    // Only ever delete inside this registry's own spill root.
    if (std::filesystem::exists(e->spill_dir, ec))
        RemoveAllUnder(root, e->spill_dir, ec);
    if (ram_freed) *ram_freed = ram;
    if (disk_freed) *disk_freed = disk;
    return true;
}

std::vector<std::shared_ptr<ScanEntry>> ScanRegistry::Snapshot() const
{
    std::lock_guard<std::mutex> lk(m_);
    std::vector<std::shared_ptr<ScanEntry>> out;
    out.reserve(scans_.size());
    for (const auto& kv : scans_) out.push_back(kv.second);
    return out;
}

std::uint64_t ScanRegistry::TotalDiskBytes() const
{
    std::lock_guard<std::mutex> lk(m_);
    std::uint64_t sum = 0;
    for (const auto& kv : scans_) sum += kv.second->disk_bytes;
    return sum;
}

void ScanRegistry::Cancel(const std::shared_ptr<ScanEntry>& e)
{
    e->cancel.store(true);
}

void ScanRegistry::GcLoop()
{
    // Sleep 10 min, then nuke scans whose touched_ts_ms is >24 h old.
    while (!gc_stop_.load()) {
        std::unique_lock<std::mutex> lk(gc_m_);
        gc_cv_.wait_for(lk, std::chrono::minutes(10),
                        [&] { return gc_stop_.load(); });
        if (gc_stop_.load()) break;
        auto now = NowMs();
        std::vector<std::string> to_drop;
        {
            std::lock_guard<std::mutex> rlk(m_);
            for (const auto& kv : scans_) {
                if (kv.second->status == ScanStatus::Running) continue;
                auto age_ms = now - kv.second->touched_ts_ms;
                if (age_ms > 24ULL * 60 * 60 * 1000) {
                    to_drop.push_back(kv.first);
                }
            }
        }
        for (const auto& sid : to_drop) {
            std::uint64_t ram{}, disk{};
            Destroy(sid, &ram, &disk);
        }
    }
}

// ------------------------- RunFirstScan ---------------------------------

void RunFirstScan(std::shared_ptr<ScanEntry> e, const MemReadFn& reader)
{
    // Review H2: don't hold ``e->m`` across the whole scan. Scanning a
    // 64 MiB span blocks Status / Fetch / Cancel pollers for seconds
    // at a time. We build hits into local vectors, take a short lock
    // per chunk to merge them into the entry, and let other RPCs
    // interleave between chunks.
    std::string err;
    auto probe = BuildFirstScanProbe(
        e->value_type, e->op, e->value_le, e->value_hi_le,
        e->tolerance_bits, &err);
    if (!probe) {
        std::lock_guard<std::mutex> elk(e->m);
        e->status = ScanStatus::Error;
        e->error = err.empty() ? "probe build failed" : err;
        e->touched_ts_ms = NowMs();
        return;
    }

    constexpr std::size_t CHUNK = 0x100000;  // 1 MiB
    const std::uint32_t align = std::max<std::uint32_t>(1, e->align);
    const std::uint32_t width = e->width;
    const std::uint32_t overlap = width > 1 ? (width - 1) : 0;
    const std::uint64_t max_results = e->max_results;

    std::vector<std::uint8_t> buf(CHUNK + overlap);
    std::uint64_t completed = 0;

    // Local accumulators merged into the entry per-chunk.
    std::vector<std::uint64_t> local_vas;
    std::vector<std::uint8_t>  local_raw;
    std::uint64_t cur_hit_count = 0;
    std::uint64_t cur_chunks_read = 0;
    std::uint64_t cur_chunks_skipped = 0;
    std::uint64_t cur_bytes_scanned = 0;
    bool spilled_once = false;  // review H3: spill once, not per hit

    auto flush_chunk = [&](bool mark_spill_this_pass) {
        std::lock_guard<std::mutex> elk(e->m);
        if (!local_vas.empty()) {
            e->vas.insert(e->vas.end(), local_vas.begin(), local_vas.end());
            e->raw.insert(e->raw.end(), local_raw.begin(), local_raw.end());
            local_vas.clear();
            local_raw.clear();
        }
        e->progress.chunks_read     = cur_chunks_read;
        e->progress.chunks_skipped  = cur_chunks_skipped;
        e->progress.bytes_scanned   = cur_bytes_scanned;
        e->progress.hits_so_far     = e->vas.size();
        cur_hit_count = e->vas.size();
        if (mark_spill_this_pass && !e->spilled) {
            // First crossing of SCAN_RAM_BUDGET — snapshot to disk
            // once and mark the entry spilled. Subsequent appends go
            // straight into the in-memory vectors; the final
            // post-scan flush writes the full file.
            WriteRawToDisk(e->spill_dir, e->vas, e->raw, 0);
            e->disk_bytes = e->vas.size() * sizeof(std::uint64_t)
                           + e->raw.size();
            e->spilled = true;
        }
    };

    auto bail_cancelled = [&] {
        std::lock_guard<std::mutex> elk(e->m);
        e->status = ScanStatus::Cancelled;
        e->touched_ts_ms = NowMs();
    };

    for (const auto& [sstart, ssize] : e->spans) {
        if (e->cancel.load()) { bail_cancelled(); return; }
        std::uint64_t cur = sstart;
        std::uint64_t end = sstart + ssize;
        // Align cursor relative to span start
        std::uint64_t misalign = (cur - sstart) % align;
        if (misalign) cur += (align - misalign);
        while (cur < end && cur_hit_count < max_results) {
            if (e->cancel.load()) { bail_cancelled(); return; }
            std::size_t n = (std::size_t)std::min<std::uint64_t>(CHUNK, end - cur);
            std::size_t got = 0;
            bool ok = reader ? reader(e->pid, cur, buf.data(), n, e->space, &got)
                              : false;
            if (!ok || got == 0) {
                cur_chunks_skipped++;
                std::uint64_t adv = std::max<std::uint64_t>(0x1000, align);
                cur += adv;
                continue;
            }
            cur_chunks_read++;
            cur_bytes_scanned = std::min(
                completed + (cur - sstart) + got, e->progress.bytes_total);
            // Iterate aligned offsets inside the chunk
            std::size_t rel_start = (std::size_t)((cur - sstart) % align);
            std::size_t off = rel_start ? (align - rel_start) : 0;
            while (off + width <= got) {
                if (probe(buf.data() + off)) {
                    std::uint64_t hit = cur + off;
                    local_vas.push_back(hit);
                    const std::uint8_t* p = buf.data() + off;
                    local_raw.insert(local_raw.end(), p, p + width);
                    cur_hit_count++;
                    if (!spilled_once &&
                            (cur_hit_count * sizeof(std::uint64_t)
                             + cur_hit_count * width
                             > SCAN_RAM_BUDGET)) {
                        spilled_once = true;  // trigger single disk snapshot
                    }
                    if (cur_hit_count >= max_results) break;
                }
                off += align;
            }
            flush_chunk(spilled_once && !e->spilled);
            if (cur + got >= end) break;
            std::size_t advance = got > overlap ? (got - overlap) : got;
            cur += advance;
            std::uint64_t rel = (cur - sstart) % align;
            if (rel) cur += (align - rel);
        }
        completed += ssize;
    }

    // Final flush + transition to Done.
    bool need_final_spill = false;
    {
        std::lock_guard<std::mutex> elk(e->m);
        if (!local_vas.empty()) {
            e->vas.insert(e->vas.end(), local_vas.begin(), local_vas.end());
            e->raw.insert(e->raw.end(), local_raw.begin(), local_raw.end());
        }
        e->progress.chunks_read     = cur_chunks_read;
        e->progress.chunks_skipped  = cur_chunks_skipped;
        e->progress.bytes_scanned   = cur_bytes_scanned;
        e->progress.hits_so_far     = e->vas.size();
        e->status = ScanStatus::Done;
        e->touched_ts_ms = NowMs();
        need_final_spill = e->spilled;
    }
    if (need_final_spill) {
        // Review M8: capture the disk write status so a failing spill
        // surfaces instead of silently dropping the on-disk mirror.
        bool wrote = WriteRawToDisk(e->spill_dir, e->vas, e->raw, e->generation);
        if (!wrote) {
            std::lock_guard<std::mutex> elk(e->m);
            e->error = "final spill WriteRawToDisk failed";
            // Keep status Done — the snapshot is still in RAM; the
            // operator loses disk durability, nothing else.
        }
    }
}

// ------------------------- RunRefine ------------------------------------

namespace {

// Comparison predicate for refine. Captures prev_raw, curr_raw and
// the saved value_type/op.
using RefineFn = std::function<bool(const std::uint8_t* prev,
                                     const std::uint8_t* curr)>;

RefineFn BuildRefine(const std::string& value_type, const std::string& op,
                     const std::vector<std::uint8_t>& value_le,
                     const std::vector<std::uint8_t>& value_hi_le,
                     const std::vector<std::uint8_t>& delta_le,
                     std::uint64_t tolerance_bits, std::uint32_t width,
                     std::string* err)
{
    double tol = TolFromBits(tolerance_bits, value_type);
    const bool is_float = (value_type == "float");
    const bool is_double = (value_type == "double");
    if (value_type == "string" || value_type == "utf16") {
        if (op == "eq") {
            auto needle = value_le;
            return [needle = std::move(needle)](const std::uint8_t* /*prev*/,
                                                 const std::uint8_t* curr) {
                return std::memcmp(curr, needle.data(), needle.size()) == 0;
            };
        }
        if (op == "changed") return [width](const std::uint8_t* prev, const std::uint8_t* curr) {
            return std::memcmp(prev, curr, width) != 0;
        };
        if (op == "unchanged") return [width](const std::uint8_t* prev, const std::uint8_t* curr) {
            return std::memcmp(prev, curr, width) == 0;
        };
        if (err) *err = "string refine: unsupported op";
        return {};
    }

    auto needle = value_le;
    auto needle_hi = value_hi_le;
    auto delta = delta_le;

    // Typed decoders captured BY VALUE so the returned RefineFn can
    // safely outlive this frame (review M3). ``vt`` holds a copy of
    // ``value_type`` because the raw reference captured by [&] would
    // dangle after BuildRefine returns.
    const std::string vt = value_type;
    auto as_int64 = [vt](const std::uint8_t* p) -> std::int64_t {
        if (vt == "int8") { std::int8_t v; std::memcpy(&v, p, 1); return v; }
        if (vt == "uint8") { std::uint8_t v; std::memcpy(&v, p, 1); return v; }
        if (vt == "int16") { std::int16_t v; std::memcpy(&v, p, 2); return v; }
        if (vt == "uint16") { std::uint16_t v; std::memcpy(&v, p, 2); return v; }
        if (vt == "int32") { std::int32_t v; std::memcpy(&v, p, 4); return v; }
        if (vt == "uint32") { std::uint32_t v; std::memcpy(&v, p, 4); return (std::int64_t)v; }
        if (vt == "int64") { std::int64_t v; std::memcpy(&v, p, 8); return v; }
        if (vt == "uint64") { std::uint64_t v; std::memcpy(&v, p, 8); return (std::int64_t)v; }
        return 0;
    };
    auto as_double = [vt, is_float, is_double, as_int64](const std::uint8_t* p) -> double {
        if (is_float) { float v; std::memcpy(&v, p, 4); return (double)v; }
        if (is_double) { double v; std::memcpy(&v, p, 8); return v; }
        return (double)as_int64(p);
    };

    // Numeric 64-bit paths route through integer compares to avoid
    // the 52-bit double mantissa loss at the high end of int64 /
    // uint64 (review H4). Everything else promotes to double.
    const bool is_u64 = (vt == "uint64");
    const bool is_i64 = (vt == "int64");

    if (op == "eq") {
        if (is_float || is_double) return [needle = std::move(needle), tol, is_float](const std::uint8_t*, const std::uint8_t* c) {
            double a, b;
            if (is_float) { float af, bf; std::memcpy(&af, c, 4); std::memcpy(&bf, needle.data(), 4); a = af; b = bf; }
            else          { std::memcpy(&a, c, 8); std::memcpy(&b, needle.data(), 8); }
            return std::abs(a - b) <= tol;
        };
        return [needle = std::move(needle), width](const std::uint8_t*, const std::uint8_t* c) {
            return std::memcmp(c, needle.data(), width) == 0;
        };
    }
    // lt / gt / between — decode both operands through the typed path
    // (review C1). The old implementation memcpy'd the LE needle bytes
    // directly into a double, which treated e.g. int32(50) as
    // ~2.47e-322 and compared every curr value as "greater than"
    // garbage-tiny.
    if (op == "lt" || op == "gt" || op == "between") {
        if (is_u64) {
            auto u_from = [](const std::vector<std::uint8_t>& b) -> std::uint64_t {
                std::uint64_t v = 0; std::memcpy(&v, b.data(), std::min<std::size_t>(8, b.size())); return v;
            };
            std::uint64_t b_val = u_from(needle);
            std::uint64_t h_val = op == "between" ? u_from(needle_hi) : 0;
            if (op == "between" && b_val > h_val) std::swap(b_val, h_val);
            return [op, b_val, h_val](const std::uint8_t*, const std::uint8_t* c) {
                std::uint64_t a; std::memcpy(&a, c, 8);
                if (op == "lt") return a < b_val;
                if (op == "gt") return a > b_val;
                return a >= b_val && a <= h_val;
            };
        }
        if (is_i64) {
            auto i_from = [](const std::vector<std::uint8_t>& b) -> std::int64_t {
                std::int64_t v = 0; std::memcpy(&v, b.data(), std::min<std::size_t>(8, b.size())); return v;
            };
            std::int64_t b_val = i_from(needle);
            std::int64_t h_val = op == "between" ? i_from(needle_hi) : 0;
            if (op == "between" && b_val > h_val) std::swap(b_val, h_val);
            return [op, b_val, h_val](const std::uint8_t*, const std::uint8_t* c) {
                std::int64_t a; std::memcpy(&a, c, 8);
                if (op == "lt") return a < b_val;
                if (op == "gt") return a > b_val;
                return a >= b_val && a <= h_val;
            };
        }
        // Everything <= 32-bit + float/double: promote to double via the typed decoder.
        double b = as_double(needle.data());
        double h = op == "between" ? as_double(needle_hi.data()) : 0.0;
        if (op == "between" && b > h) std::swap(b, h);
        return [op, b, h, as_double](const std::uint8_t*, const std::uint8_t* c) {
            double a = as_double(c);
            if (op == "lt") return a < b;
            if (op == "gt") return a > b;
            return a >= b && a <= h;
        };
    }
    if (op == "changed") return [width, tol, is_float, is_double](const std::uint8_t* prev, const std::uint8_t* curr) {
        if (is_float || is_double) {
            double a, b;
            if (is_float) { float af, bf; std::memcpy(&af, prev, 4); std::memcpy(&bf, curr, 4); a = af; b = bf; }
            else          { std::memcpy(&a, prev, 8); std::memcpy(&b, curr, 8); }
            return std::abs(a - b) > tol;
        }
        return std::memcmp(prev, curr, width) != 0;
    };
    if (op == "unchanged") return [width, tol, is_float, is_double](const std::uint8_t* prev, const std::uint8_t* curr) {
        if (is_float || is_double) {
            double a, b;
            if (is_float) { float af, bf; std::memcpy(&af, prev, 4); std::memcpy(&bf, curr, 4); a = af; b = bf; }
            else          { std::memcpy(&a, prev, 8); std::memcpy(&b, curr, 8); }
            return std::abs(a - b) <= tol;
        }
        return std::memcmp(prev, curr, width) == 0;
    };
    if (op == "increased") {
        if (is_u64) return [](const std::uint8_t* prev, const std::uint8_t* curr) {
            std::uint64_t a, b; std::memcpy(&a, curr, 8); std::memcpy(&b, prev, 8); return a > b;
        };
        if (is_i64) return [](const std::uint8_t* prev, const std::uint8_t* curr) {
            std::int64_t a, b; std::memcpy(&a, curr, 8); std::memcpy(&b, prev, 8); return a > b;
        };
        return [as_double](const std::uint8_t* prev, const std::uint8_t* curr) {
            return as_double(curr) > as_double(prev);
        };
    }
    if (op == "decreased") {
        if (is_u64) return [](const std::uint8_t* prev, const std::uint8_t* curr) {
            std::uint64_t a, b; std::memcpy(&a, curr, 8); std::memcpy(&b, prev, 8); return a < b;
        };
        if (is_i64) return [](const std::uint8_t* prev, const std::uint8_t* curr) {
            std::int64_t a, b; std::memcpy(&a, curr, 8); std::memcpy(&b, prev, 8); return a < b;
        };
        return [as_double](const std::uint8_t* prev, const std::uint8_t* curr) {
            return as_double(curr) < as_double(prev);
        };
    }
    // increased_by / decreased_by — delta decodes through the typed
    // path as well (review C2). Integer paths kept in 64-bit integer
    // arithmetic for int64 / uint64 precision.
    if (op == "increased_by" || op == "decreased_by") {
        const bool inc = (op == "increased_by");
        if (is_u64) {
            std::uint64_t dv = 0;
            std::memcpy(&dv, delta.data(), std::min<std::size_t>(8, delta.size()));
            return [inc, dv](const std::uint8_t* prev, const std::uint8_t* curr) {
                std::uint64_t a, b; std::memcpy(&a, curr, 8); std::memcpy(&b, prev, 8);
                std::uint64_t diff = inc ? (a - b) : (b - a);
                return diff == dv;
            };
        }
        if (is_i64) {
            std::int64_t dv = 0;
            std::memcpy(&dv, delta.data(), std::min<std::size_t>(8, delta.size()));
            return [inc, dv](const std::uint8_t* prev, const std::uint8_t* curr) {
                std::int64_t a, b; std::memcpy(&a, curr, 8); std::memcpy(&b, prev, 8);
                std::int64_t diff = inc ? (a - b) : (b - a);
                return diff == dv;
            };
        }
        double dv = as_double(delta.data());
        return [inc, dv, as_double, tol](const std::uint8_t* prev, const std::uint8_t* curr) {
            double a = as_double(curr), b = as_double(prev);
            double diff = inc ? (a - b) : (b - a);
            return std::abs(diff - dv) <= tol;
        };
    }
    if (err) *err = "unsupported refine op";
    return {};
}

}  // namespace

void RunRefine(std::shared_ptr<ScanEntry> e,
               const pry::ScanRefineRequest& req,
               const MemReadFn& reader,
               std::uint64_t* dropped_out,
               std::uint64_t* reads_failed_out,
               std::string* err)
{
    std::lock_guard<std::mutex> elk(e->m);
    const std::uint32_t width = e->width;
    std::vector<std::uint8_t> value_le(req.value_le().begin(), req.value_le().end());
    std::vector<std::uint8_t> value_hi_le(req.value_hi_le().begin(), req.value_hi_le().end());
    std::vector<std::uint8_t> delta_le(req.delta_le().begin(), req.delta_le().end());

    auto pred = BuildRefine(e->value_type, req.op(), value_le, value_hi_le,
                            delta_le, req.tolerance_bits(), width, err);
    if (!pred) {
        return;
    }

    // Save undo frame
    UndoFrame frame;
    frame.vas = e->vas;
    frame.raw = e->raw;
    e->undo_bytes += frame.vas.size() * sizeof(std::uint64_t) + frame.raw.size();
    e->undo.push_back(std::move(frame));
    while (e->undo.size() > SCAN_UNDO_DEPTH ||
           e->undo_bytes > SCAN_UNDO_DISK_TOTAL) {
        const auto& f = e->undo.front();
        e->undo_bytes -= f.vas.size() * sizeof(std::uint64_t) + f.raw.size();
        e->undo.erase(e->undo.begin());
    }

    // Sort + coalesce into ~256 KiB windows
    constexpr std::size_t BATCH = 0x40000;
    std::vector<std::size_t> order(e->vas.size());
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(),
              [&](std::size_t a, std::size_t b) { return e->vas[a] < e->vas[b]; });

    std::vector<std::uint64_t> new_vas;
    std::vector<std::uint8_t>  new_raw;
    new_vas.reserve(e->vas.size());
    new_raw.reserve(e->raw.size());

    std::vector<std::uint8_t> buf(BATCH + width);
    std::uint64_t reads_failed = 0;
    std::size_t i = 0;
    while (i < order.size()) {
        if (e->cancel.load()) {
            if (err) *err = "cancelled";
            // Roll back undo push
            const auto& f = e->undo.back();
            e->undo_bytes -= f.vas.size() * sizeof(std::uint64_t) + f.raw.size();
            e->undo.pop_back();
            return;
        }
        std::uint64_t win_start = e->vas[order[i]];
        std::uint64_t win_end = win_start + width;
        std::size_t j = i;
        while (j < order.size() &&
               e->vas[order[j]] + width - win_start <= BATCH) {
            win_end = std::max(win_end, e->vas[order[j]] + width);
            ++j;
        }
        std::size_t n = (std::size_t)(win_end - win_start);
        std::size_t got = 0;
        bool ok = reader ? reader(e->pid, win_start, buf.data(), n, e->space, &got)
                          : false;
        if (!ok) {
            reads_failed += (j - i);
            i = j;
            continue;
        }
        for (std::size_t k = i; k < j; ++k) {
            std::size_t idx = order[k];
            std::uint64_t va = e->vas[idx];
            std::size_t inner = (std::size_t)(va - win_start);
            if (inner + width > got) { reads_failed++; continue; }
            const std::uint8_t* curr = buf.data() + inner;
            const std::uint8_t* prev = e->raw.data() + idx * width;
            if (pred(prev, curr)) {
                new_vas.push_back(va);
                new_raw.insert(new_raw.end(), curr, curr + width);
            }
        }
        i = j;
    }

    std::uint64_t dropped = e->vas.size() - new_vas.size();
    e->vas = std::move(new_vas);
    e->raw = std::move(new_raw);
    e->generation++;
    e->touched_ts_ms = NowMs();
    if (dropped_out) *dropped_out = dropped;
    if (reads_failed_out) *reads_failed_out = reads_failed;
}

// ------------------------- ScanServiceImpl ------------------------------

ScanServiceImpl::ScanServiceImpl(std::string view) : view_(std::move(view)) {}

void ScanServiceImpl::Configure(std::filesystem::path scan_root,
                                 MemReadFn reader)
{
    reader_ = reader;
    registry_.Configure(std::move(scan_root), view_, std::move(reader));
}

namespace {
const char* StatusToString(ScanStatus s)
{
    switch (s) {
        case ScanStatus::Running:     return "running";
        case ScanStatus::Done:        return "done";
        case ScanStatus::Cancelled:   return "cancelled";
        case ScanStatus::Error:       return "error";
        case ScanStatus::Interrupted: return "interrupted";
        case ScanStatus::Capped:      return "capped";
        case ScanStatus::TimedOut:    return "timed_out";
    }
    return "unknown";
}

void FillProgress(pry::ScanProgress* out, const ScanProgressSnapshot& p)
{
    out->set_bytes_scanned(p.bytes_scanned);
    out->set_bytes_total(p.bytes_total);
    out->set_chunks_read(p.chunks_read);
    out->set_chunks_skipped(p.chunks_skipped);
    out->set_hits_so_far(p.hits_so_far);
    out->set_reads_failed(p.reads_failed);
}

bool OwnerMatches(const ScanEntry& e, const std::string& want)
{
    return want.empty() || want == e.owner_client_id;
}
}  // namespace

grpc::Status ScanServiceImpl::Create(grpc::ServerContext*,
                                      const pry::ScanCreateRequest* req,
                                      pry::ScanCreateResponse* resp)
{
    std::string err;
    auto e = registry_.Create(*req, err);
    if (!e) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error(err);
        return grpc::Status::OK;
    }
    resp->mutable_status()->set_ok(true);
    resp->set_scan_id(e->scan_id);
    resp->set_status_s(StatusToString(e->status));
    resp->set_generation(e->generation);
    FillProgress(resp->mutable_progress(), e->progress);
    return grpc::Status::OK;
}

grpc::Status ScanServiceImpl::Refine(grpc::ServerContext*,
                                      const pry::ScanRefineRequest* req,
                                      pry::ScanRefineResponse* resp)
{
    auto e = registry_.Lookup(req->scan_id());
    if (!e) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error("unknown_scan");
        return grpc::Status::OK;
    }
    if (e->status == ScanStatus::Running) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error("not_ready");
        return grpc::Status::OK;
    }
    std::uint64_t dropped = 0, reads_failed = 0;
    std::string err;
    RunRefine(e, *req, reader_, &dropped, &reads_failed, &err);
    if (!err.empty()) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error(err);
        return grpc::Status::OK;
    }
    resp->mutable_status()->set_ok(true);
    resp->set_scan_id(e->scan_id);
    resp->set_generation(e->generation);
    resp->set_hit_count(e->vas.size());
    resp->set_dropped(dropped);
    resp->set_reads_failed(reads_failed);
    resp->set_status_s("done");
    return grpc::Status::OK;
}

grpc::Status ScanServiceImpl::Undo(grpc::ServerContext*,
                                    const pry::ScanUndoRequest* req,
                                    pry::ScanUndoResponse* resp)
{
    auto e = registry_.Lookup(req->scan_id());
    if (!e) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error("unknown_scan");
        return grpc::Status::OK;
    }
    std::lock_guard<std::mutex> elk(e->m);
    if (e->undo.empty()) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error("no_undo");
        return grpc::Status::OK;
    }
    auto frame = std::move(e->undo.back());
    e->undo.pop_back();
    e->undo_bytes -= frame.vas.size() * sizeof(std::uint64_t) + frame.raw.size();
    e->vas = std::move(frame.vas);
    e->raw = std::move(frame.raw);
    if (e->generation) e->generation--;
    resp->mutable_status()->set_ok(true);
    resp->set_scan_id(e->scan_id);
    resp->set_generation(e->generation);
    resp->set_hit_count(e->vas.size());
    return grpc::Status::OK;
}

grpc::Status ScanServiceImpl::Fetch(grpc::ServerContext*,
                                     const pry::ScanFetchRequest* req,
                                     grpc::ServerWriter<pry::ScanFetchChunk>* writer)
{
    auto e = registry_.Lookup(req->scan_id());
    if (!e) {
        pry::ScanFetchChunk chunk;
        chunk.mutable_status()->set_ok(false);
        chunk.mutable_status()->set_error("unknown_scan");
        chunk.set_eof(true);
        writer->Write(chunk);
        return grpc::Status::OK;
    }

    // Review H7: don't hold ``e->m`` across writer->Write() calls — a
    // slow / blocked client would pin Refine / Undo / Destroy on this
    // scan for the entire stream. Snapshot VAs + raw under a short
    // lock, confirm the generation, then stream from the locals.
    std::vector<std::uint64_t> vas;
    std::vector<std::uint8_t>  raw;
    std::uint32_t gen = 0;
    std::uint32_t width = 0;
    ScanStatus status_at_fetch;
    {
        std::lock_guard<std::mutex> elk(e->m);
        if (req->generation() != 0 && req->generation() != e->generation) {
            pry::ScanFetchChunk chunk;
            chunk.mutable_status()->set_ok(false);
            chunk.mutable_status()->set_error("stale_generation");
            chunk.set_generation(e->generation);
            chunk.set_eof(true);
            writer->Write(chunk);
            return grpc::Status::OK;
        }
        status_at_fetch = e->status;
        if (status_at_fetch == ScanStatus::Running) {
            pry::ScanFetchChunk chunk;
            chunk.mutable_status()->set_ok(false);
            chunk.mutable_status()->set_error("not_ready");
            chunk.set_generation(e->generation);
            chunk.set_eof(true);
            writer->Write(chunk);
            return grpc::Status::OK;
        }
        vas = e->vas;   // copies current generation out
        raw = e->raw;
        gen = e->generation;
        width = e->width;
    }

    std::uint64_t off = req->offset();
    std::uint64_t limit = req->limit() ? req->limit() : 1024;
    std::uint64_t total = vas.size();
    while (off < total) {
        pry::ScanFetchChunk chunk;
        chunk.mutable_status()->set_ok(true);
        chunk.set_generation(gen);
        std::uint64_t end = std::min<std::uint64_t>(off + limit, total);
        for (std::uint64_t i = off; i < end; ++i) {
            auto* row = chunk.add_rows();
            row->set_va(vas[i]);
            row->set_raw_value(raw.data() + i * width, width);
        }
        chunk.set_total_remaining(total - end);
        chunk.set_eof(end == total);
        if (!writer->Write(chunk)) return grpc::Status::OK;
        off = end;
    }
    return grpc::Status::OK;
}

grpc::Status ScanServiceImpl::Cancel(grpc::ServerContext*,
                                      const pry::ScanCancelRequest* req,
                                      pry::ScanCancelResponse* resp)
{
    auto e = registry_.Lookup(req->scan_id());
    if (!e) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error("unknown_scan");
        return grpc::Status::OK;
    }
    registry_.Cancel(e);
    resp->mutable_status()->set_ok(true);
    resp->set_scan_id(e->scan_id);
    resp->set_status_s(StatusToString(e->status));
    return grpc::Status::OK;
}

grpc::Status ScanServiceImpl::Destroy(grpc::ServerContext*,
                                       const pry::ScanDestroyRequest* req,
                                       pry::ScanDestroyResponse* resp)
{
    std::uint64_t ram = 0, disk = 0;
    bool ok = registry_.Destroy(req->scan_id(), &ram, &disk);
    if (!ok) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error("unknown_or_busy");
        return grpc::Status::OK;
    }
    resp->mutable_status()->set_ok(true);
    resp->set_scan_id(req->scan_id());
    resp->set_ram_bytes_freed(ram);
    resp->set_disk_bytes_freed(disk);
    return grpc::Status::OK;
}

grpc::Status ScanServiceImpl::List(grpc::ServerContext*,
                                    const pry::ScanListRequest*,
                                    pry::ScanListResponse* resp)
{
    auto snap = registry_.Snapshot();
    resp->mutable_status()->set_ok(true);
    for (const auto& e : snap) {
        std::lock_guard<std::mutex> elk(e->m);
        auto* row = resp->add_entries();
        row->set_scan_id(e->scan_id);
        row->set_pid(e->pid);
        row->set_space(e->space);
        row->set_value_type(e->value_type);
        row->set_width(e->width);
        row->set_status(StatusToString(e->status));
        row->set_generation(e->generation);
        row->set_hit_count(e->vas.size());
        row->set_created_ts_ms(e->created_ts_ms);
        row->set_owner_client_id(e->owner_client_id);
        row->set_disk_bytes(e->disk_bytes);
        row->set_ram_bytes(e->vas.size() * sizeof(std::uint64_t) + e->raw.size());
    }
    return grpc::Status::OK;
}

grpc::Status ScanServiceImpl::Status(grpc::ServerContext*,
                                      const pry::ScanStatusRequest* req,
                                      pry::ScanStatusResponse* resp)
{
    auto e = registry_.Lookup(req->scan_id());
    if (!e) {
        resp->mutable_status()->set_ok(false);
        resp->mutable_status()->set_error("unknown_scan");
        return grpc::Status::OK;
    }
    std::lock_guard<std::mutex> elk(e->m);
    resp->mutable_status()->set_ok(true);
    resp->set_scan_id(e->scan_id);
    resp->set_status_s(StatusToString(e->status));
    resp->set_generation(e->generation);
    resp->set_hit_count(e->vas.size());
    FillProgress(resp->mutable_progress(), e->progress);
    resp->set_error(e->error);
    return grpc::Status::OK;
}

// ------------------------- registration ---------------------------------

void RegisterScanService(grpc::ServerBuilder& builder,
                         std::string view,
                         MemReadFn reader)
{
    // Function-static: C++17 guarantees single-init + thread-safe. The
    // service outlives the server by design (registry state must survive
    // the rebind loop in main.cpp).
    static ScanServiceImpl svc(view);
    static std::once_flag configured;
    std::call_once(configured, [&] {
        svc.Configure(DefaultScanRoot(), std::move(reader));
    });
    builder.RegisterService(&svc);
}

}  // namespace pry::scan
