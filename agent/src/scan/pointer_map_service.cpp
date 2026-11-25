// agent/src/scan/pointer_map_service.cpp
//
// v17 (Memory scanner wave 2 Phase B+C): on-target pointer map engine +
// RPC handlers. See pointer_map_service.hpp for the architecture +
// plan references.
//
// Status: Phase B landed the sweep + registry + disk mirror + module
// snapshot + discovery pass. Phase C wired the Create/Status/List/
// Cancel/Save/Load/Destroy RPC handlers. Scan + Diff are Phase D + E
// (stubbed UNIMPLEMENTED below).
//
// SCAFFOLDING NOTE: StatusResponse.pointer_map_version is currently 0
// for both agents (services_agent.cpp / um_services.cpp). Orchestrator
// refuses with kind='needs_v17' until those flip to 1 after the Phase
// L build-verify. Code here handles real traffic the moment it fires.

#include "pointer_map_service.hpp"

#include "disk_spill.hpp"
#include "scan_ids.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string_view>

#include <windows.h>

namespace pry::scan {

namespace {

std::uint64_t NowMs()
{
    using namespace std::chrono;
    return (std::uint64_t)duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

// Minimal JSON writer — avoids pulling a dep. We only emit flat
// arrays of flat objects, so a tiny escaper is enough. Keys are
// always ASCII literals we control; only values need escaping.
std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

std::string ModulesToJson(const std::vector<ModuleInfo>& mods)
{
    std::ostringstream os;
    os << "[";
    for (std::size_t i = 0; i < mods.size(); ++i) {
        if (i) os << ",";
        const auto& m = mods[i];
        os << "{\"name\":\"" << JsonEscape(m.name) << "\",";
        os << "\"path\":\"" << JsonEscape(m.path) << "\",";
        os << "\"base\":" << m.base << ",";
        os << "\"size\":" << m.size << ",";
        os << "\"timestamp_ms\":" << m.timestamp_ms << "}";
    }
    os << "]";
    return os.str();
}

// Very permissive JSON reader — only parses what ModulesToJson emits.
// Returns false if any row is structurally unexpected.
bool JsonToModules(const std::string& text, std::vector<ModuleInfo>* out)
{
    // We don't carry a real JSON parser; the discovery pass tolerates
    // missing modules.json by returning false here and the caller
    // simply leaves the entry's `modules` vector empty.
    auto find_field = [&](std::size_t from, const char* key,
                           std::string* sval, std::uint64_t* uval) -> std::size_t {
        std::string k = "\"";
        k += key;
        k += "\":";
        auto p = text.find(k, from);
        if (p == std::string::npos) return std::string::npos;
        p += k.size();
        if (sval) {
            if (p >= text.size() || text[p] != '"') return std::string::npos;
            ++p;
            auto end = text.find('"', p);
            if (end == std::string::npos) return std::string::npos;
            *sval = text.substr(p, end - p);
            return end + 1;
        }
        if (uval) {
            std::size_t end = p;
            while (end < text.size() && (std::isdigit((unsigned char)text[end])))
                ++end;
            if (end == p) return std::string::npos;
            *uval = std::strtoull(text.substr(p, end - p).c_str(),
                                   nullptr, 10);
            return end;
        }
        return p;
    };
    std::size_t cursor = 0;
    while (true) {
        auto open = text.find('{', cursor);
        if (open == std::string::npos) break;
        ModuleInfo m;
        std::string tmp;
        auto p = find_field(open, "name", &m.name, nullptr);
        if (p == std::string::npos) return false;
        p = find_field(p, "path", &m.path, nullptr);
        if (p == std::string::npos) return false;
        p = find_field(p, "base", nullptr, &m.base);
        if (p == std::string::npos) return false;
        p = find_field(p, "size", nullptr, &m.size);
        if (p == std::string::npos) return false;
        p = find_field(p, "timestamp_ms", nullptr, &m.timestamp_ms);
        if (p == std::string::npos) return false;
        out->push_back(std::move(m));
        auto close = text.find('}', p);
        if (close == std::string::npos) break;
        cursor = close + 1;
    }
    return true;
}

const char* StatusToWire(PointerMapStatus s);  // fwd decl

std::string MetaToJson(const PointerMapEntry& e)
{
    std::ostringstream os;
    os << "{\"map_id\":\"" << JsonEscape(e.map_id) << "\",";
    os << "\"pid\":" << e.pid << ",";
    os << "\"view\":\"" << JsonEscape(e.view) << "\",";
    os << "\"space\":" << static_cast<int>(e.space) << ",";
    os << "\"created_ts\":" << e.created_ts_ms << ",";
    os << "\"entries\":" << e.entries << ",";
    os << "\"status\":\"" << JsonEscape(StatusToWire(e.status)) << "\",";
    os << "\"pointer_map_version\":1}";
    return os.str();
}

PointerMapStatus StatusFromWire(const std::string& s)
{
    if (s == "running")     return PointerMapStatus::Running;
    if (s == "done")        return PointerMapStatus::Done;
    if (s == "cancelled")   return PointerMapStatus::Cancelled;
    if (s == "error")       return PointerMapStatus::Error;
    if (s == "interrupted") return PointerMapStatus::Interrupted;
    if (s == "capped")      return PointerMapStatus::Capped;
    if (s == "timed_out")   return PointerMapStatus::TimedOut;
    return PointerMapStatus::Done;
}

bool JsonReadMeta(const std::string& text, PointerMapEntry* e)
{
    auto read_str = [&](const char* key, std::string* out) {
        std::string k = "\"";
        k += key;
        k += "\":\"";
        auto p = text.find(k);
        if (p == std::string::npos) return false;
        p += k.size();
        auto end = text.find('"', p);
        if (end == std::string::npos) return false;
        *out = text.substr(p, end - p);
        return true;
    };
    auto read_u64 = [&](const char* key, std::uint64_t* out) {
        std::string k = "\"";
        k += key;
        k += "\":";
        auto p = text.find(k);
        if (p == std::string::npos) return false;
        p += k.size();
        auto end = p;
        while (end < text.size() && std::isdigit((unsigned char)text[end])) ++end;
        if (end == p) return false;
        *out = std::strtoull(text.substr(p, end - p).c_str(), nullptr, 10);
        return true;
    };
    read_str("map_id", &e->map_id);
    std::uint64_t u = 0;
    if (read_u64("pid", &u)) e->pid = (std::uint32_t)u;
    read_str("view", &e->view);
    if (read_u64("space", &u)) e->space = static_cast<pry::MemSpace>(u);
    read_u64("created_ts", &e->created_ts_ms);
    read_u64("entries", &e->entries);
    std::string status_s;
    if (read_str("status", &status_s)) {
        e->status = StatusFromWire(status_s);
    }
    return !e->map_id.empty();
}

// Walks `dir` and sums the size of every regular file. Used by Destroy
// + List to report disk bytes. Non-recursive — the map dir is flat.
std::uint64_t DirBytes(const std::filesystem::path& dir)
{
    std::uint64_t sum = 0;
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) return 0;
    for (auto it = std::filesystem::directory_iterator(dir, ec);
         !ec && it != std::filesystem::directory_iterator(); ++it) {
        auto sz = std::filesystem::file_size(it->path(), ec);
        if (!ec) sum += sz;
    }
    return sum;
}

// "pm<nonce>_NNNN" id allocation. Per-process nonce stays constant for
// a process lifetime; sequence increments atomically so parallel
// Create calls never collide.
std::string NewMapIdNonce()
{
    static const std::string nonce = [] {
        std::mt19937_64 rng((unsigned)NowMs() ^ (unsigned)GetCurrentProcessId());
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%04x",
                      (unsigned)(rng() & 0xffff));
        return std::string(buf);
    }();
    return nonce;
}

void ReleaseMmap(PointerMapEntry& e)
{
    if (e.map_view) {
        ::UnmapViewOfFile(e.map_view);
        e.map_view = nullptr;
    }
    if (e.map_mapping_h) {
        ::CloseHandle((HANDLE)e.map_mapping_h);
        e.map_mapping_h = nullptr;
    }
    if (e.map_file_h) {
        ::CloseHandle((HANDLE)e.map_file_h);
        e.map_file_h = nullptr;
    }
    if (e.idx_view) {
        ::UnmapViewOfFile(e.idx_view);
        e.idx_view = nullptr;
    }
    if (e.idx_mapping_h) {
        ::CloseHandle((HANDLE)e.idx_mapping_h);
        e.idx_mapping_h = nullptr;
    }
    if (e.idx_file_h) {
        ::CloseHandle((HANDLE)e.idx_file_h);
        e.idx_file_h = nullptr;
    }
    e.map_bytes = 0;
    e.idx_bytes = 0;
}

// mmap map.bin + by_target.idx into the entry. Called by Load +
// Create finalizer. Returns false on any OS failure; the caller
// decides whether to error or proceed read-free.
bool MmapMap(PointerMapEntry& e)
{
    ReleaseMmap(e);
    auto open_ro = [](const std::filesystem::path& path,
                       HANDLE* fh, HANDLE* mh, const void** view,
                       std::uint64_t* bytes) -> bool {
        HANDLE f = ::CreateFileW(path.wstring().c_str(), GENERIC_READ,
                                  FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(f, &sz)) {
            ::CloseHandle(f);
            return false;
        }
        if (sz.QuadPart == 0) {
            *fh = f; *mh = nullptr; *view = nullptr; *bytes = 0;
            return true;  // empty file is valid (no hits)
        }
        HANDLE m = ::CreateFileMappingW(f, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!m) {
            ::CloseHandle(f);
            return false;
        }
        void* v = ::MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
        if (!v) {
            ::CloseHandle(m);
            ::CloseHandle(f);
            return false;
        }
        *fh = f;
        *mh = m;
        *view = v;
        *bytes = (std::uint64_t)sz.QuadPart;
        return true;
    };

    HANDLE fh = nullptr, mh = nullptr;
    const void* view = nullptr;
    std::uint64_t bytes = 0;
    if (!open_ro(e.spill_dir / "map.bin",
                 &fh, &mh, &view, &bytes)) {
        return false;
    }
    e.map_file_h = (void*)fh;
    e.map_mapping_h = (void*)mh;
    e.map_view = view;
    e.map_bytes = bytes;

    if (!open_ro(e.spill_dir / "by_target.idx",
                 &fh, &mh, &view, &bytes)) {
        ReleaseMmap(e);
        return false;
    }
    e.idx_file_h = (void*)fh;
    e.idx_mapping_h = (void*)mh;
    e.idx_view = view;
    e.idx_bytes = bytes;
    return true;
}

}  // namespace

// --- free helpers -----------------------------------------------------------

bool IsCanonicalUserVA(std::uint64_t va)
{
    // x64 user space: bits 63:48 clear, va >= 64 KiB (the Windows
    // null-protection region — nothing under 0x10000 is a real
    // pointer), and canonical (upper bits sign-extended for user).
    // Plan review (sweep-no-target-validation): this is the cheap
    // low-value filter — module/VAD-range gating is best-effort
    // today (we don't carry a committed-VAD array into the sweep).
    return va >= 0x10000ULL && (va >> 47) == 0;
}

bool IsCanonicalKernelVA(std::uint64_t va)
{
    // x64 kernel space: bits 63:47 all set (sign-extended).
    return (va >> 47) == 0x1ffffULL;
}

void ReverseLookupTargetRange(const PointerMapRow* rows,
                              const std::uint32_t* by_target_idx,
                              std::size_t count,
                              std::uint64_t target_lo,
                              std::uint64_t target_hi,
                              std::size_t* out_lo,
                              std::size_t* out_hi)
{
    // by_target_idx is sorted asc by rows[by_target_idx[i]].target_va.
    // Binary-search for first index whose target_va >= target_lo, and
    // first whose target_va > target_hi. Caller then iterates
    // by_target_idx[lo..hi) and dereferences rows[].
    auto cmp_lo = [&](std::size_t i, std::uint64_t t) {
        return rows[by_target_idx[i]].target_va < t;
    };
    auto cmp_hi = [&](std::uint64_t t, std::size_t i) {
        return t < rows[by_target_idx[i]].target_va;
    };
    std::size_t lo = 0, hi = count;
    // lower_bound
    while (lo < hi) {
        std::size_t mid = lo + (hi - lo) / 2;
        if (cmp_lo(mid, target_lo)) lo = mid + 1; else hi = mid;
    }
    std::size_t first = lo;
    // upper_bound
    lo = first; hi = count;
    while (lo < hi) {
        std::size_t mid = lo + (hi - lo) / 2;
        if (cmp_hi(target_hi, mid)) hi = mid; else lo = mid + 1;
    }
    *out_lo = first;
    *out_hi = lo;
}

// binary-search a module snapshot
// sorted by ``base`` ASC (as ``PointerMapRegistry::Create`` + umagent/
// kernel enumerate helpers now produce). Returns the module whose
// ``[base, base+size)`` contains ``va``, or nullptr on miss. Zero-size
// entries (loaders see those occasionally) are ignored by skipping them
// in the containment check; sort order is still base-asc so the walk
// over the upper_bound predecessor still works.
const ModuleInfo* FindModuleByVA(std::uint64_t va,
                                 const std::vector<ModuleInfo>& modules)
{
    if (modules.empty()) return nullptr;
    // upper_bound by base: first module whose base > va. The candidate
    // that can contain ``va`` is its predecessor (base <= va).
    std::size_t lo = 0, hi = modules.size();
    while (lo < hi) {
        std::size_t mid = lo + (hi - lo) / 2;
        if (modules[mid].base <= va) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return nullptr;
    const auto& m = modules[lo - 1];
    if (m.size == 0) return nullptr;
    if (va >= m.base && va < m.base + m.size) return &m;
    return nullptr;
}

std::string ClassifyAnchor(std::uint64_t va,
                           const std::vector<ModuleInfo>& modules,
                           std::uint64_t* out_module_off,
                           std::string* out_module_name)
{
    // O(log n) vs the previous
    // linear walk. The module snapshot is sorted at Create time so the
    // search is well-defined.
    if (const ModuleInfo* m = FindModuleByVA(va, modules)) {
        if (out_module_off) *out_module_off = va - m->base;
        if (out_module_name) *out_module_name = m->name;
        // Section-level refinement (image_text / image_rdata /
        // image_data) is a Wave 3 refinement — the agent would
        // have to parse each module's PE sections. Phase D ships
        // with image_unknown as the catch-all.
        return "image_unknown";
    }
    if (out_module_off) *out_module_off = 0;
    if (out_module_name) out_module_name->clear();
    return {};
}

std::string ModuleBasenameLower(const std::string& p)
{
    auto slash = p.find_last_of("\\/");
    std::string b = (slash == std::string::npos) ? p : p.substr(slash + 1);
    for (auto& c : b) c = (char)std::tolower((unsigned char)c);
    return b;
}

// --- registry --------------------------------------------------------------

PointerMapRegistry::PointerMapRegistry() = default;

PointerMapRegistry::~PointerMapRegistry()
{
    // join every live sweep
    // worker before dropping the map entries they capture by shared_ptr.
    // Order:
    //   1. Flip ``cancel`` on every entry under ``m_``, so workers break
    //      out of their span loops at the next check.
    //   2. Join every worker thread under ``workers_m_`` (held WITHOUT
    //      ``m_`` so a worker's final ``e->m`` release can race its
    //      shared_ptr out of ``maps_``).
    //   3. Release mmaps + clear ``maps_`` under ``m_`` — safe now that
    //      no worker is running.
    {
        std::lock_guard<std::mutex> g(m_);
        for (auto& [_, e] : maps_) {
            e->cancel.store(true);
        }
    }
    {
        std::lock_guard<std::mutex> wg(workers_m_);
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
        workers_.clear();
    }
    {
        std::lock_guard<std::mutex> g(m_);
        for (auto& [_, e] : maps_) {
            std::lock_guard<std::mutex> eg(e->m);
            ReleaseMmap(*e);
        }
        maps_.clear();
    }
}

void PointerMapRegistry::Configure(std::filesystem::path scan_root,
                                   std::string view,
                                   MemReadFn reader,
                                   ModuleEnumFn enumerate)
{
    {
        std::lock_guard<std::mutex> g(m_);
        scan_root_ = std::move(scan_root);
        view_ = std::move(view);
        reader_ = std::move(reader);
        enumerate_ = std::move(enumerate);
    }
    DiscoverFromDisk();
}

std::shared_ptr<PointerMapEntry> PointerMapRegistry::Create(
    const pry::PointerMapCreateRequest& req, std::string& err)
{
    if (req.spans().empty()) {
        err = "no spans";
        return nullptr;
    }
    if (!reader_) {
        err = "registry not configured";
        return nullptr;
    }
    if (!req.map_id().empty() && !ValidId(req.map_id())) {
        err = "invalid map_id: must match [A-Za-z0-9_-]{1,64}";
        return nullptr;
    }
    auto e = std::make_shared<PointerMapEntry>();
    e->map_id = req.map_id();
    if (e->map_id.empty()) {
        // Share the ID-minting counter with Load (via MintMapId) so
        // the first Create + first Load don't collide on pm<nonce>_0001
        // (plan review follow-up: these used separate static locals).
        e->map_id = MintMapId();
    }
    e->owner_client_id = req.owner_client_id();
    e->pid = req.pid();
    e->space = req.space();
    e->view = view_;
    e->max_candidates = req.max_candidates()
        ? std::min<std::uint64_t>(req.max_candidates(),
                                   POINTER_MAP_CANDIDATE_MAX)
        : POINTER_MAP_CANDIDATE_MAX;
    e->created_ts_ms = NowMs();
    e->touched_ts_ms = e->created_ts_ms;
    for (const auto& s : req.spans()) {
        e->spans.emplace_back(s.va(), s.size());
        e->progress.bytes_total += s.size();
    }
    e->progress.regions_total = e->spans.size();
    e->spill_dir = scan_root_ / "pointer_maps" / view_ / e->map_id;

    // cap check BEFORE
    // module enumeration so a caller spamming over-cap Creates
    // doesn't pay the (potentially driver-roundtrip) enum cost
    // per rejected request. Duplicate map_id is also fatal.
    {
        std::lock_guard<std::mutex> g(m_);
        if (maps_.size() >= POINTER_MAP_COUNT_PER_MACHINE) {
            err = "pointer_map_full";
            return nullptr;
        }
        if (maps_.count(e->map_id)) {
            err = "map_id already exists";
            return nullptr;
        }
    }

    // Module snapshot right at Create time. Soft failure is OK —
    // reverse scan + diff will classify as image_unknown.
    if (enumerate_) {
        enumerate_(e->pid, &e->modules);
    }
    // sort modules by base
    // ASC once at Create so ``ClassifyAnchor`` + ``CanonicalFromVA``
    // (and DissectCompare, coming in P1) can binary-search instead
    // of walking O(n) per slot. 500 DLLs × 4096 slots = 2 M compares
    // today; this takes it to ~24 K.
    std::sort(e->modules.begin(), e->modules.end(),
              [](const ModuleInfo& a, const ModuleInfo& b) {
                  return a.base < b.base;
              });

    {
        std::lock_guard<std::mutex> g(m_);
        // Re-check post-enum: a racing Create could have taken the last
        // slot or claimed the id while we were enumerating modules.
        if (maps_.size() >= POINTER_MAP_COUNT_PER_MACHINE) {
            err = "pointer_map_full";
            return nullptr;
        }
        if (maps_.count(e->map_id)) {
            err = "map_id already exists";
            return nullptr;
        }
        maps_[e->map_id] = e;
    }

    // hand the sweep off to a
    // JOINABLE thread the registry owns. ``~PointerMapRegistry`` joins
    // these; older agents detached here and could lose a race
    // against entry destruction. Opportunistic reap first so the vector
    // doesn't grow unbounded across the registry's lifetime.
    {
        std::lock_guard<std::mutex> wg(workers_m_);
        for (auto it = workers_.begin(); it != workers_.end(); ) {
            if (it->joinable()) {
                // joinable() is true both for running AND finished-but-
                // not-yet-joined threads; there's no portable "is done"
                // probe. We leave running threads in place and only
                // compact non-joinable slots. Reap at dtor.
                ++it;
            } else {
                it = workers_.erase(it);
            }
        }
        workers_.emplace_back(&PointerMapRegistry::SweepWorker, this, e);
    }
    return e;
}

std::shared_ptr<PointerMapEntry> PointerMapRegistry::Lookup(
    const std::string& map_id) const
{
    std::lock_guard<std::mutex> g(m_);
    auto it = maps_.find(map_id);
    return it == maps_.end() ? nullptr : it->second;
}

bool PointerMapRegistry::Destroy(const std::string& map_id, bool keep_disk,
                                 std::uint64_t* ram_freed,
                                 std::uint64_t* disk_freed)
{
    std::shared_ptr<PointerMapEntry> e;
    std::filesystem::path root;
    {
        std::lock_guard<std::mutex> g(m_);
        auto it = maps_.find(map_id);
        if (it == maps_.end()) return false;
        e = it->second;
        maps_.erase(it);
        // captured under m_ (SpillRoot() would take m_ again while e->m is
        // held below: the dtor locks m_ then e->m)
        if (!scan_root_.empty() && !view_.empty()) {
            root = scan_root_ / "pointer_maps" / view_;
        }
    }
    e->cancel.store(true);
    std::lock_guard<std::mutex> eg(e->m);
    std::uint64_t rbytes = e->map_bytes + e->idx_bytes;
    ReleaseMmap(*e);
    std::uint64_t dbytes = 0;
    // Never delete a folder we don't own (a Loaded map lives in the
    // caller's remote_path), and never anything outside our spill root.
    if (!keep_disk && e->owned && !e->spill_dir.empty()) {
        std::error_code ec;
        const std::uint64_t before = DirBytes(e->spill_dir);
        if (RemoveAllUnder(root, e->spill_dir, ec)) {
            dbytes = before;
        }
    }
    if (ram_freed) *ram_freed = rbytes;
    if (disk_freed) *disk_freed = dbytes;
    return true;
}

std::vector<std::shared_ptr<PointerMapEntry>>
PointerMapRegistry::Snapshot() const
{
    std::vector<std::shared_ptr<PointerMapEntry>> out;
    std::lock_guard<std::mutex> g(m_);
    out.reserve(maps_.size());
    for (auto& [_, e] : maps_) out.push_back(e);
    return out;
}

std::uint64_t PointerMapRegistry::TotalDiskBytes() const
{
    std::uint64_t sum = 0;
    for (auto& e : Snapshot()) {
        std::lock_guard<std::mutex> eg(e->m);
        sum += e->disk_bytes;
    }
    return sum;
}

void PointerMapRegistry::Cancel(const std::shared_ptr<PointerMapEntry>& e)
{
    if (!e) return;
    e->cancel.store(true);
}

bool PointerMapRegistry::RegisterLoaded(std::shared_ptr<PointerMapEntry> e)
{
    if (!e || e->map_id.empty()) return false;
    std::lock_guard<std::mutex> g(m_);
    if (maps_.count(e->map_id)) return false;
    maps_[e->map_id] = std::move(e);
    return true;
}

std::string PointerMapRegistry::MintMapId()
{
    static std::atomic<std::uint32_t> seq{0};
    char buf[32];
    std::snprintf(buf, sizeof(buf), "pm%s_%04u",
                  NewMapIdNonce().c_str(),
                  (unsigned)(++seq));
    return buf;
}

std::filesystem::path PointerMapRegistry::SpillRoot() const
{
    std::lock_guard<std::mutex> g(m_);
    if (scan_root_.empty() || view_.empty()) return {};
    return scan_root_ / "pointer_maps" / view_;
}

void PointerMapRegistry::DiscoverFromDisk()
{
    if (scan_root_.empty() || view_.empty()) return;
    auto root = scan_root_ / "pointer_maps" / view_;
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) return;
    for (auto it = std::filesystem::directory_iterator(root, ec);
         !ec && it != std::filesystem::directory_iterator(); ++it) {
        if (!it->is_directory(ec)) continue;
        auto dir = it->path();
        auto meta_path = dir / "meta.json";
        if (!std::filesystem::exists(meta_path, ec)) continue;
        std::ifstream mf(meta_path, std::ios::binary);
        std::ostringstream ss;
        ss << mf.rdbuf();
        auto text = ss.str();
        auto e = std::make_shared<PointerMapEntry>();
        e->status = PointerMapStatus::Done;  // default when meta lacks status
        if (!JsonReadMeta(text, e.get())) continue;
        e->spill_dir = dir;
        // view overrides whatever meta said: the registry we're adding
        // to belongs to this process's view.
        e->view = view_;
        e->disk_bytes = DirBytes(dir);
        // Modules reloaded lazily on Load — keep the metadata light.
        std::lock_guard<std::mutex> g(m_);
        if (!maps_.count(e->map_id)) {
            maps_[e->map_id] = e;
        }
    }
}

// --- sweep worker ---------------------------------------------------------

void PointerMapRegistry::SweepWorker(std::shared_ptr<PointerMapEntry> e)
{
    std::vector<PointerMapRow> rows;
    rows.reserve(1u << 20);  // 16 MiB upfront is fine; grows on hit.

    const std::uint64_t ALIGN = 8;  // x64 pointer size
    const std::uint64_t BATCH = POINTER_MAP_READ_BATCH_BYTES;
    std::vector<std::uint8_t> buf(BATCH + ALIGN);

    auto accept_target = [&](std::uint64_t va) {
        if (e->space == pry::KERNEL) {
            return IsCanonicalKernelVA(va) || IsCanonicalUserVA(va);
        }
        return IsCanonicalUserVA(va);
    };

    for (const auto& [span_va, span_size] : e->spans) {
        if (e->cancel.load()) break;
        std::uint64_t cur = span_va;
        std::uint64_t end = span_va + span_size;
        // Align `cur` up to ALIGN.
        if (cur & (ALIGN - 1)) cur = (cur + ALIGN - 1) & ~(ALIGN - 1);
        while (cur < end && !e->cancel.load()) {
            std::size_t want = (std::size_t)std::min<std::uint64_t>(BATCH, end - cur);
            std::size_t got = 0;
            bool ok = reader_(e->pid, cur, buf.data(), want, e->space, &got);
            if (!ok || got < ALIGN) {
                e->progress.chunks_skipped.fetch_add(1);
                cur += want;
                continue;
            }
            // Walk aligned slots in the chunk.
            std::size_t slots = got / ALIGN;
            for (std::size_t i = 0; i < slots; ++i) {
                std::uint64_t val;
                std::memcpy(&val, buf.data() + i * ALIGN, ALIGN);
                if (!accept_target(val)) continue;
                rows.push_back({cur + i * ALIGN, val});
                if (rows.size() >= e->max_candidates) {
                    std::lock_guard<std::mutex> eg(e->m);
                    e->status = PointerMapStatus::Capped;
                    e->error = "candidate cap reached";
                    goto finalize;
                }
            }
            e->progress.bytes_scanned.fetch_add(got);
            e->progress.candidates_so_far.store(rows.size());
            cur += got;
        }
        e->progress.regions_scanned.fetch_add(1);
    }

finalize:
    // Sort by source_va ascending (sweep already walks in order per
    // span, but spans may overlap or be out of order; a final sort
    // guarantees the binary-search invariant for later reverse scans).
    std::sort(rows.begin(), rows.end(),
              [](const PointerMapRow& a, const PointerMapRow& b) {
                  return a.source_va < b.source_va;
              });

    // Build by_target.idx: indices sorted by rows[i].target_va asc.
    std::vector<std::uint32_t> idx(rows.size());
    for (std::size_t i = 0; i < rows.size(); ++i) {
        idx[i] = static_cast<std::uint32_t>(i);
    }
    std::sort(idx.begin(), idx.end(),
              [&](std::uint32_t a, std::uint32_t b) {
                  return rows[a].target_va < rows[b].target_va;
              });

    // Write to disk.
    std::error_code ec;
    std::filesystem::create_directories(e->spill_dir, ec);
    bool wrote = WriteAtomic(e->spill_dir / "map.bin", rows.data(),
                             rows.size() * sizeof(PointerMapRow));
    if (wrote) {
        wrote = WriteAtomic(e->spill_dir / "by_target.idx", idx.data(),
                            idx.size() * sizeof(std::uint32_t));
    }
    if (wrote) {
        auto mj = ModulesToJson(e->modules);
        wrote = WriteAtomic(e->spill_dir / "modules.json",
                            mj.data(), mj.size());
    }
    {
        std::lock_guard<std::mutex> eg(e->m);
        if (!wrote) {
            if (e->status == PointerMapStatus::Running) {
                e->status = PointerMapStatus::Error;
                e->error = "disk write failed";
            }
        } else {
            e->entries = rows.size();
            e->disk_bytes = DirBytes(e->spill_dir);
            if (e->cancel.load() &&
                e->status == PointerMapStatus::Running) {
                e->status = PointerMapStatus::Cancelled;
            } else if (e->status == PointerMapStatus::Running) {
                e->status = PointerMapStatus::Done;
            }
        }
        // Meta ONLY lands when the core files wrote OK — the meta
        // file is also the discovery marker, so a half-written map
        // must stay invisible to a restart. The on-disk map.bin /
        // by_target.idx remnants (if any) get cleaned on the next
        // same-id Create.
        if (wrote) {
            auto meta = MetaToJson(*e);
            WriteAtomic(e->spill_dir / "meta.json", meta.data(), meta.size());
        }
    }

    // mmap for immediate Scan/Diff availability.
    {
        std::lock_guard<std::mutex> eg(e->m);
        MmapMap(*e);
    }
}

// --- service class ---------------------------------------------------------

PointerMapServiceImpl::PointerMapServiceImpl(std::string view)
    : view_(std::move(view))
{}

void PointerMapServiceImpl::Configure(std::filesystem::path scan_root,
                                      MemReadFn reader,
                                      ModuleEnumFn enumerate)
{
    reader_ = reader;
    enumerate_ = enumerate;
    registry_.Configure(std::move(scan_root), view_, reader_, enumerate_);
}

namespace {

void FillStatus(pry::OpStatus* s, bool ok, const std::string& err,
                const std::string& kind = {})
{
    s->set_ok(ok);
    if (!ok) s->set_error(err);
    // typed error-kind slug so
    // the orchestrator doesn't have to substring-match ``error``. Only
    // set when the caller explicitly named a kind; otherwise leave it
    // empty for the orchestrator to classify from the message.
    if (!kind.empty()) s->set_kind(kind);
}

const char* StatusToWire(PointerMapStatus s)
{
    switch (s) {
        case PointerMapStatus::Running:     return "running";
        case PointerMapStatus::Done:        return "done";
        case PointerMapStatus::Cancelled:   return "cancelled";
        case PointerMapStatus::Error:       return "error";
        case PointerMapStatus::Interrupted: return "interrupted";
        case PointerMapStatus::Capped:      return "capped";
        case PointerMapStatus::TimedOut:    return "timed_out";
    }
    return "";
}

void FillProgress(pry::PointerMapProgress* p,
                  const PointerMapProgressSnapshot& s)
{
    p->set_regions_scanned(s.regions_scanned.load());
    p->set_regions_total(s.regions_total);
    p->set_bytes_scanned(s.bytes_scanned.load());
    p->set_bytes_total(s.bytes_total);
    p->set_candidates_so_far(s.candidates_so_far.load());
    p->set_chunks_skipped(s.chunks_skipped.load());
}

}  // namespace

grpc::Status PointerMapServiceImpl::Create(
    grpc::ServerContext*,
    const pry::PointerMapCreateRequest* req,
    pry::PointerMapCreateResponse* resp)
{
    std::string err;
    auto e = registry_.Create(*req, err);
    if (!e) {
        FillStatus(resp->mutable_status(), false, err);
        return grpc::Status::OK;
    }
    resp->set_map_id(e->map_id);
    resp->set_status_s(StatusToWire(e->status));
    FillProgress(resp->mutable_progress(), e->progress);
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

grpc::Status PointerMapServiceImpl::Status(
    grpc::ServerContext*,
    const pry::PointerMapStatusRequest* req,
    pry::PointerMapStatusResponse* resp)
{
    auto e = registry_.Lookup(req->map_id());
    if (!e) {
        FillStatus(resp->mutable_status(), false, "map not found");
        return grpc::Status::OK;
    }
    std::lock_guard<std::mutex> g(e->m);
    resp->set_map_id(e->map_id);
    resp->set_status_s(StatusToWire(e->status));
    FillProgress(resp->mutable_progress(), e->progress);
    resp->set_entries(e->entries);
    resp->set_disk_bytes(e->disk_bytes);
    resp->set_error(e->error);
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

grpc::Status PointerMapServiceImpl::List(
    grpc::ServerContext*,
    const pry::PointerMapListRequest*,
    pry::PointerMapListResponse* resp)
{
    auto snap = registry_.Snapshot();
    for (auto& e : snap) {
        std::lock_guard<std::mutex> g(e->m);
        auto* row = resp->add_entries();
        row->set_map_id(e->map_id);
        row->set_pid(e->pid);
        row->set_space(e->space);
        row->set_status_s(StatusToWire(e->status));
        row->set_entries(e->entries);
        row->set_disk_bytes(e->disk_bytes);
        row->set_created_ts_ms(e->created_ts_ms);
        // advertise discovery-
        // without-mmap so the orchestrator knows to call Load before
        // Scan/Diff. ``DiscoverFromDisk`` seeds entries in Done state
        // but doesn't mmap them (RAM-cheap at startup); a Scan against
        // such an entry fails with "map not mmap'd" until Load.
        row->set_needs_load(e->disk_bytes > 0 && e->map_view == nullptr);
    }
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

grpc::Status PointerMapServiceImpl::Cancel(
    grpc::ServerContext*,
    const pry::PointerMapCancelRequest* req,
    pry::PointerMapCancelResponse* resp)
{
    auto e = registry_.Lookup(req->map_id());
    if (!e) {
        FillStatus(resp->mutable_status(), false, "map not found");
        return grpc::Status::OK;
    }
    registry_.Cancel(e);
    resp->set_map_id(e->map_id);
    {
        std::lock_guard<std::mutex> g(e->m);
        resp->set_status_s(StatusToWire(e->status));
    }
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

// Save copies four files into a caller-chosen folder (the documented UX is
// e.g. remote_path='D:/maps/explorer_pre'), so it can't be confined to the
// spill root — but it must be an absolute, non-root path outside the
// Windows directory, and nothing ever deletes it later (Load marks the
// entry not-owned).
static bool SaveTargetOk(const std::filesystem::path& dst, std::string* why)
{
    if (dst.empty() || !dst.is_absolute()) {
        *why = "remote_path must be an absolute path";
        return false;
    }
    std::error_code ec;
    auto c = std::filesystem::weakly_canonical(dst, ec);
    if (ec) {
        *why = "remote_path: " + ec.message();
        return false;
    }
    if (c == c.root_path() || !c.has_relative_path()) {
        *why = "remote_path must not be a volume root";
        return false;
    }
    wchar_t win[MAX_PATH]{};
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    if (n && n < MAX_PATH) {
        std::filesystem::path w(win);
        std::error_code ec2;
        if (std::filesystem::equivalent(w, c, ec2) || PathStrictlyUnder(w, c)) {
            *why = "remote_path must not be inside the Windows directory";
            return false;
        }
    }
    return true;
}

grpc::Status PointerMapServiceImpl::Save(
    grpc::ServerContext*,
    const pry::PointerMapSaveRequest* req,
    pry::PointerMapSaveResponse* resp)
{
    auto e = registry_.Lookup(req->map_id());
    if (!e) {
        FillStatus(resp->mutable_status(), false, "map not found");
        return grpc::Status::OK;
    }
    std::lock_guard<std::mutex> g(e->m);
    if (e->status != PointerMapStatus::Done &&
        e->status != PointerMapStatus::Capped) {
        FillStatus(resp->mutable_status(), false, "map not terminal");
        return grpc::Status::OK;
    }
    std::filesystem::path dst = req->remote_path();
    std::error_code ec;
    {
        std::string why;
        if (!SaveTargetOk(dst, &why)) {
            FillStatus(resp->mutable_status(), false, why);
            return grpc::Status::OK;
        }
    }
    std::filesystem::create_directories(dst, ec);
    if (ec) {
        FillStatus(resp->mutable_status(), false,
                   std::string("mkdir failed: ") + ec.message());
        return grpc::Status::OK;
    }
    // Core files MUST exist for a legitimate save; the incidentals
    // (modules.json, meta.json) are best-effort. Refuse rather than
    // silently archiving half-baked data.
    for (auto core : {"map.bin", "by_target.idx"}) {
        auto src = e->spill_dir / core;
        if (!std::filesystem::exists(src, ec)) {
            FillStatus(resp->mutable_status(), false,
                       std::string("core file missing on source: ") + core);
            return grpc::Status::OK;
        }
    }
    std::uint64_t wrote = 0;
    for (auto name : {"map.bin", "by_target.idx",
                      "modules.json", "meta.json"}) {
        auto src = e->spill_dir / name;
        if (!std::filesystem::exists(src, ec)) continue;
        auto sz = std::filesystem::file_size(src, ec);
        std::filesystem::copy_file(src, dst / name,
            std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            FillStatus(resp->mutable_status(), false,
                       std::string("copy failed: ") + ec.message());
            return grpc::Status::OK;
        }
        wrote += sz;
    }
    resp->set_bytes_written(wrote);
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

grpc::Status PointerMapServiceImpl::Load(
    grpc::ServerContext*,
    const pry::PointerMapLoadRequest* req,
    pry::PointerMapLoadResponse* resp)
{
    std::filesystem::path src = req->remote_path();
    std::error_code ec;
    if (!std::filesystem::exists(src / "map.bin", ec)) {
        FillStatus(resp->mutable_status(), false, "map.bin missing");
        return grpc::Status::OK;
    }
    if (!req->map_id().empty() && !ValidId(req->map_id())) {
        FillStatus(resp->mutable_status(), false,
                   "invalid map_id: must match [A-Za-z0-9_-]{1,64}");
        return grpc::Status::OK;
    }
    auto e = std::make_shared<PointerMapEntry>();
    e->view = view_;
    e->status = PointerMapStatus::Done;
    // The folder belongs to the caller (typically a Save target): Destroy
    // with keep_disk=false must release the mapping, NOT delete it.
    e->owned = false;
    e->map_id = req->map_id();
    if (e->map_id.empty()) e->map_id = registry_.MintMapId();
    // Mmap files in place. Save/Load within one machine is the common
    // case; cross-machine load means the operator copied the files
    // under scan_root/pointer_maps/view/ first. Either way, we open
    // what's at `src` — we don't re-copy.
    e->spill_dir = src;
    {
        auto meta_path = src / "meta.json";
        std::ifstream mf(meta_path, std::ios::binary);
        if (mf) {
            std::ostringstream ss;
            ss << mf.rdbuf();
            // Carry the on-disk pid/view across Load so the diff path
            // can refuse cross-view loads. The loader's own view_
            // remains authoritative for registry lookup.
            PointerMapEntry meta_e;
            if (JsonReadMeta(ss.str(), &meta_e)) {
                e->pid = meta_e.pid;
                e->space = meta_e.space;
                e->created_ts_ms = meta_e.created_ts_ms;
            }
        }
    }
    {
        auto mods_path = src / "modules.json";
        std::ifstream mf(mods_path, std::ios::binary);
        if (mf) {
            std::ostringstream ss;
            ss << mf.rdbuf();
            JsonToModules(ss.str(), &e->modules);
        }
    }
    if (!MmapMap(*e)) {
        FillStatus(resp->mutable_status(), false, "mmap failed");
        return grpc::Status::OK;
    }
    // Size validation (plan review: oob-read-on-crafted-map): map.bin
    // must be a whole multiple of 16 bytes, by_target.idx must be the
    // same count × 4 bytes, and no idx[] value may index past the
    // row array. We don't walk the whole idx here (that's O(N)) —
    // just the length check — but the invariant is enough to prevent
    // the OOB read the review flagged.
    if (e->map_bytes % sizeof(PointerMapRow) != 0) {
        ReleaseMmap(*e);
        FillStatus(resp->mutable_status(), false,
                   "map.bin size not a multiple of PointerMapRow");
        return grpc::Status::OK;
    }
    std::uint64_t row_count = e->map_bytes / sizeof(PointerMapRow);
    if (e->idx_bytes != row_count * sizeof(std::uint32_t)) {
        ReleaseMmap(*e);
        FillStatus(resp->mutable_status(), false,
                   "by_target.idx size mismatch vs map.bin row count");
        return grpc::Status::OK;
    }
    e->entries = row_count;
    e->disk_bytes = DirBytes(src);
    if (!registry_.RegisterLoaded(e)) {
        ReleaseMmap(*e);
        FillStatus(resp->mutable_status(), false,
                   "map_id already registered");
        return grpc::Status::OK;
    }
    resp->set_map_id(e->map_id);
    resp->set_entries(e->entries);
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

grpc::Status PointerMapServiceImpl::Destroy(
    grpc::ServerContext*,
    const pry::PointerMapDestroyRequest* req,
    pry::PointerMapDestroyResponse* resp)
{
    std::uint64_t rbytes = 0, dbytes = 0;
    if (!registry_.Destroy(req->map_id(), req->keep_disk(),
                           &rbytes, &dbytes)) {
        FillStatus(resp->mutable_status(), false, "map not found");
        return grpc::Status::OK;
    }
    resp->set_ram_bytes_freed(rbytes);
    resp->set_disk_bytes_freed(dbytes);
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

// --- Phase D: reverse pointer scan (BFS) ----------------------------------
//
// BFS over (target → source) lookups using by_target.idx. Terminates
// at image-section anchors when static_only=true. Caps enforced per
// plan §2.7 — fanout_per_level, max_depth, max_results, wall_ms.
// Deterministic: chains sorted (depth ASC, anchor_va ASC, offsets ASC)
// before returning.
//
// Cycle prevention: each Frontier carries its own `visited` set of
// source VAs seen on the walk down from `target_va`. Before emitting
// a candidate at a given depth, we check whether its source_va is
// already in the branch's visited set — if so, the candidate would
// close a cycle and is skipped. Children inherit the parent's
// visited set plus the current candidate (recursion-style; a
// sibling branch's visited set doesn't affect this one).

namespace {

struct ScanChainInProgress {
    std::uint64_t anchor_va;
    std::vector<std::uint64_t> offsets;  // target - source_at_depth, ...
    std::uint32_t depth;                  // == offsets.size() upon finalize
    bool is_static;
    std::string anchor_module;
    std::uint64_t anchor_module_off;
    std::string anchor_class;
};

bool ChainLess(const ScanChainInProgress& a, const ScanChainInProgress& b)
{
    if (a.depth != b.depth) return a.depth < b.depth;
    if (a.anchor_va != b.anchor_va) return a.anchor_va < b.anchor_va;
    return a.offsets < b.offsets;
}

}  // namespace

grpc::Status PointerMapServiceImpl::Scan(
    grpc::ServerContext* ctx,
    const pry::PointerScanRequest* req,
    pry::PointerScanResponse* resp)
{
    auto e = registry_.Lookup(req->map_id());
    if (!e) {
        FillStatus(resp->mutable_status(), false, "map not found");
        return grpc::Status::OK;
    }
    std::lock_guard<std::mutex> g(e->m);
    if (!e->map_view || !e->idx_view) {
        FillStatus(resp->mutable_status(), false, "map not mmap'd");
        return grpc::Status::OK;
    }

    const auto* rows = static_cast<const PointerMapRow*>(e->map_view);
    const auto* idx  = static_cast<const std::uint32_t*>(e->idx_view);
    const std::size_t count = e->entries;

    const std::uint32_t max_depth =
        std::min<std::uint32_t>(req->max_depth() ? req->max_depth()
                                                  : POINTER_SCAN_MAX_DEPTH,
                                POINTER_SCAN_MAX_DEPTH);
    const std::uint32_t max_offset =
        std::min<std::uint32_t>(req->max_offset() ? req->max_offset()
                                                   : POINTER_SCAN_MAX_OFFSET,
                                POINTER_SCAN_MAX_OFFSET);
    const std::uint32_t max_results =
        std::min<std::uint32_t>(req->max_results() ? req->max_results()
                                                    : POINTER_SCAN_MAX_RESULTS,
                                POINTER_SCAN_MAX_RESULTS);
    const std::uint32_t fanout =
        std::min<std::uint32_t>(req->fanout_per_level() ? req->fanout_per_level()
                                                        : POINTER_SCAN_FANOUT_PER_LEVEL,
                                POINTER_SCAN_FANOUT_PER_LEVEL);
    const std::uint32_t wall_ms =
        std::min<std::uint32_t>(req->wall_ms() ? req->wall_ms()
                                               : POINTER_SCAN_WALL_MS,
                                POINTER_SCAN_WALL_MS);
    const bool static_only = req->static_only();

    using clock = std::chrono::steady_clock;
    // compute wall_ms_actual
    // from a ``start`` captured at entry, not back-derived from
    // ``deadline - wall_ms``. Both yield the same number today, but the
    // deadline-derived form breaks the moment anything else (cancel,
    // early-break) short-circuits the computation.
    auto start = clock::now();
    auto deadline = start + std::chrono::milliseconds(wall_ms);
    bool wall_exceeded = false;
    bool fanout_exceeded = false;

    // BFS frontier: (va_of_interest, offset_chain_so_far, visited).
    // `offsets[0]` is nearest to the anchor (the static root); the
    // last entry is nearest to the leaf target. `visited` is the set
    // of source VAs reached on this branch — admitting a candidate
    // whose source_va is already visited would close a cycle.
    struct Frontier {
        std::uint64_t target;
        std::vector<std::uint64_t> offsets;
        std::unordered_set<std::uint64_t> visited;
    };
    std::vector<ScanChainInProgress> finished;
    Frontier seed;
    seed.target = req->target_va();
    seed.visited.insert(req->target_va());
    std::vector<Frontier> cur;
    cur.push_back(std::move(seed));
    std::uint64_t candidates_examined = 0;
    bool truncated = false;

    for (std::uint32_t depth = 1; depth <= max_depth; ++depth) {
        // honour gRPC cancellation
        // from the top of every outer-loop iteration. A 15 s BFS burning
        // CPU after the client disconnected is a real incident class.
        if (ctx && ctx->IsCancelled()) { truncated = true; break; }
        if (clock::now() >= deadline) { wall_exceeded = true; break; }
        if (cur.empty()) break;
        if (finished.size() >= max_results) break;
        std::vector<Frontier> next;

        std::uint32_t level_candidates = 0;
        for (const auto& fr : cur) {
            if (ctx && ctx->IsCancelled()) { truncated = true; break; }
            if (clock::now() >= deadline) { wall_exceeded = true; break; }
            if (level_candidates >= fanout) {
                truncated = true;
                fanout_exceeded = true;
                break;
            }

            // Reverse range lookup: rows whose target_va lies in
            // [fr.target - max_offset, fr.target].
            std::uint64_t lo_va = (fr.target > max_offset)
                ? (fr.target - max_offset) : 0;
            std::size_t lo = 0, hi = 0;
            ReverseLookupTargetRange(rows, idx, count,
                                      lo_va, fr.target, &lo, &hi);
            for (std::size_t i = lo; i < hi; ++i) {
                if (finished.size() >= max_results) {
                    truncated = true;
                    fanout_exceeded = true;
                    break;
                }
                if (level_candidates >= fanout) {
                    truncated = true;
                    fanout_exceeded = true;
                    break;
                }
                candidates_examined++;
                level_candidates++;
                const auto& row = rows[idx[i]];

                // Cycle prevention (plan §4 Phase D): skip candidates
                // whose source_va already appears on this branch.
                if (fr.visited.find(row.source_va) != fr.visited.end()) {
                    continue;
                }

                std::uint64_t off = fr.target - row.target_va;

                std::uint64_t mod_off = 0;
                std::string mod_name;
                std::string klass = ClassifyAnchor(row.source_va,
                                                    e->modules,
                                                    &mod_off, &mod_name);
                bool is_static = !klass.empty();

                ScanChainInProgress chain;
                chain.anchor_va = row.source_va;
                chain.offsets = fr.offsets;
                chain.offsets.insert(chain.offsets.begin(), off);
                chain.depth = depth;
                chain.is_static = is_static;
                chain.anchor_module = mod_name;
                chain.anchor_module_off = mod_off;
                chain.anchor_class = is_static
                    ? klass
                    : std::string("other");

                auto push_child = [&]() {
                    if (depth >= max_depth) return;
                    Frontier f;
                    f.target = row.source_va;
                    f.offsets = chain.offsets;
                    f.visited = fr.visited;
                    f.visited.insert(row.source_va);
                    next.push_back(std::move(f));
                };

                if (is_static) {
                    finished.push_back(std::move(chain));
                } else if (!static_only) {
                    finished.push_back(chain);
                    push_child();
                } else {
                    // static_only=true: non-static source becomes a
                    // frontier only (don't emit); recurse deeper.
                    push_child();
                }
            }
            if (finished.size() >= max_results) {
                truncated = true;
                fanout_exceeded = true;
                break;
            }
        }
        cur = std::move(next);
    }

    std::sort(finished.begin(), finished.end(), ChainLess);

    for (const auto& c : finished) {
        auto* out = resp->add_chains();
        out->set_anchor_va(c.anchor_va);
        out->set_anchor_module(c.anchor_module);
        out->set_anchor_module_off(c.anchor_module_off);
        out->set_anchor_class(c.anchor_class);
        for (auto off : c.offsets) out->add_offsets(off);
        out->set_static_(c.is_static);
    }
    resp->set_truncated(truncated || wall_exceeded);
    // disambiguated truncation
    // cause. Orchestrator ``_wrap`` reads these two bools instead of
    // the fragile ``wall_ms_actual > 0`` heuristic.
    resp->set_wall_exceeded(wall_exceeded);
    resp->set_fanout_exceeded(fanout_exceeded);
    // straight ``now - start``.
    resp->set_wall_ms_actual(
        (std::uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            clock::now() - start).count());
    resp->set_candidates_examined(candidates_examined);
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

// --- Phase E: pointer-map diff --------------------------------------------
//
// Single linear pass over map A's rows. For each (source_va, target_va)
// in A, binary-search for the same source_va in B. Classify each pair
// against both maps' module snapshots to compute a canonical identity
// ("<basename>!<offset>").

namespace {

constexpr std::size_t DIFF_ROW_CAP = 65'536;
// filter-list cap. Diff's filter
// path is O(count_a × |chains|); a 10 M-chain request hangs the agent.
constexpr std::size_t DIFF_CHAINS_CAP = 1024;

std::pair<std::string, std::uint64_t>
CanonicalFromVA(std::uint64_t va, const std::vector<ModuleInfo>& mods)
{
    // O(log n) module lookup over
    // the base-sorted snapshot. ``mods`` is guaranteed sorted by the
    // registry's Create path.
    if (const ModuleInfo* m = FindModuleByVA(va, mods)) {
        return {ModuleBasenameLower(m->name), va - m->base};
    }
    return {{}, 0};
}

}  // namespace

grpc::Status PointerMapServiceImpl::Diff(
    grpc::ServerContext* ctx,
    const pry::PointerMapDiffRequest* req,
    pry::PointerMapDiffResponse* resp)
{
    // refuse early on an
    // oversized filter list so a hostile / buggy caller can't force
    // O(count_a × |chains|) work. Runs BEFORE any lookup so the error
    // is cheap.
    if (req->chains_size() > (int)DIFF_CHAINS_CAP) {
        auto* s = resp->mutable_status();
        s->set_ok(false);
        s->set_error("too many chains (cap " +
                     std::to_string(DIFF_CHAINS_CAP) + ")");
        s->set_kind("too_many_chains");
        return grpc::Status::OK;
    }
    auto a = registry_.Lookup(req->map_id_a());
    auto b = registry_.Lookup(req->map_id_b());
    if (!a || !b) {
        FillStatus(resp->mutable_status(), false, "map not found");
        return grpc::Status::OK;
    }
    std::lock_guard<std::mutex> ga(a->m);
    std::lock_guard<std::mutex> gb(b->m);
    if (!a->map_view || !b->map_view) {
        FillStatus(resp->mutable_status(), false, "map not mmap'd");
        return grpc::Status::OK;
    }
    if (a->pid != b->pid) {
        FillStatus(resp->mutable_status(), false, "pid mismatch");
        return grpc::Status::OK;
    }
    if (a->space != b->space) {
        FillStatus(resp->mutable_status(), false,
                   "space mismatch (cross-view diff refused)");
        return grpc::Status::OK;
    }
    const auto* rows_a = static_cast<const PointerMapRow*>(a->map_view);
    const auto* rows_b = static_cast<const PointerMapRow*>(b->map_view);
    const std::size_t count_a = a->entries;
    const std::size_t count_b = b->entries;

    // Build a filter set from req->chains() if present. Each chain's
    // anchor_module!anchor_module_off is the static anchor root we
    // want to still resolve in both maps — a row is kept iff its
    // source_va canonicalizes to one of the chain anchors. This is
    // the "does this chain still work" question plan §4 Phase E
    // specifies, not "does this pointer target the chain's root".
    std::vector<std::pair<std::string, std::uint64_t>> filter;
    for (const auto& c : req->chains()) {
        if (!c.anchor_module().empty()) {
            filter.emplace_back(ModuleBasenameLower(c.anchor_module()),
                                c.anchor_module_off());
        }
    }
    const bool have_filter = !filter.empty();

    std::uint64_t compared = 0;
    bool truncated = false;

    for (std::size_t i = 0; i < count_a; ++i) {
        // honour gRPC cancel so
        // a 65 K-row diff doesn't keep CPU after the caller walks away.
        // Checked per-row (cheap; the body already touches cache lines
        // from rows_a/rows_b).
        if (ctx && ctx->IsCancelled()) {
            truncated = true;
            break;
        }
        if (resp->rows_size() >= (int)DIFF_ROW_CAP) {
            truncated = true;
            break;
        }
        auto src = rows_a[i].source_va;
        // Binary-search in B (rows_b is sorted by source_va asc).
        std::size_t lo = 0, hi = count_b;
        while (lo < hi) {
            auto mid = lo + (hi - lo) / 2;
            if (rows_b[mid].source_va < src) lo = mid + 1;
            else hi = mid;
        }
        std::uint64_t tgt_a = rows_a[i].target_va;
        std::uint64_t tgt_b = 0;
        bool in_b = (lo < count_b && rows_b[lo].source_va == src);
        if (in_b) tgt_b = rows_b[lo].target_va;
        compared++;

        auto [mod_a, off_a] = CanonicalFromVA(tgt_a, a->modules);
        auto [mod_b, off_b] = CanonicalFromVA(tgt_b, b->modules);

        if (req->static_only() && mod_a.empty()) continue;

        if (have_filter) {
            // Filter is "keep rows whose anchor (source side) canon
            // matches one of the chain anchors". Check A's side
            // (if the anchor row left map B entirely, the row
            // drops out of the diff above when in_b is false and
            // mod_a is empty, which the caller picks up via
            // drift_reason='target_unmapped').
            auto [src_mod_a, src_off_a] = CanonicalFromVA(src, a->modules);
            auto [src_mod_b, src_off_b] = (in_b
                ? CanonicalFromVA(src, b->modules)
                : std::make_pair(std::string(), std::uint64_t{0}));
            bool keep = false;
            for (const auto& f : filter) {
                if (src_mod_a == f.first && src_off_a == f.second) {
                    keep = true; break;
                }
                if (in_b && src_mod_b == f.first &&
                    src_off_b == f.second) {
                    keep = true; break;
                }
            }
            if (!keep) continue;
        }

        std::string canonical;
        if (!mod_a.empty()) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "!0x%llx",
                          (unsigned long long)off_a);
            canonical = mod_a + buf;
        }

        bool still_valid = false;
        std::string drift;
        if (!in_b) {
            drift = "target_unmapped";
        } else if (mod_a.empty()) {
            // Dynamic anchor (heap/stack); only equal targets count.
            still_valid = (tgt_a == tgt_b);
            if (!still_valid) drift = "value_changed";
        } else if (mod_b.empty()) {
            // Module unloaded in B.
            drift = "module_unloaded";
        } else if (mod_a == mod_b && off_a == off_b) {
            still_valid = true;
        } else {
            drift = "value_changed";
        }

        auto* row = resp->add_rows();
        row->set_source_va_a(src);
        row->set_source_va_b(in_b ? src : 0);
        row->set_target_va_a(tgt_a);
        row->set_target_va_b(tgt_b);
        row->set_canonical_target(canonical);
        row->set_still_valid(still_valid);
        row->set_drift_reason(drift);
    }
    resp->set_compared_entries(compared);
    resp->set_truncated(truncated);
    FillStatus(resp->mutable_status(), true, "");
    return grpc::Status::OK;
}

// --- registration ----------------------------------------------------------

void RegisterPointerMapService(grpc::ServerBuilder& builder,
                               std::string view,
                               MemReadFn reader,
                               ModuleEnumFn enumerate)
{
    static std::unordered_map<std::string,
                              std::unique_ptr<PointerMapServiceImpl>> svcs;
    auto& svc = svcs[view];
    if (!svc) {
        svc = std::make_unique<PointerMapServiceImpl>(view);
        svc->Configure(DefaultScanRoot(), std::move(reader),
                       std::move(enumerate));
    } else {
        // on driver reconnect
        // we're handed fresh ``reader`` / ``enumerate`` callables; the
        // previous code silently ignored them so the registered
        // service kept holding the stale ones. Always rebind, and
        // assert-log on repeat so an unexpected second register on a
        // single view is loud.
        std::fprintf(stderr,
                     "[pry.scan] WARN: RegisterPointerMapService "
                     "re-register on view=%s — rebinding callables\n",
                     view.c_str());
        svc->Configure(DefaultScanRoot(), std::move(reader),
                       std::move(enumerate));
    }
    builder.RegisterService(svc.get());
}

}  // namespace pry::scan
