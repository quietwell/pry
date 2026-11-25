// agent/src/scan/dissect_service.cpp
//
// v17 (Memory scanner wave 2 Phase F): decode-per-slot implementation of
// the DissectService. See dissect_service.hpp for scope + plan links.

#include "dissect_service.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <windows.h>

namespace pry::scan {

namespace {

bool IsPrintableAscii(std::uint8_t c)
{
    return c >= 0x20 && c <= 0x7E;
}

bool IsPrintableBmp(wchar_t w)
{
    if (w < 0x20) return false;
    if (w == 0xFFFE || w == 0xFFFF) return false;
    // surrogates are not BMP code points proper
    if (w >= 0xD800 && w <= 0xDFFF) return false;
    return true;
}

std::string AsciiPrefix(const std::uint8_t* p, std::size_t avail)
{
    // Up to 16 printable ASCII chars; stop at the first non-printable.
    std::string out;
    out.reserve(16);
    for (std::size_t i = 0; i < std::min<std::size_t>(16, avail); ++i) {
        if (!IsPrintableAscii(p[i])) break;
        out += (char)p[i];
    }
    return out;
}

std::string Utf16Prefix(const std::uint8_t* p, std::size_t avail)
{
    // Up to 16 BMP wchars; stop at first non-printable or odd length.
    std::string out;
    out.reserve(32);
    std::size_t words = std::min<std::size_t>(16, avail / 2);
    for (std::size_t i = 0; i < words; ++i) {
        wchar_t w;
        std::memcpy(&w, p + i * 2, 2);
        if (!IsPrintableBmp(w)) break;
        // Encode as UTF-8 (BMP only — 1/2/3 bytes).
        if (w < 0x80) {
            out += (char)w;
        } else if (w < 0x800) {
            out += (char)(0xC0 | (w >> 6));
            out += (char)(0x80 | (w & 0x3F));
        } else {
            out += (char)(0xE0 | (w >> 12));
            out += (char)(0x80 | ((w >> 6) & 0x3F));
            out += (char)(0x80 | (w & 0x3F));
        }
    }
    return out;
}

bool FloatReasonable(double v)
{
    if (!std::isfinite(v)) return false;
    double a = std::fabs(v);
    return a >= 1e-10 && a <= 1e10;
}

}  // namespace

void DecodeSlot(const std::uint8_t* buf,
                std::size_t buf_size,
                std::size_t off,
                std::uint64_t base_va,
                const std::vector<ModuleInfo>& modules,
                bool with_modules,
                pry::DissectSlot* out)
{
    out->set_offset((std::uint32_t)off);
    out->set_va(base_va + off);

    // Raw multi-type decode. Window-tail slots zero-pad up to 8 bytes
    // before every unpack so u64/f64/f32 behavior matches the
    // orchestrator-side v16 fallback bit-for-bit (plan review:
    // fast-slow-path-divergence). Python's struct.unpack on an
    // 8-byte zero-padded slice is the authoritative shape.
    std::uint8_t pad[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    std::size_t avail = (off < buf_size) ? (buf_size - off) : 0;
    std::size_t copy = std::min<std::size_t>(8, avail);
    if (copy > 0) std::memcpy(pad, buf + off, copy);
    std::uint64_t u64;
    std::uint32_t u32;
    std::int32_t  i32;
    float  f32;
    double f64;
    std::memcpy(&u64, pad, 8);
    std::memcpy(&f64, pad, 8);
    std::memcpy(&u32, pad, 4);
    std::memcpy(&i32, pad, 4);
    std::memcpy(&f32, pad, 4);
    out->set_u64_le(u64);
    out->set_i32_le(i32);
    out->set_u32_le(u32);
    out->set_f32_le(f32);
    out->set_f64_le(f64);

    // ASCII + UTF-16 prefixes (dense bytes; not score-gated).
    out->set_ascii_prefix(AsciiPrefix(buf + off, avail));
    out->set_utf16_prefix(Utf16Prefix(buf + off, avail));

    // Pointer classification.
    std::uint64_t ptr_off = 0;
    std::string ptr_module;
    std::string ptr_class;
    std::uint32_t score_ptr = 0;
    if (with_modules && u64 != 0) {
        // binary-search a
        // base-sorted module snapshot instead of walking O(n). Caller
        // (pointer_map registry + umagent/kernel enumerators) sorts.
        if (const ModuleInfo* m = FindModuleByVA(u64, modules)) {
            ptr_module = m->name;
            ptr_off = u64 - m->base;
            // §2.3 R7: section-level refinement is Wave 3; treat
            // module-interior as "image_unknown" today. If any
            // module-interior point counts as "mapped executable
            // text", the pointer score lands on +50 (we treat
            // every image hit as an implicit image_text match for
            // scoring purposes until the PE section walk lands).
            ptr_class = "image_unknown";
            score_ptr = DISSECT_SCORE_PTR_MOD_EXEC;
        }
        if (ptr_module.empty() && (u64 >> 47) == 0 && u64 > 0x10000) {
            // Canonical user-mode VA that doesn't land on a known
            // module — probably heap/stack/anonymous. Soft score so
            // ascii/utf16 still beat it when stringy.
            ptr_class = "other";
            score_ptr = DISSECT_SCORE_PTR_MAPPED_ANY;
        }
    }
    out->set_ptr_target_va(u64 != 0 && !ptr_class.empty() ? u64 : 0);
    out->set_ptr_module(ptr_module);
    out->set_ptr_module_off(ptr_off);
    out->set_ptr_classification(ptr_class);

    // String scores.
    std::uint32_t score_ascii = 0;
    {
        const auto& a = out->ascii_prefix();
        if (a.size() >= 16) score_ascii = DISSECT_SCORE_ASCII_16B;
        else if (a.size() >= 8) score_ascii = DISSECT_SCORE_ASCII_8B;
    }
    std::uint32_t score_utf16 = 0;
    {
        // Count code points, not UTF-8 bytes.
        std::size_t words = std::min<std::size_t>(16, avail / 2);
        std::size_t printable = 0;
        for (std::size_t i = 0; i < words; ++i) {
            wchar_t w;
            std::memcpy(&w, buf + off + i * 2, 2);
            if (!IsPrintableBmp(w)) break;
            ++printable;
        }
        if (printable >= 16) score_utf16 = DISSECT_SCORE_UTF16_16W;
        else if (printable >= 8) score_utf16 = DISSECT_SCORE_UTF16_8W;
    }

    // Float scores.
    std::uint32_t score_f64 = FloatReasonable(f64) ? DISSECT_SCORE_F64 : 0;
    std::uint32_t score_f32 = FloatReasonable((double)f32) ? DISSECT_SCORE_F32 : 0;

    out->set_score_pointer(score_ptr);
    out->set_score_utf16(score_utf16);
    out->set_score_ascii(score_ascii);
    out->set_score_f64(score_f64);
    out->set_score_f32(score_f32);

    // Tie-broken best-of-N per plan §3.3.
    // Order: pointer, utf16, ascii, f64, f32, i32 (baseline).
    std::uint32_t best = 0;
    std::string best_name = "i32";   // always-present baseline
    auto bid = [&](std::uint32_t score, const char* name) {
        if (score > best) {
            best = score;
            best_name = name;
        }
    };
    bid(score_ptr,   "pointer");
    bid(score_utf16, "utf16");
    bid(score_ascii, "ascii");
    bid(score_f64,   "f64");
    bid(score_f32,   "f32");
    out->set_probable_type(best_name);
}

DissectServiceImpl::DissectServiceImpl(std::string view,
                                       MemReadFn reader,
                                       ModuleEnumFn enumerate)
    : view_(std::move(view)),
      reader_(std::move(reader)),
      enumerate_(std::move(enumerate))
{}

void DissectServiceImpl::Rebind(MemReadFn reader, ModuleEnumFn enumerate)
{
    // swap in fresh callables on
    // re-register. No lock — Dissect() reads these callables by copy at
    // the top of each call; a racing in-flight call sees either the old
    // or the new pair, which is fine since both target the same view.
    reader_ = std::move(reader);
    enumerate_ = std::move(enumerate);
}

grpc::Status DissectServiceImpl::Dissect(
    grpc::ServerContext*,
    const pry::DissectRequest* req,
    pry::DissectResponse* resp)
{
    auto* status = resp->mutable_status();
    std::uint32_t size = req->size();
    if (size == 0 || size > DISSECT_MAX_BYTES) {
        status->set_ok(false);
        status->set_error("size out of range");
        return grpc::Status::OK;
    }
    std::uint32_t align = req->align() ? req->align() : 4;
    if (align != 4 && align != 8) {
        status->set_ok(false);
        status->set_error("align must be 4 or 8");
        return grpc::Status::OK;
    }

    std::vector<std::uint8_t> buf(size, 0);
    std::size_t got = 0;
    bool ok = reader_(req->pid(), req->address(), buf.data(), size,
                      req->space(), &got);
    if (!ok) {
        status->set_ok(false);
        status->set_error("read failed");
        return grpc::Status::OK;
    }
    buf.resize(got);  // pad past got is unread

    std::vector<ModuleInfo> modules;
    if (req->with_modules() && enumerate_) {
        enumerate_(req->pid(), &modules);
        // sort by base ASC so
        // ``DecodeSlot``'s pointer-classification lookup can binary-
        // search. Dissect enumerates fresh per call (no registry
        // snapshot to piggyback on), so the sort lives here.
        std::sort(modules.begin(), modules.end(),
                  [](const ModuleInfo& a, const ModuleInfo& b) {
                      return a.base < b.base;
                  });
    }

    std::size_t total_rows = got / align;
    std::size_t rows = total_rows;
    bool truncated = false;
    if (rows > DISSECT_MAX_ROWS) {
        rows = DISSECT_MAX_ROWS;
        truncated = true;
    }
    for (std::size_t r = 0; r < rows; ++r) {
        auto* slot = resp->add_slots();
        DecodeSlot(buf.data(), got, r * align, req->address(),
                   modules, req->with_modules(), slot);
    }
    // surface truncation cause
    // so the caller can tell "fewer rows because hit cap" apart from
    // "fewer rows because short read".
    resp->set_total_rows((std::uint32_t)total_rows);
    resp->set_truncated(truncated);
    status->set_ok(true);
    return grpc::Status::OK;
}

grpc::Status DissectServiceImpl::Compare(
    grpc::ServerContext*,
    const pry::DissectCompareRequest* req,
    pry::DissectCompareResponse* resp)
{
    auto* status = resp->mutable_status();

    // Input validation.
    std::uint32_t n = (std::uint32_t)req->base_vas_size();
    if (n == 0) {
        status->set_ok(false);
        status->set_error("base_vas empty");
        status->set_kind("bad_arg");
        return grpc::Status::OK;
    }
    if (n > DISSECT_COMPARE_MAX_INSTANCES) {
        status->set_ok(false);
        status->set_error("too many instances (cap "
                          + std::to_string(DISSECT_COMPARE_MAX_INSTANCES) + ")");
        status->set_kind("too_many_instances");
        return grpc::Status::OK;
    }
    std::uint32_t window = req->window_size();
    if (window == 0 || window > DISSECT_COMPARE_MAX_BYTES_PER) {
        status->set_ok(false);
        status->set_error("window_size out of range");
        status->set_kind("bad_arg");
        return grpc::Status::OK;
    }
    std::uint32_t align = req->align() ? req->align() : 4;
    if (align != 4 && align != 8) {
        status->set_ok(false);
        status->set_error("align must be 4 or 8");
        status->set_kind("bad_arg");
        return grpc::Status::OK;
    }
    std::uint32_t shared_vote = req->shared_ptr_min_vote()
        ? req->shared_ptr_min_vote() : DISSECT_COMPARE_SHARED_VOTE;
    std::uint32_t min_for_class = req->min_instances_for_class()
        ? req->min_instances_for_class()
        : DISSECT_COMPARE_MIN_INSTANCES_FOR_CLASS;

    // Fetch module list once — same sort invariant as Dissect (binary
    // search in FindModuleByVA via the P5-sorted snapshot).
    std::vector<ModuleInfo> modules;
    if (req->with_modules() && enumerate_) {
        enumerate_(req->pid(), &modules);
        std::sort(modules.begin(), modules.end(),
                  [](const ModuleInfo& a, const ModuleInfo& b) {
                      return a.base < b.base;
                  });
    }

    // Per-instance read + decode. Readers that hit `unreadable=true`
    // leave `slots` empty and the classifier skips them — the nested
    // row-form protects downstream readers from desync.
    const std::uint32_t n_offsets = window / align;
    std::vector<std::vector<std::uint8_t>> bufs(n);
    std::vector<std::size_t> got(n, 0);
    std::vector<bool> readable(n, false);
    for (std::uint32_t i = 0; i < n; ++i) {
        auto* row = resp->add_per_instance();
        std::uint64_t base_va = req->base_vas((int)i);
        row->set_base_va(base_va);
        bufs[i].assign(window, 0);
        std::size_t g = 0;
        bool ok = reader_(req->pid(), base_va, bufs[i].data(), window,
                          req->space(), &g);
        if (!ok || g == 0) {
            row->set_unreadable(true);
            continue;
        }
        bufs[i].resize(g);
        got[i] = g;
        readable[i] = true;
        row->set_unreadable(false);
        // Per-offset slot decode.
        std::size_t rows_i = std::min<std::size_t>(g / align,
                                                     DISSECT_MAX_ROWS);
        for (std::size_t r = 0; r < rows_i; ++r) {
            auto* slot = row->add_slots();
            DecodeSlot(bufs[i].data(), g, r * align, base_va,
                       modules, req->with_modules(), slot);
        }
    }

    // Per-offset classification across the per-instance rows.
    //
    // At each offset:
    //   R = readable_instances for this offset (whose window covered it)
    //   values[] = each readable instance's u64 slot value
    //   pointer_count = how many of those slots were classified pointers
    //
    // Then:
    //   R < min_for_class    -> 'inconclusive'
    //   R == 0               -> 'unreadable'
    //   D == 1               -> 'stable'
    //   max_votes >= shared_vote AND modal is a module-ptr for all voters
    //                        -> 'shared_pointer'
    //   D == R:
    //     pointer_frac >= 0.8 -> 'per_instance_ptr'
    //     else                -> 'per_instance_scalar'
    //   else                 -> 'noisy'
    for (std::uint32_t off_idx = 0; off_idx < n_offsets; ++off_idx) {
        auto* cls = resp->add_offsets();
        std::uint32_t off = off_idx * align;
        cls->set_offset(off);

        // Walk the per-instance slots for this offset.
        std::vector<std::uint64_t> values;
        values.reserve(n);
        std::vector<std::string> ptr_modules;   // parallel to values
        std::vector<std::uint64_t> ptr_module_offs;
        std::vector<std::string> probable_types;
        std::uint32_t pointer_count = 0;
        for (std::uint32_t i = 0; i < n; ++i) {
            if (!readable[i]) continue;
            const auto& row = resp->per_instance((int)i);
            if ((std::uint32_t)row.slots_size() <= off_idx) continue;
            const auto& s = row.slots((int)off_idx);
            values.push_back(s.u64_le());
            ptr_modules.push_back(s.ptr_module());
            ptr_module_offs.push_back(s.ptr_module_off());
            probable_types.push_back(s.probable_type());
            if (s.probable_type() == "pointer") ++pointer_count;
        }
        std::uint32_t R = (std::uint32_t)values.size();
        cls->set_readable_instances(R);

        // Count distinct values + modal.
        std::unordered_map<std::uint64_t, std::uint32_t> counts;
        for (auto v : values) ++counts[v];
        std::uint32_t D = (std::uint32_t)counts.size();
        cls->set_distinct_values(D);
        std::uint64_t modal = 0;
        std::uint32_t modal_votes = 0;
        for (const auto& kv : counts) {
            if (kv.second > modal_votes) {
                modal_votes = kv.second;
                modal = kv.first;
            }
        }
        cls->set_modal_value(modal);
        cls->set_modal_votes(modal_votes);

        // probable_type majority vote with the standard tie-break
        // pointer > utf16 > ascii > f64 > f32 > i32.
        std::unordered_map<std::string, std::uint32_t> type_counts;
        for (const auto& t : probable_types) ++type_counts[t];
        std::uint32_t best_type_votes = 0;
        std::string best_type = "i32";
        auto rank = [](const std::string& t) -> int {
            if (t == "pointer") return 5;
            if (t == "utf16")   return 4;
            if (t == "ascii")   return 3;
            if (t == "f64")     return 2;
            if (t == "f32")     return 1;
            return 0;  // i32 baseline
        };
        for (const auto& kv : type_counts) {
            if (kv.second > best_type_votes ||
                (kv.second == best_type_votes &&
                 rank(kv.first) > rank(best_type))) {
                best_type_votes = kv.second;
                best_type = kv.first;
            }
        }
        cls->set_probable_type(best_type);

        // Classification.
        std::string classification;
        if (R < min_for_class) {
            classification = "inconclusive";
        } else if (R == 0) {
            classification = "unreadable";
        } else if (D == 1) {
            classification = "stable";
            // When the stable value is a known module pointer, surface
            // the target module metadata — a stable field across every
            // instance that happens to be a pointer is effectively a
            // shared pointer too.
            if (!ptr_modules.empty() && !ptr_modules[0].empty()) {
                cls->set_shared_target_module(ptr_modules[0]);
                cls->set_shared_target_module_off(ptr_module_offs[0]);
            }
        } else if (modal_votes >= shared_vote) {
            // Shared-pointer candidate: every voter must have the modal
            // value pointing into the same module.
            bool all_voters_match_module = true;
            std::string mod;
            std::uint64_t mod_off = 0;
            for (std::uint32_t k = 0; k < values.size(); ++k) {
                if (values[k] != modal) continue;
                if (ptr_modules[k].empty()) {
                    all_voters_match_module = false;
                    break;
                }
                if (mod.empty()) {
                    mod = ptr_modules[k];
                    mod_off = ptr_module_offs[k];
                } else if (mod != ptr_modules[k]) {
                    all_voters_match_module = false;
                    break;
                }
            }
            if (all_voters_match_module && !mod.empty()) {
                classification = "shared_pointer";
                cls->set_shared_target_module(mod);
                cls->set_shared_target_module_off(mod_off);
            } else if (D == R) {
                // No module anchor; fall through to per_instance_*.
                double ptr_frac = (double)pointer_count / (double)R;
                classification = (ptr_frac >= 0.8)
                    ? "per_instance_ptr" : "per_instance_scalar";
            } else {
                classification = "noisy";
            }
        } else if (D == R) {
            double ptr_frac = (double)pointer_count / (double)R;
            classification = (ptr_frac >= 0.8)
                ? "per_instance_ptr" : "per_instance_scalar";
        } else {
            classification = "noisy";
        }
        cls->set_classification(classification);
    }

    resp->set_n_instances(n);
    resp->set_n_offsets(n_offsets);
    status->set_ok(true);
    return grpc::Status::OK;
}

void RegisterDissectService(grpc::ServerBuilder& builder,
                            std::string view,
                            MemReadFn reader,
                            ModuleEnumFn enumerate)
{
    static std::unordered_map<std::string,
                              std::unique_ptr<DissectServiceImpl>> svcs;
    auto& svc = svcs[view];
    if (!svc) {
        svc = std::make_unique<DissectServiceImpl>(view, std::move(reader),
                                                    std::move(enumerate));
    } else {
        // rebind callables on
        // re-register and log the repeat. Older builds silently ignored
        // the second set; a driver reconnect left the service holding a
        // dead reader/enumerate.
        std::fprintf(stderr,
                     "[pry.scan] WARN: RegisterDissectService "
                     "re-register on view=%s — rebinding callables\n",
                     view.c_str());
        svc->Rebind(std::move(reader), std::move(enumerate));
    }
    builder.RegisterService(svc.get());
}

}  // namespace pry::scan
