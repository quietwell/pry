// agent/src/host/img_coherency.cpp — SI feature #1: image coherency scoring.
//
// Shared source built by both agent and umagent targets. The scorer
// walks a PE image from two readers (in-memory + on-disk), skipping
// bytes flagged in the exclusion bitmap (relocs, IAT thunks, LoadConfig
// override tables, CFG function/CFCheck tables, ARM64X dynamic relocs,
// the ImageBase field in the optional header), and coalesces runs of
// mismatches into MismatchRange entries. See the hpp banner and the
// slice plan at an internal plan
// 04-umagent-orchestrator.md §Feature 1 for the response contract.

#include "img_coherency.hpp"

#include <algorithm>
#include <cstring>
#include <cstdio>

namespace pry::host {

namespace {

constexpr size_t kChunkBytes = 1 << 16;      // 64 KiB section-walk chunk
constexpr size_t kMismatchSampleCap = 64;    // bytes captured per mismatch
constexpr uint64_t kQuickBudget = 192 * 1024;
constexpr uint64_t kNormalBudget = 40ull * 1024 * 1024;

constexpr uint32_t kImageScnMemExec = 0x20000000u;
constexpr uint32_t kImageScnMemWrite = 0x80000000u;

constexpr uint32_t kDirBaseReloc = 5;
constexpr uint32_t kDirImport = 1;
constexpr uint32_t kDirLoadConfig = 10;
constexpr uint32_t kDirIat = 12;
constexpr uint32_t kDirDelayImport = 13;

inline uint16_t Rd16(const uint8_t* p) {
    uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}

inline uint32_t Rd32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

inline uint64_t Rd64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

// Compact exclusion bitmap: 1 bit per 16 bytes of image (16x reduction
// over per-byte, trivially rounds every range to its 16-byte envelope
// which is fine — mismatches get coalesced anyway).
class ExclusionBitmap {
public:
    void init(size_t image_size) {
        bits_.assign((image_size + 127) / 128, 0);  // 128 = 8 bits * 16 bytes
        size_ = image_size;
    }

    void mark(uint64_t rva, uint64_t len) {
        if (!len || rva >= size_) return;
        uint64_t end = std::min<uint64_t>(rva + len, size_);
        uint64_t first = rva / 16;
        uint64_t last = (end - 1) / 16;
        for (uint64_t i = first; i <= last; ++i) {
            size_t byte = i / 8;
            if (byte >= bits_.size()) break;
            bits_[byte] = static_cast<uint8_t>(bits_[byte] | (1u << (i & 7)));
        }
    }

    bool is_excluded(uint64_t rva) const {
        if (rva >= size_) return true;
        uint64_t i = rva / 16;
        size_t byte = i / 8;
        if (byte >= bits_.size()) return true;
        return (bits_[byte] >> (i & 7)) & 1;
    }

private:
    std::vector<uint8_t> bits_;
    size_t size_ = 0;
};

struct PeView {
    bool pe32_plus = false;
    uint32_t e_lfanew = 0;
    uint16_t num_sections = 0;
    uint16_t opt_size = 0;
    uint32_t size_of_image = 0;
    uint32_t directories[16][2] = {};  // (rva, size)
    uint64_t image_base = 0;
    uint32_t image_base_field_off = 0; // file offset of ImageBase in opt header
    std::vector<SectionSpan> sections;
};

bool ParsePe(const std::vector<uint8_t>& buf, PeView* v, std::string* err) {
    if (buf.size() < 0x40 || buf[0] != 'M' || buf[1] != 'Z') {
        if (err) *err = "coherency: not a PE image (MZ missing)";
        return false;
    }
    v->e_lfanew = Rd32(buf.data() + 0x3C);
    if (v->e_lfanew + 24 > buf.size()
        || std::memcmp(buf.data() + v->e_lfanew, "PE\0\0", 4) != 0) {
        if (err) *err = "coherency: bad PE signature";
        return false;
    }
    uint32_t coff = v->e_lfanew + 4;
    uint16_t machine = Rd16(buf.data() + coff);
    (void)machine;
    v->num_sections = Rd16(buf.data() + coff + 2);
    v->opt_size = Rd16(buf.data() + coff + 16);
    uint32_t opt = coff + 20;
    if (opt + v->opt_size > buf.size() || v->opt_size < 0x60) {
        if (err) *err = "coherency: truncated optional header";
        return false;
    }
    uint16_t magic = Rd16(buf.data() + opt);
    v->pe32_plus = magic == 0x20B;
    if (!v->pe32_plus && magic != 0x10B) {
        if (err) *err = "coherency: unknown PE optional magic";
        return false;
    }
    v->size_of_image = Rd32(buf.data() + opt + 56);
    uint32_t ibase_off = v->pe32_plus ? (opt + 24) : (opt + 28);
    v->image_base_field_off = ibase_off;
    v->image_base = v->pe32_plus ? Rd64(buf.data() + ibase_off)
                                  : Rd32(buf.data() + ibase_off);
    uint32_t ndirs = Rd32(buf.data() + opt + (v->pe32_plus ? 108 : 92));
    uint32_t dir_base = opt + (v->pe32_plus ? 112 : 96);
    for (uint32_t i = 0; i < 16 && i < ndirs; ++i) {
        v->directories[i][0] = Rd32(buf.data() + dir_base + i * 8);
        v->directories[i][1] = Rd32(buf.data() + dir_base + i * 8 + 4);
    }
    uint32_t sec_off = opt + v->opt_size;
    for (uint16_t i = 0; i < v->num_sections; ++i) {
        uint32_t off = sec_off + i * 40;
        if (off + 40 > buf.size()) break;
        SectionSpan s;
        char name[9] = {0};
        std::memcpy(name, buf.data() + off, 8);
        s.name = name;
        s.size = Rd32(buf.data() + off + 8);
        s.va = Rd32(buf.data() + off + 12);
        uint32_t raw = Rd32(buf.data() + off + 16);
        (void)raw;
        s.characteristics = Rd32(buf.data() + off + 36);
        s.executable = (s.characteristics & kImageScnMemExec) != 0;
        v->sections.push_back(std::move(s));
    }
    return true;
}

void MarkRelocs(const std::vector<uint8_t>& buf, const PeView& v,
                ExclusionBitmap* bm) {
    uint32_t rva = v.directories[kDirBaseReloc][0];
    uint32_t size = v.directories[kDirBaseReloc][1];
    if (!rva || !size) return;
    // Reloc directory itself must be skipped — the mapped image's
    // reloc entries are post-fixup, the disk file's are pre-fixup.
    bm->mark(rva, size);
    // Walk reloc blocks and mark each 4K page's fixup slot (<=12 bytes
    // slack past the slot for the handful of 8-byte imm fixups). The
    // slots are inside .text/.data/.rdata; marking them covers the
    // actual bytes the loader rewrote.
    //
    // On ``image`` layout the directory lives inside the mapped image
    // starting at rva; the headers buffer only holds a prefix, so we
    // walk only until we run out of bytes.
    size_t off = rva;
    size_t end = rva + size;
    while (off + 8 <= buf.size() && off < end) {
        uint32_t page = Rd32(buf.data() + off);
        uint32_t block = Rd32(buf.data() + off + 4);
        if (block < 8 || off + block > buf.size() || off + block > end) break;
        uint32_t n = (block - 8) / 2;
        for (uint32_t i = 0; i < n; ++i) {
            uint16_t ent = Rd16(buf.data() + off + 8 + i * 2);
            uint16_t typ = ent >> 12;
            uint16_t rel_off = ent & 0x0FFF;
            if (typ == 0) continue;  // IMAGE_REL_BASED_ABSOLUTE
            uint32_t len = (typ == 10) ? 8u : 4u;  // DIR64 vs HIGHLOW/HIGH/LOW
            bm->mark(static_cast<uint64_t>(page) + rel_off, len);
        }
        off += block;
    }
}

void MarkIat(const std::vector<uint8_t>& buf, const PeView& v,
             ExclusionBitmap* bm) {
    // IAT data directory (slot 12) is a direct (rva, size) over the
    // first-thunk table; mark it wholesale.
    uint32_t iat_rva = v.directories[kDirIat][0];
    uint32_t iat_size = v.directories[kDirIat][1];
    if (iat_rva && iat_size) {
        bm->mark(iat_rva, iat_size);
    }
    // Walk IMAGE_IMPORT_DESCRIPTOR for first-thunk ranges (covers
    // layouts that don't set DIR_IAT reliably, e.g. older linkers).
    uint32_t imp_rva = v.directories[kDirImport][0];
    uint32_t imp_size = v.directories[kDirImport][1];
    if (imp_rva && imp_size) {
        size_t off = imp_rva;
        size_t end = imp_rva + imp_size;
        size_t ptr_sz = v.pe32_plus ? 8 : 4;
        while (off + 20 <= buf.size() && off < end) {
            uint32_t first_thunk = Rd32(buf.data() + off + 16);
            uint32_t name_rva = Rd32(buf.data() + off + 12);
            if (!first_thunk && !name_rva) break;
            if (first_thunk) {
                // Walk thunks until NULL.
                size_t t = first_thunk;
                size_t guard = 4096;
                while (guard-- && t + ptr_sz <= buf.size()) {
                    uint64_t val = v.pe32_plus ? Rd64(buf.data() + t)
                                                : Rd32(buf.data() + t);
                    bm->mark(t, ptr_sz);
                    if (!val) break;
                    t += ptr_sz;
                }
            }
            off += 20;
        }
    }
    // Delay-import descriptors — same shape.
    uint32_t del_rva = v.directories[kDirDelayImport][0];
    uint32_t del_size = v.directories[kDirDelayImport][1];
    if (del_rva && del_size) {
        bm->mark(del_rva, del_size);
    }
}

void MarkLoadConfig(const std::vector<uint8_t>& buf, const PeView& v,
                    ExclusionBitmap* bm) {
    uint32_t rva = v.directories[kDirLoadConfig][0];
    uint32_t size = v.directories[kDirLoadConfig][1];
    if (!rva || !size) return;
    bm->mark(rva, size);  // the whole load-config struct is loader-touched
    if (rva + size > buf.size()) return;
    // On x64 the GuardCFCheckFunctionPointer is at offset 0x78 and the
    // GuardCFFunctionTable at 0x80 with Count at 0x88. The slice doc
    // (step 4) spells out these ranges go into the exclusion bitmap.
    if (!v.pe32_plus) return;  // keep PE32 path trivially excluded already
    if (size < 0x90) return;
    uint64_t cfg_fn_table_va = Rd64(buf.data() + rva + 0x80);
    uint64_t cfg_fn_table_count = Rd64(buf.data() + rva + 0x88);
    if (cfg_fn_table_va > v.image_base) {
        uint64_t cfg_fn_rva = cfg_fn_table_va - v.image_base;
        uint64_t cfg_fn_bytes = cfg_fn_table_count * 4;  // 4 bytes per entry
        bm->mark(cfg_fn_rva, cfg_fn_bytes);
    }
    // ARM64X dynamic reloc table (field at 0x100 in load config; present
    // only on ARM64X builds). Opt-size gates whether the field exists.
    if (size >= 0x108) {
        uint64_t dyn_va = Rd64(buf.data() + rva + 0x100);
        uint64_t dyn_sz = (size >= 0x110) ? Rd64(buf.data() + rva + 0x108) : 0;
        if (dyn_va > v.image_base && dyn_sz) {
            bm->mark(dyn_va - v.image_base, dyn_sz);
        }
    }
}

void MarkImageBaseField(const PeView& v, ExclusionBitmap* bm) {
    // The ImageBase field in the optional header gets rewritten at load
    // time when the loader rebases the image.
    uint32_t width = v.pe32_plus ? 8u : 4u;
    bm->mark(v.image_base_field_off, width);
}

std::string FindSectionName(const PeView& v, uint64_t rva) {
    for (const auto& s : v.sections) {
        if (s.va <= rva && rva < static_cast<uint64_t>(s.va) + s.size) {
            return s.name;
        }
    }
    return "";
}

bool InReloc(const PeView& v, uint64_t rva) {
    uint32_t r = v.directories[kDirBaseReloc][0];
    uint32_t s = v.directories[kDirBaseReloc][1];
    return s && rva >= r && rva < static_cast<uint64_t>(r) + s;
}

bool InIat(const PeView& v, uint64_t rva) {
    uint32_t r = v.directories[kDirIat][0];
    uint32_t s = v.directories[kDirIat][1];
    return s && rva >= r && rva < static_cast<uint64_t>(r) + s;
}

uint64_t SectionBudget(const SectionSpan& s, CoherencyMode mode,
                       uint64_t remaining) {
    if (mode == CoherencyMode::kFull) return s.size;
    uint64_t cap = (mode == CoherencyMode::kQuick)
                       ? (s.name == ".text" || s.name == ".rdata"
                              ? 64ull * 1024
                              : 32ull * 1024)
                       : static_cast<uint64_t>(s.size);
    cap = std::min<uint64_t>(cap, remaining);
    return std::min<uint64_t>(cap, s.size);
}

void CoalesceMismatch(std::vector<MismatchRange>* out,
                      uint32_t rva, uint32_t length,
                      const uint8_t* mem_bytes, const uint8_t* disk_bytes,
                      const std::string& section_name,
                      const std::string& hint,
                      bool include_hex,
                      uint32_t max_entries) {
    // Try to extend the last range when it is contiguous (same RVA
    // sequence) and still under the per-range sample cap. Otherwise
    // append a new entry — unless we are already at the cap, in which
    // case the caller flips truncated=true.
    if (!out->empty()) {
        auto& last = out->back();
        if (last.rva + last.length == rva) {
            last.length += length;
            if (include_hex) {
                size_t take = std::min<size_t>(
                    length, kMismatchSampleCap - std::min(
                                last.in_memory_sample.size(),
                                kMismatchSampleCap));
                last.in_memory_sample.append(
                    reinterpret_cast<const char*>(mem_bytes), take);
                last.on_disk_sample.append(
                    reinterpret_cast<const char*>(disk_bytes), take);
            }
            return;
        }
    }
    if (max_entries && out->size() >= max_entries) return;
    MismatchRange m;
    m.rva = rva;
    m.length = length;
    m.section = section_name;
    m.hint = hint;
    if (include_hex) {
        size_t take = std::min<size_t>(length, kMismatchSampleCap);
        m.in_memory_sample.assign(
            reinterpret_cast<const char*>(mem_bytes), take);
        m.on_disk_sample.assign(
            reinterpret_cast<const char*>(disk_bytes), take);
    }
    out->push_back(std::move(m));
}

}  // namespace

bool ComputeCoherency(const Request& req,
                      const Reader& mapped_reader,
                      const Reader& disk_reader,
                      const std::vector<uint8_t>& headers,
                      Result* out,
                      std::string* err) {
    PeView v;
    if (!ParsePe(headers, &v, err)) {
        return false;
    }
    out->size_of_image = v.size_of_image;
    out->sections.reserve(v.sections.size());
    for (const auto& s : v.sections) {
        out->sections.push_back(s);
    }
    out->reloc_dir_rva = v.directories[kDirBaseReloc][0];
    out->reloc_dir_size = v.directories[kDirBaseReloc][1];

    ExclusionBitmap bm;
    bm.init(v.size_of_image);
    MarkRelocs(headers, v, &bm);
    MarkIat(headers, v, &bm);
    MarkLoadConfig(headers, v, &bm);
    MarkImageBaseField(v, &bm);
    // Headers themselves get excluded wholesale — the mapped headers
    // vs file headers differ in many trivially-authentic ways (e.g.
    // GlobalFlag flips, timestamp fixups by some loaders).
    uint32_t hdr_end = v.e_lfanew + 24 + v.opt_size
                       + v.num_sections * 40;
    bm.mark(0, hdr_end);

    uint64_t budget = (req.mode == CoherencyMode::kQuick)
                          ? kQuickBudget
                          : (req.mode == CoherencyMode::kNormal
                                 ? kNormalBudget
                                 : static_cast<uint64_t>(v.size_of_image));
    uint64_t remaining = budget;

    std::vector<uint8_t> mem_buf(kChunkBytes);
    std::vector<uint8_t> disk_buf(kChunkBytes);

    uint32_t max_ranges = req.max_mismatch_ranges;
    out->sections_total = v.sections.size();

    for (const auto& s : v.sections) {
        if (!remaining && req.mode != CoherencyMode::kFull) {
            out->truncated = true;
            break;
        }
        if (!s.size) continue;
        // Writable sections are legitimately divergent at any point
        // after load. Skip them wholesale — classifier/parity benefits.
        if ((s.characteristics & kImageScnMemWrite) && !s.executable) {
            out->sections_skipped_relocatable++;
            continue;
        }
        uint64_t to_cmp = SectionBudget(s, req.mode, remaining);
        uint64_t off = 0;
        bool hit_cap = false;
        while (off < to_cmp) {
            size_t take = static_cast<size_t>(
                std::min<uint64_t>(kChunkBytes, to_cmp - off));
            uint32_t rva = s.va + static_cast<uint32_t>(off);
            size_t got_mem = mapped_reader(rva, take, mem_buf.data());
            size_t got_disk = disk_reader(rva, take, disk_buf.data());
            if (got_mem == 0 && got_disk == 0) {
                CoalesceMismatch(&out->mismatches, rva,
                                 static_cast<uint32_t>(take),
                                 nullptr, nullptr, s.name,
                                 "unreadable_chunk", false, max_ranges);
                if (max_ranges && out->mismatches.size() >= max_ranges) {
                    out->truncated = true;
                    hit_cap = true;
                    break;
                }
                off += take;
                continue;
            }
            size_t common = std::min(got_mem, got_disk);
            uint32_t run_start = 0;
            uint32_t run_len = 0;
            for (size_t i = 0; i < common; ++i) {
                if (bm.is_excluded(rva + i)) {
                    if (run_len) {
                        std::string hint;
                        if (InReloc(v, rva + run_start)) hint = "reloc";
                        else if (InIat(v, rva + run_start)) hint = "iat_slot";
                        CoalesceMismatch(
                            &out->mismatches, rva + run_start, run_len,
                            mem_buf.data() + run_start,
                            disk_buf.data() + run_start,
                            s.name, hint, req.include_mismatch_hex,
                            max_ranges);
                        run_len = 0;
                    }
                    continue;
                }
                out->bytes_compared++;
                if (mem_buf[i] != disk_buf[i]) {
                    out->bytes_mismatched++;
                    if (!run_len) run_start = static_cast<uint32_t>(i);
                    ++run_len;
                } else if (run_len) {
                    std::string hint;
                    if (InReloc(v, rva + run_start)) hint = "reloc";
                    else if (InIat(v, rva + run_start)) hint = "iat_slot";
                    CoalesceMismatch(
                        &out->mismatches, rva + run_start, run_len,
                        mem_buf.data() + run_start,
                        disk_buf.data() + run_start,
                        s.name, hint, req.include_mismatch_hex,
                        max_ranges);
                    run_len = 0;
                    if (max_ranges && out->mismatches.size() >= max_ranges) {
                        out->truncated = true;
                        hit_cap = true;
                        break;
                    }
                }
            }
            if (run_len) {
                std::string hint;
                if (InReloc(v, rva + run_start)) hint = "reloc";
                else if (InIat(v, rva + run_start)) hint = "iat_slot";
                CoalesceMismatch(
                    &out->mismatches, rva + run_start, run_len,
                    mem_buf.data() + run_start,
                    disk_buf.data() + run_start,
                    s.name, hint, req.include_mismatch_hex,
                    max_ranges);
                if (max_ranges && out->mismatches.size() >= max_ranges) {
                    out->truncated = true;
                    hit_cap = true;
                }
            }
            if (hit_cap) break;
            if (got_mem != take || got_disk != take) {
                // Short read on either side — note the hole and stop
                // this section cleanly.
                CoalesceMismatch(&out->mismatches,
                                 rva + static_cast<uint32_t>(common),
                                 static_cast<uint32_t>(take - common),
                                 nullptr, nullptr, s.name,
                                 "section_hole", false, max_ranges);
                break;
            }
            off += take;
        }
        if (hit_cap) break;
        if (req.mode != CoherencyMode::kFull) {
            if (to_cmp >= remaining) remaining = 0;
            else remaining -= to_cmp;
        }
    }
    if (out->bytes_compared) {
        out->coherency =
            1.0f - static_cast<float>(out->bytes_mismatched)
                       / static_cast<float>(out->bytes_compared);
    } else {
        out->coherency = 1.0f;
    }
    if (req.mode != CoherencyMode::kFull && out->bytes_compared > 0
        && out->bytes_compared < v.size_of_image) {
        out->truncated = true;
    }
    return true;
}

}  // namespace pry::host
