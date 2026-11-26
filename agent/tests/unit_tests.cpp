// agent/tests/unit_tests.cpp — framework-free C++ unit tests (ctest).
//
// Covers the pieces of the agent/umagent/comm surface that are testable on
// the dev host without a driver or a lab VM:
//   * the server-wide bearer-auth processor, against a REAL in-process gRPC
//     server on 127.0.0.1 (auth required everywhere, Identify exempt, the
//     ABI gate hook answering FAILED_PRECONDITION, constant-time compare);
//   * the shared pattern-scan loop (comm/pattern_scan.hpp) edge cases;
//   * comm ABI struct layout asserts and the array-reply validator;
//   * scan/map id validation + scan-root containment;
//   * the CommandLineToArgvW-compatible argument quoting;
//   * byte-count -> WCHAR-count math for WTS-style wide buffers.
//
// Exit code 0 = all passed. Each failed CHECK prints file:line.

#include <grpcpp/grpcpp.h>
#include "pry.grpc.pb.h"

#include "grpc_auth.hpp"
#include "pattern_scan.hpp"
#include "pry_comm.h"
#include "src/exec/cmdline_quote.hpp"
#include "src/grpc/abi_gate.hpp"
#include "src/host/wide_len.hpp"
#include "src/scan/scan_ids.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <windows.h>
#include <shellapi.h>

// comm ABI layout pins, re-asserted from the test side so a header drift
// fails this target too (comm/pry_comm.cpp holds the full list).
static_assert(sizeof(PRY_PING_OUT) == 24, "ping out ABI");
static_assert(sizeof(PRY_MEM_REQ) == 32, "mem req ABI");
static_assert(sizeof(PRY_BP_ENTRY) == 48, "bp entry ABI");
static_assert(offsetof(PRY_BP_ENTRY, Address) == 32, "bp entry layout");
static_assert(sizeof(PRY_VAD_ENTRY) == 40, "vad entry ABI");
static_assert(sizeof(PRY_POOL_ENTRY) == 32, "pool entry ABI");
static_assert(sizeof(PRY_PHYS_RANGE_ENTRY) == 24, "phys range entry ABI");
static_assert(sizeof(PRY_WDG_ENTRY) == 48 + PRY_WDG_MAX_LABEL, "watchdog entry ABI");
static_assert(sizeof(PRY_MEM_WRITE_IN) == 48, "mem write ext ABI");
static_assert(sizeof(PRY_MEM_WRITE_OUT) == 16, "mem write out ABI");
static_assert(PRY_ABI_VERSION == 17, "agent built against ABI v17");

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(cond)                                                                   \
    do {                                                                              \
        ++g_checks;                                                                   \
        if (!(cond)) {                                                                \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            ++g_failures;                                                             \
        }                                                                             \
    } while (0)

// ------------------------------------------------------------- auth ----

void TestConstantTimeEquals()
{
    using pry::auth::BearerMatches;
    using pry::auth::ConstantTimeEquals;
    CHECK(ConstantTimeEquals("", ""));
    CHECK(ConstantTimeEquals("abc", "abc"));
    CHECK(!ConstantTimeEquals("abc", "abd"));
    CHECK(!ConstantTimeEquals("abc", "ab"));
    CHECK(!ConstantTimeEquals("ab", "abc"));
    CHECK(BearerMatches("Bearer tok", "tok"));
    CHECK(!BearerMatches("Bearer tok2", "tok"));
    CHECK(!BearerMatches("bearer tok", "tok"));
    CHECK(!BearerMatches("tok", "tok"));
    CHECK(!BearerMatches("", "tok"));
    CHECK(!BearerMatches("Bearer ", "tok"));
}

class FakeAgentSvc final : public pry::Agent::Service {
public:
    // Deliberately NO per-handler CheckAuth: the processor must cover it.
    grpc::Status Status(grpc::ServerContext*, const pry::StatusRequest*,
                        pry::StatusResponse* resp) override
    {
        resp->set_agent_version("fake");
        handled.fetch_add(1);
        return grpc::Status::OK;
    }
    grpc::Status Identify(grpc::ServerContext*, const pry::IdentifyRequest*,
                          pry::IdentifyResponse* resp) override
    {
        resp->set_view_kind("kernel");
        return grpc::Status::OK;
    }
    std::atomic<int> handled{0};
};

class FakeScanSvc final : public pry::ScanService::Service {
public:
    grpc::Status List(grpc::ServerContext*, const pry::ScanListRequest*,
                      pry::ScanListResponse* resp) override
    {
        resp->mutable_status()->set_ok(true);
        handled.fetch_add(1);
        return grpc::Status::OK;
    }
    std::atomic<int> handled{0};
};

struct AuthServer {
    FakeAgentSvc agent;
    FakeScanSvc scan;
    std::unique_ptr<grpc::Server> server;
    int port = 0;
    std::atomic<bool> gate_closed{false};

    bool Start(const std::string& token)
    {
        pry::auth::ServerAuthPolicy pol;
        pol.token = token;
        pol.exempt_methods = pry::auth::DefaultExemptMethods();
        pol.gate = [this](std::string_view m) -> grpc::Status {
            if (gate_closed.load() && m.rfind("/pry.ScanService/", 0) == 0) {
                return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "gate closed");
            }
            return grpc::Status::OK;
        };
        grpc::ServerBuilder b;
        b.AddListeningPort("127.0.0.1:0", pry::auth::MakeServerCredentials(pol), &port);
        b.RegisterService(&agent);
        b.RegisterService(&scan);
        server = b.BuildAndStart();
        return server && port > 0;
    }
};

grpc::StatusCode CallStatus(pry::Agent::Stub& stub, const char* auth)
{
    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
    if (auth) {
        ctx.AddMetadata("authorization", auth);
    }
    pry::StatusRequest req;
    pry::StatusResponse resp;
    return stub.Status(&ctx, req, &resp).error_code();
}

void TestAuthProcessorServer()
{
    AuthServer s;
    CHECK(s.Start("s3cret-token"));
    if (!s.server) {
        return;
    }
    auto ch = grpc::CreateChannel("127.0.0.1:" + std::to_string(s.port),
                                  grpc::InsecureChannelCredentials());
    auto agent = pry::Agent::NewStub(ch);
    auto scan = pry::ScanService::NewStub(ch);

    CHECK(CallStatus(*agent, nullptr) == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(CallStatus(*agent, "Bearer wrong") == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(CallStatus(*agent, "s3cret-token") == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(s.agent.handled.load() == 0); // handler never ran without auth
    CHECK(CallStatus(*agent, "Bearer s3cret-token") == grpc::StatusCode::OK);
    CHECK(s.agent.handled.load() == 1);

    // Identify: exempt, no token needed.
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
        pry::IdentifyRequest req;
        pry::IdentifyResponse resp;
        auto st = agent->Identify(&ctx, req, &resp);
        CHECK(st.ok());
        CHECK(resp.view_kind() == "kernel");
    }

    // A service whose handlers never call CheckAuth is still covered.
    auto scan_list = [&](const char* auth) {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
        if (auth) ctx.AddMetadata("authorization", auth);
        pry::ScanListRequest req;
        pry::ScanListResponse resp;
        return scan->List(&ctx, req, &resp);
    };
    CHECK(scan_list(nullptr).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(s.scan.handled.load() == 0);
    CHECK(scan_list("Bearer s3cret-token").ok());
    CHECK(s.scan.handled.load() == 1);

    // Gate hook: authenticated, but refused before the handler.
    s.gate_closed.store(true);
    {
        auto st = scan_list("Bearer s3cret-token");
        CHECK(st.error_code() == grpc::StatusCode::FAILED_PRECONDITION);
        CHECK(st.error_message() == "gate closed");
    }
    CHECK(s.scan.handled.load() == 1);
    // Gate does not apply to other services / unauthenticated still first.
    CHECK(CallStatus(*agent, "Bearer s3cret-token") == grpc::StatusCode::OK);
    CHECK(scan_list(nullptr).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    s.server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(2));
}

void TestAuthDisabledWithEmptyToken()
{
    AuthServer s;
    CHECK(s.Start(""));
    if (!s.server) {
        return;
    }
    auto ch = grpc::CreateChannel("127.0.0.1:" + std::to_string(s.port),
                                  grpc::InsecureChannelCredentials());
    auto agent = pry::Agent::NewStub(ch);
    CHECK(CallStatus(*agent, nullptr) == grpc::StatusCode::OK);
    s.server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(2));
}


// ------------------------------------------------------- pattern scan ----

// Memory image backed reader: [base, base+mem.size()) readable, optional
// unreadable hole [hole_lo, hole_hi) that truncates reads (short read).
struct FakeMem {
    std::uint64_t base = 0x10000;
    std::vector<std::uint8_t> mem;
    std::uint64_t hole_lo = 0, hole_hi = 0;
    pry::patscan::ReadFn Reader() const
    {
        return [this](std::uint64_t va, std::uint8_t* dst, std::size_t want) -> std::size_t {
            if (va < base || va >= base + mem.size()) return 0;
            if (hole_hi > hole_lo && va >= hole_lo && va < hole_hi) return 0;
            std::uint64_t end = std::min<std::uint64_t>(va + want, base + mem.size());
            if (hole_hi > hole_lo && va < hole_lo && end > hole_lo) end = hole_lo;
            std::size_t n = (std::size_t)(end - va);
            std::memcpy(dst, mem.data() + (va - base), n);
            return n;
        };
    }
};

std::vector<std::uint64_t> NaiveFind(const FakeMem& m, std::uint64_t start, std::uint64_t size,
                                     const std::string& pat, const std::string& mask)
{
    std::vector<std::uint64_t> out;
    for (std::uint64_t va = start; va + pat.size() <= start + size; ++va) {
        if (pry::patscan::MatchAt(m.mem.data() + (va - m.base), pat, mask)) out.push_back(va);
    }
    return out;
}

void TestPatternScanBoundaries()
{
    using namespace pry::patscan;
    FakeMem m;
    m.mem.assign(10000, 0);
    const std::string pat("\xDE\xAD\xBE\xEF", 4);
    // plant matches: at the start, straddling the window edges the chunk
    // sizes below produce, and as the very LAST start position of the range
    const std::vector<std::uint64_t> plant = {0, 62, 125, 189, 2000, 4094, 9996};
    for (auto off : plant) std::memcpy(m.mem.data() + off, pat.data(), 4);
    const auto expect = NaiveFind(m, m.base, m.mem.size(), pat, "");
    CHECK(expect.size() == plant.size());
    for (std::size_t chunk : {std::size_t(8), std::size_t(64), std::size_t(100),
                              std::size_t(4096), std::size_t(1) << 20}) {
        std::vector<std::uint64_t> hits;
        std::vector<Range> rs{{m.base, m.mem.size()}};
        auto st = ScanRanges(rs, pat, "", 1000, m.Reader(), &hits, {}, chunk);
        CHECK(hits == expect);
        CHECK(st.bytes_scanned == m.mem.size()); // whole window, no early stop
        CHECK(st.cursor == m.base + m.mem.size());
        CHECK(!st.read_stopped && !st.cap_hit && !st.cancelled);
    }
    // the old agent loop (limit = got - p) missed the last start position
    {
        std::vector<std::uint64_t> hits;
        ScanRanges({{m.base + 9000, 1000}}, pat, "", 1000, m.Reader(), &hits);
        CHECK(!hits.empty() && hits.back() == m.base + 9996);
    }
    // wildcard mask
    {
        const std::string wpat("\xDE\x00\xBE", 3);
        std::vector<std::uint64_t> hits;
        ScanRanges({{m.base, m.mem.size()}}, wpat, "x?x", 1000, m.Reader(), &hits);
        CHECK(hits == NaiveFind(m, m.base, m.mem.size(), wpat, "x?x"));
        CHECK(hits.size() == plant.size());
    }
    // result cap
    {
        std::vector<std::uint64_t> hits;
        auto st = ScanRanges({{m.base, m.mem.size()}}, pat, "", 3, m.Reader(), &hits, {}, 64);
        CHECK(hits.size() == 3);
        CHECK(st.cap_hit);
    }
    // window shorter than the pattern: nothing, no crash, no endless loop
    {
        std::vector<std::uint64_t> hits;
        auto st = ScanRanges({{m.base, 3}}, pat, "", 10, m.Reader(), &hits);
        CHECK(hits.empty());
        CHECK(st.cursor == m.base + 3);
    }
    // single-byte pattern, matches on window edges and at the last byte
    {
        FakeMem z;
        z.mem.assign(300, 0);
        z.mem[0] = z.mem[127] = z.mem[128] = z.mem[299] = 0x41;
        std::vector<std::uint64_t> hits;
        ScanRanges({{z.base, 300}}, "A", "", 100, z.Reader(), &hits, {}, 64);
        CHECK(hits.size() == 4);
        CHECK(!hits.empty() && hits.back() == z.base + 299);
    }
    // unreadable hole: stops at the hole after scanning the bytes before it
    {
        FakeMem h = m;
        h.hole_lo = h.base + 5000;
        h.hole_hi = h.base + 6000;
        std::vector<std::uint64_t> hits;
        auto st = ScanRanges({{h.base, h.mem.size()}}, pat, "", 1000, h.Reader(), &hits, {}, 4096);
        CHECK(st.read_stopped);
        CHECK(st.cursor == h.base + 5000);
        CHECK(hits == NaiveFind(h, h.base, 5000, pat, ""));
    }
    // cancellation from the chunk callback
    {
        std::vector<std::uint64_t> hits;
        int calls = 0;
        auto st = ScanRanges({{m.base, m.mem.size()}}, pat, "", 1000, m.Reader(), &hits,
                             [&](std::uint64_t, std::uint64_t) { return ++calls < 2; }, 64);
        CHECK(st.cancelled);
        CHECK(calls == 2);
    }
    // a reader claiming more than it was asked for is clamped
    {
        std::vector<std::uint64_t> hits;
        ReadFn liar = [&](std::uint64_t va, std::uint8_t* dst, std::size_t want) {
            std::memcpy(dst, m.mem.data() + (va - m.base), want);
            return want + 100;
        };
        auto st = ScanRanges({{m.base, 200}}, pat, "", 100, liar, &hits, {}, 64);
        CHECK(st.bytes_scanned == 200);
    }
}

void TestPatternScanPlanning()
{
    using namespace pry::patscan;
    const std::vector<Region> regions = {
        {0x1000, 0x1000, 0x04},  // PAGE_READWRITE
        {0x2000, 0x1000, 0x01},  // PAGE_NOACCESS -> skipped
        {0x3000, 0x1000, 0x104}, // RW|GUARD -> skipped
        {0x4000, 0x2000, 0x20},  // PAGE_EXECUTE_READ
        {0x7000, 0x1000, 0},     // reserved (protect 0) -> skipped
    };
    auto all = PlanRanges(0, 0, regions); // base==0: every readable region
    CHECK(all.size() == 2);
    CHECK(all.size() == 2 && all[0].start == 0x1000 && all[1].start == 0x4000 &&
          all[1].size == 0x2000);
    auto from = PlanRanges(0x4800, 0, regions); // size==0: base -> end of chain
    CHECK(from.size() == 1 && from[0].start == 0x4800 && from[0].size == 0x1800);
    auto win = PlanRanges(0x1234, 0x10, regions); // explicit window
    CHECK(win.size() == 1 && win[0].start == 0x1234 && win[0].size == 0x10);
    CHECK(ValidPattern("ab", ""));
    CHECK(ValidPattern("ab", "x?"));
    CHECK(!ValidPattern("", ""));
    CHECK(!ValidPattern("ab", "x"));
    CHECK(RangeEnd(UINT64_MAX - 5, 100) == UINT64_MAX);
}

// ------------------------------------------------- comm reply checks ----

void TestReplyRowsFit()
{
    using pry::ReplyRowsFit;
    const size_t hdr = sizeof(PRY_NOTIFY_READ_HDR), ent = sizeof(PRY_EVT);
    const size_t buf = hdr + 16 * ent;
    CHECK(ReplyRowsFit((unsigned long)(hdr + 3 * ent), buf, hdr, ent, 3));
    CHECK(ReplyRowsFit(0, buf, hdr, ent, 0)); // empty reply
    // a v13 driver's rows are 8 bytes shorter each: caught, not misparsed
    CHECK(!ReplyRowsFit((unsigned long)(hdr + 3 * (ent - 8)), buf, hdr, ent, 3));
    CHECK(!ReplyRowsFit((unsigned long)buf, buf, hdr, ent, 17)); // past the buffer
    CHECK(!ReplyRowsFit(0xFFFFFFFFul, buf, hdr, ent, 0xFFFFFFFFu));
}

// ----------------------------------------------------- id / path safety ----

void TestScanIds()
{
    using pry::scan::PathStrictlyUnder;
    using pry::scan::ValidId;
    CHECK(ValidId("scan_01-A"));
    CHECK(ValidId(std::string(64, 'a')));
    CHECK(!ValidId(std::string(65, 'a')));
    CHECK(!ValidId(""));
    CHECK(!ValidId("C:\\Windows"));
    CHECK(!ValidId("..\\x"));
    CHECK(!ValidId(".."));
    CHECK(!ValidId("a/b"));
    CHECK(!ValidId("a.b"));
    CHECK(!ValidId("a b"));
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / "pry_ut_root";
    CHECK(PathStrictlyUnder(root, root / "kernel" / "s1"));
    CHECK(!PathStrictlyUnder(root, root));
    CHECK(!PathStrictlyUnder(root, root / ".." / "elsewhere"));
    CHECK(!PathStrictlyUnder(root, fs::path(root.wstring() + L"_sibling") / "x"));
    CHECK(!PathStrictlyUnder(root, fs::path(L"C:\\Windows\\System32")));
    CHECK(!PathStrictlyUnder(root, fs::path(L"relative\\x")));
    // operator/ with an absolute id REPLACES the path — what ValidId stops
    CHECK(!PathStrictlyUnder(root, root / "C:\\Windows"));
}

// ---------------------------------------------------- argv quoting ----

void TestQuoteArgRoundTrip()
{
    const std::vector<std::wstring> args = {
        L"plain", L"", L"with space", L"tab\there", L"q\"uote", L"trail\\",
        L"C:\\dir with space\\", L"\\\\server\\share", L"a\\\"b", L"\"\"",
        L"back\\\\\"slashes", L"\\", L"x\\\\",
    };
    std::wstring line = pry::QuoteExe(L"C:\\Program Files\\x.exe");
    for (const auto& a : args) {
        line += L" " + pry::QuoteArg(a);
    }
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(line.c_str(), &argc);
    CHECK(argv != nullptr);
    if (!argv) return;
    CHECK(argc == (int)args.size() + 1);
    if (argc == (int)args.size() + 1) {
        CHECK(std::wstring(argv[0]) == L"C:\\Program Files\\x.exe");
        for (size_t i = 0; i < args.size(); ++i) {
            if (std::wstring(argv[i + 1]) != args[i]) {
                std::fprintf(stderr, "  argv[%zu] mismatch\n", i + 1);
            }
            CHECK(std::wstring(argv[i + 1]) == args[i]);
        }
    }
    LocalFree(argv);
}

// --------------------------------------------------- ABI gate list ----

void TestAbiGateList()
{
    using pry::IsDriverBackedMethod;
    CHECK(IsDriverBackedMethod("/pry.Watchdog/Arm"));
    CHECK(IsDriverBackedMethod("/pry.Events/Stream"));
    CHECK(IsDriverBackedMethod("/pry.Memory/VadList"));
    CHECK(IsDriverBackedMethod("/pry.WatchHw/Add"));
    CHECK(!IsDriverBackedMethod("/pry.Memory/Read"));      // RPM fallback
    CHECK(!IsDriverBackedMethod("/pry.Agent/Status"));     // must keep answering
    CHECK(!IsDriverBackedMethod("/pry.Agent/DriverLoad")); // the way out
    CHECK(!IsDriverBackedMethod("/pry.Breakpoints/Add"));  // dbgeng path
    CHECK(!IsDriverBackedMethod("/pry.ScanService/Create"));
    CHECK(!IsDriverBackedMethod(""));
}

// ------------------------------------------- byte-length wide buffers ----

void TestWideCharsInByteBuffer()
{
    using pry::host::WideCharsInByteBuffer;

    // The live regression: an 8-character WTSUserName reports 18 bytes
    // (8 WCHARs + NUL). Slack after the NUL must never be counted.
    wchar_t user[32];
    for (auto& c : user) c = L'X';
    std::memcpy(user, L"labuser1", 9 * sizeof(wchar_t));
    CHECK(WideCharsInByteBuffer(user, 9 * sizeof(wchar_t)) == 8);
    // A byte count larger than the string still stops at the NUL.
    CHECK(WideCharsInByteBuffer(user, sizeof(user)) == 8);

    // No NUL inside the reported size: stop at the size, never read past it.
    const wchar_t abc[] = L"abcdef";
    CHECK(WideCharsInByteBuffer(abc, 3 * sizeof(wchar_t)) == 3);
    // An odd trailing byte is not a whole WCHAR.
    CHECK(WideCharsInByteBuffer(abc, 3 * sizeof(wchar_t) + 1) == 3);
    CHECK(WideCharsInByteBuffer(abc, 1) == 0);

    // Empty / degenerate inputs.
    CHECK(WideCharsInByteBuffer(L"", sizeof(wchar_t)) == 0);
    CHECK(WideCharsInByteBuffer(abc, 0) == 0);
    CHECK(WideCharsInByteBuffer(nullptr, 16) == 0);
}

} // namespace

int main()
{
    TestConstantTimeEquals();
    TestAuthProcessorServer();
    TestAuthDisabledWithEmptyToken();
    TestPatternScanBoundaries();
    TestPatternScanPlanning();
    TestReplyRowsFit();
    TestScanIds();
    TestQuoteArgRoundTrip();
    TestAbiGateList();
    TestWideCharsInByteBuffer();
    std::printf("pry_unit_tests: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
