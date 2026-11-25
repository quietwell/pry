#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/sync_stream.h>
#include "pry.grpc.pb.h"
#include "pry_abi.h"
#include "grpc_auth.hpp"
#include "abi_gate.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include "services.hpp"
#include "services_internal.hpp"
#include "../breadcrumb.hpp"
#include "../common.h"
#include "../dump/dumper.hpp"
#include "../files.hpp"
#include "../host/host_info.hpp"
#include "../pe/pe_reader.hpp"
#include "../pe/heap_walker.hpp"
#include "../watch.hpp"

#include <tlhelp32.h>
#include <fstream>
#include <cctype>

namespace pry {

grpc::Status CheckAuth(::grpc::ServerContext* ctx, const std::string& token)
{
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor installed by MakeServerCredentials in
    // main.cpp is authoritative (it also covers services whose handlers
    // never call this); the per-handler call is defence in depth.
    return auth::CheckAuth(ctx, token);
}

grpc::Status DriverAbiGate(DriverMgr& drv, std::string_view method)
{
    // Lock-free: DriverAbi() is the atomic cache comm refreshes on every
    // PING (Status, DriverLoad, the auto-probe after a handle reopen).
    // 0 = not probed / no driver: let the handler answer driver_absent.
    const UINT32 have = drv.Comm().DriverAbi();
    if (have == 0 || have == PRY_ABI_VERSION || !IsDriverBackedMethod(method)) {
        return grpc::Status::OK;
    }
    return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                        "driver_abi_mismatch: loaded driver ABI " + std::to_string(have) +
                            " != agent ABI " + std::to_string(PRY_ABI_VERSION) +
                            "; load the matching pry_driver.sys (target_manage driver_load) "
                            "before using driver-backed RPCs");
}

bool UserMemReadFn(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len)
{
    auto* c = (MemReaderCtx*)ctx;
    SIZE_T got = 0;
    if (c->drv && c->drv->Comm().MemRead(Space::User, pid, addr, dst, len, &got) && got == len) {
        return true;
    }
    HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        return false;
    }
    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(h, (LPCVOID)(uintptr_t)addr, dst, len, &read);
    CloseHandle(h);
    return ok && read == len;
}

bool KernelMemReadFn(void* ctx, UINT32 pid, UINT64 addr, void* dst, size_t len)
{
    (void)pid;
    auto* c = (MemReaderCtx*)ctx;
    SIZE_T got = 0;
    return c->drv && c->drv->Comm().MemRead(Space::Kernel, 0, addr, dst, len, &got) &&
           got == len;
}

bool ListUserModules(DriverMgr* drv, UINT32 pid, std::vector<pry::ModuleEntry>* out)
{
    if (drv && drv->Comm().Open() && drv->Comm().UserModules(pid, *out)) {
        return true;
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            pry::ModuleEntry e;
            e.Base = (UINT64)(uintptr_t)me.modBaseAddr;
            e.Size = me.modBaseSize;
            e.Name = me.szModule;
            e.Path = me.szExePath;
            out->push_back(e);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return !out->empty();
}

std::string WideToUtf8(const std::wstring& w)
{
    // proto3 string fields are UTF-8 — truncating each WCHAR
    // to a char via the iterator pair ctor produced invalid UTF-8 for
    // any non-ASCII input, which modern protobuf-cpp silently refuses
    // to serialize, dropping the entire response proto. The gRPC
    // layer then sends only trailers (headers-only / "no DATA frame"),
    // which asyncio clients see as resp=None with StatusCode.OK.
    if (w.empty()) {
        return {};
    }
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (n <= 0) {
        return {};
    }
    std::string s((size_t)n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                          s.data(), n, nullptr, nullptr);
    return s;
}

std::string BasenameLower(const std::string& p)
{
    size_t slash = p.find_last_of("\\/");
    std::string b = slash == std::string::npos ? p : p.substr(slash + 1);
    for (auto& ch : b) {
        ch = (char)std::tolower((unsigned char)ch);
    }
    return b;
}

UINT64 FindModuleBase(const std::vector<pry::ModuleEntry>& mods,
                      const std::string& want)
{
    // match either basename or full path, case-insensitively (see DumpModule
    // in services2.cpp for the reference pattern).
    std::string want_lower = BasenameLower(want);
    for (const auto& m : mods) {
        std::string name = WideToUtf8(m.Name);
        std::string path = WideToUtf8(m.Path);
        if (_stricmp(name.c_str(), want.c_str()) == 0 ||
            _stricmp(path.c_str(), want.c_str()) == 0 ||
            BasenameLower(name) == want_lower ||
            BasenameLower(path) == want_lower) {
            return m.Base;
        }
    }
    return 0;
}

std::string FindOwningModule(const std::vector<pry::ModuleEntry>& mods, UINT64 addr)
{
    for (const auto& m : mods) {
        if (m.Size == 0) {
            continue;
        }
        if (addr >= m.Base && addr < m.Base + m.Size) {
            return WideToUtf8(m.Name);
        }
    }
    return {};
}

void FillStatus(google::protobuf::Message* msg, const std::string& err)
{
    // Two response shapes exist:
    //   1. bare OpStatus (Detach, Suspend, Resume, KillProcess, ...): the
    //      message IS the status
    //   2. wrapper responses with an embedded OpStatus at field 0
    // Blindly MutableMessage-ing field 0 on shape 1 hit a CPPTYPE_BOOL field
    // and protobuf aborted the whole agent (FAST_FAIL_FATAL_APP_EXIT).
    auto* d = msg->GetDescriptor();
    auto* refl = msg->GetReflection();
    pry::OpStatus* st = nullptr;
    if (d->name() == "OpStatus") {
        st = static_cast<pry::OpStatus*>(msg);
    } else if (d->field_count() > 0 &&
               d->field(0)->type() == google::protobuf::FieldDescriptor::TYPE_MESSAGE) {
        st = static_cast<pry::OpStatus*>(refl->MutableMessage(msg, d->field(0)));
    } else {
        OutputDebugStringA("FillStatus: unknown response shape, status not set\n");
        return;
    }
    st->set_ok(err.empty());
    if (!err.empty()) {
        st->set_error(err);
        st->set_errno_code(1);
    }
}

// Phase 6a: split into services_{agent,memory,debug,bp}.cpp.
// The four factory functions live in each of those TUs; this function
// just fans out to them in the original construct-then-register order.
void RegisterCoreServices(grpc::ServerBuilder& builder, const AgentConfig& cfg, DriverMgr& drv,
                          ExecMgr& exec, host::NetPinMgr& netPin)
{
    (void)exec; // reserved for future core services; unused today
    RegisterAgentSvc(builder, cfg, drv);
    RegisterNetPinSvc(builder, cfg, netPin);
    RegisterMemorySvc(builder, cfg, drv);
    RegisterDebugSvc(builder, cfg, drv);
    RegisterBpSvc(builder, cfg, drv);
}

} // namespace pry
