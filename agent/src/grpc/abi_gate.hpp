// agent/src/grpc/abi_gate.hpp — which RPCs the driver ABI gate refuses.
//
// While the loaded driver's PING-reported ABI differs from the agent's
// PRY_ABI_VERSION, the server-wide auth processor (comm/grpc_auth.hpp,
// installed in main.cpp) answers these methods with FAILED_PRECONDITION
// "driver_abi_mismatch: ..." before the handler runs. They have no
// usermode fallback, so a mismatched driver could only produce misparsed
// replies.
//
// Every OTHER driver touch is still covered one layer down: with
// Driver::RequireAbi() set, comm refuses each non-PING IOCTL with the same
// "driver_abi_mismatch" text, so mixed handlers (Memory.Read, Breakpoints,
// Exec.CallFunction kernel, the kernel-space scan reader, ...) fail with
// ok=false or fall back to their usermode path (ReadProcessMemory,
// toolhelp, dbgeng) instead of misparsing.
//
// Keep this list in sync when adding a driver-only service. Pure header so
// agent/tests/unit_tests.cpp can pin it.
#pragma once

#include <string_view>

namespace pry {

inline bool IsDriverBackedMethod(std::string_view path)
{
    // whole services with no usermode path
    constexpr std::string_view kServices[] = {
        "/pry.Watchdog/", "/pry.Events/",    "/pry.Cpu/",       "/pry.SelfProt/",
        "/pry.HandleOps/", "/pry.StackWalk/", "/pry.WatchHw/",
    };
    for (auto s : kServices) {
        if (path.substr(0, s.size()) == s) {
            return true;
        }
    }
    // driver-only Memory methods
    constexpr std::string_view kMethods[] = {
        "/pry.Memory/VadList",  "/pry.Memory/HandleList",  "/pry.Memory/PhysicalRanges",
        "/pry.Memory/PoolScan", "/pry.Memory/VaTranslate", "/pry.Memory/IdtList",
        "/pry.Memory/ObjEnum",
    };
    for (auto m : kMethods) {
        if (path == m) {
            return true;
        }
    }
    return false;
}

} // namespace pry
