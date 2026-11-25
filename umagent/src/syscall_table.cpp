// umagent/src/syscall_table.cpp — SI feature #3 syscall-number calibration.
//
// Builds `name → number` and `number → name` maps by scanning ntdll.dll
// stub prologues in the current process. The stable x64 ntdll syscall
// stub since Win7 looks like:
//
//     4C 8B D1              mov r10, rcx
//     B8 <imm32>            mov eax, <syscall nr>
//     F6 04 25 ... 01       test byte ptr [0x7FFE0308], 1   (Win11)
//     75 03                 jne short +3
//     0F 05                 syscall
//     C3                    ret
//
// Reading 4 bytes at stub+4 picks up the imm32 regardless of the
// surrounding test/jne block (older builds skip those but keep the
// `mov eax, imm32` right after `mov r10, rcx`). We tolerate the handful
// of exports that don't follow the pattern (e.g. NtQuerySystemTime on
// some builds) by skipping their stubs rather than guessing. Build is
// ~30 ms; cached singleton behind std::call_once.
//
// Reference: an internal plan
// Feature #3.

#include "syscall_table.hpp"

#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

namespace um {

namespace {

// Resolve ntdll.dll in the current process. Returns 0 when the module
// isn't present (shouldn't happen on Windows; defensive).
HMODULE LocateNtdll() {
    HMODULE h = ::GetModuleHandleW(L"ntdll.dll");
    return h;
}

// Walk the module's export table and invoke `visitor(name, rva)` for
// every exported function whose name starts with "Nt" (not "Ntdll*").
// We use the raw PE walker so we don't need GetProcAddress on every
// name — ~2000 exports is fast enough but the batch walk is cleaner.
template <typename Fn>
void ForEachNtExport(HMODULE module, Fn&& visitor) {
    if (!module) return;
    auto base = reinterpret_cast<std::uint8_t*>(module);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return;
    auto exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto names = reinterpret_cast<std::uint32_t*>(base + exp->AddressOfNames);
    auto ords = reinterpret_cast<std::uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto funcs = reinterpret_cast<std::uint32_t*>(base + exp->AddressOfFunctions);
    for (std::uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        // Only genuine syscall stubs: names starting with "Nt" followed by
        // an uppercase letter. "Ntdll*" and "Ntsupp*" are not syscalls.
        if (name[0] != 'N' || name[1] != 't' || !(name[2] >= 'A' && name[2] <= 'Z')) {
            continue;
        }
        std::uint32_t rva = funcs[ords[i]];
        visitor(name, rva);
    }
}

// Decode the syscall number from a stub at `stub`. Returns UINT32_MAX
// when the bytes don't match the known prologue; the caller skips such
// exports rather than fabricating a number.
std::uint32_t DecodeStubNumber(const std::uint8_t* stub) {
    // Prologue 1 (Win7+): 4C 8B D1 B8 <imm32>
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) {
        std::uint32_t imm = 0;
        std::memcpy(&imm, stub + 4, sizeof(imm));
        return imm;
    }
    // Some wrappers (Zw aliases on checked builds) prepend one byte of
    // padding; try the +1 shift.
    if (stub[1] == 0x4C && stub[2] == 0x8B && stub[3] == 0xD1 && stub[4] == 0xB8) {
        std::uint32_t imm = 0;
        std::memcpy(&imm, stub + 5, sizeof(imm));
        return imm;
    }
    return UINT32_MAX;
}

// Fill `t.ntdll_version` / `t.ntdll_build` via GetFileVersionInfo on the
// backing file. Best effort — the caller treats empties as "unknown".
void FillNtdllVersion(HMODULE ntdll, SyscallNameTable& t) {
    wchar_t path[MAX_PATH]{};
    if (!::GetModuleFileNameW(ntdll, path, MAX_PATH)) return;
    DWORD dummy = 0;
    DWORD sz = ::GetFileVersionInfoSizeW(path, &dummy);
    if (!sz) return;
    std::string blob(sz, '\0');
    if (!::GetFileVersionInfoW(path, 0, sz, blob.data())) return;
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffi_len = 0;
    if (!::VerQueryValueW(blob.data(), L"\\",
                          reinterpret_cast<void**>(&ffi), &ffi_len) ||
        !ffi || ffi_len < sizeof(*ffi)) {
        return;
    }
    unsigned major = HIWORD(ffi->dwFileVersionMS);
    unsigned minor = LOWORD(ffi->dwFileVersionMS);
    unsigned build = HIWORD(ffi->dwFileVersionLS);
    unsigned patch = LOWORD(ffi->dwFileVersionLS);
    char buf[64]{};
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%u.%u.%u.%u",
                major, minor, build, patch);
    t.ntdll_version = buf;
    t.ntdll_build = build;
}

void Populate(SyscallNameTable& t) {
    HMODULE ntdll = LocateNtdll();
    if (!ntdll) {
        t.calibrated = false;
        return;
    }
    t.ntdll_base = reinterpret_cast<std::uint64_t>(ntdll);
    FillNtdllVersion(ntdll, t);
    auto base = reinterpret_cast<std::uint8_t*>(ntdll);
    ForEachNtExport(ntdll, [&](const char* name, std::uint32_t rva) {
        std::uint32_t nr = DecodeStubNumber(base + rva);
        if (nr == UINT32_MAX) return;
        // Only accept plausible syscall numbers (<= ~2000 on modern Win11).
        // Anything bigger is almost certainly a wrapper whose prologue
        // happens to collide — skip it.
        if (nr > 0x4FFF) return;
        t.name_by_nr.emplace(nr, name);
        t.nr_by_name.emplace(name, nr);
    });
    t.calibrated = !t.name_by_nr.empty();
}

SyscallNameTable& Singleton() {
    static SyscallNameTable table;
    return table;
}

std::once_flag& OnceFlag() {
    static std::once_flag flag;
    return flag;
}

std::mutex& RecalibrateMutex() {
    static std::mutex m;
    return m;
}

}  // namespace

const SyscallNameTable& GetSyscallTable(bool recalibrate) {
    if (recalibrate) {
        std::lock_guard<std::mutex> lk(RecalibrateMutex());
        SyscallNameTable fresh;
        Populate(fresh);
        Singleton() = std::move(fresh);
        return Singleton();
    }
    std::call_once(OnceFlag(), [] { Populate(Singleton()); });
    return Singleton();
}

std::string LookupSyscallName(std::uint32_t number) {
    const auto& t = GetSyscallTable(false);
    auto it = t.name_by_nr.find(number);
    return (it == t.name_by_nr.end()) ? std::string{} : it->second;
}

std::uint32_t LookupSyscallNumber(const std::string& name) {
    const auto& t = GetSyscallTable(false);
    auto it = t.nr_by_name.find(name);
    return (it == t.nr_by_name.end()) ? UINT32_MAX : it->second;
}

}  // namespace um
