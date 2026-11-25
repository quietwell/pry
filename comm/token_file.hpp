// comm/token_file.hpp — read the agent/umagent bearer token from a file
// (`--token-file <path>`), so the secret no longer sits in the service
// binPath where any local user can read it with `sc qc`.
//
// scripts/install_agent_service.ps1 writes C:\pry\agent.token with an
// ACL of SYSTEM + Administrators only. The file holds the token as plain
// UTF-8/ASCII; a UTF-8 BOM and surrounding whitespace/newlines are
// stripped. Header-only (umagent does not link pry_comm).
#pragma once

#include <windows.h>

#include <string>

namespace pry {

inline bool ReadTokenFile(const std::wstring& path, std::string* token, std::string* err)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        *err = "cannot open token file (gle=" + std::to_string(GetLastError()) + ")";
        return false;
    }
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 4096) {
        CloseHandle(h);
        *err = "token file must be 1..4096 bytes";
        return false;
    }
    std::string buf((size_t)sz.QuadPart, '\0');
    DWORD got = 0;
    BOOL ok = ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr);
    DWORD gle = GetLastError();
    CloseHandle(h);
    if (!ok) {
        *err = "cannot read token file (gle=" + std::to_string(gle) + ")";
        return false;
    }
    buf.resize(got);
    if (buf.size() >= 3 && (unsigned char)buf[0] == 0xEF && (unsigned char)buf[1] == 0xBB &&
        (unsigned char)buf[2] == 0xBF) {
        buf.erase(0, 3);
    }
    const char* ws = " \t\r\n";
    size_t b = buf.find_first_not_of(ws);
    size_t e = buf.find_last_not_of(ws);
    if (b == std::string::npos) {
        *err = "token file is empty";
        return false;
    }
    *token = buf.substr(b, e - b + 1);
    return true;
}

} // namespace pry
