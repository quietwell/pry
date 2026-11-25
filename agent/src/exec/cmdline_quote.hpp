// agent/src/exec/cmdline_quote.hpp — build a CreateProcess command line
// whose arguments round-trip through CommandLineToArgvW / the MSVC CRT
// argv parser unchanged.
//
// Rules (MSDN "Parsing C++ command-line arguments"): inside a quoted
// argument, 2n backslashes before a quote are n literal backslashes and the
// quote ends the argument, 2n+1 backslashes + quote are n backslashes and a
// literal quote; backslashes not followed by a quote are literal. So:
//   * a run of n backslashes followed by `"` is emitted as 2n+1 backslashes
//     plus `\"`'s quote;
//   * a run of n backslashes at the very end (before our closing quote) is
//     emitted as 2n backslashes;
//   * every other character is copied.
// Arguments are always quoted (the agent always did; it keeps empty
// arguments and embedded whitespace intact).
//
// argv[0] (the executable) follows different rules — no escape processing,
// quotes only delimit — so it goes through QuoteExe, which only wraps.
// Not for cmd.exe /c or powershell -Command bodies: those shells re-parse
// the raw line with their own rules (use RunShellEncoded for PowerShell).
#pragma once

#include <string>

namespace pry {

inline std::wstring QuoteArg(const std::wstring& arg)
{
    std::wstring out = L"\"";
    for (auto it = arg.begin();; ++it) {
        size_t backslashes = 0;
        while (it != arg.end() && *it == L'\\') {
            ++it;
            ++backslashes;
        }
        if (it == arg.end()) {
            out.append(backslashes * 2, L'\\');
            break;
        }
        if (*it == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(*it);
        }
    }
    out.push_back(L'"');
    return out;
}

inline std::wstring QuoteExe(const std::wstring& exe)
{
    return L"\"" + exe + L"\"";
}

} // namespace pry
