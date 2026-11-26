// agent/src/host/wide_len.hpp — length math for wide-string buffers whose
// size an API reports in BYTES rather than characters.
//
// WTSQuerySessionInformationW (and friends) hand back a WCHAR buffer plus a
// byte count that includes the terminating NUL. Treating that count as a
// character count reads roughly twice the allocation and ships heap bytes
// past the NUL to the caller. WideCharsInByteBuffer turns the byte count into
// a safe character count: it never looks past len_bytes, and it stops at the
// first NUL so a terminator (or slack after it) never reaches the converter.
//
// Header-only so agent/tests/unit_tests.cpp can pin the math without WTS.
#pragma once

#include <cstddef>
#include <wchar.h>

namespace pry::host {

inline size_t WideCharsInByteBuffer(const wchar_t* buf, size_t len_bytes)
{
    if (buf == nullptr) {
        return 0;
    }
    // Floor division: a trailing odd byte is not a whole WCHAR.
    return ::wcsnlen(buf, len_bytes / sizeof(wchar_t));
}

} // namespace pry::host
