/* pry_recon.h — shipped with reconstruct_manage (slice 1).
 *
 * Include it as  #include "pry_recon.h"  from a reconstruction. It is
 * the only quoted include the compile step's source guard accepts.
 *
 * Exports: list every function to export in the compile call's
 * exports=[...]; PRY_EXPORT is optional (the linker exports by name).
 *
 * x86 calling conventions: declare the convention the original uses —
 * PRY_CDECL (default), PRY_STDCALL, PRY_FASTCALL. MSVC has no
 * __thiscall for free C functions; reconstruct a thiscall method as
 *     int PRY_FASTCALL method(void *self, int unused_edx, int a, ...)
 * and verify it with cc='thiscall': `self` arrives in ECX, the dummy
 * takes EDX (which thiscall leaves undefined), and the remaining
 * arguments sit on the stack exactly where thiscall puts them.
 * On x64 all of these are ignored (one convention, Win64).
 */
#ifndef PRY_RECON_H
#define PRY_RECON_H

#include <stddef.h>
#include <stdint.h>

#define PRY_EXPORT __declspec(dllexport)
#define PRY_CDECL __cdecl
#define PRY_STDCALL __stdcall
#define PRY_FASTCALL __fastcall

typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef float f32;
typedef double f64;

/* Decompiler-style aliases (Hex-Rays / Ghidra output). */
typedef uint8_t _BYTE;
typedef uint16_t _WORD;
typedef uint32_t _DWORD;
typedef uint64_t _QWORD;
typedef uint8_t _BOOL1;
typedef int32_t _BOOL4;

#define PRY_LOBYTE(x) ((uint8_t)(x))
#define PRY_HIBYTE(x) ((uint8_t)(((uint32_t)(x)) >> 8))
#define PRY_LOWORD(x) ((uint16_t)(x))
#define PRY_HIWORD(x) ((uint16_t)(((uint32_t)(x)) >> 16))
#define PRY_ROL32(x, n) ((uint32_t)(((uint32_t)(x) << ((n) & 31)) | \
                            ((uint32_t)(x) >> ((32 - ((n) & 31)) & 31))))
#define PRY_ROR32(x, n) ((uint32_t)(((uint32_t)(x) >> ((n) & 31)) | \
                            ((uint32_t)(x) << ((32 - ((n) & 31)) & 31))))

#endif /* PRY_RECON_H */
