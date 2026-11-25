"""Address coercion helpers.

``_addr`` accepts int / hex-string / decimal-string without touching a
client; ``_addr_resolve`` additionally resolves ``module+offset`` by
looking up the module base via a live client. ``_enrich_win32`` appends
symbolic names after ``gle=N`` / ``status=0xN`` substrings.
"""

from __future__ import annotations

from typing import Any

from ...error_maps import WIN32_ERRORS as _WIN32_ERRORS


def _enrich_win32(msg: str) -> str:
    """Append a symbolic name after any 'gle=N' or 'status=0xN' in msg."""
    import re
    def _sub_dec(m: "re.Match[str]") -> str:
        n = int(m.group(1))
        name = _WIN32_ERRORS.get(n)
        return f"{m.group(0)} ({name})" if name and name not in m.string else m.group(0)
    def _sub_hex(m: "re.Match[str]") -> str:
        n = int(m.group(1), 16)
        name = _WIN32_ERRORS.get(n)
        return f"{m.group(0)} ({name})" if name and name not in m.string else m.group(0)
    msg = re.sub(r"gle=(\d+)", _sub_dec, msg)
    msg = re.sub(r"(?:status|nt|err)=0x([0-9a-fA-F]+)", _sub_hex, msg)
    return msg


def _addr(value: Any, name: str = "address") -> int:
    """Coerce an address from int OR hex/decimal string. Callers accept
    both because LLMs mistype 20-digit decimals — hex strings survive the
    round-trip losslessly. Empty/zero -> 0.

    Does NOT resolve `module+offset` notation — that needs a live client
    to look up module bases. Use `_addr_resolve` for the async version."""
    if value is None or value == "":
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return 0
        if "+" in s and not s.lower().startswith("0x"):
            raise ValueError(
                f"{name}: {value!r} looks like module+offset notation; "
                "use _addr_resolve() (call site must go through memory_manage / "
                "debug_manage / bp_manage which pass the client for lookup)")
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
        except ValueError as exc:
            raise ValueError(f"{name}: not a valid int or 0x-hex string: {value!r}") from exc
    raise TypeError(f"{name}: expected int or str, got {type(value).__name__}")


async def _addr_resolve(value: Any, client, *, kernel: bool = True,
                        pid: int = 0, name: str = "address") -> int:
    """Same as _addr but also accepts `module+offset`, `module.sys+0x…`,
    or `module!export`.

    Looks up module base via `client.mem_modules(pid, kernel)` for the
    `+offset` form and the export table via `client.mem_exports(pid, mod,
    kernel)` for the `!export` form. The choice of kernel vs user list
    follows the space the caller is scanning: for kernel/physical
    addresses the module lives in the kernel module list, for user
    addresses it lives in the target process's module list.
    """
    if not isinstance(value, str):
        return _addr(value, name)
    s = value.strip()
    if not s or s.lower().startswith("0x"):
        return _addr(value, name)
    # `module!export` — resolve through the module's export table.
    if "!" in s:
        mod, _, exp = s.partition("!")
        mod = mod.strip()
        exp = exp.strip()
        if not mod or not exp:
            raise ValueError(
                f"{name}: {value!r} not valid module!export notation")
        # windbg accepts bare module stems ('ntdll!NtClose') OR fully
        # qualified names ('ntdll.dll!NtClose'). The agent-side export
        # lookup is a literal name compare, so a bare 'ntdll' fails
        # against the loaded 'ntdll.dll' entry. Try the obvious
        # suffixes before giving up.
        candidates = [mod]
        has_ext = any(mod.lower().endswith(ext)
                      for ext in (".dll", ".sys", ".exe", ".drv", ".cpl",
                                  ".ocx"))
        if not has_ext:
            # In user space modules are .dll / .exe; in kernel space
            # .sys. Try the likely one first, keep the other as
            # fallback so the resolver still works for an uncommon
            # cross-space probe.
            if kernel:
                candidates += [f"{mod}.sys", f"{mod}.dll", f"{mod}.exe"]
            else:
                candidates += [f"{mod}.dll", f"{mod}.exe", f"{mod}.sys"]
        exports = []
        last_err: Exception | None = None
        for cand in candidates:
            try:
                exports = await client.mem_exports(
                    pid, cand, kernel=kernel)
            except Exception as exc:  # noqa: BLE001 - live error
                last_err = exc
                exports = []
                continue
            if exports:
                break
        if not exports:
            if last_err is not None:
                raise ValueError(
                    f"{name}: resolving {value!r}: {last_err}") from last_err
            raise ValueError(
                f"{name}: no exports found for {mod!r} "
                f"(tried {candidates!r}; memory_manage(action='modules', "
                f"filter=…) to browse)")
        want = exp.lower()
        for e in exports:
            nm = str(e.get("name", "")).lower()
            if nm == want:
                return int(_addr(e.get("address"), name=name))
        listed = ", ".join(str(e.get("name", "?")) for e in exports[:5])
        raise ValueError(
            f"{name}: export {exp!r} not found in {mod!r} "
            f"(sample: {listed or 'none'}; memory_manage(action='exports', "
            f"module={mod!r}) to browse)")
    if "+" not in s:
        # Bare module name without `+offset` or `!export` — easy to send
        # by mistake; point to the two documented resolve paths rather
        # than crash with the generic "not a valid int" from _addr.
        if s.lower().endswith(('.exe', '.dll', '.sys', '.cpl', '.ocx', '.drv')):
            raise ValueError(
                f"{name}: {value!r} is a bare module name — use "
                f"'{s}+<offset>' for a VA inside the module or "
                f"'{s}!<export>' to resolve an export symbol")
        return _addr(value, name)
    mod, sep, off = s.partition("+")
    mod = mod.strip()
    off = off.strip()
    if not mod or not off:
        raise ValueError(f"{name}: {value!r} not valid module+offset notation")
    try:
        offset = int(off, 16) if off.lower().startswith("0x") else int(off, 0)
    except ValueError as exc:
        raise ValueError(f"{name}: offset {off!r} not a valid int/hex") from exc
    mod_l = mod.lower()
    mods = await client.mem_modules(pid, kernel)
    for m in mods:
        nm = str(m.get("name", "")).lower()
        pth = str(m.get("path", "")).lower()
        if nm == mod_l or pth.endswith("\\" + mod_l) or nm.startswith(mod_l):
            base = m.get("base")
            base_i = int(base) if isinstance(base, (int, str)) else 0
            return base_i + offset
    raise ValueError(
        f"{name}: module {mod!r} not found in "
        f"{'kernel' if kernel else 'pid=' + str(pid) + ' user'} module list "
        "(memory_manage(action='modules', filter=…) to browse; case-insensitive)")


__all__ = [
    "_addr",
    "_addr_resolve",
    "_enrich_win32",
]
