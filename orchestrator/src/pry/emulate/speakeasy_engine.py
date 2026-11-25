"""Speakeasy backend — Windows-focused shellcode / PE emulation."""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from ..codegen import _load_speakeasy
from .base import EVENT_RING_DEFAULT, _Engine


# --- Speakeasy backend (Windows shellcode / PE) ----------------------------


class _SpeakeasyEngine(_Engine):
    """Thin wrapper around ``speakeasy.Speakeasy``. Delegates cpu-bound
    work to Speakeasy's own emulator; the wrapper only translates
    argument shapes and captures API calls into our event ring.
    """

    kind = "speakeasy"

    def __init__(self, arch: str, mode: str = "shellcode",
                 flavor: str = "latest") -> None:
        se = _load_speakeasy()
        self._se_mod = se
        self.arch = arch
        self._mode = mode
        self._flavor = flavor
        # ``debug=False`` keeps stdout clean.
        self._emu = se.Speakeasy()
        self._entry_module = None
        self._events: deque[dict[str, Any]] = deque(maxlen=EVENT_RING_DEFAULT)
        self._api_calls: list[dict[str, Any]] = []
        self._hooks: dict[str, Any] = {}
        self._hook_seq = 0

    def load_shellcode(self, data: bytes, entry: int) -> int:
        # Speakeasy expects a specific arch string ("x86"|"amd64").
        # 2.x made fpath the first positional — raw bytes must go via
        # the `data=` keyword or they get treated as a path.
        arch = "amd64" if self.arch == "x64" else "x86"
        addr = self._emu.load_shellcode(data=data, arch=arch)
        # Speakeasy assigns its own base; return whatever it picked.
        self.entry = int(addr)
        return self.entry

    def load_pe(self, path: str, cmdline: str = "",
                image_base: int = 0) -> int:
        module = self._emu.load_module(path)
        self._entry_module = module
        try:
            base = int(module.get_base())
        except Exception:
            base = 0
        self.entry = base
        return base

    def _apply_limits(self, *, max_ins: int, timeout_s: float) -> list[str]:
        """Push per-run limits into Speakeasy's (frozen pydantic) config:
        ``timeout`` (seconds) and ``max_instructions`` are read from
        ``emu.config`` at run time, so a model copy swapped onto both the
        facade and the live emulator applies them. Returns the limits
        that could NOT be applied (reported, never silently dropped)."""
        emu = self._emu
        base = getattr(self, "_base_config", None)
        if base is None:
            base = getattr(emu, "config", None)
            self._base_config = base
        upd: dict[str, Any] = {}
        if timeout_s:
            upd["timeout"] = float(timeout_s)
        if max_ins:
            upd["max_instructions"] = int(max_ins)
        if base is None or not hasattr(base, "model_copy"):
            return sorted(upd)
        try:
            cfg = base.model_copy(update=upd) if upd else base
            emu.config = cfg
            inner = getattr(emu, "emu", None)
            if inner is not None and hasattr(inner, "config"):
                inner.config = cfg
        except Exception:
            return sorted(upd)
        return []

    def _arm_until(self, until: int) -> bool:
        """Stop emulation when execution reaches ``until`` (code hook +
        ``Speakeasy.stop``). The hook stays registered across runs but
        only fires for the run that armed it."""
        self._active_until = int(until)
        self._until_hit = False
        hooks = getattr(self, "_until_hooks", None)
        if hooks is None:
            hooks = self._until_hooks = set()
        if until in hooks:
            return True
        emu = self._emu

        def _cb(_emu_arg, address, _size, *_rest):
            # speakeasy code hooks call cb(se, addr, size) — older
            # builds passed an extra ctx; accept both.
            if getattr(self, "_active_until", 0) == address:
                self._until_hit = True
                try:
                    emu.stop()
                except Exception:  # pragma: no cover
                    pass
            return True

        try:
            emu.add_code_hook(_cb, begin=until, end=until + 1)
        except Exception:
            return False
        hooks.add(until)
        return True

    def run(self, *, until: int = 0, max_ins: int = 0,
            timeout_s: float = 0.0) -> dict[str, Any]:
        started = time.time()
        halt_reason = "ok"
        unsupported = self._apply_limits(max_ins=max_ins, timeout_s=timeout_s)
        if until and not self._arm_until(until):
            unsupported.append("until")
        if not until:
            self._active_until = 0
        # Speakeasy exposes `run_shellcode` / `run_module` — pick by mode.
        try:
            if self._mode == "pe" and self._entry_module is not None:
                self._emu.run_module(self._entry_module)
            else:
                self._emu.run_shellcode(self.entry) if self.entry \
                    else None
        except Exception as exc:
            halt_reason = f"{type(exc).__name__}: {exc}"
        finally:
            self._active_until = 0
        if halt_reason == "ok" and until and getattr(self, "_until_hit", False):
            halt_reason = "until_reached"
        duration = time.time() - started
        try:
            api_log = getattr(self._emu, "get_api_log", None) or \
                getattr(self._emu, "get_api_calls", None)
            api_calls = list(api_log() or []) if api_log else []
        except Exception:  # pragma: no cover
            api_calls = []
        self._api_calls.extend(api_calls)
        out: dict[str, Any] = {
            "halt_reason": halt_reason,
            "duration_s": round(duration, 6),
            "api_calls": api_calls,
            "events": list(self._events),
            "limits": {"until": until or None, "max_ins": max_ins or None,
                       "timeout_s": timeout_s or None},
        }
        if unsupported:
            out["limits_unsupported"] = sorted(set(unsupported))
            out["note"] = ("speakeasy could not apply "
                           + ", ".join(sorted(set(unsupported)))
                           + " on this build — the run used its defaults "
                             "(use engine=unicorn for exact limits)")
        return out

    def step(self, n: int = 1) -> dict[str, Any]:
        # Speakeasy has no resume-at-cursor stepping: each run restarts at
        # the entry, so `step(n)` executes the FIRST n instructions from
        # the entry (instruction cap now honoured via max_instructions).
        result = self.run(max_ins=int(n or 1))
        result.setdefault(
            "note", "speakeasy step re-runs from the entry with an "
                    "instruction cap of n (no resume at the cursor); use "
                    "engine=unicorn for true single-stepping")
        return result

    def read_regs(self) -> dict[str, int]:
        try:
            emu = self._emu
            regs_getter = getattr(emu, "get_regs", None) or \
                getattr(emu, "get_all_registers", None) or \
                getattr(emu, "reg_read_all", None)
            if regs_getter is None:
                return {}

            def _to_int(v: Any) -> int:
                if isinstance(v, int):
                    return v
                s = str(v).strip()
                try:
                    return int(s, 0)
                except ValueError:
                    return int(s, 16)

            return {str(k): _to_int(v)
                    for k, v in dict(regs_getter()).items()}
        except Exception:  # pragma: no cover
            return {}

    def write_regs(self, regs: dict[str, int]) -> None:
        emu = self._emu
        setter = getattr(emu, "reg_write", None)
        if setter is None:  # pragma: no cover
            raise RuntimeError("speakeasy engine: reg_write not available")
        for k, v in regs.items():
            iv = int(v, 0) if isinstance(v, str) else int(v)
            setter(k, iv)

    def mem_map(self, address: int, size: int, prot: str = "rwx",
                label: str = "") -> None:
        emu = self._emu
        emu.mem_map(address, size, tag=label or "user")

    def mem_unmap(self, address: int, size: int) -> None:  # pragma: no cover
        emu = self._emu
        unmap = getattr(emu, "mem_unmap", None)
        if unmap:
            unmap(address, size)

    def mem_read(self, address: int, size: int) -> bytes:
        return bytes(self._emu.mem_read(address, size))

    def mem_write(self, address: int, data: bytes) -> int:
        self._emu.mem_write(address, bytes(data))
        return len(data)

    def add_hook(self, spec: dict[str, Any]) -> str:
        events = self._events
        emu = self._emu
        kind = spec.get("kind", "api")
        action = spec.get("action", "log")
        return_value = spec.get("return_value")

        if kind == "api":
            api = str(spec.get("api", ""))
            if "!" not in api:
                raise ValueError("api hook: format is 'module!name' "
                                  "(e.g. 'kernel32!VirtualAlloc')")
            mod, name = api.split("!", 1)

            def _cb(emu_arg, api_name, func, params):
                events.append({"kind": "api_call",
                                "api": api,
                                "params": [str(p) for p in (params or [])],
                                "ts": time.time()})
                if action == "return" and return_value is not None:
                    return int(return_value, 0) if isinstance(return_value, str) \
                           else int(return_value)
                return None

            h = emu.add_api_hook(_cb, mod, name)
        elif kind == "addr":
            addr = int(spec.get("address", 0), 0) if isinstance(spec.get("address"), str) \
                    else int(spec.get("address", 0))

            def _cb_addr(emu_arg, address, size, *_ctx):
                events.append({"kind": "addr_hook",
                                "address": address,
                                "size": size,
                                "ts": time.time()})

            h = emu.add_code_hook(_cb_addr, begin=addr, end=addr)
        else:
            raise ValueError(f"unknown hook kind {kind!r}")
        self._hook_seq += 1
        hid = f"h{self._hook_seq:04d}"
        self._hooks[hid] = h
        return hid

    def remove_hook(self, hook_id: str) -> bool:
        h = self._hooks.pop(hook_id, None)
        if h is None:
            return False
        try:
            self._emu.remove_hook(h)
        except Exception:  # pragma: no cover
            pass
        return True

    def snapshot(self) -> dict[str, Any]:  # pragma: no cover - depends on speakeasy
        raise NotImplementedError("speakeasy snapshot/restore not wired yet — "
                                   "use engine=unicorn for snapshotting")

    def restore(self, snap: dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:
        self._emu = None
