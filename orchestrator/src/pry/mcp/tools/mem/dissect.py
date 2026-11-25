"""Dissect handler for ``memory_manage`` (v17 fast path + v16 fallback).

Mirrors the Wave 1 pattern where a v15 agent falls back to the
orchestrator-side implementation: the Phase B-K agent (and any
pre-v17 agent) lacks DissectService, so we decode each aligned slot
via ``memory_manage(action='read', decode=...)``. Slower by a
round-trip per slot, but functional.

Scorer is a straight port of the C++ side (plan §3.3) so a Python
caller mocking either routing path sees identical ``probable_type``
choices. Tie-breaks in the order pointer > utf16 > ascii > f64 > f32
> i32.
"""
from __future__ import annotations

import logging
import math
import struct
from typing import Any

from .._runtime.response import _hexify_dict, _j
from .pointer_map import _map_agent_error_kind


log = logging.getLogger("pry.mcp.tools.mem")

# once-per-session WARN gate for
# the dissect_version cache-lookup broad-except fallback.
_v17_gate_warn_logged = False


DISSECT_MAX_BYTES = 65_536
DISSECT_MAX_ROWS = 4_096

# multi-instance compare caps — mirrors
# the agent-side DISSECT_COMPARE_* constants in dissect_service.hpp.
DISSECT_COMPARE_MAX_INSTANCES = 32
DISSECT_COMPARE_SHARED_VOTE = 2
DISSECT_COMPARE_MIN_INSTANCES_FOR_CLASS = 3


# Classification rank table — matches dissect_service.cpp::Compare's
# probable_type tie-break. Kept in sync via the shared plan doc.
_PROBABLE_TYPE_RANK = {
    "pointer": 5, "utf16": 4, "ascii": 3, "f64": 2, "f32": 1, "i32": 0,
}

# Score weights — same as agent/src/scan/dissect_service.hpp.
SCORE_PTR_MOD_EXEC   = 50
SCORE_PTR_MAPPED_ANY = 10
SCORE_UTF16_16W      = 40
SCORE_UTF16_8W       = 20
SCORE_ASCII_16B      = 30
SCORE_ASCII_8B       = 15
SCORE_F64            =  5
SCORE_F32            =  5


def _is_printable_ascii(b: int) -> bool:
    return 0x20 <= b <= 0x7E


def _is_printable_bmp(w: int) -> bool:
    if w < 0x20:
        return False
    if w == 0xFFFE or w == 0xFFFF:
        return False
    if 0xD800 <= w <= 0xDFFF:
        return False
    return True


def _ascii_prefix(buf: bytes) -> str:
    out = []
    for b in buf[:16]:
        if not _is_printable_ascii(b):
            break
        out.append(chr(b))
    return "".join(out)


def _utf16_prefix(buf: bytes) -> str:
    words = min(16, len(buf) // 2)
    out = []
    for i in range(words):
        w = buf[i * 2] | (buf[i * 2 + 1] << 8)
        if not _is_printable_bmp(w):
            break
        out.append(chr(w))
    return "".join(out)


def _float_reasonable(v: float) -> bool:
    if not math.isfinite(v):
        return False
    a = abs(v)
    return 1e-10 <= a <= 1e10


def _classify_pointer(u64: int, modules: list[dict[str, Any]]) -> tuple[str, str, int, int]:
    """Return (classification, module_name, module_off, score)."""
    if u64 == 0:
        return "", "", 0, 0
    for m in modules:
        base = int(m.get("base", 0))
        size = int(m.get("size", 0))
        if size and base <= u64 < base + size:
            return "image_unknown", m.get("name", ""), u64 - base, SCORE_PTR_MOD_EXEC
    # canonical user-mode VA not in a module -> probably heap/stack/anon
    if (u64 >> 47) == 0 and u64 > 0x10000:
        return "other", "", 0, SCORE_PTR_MAPPED_ANY
    return "", "", 0, 0


def _decode_slot(buf: bytes, off: int, base_va: int,
                 modules: list[dict[str, Any]],
                 with_modules: bool) -> dict[str, Any]:
    """Produce one DissectSlot dict — matches the agent-side DecodeSlot
    bit-for-bit for the same inputs."""
    end = len(buf)
    slice_ = buf[off:off + 8].ljust(8, b"\x00") if off < end else b"\x00" * 8
    u64 = struct.unpack("<Q", slice_)[0]
    i32 = struct.unpack("<i", slice_[:4])[0]
    u32 = struct.unpack("<I", slice_[:4])[0]
    f32 = struct.unpack("<f", slice_[:4])[0]
    f64 = struct.unpack("<d", slice_)[0]

    tail = buf[off:off + 32]
    ascii_p = _ascii_prefix(tail)
    utf16_p = _utf16_prefix(tail)

    score_ptr = 0
    ptr_target = 0
    ptr_module = ""
    ptr_off = 0
    ptr_class = ""
    if with_modules:
        klass, mod, mod_off, score = _classify_pointer(u64, modules)
        if klass:
            ptr_class = klass
            ptr_module = mod
            ptr_off = mod_off
            score_ptr = score
            ptr_target = u64

    score_ascii = 0
    if len(ascii_p) >= 16:
        score_ascii = SCORE_ASCII_16B
    elif len(ascii_p) >= 8:
        score_ascii = SCORE_ASCII_8B

    score_utf16 = 0
    wlen = len(utf16_p)  # characters, not UTF-8 bytes
    if wlen >= 16:
        score_utf16 = SCORE_UTF16_16W
    elif wlen >= 8:
        score_utf16 = SCORE_UTF16_8W

    score_f64 = SCORE_F64 if _float_reasonable(f64) else 0
    score_f32 = SCORE_F32 if _float_reasonable(f32) else 0

    best = 0
    best_name = "i32"
    for score, name in [(score_ptr, "pointer"),
                        (score_utf16, "utf16"),
                        (score_ascii, "ascii"),
                        (score_f64, "f64"),
                        (score_f32, "f32")]:
        if score > best:
            best = score
            best_name = name

    return {
        "offset": off,
        "va": base_va + off,
        "u64_le": u64,
        "i32_le": i32,
        "u32_le": u32,
        "f32_le": f32,
        "f64_le": f64,
        "ptr_target_va": ptr_target,
        "ptr_module": ptr_module,
        "ptr_module_off": ptr_off,
        "ptr_classification": ptr_class,
        "ascii_prefix": ascii_p,
        "utf16_prefix": utf16_p,
        "probable_type": best_name,
        "score_pointer": score_ptr,
        "score_utf16": score_utf16,
        "score_ascii": score_ascii,
        "score_f64": score_f64,
        "score_f32": score_f32,
    }


def dissect_decode(buf: bytes, *, address: int, align: int = 4,
                   modules: list[dict[str, Any]] | None = None,
                   with_modules: bool = True) -> list[dict[str, Any]]:
    """Pure-python decode of a byte window into DissectSlot rows.
    Exposed for both the v16 fallback path and the test suite."""
    if align not in (4, 8):
        raise ValueError(f"align must be 4 or 8, got {align}")
    mods = modules or []
    rows = []
    n = min(len(buf) // align, DISSECT_MAX_ROWS)
    for r in range(n):
        rows.append(_decode_slot(buf, r * align, address, mods,
                                  with_modules))
    return rows


def dissect_compare_decode(
        bases: list[int], bufs: list[bytes], *,
        align: int = 4, window_size: int = 0,
        modules: list[dict[str, Any]] | None = None,
        with_modules: bool = True,
        shared_ptr_min_vote: int = 0,
        min_instances_for_class: int = 0,
) -> dict[str, Any]:
    """Pure-python reference implementation of the agent's
    ``DissectServiceImpl::Compare`` handler.

    Produced for the Wave 3 P1 test suite: lets us drive the full
    classification taxonomy from synthetic buffers without a rebuilt
    agent. Mirrors ``agent/src/scan/dissect_service.cpp`` line-for-line
    on the classification rules; `_decode_slot` provides the slot shape.

    Returns the same envelope the orchestrator client wraps around a
    live ``DissectCompareResponse``.
    """
    if align not in (4, 8):
        raise ValueError(f"align must be 4 or 8, got {align}")
    if len(bufs) != len(bases):
        raise ValueError("bufs/bases length mismatch")
    n = len(bases)
    w = int(window_size) if window_size else (
        max((len(b) for b in bufs), default=0))
    if w <= 0:
        w = max((len(b) for b in bufs), default=0)
    n_offsets = w // align
    shared_vote = int(shared_ptr_min_vote or DISSECT_COMPARE_SHARED_VOTE)
    min_for_class = int(min_instances_for_class
                        or DISSECT_COMPARE_MIN_INSTANCES_FOR_CLASS)
    mods = modules or []

    # Decode each instance: list of DissectInstanceSlots-shaped dicts.
    per_instance: list[dict[str, Any]] = []
    readable_flags: list[bool] = []
    for i, base_va in enumerate(bases):
        buf = bufs[i]
        row: dict[str, Any] = {"base_va": int(base_va),
                                "unreadable": False, "slots": []}
        if not buf:
            row["unreadable"] = True
            per_instance.append(row)
            readable_flags.append(False)
            continue
        rows_i = min(len(buf) // align, DISSECT_MAX_ROWS)
        for r in range(rows_i):
            row["slots"].append(_decode_slot(buf, r * align, base_va,
                                              mods, with_modules))
        per_instance.append(row)
        readable_flags.append(True)

    # Classify each offset across the per-instance rows.
    offsets_out: list[dict[str, Any]] = []
    for off_idx in range(n_offsets):
        off = off_idx * align
        values: list[int] = []
        ptr_modules: list[str] = []
        ptr_module_offs: list[int] = []
        probable_types: list[str] = []
        pointer_count = 0
        for i in range(n):
            if not readable_flags[i]:
                continue
            slots = per_instance[i]["slots"]
            if off_idx >= len(slots):
                continue
            s = slots[off_idx]
            values.append(int(s["u64_le"]))
            ptr_modules.append(str(s.get("ptr_module") or ""))
            ptr_module_offs.append(int(s.get("ptr_module_off") or 0))
            pt = str(s.get("probable_type") or "")
            probable_types.append(pt)
            if pt == "pointer":
                pointer_count += 1
        R = len(values)
        # Modal value.
        counts: dict[int, int] = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        D = len(counts)
        modal = 0
        modal_votes = 0
        for v, c in counts.items():
            if c > modal_votes:
                modal_votes = c
                modal = v
        # Probable-type majority with rank tie-break.
        type_counts: dict[str, int] = {}
        for t in probable_types:
            type_counts[t] = type_counts.get(t, 0) + 1
        best_type_votes = 0
        best_type = "i32"
        for t, c in type_counts.items():
            if c > best_type_votes or (
                    c == best_type_votes
                    and _PROBABLE_TYPE_RANK.get(t, -1)
                    > _PROBABLE_TYPE_RANK.get(best_type, -1)):
                best_type_votes = c
                best_type = t

        out: dict[str, Any] = {
            "offset": off,
            "classification": "",
            "distinct_values": D,
            "readable_instances": R,
            "modal_value": modal,
            "modal_votes": modal_votes,
            "probable_type": best_type,
            "shared_target_module": "",
            "shared_target_module_off": 0,
        }

        # Classification, matching dissect_service.cpp::Compare.
        if R < min_for_class:
            classification = "inconclusive"
        elif R == 0:
            classification = "unreadable"
        elif D == 1:
            classification = "stable"
            if ptr_modules and ptr_modules[0]:
                out["shared_target_module"] = ptr_modules[0]
                out["shared_target_module_off"] = ptr_module_offs[0]
        elif modal_votes >= shared_vote:
            # Shared-pointer candidate requires the modal voters all
            # point into the same module.
            all_voters_match_module = True
            mod = ""
            mod_off = 0
            for k, v in enumerate(values):
                if v != modal:
                    continue
                if not ptr_modules[k]:
                    all_voters_match_module = False
                    break
                if not mod:
                    mod = ptr_modules[k]
                    mod_off = ptr_module_offs[k]
                elif mod != ptr_modules[k]:
                    all_voters_match_module = False
                    break
            if all_voters_match_module and mod:
                classification = "shared_pointer"
                out["shared_target_module"] = mod
                out["shared_target_module_off"] = mod_off
            elif D == R:
                ptr_frac = pointer_count / R
                classification = ("per_instance_ptr" if ptr_frac >= 0.8
                                   else "per_instance_scalar")
            else:
                classification = "noisy"
        elif D == R:
            ptr_frac = pointer_count / R
            classification = ("per_instance_ptr" if ptr_frac >= 0.8
                               else "per_instance_scalar")
        else:
            classification = "noisy"
        out["classification"] = classification
        offsets_out.append(out)

    return {
        "ok": True,
        "offsets": offsets_out,
        "per_instance": per_instance,
        "n_instances": n,
        "n_offsets": n_offsets,
    }


# -------------------------------------------- envelope helpers ---------------

def _wrap(data: dict[str, Any], *, view: str = "") -> str:
    ok = bool(data.get("ok", True))
    kind: str = "dissect"
    if not ok:
        # translate the agent's
        # error-kind slug so dissect failures surface as a named kind,
        # not the generic ``kind='dissect'``. Shares pointer_map.py's
        # mapper (common pool of agent-side error strings; adding a
        # dissect-specific one later just extends that function).
        agent_err = str(data.get("error") or "")
        agent_kind = str(data.get("agent_kind") or "")
        mapped = _map_agent_error_kind(agent_err, agent_kind=agent_kind)
        # Dissect may also propagate its own orchestrator-set kinds
        # (would_exceed, bad_argument, read_failed); honour them.
        existing_kind = str(data.get("kind") or "")
        if existing_kind:
            kind = existing_kind
        elif mapped:
            kind = mapped
    env = {
        "ok": ok,
        "kind": kind,
        "tool": "memory_manage",
        "action": "dissect",
        "data": {k: v for k, v in data.items() if k not in ("ok", "kind")},
    }
    if view:
        env["target"] = view
    return _j(_hexify_dict(env, add_int_mirror=True))


def _dissect_version(ctx, name: str) -> int:
    """Return the cached ``dissect_version`` for a view key / bare
    machine label.

    Dedicated gate — older agents left ``pointer_map_version`` as the proxy signal, which
    conflated two services. The field defaults to 0 on old agents so
    this returns 0 (fallback path) for them. New callers get the
    DissectService advert directly.
    """
    global _v17_gate_warn_logged
    try:
        sess = ctx.session
        info_map = sess._machine_info or {}
        view = name or ""
        if not view and hasattr(sess, "focus_view"):
            view = sess.focus_view()
        info = info_map.get(view)
        if info:
            return int(info.get("dissect_version") or 0)
        # Bare-machine-name path — scan every view on that machine.
        if hasattr(sess, "machine_of") and name:
            machine = sess.machine_of(name)
            for k, v in info_map.items():
                key_machine = (sess.machine_of(k)
                               if hasattr(sess, "machine_of") else k)
                if key_machine == machine:
                    ver = int((v or {}).get("dissect_version") or 0)
                    if ver >= 1:
                        return ver
    except Exception:
        # warn once per session.
        if not _v17_gate_warn_logged:
            log.warning("_dissect_version: session cache lookup raised; "
                        "falling back to version=0 (pre-v17 behaviour) for "
                        "name=%r. Subsequent occurrences will be silent.",
                        name)
            _v17_gate_warn_logged = True
    return 0


async def _list_modules_via_mem(c, pid: int) -> list[dict[str, Any]]:
    """v16 fallback: fetch module list through the agent's existing
    ListModules RPC. Returns [] on failure."""
    try:
        if not hasattr(c, "list_modules"):
            return []
        r = await c.list_modules(pid=pid)
        if not r.get("ok"):
            return []
        return [{"name": m.get("name", ""), "base": int(m.get("base", 0)),
                 "size": int(m.get("size", 0))}
                for m in (r.get("modules") or [])]
    except Exception:
        return []


async def _read_bytes_via_mem(c, *, pid: int, address: int,
                              size: int, space: str) -> bytes:
    """v16 fallback: fetch `size` bytes via the existing memory read.
    Returns whatever the agent handed back; may be short on partial."""
    r = await c.mem_read(pid=pid, va=address, size=size, space=space)
    if not r.get("ok"):
        return b""
    return bytes(r.get("data") or b"")


async def _decorate_dissect_slots(ctx, *, view: str, pid: int,
                                   data: dict[str, Any]) -> None:
    """Stamp ``slot.ptr_sym`` on every slot whose ``ptr_module`` is set
    using a single ``lookup_batch`` (plan §5). In place; never raises
    — a backend failure leaves slots undecorated."""
    if not isinstance(data, dict):
        return
    slots = data.get("slots")
    if not isinstance(slots, list) or not slots:
        return
    if not view:
        return
    try:
        from ._decorate import SymbolDecorator
    except Exception:  # noqa: BLE001 - decoration is advisory
        return
    vas: list[int] = []
    for s in slots:
        if not isinstance(s, dict):
            continue
        if not s.get("ptr_module"):
            continue
        va = s.get("ptr_target_va")
        if isinstance(va, int) and va:
            vas.append(int(va))
    if not vas:
        return
    try:
        dec = SymbolDecorator(ctx)
        labels = await dec.decorate_vas(view, pid, vas)
    except Exception:  # noqa: BLE001 - decoration never fails the parent
        return
    for s in slots:
        if not isinstance(s, dict):
            continue
        va = s.get("ptr_target_va")
        if isinstance(va, int) and va:
            lbl = labels.get(int(va))
            if lbl:
                s["ptr_sym"] = lbl


async def handle_dissect(ctx, c, *, pid: int, address: int, size: int,
                         space: str = "user",
                         with_modules: bool = True,
                         decode: list[str] | None = None,
                         align: int = 4, name: str = "",
                         # Wave 3 Phase D: slot-pointer -> module!Sym+disp
                         # decoration. Default on; caller opt-out for
                         # speed or when PDBs aren't cached.
                         decorate: bool = True) -> str:
    if size <= 0 or size > DISSECT_MAX_BYTES:
        return _wrap({"ok": False, "kind": "would_exceed",
                      "error": f"size out of range (1..{DISSECT_MAX_BYTES})",
                      "slots": []},
                     view=name)
    if align not in (4, 8):
        return _wrap({"ok": False, "kind": "bad_arg",
                      "error": f"align must be 4 or 8, got {align}",
                      "slots": []},
                     view=name)

    ver = _dissect_version(ctx, name)
    if ver >= 1:
        # v17 fast path.
        result = await c.dissect(pid=pid, address=address, size=size,
                                  space=space, with_modules=with_modules,
                                  decode=decode or [], align=align)
        if decorate and bool(result.get("ok", True)):
            await _decorate_dissect_slots(ctx, view=name, pid=pid,
                                           data=result)
        return _wrap(result, view=name)

    # v16 orchestrator-side fallback: one read + pure-python decode.
    buf = await _read_bytes_via_mem(c, pid=pid, address=address,
                                     size=size, space=space)
    if not buf:
        return _wrap({"ok": False, "kind": "read_failed",
                      "error": "memory read returned no bytes",
                      "slots": []},
                     view=name)
    modules: list[dict[str, Any]] = []
    if with_modules:
        modules = await _list_modules_via_mem(c, pid)
    rows = dissect_decode(buf, address=address, align=align,
                           modules=modules, with_modules=with_modules)
    fallback_payload: dict[str, Any] = {"ok": True, "slots": rows,
                                         "fallback": True, "agent_abi": "v16"}
    if decorate:
        await _decorate_dissect_slots(ctx, view=name, pid=pid,
                                       data=fallback_payload)
    return _wrap(fallback_payload, view=name)


# --------------------------------- DissectCompare (Wave 3 P1) ---------------

def _wrap_compare(data: dict[str, Any], *, view: str = "") -> str:
    """Envelope for ``dissect_compare``. Mirrors ``_wrap`` but flagged
    with its own action slug so callers can key on it."""
    ok = bool(data.get("ok", True))
    kind: str = "dissect_compare"
    if not ok:
        agent_err = str(data.get("error") or "")
        agent_kind = str(data.get("agent_kind") or "")
        mapped = _map_agent_error_kind(agent_err, agent_kind=agent_kind)
        existing_kind = str(data.get("kind") or "")
        if existing_kind:
            kind = existing_kind
        elif mapped:
            kind = mapped
    env = {
        "ok": ok,
        "kind": kind,
        "tool": "memory_manage",
        "action": "dissect_compare",
        "data": {k: v for k, v in data.items() if k not in ("ok", "kind")},
    }
    if view:
        env["target"] = view
    return _j(_hexify_dict(env, add_int_mirror=True))


def _needs_v2_envelope(view: str) -> str:
    env = {
        "ok": False,
        "kind": "feature_unavailable",
        "tool": "memory_manage",
        "action": "dissect_compare",
        "error": ("dissect_compare: this view's agent does not advertise "
                  "dissect_version>=2 (Wave 3 P1 handler absent). "
                  "Rebuild + redeploy the agent per README \"ABI v17 "
                  "rebuild\" with the Wave 3 P1 change."),
        "hint": ("flip set_dissect_version(2) on the view's Status "
                 "handler after the Compare handler is registered "
                 "(plan §3)."),
    }
    if view:
        env["target"] = view
    return _j(env)


async def _decorate_dissect_compare(ctx, *, view: str, pid: int,
                                     data: dict[str, Any]) -> None:
    """Decorate a dissect_compare response in place. Walks:
      * every ``per_instance[].slots[]`` row — stamps ``ptr_sym`` where
        ``ptr_module`` is set (same shape as ``_decorate_dissect_slots``);
      * every ``offsets[].shared_target_module`` + ``shared_target_module_off``
        — stamps a flattened ``shared_target`` string (``mod!Sym+disp`` /
        ``mod+0xNN`` / etc.) via the SymbolDecorator.
    Never raises — decoration is advisory, a backend failure leaves the
    response undecorated.
    """
    if not isinstance(data, dict) or not view:
        return
    try:
        from ._decorate import SymbolDecorator
    except Exception:  # noqa: BLE001 - decoration advisory
        return
    try:
        dec = SymbolDecorator(ctx)
    except Exception:  # noqa: BLE001
        return

    per_instance = data.get("per_instance")
    if isinstance(per_instance, list):
        # Flat batch: collect every pointer-tagged VA across every
        # instance into a single lookup_batch.
        vas: list[int] = []
        for inst in per_instance:
            if not isinstance(inst, dict):
                continue
            for s in (inst.get("slots") or []):
                if not isinstance(s, dict):
                    continue
                if not s.get("ptr_module"):
                    continue
                va = s.get("ptr_target_va")
                if isinstance(va, int) and va:
                    vas.append(int(va))
        # Also batch every offsets[].shared_target_module modal value.
        offsets = data.get("offsets")
        offset_vas: list[int] = []
        if isinstance(offsets, list):
            for o in offsets:
                if not isinstance(o, dict):
                    continue
                if not o.get("shared_target_module"):
                    continue
                mv = o.get("modal_value")
                if isinstance(mv, int) and mv:
                    offset_vas.append(int(mv))
        try:
            labels: dict[int, str | None] = {}
            if vas or offset_vas:
                labels = await dec.decorate_vas(view, pid,
                                                 list(set(vas + offset_vas)))
        except Exception:  # noqa: BLE001
            labels = {}
        # Stamp slot-level ``ptr_sym`` back onto each row.
        for inst in per_instance:
            if not isinstance(inst, dict):
                continue
            for s in (inst.get("slots") or []):
                if not isinstance(s, dict):
                    continue
                va = s.get("ptr_target_va")
                if isinstance(va, int) and va:
                    lbl = labels.get(int(va))
                    if lbl:
                        s["ptr_sym"] = lbl
        # Flatten each offset's shared target to a human string. When
        # the decorator returned a label use it; otherwise fall back to
        # ``module+0x<off>`` so the caller always gets a readable
        # ``shared_target`` on a shared_pointer offset.
        if isinstance(offsets, list):
            for o in offsets:
                if not isinstance(o, dict):
                    continue
                mod = o.get("shared_target_module") or ""
                if not mod:
                    continue
                mv = o.get("modal_value")
                lbl = labels.get(int(mv)) if isinstance(mv, int) and mv else None
                if lbl:
                    o["shared_target"] = lbl
                else:
                    mod_off = o.get("shared_target_module_off")
                    try:
                        mo_i = int(mod_off or 0)
                    except (TypeError, ValueError):
                        mo_i = 0
                    o["shared_target"] = f"{mod}+{mo_i:#x}" if mo_i else mod


async def handle_dissect_compare(ctx, c, *, pid: int,
                                  base_vas: list[int] | None,
                                  window_size: int,
                                  align: int = 4,
                                  space: str = "user",
                                  with_modules: bool = True,
                                  shared_ptr_min_vote: int = 0,
                                  min_instances_for_class: int = 0,
                                  decorate: bool = True,
                                  name: str = "") -> str:
    """Multi-instance structure compare. Plan §3.

    Gates on ``dissect_version >= 2`` via the P5-added
    ``StatusResponse.dissect_version`` field. Below that threshold the
    agent either doesn't ship the Compare handler or the handler was
    registered without a matching orchestrator; refuse cleanly with
    ``kind='feature_unavailable'``.
    """
    # Input validation (orchestrator-side preflight — mirror agent caps).
    _bases = list(base_vas or [])
    if not _bases:
        return _wrap_compare({"ok": False, "kind": "bad_arg",
                               "error": "base_vas is empty",
                               "offsets": [], "per_instance": [],
                               "n_instances": 0, "n_offsets": 0},
                              view=name)
    if len(_bases) > DISSECT_COMPARE_MAX_INSTANCES:
        return _wrap_compare({"ok": False, "kind": "too_many_instances",
                               "error": (f"base_vas has {len(_bases)} entries, "
                                         f"cap is {DISSECT_COMPARE_MAX_INSTANCES}"),
                               "offsets": [], "per_instance": [],
                               "n_instances": 0, "n_offsets": 0},
                              view=name)
    if window_size <= 0 or window_size > DISSECT_MAX_BYTES:
        return _wrap_compare({"ok": False, "kind": "would_exceed",
                               "error": f"window_size out of range "
                                        f"(1..{DISSECT_MAX_BYTES})",
                               "offsets": [], "per_instance": [],
                               "n_instances": 0, "n_offsets": 0},
                              view=name)
    if align not in (4, 8):
        return _wrap_compare({"ok": False, "kind": "bad_arg",
                               "error": f"align must be 4 or 8, got {align}",
                               "offsets": [], "per_instance": [],
                               "n_instances": 0, "n_offsets": 0},
                              view=name)

    ver = _dissect_version(ctx, name)
    if ver < 2:
        return _needs_v2_envelope(name)

    result = await c.dissect_compare(
        pid=int(pid), base_vas=_bases, window_size=int(window_size),
        align=int(align), space=space, with_modules=bool(with_modules),
        shared_ptr_min_vote=int(shared_ptr_min_vote),
        min_instances_for_class=int(min_instances_for_class),
    )
    if decorate and bool(result.get("ok", True)):
        await _decorate_dissect_compare(ctx, view=name, pid=pid,
                                         data=result)
    return _wrap_compare(result, view=name)
