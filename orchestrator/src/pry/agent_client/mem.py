"""Memory-service methods split off from AgentClient."""

from __future__ import annotations

from typing import Any, AsyncIterator

from ..generated import pry_pb2 as pb
from .wire import proto_to_dict, status_dict

# v12: MemoryWriteRequest.flags mirrors PRY_MEM_WRF_* (comm/pry_abi.h);
# response write_path indexes proto's 0..3 enum.
_PRY_MEM_WRF_STRICT_VA = 0x1
_WRITE_PATH_NAMES = {0: "unknown", 1: "direct_va", 2: "phys_remap", 3: "foreign_cr3"}


class MemMixin:
    # --------------------------------------------------------------- Memory ----

    def _softfault_ok(self, allow_fault: bool) -> bool:
        """security.allow_kernel_softfault enforcement at the wire.
        The session sets ``allow_softfault`` from config; when it is off,
        ``allow_fault`` is dropped from every read this client sends (a
        driver soft-fault of a non-resident kernel page wedged the lab VM),
        whichever orchestrator code path asked for it."""
        if allow_fault and not getattr(self, "allow_softfault", False):
            return False
        return bool(allow_fault)

    async def mem_read(self, pid: int, address: int, size: int, space: str = "user",
                       allow_fault: bool = False,
                       partial: bool = False,
                       timeout: float | None = None,
                       want_meta: bool = False,
                       *,
                       max_bytes: int = 0,
                       allow_mmio: bool = False) -> bytes | tuple[bytes, dict]:
        """Read `size` bytes from `pid`/`address` in the given space.

        v6 `partial=True` (kernel space only): per-4KB walk on the driver
        side; returns whatever prefix succeeds. Combine with `want_meta=True`
        to get `(data, {"read_bytes": N, "first_bad_offset": M})` — the
        offset tells you where the hole starts so you can advance past it.
        Without want_meta the return is bytes as before (backwards-compat).

        v9 `max_bytes` (keyword-only): agent-side hard byte cap independent
        of `size`. 0 disables. When set to N < size, the driver reads only
        N bytes without touching the maxMemReadBytes ceiling.

        vNEXT T3.1 (PR#5) `allow_mmio` (keyword-only, space='physical'
        only): opt into the historical MMIO/firmware-ROM read path. The
        driver default-denies physical reads outside RAM with
        STATUS_ACCESS_DENIED since one MmCopyMemory on a PCI BAR wedged
        the box in field testing. `want_meta=True` surfaces
        ``agent_without_allow_mmio`` in the meta dict when the agent
        build predates the field — the orchestrator uses that to warn
        the operator without refusing the read.
        """
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        allow_fault = self._softfault_ok(allow_fault)
        req_kwargs = {"pid": pid, "address": address, "size": size, "space": sp,
                      "allow_fault": allow_fault}
        # Only set partial= when the caller asked for it — a v5 agent that
        # doesn't know the field silently ignores unknown proto3 fields.
        if partial:
            req_kwargs["partial"] = True
        if max_bytes:
            req_kwargs["max_bytes"] = int(max_bytes)
        # vNEXT T3.1 (PR#5): wire the physical-read guard flag through to
        # the agent. Guard with hasattr so older generated pb bindings
        # (pre-T3.1) still work — proto3 silently drops unknown fields,
        # which would otherwise mean the opt-in request looked exactly
        # like a legacy pre-guard call. agent_without_allow_mmio is set
        # on the returned meta so the orchestrator can warn the caller.
        has_field = "allow_mmio" in pb.MemoryReadRequest.DESCRIPTOR.fields_by_name
        if allow_mmio and has_field:
            req_kwargs["allow_mmio"] = True
        msg = await self._call(
            self.memory.Read,
            pb.MemoryReadRequest(**req_kwargs),
            timeout=timeout,
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        data = bytes(msg.data)
        if want_meta:
            meta = {"read_bytes": msg.read_bytes,
                    "first_bad_offset": getattr(msg, "first_bad_offset", 0)}
            if allow_mmio and not has_field:
                # Caller asked for the opt-in but this orchestrator was
                # built against pre-T3.1 proto bindings — the agent will
                # not see the flag. Surface it so the MCP tool can warn.
                meta["agent_without_allow_mmio"] = True
            return data, meta
        return data

    async def mem_write(self, pid: int, address: int, data: bytes, space: str = "user",
                        allow_map_write: bool = False, *,
                        strict_va: bool = False, cr3: int = 0) -> dict[str, Any]:
        """Write `data` to `pid`/`address`; returns
        ``{"written_bytes": n, "write_path": str}``.

        v12 (ABI v12 agent+driver): `write_path` reports which store path
        ran — "direct_va" (linear VA copy), "phys_remap" (page-walk +
        physical map; DR watchpoints on the linear address did NOT see
        the store), "foreign_cr3" (direct VA under `cr3`), or "unknown"
        (pre-v12 peer / no out-reply).

        `strict_va` (kernel space): refuse the phys-remap fallback — a
        fault on the direct VA path fails the write instead of silently
        bypassing linear-address watchpoints.
        `cr3` (kernel space): run the store under the caller-supplied
        address space (driver verifies the foreign kernel half first).
        Both are keyword-only; `allow_map_write` stays positional-or-keyword
        for the pre-v12 callers that pass it as the 5th arg.
        """
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        flags = _PRY_MEM_WRF_STRICT_VA if strict_va else 0
        msg = await self._call(
            self.memory.Write,
            pb.MemoryWriteRequest(pid=pid, address=address, data=data, space=sp,
                                  allow_map_write=allow_map_write,
                                  cr3=cr3, flags=flags),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"written_bytes": msg.written_bytes,
                "write_path": _WRITE_PATH_NAMES.get(
                    msg.write_path, f"path_{msg.write_path}")}

    async def mem_alloc(self, pid: int, size: int, protect: int = 4, kernel: bool = False) -> int:
        msg = await self._call(
            self.memory.Alloc,
            pb.MemoryAllocRequest(pid=pid, size=size, protect=protect, kernel=kernel),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return msg.address

    async def mem_free(self, pid: int, address: int, kernel: bool = False) -> dict[str, Any]:
        st = await self._call(
            self.memory.Free, pb.MemoryFreeRequest(pid=pid, address=address, kernel=kernel)
        )
        return status_dict(st.status)

    async def mem_protect(self, pid: int, address: int, size: int, protect: int) -> dict[str, Any]:
        msg = await self._call(
            self.memory.Protect,
            pb.MemoryProtectRequest(pid=pid, address=address, size=size, protect=protect),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"old_protect": msg.old_protect}

    async def mem_modules(self, pid: int, kernel: bool = False,
                          *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        msg = await self._call(
            self.memory.Modules,
            pb.ModulesRequest(pid=pid, kernel=kernel, limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(m) for m in msg.modules]

    async def mem_imports(self, pid: int, module: str, kernel: bool = False,
                          *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """Walk the IAT of `module` in `pid` (or in the kernel view when kernel=True)."""
        msg = await self._call(
            self.memory.ModuleImports,
            pb.ModuleImportsRequest(pid=pid, module=module, kernel=kernel,
                                    limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(e) for e in msg.entries]

    async def mem_exports(self, pid: int, module: str, kernel: bool = False,
                          *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """Walk the export table of `module` in `pid` (kernel view when kernel=True)."""
        msg = await self._call(
            self.memory.ModuleExports,
            pb.ModuleExportsRequest(pid=pid, module=module, kernel=kernel,
                                    limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(e) for e in msg.entries]

    async def mem_heaps(self, pid: int, want_blocks: bool = False,
                        max_blocks: int = 0) -> list[dict[str, Any]]:
        """Cross-process heap enumeration; want_blocks=True fetches per-block detail."""
        msg = await self._call(
            self.memory.HeapList,
            pb.HeapListRequest(pid=pid, want_blocks=want_blocks, max_blocks=max_blocks),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(h) for h in msg.heaps]

    async def heap_attrib(self, *, pid: int, vas: list[int],
                          refresh: bool = False) -> dict[str, Any]:
        """batched VA -> heap allocation
        attribution.

        Thin wrapper over ``Memory.HeapAttribLookup``. The agent builds
        a per-pid interval-tree index on first call, rebuilds when
        either the TTL (2 s default), the committed-sum delta probe
        (> max(1 MiB, 1 %)), or ``refresh=True`` demands it. Returns::

            {
              "ok": True / False,
              "error": str,                 # only on failure
              "agent_kind": str,            # only when the agent set OpStatus.kind
              "records": [{va, found, heap_handle, segment_base,
                           chunk_base, chunk_size, flags, size_class},
                          ...],
              "index_from_cache": bool,
              "cache_epoch": int,
              "cache_age_ms": int,
              "cache_committed_sum": int,
            }

        Records are returned in the same order as the input ``vas`` so
        the caller can ``zip`` them.
        """
        if not hasattr(pb, "HeapAttribRequest") or \
                not hasattr(self.memory, "HeapAttribLookup"):
            return {
                "ok": False,
                "kind": "agent_version",
                "error": ("heap_attrib: agent predates the HeapAttribLookup "
                          "RPC"),
                "records": [],
                "index_from_cache": False,
                "cache_epoch": 0,
                "cache_age_ms": 0,
                "cache_committed_sum": 0,
            }
        req = pb.HeapAttribRequest(
            pid=int(pid or 0),
            vas=[int(v) for v in (vas or [])],
            refresh=bool(refresh),
        )
        try:
            msg = await self._call(self.memory.HeapAttribLookup, req)
        except Exception as exc:  # noqa: BLE001
            text = str(exc)
            if "UNIMPLEMENTED" in text:
                return {
                    "ok": False, "kind": "agent_version",
                    "error": ("heap_attrib: agent predates the "
                              "HeapAttribLookup RPC"),
                    "records": [], "index_from_cache": False,
                    "cache_epoch": 0, "cache_age_ms": 0,
                    "cache_committed_sum": 0,
                }
            raise
        out: dict[str, Any] = {
            "ok": bool(msg.status.ok),
            "records": [{
                "va": int(r.va),
                "found": bool(r.found),
                "heap_handle": int(r.heap_handle),
                "segment_base": int(r.segment_base),
                "chunk_base": int(r.chunk_base),
                "chunk_size": int(r.chunk_size),
                "flags": int(r.flags),
                "size_class": int(r.size_class),
            } for r in msg.records],
            "index_from_cache": bool(msg.index_from_cache),
            "cache_epoch": int(msg.cache_epoch),
            "cache_age_ms": int(msg.cache_age_ms),
            "cache_committed_sum": int(msg.cache_committed_sum),
        }
        if not msg.status.ok:
            out["error"] = msg.status.error
            kind = getattr(msg.status, "kind", "") or ""
            if kind:
                out["agent_kind"] = kind
        return out

    async def mem_heap_info(self, pid: int, *, heap_filter: int = 0,
                            include_segments: bool = False,
                            include_lfh_buckets: bool = False,
                            ) -> dict[str, Any]:
        """segment-heap decode.

        * ``heap_filter`` — non-zero HEAP* (handle) VA to decode a
          single heap in the target; 0 decodes every heap in the pid.
        * ``include_segments`` — populate the SegContext page-descriptor
          walk under each heap row.
        * ``include_lfh_buckets`` — fill LFH bucket + variable-size
          state per heap (requires ``include_segments``).

        PPL asymmetry: the umagent view opens the target with
        ``PROCESS_VM_READ`` and fails ``access_denied`` on PP/PPL
        processes. The agent view reads through the pry driver, so
        PPL heaps still decode cleanly. The orchestrator tool handler
        documents this in the help blurb.

        Returns ``{ok, heaps[], coverage, hint}``. ``coverage='partial'``
        + ``hint='dyn_data_wave_3_pending'`` while the segment-heap
        offset table is still owned by Wave 3 dyn-data.
        """
        if getattr(self, "memory", None) is None or \
                not hasattr(pb, "HeapInfoRequest"):
            return {"ok": False, "kind": "agent_version",
                    "error": ("heap_info: older agent/umagent "
                              "(Memory.HeapInfo missing)"),
                    "heaps": [], "coverage": "unknown"}
        req = pb.HeapInfoRequest(
            pid=int(pid or 0),
            heap_filter=int(heap_filter or 0),
            include_segments=bool(include_segments),
            include_lfh_buckets=bool(include_lfh_buckets),
        )
        try:
            msg = await self._call(self.memory.HeapInfo, req)
        except Exception as exc:
            text = str(exc)
            if "UNIMPLEMENTED" in text:
                return {"ok": False, "kind": "agent_version",
                        "error": ("heap_info: agent/umagent predates the "
                                  "HeapInfo RPC"),
                        "heaps": [], "coverage": "unknown"}
            raise
        return {
            "ok": bool(msg.status.ok),
            "error": msg.status.error if not msg.status.ok else "",
            "heaps": [proto_to_dict(h) for h in msg.heaps],
            "coverage": str(msg.coverage or "complete"),
            "hint": str(msg.hint or ""),
        }

    async def mem_processes(self, *, limit: int = 0, offset: int = 0,
                            with_cmdline: bool = False,
                            full: bool = False) -> list[dict[str, Any]] | dict[str, Any]:
        # v14: agent+umagent enumerate via NtQuerySystemInformation now —
        # no driver dependency, plus session_id + create_time_100ns rows.
        # cmdline is opt-in (per-pid open cost). full=True returns
        # {"processes": [...], "source": "agent"|"driver"} so callers can
        # tell which enumerator answered.
        req_kw: dict[str, Any] = {"limit": limit, "offset": offset}
        if "with_cmdline" in pb.ListProcessesRequest.DESCRIPTOR.fields_by_name:
            req_kw["with_cmdline"] = bool(with_cmdline)
        msg = await self._call(
            self.memory.ListProcesses,
            pb.ListProcessesRequest(**req_kw),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        rows = [proto_to_dict(p) for p in msg.processes]
        if full:
            return {"processes": rows,
                    "source": str(getattr(msg, "source", "") or "agent")}
        return rows

    async def mem_scan(
        self, pid: int, pattern: bytes, mask: str = "", base: int = 0, size: int = 0,
        max_results: int = 64, space: str = "user",
    ) -> list[int]:
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        msg = await self._call(
            self.memory.Scan,
            pb.PatternScanRequest(
                pid=pid, pattern=pattern, mask=mask, base=base, size=size,
                max_results=max_results, space=sp,
            ),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return list(msg.addresses)

    async def mem_scan_stream(
        self, pid: int, pattern: bytes, mask: str = "", base: int = 0,
        size: int = 0, max_results: int = 64, space: str = "user",
    ) -> "AsyncIterator[dict[str, Any]]":
        """server-streaming pattern scan.

        Yields one dict per PatternScanChunk arriving from the agent:
        ``{addresses: [int,...], bytes_scanned, cursor, done, status?}``.
        Consumer cancels by breaking out of the iteration — gRPC tears
        down the stream and the agent's handler observes IsCancelled().
        """
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        request = pb.PatternScanRequest(
            pid=pid, pattern=pattern, mask=mask, base=base, size=size,
            max_results=max_results, space=sp,
        )
        # No client-side timeout: scan streams are inherently long. If the
        # caller wants a deadline they wrap the iteration in asyncio.wait_for
        # or break out on their own progress-timeout logic.
        async for chunk in self._stream(self.memory.ScanStream, request):
            out: dict[str, Any] = {
                "addresses": list(chunk.addresses),
                "bytes_scanned": int(chunk.bytes_scanned),
                "cursor": int(chunk.cursor),
                "done": bool(chunk.done),
            }
            if chunk.HasField("status") and not chunk.status.ok:
                out["error"] = chunk.status.error
            yield out

    async def vad_list(self, pid: int, *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """VAD walk of pid (kernel view; build-gated offsets)."""
        msg = await self._call(
            self.memory.VadList,
            pb.VadRequest(pid=pid, limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(e) for e in msg.entries]

    async def handle_list(self, pid: int, want_names: bool = False,
                          *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """Handle table of pid; names resolved only when want_names (slow)."""
        msg = await self._call(
            self.memory.HandleList,
            pb.HandleListRequest(pid=pid, want_names=want_names,
                                 limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(h) for h in msg.handles]

    # -------------------------------------- v4: phys ranges / pool scan / reg --

    async def phys_ranges(self, *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """Enumerate MmGetPhysicalMemoryRanges (re-queried per call)."""
        msg = await self._call(
            self.memory.PhysicalRanges,
            pb.PhysRangesRequest(limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [{"base": r.base, "size": r.size, "kind": r.kind} for r in msg.ranges]

    async def pool_scan(self, tag_filter: int = 0, nonpaged_only: bool = False,
                        paged_only: bool = False, max_results: int = 256,
                        pattern: bytes = b"", mask: bytes = b"",
                        offset: int = 0, content_span: int = 0,
                        cursor: int = 0) -> dict[str, Any]:
        """Kernel big-pool walk with optional tag/paged/content filters.

        `pattern` (<=64 bytes, newer driver) + `content_span` (<=64 KiB,
        newer driver) drives an MmCopyMemory-backed content check on
        each surviving entry; a wildcard mask byte is 0 or '?' (0x3F).

        `cursor` resumes a prior scan from
        ``next_cursor``; the response carries `holes`, `span_truncated`,
        `last_index`, and `next_cursor` (0 when the scan completed).
        """
        req_kwargs = {
            "tag_filter": tag_filter, "nonpaged_only": nonpaged_only,
            "paged_only": paged_only, "max_results": max_results,
            "pattern": pattern, "mask": mask,
            "offset": offset, "content_span": content_span,
        }
        probe = pb.PoolScanRequest()
        if hasattr(probe, "cursor"):
            req_kwargs["cursor"] = int(cursor)
        req = pb.PoolScanRequest(**req_kwargs)
        msg = await self._call(self.memory.PoolScan, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {
            "required": msg.required, "considered": msg.considered,
            # Resumable-scan fields; 0 on older agents.
            "holes": int(getattr(msg, "holes", 0) or 0),
            "span_truncated": int(getattr(msg, "span_truncated", 0) or 0),
            "last_index": int(getattr(msg, "last_index", 0) or 0),
            "next_cursor": int(getattr(msg, "next_cursor", 0) or 0),
            "entries": [{
                "va": e.virtual_address, "size": e.size_in_bytes,
                "tag": e.tag, "tag_ascii": e.tag_ascii,
                "nonpaged": e.nonpaged,
                "matched_offset": e.matched_offset,
            } for e in msg.entries],
        }

    # ------------------------------------- v5: mem streaming + agent breadcrumb --

    async def mem_read_stream(self, pid: int, address: int, size: int,
                              space: str = "user",
                              allow_fault: bool = False,
                              timeout: float | None = None):
        """Async iterator of (offset, bytes) chunks over the server-streaming
        Memory.ReadStream RPC. Removes the manual-chunk dance callers had
        to do for >4 MiB kernel reads. Caller consumes:

            async for offset, chunk in c.mem_read_stream(0, va, size, "kernel"):
                out[offset:offset+len(chunk)] = chunk

        Raises RuntimeError on any mid-stream error chunk.
        """
        if not hasattr(self.memory, "ReadStream"):
            raise RuntimeError("mem_read_stream: agent < v5 (Memory.ReadStream missing)")
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        req = pb.MemoryReadRequest(pid=pid, address=address, size=size, space=sp,
                                   allow_fault=self._softfault_ok(allow_fault))
        eff = self._timeout if timeout is None else (timeout if timeout > 0 else None)
        # through _stream — same deadline / error normalization /
        # recent_ops ring as unary calls.
        first = True
        async for chunk in self._stream(self.memory.ReadStream, req,
                                        timeout=eff):
            if first:
                first = False
                if chunk.HasField("status") and not chunk.status.ok:
                    raise RuntimeError(f"mem_read_stream: {chunk.status.error}")
            if chunk.HasField("status") and chunk.status.error:
                # Mid-stream error chunk: raise. eof will also be set.
                raise RuntimeError(f"mem_read_stream: {chunk.status.error}")
            if chunk.data:
                yield chunk.offset, chunk.data
            if chunk.eof:
                return

    async def mem_read_all(self, pid: int, address: int, size: int,
                           space: str = "user", allow_fault: bool = False,
                           timeout: float | None = None,
                           cap_bytes: int = 256 * 1024 * 1024) -> bytes:
        """Collect a mem_read_stream() into a single bytes. `cap_bytes` is
        a safety belt against a runaway caller — raises if size exceeds it.
        """
        if size > cap_bytes:
            raise ValueError(f"mem_read_all: size {size} > cap_bytes {cap_bytes}; "
                             "raise cap_bytes or use mem_read_stream directly")
        buf = bytearray(size)
        async for off, data in self.mem_read_stream(pid, address, size, space,
                                                     allow_fault=allow_fault,
                                                     timeout=timeout):
            end = off + len(data)
            if end > size:
                # Server sent past our end — clamp; probably a bug there
                data = data[: size - off]
                end = size
            buf[off:end] = data
        return bytes(buf)

    # ------------------------------------- v7: va_translate + memory watch --

    async def mem_va_translate(self, va: int, space: str = "kernel",
                                pid: int = 0, cr3: int = 0) -> dict[str, Any]:
        """VA -> PA via the driver's page-table walk.

        v12: `space="user"` requires `pid` — the driver attaches to that
        process and walks its tables. `cr3` (either space) forces an
        explicit root instead of the space/pid-resolved one — useful for
        foreign-address-space forensics.
        """
        if not hasattr(self.memory, "VaTranslate"):
            raise RuntimeError("mem_va_translate: agent < v7 (Memory.VaTranslate missing)")
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        req = pb.VaTranslateRequest(space=sp, pid=pid, va=va, cr3=cr3)
        msg = await self._call(self.memory.VaTranslate, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {
            "pa": msg.pa, "present": msg.present, "cr3": msg.cr3,
            "page_size_shift": msg.page_size_shift,
        }

    async def idt_list(self, all_cpus: bool = False) -> dict[str, Any]:
        """v12 per-CPU IDT dump (Memory.IdtList, ABI v12).

        Returns ``{"ok", "idt_base", "idt_limit", "entries": [row, ...]}``
        where each row keeps the raw decoded KIDTENTRY64 fields —
        cpu/vector/handler_va/selector/ist/dpl plus `idt_base` (the IDTR
        base of the CPU that row was read on; per-CPU drift is a detour
        signature for the caller to score).
        """
        if not hasattr(self.memory, "IdtList"):
            raise RuntimeError("idt_list: agent < v12 (Memory.IdtList missing)")
        msg = await self._call(self.memory.IdtList,
                               pb.IdtListRequest(all_cpus=all_cpus))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {
            "ok": True,
            "idt_base": msg.idt_base,
            "idt_limit": msg.idt_limit,
            "entries": [{
                "cpu": e.cpu, "vector": e.vector,
                "handler_va": e.handler_va, "selector": e.selector,
                "ist": e.ist, "dpl": e.dpl,
                "idt_base": getattr(e, "idt_base", 0),
            } for e in msg.entries],
        }

    async def mem_watch_stream(self, address: int, length: int,
                               space: str = "kernel", pid: int = 0,
                               interval_ms: int = 100, duration_s: int = 60,
                               expected_hex: bytes = b"", max_events: int = 0,
                               tag: str = "") -> AsyncIterator[dict[str, Any]]:
        """Async iterator over Memory.Watch events. Yields dicts with
        {seq, ts_ms, prev, now, eof, reason, read_failed}. Terminates when
        the agent closes the stream (duration/max_events/read_failed) or
        when the caller stops iterating (client-cancel semantics).
        """
        if not hasattr(self.memory, "Watch"):
            raise RuntimeError("mem_watch_stream: agent < v7 (Memory.Watch missing)")
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        req = pb.WatchRequest(space=sp, pid=pid, address=address, length=length,
                              interval_ms=interval_ms, duration_s=duration_s,
                              expected_hex=expected_hex, max_events=max_events,
                              tag=tag)
        # Deadline = the agent-side duration plus slack (0 = open-ended).
        deadline = (float(duration_s) + 30.0) if duration_s else None
        first = True
        async for ev in self._stream(self.memory.Watch, req,
                                     timeout=deadline):
            if first:
                first = False
                if ev.HasField("status") and not ev.status.ok:
                    raise RuntimeError(f"mem_watch: {ev.status.error}")
            yield {
                "seq": ev.seq,
                "ts_ms": ev.ts_ms,
                "prev": bytes(ev.prev).hex(),
                "now": bytes(ev.now).hex(),
                "eof": ev.eof,
                "reason": ev.reason,
                "read_failed": ev.read_failed,
            }
            if ev.eof:
                return

    # ------------------------------------- SI #1 image coherency scoring --

    async def mem_coherency(self, *, pid: int, module: str = "",
                            module_base: int = 0,
                            mode: str = "normal",
                            max_ranges: int = 128,
                            include_mismatch_hex: bool = False) -> dict[str, Any]:
        """SI feature #1: image coherency score for one module.

        Routes to the agent's or umagent's ImageCoherency.Score RPC.
        ``mode`` is "quick" | "normal" | "full"; the agent caps the
        bytes-compared budget per mode. Response matches the proto
        ImageCoherencyResponse — populated classifier label is added by
        the orchestrator caller, not here.
        """
        if self.coherency is None:
            raise RuntimeError(
                "mem_coherency: older agent/umagent "
                "(ImageCoherency service missing)")
        mode_map = {"quick": pb.ImageCoherencyRequest.QUICK,
                    "normal": pb.ImageCoherencyRequest.NORMAL,
                    "full": pb.ImageCoherencyRequest.FULL}
        m = mode_map.get(str(mode).lower(), pb.ImageCoherencyRequest.NORMAL)
        req = pb.ImageCoherencyRequest(
            pid=int(pid or 0), module_base=int(module_base or 0),
            module_name=str(module or ""), mode=m,
            max_mismatch_ranges=int(max_ranges or 0),
            include_mismatch_hex=bool(include_mismatch_hex),
        )
        msg = await self._call(self.coherency.Score, req)
        if not msg.status.ok:
            return {"ok": False, "error": msg.status.error,
                    "module": msg.module_basename}
        out: dict[str, Any] = {
            "ok": True,
            "module": msg.module_basename,
            "module_path_disk": msg.module_path_disk,
            "size_of_image": int(msg.size_of_image),
            "bytes_compared": int(msg.bytes_compared),
            "bytes_mismatched": int(msg.bytes_mismatched),
            "coherency": float(msg.coherency),
            "sections_total": int(msg.sections_total),
            "sections_skipped_relocatable": int(msg.sections_skipped_relocatable),
            "truncated": bool(msg.truncated),
            "reloc_dir_rva": int(msg.reloc_dir_rva),
            "reloc_dir_size": int(msg.reloc_dir_size),
            "sections": [{"name": s.name,
                          "va": int(s.va),
                          "size": int(s.size),
                          "characteristics": int(s.characteristics)}
                         for s in msg.sections],
            "mismatches": [{"rva": int(r.rva),
                            "length": int(r.length),
                            "in_memory_hex": bytes(r.in_memory_sample).hex(),
                            "on_disk_hex": bytes(r.on_disk_sample).hex(),
                            "section": r.section,
                            "hint": r.hint} for r in msg.ranges],
        }
        return out

    # ---- SI #2 (Wave 1) hidden-process oracle rows -----
    async def hidden_proc_scan(self, *, pid_max: int = 0, step: int = 0,
                               modes: list[str] | None = None,
                               timeout_ms: int = 0) -> dict[str, Any]:
        """SI #2 Wave 1 — HiddenProcess.Scan (brute/registry/etw)."""
        if self.hidden_proc is None:
            raise RuntimeError("hidden_proc_scan: older agent/umagent "
                               "(HiddenProcess service missing)")
        req = pb.HiddenProcessRequest(
            pid_max=int(pid_max or 0), step=int(step or 0),
            modes=[str(m).lower() for m in (modes or [])
                    if isinstance(m, str) and m],
            timeout_ms=int(timeout_ms or 0))
        msg = await self._call(self.hidden_proc.Scan, req)
        base = {"modes_run": list(msg.modes_run),
                "modes_failed": list(msg.modes_failed)}
        if not msg.status.ok:
            return {"ok": False, "error": msg.status.error, **base}
        return {"ok": True, **base,
                "rows": [{"pid": int(r.pid), "image": r.image,
                          "present_brute": bool(r.present_brute),
                          "present_registry": bool(r.present_registry),
                          "present_etw": bool(r.present_etw),
                          "exit_time_100ns": int(r.exit_time_100ns),
                          "handle_count": int(r.handle_count),
                          "sources": r.sources} for r in msg.rows],
                "pid_max_used": int(msg.pid_max_used),
                "step_used": int(msg.step_used)}

    async def mem_watch_collect(self, address: int, length: int,
                                 space: str = "kernel", pid: int = 0,
                                 interval_ms: int = 100, duration_s: int = 60,
                                 expected_hex: bytes = b"", max_events: int = 0,
                                 tag: str = "") -> dict[str, Any]:
        """Synchronous helper for one-shot MCP callers: run the watch to
        completion and return the accumulated events. For long-running or
        push-style workflows use the mem_watch_stream iterator directly."""
        events: list[dict[str, Any]] = []
        reason = ""
        async for ev in self.mem_watch_stream(
            address=address, length=length, space=space, pid=pid,
            interval_ms=interval_ms, duration_s=duration_s,
            expected_hex=expected_hex, max_events=max_events, tag=tag,
        ):
            if ev["eof"]:
                reason = ev.get("reason") or ""
                break
            events.append(ev)
            if max_events and len(events) >= max_events:
                # Client-side cap in case the agent's max_events guard
                # missed by one (defensive; the stream should EOF first).
                break
        return {"ok": True, "events": events, "count": len(events),
                "reason": reason, "tag": tag}

    # SI #6 handle ops + SI #9 kernel-stack walk — the method bodies live
    # on HandleOpsMixin (agent_client/handle_ops.py); AgentClient inherits
    # the mixin alongside MemMixin so the methods still land on the client.
