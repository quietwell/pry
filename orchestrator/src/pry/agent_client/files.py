"""Files-service methods split off from AgentClient."""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
from pathlib import Path
from typing import Any

from ..generated import pry_pb2 as pb
from .wire import proto_to_dict, status_dict

#: Transfer deadlines. A whole-stream deadline used to be the 10 s
#: client default for uploads of up to max_transfer_mb (512 MB) — anything
#: past a few MB on the lab link was cut off. Deadlines now scale with the
#: payload at a conservative floor throughput, and every streamed chunk
#: must arrive within the idle window.
_TRANSFER_BASE_S = 30.0
_TRANSFER_FLOOR_BPS = 1024 * 1024          # assume >= 1 MiB/s
_TRANSFER_IDLE_S = 60.0
_DOWNLOAD_HARD_CAP_S = 2 * 3600.0
_CHUNK = 64 * 1024


def transfer_deadline_s(nbytes: int) -> float:
    """Size-scaled gRPC deadline for moving *nbytes* over the agent link."""
    return _TRANSFER_BASE_S + max(0, int(nbytes)) / _TRANSFER_FLOOR_BPS


class TransferIntegrityError(RuntimeError):
    """A transfer completed at the transport level but the byte count or
    the sha256 does not match — the destination is NOT the source."""


def _read_and_hash(path: str) -> tuple[bytes, str]:
    data = Path(path).read_bytes()
    return data, hashlib.sha256(data).hexdigest()


class FilesMixin:
    # ----------------------------------------------------------------- Files ----

    async def file_upload(self, local_path: str, remote_path: str, *,
                          timeout_s: float | None = None) -> dict[str, Any]:
        """Stream *local_path* to *remote_path* on the target.

        The file is read and hashed off the event loop; the
        deadline scales with the size (``transfer_deadline_s``); and the
        result is verified — ``ok`` is False with ``kind='integrity'``
        unless the agent reports exactly ``len(data)`` bytes written AND a
        sha256 equal to the local one. Callers that swap binaries (see
        scripts/update_target.py) must check ``ok`` before using the file.
        """
        data, local_sha = await asyncio.to_thread(_read_and_hash, local_path)
        size = len(data)

        async def gen():
            yield pb.UploadChunk(header=pb.UploadHeader(path=remote_path, size=size))
            for off in range(0, size, _CHUNK):
                yield pb.UploadChunk(data=data[off: off + _CHUNK])

        deadline = timeout_s if timeout_s else transfer_deadline_s(size)
        msg = await self._call(self.files.Upload, gen(), timeout=deadline)
        remote_sha = str(msg.sha256 or "").lower()
        written = int(msg.bytes_written)
        out: dict[str, Any] = {
            "ok": bool(msg.status.ok),
            "error": msg.status.error,
            "sha256": msg.sha256,
            "bytes_written": written,
            "local_sha256": local_sha,
            "local_bytes": size,
        }
        if out["ok"] and (written != size or remote_sha != local_sha):
            out["ok"] = False
            out["kind"] = "integrity"
            out["error"] = (
                f"upload integrity check failed for {remote_path}: agent "
                f"wrote {written}/{size} bytes, sha256 "
                f"{remote_sha[:16] or '<none>'} != local {local_sha[:16]} — "
                "do NOT use the remote file")
        return out

    async def _download_to(self, call_fn, request, local_path: str, *,
                           expect_from_header) -> dict[str, Any]:
        """Drain a DownloadChunk stream into ``<local_path>.partial`` and
        rename it into place only after the byte count (and, for a
        whole-file read, the sha256) matches the header. A truncated or
        corrupted stream raises :class:`TransferIntegrityError` and leaves
        no file at *local_path*."""
        sha = hashlib.sha256()
        total = 0
        header = None
        dest = Path(local_path)
        await asyncio.to_thread(dest.parent.mkdir, parents=True, exist_ok=True)
        part = dest.with_name(dest.name + ".partial")
        fh = await asyncio.to_thread(open, part, "wb")
        try:
            deadline = time.monotonic() + _DOWNLOAD_HARD_CAP_S
            async for chunk in self._stream(call_fn, request,
                                            timeout=_DOWNLOAD_HARD_CAP_S,
                                            idle_s=_TRANSFER_IDLE_S):
                which = chunk.WhichOneof("payload")
                if which == "header":
                    header = chunk.header
                    want = expect_from_header(header)
                    if want is not None:
                        deadline = time.monotonic() + transfer_deadline_s(want)
                elif which == "data":
                    await asyncio.to_thread(fh.write, chunk.data)
                    sha.update(chunk.data)
                    total += len(chunk.data)
                if time.monotonic() > deadline:
                    raise TransferIntegrityError(
                        f"download of {getattr(request, 'path', '?')} exceeded "
                        f"its size-scaled deadline after {total} bytes")
        except BaseException:
            await asyncio.to_thread(fh.close)
            await asyncio.to_thread(_unlink_quiet, part)
            raise
        await asyncio.to_thread(fh.close)
        digest = sha.hexdigest()
        want = expect_from_header(header) if header is not None else None
        problem = ""
        if header is None:
            problem = "stream carried no header"
        elif want is not None and total != want:
            problem = f"received {total} of {want} bytes (stream truncated)"
        elif want is not None and getattr(request, "offset", 0) == 0 \
                and total == int(getattr(header, "size", 0) or 0) \
                and getattr(header, "sha256", "") \
                and str(header.sha256).lower() != digest:
            problem = (f"sha256 {digest[:16]} != agent's "
                       f"{str(header.sha256)[:16]}")
        if problem:
            await asyncio.to_thread(_unlink_quiet, part)
            raise TransferIntegrityError(
                f"download of {getattr(request, 'path', '?')} failed "
                f"integrity: {problem}")
        await asyncio.to_thread(os.replace, part, dest)
        return {"header": header, "bytes": total, "sha256": digest}

    async def file_download(self, remote_path: str, local_path: str, offset: int = 0,
                            length: int = 0) -> dict[str, Any]:
        req = pb.DownloadRequest(path=remote_path, offset=offset, length=length)

        def _expect(h) -> int | None:
            size = int(getattr(h, "size", 0) or 0)
            avail = max(0, size - int(offset))
            return min(int(length), avail) if length else avail

        got = await self._download_to(self.files.Download, req, local_path,
                                      expect_from_header=_expect)
        header = got["header"]
        via_snapshot = bool(getattr(header, "via_snapshot", False))
        total = got["bytes"]
        # T2.3 (PR#1): abs_path so the caller never has to re-resolve
        # local_path. Matches the convention used by file_manage ingest.
        try:
            abs_path = str(Path(local_path).resolve())
        except Exception:
            abs_path = local_path
        out = {"path": local_path, "abs_path": abs_path, "bytes": total,
               "sha256": got["sha256"], "via_snapshot": via_snapshot,
               "verified": True}
        if via_snapshot:
            out["note"] = ("downloaded bytes are a VSS shadow copy — the live "
                           "file is share-mode-0 locked and may have changed "
                           "since the snapshot")
        return out

    async def file_dump_module(self, pid: int, module: str, local_path: str,
                               quiesce: bool = False, dump_type: str = "as_loaded",
                               kernel: bool = False) -> dict[str, Any]:
        sha = hashlib.sha256()
        total = 0
        notes = ""
        sections: list[dict[str, Any]] = []
        await asyncio.to_thread(Path(local_path).parent.mkdir,
                                parents=True, exist_ok=True)
        buf = bytearray()
        async for chunk in self._stream(
                self.files.DumpModule,
                pb.DumpModuleRequest(pid=pid, module=module, quiesce=quiesce,
                                     dump_type=dump_type, kernel=kernel),
                timeout=_DOWNLOAD_HARD_CAP_S, idle_s=_TRANSFER_IDLE_S * 2):
            which = chunk.WhichOneof("payload")
            if which == "header":
                notes = chunk.header.notes
                # per-section residency map from the dumper.
                sections = [
                    {"name": s.name, "va": s.va, "size": s.size,
                     "dumped_bytes": s.dumped_bytes, "complete": s.complete}
                    for s in chunk.header.sections
                ]
            elif which == "data":
                buf.extend(chunk.data)
                total += len(chunk.data)
        data = bytes(buf)
        await asyncio.to_thread(Path(local_path).write_bytes, data)
        sha.update(data)
        return {"path": local_path, "bytes": total, "sha256": sha.hexdigest(),
                "notes": notes, "sections": sections}

    async def file_hash(self, remote_path: str) -> dict[str, Any]:
        msg = await self._call(self.files.Hash, pb.HashRequest(path=remote_path))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"sha256": msg.sha256, "size": msg.size,
                "via_snapshot": bool(getattr(msg, "via_snapshot", False))}

    async def file_tail(self, remote_path: str, bytes_wanted: int = 65536,
                        line_align: bool = True) -> dict[str, Any]:
        """Return the last N bytes of a remote file.

        Phase 0 implementation: `file_hash` for size, then Download with
        `offset=max(0, size - bytes_wanted)`. Phase 1 will short-circuit to
        the new `Files.LogTail` RPC when the agent supports it — the return
        shape stays the same so callers don't care.
        """
        # Prefer the native Files.LogTail RPC when the agent supports it.
        if hasattr(self.files, "LogTail"):
            try:
                msg = await self._call(
                    self.files.LogTail,
                    pb.LogTailRequest(path=remote_path, bytes=bytes_wanted,
                                      line_align=line_align, include_rotated=False),
                )
                if msg.status.ok:
                    return {"path": remote_path,
                            "data": msg.data.decode("utf-8", "replace"),
                            "bytes": len(msg.data),
                            "total_size": msg.total_size,
                            "tail_offset": msg.tail_offset,
                            "truncated": msg.truncated,
                            "via_snapshot": bool(getattr(msg, "via_snapshot", False)),
                            "backend": "log_tail"}
            except Exception:
                # Fall back to chunked download if the RPC path errors.
                pass
        # Fallback: hash-for-size + range download.
        try:
            meta = await self.file_hash(remote_path)
        except Exception as exc:
            err = str(exc)
            low = err.lower()
            # v14: classify the agent's Win32 error instead of the old
            # catch-all "check the path exists" — which claimed an existing
            # locked file was missing. gle=32/gle=33 = share violation;
            # gle=5 = access denied; gle=2/3 = actually missing.
            if "gle=32" in low or "gle=33" in low or "sharing" in low or \
                    "0xc0000043" in low:
                hint = ("file exists but is share-mode-0 locked — metadata "
                        "still works; a v14+ agent falls back to a VSS "
                        "shadow copy for content, and follow_start reports "
                        "growth via stat events until the writer unlocks")
            elif "gle=5" in low or "denied" in low:
                hint = "access denied on open — try kernel=true paths or an elevated agent"
            elif "gle=2" in low or "gle=3" in low or "cannot stat" in low:
                hint = "check the path exists on the target"
            else:
                hint = ("stat succeeded but hash/read failed — see error "
                        "for the Win32 code")
            return {"ok": False,
                    "error": f"file_tail: stat/hash probe failed: {err}",
                    "hint": hint}
        total = int(meta.get("size", 0))
        want = min(int(bytes_wanted), total)
        offset = max(0, total - want)
        buf = bytearray()
        via_snapshot = False
        async for chunk in self._stream(
                self.files.Download,
                pb.DownloadRequest(path=remote_path, offset=offset, length=want),
                timeout=transfer_deadline_s(want), idle_s=_TRANSFER_IDLE_S):
            which = chunk.WhichOneof("payload")
            if which == "header":
                via_snapshot = bool(getattr(chunk.header, "via_snapshot", False))
            elif which == "data":
                buf.extend(chunk.data)
        text = bytes(buf).decode("utf-8", "replace")
        if line_align and len(text) < total and "\n" in text:
            # Skip the first (possibly partial) line so the tail is line-clean.
            text = text.split("\n", 1)[1] if "\n" in text else text
        return {"path": remote_path, "data": text, "bytes": len(buf),
                "total_size": total, "tail_offset": offset,
                "truncated": offset > 0, "backend": "download_range",
                "via_snapshot": via_snapshot or bool(meta.get("via_snapshot"))}

    async def file_list_dir(self, path: str, recursive: bool = False, max_entries: int = 2000) -> list[dict[str, Any]]:
        msg = await self._call(
            self.files.ListDir, pb.ListDirRequest(path=path, recursive=recursive, max_entries=max_entries)
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(e) for e in msg.entries]

    async def file_delete(self, path: str, no_trash: bool = False) -> dict[str, Any]:
        st = await self._call(self.files.Delete, pb.DeleteRequest(path=path, no_trash=no_trash))
        return status_dict(st)

    # v8: streaming tail-f. The gRPC stream is driven from the orchestrator side
    # (this is an async iterator over LogFollowChunk); the MCP tool feeds chunks
    # into a bounded per-follow_id ring the LLM polls. Returns None if the agent
    # predates v8 and the RPC isn't wired up (caller falls back to LogTail).
    async def log_follow_iter(self, path: str, *,
                              from_offset: int = 0,
                              initial_tail_bytes: int = 65536,
                              poll_interval_ms: int = 200,
                              max_chunk_bytes: int = 65536,
                              line_align: bool = True,
                              follow_rotation: bool = True,
                              duration_s: int = 600,
                              max_bytes: int = 0):
        """Async generator yielding LogFollowChunk messages until the stream ends.

        The agent stamps ok=true on the first chunk and eof=true on the terminal
        chunk (with `reason` populated). We yield every chunk including the
        terminal one so the caller can surface `reason` cleanly.
        """
        if not hasattr(self.files, "LogFollow"):
            return
        req = pb.LogFollowRequest(
            path=path,
            from_offset=from_offset,
            initial_tail_bytes=initial_tail_bytes,
            poll_interval_ms=poll_interval_ms,
            max_chunk_bytes=max_chunk_bytes,
            line_align=line_align,
            follow_rotation=follow_rotation,
            duration_s=duration_s,
            max_bytes=max_bytes,
        )
        # through _stream (recent_ops ring entry streaming -> ok /
        # error / cancelled, normalized errors). Deadline = the agent-side
        # duration plus slack; 0 = open-ended follow.
        deadline = (float(duration_s) + 30.0) if duration_s else None
        async for chunk in self._stream(self.files.LogFollow, req,
                                        timeout=deadline):
            yield chunk


def _unlink_quiet(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
