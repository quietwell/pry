"""mechanics audit — an in-process REAL gRPC server.

Every other client test monkeypatches ``AgentClient._call`` or uses a
duck-typed fake, so none of them ever exercised the wire: bearer metadata,
uint64-as-string through MessageToDict, stream truncation, UNIMPLEMENTED,
deadlines. Here a ``grpc.aio`` server on 127.0.0.1 hosts small fake
servicers (Agent / Files / Debug / WatchHw) and the production
:class:`AgentClient` talks to it over a real channel.
"""
from __future__ import annotations

import asyncio
import hashlib
from typing import Any

import grpc
import pytest

from pry.agent_client import AgentClient
from pry.agent_client._errors import AgentRpcError
from pry.agent_client.files import TransferIntegrityError
from pry.generated import pry_pb2 as pb
from pry.generated import pry_pb2_grpc as pbg

TOKEN = "harness-token"
BOOT = 1_700_000_000_123  # > 2**32: exercises the uint64 path


def _auth(context) -> str:
    for k, v in context.invocation_metadata() or ():
        if k == "authorization":
            return v
    return ""


class _Log:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []   # (method, authorization)

    def note(self, method: str, context) -> None:
        self.calls.append((method, _auth(context)))

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]


class AgentSvc(pbg.AgentServicer):
    def __init__(self, log: _Log, *, identify: bool = True,
                 computer_name: str = "LAB2-WIN") -> None:
        self.log = log
        self.identify_ok = identify
        self.computer_name = computer_name

    async def Status(self, request, context):
        self.log.note("Status", context)
        if _auth(context) != f"Bearer {TOKEN}":
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "bad token")
        return pb.StatusResponse(
            status=pb.OpStatus(ok=True), agent_version="harness",
            boot_epoch_ms=BOOT, agent_uptime_ms=5_000_000_000,
            agent_instance_id="inst-1")

    async def Identify(self, request, context):
        self.log.note("Identify", context)
        if not self.identify_ok:
            await context.abort(grpc.StatusCode.UNIMPLEMENTED,
                                "Method not implemented!")
        return pb.IdentifyResponse(
            computer_name=self.computer_name, boot_epoch_ms=BOOT,
            agent_instance_id="inst-1", agent_version="harness",
            view_kind="kernel")

    async def HostInfo(self, request, context):
        self.log.note("HostInfo", context)
        return pb.HostInfoResponse(status=pb.OpStatus(ok=True))


class FilesSvc(pbg.FilesServicer):
    """Upload: ``short_write`` under-reports; Download: ``truncate`` stops
    the stream early with OK; ``stall_s`` sleeps after the header;
    ``abort_mid`` aborts UNAVAILABLE after the first chunk."""

    def __init__(self, log: _Log) -> None:
        self.log = log
        self.files: dict[str, bytes] = {}
        self.short_write = False
        self.truncate = False
        self.stall_s = 0.0
        self.abort_mid = False

    async def Upload(self, request_iterator, context):
        self.log.note("Upload", context)
        path, buf = "", bytearray()
        async for chunk in request_iterator:
            if chunk.WhichOneof("payload") == "header":
                path = chunk.header.path
            else:
                buf.extend(chunk.data)
        data = bytes(buf[:-1] if self.short_write and buf else buf)
        self.files[path] = data
        return pb.UploadResponse(status=pb.OpStatus(ok=True), path=path,
                                 sha256=hashlib.sha256(data).hexdigest(),
                                 bytes_written=len(data))

    async def Download(self, request, context):
        self.log.note("Download", context)
        data = self.files.get(request.path, b"")
        yield pb.DownloadChunk(header=pb.DownloadHeader(
            size=len(data), sha256=hashlib.sha256(data).hexdigest()))
        if self.stall_s:
            await asyncio.sleep(self.stall_s)
        body = data[: len(data) // 2] if self.truncate else data
        for off in range(0, len(body), 4):
            yield pb.DownloadChunk(data=body[off: off + 4])
            if self.abort_mid:
                await context.abort(grpc.StatusCode.UNAVAILABLE, "agent died")


class DebugSvc(pbg.DebugServicer):
    def __init__(self, log: _Log) -> None:
        self.log = log

    async def Wait(self, request, context):
        self.log.note("Wait", context)
        # Block for the requested server-side wait, then report a timeout
        # stop (what the agent does when nothing stopped the target).
        await asyncio.sleep(request.timeout_ms / 1000.0)
        return pb.DebugOpStatus(
            status=pb.OpStatus(ok=True),
            state=pb.StopInfo(active=True, stopped=False, timed_out=True))


class WatchHwSvc(pbg.WatchHwServicer):
    def __init__(self, log: _Log) -> None:
        self.log = log
        self.armed: dict[int, Any] = {}

    async def Add(self, request, context):
        self.log.note("WatchHw.Add", context)
        cookie = 40 + len(self.armed) + 1
        self.armed[cookie] = request
        return pb.WatchHwAddResponse(status=pb.OpStatus(ok=True),
                                     watch_cookie=cookie, slot=2,
                                     threads_patched=3)

    async def Remove(self, request, context):
        self.log.note("WatchHw.Remove", context)
        gone = self.armed.pop(request.watch_cookie, None) is None
        return pb.OpStatus(ok=True, errno_code=2 if gone else 0)


class Harness:
    def __init__(self, *, identify: bool = True, debug: bool = True,
                 computer_name: str = "LAB2-WIN") -> None:
        self.log = _Log()
        self.agent = AgentSvc(self.log, identify=identify,
                              computer_name=computer_name)
        self.files = FilesSvc(self.log)
        self.debug = DebugSvc(self.log)
        self.watch = WatchHwSvc(self.log)
        self._with_debug = debug
        self.server: grpc.aio.Server | None = None
        self.port = 0

    async def __aenter__(self) -> "Harness":
        self.server = grpc.aio.server()
        pbg.add_AgentServicer_to_server(self.agent, self.server)
        pbg.add_FilesServicer_to_server(self.files, self.server)
        pbg.add_WatchHwServicer_to_server(self.watch, self.server)
        if self._with_debug:
            pbg.add_DebugServicer_to_server(self.debug, self.server)
        self.port = self.server.add_insecure_port("127.0.0.1:0")
        await self.server.start()
        return self

    async def __aexit__(self, *exc) -> None:
        assert self.server is not None
        await self.server.stop(grace=None)

    async def client(self, timeout_ms: int = 10000) -> AgentClient:
        c = AgentClient("127.0.0.1", self.port, TOKEN, timeout_ms=timeout_ms)
        await c.connect(timeout_s=5.0)
        return c


# --------------------------------------------------------------------------- #
# auth metadata + uint64
# --------------------------------------------------------------------------- #

async def test_bearer_metadata_is_sent_and_uint64_fields_are_ints():
    async with Harness() as h:
        c = await h.client()
        try:
            st = await c.status()
        finally:
            await c.close()
    assert h.log.calls == [("Status", f"Bearer {TOKEN}")]
    # MessageToDict renders uint64 as a decimal STRING; status() coerces.
    assert st["boot_epoch_ms"] == BOOT and isinstance(st["boot_epoch_ms"], int)
    assert isinstance(st["agent_uptime_ms"], int)
    assert st["ok"] is True


async def test_identify_sends_no_token_and_coerces_uint64():
    async with Harness() as h:
        c = await h.client()
        try:
            ident = await c.identify()
        finally:
            await c.close()
    assert h.log.calls == [("Identify", "")]          # token NOT on the wire
    assert ident == {"computer_name": "LAB2-WIN", "boot_epoch_ms": BOOT,
                     "agent_instance_id": "inst-1",
                     "agent_version": "harness", "view_kind": "kernel"}


async def test_identify_on_an_old_agent_returns_none():
    async with Harness(identify=False) as h:
        c = await h.client()
        try:
            assert await c.identify() is None
        finally:
            await c.close()


# --------------------------------------------------------------------------- #
# UNIMPLEMENTED -> not_supported
# --------------------------------------------------------------------------- #

async def test_unimplemented_service_maps_to_not_supported():
    async with Harness(debug=False) as h:
        c = await h.client()
        try:
            with pytest.raises(AgentRpcError) as ei:
                await c.debug_status()
        finally:
            await c.close()
    assert ei.value.kind == "not_supported"
    assert ei.value.code == grpc.StatusCode.UNIMPLEMENTED
    assert str(ei.value).startswith("UNIMPLEMENTED")


# --------------------------------------------------------------------------- #
# upload / download integrity
# --------------------------------------------------------------------------- #

async def test_upload_roundtrip_is_verified(tmp_path):
    src = tmp_path / "blob.bin"
    src.write_bytes(bytes(range(256)) * 300)
    async with Harness() as h:
        c = await h.client()
        try:
            up = await c.file_upload(str(src), r"C:\pry\blob.bin")
        finally:
            await c.close()
    assert up["ok"] is True
    assert up["sha256"] == up["local_sha256"] == hashlib.sha256(
        src.read_bytes()).hexdigest()
    assert up["bytes_written"] == up["local_bytes"] == 256 * 300
    assert h.log.calls[0] == ("Upload", f"Bearer {TOKEN}")


async def test_short_upload_is_reported_not_ok(tmp_path):
    src = tmp_path / "blob.bin"
    src.write_bytes(b"x" * 1000)
    async with Harness() as h:
        h.files.short_write = True
        c = await h.client()
        try:
            up = await c.file_upload(str(src), r"C:\pry\blob.bin")
        finally:
            await c.close()
    assert up["ok"] is False
    assert up["kind"] == "integrity"
    assert "999/1000" in up["error"]


async def test_download_roundtrip_verifies_sha(tmp_path):
    async with Harness() as h:
        h.files.files[r"C:\x.bin"] = b"0123456789abcdef"
        c = await h.client()
        try:
            out = await c.file_download(r"C:\x.bin", str(tmp_path / "x.bin"))
        finally:
            await c.close()
    assert out["bytes"] == 16 and out["verified"] is True
    assert (tmp_path / "x.bin").read_bytes() == b"0123456789abcdef"
    assert not (tmp_path / "x.bin.partial").exists()


async def test_truncated_download_raises_and_leaves_no_file(tmp_path):
    async with Harness() as h:
        h.files.files[r"C:\x.bin"] = b"0123456789abcdef"
        h.files.truncate = True       # stream ends OK after half the bytes
        c = await h.client()
        try:
            with pytest.raises(TransferIntegrityError) as ei:
                await c.file_download(r"C:\x.bin", str(tmp_path / "x.bin"))
        finally:
            await c.close()
    assert "8 of 16 bytes" in str(ei.value)
    assert not (tmp_path / "x.bin").exists()
    assert not (tmp_path / "x.bin.partial").exists()


async def test_stream_abort_is_normalized_and_recorded(tmp_path):
    async with Harness() as h:
        h.files.files[r"C:\x.bin"] = b"0123456789abcdef"
        h.files.abort_mid = True
        c = await h.client()
        try:
            with pytest.raises(AgentRpcError) as ei:
                await c.file_download(r"C:\x.bin", str(tmp_path / "x.bin"))
            ops = c.recent_ops()
        finally:
            await c.close()
    assert ei.value.kind == "unavailable"
    assert ops[-1]["status"] == "error" and "Download" in ops[-1]["method"]
    assert not (tmp_path / "x.bin").exists()


async def test_stalled_stream_hits_the_idle_deadline(tmp_path, monkeypatch):
    import pry.agent_client.files as files_mod
    monkeypatch.setattr(files_mod, "_TRANSFER_IDLE_S", 0.3)
    async with Harness() as h:
        h.files.files[r"C:\x.bin"] = b"abcd"
        h.files.stall_s = 3.0
        c = await h.client()
        try:
            with pytest.raises(AgentRpcError) as ei:
                await c.file_download(r"C:\x.bin", str(tmp_path / "x.bin"))
        finally:
            await c.close()
    assert ei.value.kind == "deadline"


# --------------------------------------------------------------------------- #
# deadlines for the waiting debug verbs
# --------------------------------------------------------------------------- #

async def test_debug_wait_deadline_tracks_the_server_wait():
    """The agent blocks timeout_ms before answering timed_out=true. With
    the 1 s client default the old code died with DEADLINE_EXCEEDED and lost
    the StopInfo; the wait now carries timeout_ms/1000 + 5 s."""
    async with Harness() as h:
        c = await h.client(timeout_ms=1000)
        try:
            out = await c.debug_wait(timeout_ms=1500)
            # the raw default-deadline path shows what used to happen
            with pytest.raises(AgentRpcError) as ei:
                await c._call(c.debug.Wait, pb.WaitRequest(timeout_ms=1500))
        finally:
            await c.close()
    assert out["ok"] is True and out["state"]["timed_out"] is True
    assert ei.value.kind == "deadline"


async def test_cancelled_call_is_recorded_as_cancelled():
    async with Harness() as h:
        c = await h.client()
        try:
            task = asyncio.create_task(c.debug_wait(timeout_ms=5000))
            await asyncio.sleep(0.3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            ops = c.recent_ops()
        finally:
            await c.close()
    assert ops[-1]["status"] == "cancelled"
    assert all(o["status"] != "pending" for o in ops)


# --------------------------------------------------------------------------- #
# WatchHw client
# --------------------------------------------------------------------------- #

async def test_watchhw_add_and_remove_over_the_wire():
    async with Harness() as h:
        c = await h.client()
        try:
            r = await c.bp_hw_watch_add(pid=1234, tid=0, address=0x7FF600001000,
                                        size=8, access="write")
            gone = await c.bp_hw_watch_remove(r["watch_cookie"])
            again = await c.bp_hw_watch_remove(r["watch_cookie"])
        finally:
            await c.close()
    assert r["ok"] is True and r["watch_cookie"] == 41 and r["slot"] == 2
    assert r["threads_patched"] == 3
    assert gone["ok"] is True and "already_removed" not in gone
    assert again.get("already_removed") is True
    assert ("WatchHw.Add", f"Bearer {TOKEN}") in h.log.calls


# --------------------------------------------------------------------------- #
# Session.connect identify-before-token over a real channel
# --------------------------------------------------------------------------- #

def _session(tmp_path, port: int, monkeypatch):
    from pry.config import MachineConfig, PryConfig
    from pry.registry import MachineRegistry
    from pry.session import Session
    monkeypatch.setenv("PRY_AUDIT_DISABLE", "1")
    cfg = PryConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    # configured host is a dead loopback address; the beacon points at the
    # live harness on 127.0.0.1
    cfg.machines = {"lab2": MachineConfig(host="127.0.0.3", kernel_port=port,
                                          token=TOKEN, trust="lab")}
    session = Session(cfg)
    reg = MachineRegistry.load(cfg)
    session.set_registry_provider(lambda: reg)
    reg.record_observed_endpoint("lab2", host="127.0.0.1", port=port,
                                 allow_create=True)
    return session, reg


async def test_learned_endpoint_with_the_wrong_identity_never_gets_the_token(
        tmp_path, monkeypatch):
    from pry.session import WrongMachineError
    async with Harness(computer_name="OTHER-BOX") as h:
        session, reg = _session(tmp_path, h.port, monkeypatch)
        reg.set("lab2", computer_name="LAB2-WIN")
        with pytest.raises(WrongMachineError):
            await session.connect(machine="lab2", owner="o1")
        await session.disconnect()
    assert h.log.methods() == ["Identify"]
    assert all(auth == "" for _m, auth in h.log.calls)


async def test_learned_endpoint_without_proof_is_refused_token_withheld(
        tmp_path, monkeypatch):
    from pry.session import UnverifiedMachineError
    async with Harness(computer_name="SOMEBOX") as h:
        session, _reg = _session(tmp_path, h.port, monkeypatch)
        with pytest.raises(UnverifiedMachineError) as ei:
            await session.connect(machine="lab2", owner="o1")
        await session.disconnect()
    assert ei.value.token_withheld is True
    assert h.log.methods() == ["Identify"]


async def test_learned_endpoint_with_matching_identity_connects(
        tmp_path, monkeypatch):
    async with Harness(computer_name="LAB2-WIN") as h:
        session, reg = _session(tmp_path, h.port, monkeypatch)
        reg.set("lab2", computer_name="LAB2-WIN")
        st = await session.connect(machine="lab2", owner="o1")
        try:
            assert st["endpoint_source"] in ("observed", "beacon")
            assert session._last_good_host["lab2"] == "127.0.0.1"
            # Identify (no token) strictly before the first token-bearing call
            assert h.log.calls[0] == ("Identify", "")
            assert ("Status", f"Bearer {TOKEN}") in h.log.calls
            # stored client carries the config soft-fault policy
            assert session.clients["lab2.kernel"].allow_softfault is False
        finally:
            await session.disconnect()


async def test_old_agent_learned_endpoint_needs_a_match(tmp_path, monkeypatch):
    """No Identify (UNIMPLEMENTED): today's flow, but an unknown identity
    on a learned address is refused instead of attached."""
    from pry.session import UnverifiedMachineError
    async with Harness(identify=False) as h:
        session, _reg = _session(tmp_path, h.port, monkeypatch)
        with pytest.raises(UnverifiedMachineError) as ei:
            await session.connect(machine="lab2", owner="o1")
        await session.disconnect()
    assert ei.value.token_withheld is False
    assert "lab2.kernel" not in session.clients
