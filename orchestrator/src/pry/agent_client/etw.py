"""ETW-trace client methods (SI #10).

Wraps the agent/umagent EtwTrace RPCs: Start/Stop/Sessions/Tail/
Events/Stats. The service is driver-free (ETW is a user-mode API),
so this mixin is identical against both views.
"""

from __future__ import annotations

from typing import Any

from ..generated import pry_pb2 as pb


def _event_dict(e: Any) -> dict[str, Any]:
    return {
        "seq": int(e.seq),
        "ts_100ns": int(e.ts_100ns),
        "provider_guid": str(e.provider_guid),
        "event_id": int(e.event_id),
        "pid": int(e.pid),
        "tid": int(e.tid),
        "opcode": int(e.opcode),
        "version": int(e.version),
        "level": int(e.level),
        "keywords": int(e.keywords),
        "kind": str(e.kind),
        "fields": {str(k): str(v) for k, v in e.fields.items()},
    }


class EtwMixin:
    # ---------------------------------------------------------------- Etw ----

    def _etw_absent(self) -> dict[str, Any]:
        return {
            "ok": False,
            "kind": "agent_version",
            "error": "etw: older agent (EtwTrace service missing)",
            "hint": "rebuild + redeploy the agent (SI #10 adds EtwTrace)",
        }

    async def etw_start(self, session_name: str, providers: list[str],
                        keywords_any: int = 0, keywords_all: int = 0,
                        level: int = 0, buffer_size_kb: int = 0,
                        min_buffers: int = 0, max_buffers: int = 0,
                        ring_capacity: int = 0) -> dict[str, Any]:
        """Start a private kernel ETW session + ProcessTrace consumer."""
        if getattr(self, "etw", None) is None:
            return self._etw_absent()
        req = pb.EtwStartRequest(
            session_name=session_name, providers=list(providers or []),
            keywords_any=int(keywords_any), keywords_all=int(keywords_all),
            level=int(level), buffer_size_kb=int(buffer_size_kb),
            min_buffers=int(min_buffers), max_buffers=int(max_buffers),
            ring_capacity=int(ring_capacity),
        )
        msg = await self._call(self.etw.Start, req)
        return {
            "ok": msg.status.ok, "error": msg.status.error,
            "session_name": str(msg.session_name),
            "session_handle": int(msg.session_handle),
            "ring_capacity": int(msg.ring_capacity),
            "started_providers": list(msg.started_providers),
            "failed_providers": list(msg.failed_providers),
        }

    async def etw_stop(self, session_name: str) -> dict[str, Any]:
        if getattr(self, "etw", None) is None:
            return self._etw_absent()
        msg = await self._call(self.etw.Stop,
                                pb.EtwStopRequest(session_name=session_name))
        return {
            "ok": msg.status.ok, "error": msg.status.error,
            "events_total": int(msg.events_total),
            "events_dropped": int(msg.events_dropped),
        }

    async def etw_trace_sessions(self) -> dict[str, Any]:
        """List this agent's private ETW sessions (SI #10). This is the
        private-session inventory, distinct from device_manage
        action='etw_sessions' which answers QueryAllTraces for every
        logger on the box."""
        if getattr(self, "etw", None) is None:
            return self._etw_absent()
        msg = await self._call(self.etw.Sessions,
                                pb.EtwTraceSessionsRequest())
        return {
            "ok": msg.status.ok, "error": msg.status.error,
            "sessions": [
                {"session_name": str(s.session_name),
                 "events_total": int(s.events_total),
                 "events_dropped": int(s.events_dropped),
                 "providers": int(s.providers),
                 "running": bool(s.running)}
                for s in msg.sessions
            ],
        }

    async def etw_tail(self, session_name: str, since_seq: int = 0,
                       limit: int = 0) -> dict[str, Any]:
        if getattr(self, "etw", None) is None:
            return self._etw_absent()
        req = pb.EtwTailRequest(session_name=session_name,
                                 since_seq=int(since_seq),
                                 limit=int(limit))
        msg = await self._call(self.etw.Tail, req)
        return {
            "ok": msg.status.ok, "error": msg.status.error,
            "events": [_event_dict(e) for e in msg.events],
            "last_seq": int(msg.last_seq),
            "dropped": int(msg.dropped),
        }

    async def etw_events(self, session_name: str, max_events: int = 0,
                         timeout_ms: int = 0) -> dict[str, Any]:
        if getattr(self, "etw", None) is None:
            return self._etw_absent()
        req = pb.EtwEventsRequest(session_name=session_name,
                                    max_events=int(max_events),
                                    timeout_ms=int(timeout_ms))
        msg = await self._call(self.etw.Events, req)
        return {
            "ok": msg.status.ok, "error": msg.status.error,
            "events": [_event_dict(e) for e in msg.events],
            "last_seq": int(msg.last_seq),
            "dropped": int(msg.dropped),
        }

    async def etw_stats(self, session_name: str) -> dict[str, Any]:
        if getattr(self, "etw", None) is None:
            return self._etw_absent()
        msg = await self._call(self.etw.Stats,
                                pb.EtwStatsRequest(session_name=session_name))
        return {
            "ok": msg.status.ok, "error": msg.status.error,
            "session_name": str(msg.session_name),
            "events_total": int(msg.events_total),
            "events_dropped": int(msg.events_dropped),
            "events_lost": int(msg.events_lost),
            "buffers_written": int(msg.buffers_written),
            "buffers_lost": int(msg.buffers_lost),
            "ring_capacity": int(msg.ring_capacity),
            "ring_used": int(msg.ring_used),
            "running": bool(msg.running),
        }
