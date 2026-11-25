"""Shared agent-facing call conventions (``tools/_runtime/surface.py``).

Covers the middleware + schema pass that ``build_server`` installs:
virtual params (``verb`` / ``cursor`` / ``force``), descriptive param
aliases, JSON-text params accepting objects, friendly ``bad_arg`` errors
for schema-validation failures, error ``class``/``retryable`` stamps,
``next`` hints on job starts, retired verbs answering ``moved``, and the
published-schema enrichment.
"""

from __future__ import annotations

import json

import pytest

import _catalog
from pry.mcp.tools import build_server
from pry.mcp.tools._runtime import surface


@pytest.fixture()
def server():
    return build_server(_catalog._minimal_context())


async def _call(server, tool: str, args: dict) -> dict:
    res = await server.call_tool(tool, args)
    body = getattr(res, "structured_content", None)
    if not isinstance(body, dict):
        body = json.loads(res.content[0].text)
    return body


async def _schema(server, tool: str) -> dict:
    for t in await server.list_tools():
        if t.name == tool:
            return t.parameters
    raise AssertionError(tool)


# --------------------------------------------------------------- verb= --

async def test_actions_verb_narrows_to_one_verb(server) -> None:
    body = await _call(server, "memory_manage",
                       {"action": "actions", "verb": "walk_list"})
    assert body["ok"] is True
    acts = body["data"]["actions"]
    assert list(acts) == ["walk_list"]
    assert "next_offset" in acts["walk_list"]["key_args"]


async def test_actions_unknown_verb_suggests(server) -> None:
    body = await _call(server, "memory_manage",
                       {"action": "actions", "verb": "walklist"})
    assert body["ok"] is False
    assert body["error"]["kind"] == "unknown_action"
    assert "walk_list" in body["data"]["did_you_mean"]


async def test_help_hides_moved_and_registry_only_verbs(server) -> None:
    mem = (await _call(server, "memory_manage", {"action": "actions"}))
    assert "process_list" not in mem["data"]["actions"]   # moved
    assert "imports" not in mem["data"]["actions"]        # moved
    net = (await _call(server, "net_manage", {"action": "actions"}))
    assert "dns" not in net["data"]["actions"]            # registry-only


async def test_handwritten_help_wins_over_registry(server) -> None:
    body = await _call(server, "memory_manage",
                       {"action": "actions", "verb": "read"})
    example = body["data"]["actions"]["read"]["example"]
    assert "address=" in example  # not the bare registry stub


# ------------------------------------------------- validation -> bad_arg --

async def test_unknown_param_is_bad_arg_with_suggestion(server) -> None:
    body = await _call(server, "object_manage",
                       {"action": "enum", "max_entries": 5})
    assert body["ok"] is False
    err = body["error"]
    assert err["kind"] == "bad_arg" and err["class"] == "bad_arg"
    assert "max_entries" in err["error"]
    assert "max_results" in err["did_you_mean"]["max_entries"]
    assert "object_manage(action='actions', verb='enum')" in err["hint"]


async def test_unknown_action_kind_and_did_you_mean(server) -> None:
    body = await _call(server, "svc_manage", {"action": "lst"})
    assert body["ok"] is False
    assert body["error"]["kind"] == "unknown_action"
    assert "list" in body["error"].get("did_you_mean", [])
    # registry-only verbs are not offered as valid
    net = await _call(server, "net_manage", {"action": "dns"})
    assert "alias for itself" not in json.dumps(net)
    assert "dns" not in net["error"]["error"].split("expected one of:")[1]


# ------------------------------------------------------- aliases / json --

def test_rewrite_args_aliases_and_virtuals() -> None:
    spec = surface.ToolSurface(
        name="memory_manage",
        native=frozenset({"action", "value", "count", "offset", "env_json"}),
        virtual=frozenset({"cursor", "verb"}),
        aliases={a.alias: a for a in surface.PARAM_ALIASES["memory_manage"]},
        json_params=frozenset({"env_json"}),
    )
    call, raw, virtual = surface.rewrite_args(spec, {
        "action": "walk_list", "next_offset": "0x8", "max_hops": 4,
        "cursor": "offset:20", "env_json": {"a": 1}})
    assert call["value"] == "0x8" and call["count"] == 4
    assert "next_offset" not in call and "cursor" not in call
    assert call["offset"] == 20
    assert json.loads(call["env_json"]) == {"a": 1}
    assert raw["value"] == "0x8" and virtual["cursor"] == "offset:20"
    # alias outside its verb is left for validation to reject
    call2, _, _ = surface.rewrite_args(spec, {"action": "read",
                                              "next_offset": 8})
    assert "next_offset" in call2
    with pytest.raises(surface.ArgError):
        surface.rewrite_args(spec, {"action": "walk_list",
                                    "next_offset": 8, "value": "0x10"})


async def test_json_param_accepts_object(server) -> None:
    body = await _call(server, "value_manage", {
        "action": "eval", "expr": "x + 1", "env_json": {"x": 41}})
    assert body["ok"] is True, body
    assert "42" in json.dumps(body["data"])


async def test_bp_global_alias_is_accepted(server) -> None:
    schema = await _schema(server, "bp_manage")
    assert "global" in schema["properties"]
    assert "global_" in schema["properties"]


# ------------------------------------------------------------ cursor= --

async def test_cursor_pages_knowledge_list(server) -> None:
    for i in range(3):
        rec = await _call(server, "knowledge_manage", {
            "action": "record", "title": f"f{i}", "severity": "low",
            "description": "d", "dedupe": False})
        assert rec["ok"] is True, rec
    first = await _call(server, "knowledge_manage",
                        {"action": "list", "limit": 1, "verbosity": "full"})
    cur = first["summary"]["next_cursor"]
    assert cur
    second = await _call(server, "knowledge_manage",
                         {"action": "list", "limit": 1, "cursor": cur,
                          "verbosity": "full"})
    ids1 = [r["id"] for r in first["data"]["items"]]
    ids2 = [r["id"] for r in second["data"]["items"]]
    assert ids1 and ids2 and ids1 != ids2


async def test_cursor_published_on_paging_tools(server) -> None:
    for tool in ("object_manage", "process_manage", "kernel_manage"):
        props = (await _schema(server, tool))["properties"]
        assert "offset" in props and "cursor" in props, tool


# ------------------------------------------------------------- force= --

async def test_force_published_on_gated_tools(server) -> None:
    for tool in ("process_manage", "exec_manage", "device_manage",
                 "token_manage", "net_manage", "memory_manage"):
        props = (await _schema(server, tool))["properties"]
        assert "force" in props, tool


def test_trust_gate_reads_raw_force_and_name(tmp_path) -> None:
    from types import SimpleNamespace

    from pry.allowlist import TargetNotAllowed
    from pry.mcp.tools._runtime.guard import _check_actuator_trust

    seen = {}

    class _Sess:
        def resolve_view_name(self, name):
            seen["name"] = name
            return f"{name or 'focus'}.kernel"

        def machine_of(self, key):
            return key.split(".")[0]

    ctx = SimpleNamespace(
        cfg=SimpleNamespace(security=SimpleNamespace(
            min_trust_actuator="lab")),
        session=_Sess(),
        registry=SimpleNamespace(trust_for=lambda m: "untrusted"))
    token = surface.CALL_INFO.set({"tool": "exec_manage", "action": "call",
                                   "args": {"name": "lab3", "force": False}})
    try:
        with pytest.raises(TargetNotAllowed) as exc:
            _check_actuator_trust(ctx, "exec_manage", "call", {"pid": 4})
        assert seen["name"] == "lab3"          # name= from the raw call
        assert "machines_manage(action='set'" in str(exc.value)
    finally:
        surface.CALL_INFO.reset(token)
    token = surface.CALL_INFO.set({"tool": "exec_manage", "action": "call",
                                   "args": {"name": "lab3", "force": True}})
    try:
        _check_actuator_trust(ctx, "exec_manage", "call", {"pid": 4})
    finally:
        surface.CALL_INFO.reset(token)


# ----------------------------------------------- moved / class / next --

@pytest.mark.parametrize("tool,action,new_tool,new_action", [
    ("exec_manage", "kill_process", "process_manage", "kill"),
    ("device_manage", "etw_sessions", "event_manage", "etw_sessions"),
    ("kernel_manage", "scan_status", "memory_manage", "scan_status"),
    ("memory_manage", "imports", "module_manage", "imports"),
])
async def test_retired_verbs_answer_moved(server, tool, action, new_tool,
                                          new_action) -> None:
    body = await _call(server, tool, {"action": action})
    assert body["ok"] is False and body["kind"] == "error"
    assert body["error"]["kind"] == "moved"
    assert body["error"]["class"] == "bad_arg"
    assert body["replacement"] == {"tool": new_tool, "action": new_action}


def test_error_class_and_public_pin_and_next() -> None:
    from pry.mcp.tools._runtime.envelope import _agent_postprocess

    env = {"ok": False, "kind": "error", "tool": "memory_manage",
           "action": "process_list",
           "error": {"kind": "driver_absent_or_stale", "error": "x"}}
    token = surface.CALL_INFO.set({"tool": "process_manage",
                                   "action": "list", "args": {}})
    try:
        _agent_postprocess(env)
    finally:
        surface.CALL_INFO.reset(token)
    assert env["tool"] == "process_manage" and env["action"] == "list"
    assert env["error"]["class"] == "unavailable"
    assert env["error"]["retryable"] is False

    ok = {"ok": True, "kind": "scan", "tool": "memory_manage",
          "action": "scan_start", "data": {"scan_id": "s0007"}}
    _agent_postprocess(ok)
    assert ok["next"]["poll"] == {"tool": "memory_manage",
                                  "action": "scan_status",
                                  "args": {"action": "scan_status",
                                           "scan_id": "s0007"}}
    assert ok["next"]["cancel"]["action"] == "scan_cancel"


def test_missing_driver_is_not_file_not_found() -> None:
    from pry.mcp._error_enrich import enrich_error
    out = enrich_error("module_manage", "list",
                       "RuntimeError: CreateFile(\\\\.\\PryDrv) gle=2")
    assert out["kind"] == "driver_absent_or_stale"
    assert "driver_load" in out["hint"]


# -------------------------------------------------------------- schema --

async def test_schema_descriptions_and_types(server) -> None:
    mem = (await _schema(server, "memory_manage"))["properties"]
    assert "view" in mem["name"]["description"]
    assert "next pointer" in mem["next_offset"]["description"]
    assert mem["filter"].get("anyOf")              # typed, not {}
    scr = (await _schema(server, "script_manage"))["properties"]
    assert "plugin" in scr["name"]["description"]
    ida = (await _schema(server, "ida_manage"))["properties"]
    assert "enum" not in ida["action"]             # passthrough verbs
    val = (await _schema(server, "value_manage"))["properties"]
    assert any(b.get("type") == "object" for b in val["env_json"]["anyOf"])


async def test_fields_warns_on_unknown_names() -> None:
    from pry.mcp._envelope import list_envelope
    env = list_envelope([{"pid": 1, "image_name": "a"}],
                        tool="process_manage", action="list",
                        fields=["pid", "name"])
    assert any("name" in w and "image_name" in w for w in env["warnings"])


async def test_knowledge_about_is_compact_by_default(server) -> None:
    for i in range(2):
        await _call(server, "knowledge_manage", {
            "action": "record", "title": f"t{i}", "severity": "high",
            "description": "x" * 500, "module": "nt.sys", "dedupe": False})
    body = await _call(server, "knowledge_manage",
                       {"action": "about", "module": "nt.sys"})
    rows = body["data"]["findings"]
    assert rows and "description" not in rows[0]
    assert body["data"]["counts"]["findings"] == 2
    full = await _call(server, "knowledge_manage", {
        "action": "about", "module": "nt.sys", "verbosity": "full"})
    assert "description" in full["data"]["findings"][0]
    summ = await _call(server, "knowledge_manage", {
        "action": "about", "module": "nt.sys", "summary": True})
    assert summ["data"]["counts"]["findings"] == 2
    assert "findings" not in summ["data"]


async def test_machines_list_needs_no_machine(server) -> None:
    """machines_manage(action='list') forwarded as 'machines_list', which
    the legacy handler treats as a per-alias call demanding machine=."""
    body = await _call(server, "machines_manage", {"action": "list"})
    assert body["ok"] is True, body
    assert "machines" in body["data"]


def test_unimplemented_rpc_is_unavailable_with_view_hint() -> None:
    from pry.mcp._error_class import classify
    from pry.mcp._error_enrich import enrich_error
    out = enrich_error("file_manage", "hash", "AgentRpcError: UNIMPLEMENTED")
    assert out["kind"] == "not_supported"
    assert classify(out["kind"]) == ("unavailable", False)
    assert ".kernel" in out["hint"]


def test_target_stamp_uses_raw_name_when_args_lack_it() -> None:
    from types import SimpleNamespace

    from pry.mcp.tools._runtime.envelope import _stamp_target

    class _Sess:
        clients = {"lab.kernel": object(), "lab.user": object()}

        def resolve_view_name(self, name):
            return name or "lab.user"   # focus would say .user

        def stamp_needed(self, key):
            return True

    ctx = SimpleNamespace(session=_Sess())
    env = {"ok": True, "tool": "file_manage", "action": "hash"}
    token = surface.CALL_INFO.set({"tool": "file_manage", "action": "hash",
                                   "args": {"name": "lab.kernel"}})
    try:
        _stamp_target(env, ctx, {"action": "hash", "path": "x"})
    finally:
        surface.CALL_INFO.reset(token)
    assert env["target"] == "lab.kernel"


def test_public_action_pinned_for_same_tool() -> None:
    from pry.mcp.tools._runtime.envelope import _agent_postprocess
    env = {"ok": True, "kind": "process_info", "tool": "process_manage",
           "action": "process_list", "data": {}}
    token = surface.CALL_INFO.set({"tool": "process_manage", "action": "get",
                                   "args": {}})
    try:
        _agent_postprocess(env)
    finally:
        surface.CALL_INFO.reset(token)
    assert env["action"] == "get"


def test_anon_identity_is_stable_per_client_app(monkeypatch) -> None:
    from types import SimpleNamespace

    from pry.caller import _resolve_client_id

    monkeypatch.delenv("MCP_ANON_IDENTITY", raising=False)

    def req(port):
        return SimpleNamespace(
            headers={"user-agent": "claude-code/2.1 (node)"},
            client=SimpleNamespace(host="127.0.0.1", port=port), scope={})

    a, b = _resolve_client_id(req(50001), None), _resolve_client_id(req(50999), None)
    assert a == b == "anon-127.0.0.1-claude-code/2.1"
    other = SimpleNamespace(headers={"user-agent": "opencode/0.9"},
                            client=SimpleNamespace(host="127.0.0.1", port=1),
                            scope={})
    assert _resolve_client_id(other, None) != a


async def test_hw_bp_add_refuses_without_hook_consent() -> None:
    from types import SimpleNamespace

    from pry.mcp.tools.bp import _ensure_bp_hook

    ctx = SimpleNamespace(cfg=SimpleNamespace(
        security=SimpleNamespace(allow_event_stream=True)))
    calls = []

    class _C:
        events = object()

        async def events_poll(self, **kw):
            calls.append(kw)
            return {"ok": True, "bp_hook": True}

    refused = await _ensure_bp_hook(ctx, _C(), dangerous_ok=False)
    assert refused["kind"] == "confirm_required" and not calls
    assert await _ensure_bp_hook(ctx, _C(), dangerous_ok=True) is None
    assert calls and calls[0]["dangerous_ok"] is True
