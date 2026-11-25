"""Agent-facing call surface: build-time schema pass + call middleware.

Every tool is a ``<domain>_manage(action=..., ...)`` mega-tool with a flat
param list. A handful of conventions are shared by all of them, and this
module implements those conventions once instead of in 31 signatures:

* **Virtual params** appear in the published schema but are consumed here
  before the tool body runs (the Python signature does not declare them):

  - ``verb=``   with ``action='actions'``: help for that one verb only;
  - ``cursor=`` paging cursor (``summary.next_cursor``), decoded into
                ``offset`` for every tool that pages;
  - ``force=``  override the machine-trust gate on actuator verbs.

* **Param aliases** give an overloaded native param a descriptive name for
  the verbs that overload it (``walk_list next_offset=`` -> ``value``,
  ``pool_scan tag=`` -> ``module``, ...). The alias is rewritten onto the
  native param; passing both is a ``bad_arg``.

* **JSON-string params** (``*_json``) also accept a plain object/array; it
  is serialized here, so agents don't have to escape JSON inside JSON.

* **Argument-validation errors** (unknown param, wrong type) come back as a
  normal ``bad_arg`` envelope with the closest param names and the verb's
  key args, instead of a raw pydantic message.

* **Schema enrichment**: param descriptions (``param_docs``) and typed
  unions for params declared ``Any`` are written into each tool's
  published ``inputSchema``. FastMCP validates calls against the Python
  signature, so this never narrows what the server accepts.

The raw call arguments are parked in :data:`CALL_INFO` so ``_guard`` can
read ``force=`` / ``name=`` for the trust gate and pin the public
``tool``/``action`` on forwarded responses.
"""

from __future__ import annotations

import contextvars
import difflib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .help import ACTIONS_VERB, register_action_enum
from .param_docs import describe_param, schema_override

log = logging.getLogger(__name__)


# {"tool", "action", "args"} of the MCP call being served (raw arguments,
# after alias rewriting, before virtual params are stripped). Read by the
# trust gate and by ``_emit`` (public tool/action pin, ``next`` hints).
CALL_INFO: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "pry_call_info", default=None)


VIRTUAL_PARAMS: dict[str, dict[str, Any]] = {
    "verb": {
        "type": "string", "default": "",
        "description": "action='actions': help for this verb only",
    },
    "cursor": {
        "type": "string", "default": "",
        "description": "summary.next_cursor of the previous page",
    },
    "force": {
        "type": "boolean", "default": False,
        "description": "override the machine-trust gate on actuator verbs",
    },
}


@dataclass(frozen=True)
class ParamAlias:
    """``alias`` is rewritten onto ``target`` (only for ``actions`` when
    given). ``description`` goes into the published schema."""
    alias: str
    target: str
    description: str
    actions: frozenset[str] = frozenset()


# Descriptive names for overloaded native params. The handler code keeps
# reading the native param; the alias is what help and docs teach.
PARAM_ALIASES: dict[str, tuple[ParamAlias, ...]] = {
    "memory_manage": (
        ParamAlias("next_offset", "value",
                   "walk_list: byte offset of the next pointer inside each "
                   "node (int or hex string)", frozenset({"walk_list"})),
        ParamAlias("max_hops", "count",
                   "walk_list: maximum nodes to follow (default 64)",
                   frozenset({"walk_list"})),
        ParamAlias("interval_s", "timeout_s",
                   "watch: poll interval in seconds (mode='poll')",
                   frozenset({"watch"})),
        ParamAlias("tag", "filter",
                   "watch: free-text tag stored on the watch",
                   frozenset({"watch"})),
        ParamAlias("max_events", "max_results",
                   "watch: event cap; also bounds the poll duration in "
                   "seconds (<=30 with <=32 events collects inline)",
                   frozenset({"watch"})),
        ParamAlias("watch_id", "module",
                   "watch_stop: id returned by watch (e.g. 'w0001')",
                   frozenset({"watch_stop"})),
    ),
    "kernel_manage": (
        ParamAlias("tag", "module",
                   "pool_scan: pool tag filter, 4-char string ('Proc') or "
                   "int", frozenset({"pool_scan"})),
        ParamAlias("content_offset", "protect",
                   "pool_scan: byte offset into each allocation where the "
                   "pattern window (size=) starts", frozenset({"pool_scan"})),
    ),
    "bp_manage": (
        ParamAlias("global", "global_",
                   "same as global_: system-wide hw breakpoint (ignores pid)"),
    ),
}


@dataclass
class ToolSurface:
    """Per-tool facts the middleware needs at call time."""
    name: str
    native: frozenset[str]
    virtual: frozenset[str]
    aliases: dict[str, ParamAlias] = field(default_factory=dict)
    json_params: frozenset[str] = frozenset()
    actions: frozenset[str] | None = None


def _tool_objects(mcp) -> list:
    provider = getattr(mcp, "local_provider", None) or getattr(
        mcp, "_local_provider", None)
    comps = getattr(provider, "_components", {}) or {}
    from fastmcp.tools import Tool
    return [c for c in comps.values() if isinstance(c, Tool)]


def _gated_tools() -> set[str]:
    from .guard import _ACTUATOR_PAIRS
    return {t for (t, _a) in _ACTUATOR_PAIRS}


def _is_json_string_param(pname: str, pschema: dict) -> bool:
    return pname.endswith("_json") and pschema.get("type") == "string"


def finalize_surface(mcp) -> dict[str, ToolSurface]:
    """Enrich every registered tool's published schema and return the
    per-tool call facts for :class:`AgentSurfaceMiddleware`.

    Idempotent per tool object (a second pass sees the virtual params as
    already present and leaves them alone)."""
    gated = _gated_tools()
    out: dict[str, ToolSurface] = {}
    for tool in _tool_objects(mcp):
        schema = tool.parameters if isinstance(tool.parameters, dict) else {}
        props: dict[str, dict] = schema.setdefault("properties", {})
        native = frozenset(
            getattr(tool, "_pry_native", None) or props.keys())
        try:
            object.__setattr__(tool, "_pry_native", native)
        except Exception:  # noqa: BLE001 — cosmetic cache only
            pass

        action_enum = None
        act = props.get("action") or {}
        if isinstance(act.get("enum"), list):
            action_enum = frozenset(act["enum"])
        register_action_enum(tool.name, action_enum)

        virtual: set[str] = set()
        wanted = ["verb"]
        if "offset" in native:
            wanted.append("cursor")
        if tool.name in gated:
            wanted.append("force")
        for vp in wanted:
            if vp in native:
                continue
            props.setdefault(vp, dict(VIRTUAL_PARAMS[vp]))
            virtual.add(vp)

        aliases: dict[str, ParamAlias] = {}
        for al in PARAM_ALIASES.get(tool.name, ()):
            if al.alias in native or al.target not in native:
                continue
            aliases[al.alias] = al
            base = dict(props.get(al.target) or {})
            base.pop("default", None)
            base.pop("title", None)
            base["description"] = al.description
            props.setdefault(al.alias, base)

        json_params = frozenset(
            p for p in native if _is_json_string_param(p, props.get(p) or {}))
        for p in json_params:
            ps = props[p]
            default = ps.get("default", "")
            props[p] = {"anyOf": [{"type": "string"}, {"type": "object"},
                                  {"type": "array"}],
                        "default": default}

        for pname, pschema in list(props.items()):
            if pname in virtual or pname in aliases:
                continue
            override = schema_override(tool.name, pname, pschema)
            if override is not None:
                pschema = dict(override)
                props[pname] = pschema
            if not pschema.get("description"):
                desc = describe_param(tool.name, pname)
                if desc:
                    pschema["description"] = desc
            if pname in json_params and not pschema.get("description"):
                pschema["description"] = "JSON text or a plain object"

        out[tool.name] = ToolSurface(
            name=tool.name, native=native, virtual=frozenset(virtual),
            aliases=aliases, json_params=json_params, actions=action_enum)
    return out


# ---------------------------------------------------------------------------
# call-time helpers
# ---------------------------------------------------------------------------

def decode_cursor(cursor: Any) -> int:
    """``'offset:N'`` / ``'N'`` / int -> N (0 when unparseable)."""
    if cursor is None or cursor == "":
        return 0
    if isinstance(cursor, int):
        return max(0, cursor)
    s = str(cursor).strip()
    if s.startswith("offset:"):
        s = s[len("offset:"):]
    try:
        return max(0, int(s, 0))
    except ValueError:
        return 0


class ArgError(ValueError):
    """Raised by :func:`rewrite_args` for a conflicting alias pair."""


def rewrite_args(spec: ToolSurface, args: dict[str, Any]
                 ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return ``(call_args, raw_args, virtual_values)``.

    ``raw_args`` is the caller's view after alias rewriting (what the trust
    gate and logs should see); ``call_args`` is what the tool body gets.
    """
    action = str(args.get("action") or "")
    raw = dict(args)
    for alias, al in spec.aliases.items():
        if alias not in raw:
            continue
        if al.actions and action not in al.actions:
            # Not this verb's alias: let validation report it as unknown.
            continue
        value = raw.pop(alias)
        if al.target in raw and raw[al.target] not in (None, "", 0, False):
            raise ArgError(
                f"pass either {alias}= or {al.target}=, not both "
                f"({alias} is the {action or 'verb'} name for {al.target})")
        raw[al.target] = value
    for p in spec.json_params:
        v = raw.get(p)
        if isinstance(v, (dict, list)):
            raw[p] = json.dumps(v)
    call = dict(raw)
    virtual: dict[str, Any] = {}
    for vp in spec.virtual:
        if vp in call:
            virtual[vp] = call.pop(vp)
    cursor = virtual.get("cursor", raw.get("cursor"))
    if cursor and "offset" in spec.native and not call.get("offset"):
        n = decode_cursor(cursor)
        if n:
            call["offset"] = n
    return call, raw, virtual


def _validation_errors(exc: BaseException) -> list[dict]:
    cause = exc.__cause__ if exc.__cause__ is not None else exc
    errors = getattr(cause, "errors", None)
    if callable(errors):
        try:
            return list(errors(include_url=False))
        except TypeError:
            return list(errors())
    return []


def bad_arg_envelope(tool: str, action: str, message: str, *,
                     unknown: dict[str, list[str]] | None = None,
                     key_args: str = "", example: str = "") -> dict:
    hint = f"{tool}(action='actions', verb={action!r}) shows the verb's args"
    if key_args:
        hint = f"key args for {action}: {key_args}. " + hint
    err: dict[str, Any] = {"error": message, "kind": "bad_arg",
                           "class": "bad_arg", "retryable": False,
                           "hint": hint}
    if unknown:
        err["did_you_mean"] = {k: v for k, v in unknown.items() if v}
    if example:
        err["example"] = example
    return {"ok": False, "kind": "error", "tool": tool, "action": action,
            "error": err}


def describe_validation_error(tool: str, action: str, exc: BaseException,
                              spec: ToolSurface | None) -> tuple[str, dict]:
    """Turn a pydantic call-validation error into ``(message, unknown)``."""
    known = sorted((spec.native | spec.virtual | set(spec.aliases))
                   if spec else [])
    unknown: dict[str, list[str]] = {}
    parts: list[str] = []
    for e in _validation_errors(exc):
        loc = [str(x) for x in (e.get("loc") or ())]
        pname = loc[-1] if loc else "?"
        etype = str(e.get("type") or "")
        if etype == "unexpected_keyword_argument":
            unknown[pname] = difflib.get_close_matches(pname, known, n=3,
                                                       cutoff=0.55)
            parts.append(f"unknown param {pname!r}")
        elif etype == "missing_argument" or etype == "missing":
            parts.append(f"missing required param {pname!r}")
        else:
            got = e.get("input")
            parts.append(f"{pname}: {e.get('msg')} (got {got!r})"[:200])
    if not parts:
        parts.append(str(exc).splitlines()[0][:200])
    return f"{tool}.{action or '?'}: " + "; ".join(parts), unknown


def _text_result(payload: dict):
    """Wire result for an envelope built here: the same finalize +
    ``to_tool_result`` path every tool response takes (``structured
    content`` = the envelope), so clients see one shape."""
    from .envelope import _emit
    res = _emit(payload)
    if isinstance(res, str):  # fastmcp-less unit envs
        from fastmcp.tools import ToolResult
        from mcp.types import TextContent
        return ToolResult(content=[TextContent(type="text", text=res)])
    return res


def _parse_result_json(result) -> dict | None:
    body = getattr(result, "structured_content", None)
    if isinstance(body, dict):
        return body
    content = getattr(result, "content", None) or []
    for c in content:
        text = getattr(c, "text", None)
        if text:
            try:
                d = json.loads(text)
            except (TypeError, ValueError):
                return None
            return d if isinstance(d, dict) else None
    return None


try:
    from fastmcp.server.middleware import Middleware as _MiddlewareBase
except Exception:  # pragma: no cover — fastmcp always ships it
    _MiddlewareBase = object  # type: ignore[assignment,misc]


class AgentSurfaceMiddleware(_MiddlewareBase):  # type: ignore[misc]
    """Applies the shared call conventions (see module docstring)."""

    def __init__(self, surfaces: dict[str, ToolSurface]):
        self.surfaces = surfaces

    async def on_call_tool(self, context, call_next):
        from fastmcp.exceptions import ValidationError as _FmValidationError

        msg = context.message
        name = getattr(msg, "name", "") or ""
        spec = self.surfaces.get(name)
        if spec is None:
            return await call_next(context)
        args = dict(getattr(msg, "arguments", None) or {})
        action = str(args.get("action") or "")
        try:
            call_args, raw_args, virtual = rewrite_args(spec, args)
        except ArgError as exc:
            return _text_result(bad_arg_envelope(name, action,
                                                 f"{name}.{action}: {exc}"))
        token_call = CALL_INFO.set({"tool": name, "action": action,
                                    "args": raw_args})
        token_verb = ACTIONS_VERB.set(
            str(virtual.get("verb") or raw_args.get("verb") or "")
            if action == "actions" else "")
        try:
            new_msg = msg.model_copy(update={"arguments": call_args})
            try:
                return await call_next(context.copy(message=new_msg))
            except _FmValidationError as exc:
                message, unknown = describe_validation_error(
                    name, action, exc, spec)
                key_args, example = await self._verb_help(
                    context, call_next, msg, action)
                return _text_result(bad_arg_envelope(
                    name, action, message, unknown=unknown,
                    key_args=key_args, example=example))
        finally:
            ACTIONS_VERB.reset(token_verb)
            CALL_INFO.reset(token_call)

    async def _verb_help(self, context, call_next, msg, action: str
                         ) -> tuple[str, str]:
        """Best-effort ``(key_args, example)`` for ``action`` — asks the
        tool itself via ``action='actions'`` so every help table counts."""
        if not action or action == "actions":
            return "", ""
        token = ACTIONS_VERB.set(action)
        try:
            help_msg = msg.model_copy(update={"arguments": {"action": "actions"}})
            res = await call_next(context.copy(message=help_msg))
        except Exception:  # noqa: BLE001 — hint building never masks
            return "", ""
        finally:
            ACTIONS_VERB.reset(token)
        body = _parse_result_json(res) or {}
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        spec = ((data or {}).get("actions") or {}).get(action) or {}
        return str(spec.get("key_args") or ""), str(spec.get("example") or "")


def install(mcp, ctx=None) -> dict[str, ToolSurface]:
    """Run the schema pass and add the middleware. Called once from
    ``build_server`` after every tool is registered."""
    surfaces = finalize_surface(mcp)
    mcp.add_middleware(AgentSurfaceMiddleware(surfaces))
    return surfaces


__all__ = [
    "CALL_INFO",
    "VIRTUAL_PARAMS",
    "PARAM_ALIASES",
    "ParamAlias",
    "ToolSurface",
    "AgentSurfaceMiddleware",
    "finalize_surface",
    "rewrite_args",
    "decode_cursor",
    "install",
]
