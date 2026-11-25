"""Shim preserving the ``from .common import *`` surface area.

Every ``@mcp.tool`` closure inside the per-domain modules reads its
helpers through ``from .common import *``. R2a split the actual
implementations into ``_runtime/*.py`` (response / envelope / guard /
help / addrs / driver_gate / row_filters / breadcrumbs / codegen_glue);
this module re-exports them alongside the pydantic + fastmcp +
external-package symbols the historical ``__all__`` carried.

Zero behaviour change: every public name that used to live here keeps
its leading underscore (API stability — several tests import them by
name) and resolves to the exact same object.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import struct
from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ...agent_client import AgentClient
from ...allowlist import TargetNotAllowed as TargetNotAllowedError
from ...caller import current_client_id
from ...config import PRIMARY_TARGET
from ...findings import FindingsLedger
from ...ida_bridge import IdaBridge, IdaBridgeError
from ...ghidra_bridge import GhidraBridge, GhidraBridgeError
from ...leases import BusyInfo, LeaseHandle, LeaseManager
from ...ownership import OwnershipRegistry
from ...parity import format_report, run_parity, verdict
from ...plugins import PluginError, discover, file_result, meta_dict, run_plugin
from ...session import AmbiguousTargetError, Session

from .context import Context

# Pull every ``_runtime/*`` helper into this module so ``from .common
# import *`` and ``from .common import _foo`` keep working unchanged.
from ._runtime import *  # noqa: F401,F403
from ._runtime import __all__ as _RUNTIME_ALL

log = logging.getLogger(__name__)

try:
    from mcp.types import ToolAnnotations

    READONLY_FALSE = ToolAnnotations(readOnlyHint=False, destructiveHint=True)
    READONLY_TRUE = ToolAnnotations(readOnlyHint=True, destructiveHint=False)
except Exception:  # pragma: no cover - annotations are cosmetic
    READONLY_FALSE = None
    READONLY_TRUE = None


__all__ = sorted(set(list(_RUNTIME_ALL) + [
    'AmbiguousTargetError',
    'AgentClient',
    'Annotated',
    'Any',
    'BaseModel',
    'BusyInfo',
    'Context',
    'FastMCP',
    'Field',
    'FindingsLedger',
    'GhidraBridge',
    'GhidraBridgeError',
    'IdaBridge',
    'IdaBridgeError',
    'LeaseHandle',
    'LeaseManager',
    'OwnershipRegistry',
    'PRIMARY_TARGET',
    'Path',
    'PluginError',
    'READONLY_FALSE',
    'READONLY_TRUE',
    'Session',
    'TargetNotAllowedError',
    'ToolAnnotations',
    'annotations',
    'asyncio',
    'current_client_id',
    'discover',
    'file_result',
    'format_report',
    'hashlib',
    'json',
    'log',
    'logging',
    'meta_dict',
    'os',
    'run_parity',
    'run_plugin',
    'struct',
    'verdict',
]))
