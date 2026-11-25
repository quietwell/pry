"""Shared helpers backing every per-domain MCP tool closure.

The ``tools/common.py`` shim does ``from ._runtime import *`` so every
``from .common import *`` call site in a tool module continues to see
the same ~50 helpers that used to live in a 1485-line ``common.py``.

Explicit ``__all__`` guards against the usual star-import pitfalls:
names that don't start with ``_`` AND aren't in ``__all__`` are not
exported, so submodule-internal imports (``json``, ``re``, …) stay
out of the public shim surface.
"""

from __future__ import annotations

from .addrs import *  # noqa: F401,F403
from .breadcrumbs import *  # noqa: F401,F403
from .codegen_glue import *  # noqa: F401,F403
from .driver_gate import *  # noqa: F401,F403
from .envelope import *  # noqa: F401,F403
from .guard import *  # noqa: F401,F403
from .help import *  # noqa: F401,F403
from .response import *  # noqa: F401,F403
from .row_filters import *  # noqa: F401,F403

from .addrs import __all__ as _addrs_all
from .breadcrumbs import __all__ as _breadcrumbs_all
from .codegen_glue import __all__ as _codegen_glue_all
from .driver_gate import __all__ as _driver_gate_all
from .envelope import __all__ as _envelope_all
from .guard import __all__ as _guard_all
from .help import __all__ as _help_all
from .response import __all__ as _response_all
from .row_filters import __all__ as _row_filters_all


__all__ = sorted(set(
    list(_addrs_all)
    + list(_breadcrumbs_all)
    + list(_codegen_glue_all)
    + list(_driver_gate_all)
    + list(_envelope_all)
    + list(_guard_all)
    + list(_help_all)
    + list(_response_all)
    + list(_row_filters_all)
))
