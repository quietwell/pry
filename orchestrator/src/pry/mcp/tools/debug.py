"""Memory scanner wave 3 P4 lifted the ``debug`` tool to a package.

The dispatcher that used to live in this file (DEBUG_ACTIONS,
_DEBUG_ACTION_HELP, the ``debug_manage`` register() closure) now lives
in ``debug/__init__.py`` — the ``pry.mcp.tools.debug`` import path
still resolves to the same ``register()`` surface because Python prefers
a package over a sibling ``.py`` module.

Adding the four AccessTrace verbs needed a second file under this
namespace (``debug/_x64_memop.py``, ``debug/_watchhw_driver.py``,
``debug/_dbgeng_driver.py``, ``debug/access_trace.py``), which Python
cannot accommodate without promoting the module to a package. Same
mechanical move the ``mem`` tool already went through — see
``mem.py`` for its landmark.

This file is a landmark only. Python never imports it (the package
wins at module resolution); it exists so filesystem-reading tooling
that remembers ``tools/debug.py``'s pre-Wave-3 path still finds a file
at the old location.
"""
