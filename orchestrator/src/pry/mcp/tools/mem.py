"""R4 moved the ``mem`` tool to a package — see ``mem/__init__.py``.

Phase R4 of the restructuring plan (``an internal plan
03-orchestrator-python.md``) lifted ``mem.py``'s ``register()`` closure
helpers into ``mem/_common.py`` + ``mem/_envelope.py`` and split the
scan subsystem into ``mem/scan.py``. The dispatcher now lives at
``mem/__init__.py`` — the ``pry.mcp.tools.mem`` import path still
resolves to the same ``_MEMORY_ACTIONS_MASTER`` / ``register()`` surface, because
Python prefers a package over a sibling ``mem.py`` module. R5 will
drag each verb body out into its own sibling file (``mem/read.py``
etc.) and shrink ``mem/__init__.py`` to the ~400-line dispatcher the
slice doc targets.

This file is a landmark only. Python never imports it (the package
wins at module resolution); it exists so filesystem-reading tooling
that remembers ``tools/mem.py``'s pre-R4 path still finds a file at
the old location.
"""
