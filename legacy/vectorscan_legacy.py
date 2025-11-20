"""Compatibility shim that exposes the CLI from `tools.vectorscan` at the project root.

This file allows tests and linters to import `vectorscan` directly without relying on `sys.path` hacks.
"""

import sys
from importlib import import_module

_vectorscan_module = import_module("tools.vectorscan.vectorscan")
sys.modules[__name__] = _vectorscan_module


def main() -> int:
    module_main = getattr(_vectorscan_module, "main", None)
    if module_main is None:
        raise SystemExit("legacy vectorscan entrypoint is unavailable")
    return int(module_main())
