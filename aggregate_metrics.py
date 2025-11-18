"""Compatibility shim for the aggregate_metrics CLI entry point.

This allows tests to `import aggregate_metrics` without modifying PYTHONPATH.
"""

import sys
from importlib import import_module

_module = import_module("tools.vectorscan.aggregate_metrics")
sys.modules[__name__] = _module
