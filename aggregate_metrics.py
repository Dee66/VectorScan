"""Compatibility shim for the aggregate_metrics CLI entry point.

This allows tests to `import aggregate_metrics` without modifying PYTHONPATH.
"""
from importlib import import_module
import sys

_module = import_module("tools.vectorscan.aggregate_metrics")
sys.modules[__name__] = _module
