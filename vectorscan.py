"""Compatibility shim that exposes the CLI from `tools.vectorscan` at the project root.

This file allows tests and linters to import `vectorscan` directly without relying on `sys.path` hacks.
"""
from importlib import import_module
import sys

_vectorscan_module = import_module("tools.vectorscan.vectorscan")
sys.modules[__name__] = _vectorscan_module
