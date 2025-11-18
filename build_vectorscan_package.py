#!/usr/bin/env python3
"""Compatibility alias for tools.vectorscan.build_vectorscan_package."""

from importlib import import_module
import sys

_impl = import_module("tools.vectorscan.build_vectorscan_package")
sys.modules[__name__] = _impl


if __name__ == "__main__":
    _impl.main()
