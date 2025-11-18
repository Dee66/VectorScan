#!/usr/bin/env python3
"""Compatibility alias for ``tools.vectorscan.build_vectorscan_package``."""

from __future__ import annotations

import sys
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.vectorscan import build_vectorscan_package as _build_vectorscan_package

    main = _build_vectorscan_package.main
    write_sha256 = _build_vectorscan_package.write_sha256

_MODULE = import_module("tools.vectorscan.build_vectorscan_package")
sys.modules[__name__] = _MODULE


if __name__ == "__main__":
    raise SystemExit(_MODULE.main())
