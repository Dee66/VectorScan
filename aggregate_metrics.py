"""Compatibility shim for ``tools.vectorscan.aggregate_metrics`` entry point."""

from __future__ import annotations

import sys
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.vectorscan import aggregate_metrics as _aggregate_metrics

    extract_result = _aggregate_metrics.extract_result
    load_json = _aggregate_metrics.load_json
    main = _aggregate_metrics.main

_MODULE = import_module("tools.vectorscan.aggregate_metrics")
sys.modules[__name__] = _MODULE


if __name__ == "__main__":
    raise SystemExit(_MODULE.main())
