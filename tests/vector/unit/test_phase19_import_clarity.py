"""Phase 19 regression tests for canonical import hygiene."""

from pathlib import Path
import importlib


def test_vectorscan_package_imports_cleanly():
    module = importlib.import_module("vectorscan")
    assert module.__name__ == "vectorscan"


def test_legacy_shims_removed():
    assert not Path("vectorscan.py").exists()
    assert not Path("vectorscan_legacy.py").exists()
