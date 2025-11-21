"""Global pytest configuration for VectorScan tests."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_ROOT = _REPO_ROOT / "src"
_PACKAGE_ROOT = (_SRC_ROOT / "vectorscan").resolve()

if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))


def _load_canonical_vectorscan_package() -> None:
    """Force sys.modules['vectorscan'] to reference the src/ package."""

    sys.modules.pop("vectorscan", None)
    importlib.invalidate_caches()
    module = importlib.import_module("vectorscan")
    canonical = str(_PACKAGE_ROOT)
    package_path = getattr(module, "__path__", None)
    if not package_path:
        module.__path__ = [canonical]
        return
    resolved = {str(Path(entry).resolve()) for entry in package_path}
    if canonical not in resolved:
        module.__path__ = [canonical]


_load_canonical_vectorscan_package()


def pytest_sessionstart(session):
    """Ensure no stale shim remains cached before tests import vectorscan."""

    _load_canonical_vectorscan_package()

_STABLE_DURATION_MS = "123"


@pytest.fixture(scope="session", autouse=True)
def _stable_scan_duration_env() -> None:
    """Force deterministic scan_duration_ms across the entire test suite.

    Many CLI-focused tests spawn subprocesses without custom env overrides, so we
    set VSCAN_FORCE_DURATION_MS once per pytest session. This keeps JSON/YAML
    golden comparisons, determinism stress tests, and performance baselines
    stable without requiring every test to remember the override.
    """

    if os.getenv("VSCAN_FORCE_DURATION_MS"):
        return
    os.environ["VSCAN_FORCE_DURATION_MS"] = _STABLE_DURATION_MS
