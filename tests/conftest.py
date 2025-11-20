"""Global pytest configuration for VectorScan tests."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath("src"))

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
