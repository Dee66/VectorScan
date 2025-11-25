"""Global pytest configuration for VectorScan tests."""

from __future__ import annotations

import importlib
import json
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


def pytest_addoption(parser) -> None:
    """Register project-specific pytest flags."""

    parser.addoption(
        "--update-snapshots",
        action="store_true",
        default=False,
        help="Regenerate canonical VectorScan golden and snapshot fixtures.",
    )


def pytest_configure(config) -> None:
    """Propagate snapshot update flag to the test environment."""

    if config.getoption("--update-snapshots"):
        os.environ["VSCAN_UPDATE_SNAPSHOTS"] = "1"


@pytest.fixture(scope="session")
def snapshot_updater(pytestconfig):
    """Return a helper to write canonical snapshot payloads when requested."""

    update_mode = pytestconfig.getoption("--update-snapshots")
    return SnapshotWriter(enabled=bool(update_mode), repo_root=_REPO_ROOT)


class SnapshotWriter:
    """Helper that rewrites snapshot files with canonical payloads when enabled."""

    def __init__(self, *, enabled: bool, repo_root: Path) -> None:
        self.enabled = enabled
        self.repo_root = repo_root
        self._golden_dir = (self.repo_root / "tests" / "golden").resolve()
        self._snapshots_dir = (self.repo_root / "tests" / "snapshots").resolve()

    def maybe_write(self, path: Path, payload: dict) -> None:
        if not self.enabled:
            return
        target_path = Path(path)
        if not target_path.is_absolute():
            target_path = (self.repo_root / target_path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(payload, indent=2, sort_keys=True)
        target_path.write_text(serialized, encoding="utf-8")
        try:
            relative = target_path.relative_to(self._golden_dir)
        except ValueError:
            return
        snapshot_path = self._snapshots_dir / relative
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(serialized, encoding="utf-8")


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


@pytest.fixture(scope="session", autouse=True)
def _terraform_stubbed_environment():
    """Ensure Terraform interactions stay offline and deterministic."""

    tracked = {
        "VSCAN_ALLOW_NETWORK": os.environ.get("VSCAN_ALLOW_NETWORK"),
        "VSCAN_TERRAFORM_AUTO_DOWNLOAD": os.environ.get("VSCAN_TERRAFORM_AUTO_DOWNLOAD"),
        "VSCAN_TERRAFORM_STUB": os.environ.get("VSCAN_TERRAFORM_STUB"),
    }
    os.environ.setdefault("VSCAN_ALLOW_NETWORK", "0")
    os.environ.setdefault("VSCAN_TERRAFORM_AUTO_DOWNLOAD", "0")
    os.environ.setdefault("VSCAN_TERRAFORM_STUB", "1")
    try:
        yield
    finally:
        for key, value in tracked.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture(scope="session")
def terraform_mocks():
    """Provide reusable Terraform test reports for monkeypatch helpers."""

    from tests.fixtures import terraform_mocks as helpers

    return helpers
