"""Global pytest configuration for VectorScan tests."""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest
from tools.vectorscan.constants import DEFAULT_TERRAFORM_CACHE, REQUIRED_TERRAFORM_VERSION

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_ROOT = _REPO_ROOT / "src"
_PACKAGE_ROOT = (_SRC_ROOT / "vectorscan").resolve()

# Make both the repository root and the src/ directory available on sys.path.
# This allows imports that reference the top-level `src` package (e.g.
# `import src.vectorscan`) as well as imports that expect `vectorscan` to be
# directly importable from `src/` (legacy test shims).
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))


def _load_canonical_vectorscan_package() -> None:
    """Force sys.modules['vectorscan'] to reference the src/ package."""

    sys.modules.pop("vectorscan", None)
    importlib.invalidate_caches()
    module = importlib.import_module("vectorscan")
    canonical = str(_PACKAGE_ROOT)
    package_path = getattr(module, "__path__", None)
    # Ensure `__file__` exists on the module so tests that monkeypatch
    # `vectorscan.__file__` can operate as expected.
    if not getattr(module, "__file__", None):
        module.__file__ = str((_PACKAGE_ROOT / "__init__.py"))
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
        "VSCAN_USE_LOCAL_TERRAFORM_CACHE": os.environ.get("VSCAN_USE_LOCAL_TERRAFORM_CACHE"),
    }
    # Force deterministic network/terraform stubbing values for the test
    # session regardless of the external environment.
    os.environ["VSCAN_ALLOW_NETWORK"] = "0"
    os.environ["VSCAN_TERRAFORM_AUTO_DOWNLOAD"] = "0"
    os.environ["VSCAN_TERRAFORM_STUB"] = "1"
    # Ensure repository-local terraform cache usage is disabled by default
    # for unit tests. Tests that explicitly opt-in may set the environment
    # variable themselves for integration scenarios.
    os.environ.pop("VSCAN_USE_LOCAL_TERRAFORM_CACHE", None)

    # For deterministic test runs, create a lightweight repository-local
    # terraform stub binary (if not already present) that reports the
    # required Terraform version. This satisfies tests that expect a
    # discoverable binary without relying on system discovery.
    created_stub = False
    try:
        # Create stubs for a small set of Terraform versions exercised by unit
        # tests. This avoids relying on system discovery and keeps behavior
        # deterministic for subprocess calls.
        versions = {
            REQUIRED_TERRAFORM_VERSION,
            "1.3.0",
            "9.9.9",
            "1.5.7",
            "0.12.0",
            "0.11.0",
        }
        for ver in versions:
            dest_dir = (DEFAULT_TERRAFORM_CACHE / ver)
            dest_dir.mkdir(parents=True, exist_ok=True)
            binary = dest_dir / ("terraform.exe" if sys.platform.startswith("win") else "terraform")
            if not binary.exists():
                stub = f"""#!/usr/bin/env bash
# Minimal terraform stub for tests
cmd="$1"
shift || true
case "$cmd" in
  version)
    if [ "$1" = "-json" ]; then
      echo '{{"terraform_version":"{ver}"}}'
      exit 0
    else
      echo "Terraform v{ver}"
      exit 0
    fi
    ;;
  *)
    exit 0
    ;;
esac
"""
                binary.write_text(stub, encoding="utf-8")
                binary.chmod(0o755)
                created_stub = True
    except Exception:
        created_stub = False
    try:
        yield
    finally:
        for key, value in tracked.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        # Remove the test-created repo-local terraform stub if we created it
        try:
            if created_stub:
                binary.unlink(missing_ok=True)
                try:
                    # attempt to remove parent dir if empty
                    dest_dir.rmdir()
                except Exception:
                    pass
        except Exception:
            pass


@pytest.fixture(scope="session")
def terraform_mocks():
    """Provide reusable Terraform test reports for monkeypatch helpers."""

    from tests.fixtures import terraform_mocks as helpers

    return helpers
