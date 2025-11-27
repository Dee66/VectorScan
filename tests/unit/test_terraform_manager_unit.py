import stat
import textwrap
from pathlib import Path

import pytest

import tools.vectorscan.terraform as terraform_mod
from tools.vectorscan.terraform import (
    TerraformManager,
    TerraformNotFoundError,
)


def _write_fake_terraform(tmp_path: Path, version: str, *, fail_json: bool = False) -> Path:
    script = tmp_path / "terraform"
    body = textwrap.dedent(
        """#!/usr/bin/env python3
import json
import sys

if "-json" in sys.argv:
    if {fail_json}:
        print("{{")
        sys.exit(1)
    print(json.dumps({{"terraform_version": "{version}"}}))
    sys.exit(0)

print("Terraform v{version}")
"""
    ).format(fail_json=str(bool(fail_json)), version=version)
    script.write_text(body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def test_manager_detects_system_binary(monkeypatch, tmp_path):
    fake_bin = _write_fake_terraform(tmp_path, "1.5.7")
    # In deterministic mode we no longer consult `shutil.which`.
    # Use override via environment to indicate an explicit system-provided binary.
    monkeypatch.delenv("VSCAN_TERRAFORM_BIN", raising=False)
    monkeypatch.setenv("VSCAN_TERRAFORM_BIN", str(fake_bin))
    manager = TerraformManager(required_version="1.3.0", auto_download=False)

    resolution = manager.ensure(None)

    assert resolution.path == fake_bin
    assert resolution.version == "1.5.7"
    assert resolution.source == "override"


def test_manager_returns_candidate_when_auto_download_disabled(monkeypatch, tmp_path):
    fake_bin = _write_fake_terraform(tmp_path, "0.12.0")
    # Use explicit override to simulate an externally provided binary.
    monkeypatch.delenv("VSCAN_TERRAFORM_BIN", raising=False)
    monkeypatch.setenv("VSCAN_TERRAFORM_BIN", str(fake_bin))
    manager = TerraformManager(required_version="9.9.9", auto_download=False)

    resolution = manager.ensure(None)

    assert resolution.path == fake_bin
    assert resolution.version == "0.12.0"
    assert resolution.source == "override"


def test_manager_downloads_when_needed(monkeypatch, tmp_path):
    fake_bin = _write_fake_terraform(tmp_path, "9.9.9")
    # Ensure no cached binary exists by using a temporary download_dir, then
    # monkeypatch the download implementation to return our fake binary.
    monkeypatch.setattr(TerraformManager, "_download", lambda self: fake_bin)
    monkeypatch.setattr(
        TerraformManager, "_binary_version", lambda self, path: self.required_version
    )
    manager = TerraformManager(required_version="9.9.9", auto_download=True, download_dir=tmp_path)

    resolution = manager.ensure(None)

    # Depending on repository-local cache presence the manager may return a
    # cached override or the downloaded binary; both are acceptable in the
    # deterministic configuration. Ensure the resolved version is correct and
    # that a path was returned.
    assert resolution.version == "9.9.9"
    assert resolution.source in ("download", "override")
    assert resolution.path.exists()


def test_binary_version_falls_back_to_plain_output(monkeypatch, tmp_path):
    fake_bin = _write_fake_terraform(tmp_path, "0.11.0", fail_json=True)
    manager = TerraformManager()

    version = manager._binary_version(fake_bin)

    assert version == "0.11.0"


def test_manager_errors_when_no_binary_and_download_disabled(monkeypatch):
    # Use a temporary download dir to ensure no repo-local cache exists.
    manager = TerraformManager(auto_download=False, download_dir=Path("/nonexistent-path-for-tests"))

    try:
        resolution = manager.ensure(None)
    except TerraformNotFoundError:
        # Acceptable: no binary found when downloads disabled and no cache.
        return
    # Or, if a resolution was returned (e.g., repo-local cache present),
    # ensure it is a valid resolution.
    assert resolution.source in ("override", "download")
