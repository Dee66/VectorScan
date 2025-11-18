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
    monkeypatch.setattr(terraform_mod.shutil, "which", lambda _: str(fake_bin))
    manager = TerraformManager(required_version="1.3.0", auto_download=False)

    resolution = manager.ensure(None)

    assert resolution.path == fake_bin
    assert resolution.version == "1.5.7"
    assert resolution.source == "system"


def test_manager_returns_candidate_when_auto_download_disabled(monkeypatch, tmp_path):
    fake_bin = _write_fake_terraform(tmp_path, "0.12.0")
    monkeypatch.setattr(terraform_mod.shutil, "which", lambda _: str(fake_bin))
    manager = TerraformManager(required_version="9.9.9", auto_download=False)

    resolution = manager.ensure(None)

    assert resolution.path == fake_bin
    assert resolution.version == "0.12.0"
    assert resolution.source == "system"


def test_manager_downloads_when_needed(monkeypatch, tmp_path):
    fake_bin = _write_fake_terraform(tmp_path, "9.9.9")
    monkeypatch.setattr(terraform_mod.shutil, "which", lambda _: None)
    monkeypatch.setattr(TerraformManager, "_download", lambda self: fake_bin)
    monkeypatch.setattr(
        TerraformManager, "_binary_version", lambda self, path: self.required_version
    )
    manager = TerraformManager(required_version="9.9.9", auto_download=True)

    resolution = manager.ensure(None)

    assert resolution.path == fake_bin
    assert resolution.version == "9.9.9"
    assert resolution.source == "download"


def test_binary_version_falls_back_to_plain_output(monkeypatch, tmp_path):
    fake_bin = _write_fake_terraform(tmp_path, "0.11.0", fail_json=True)
    manager = TerraformManager()

    version = manager._binary_version(fake_bin)

    assert version == "0.11.0"


def test_manager_errors_when_no_binary_and_download_disabled(monkeypatch):
    monkeypatch.setattr(terraform_mod.shutil, "which", lambda _: None)
    manager = TerraformManager(auto_download=False)

    with pytest.raises(TerraformNotFoundError):
        manager.ensure(None)
