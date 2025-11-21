import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.vectorscan import vectorscan as vscan

_safe_chdir_flag = vscan._safe_chdir_flag
ModernTerraformTestStrategy = vscan.ModernTerraformTestStrategy


def test_safe_chdir_flag_accepts_repo_path(tmp_path):
    root = tmp_path / "repo"
    target = root / "tests" / "tf-tests"
    target.mkdir(parents=True)

    flag = _safe_chdir_flag(target, root=root)
    assert flag.endswith(str(target.resolve()))


def test_safe_chdir_flag_blocks_escape(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(ValueError):
        _safe_chdir_flag(outside, root=root)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable on platform")
def test_safe_chdir_flag_blocks_symlink_escape(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_tf = outside / "tf-tests"
    outside_tf.mkdir()

    tests_dir = repo / "tests"
    tests_dir.mkdir()
    symlink_target = tests_dir / "tf-tests"
    symlink_target.symlink_to(outside_tf, target_is_directory=True)

    with pytest.raises(ValueError) as excinfo:
        _safe_chdir_flag(symlink_target, root=repo)

    assert "escapes" in str(excinfo.value)


def test_modern_strategy_reports_error_on_unsafe_path(monkeypatch):
    strategy = ModernTerraformTestStrategy()

    def boom(*args, **kwargs):  # pragma: no cover - simple test helper
        raise ValueError("escape detected")

    monkeypatch.setattr(vscan, "_safe_chdir_flag", boom)

    report = strategy.run(Path("/usr/bin/terraform"), "1.9.0")
    assert report["status"] == "ERROR"
    assert "escape detected" in report["message"]


def test_modern_strategy_commands_include_safe_chdir(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    tf_dir = repo / "tests" / "tf-tests"
    tf_dir.mkdir(parents=True)

    monkeypatch.setattr(vscan, "ROOT_DIR", repo)

    chdir_calls = []

    def fake_safe(path, root=None):
        chdir_calls.append((path, root))
        assert path == tf_dir
        return "-chdir=/safe"

    monkeypatch.setattr(vscan, "_safe_chdir_flag", fake_safe)

    recorded_commands = []

    def fake_run(cmd, capture_output=True, text=True, check=False):
        recorded_commands.append(cmd)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(vscan.subprocess, "run", fake_run)

    strategy = ModernTerraformTestStrategy()
    report = strategy.run(Path("/usr/bin/terraform"), "1.9.0")

    assert report["status"] == "PASS"
    assert len(chdir_calls) == 1
    assert recorded_commands
    assert all(cmd[1] == "-chdir=/safe" for cmd in recorded_commands)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable on platform")
def test_modern_strategy_rejects_symlink_escape(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_tf = outside / "tf-tests"
    outside_tf.mkdir()

    tests_dir = repo / "tests"
    tests_dir.mkdir()
    tf_symlink = tests_dir / "tf-tests"
    tf_symlink.symlink_to(outside_tf, target_is_directory=True)

    monkeypatch.setattr(vscan, "ROOT_DIR", repo)

    strategy = ModernTerraformTestStrategy()
    report = strategy.run(Path("/usr/bin/terraform"), "1.9.0")

    assert report["status"] == "ERROR"
    assert "escapes" in report["message"]
