import importlib.util
import sys
from pathlib import Path


def load_release_module():
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "automate_release.py"
    spec = importlib.util.spec_from_file_location("automate_release_for_tests", str(mod_path))
    assert spec and spec.loader, "Failed to create module spec"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_default_user_bin_respects_override(monkeypatch, tmp_path):
    mod = load_release_module()
    override = tmp_path / "custom-bin"
    monkeypatch.setenv("VSCAN_USER_BIN", str(override))
    monkeypatch.delenv("HOME", raising=False)
    path = mod.default_user_bin()
    assert path == override


def test_default_user_bin_fallback_when_home_missing(monkeypatch):
    mod = load_release_module()
    monkeypatch.delenv("VSCAN_USER_BIN", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    path = mod.default_user_bin()
    assert path == (mod.REPO_ROOT / ".vectorscan-user-bin").resolve()
