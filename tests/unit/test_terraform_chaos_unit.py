import hashlib
import io
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tools.vectorscan.vectorscan as vs  # noqa: E402


def test_run_terraform_tests_handles_binary_crash(monkeypatch):
    resolution = vs.TerraformResolution(
        path=Path("/fake/bin/terraform"), version="1.8.5", source="system"
    )

    def fake_ensure(self, override_path):  # pragma: no cover - monkeypatched
        return resolution

    class ExplodingStrategy(vs.TerraformTestStrategy):
        name = "exploding"

        def run(self, terraform_bin: Path, version: str):  # pragma: no cover - monkeypatched
            raise OSError("simulated terraform panic")

    monkeypatch.setattr(vs.TerraformManager, "ensure", fake_ensure)
    monkeypatch.setattr(vs, "_select_strategy", lambda version: ExplodingStrategy())

    report = vs.run_terraform_tests(None, auto_download=True)
    assert report["status"] == "ERROR"
    assert "simulated terraform panic" in report["message"]
    assert report["version"] == "1.8.5"
    assert report["strategy"] == "exploding"
    assert report["binary"].endswith("terraform")


def test_truncate_output_limits_long_strings():
    long_text = "A" * 5000
    truncated = vs._truncate_output(long_text, limit=100)
    assert truncated.endswith("... (truncated)")
    assert len(truncated) == 100 + len("\n... (truncated)")


def test_truncate_output_strict_returns_full_text():
    text = "A" * 5000
    result = vs._truncate_output(text, limit=10, strict=True)
    assert result == text


def test_modern_strategy_reports_corrupted_state(monkeypatch):
    strategy = vs.ModernTerraformTestStrategy()
    calls = []

    def fake_run(cmd, **kwargs):  # pragma: no cover - monkeypatched
        # Command shape: [terraform_bin, "-chdir=...", subcommand, ...]
        op = cmd[2]
        calls.append(op)
        if op == "init":
            return SimpleNamespace(returncode=0, stdout="init ok", stderr="")
        return SimpleNamespace(
            returncode=1,
            stdout="running tests",
            stderr="Error: state snapshot was invalid\nMore diagnostics",
        )

    monkeypatch.setattr(vs.subprocess, "run", fake_run)

    result = strategy.run(Path("/fake/bin/terraform"), "1.8.5")
    assert calls == ["init", "test"]
    assert result["status"] == "FAIL"
    assert result["returncode"] == 1
    assert "state snapshot was invalid" in result["stderr"]
    assert result["init_returncode"] == 0


def test_run_terraform_tests_skips_when_missing(monkeypatch):
    def fake_ensure(self, override_path):  # pragma: no cover - monkeypatched helper
        raise vs.TerraformNotFoundError(
            "Terraform CLI not found and auto-download disabled. Set VSCAN_TERRAFORM_BIN or enable downloads."
        )

    monkeypatch.setattr(vs.TerraformManager, "ensure", fake_ensure)
    report = vs.run_terraform_tests(None, auto_download=False)
    assert report["status"] == "SKIP"
    assert "Terraform CLI not found" in report["message"]


def test_terraform_download_handles_unwritable_tmpdir(monkeypatch, tmp_path):
    version = "9.9.9"
    manager = vs.TerraformManager(
        required_version=version, download_dir=tmp_path, auto_download=True
    )

    os_tag = vs.platform.system().lower()
    arch_tag = vs.platform.machine().lower()
    os_map = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    arch_map = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
    filename = f"terraform_{version}_{os_map[os_tag]}_{arch_map[arch_tag]}.zip"
    binary_name = "terraform.exe" if os_map[os_tag] == "windows" else "terraform"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(binary_name, "fake terraform binary")
    zip_bytes = buf.getvalue()
    checksum = hashlib.sha256(zip_bytes).hexdigest()
    sums_blob = f"{checksum}  {filename}\n".encode("utf-8")

    class FakeResp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(url, timeout=30):  # pragma: no cover - monkeypatched helper
        target = getattr(url, "full_url", url)
        if str(target).endswith("SHA256SUMS"):
            return FakeResp(sums_blob)
        return FakeResp(zip_bytes)

    monkeypatch.setattr(vs.request, "urlopen", fake_urlopen)

    def raise_perm(*_, **__):  # pragma: no cover - monkeypatched helper
        raise PermissionError("no tmp")

    monkeypatch.setattr(vs.tempfile, "mkdtemp", raise_perm)

    with pytest.raises(vs.TerraformDownloadError) as excinfo:
        manager._download()

    assert "Failed to create temp dir" in str(excinfo.value)


def test_terraform_download_rejects_checksum_mismatch(monkeypatch, tmp_path):
    version = "9.9.9"
    manager = vs.TerraformManager(
        required_version=version, download_dir=tmp_path, auto_download=True
    )

    os_tag = vs.platform.system().lower()
    arch_tag = vs.platform.machine().lower()
    os_map = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    arch_map = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
    filename = f"terraform_{version}_{os_map[os_tag]}_{arch_map[arch_tag]}.zip"
    binary_name = "terraform.exe" if os_map[os_tag] == "windows" else "terraform"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(binary_name, "fake terraform binary contents")
    zip_bytes = buf.getvalue()
    checksum = hashlib.sha256(zip_bytes).hexdigest()
    mismatched_checksum = "0" * 64 if checksum != "0" * 64 else "f" * 64
    sums_blob = f"{mismatched_checksum}  {filename}\n".encode("utf-8")

    class FakeResp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(url, timeout=30):  # pragma: no cover - deterministic helper
        target = getattr(url, "full_url", url)
        if str(target).endswith("SHA256SUMS"):
            return FakeResp(sums_blob)
        return FakeResp(zip_bytes)

    monkeypatch.setattr(vs.request, "urlopen", fake_urlopen)

    with pytest.raises(vs.TerraformDownloadError) as excinfo:
        manager._download()

    assert "Checksum mismatch" in str(excinfo.value)
    dest_binary = tmp_path / version / binary_name
    assert not dest_binary.exists()
