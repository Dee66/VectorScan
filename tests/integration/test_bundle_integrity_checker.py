import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCRIPT = ROOT / "scripts" / "bundle_integrity_checker.py"
PKG_BUILDER = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"


def _run_checker(args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )


def _build_bundle(tmp_path, monkeypatch, bundle_name="vectorscan-free-int-test"):
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(PKG_BUILDER))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    monkeypatch.setattr(mod, "DIST", tmp_path)
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    rc = mod.main(["--bundle-name", bundle_name])
    assert rc == 0

    bundle_path = tmp_path / f"{bundle_name}.zip"
    manifest_path = tmp_path / f"{bundle_name}.manifest.json"
    assert bundle_path.exists()
    assert manifest_path.exists()
    return bundle_path, manifest_path


def _rewrite_zip(source: Path, dest: Path, mutate):
    with zipfile.ZipFile(source, "r") as src, zipfile.ZipFile(dest, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            action = mutate(info, data)
            if action is None:
                dst.writestr(info, data)
                continue
            if action == "skip":
                continue
            new_name, new_data = action
            new_info = zipfile.ZipInfo(new_name)
            new_info.date_time = info.date_time
            new_info.compress_type = info.compress_type
            new_info.external_attr = info.external_attr
            dst.writestr(new_info, new_data)


@pytest.mark.integration
def test_checker_accepts_clean_bundle(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    result = _run_checker(["--bundle", str(bundle)])
    assert result.returncode == 0, result.stderr
    assert "manifest matches" in result.stdout


@pytest.mark.integration
def test_checker_detects_modified_file(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    tampered = tmp_path / "tampered.zip"

    def mutate(info, data):
        if info.filename == "tools/vectorscan/README.md":
            return info.filename, b"tampered data"
        return None

    _rewrite_zip(bundle, tampered, mutate)

    result = _run_checker(["--bundle", str(tampered)])
    assert result.returncode == 4
    assert "sha256 mismatch" in result.stderr


@pytest.mark.integration
def test_checker_detects_missing_file(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    missing = tmp_path / "missing.zip"

    def mutate(info, data):
        if info.filename == "tools/vectorscan/free_policies.rego":
            return "skip"
        return None

    _rewrite_zip(bundle, missing, mutate)

    result = _run_checker(["--bundle", str(missing)])
    assert result.returncode == 4
    assert "missing file" in result.stderr


@pytest.mark.integration
def test_checker_requires_manifest_in_bundle(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    stripped = tmp_path / "stripped.zip"

    def mutate(info, data):
        if info.filename == "manifest.json":
            return "skip"
        return None

    _rewrite_zip(bundle, stripped, mutate)

    result = _run_checker(["--bundle", str(stripped)])
    assert result.returncode == 3
    assert "missing manifest" in result.stderr


@pytest.mark.integration
def test_checker_detects_manifest_mismatch(tmp_path, monkeypatch):
    bundle, manifest = _build_bundle(tmp_path, monkeypatch)
    altered_manifest = tmp_path / "altered_manifest.json"
    data = json.loads(manifest.read_text())
    data["files"][0]["sha256"] = "0" * 64
    altered_manifest.write_text(json.dumps(data), encoding="utf-8")

    result = _run_checker(["--bundle", str(bundle), "--manifest", str(altered_manifest)])
    assert result.returncode == 2
    assert "does not match" in result.stderr


@pytest.mark.integration
def test_checker_rejects_corrupt_zip(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    truncated = tmp_path / "corrupt.zip"
    data = bundle.read_bytes()
    truncated.write_bytes(data[: max(1, len(data) // 4)])

    result = _run_checker(["--bundle", str(truncated)])
    assert result.returncode == 2
    assert "not a valid zip" in result.stderr


@pytest.mark.integration
def test_checker_rejects_invalid_manifest_json(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    broken = tmp_path / "broken.zip"

    def mutate(info, _):
        if info.filename == "manifest.json":
            return info.filename, b"{"
        return None

    _rewrite_zip(bundle, broken, mutate)

    result = _run_checker(["--bundle", str(broken)])
    assert result.returncode == 2
    assert "manifest JSON is invalid" in result.stderr


@pytest.mark.integration
def test_checker_detects_unlisted_extra_file(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    extra = tmp_path / "extra.zip"

    with zipfile.ZipFile(bundle, "r") as src, zipfile.ZipFile(extra, "w") as dst:
        for info in src.infolist():
            dst.writestr(info, src.read(info.filename))
        dst.writestr("unexpected.txt", b"unlisted")

    result = _run_checker(["--bundle", str(extra)])
    assert result.returncode == 4
    assert "files not listed in manifest" in result.stderr


@pytest.mark.integration
def test_checker_detects_preview_metadata_mismatch(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    broken = tmp_path / "preview-mismatch.zip"

    def mutate(info, data):
        if info.filename == "manifest.json":
            manifest = json.loads(data.decode("utf-8"))
            manifest["preview_manifest"]["sha256"] = "0" * 64
            return info.filename, json.dumps(manifest).encode("utf-8")
        return None

    _rewrite_zip(bundle, broken, mutate)

    result = _run_checker(["--bundle", str(broken)])
    assert result.returncode == 2
    assert "preview_manifest sha256 mismatch" in result.stderr


@pytest.mark.integration
def test_checker_requires_signer_metadata(tmp_path, monkeypatch):
    bundle, _ = _build_bundle(tmp_path, monkeypatch)
    broken = tmp_path / "no-signers.zip"

    def mutate(info, data):
        if info.filename == "manifest.json":
            manifest = json.loads(data.decode("utf-8"))
            manifest["signers"] = []
            return info.filename, json.dumps(manifest).encode("utf-8")
        return None

    _rewrite_zip(bundle, broken, mutate)

    result = _run_checker(["--bundle", str(broken)])
    assert result.returncode == 2
    assert "signers metadata missing" in result.stderr
