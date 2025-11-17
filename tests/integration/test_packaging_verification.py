import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath
import zipfile

# Ensure repository root import paths
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_build_vectorscan_package_smoke(tmp_path, monkeypatch):
    # Import module
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    # Use a temporary dist directory by monkeypatching DIST
    monkeypatch.setattr(mod, "DIST", tmp_path)

    # Run main, allow pytest flags via parse_known_args
    rc = mod.main(["--bundle-name", "vectorscan-free-test"])
    assert rc == 0

    # Verify outputs
    out_zip = tmp_path / "vectorscan-free-test.zip"
    out_sha = tmp_path / "vectorscan-free-test.zip.sha256"
    manifest_path = tmp_path / "vectorscan-free-test.manifest.json"
    manifest_sha = manifest_path.with_suffix(".json.sha256")
    sbom_path = tmp_path / "vectorscan-free-test.sbom.json"
    sbom_sha = sbom_path.with_suffix(".json.sha256")
    assert out_zip.exists()
    assert out_sha.exists()
    assert manifest_path.exists()
    assert manifest_sha.exists()
    assert sbom_path.exists()
    assert sbom_sha.exists()

    with zipfile.ZipFile(out_zip) as z:
        names = set(z.namelist())
        # Must include core files
        assert "tools/vectorscan/vectorscan.py" in names
        assert "tools/vectorscan/README.md" in names
        assert "tools/vectorscan/free_policies.rego" in names
        # License snippet
        assert "LICENSE_FREE.txt" in names
    assert "manifest.json" in names
    assert "sbom.json" in names

    manifest = json.loads(manifest_path.read_text())
    assert manifest["bundle_name"] == "vectorscan-free-test"
    assert manifest["bundle_version"] == "dev"
    paths = {entry["path"] for entry in manifest["files"]}
    assert "tools/vectorscan/vectorscan.py" in paths
    assert "LICENSE_FREE.txt" in paths
    assert "sbom.json" in paths
    assert all(len(entry["sha256"]) == 64 for entry in manifest["files"])

    sbom = json.loads(sbom_path.read_text())
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["metadata"]["component"]["name"] == "vectorscan-free-test"
    component_names = {component["name"] for component in sbom["components"]}
    assert "fastapi" in component_names


def test_create_release_bundle_dry_run(tmp_path, monkeypatch):
    # Import module
    script_path = ROOT / "scripts" / "create_release_bundle.py"
    import importlib.util
    spec = importlib.util.spec_from_file_location("create_release_bundle", str(script_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    # Monkeypatch REPO_ROOT to a temp copy so we don't bundle the whole repo
    # Create minimal structure in tmp: README.md, tools/vectorscan, docs
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("Test README", encoding="utf-8")
    (repo / "docs").mkdir()
    (repo / "tools").mkdir()
    # Add minimal files so directories contribute entries to the zip
    (repo / "docs" / "guide.md").write_text("Docs guide", encoding="utf-8")
    (repo / "tools" / "helper.txt").write_text("Helper", encoding="utf-8")

    monkeypatch.setattr(mod, "REPO_ROOT", repo)
    monkeypatch.setattr(mod, "PKG_ROOT", repo)

    # Skip git check
    rc = mod.main(["--version", "0.0.0", "--no-git-check"])
    assert rc == 0

    # Check outputs
    dist = repo / "dist"
    zip_path = dist / "vectorguard-v0.0.0.zip"
    sha_path = dist / "vectorguard-v0.0.0.zip.sha256"
    assert zip_path.exists()
    assert sha_path.exists()

    # Verify contents include README.md and at least one directory
    with zipfile.ZipFile(zip_path) as z:
        names = set(z.namelist())
        assert "README.md" in names
    assert any(n.startswith("docs/") or n.startswith("tools/") for n in names)


def test_build_vectorscan_package_reproducible(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    bundle_name = "vectorscan-free-repro"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    # Avoid Terraform download side-effects for reproducibility test
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    rc1 = mod.main(["--bundle-name", bundle_name])
    assert rc1 == 0
    bundle_path = tmp_path / f"{bundle_name}.zip"
    sha_path = bundle_path.with_suffix(bundle_path.suffix + ".sha256")
    sbom_path = tmp_path / f"{bundle_name}.sbom.json"
    assert bundle_path.exists() and sha_path.exists()
    first_zip = bundle_path.read_bytes()
    first_sha = sha_path.read_text()

    first_manifest = (tmp_path / f"{bundle_name}.manifest.json").read_text()
    first_sbom = sbom_path.read_text()

    rc2 = mod.main(["--bundle-name", bundle_name])
    assert rc2 == 0
    second_zip = bundle_path.read_bytes()
    second_sha = sha_path.read_text()
    second_manifest = (tmp_path / f"{bundle_name}.manifest.json").read_text()
    second_sbom = sbom_path.read_text()

    assert first_zip == second_zip, "Bundle zip should be byte-identical across runs"
    assert first_sha == second_sha, ".sha256 output should be identical across runs"
    assert first_manifest == second_manifest, "Manifest output should be identical across runs"
    assert first_sbom == second_sbom, "SBOM output should be identical across runs"


def test_zip_entries_have_fixed_timestamp(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    bundle_name = "vectorscan-free-fixed-time"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    rc = mod.main(["--bundle-name", bundle_name])
    assert rc == 0

    bundle_path = tmp_path / f"{bundle_name}.zip"
    with zipfile.ZipFile(bundle_path) as z:
        infos = z.infolist()
        assert infos, "expected zip entries"
        for info in infos:
            assert info.date_time == (1980, 1, 1, 0, 0, 0), f"Unexpected timestamp for {info.filename}: {info.date_time}"


def test_cli_runs_from_unzipped_bundle(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    bundle_name = "vectorscan-free-cli-smoke"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    rc = mod.main(["--bundle-name", bundle_name])
    assert rc == 0

    bundle_path = tmp_path / f"{bundle_name}.zip"
    assert bundle_path.exists()

    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    with zipfile.ZipFile(bundle_path) as z:
        z.extractall(path=extract_dir)

    cli_path = extract_dir / "tools" / "vectorscan" / "vectorscan.py"
    assert cli_path.exists()

    plan_path = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
    result = subprocess.run(
        [sys.executable, str(cli_path), str(plan_path), "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "\"status\": \"PASS\"" in result.stdout


def test_bundle_contains_no_hidden_mac_artifacts(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    bundle_name = "vectorscan-free-hidden-guard"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    # Avoid Terraform download to keep the test fast
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    rc = mod.main(["--bundle-name", bundle_name])
    assert rc == 0

    bundle_path = tmp_path / f"{bundle_name}.zip"
    assert bundle_path.exists()

    with zipfile.ZipFile(bundle_path) as z:
        names = z.namelist()
        offenders = []
        for name in names:
            parts = PurePosixPath(name).parts
            if "__MACOSX" in parts:
                offenders.append(name)
                continue
            if any(part == ".DS_Store" for part in parts):
                offenders.append(name)
                continue
            if PurePosixPath(name).name.startswith("._"):
                offenders.append(name)
        assert not offenders, f"Unexpected hidden macOS artifacts found: {offenders}"


def test_manifest_lists_expected_files(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    bundle_name = "vectorscan-free-manifest"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    rc = mod.main(["--bundle-name", bundle_name, "--bundle-version", "1.2.3"])
    assert rc == 0

    manifest_path = tmp_path / f"{bundle_name}.manifest.json"
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    assert manifest["bundle_name"] == bundle_name
    assert manifest["bundle_version"] == "1.2.3"
    assert manifest["file_count"] == len(manifest["files"])
    paths = {entry["path"] for entry in manifest["files"]}
    assert "tools/vectorscan/vectorscan.py" in paths
    assert "LICENSE_FREE.txt" in paths
    assert "sbom.json" in paths
    assert not any(path.startswith("__MACOSX") for path in paths)

    # Manifest embedded inside the zip should match the dist copy
    bundle_path = tmp_path / f"{bundle_name}.zip"
    with zipfile.ZipFile(bundle_path) as z:
        zipped_manifest = json.loads(z.read("manifest.json").decode("utf-8"))
    assert zipped_manifest == manifest


def test_sbom_matches_requirement_files(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    bundle_name = "vectorscan-free-sbom"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    rc = mod.main(["--bundle-name", bundle_name])
    assert rc == 0

    sbom_path = tmp_path / f"{bundle_name}.sbom.json"
    sbom = json.loads(sbom_path.read_text())
    components = sbom["components"]

    expected_entries = mod._collect_requirement_entries(mod.REQUIREMENT_FILES)  # type: ignore[attr-defined]
    expected_map = {entry["name"]: entry for entry in expected_entries}
    assert expected_map, "Expected to read requirement entries"

    component_names = {component["name"] for component in components}
    assert component_names == set(expected_map.keys())

    for component in components:
        props = {prop["name"]: prop["value"] for prop in component.get("properties", [])}
        assert "cdx:requirement" in props
        assert props["cdx:requirement"] == expected_map[component["name"]]["raw"]


def test_text_files_normalized_to_lf(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    extra_dir = ROOT / f"tmp_crlf_{uuid.uuid4().hex}"
    extra_dir.mkdir(exist_ok=True)
    extra_file = extra_dir / "crlf_sample.txt"
    extra_file.write_bytes(b"line1\r\nline2\rline3\n")

    bundle_name = "vectorscan-free-crlf"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    monkeypatch.setattr(mod, "FILES", list(mod.FILES) + [extra_file])  # type: ignore[attr-defined]
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    try:
        rc = mod.main(["--bundle-name", bundle_name])
        assert rc == 0

        bundle_path = tmp_path / f"{bundle_name}.zip"
        with zipfile.ZipFile(bundle_path) as z:
            arcname = extra_file.relative_to(ROOT).as_posix()
            data = z.read(arcname)
        assert b"\r" not in data
    finally:
        shutil.rmtree(extra_dir, ignore_errors=True)


def test_unicode_filename_is_preserved(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    unicode_dir = ROOT / f"tmp_unicode_{uuid.uuid4().hex}"
    unicode_dir.mkdir(exist_ok=True)
    unicode_file = unicode_dir / "分析指南📄.md"
    unicode_file.write_text("unicode test", encoding="utf-8")

    bundle_name = "vectorscan-free-unicode"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    monkeypatch.setattr(mod, "FILES", list(mod.FILES) + [unicode_file])  # type: ignore[attr-defined]
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    try:
        rc = mod.main(["--bundle-name", bundle_name])
        assert rc == 0

        rel = unicode_file.relative_to(ROOT).as_posix()
        bundle_path = tmp_path / f"{bundle_name}.zip"
        with zipfile.ZipFile(bundle_path) as z:
            names = z.namelist()
            assert rel in names
        manifest = json.loads((tmp_path / f"{bundle_name}.manifest.json").read_text())
        assert rel in {entry["path"] for entry in manifest["files"]}
    finally:
        shutil.rmtree(unicode_dir, ignore_errors=True)


def test_sensitive_files_are_blocked(tmp_path, monkeypatch):
    pkg_path = ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_vectorscan_package", str(pkg_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    secrets_dir = ROOT / f"tmp_secret_{uuid.uuid4().hex}"
    secrets_dir.mkdir(exist_ok=True)
    secret_file = secrets_dir / ".env"
    secret_file.write_text("API_KEY=topsecret", encoding="utf-8")

    bundle_name = "vectorscan-free-secrets"
    monkeypatch.setattr(mod, "DIST", tmp_path)
    monkeypatch.setattr(mod, "FILES", list(mod.FILES) + [secret_file])  # type: ignore[attr-defined]
    monkeypatch.setattr(mod, "load_vectorscan_module", lambda: None)

    try:
        rc = mod.main(["--bundle-name", bundle_name])
        assert rc == 2
        assert not (tmp_path / f"{bundle_name}.zip").exists()
    finally:
        shutil.rmtree(secrets_dir, ignore_errors=True)
