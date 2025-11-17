import os
import sys
import json
import io
import zipfile
import subprocess
import importlib.util
import re
from pathlib import Path

import pytest


# Ensure repository root and tools/vectorscan are importable
_ROOT = Path(__file__).resolve().parents[2]
_TOOLS_VSCAN = _ROOT / "tools" / "vectorscan"
for p in (str(_ROOT), str(_TOOLS_VSCAN)):
    if p not in sys.path:
        sys.path.insert(0, p)


def _read_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _run_cli_from_bundle(bundle_root: Path, plan: Path, base_env: dict[str, str]) -> dict:
    env = base_env.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = f"{bundle_root}{os.pathsep}{existing}" if existing else str(bundle_root)
    cmd = [sys.executable, "tools/vectorscan/vectorscan.py", str(plan), "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=bundle_root, env=env)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_end_to_end_happy_path(tmp_path, capsys):
    # Full flow: PASS plan -> PASS exit, optional local lead capture file is written
    import vectorscan

    plan = _ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"

    # Pre-count capture files
    captures_dir = _TOOLS_VSCAN / "captures"
    before = set(captures_dir.glob("lead_*.json")) if captures_dir.exists() else set()

    code = vectorscan.main([str(plan), "--lead-capture", "--email", "e2e@example.com"])  # type: ignore[arg-type]
    out = capsys.readouterr().out
    clean = _strip_ansi(out)

    # Asserts
    assert code == 0
    assert "PASS - tfplan.json - VectorScan checks" in clean

    # A new capture file should exist and contain our email
    after = set(captures_dir.glob("lead_*.json")) if captures_dir.exists() else set()
    new_files = list(after - before)
    assert new_files, "Expected a new local lead capture file to be written"
    payload = _read_json(new_files[-1])
    assert payload.get("email") == "e2e@example.com"
    assert payload.get("result", {}).get("status") == "PASS"


def test_end_to_end_unhappy_path(capsys):
    # Full flow: FAIL plan -> FAIL exit, violations include both policy codes
    import vectorscan

    plan = _ROOT / "examples" / "aws-pgvector-rag" / "tfplan-fail.json"
    code = vectorscan.main([str(plan)])  # type: ignore[arg-type]
    out = capsys.readouterr().out
    clean = _strip_ansi(out)

    assert code == 3
    assert "FAIL - tfplan.json - VectorScan checks" in clean
    assert "P-SEC-001" in clean  # encryption mandate
    assert "P-FIN-001" in clean  # mandatory tags


def test_end_to_end_partial_failure(monkeypatch, capsys):
    # Partial failure: PASS plan but remote POST fails; CLI still succeeds and prints POST result
    import vectorscan
    from urllib import error
    import urllib.request as ur

    plan = _ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"

    # Force urlopen to raise immediately (simulate endpoint outage) to keep test fast
    original = ur.urlopen
    def boom(*args, **kwargs):
        raise error.URLError("connection refused")
    ur.urlopen = boom  # type: ignore[assignment]

    try:
        os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"
        code = vectorscan.main([str(plan), "--lead-capture", "--email", "e2e2@example.com"])  # type: ignore[arg-type]
    finally:
        ur.urlopen = original
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    out = capsys.readouterr().out
    clean = _strip_ansi(out)
    assert code == 0
    assert "PASS - tfplan.json - VectorScan checks" in clean
    assert "Lead POST =>" in clean and "SKIP/FAIL" in clean


def test_end_to_end_unicode_output(monkeypatch, tmp_path, capsys):
    import vectorscan

    plan = tmp_path / "unicode-plan.json"
    plan.write_text(json.dumps({
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "db-🚀",
                        "values": {
                            "storage_encrypted": False,
                            "kms_key_id": None,
                            "tags": {"CostCenter": "研发", "Project": "测试"},
                        },
                    },
                    {
                        "type": "aws_db_instance",
                        "name": "db-pass",
                        "values": {
                            "storage_encrypted": True,
                            "kms_key_id": "🔐",
                            "tags": {"CostCenter": "研发", "Project": "测试"},
                        },
                    },
                ]
            }
        }
    }), encoding="utf-8")

    capsys.readouterr()
    code = vectorscan.main([str(plan), "--json"])  # type: ignore[arg-type]
    output = capsys.readouterr().out
    payload = json.loads(output)

    assert code == 3
    assert any("🚀" in v for v in payload["violations"])
    assert "🚀" in output

    # Human-readable output should also preserve Unicode/emoji
    capsys.readouterr()
    code_text = vectorscan.main([str(plan)])  # type: ignore[arg-type]
    human = capsys.readouterr().out
    human_clean = _strip_ansi(human)
    assert code_text == 3
    assert "db-🚀" in human_clean


def test_release_bundle_reproducibility(monkeypatch, tmp_path):
    # Build the free bundle twice under deterministic clocks, unzip, and ensure CLI outputs match
    spec = importlib.util.spec_from_file_location(
        "vectorscan_bundle_builder",
        (_ROOT / "tools" / "vectorscan" / "build_vectorscan_package.py"),
    )
    assert spec and spec.loader
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)  # type: ignore[attr-defined]

    epoch = 1_700_000_000
    monkeypatch.setenv("VSCAN_CLOCK_EPOCH", str(epoch))
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(epoch))

    bundle_name = "vectorscan-free-e2e"
    bundle_version = "9.9.9-test"

    monkeypatch.setattr(builder, "DIST", tmp_path)

    def _skip_terraform(*_args, **_kwargs):
        raise RuntimeError("skip terraform download for tests")

    monkeypatch.setattr(builder, "ensure_terraform_binary", _skip_terraform)

    args = ["--bundle-name", bundle_name, "--bundle-version", bundle_version]

    first_rc = builder.main(args)
    assert first_rc == 0
    zip_path = tmp_path / f"{bundle_name}.zip"
    manifest_path = tmp_path / f"{bundle_name}.manifest.json"
    sbom_path = tmp_path / f"{bundle_name}.sbom.json"
    first_zip = zip_path.read_bytes()
    first_manifest = manifest_path.read_bytes()
    first_sbom = sbom_path.read_bytes()

    second_rc = builder.main(args)
    assert second_rc == 0
    second_zip = zip_path.read_bytes()
    second_manifest = manifest_path.read_bytes()
    second_sbom = sbom_path.read_bytes()

    assert first_zip == second_zip
    assert first_manifest == second_manifest
    assert first_sbom == second_sbom

    extract_a = tmp_path / "bundle_a"
    extract_b = tmp_path / "bundle_b"
    extract_a.mkdir()
    extract_b.mkdir()

    for payload, target in ((first_zip, extract_a), (second_zip, extract_b)):
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            zf.extractall(target)

    plan = _ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
    env = os.environ.copy()
    env["VSCAN_CLOCK_EPOCH"] = str(epoch)
    env["SOURCE_DATE_EPOCH"] = str(epoch)

    result_a = _run_cli_from_bundle(extract_a, plan, env)
    result_b = _run_cli_from_bundle(extract_b, plan, env)

    assert result_a == result_b
    assert result_a["status"] == "PASS"
