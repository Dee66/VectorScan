import contextlib
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "run_scan.sh"
FIX = REPO_ROOT / "tests" / "fixtures"
GOLD = REPO_ROOT / "tests" / "golden"
AUDIT_ROOT = REPO_ROOT / "audit_logs"
DETERMINISTIC_ENV = {
    "VSCAN_CLOCK_EPOCH": "1704153600",  # 2024-01-02T00:00:00Z
    "VSCAN_FORCE_DURATION_MS": "123",
    "VSCAN_FORCE_PLAN_PARSE_MS": "123",
    "VSCAN_ENV_PLATFORM": "linux",
    "VSCAN_ENV_PLATFORM_RELEASE": "unit-kernel",
    "VSCAN_ENV_PYTHON_VERSION": "3.11.test",
    "VSCAN_ENV_PYTHON_IMPL": "CPython",
    "VSCAN_ENV_TERRAFORM_VERSION": "not-run",
    "VSCAN_ENV_TERRAFORM_SOURCE": "not-run",
    "VSCAN_ENV_VECTORSCAN_VERSION": "0.1.0",
}


def _deterministic_env() -> dict:
    env = os.environ.copy()
    env.update(DETERMINISTIC_ENV)
    return env


def _generate_ledger(subdir: str) -> Path:
    out_dir = AUDIT_ROOT / subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{uuid.uuid4().hex}.yaml"
    subprocess.run(
        [
            str(SCRIPT),
            "-i",
            str(FIX / "tfplan_iam_drift.json"),
            "-e",
            "tests",
            "-o",
            str(out_path.relative_to(REPO_ROOT)),
        ],
        check=True,
        cwd=REPO_ROOT,
        env=_deterministic_env(),
    )
    return out_path


def test_audit_ledger_generation_matches_template():
    out_path = _generate_ledger("pytest")
    try:
        generated = out_path.read_text(encoding="utf-8").strip()
    finally:
        with contextlib.suppress(FileNotFoundError):
            out_path.unlink()
        with contextlib.suppress(OSError):
            out_path.parent.rmdir()
    assert "VectorScan_Audit_Ledger:" in generated
    # Compare key sections presence
    for key in ("environment:", "timestamp:", "overall_score:", "audit_status:", "policy_errors:"):
        assert key in generated
    assert "environment_metadata:" in generated
    for env_key in (
        "    platform:",
        "    platform_release:",
        "    python_version:",
        "    python_implementation:",
        "    terraform_version:",
        "    terraform_source:",
        "    strict_mode:",
        "    offline_mode:",
    ):
        assert env_key in generated
    assert "violation_severity_summary:" in generated
    for level in ("critical", "high", "medium", "low"):
        assert f"    {level}:" in generated
    for plan_key in ("change_summary:", "resources_by_type:", "file_size_mb:", "exceeds_threshold:"):
        assert plan_key in generated
    assert "plan_slo:" in generated
    assert "file_size_limit_bytes:" in generated
    assert "scan_duration_ms:" in generated


def test_audit_ledger_rejects_outside_repo(tmp_path):
    out_path = tmp_path / "evil.yaml"
    result = subprocess.run(
        [
            str(SCRIPT),
            "-i",
            str(FIX / "tfplan_iam_drift.json"),
            "-e",
            "tests",
            "-o",
            str(out_path),
        ],
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode == 2
    assert "audit ledger output must stay under" in result.stderr


def test_audit_ledger_matches_golden_snapshot():
    out_path = _generate_ledger("pytest-golden")
    try:
        generated = out_path.read_text(encoding="utf-8").strip()
    finally:
        with contextlib.suppress(FileNotFoundError):
            out_path.unlink()
        with contextlib.suppress(OSError):
            out_path.parent.rmdir()

    expected = (GOLD / "audit_ledger.yaml").read_text(encoding="utf-8").strip()
    assert generated == expected


def test_audit_ledger_yaml_structure():
    out_path = _generate_ledger("pytest-structure")
    try:
        loaded = yaml.safe_load(out_path.read_text(encoding="utf-8"))
    finally:
        with contextlib.suppress(FileNotFoundError):
            out_path.unlink()
        with contextlib.suppress(OSError):
            out_path.parent.rmdir()

    assert isinstance(loaded, dict)
    root = loaded.get("VectorScan_Audit_Ledger")
    assert isinstance(root, dict)
    required_keys = {
        "timestamp",
        "environment",
        "environment_metadata",
        "plan_metadata",
        "policy_errors",
        "violation_severity_summary",
        "smell_report",
        "audit_status",
        "overall_score",
    }
    missing = required_keys - set(root)
    assert not missing, f"missing keys: {missing}"
    assert isinstance(root["environment_metadata"], dict)
    assert isinstance(root["plan_metadata"], dict)
    assert isinstance(root["policy_errors"], list)
    assert isinstance(root["violation_severity_summary"], dict)
    assert isinstance(root["smell_report"], dict)


def test_audit_ledger_smell_report_block():
    out_path = _generate_ledger("pytest-smells")
    try:
        ledger = yaml.safe_load(out_path.read_text(encoding="utf-8"))
    finally:
        with contextlib.suppress(FileNotFoundError):
            out_path.unlink()
        with contextlib.suppress(OSError):
            out_path.parent.rmdir()

    report = ledger["VectorScan_Audit_Ledger"].get("smell_report")
    assert isinstance(report, dict)
    assert {"level", "summary", "finding_count", "details"}.issubset(report)
    assert isinstance(report["summary"], str)
    assert isinstance(report["finding_count"], int)
    assert isinstance(report["details"], list)


def test_audit_ledger_creates_missing_subdirectories():
    subdir = AUDIT_ROOT / "pytest-auto" / uuid.uuid4().hex
    target = subdir / "ledger.yaml"
    if target.parent.exists():
        shutil.rmtree(target.parent)

    subprocess.run(
        [
            str(SCRIPT),
            "-i",
            str(FIX / "tfplan_iam_drift.json"),
            "-e",
            "tests",
            "-o",
            str(target.relative_to(REPO_ROOT)),
        ],
        check=True,
        cwd=REPO_ROOT,
        env=_deterministic_env(),
    )

    try:
        assert target.exists()
        assert target.parent.exists()
    finally:
        with contextlib.suppress(FileNotFoundError):
            target.unlink()
        with contextlib.suppress(OSError):
            shutil.rmtree(target.parent, ignore_errors=True)

