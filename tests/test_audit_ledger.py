import contextlib
from pathlib import Path
import subprocess
import uuid

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "run_scan.sh"
FIX = REPO_ROOT / "tests" / "fixtures"
GOLD = REPO_ROOT / "tests" / "golden"
AUDIT_ROOT = REPO_ROOT / "audit_logs"


def test_audit_ledger_generation_matches_template():
    out_dir = AUDIT_ROOT / "pytest"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{uuid.uuid4().hex}.yaml"
    try:
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
        )
        generated = out_path.read_text(encoding="utf-8").strip()
    finally:
        with contextlib.suppress(FileNotFoundError):
            out_path.unlink()
        with contextlib.suppress(OSError):
            out_dir.rmdir()
    expected = (GOLD / "audit_ledger.yaml").read_text(encoding="utf-8").strip()
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
    )
    assert result.returncode == 2
    assert "audit ledger output must stay under" in result.stderr

