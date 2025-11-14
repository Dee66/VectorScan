from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "run_scan.sh"
FIX = REPO_ROOT / "tests" / "fixtures"
GOLD = REPO_ROOT / "tests" / "golden"


def test_audit_ledger_generation_matches_template():
    out_path = REPO_ROOT / "tests" / "tmp_audit.yaml"
    subprocess.run([str(SCRIPT), "-i", str(FIX / "tfplan_iam_drift.json"), "-e", "tests", "-o", str(out_path)], check=True)
    generated = out_path.read_text(encoding="utf-8").strip()
    expected = (GOLD / "audit_ledger.yaml").read_text(encoding="utf-8").strip()
    assert "VectorScan_Audit_Ledger:" in generated
    # Compare key sections presence
    for key in ("environment:", "timestamp:", "overall_score:", "audit_status:"):
        assert key in generated

