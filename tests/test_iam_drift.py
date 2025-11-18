import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "tools" / "vectorscan" / "vectorscan.py"
FIX = REPO_ROOT / "tests" / "fixtures"


def test_iam_drift_report_structure():
    res = subprocess.run(
        ["python3", str(CLI), str(FIX / "tfplan_iam_drift.json"), "--json"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    payload = json.loads(res.stdout)
    report = payload["iam_drift_report"]
    assert report["status"] in {"PASS", "FAIL"}
    assert isinstance(report["items"], list)
    if report["status"] == "FAIL":
        assert report["counts"]["risky_changes"] >= 1
        assert any("risky_additions" in item for item in report["items"])
