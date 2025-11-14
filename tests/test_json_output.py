import json
from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "tools" / "vectorscan" / "vectorscan.py"
FIX = REPO_ROOT / "tests" / "fixtures"
GOLD = REPO_ROOT / "tests" / "golden"


def run_json(plan: Path):
    return subprocess.run(["python3", str(CLI), str(plan), "--json"], capture_output=True, text=True)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_pass_matches_golden():
    res = run_json(FIX / "tfplan_pass.json")
    assert res.returncode == 0
    got = json.loads(res.stdout)
    exp = _load(GOLD / "pass_output.json")
    # Compare stable top-level keys
    for key in ("status", "counts", "checks", "metrics"):
        assert got[key] == exp[key]


def test_fail_matches_golden():
    res = run_json(FIX / "tfplan_fail.json")
    assert res.returncode == 3
    got = json.loads(res.stdout)
    exp = _load(GOLD / "fail_output.json")
    assert got["status"] == exp["status"]
    assert got["counts"] == exp["counts"]
    # Violations list should start with same policy IDs
    assert [v.split(":")[0] for v in got["violations"]] == [v.split(":")[0] for v in exp["violations"]]


def test_iam_drift_matches_golden_and_penalty():
    res = run_json(FIX / "tfplan_iam_drift.json")
    assert res.returncode == 0
    got = json.loads(res.stdout)
    exp = _load(GOLD / "iam_drift_output.json")
    assert got["iam_drift_report"]["status"] == "FAIL"
    assert got["iam_drift_report"]["counts"]["risky_changes"] == 1
    # Penalty applied to compliance_score (default 20)
    assert got["metrics"]["compliance_score"] == exp["metrics"]["compliance_score"]
