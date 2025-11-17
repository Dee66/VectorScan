import json
import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = Path("tools") / "vectorscan" / "vectorscan.py"
FIX = Path("tests") / "fixtures"
GOLD = Path("tests") / "golden"

ENV = os.environ.copy()
env_pythonpath = ENV.get("PYTHONPATH")
env_segments = [str(REPO_ROOT)]
if env_pythonpath:
    env_segments.append(env_pythonpath)
ENV["PYTHONPATH"] = os.pathsep.join(env_segments)
ENV["VSCAN_CLOCK_EPOCH"] = "1700000000"
ENV["VSCAN_CLOCK_ISO"] = "2024-01-02T00:00:00Z"
ENV["VSCAN_FORCE_DURATION_MS"] = "123"
ENV["VSCAN_FORCE_PLAN_PARSE_MS"] = "123"
ENV["VSCAN_ENV_PLATFORM"] = "linux"
ENV["VSCAN_ENV_PLATFORM_RELEASE"] = "unit-kernel"
ENV["VSCAN_ENV_PYTHON_VERSION"] = "3.11.test"
ENV["VSCAN_ENV_PYTHON_IMPL"] = "CPython"
ENV["VSCAN_ENV_TERRAFORM_VERSION"] = "not-run"
ENV["VSCAN_ENV_TERRAFORM_SOURCE"] = "not-run"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _relativize(path_value: str) -> str:
    candidate = Path(path_value)
    if candidate.is_absolute():
        try:
            return str(candidate.resolve().relative_to(REPO_ROOT))
        except ValueError:
            return candidate.as_posix()
    return candidate.as_posix()


def _normalize(payload: dict) -> dict:
    clone = json.loads(json.dumps(payload))
    if "file" in clone:
        clone["file"] = _relativize(clone["file"])
    return clone


def run_json(plan: Path, *, extra_args: list[str] | None = None):
    plan = Path(plan)
    if plan.is_absolute():
        try:
            plan = plan.relative_to(REPO_ROOT)
        except ValueError:
            pass
    cmd = ["python3", str(CLI), plan.as_posix(), "--json"]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=ENV,
    )


def _assert_matches(plan_name: str, golden_name: str, expected_code: int, extra_args: list[str] | None = None) -> dict:
    res = run_json(FIX / plan_name, extra_args=extra_args)
    assert res.returncode == expected_code, res.stderr
    got = _normalize(json.loads(res.stdout))
    exp = _normalize(_load(GOLD / golden_name))
    assert got == exp
    return got


def _assert_matches_explain(plan_name: str, golden_name: str, expected_code: int) -> dict:
    res = run_json(FIX / plan_name, extra_args=["--explain"])
    assert res.returncode == expected_code, res.stderr
    got = _normalize(json.loads(res.stdout))
    exp = _normalize(_load(GOLD / golden_name))
    assert got == exp
    return got


def test_pass_matches_golden():
    _assert_matches("tfplan_pass.json", "pass_output.json", expected_code=0)


def test_fail_matches_golden():
    _assert_matches("tfplan_fail.json", "fail_output.json", expected_code=3)


def test_iam_drift_matches_golden_and_penalty():
    got = _assert_matches("tfplan_iam_drift.json", "iam_drift_output.json", expected_code=0)
    assert got["iam_drift_report"]["status"] == "FAIL"
    assert got["iam_drift_report"]["counts"]["risky_changes"] == 1
    # Penalty applied to compliance_score (default 20) and captured in golden snapshot
    assert got["metrics"]["compliance_score"] == 80


def test_explain_mode_snapshots():
    _assert_matches_explain("tfplan_pass.json", "pass_explain_output.json", expected_code=0)
    _assert_matches_explain("tfplan_fail.json", "fail_explain_output.json", expected_code=3)
    explain = _assert_matches_explain("tfplan_iam_drift.json", "iam_drift_explain_output.json", expected_code=0)
    assert "explanation" in explain
    assert explain["explanation"]["iam_drift"]["status"] == "FAIL"


def test_diff_mode_snapshots():
    diff_pass = _assert_matches(
        "tfplan_pass.json",
        "pass_diff_output.json",
        expected_code=0,
        extra_args=["--diff"],
    )
    assert "plan_diff" in diff_pass
    _assert_matches(
        "tfplan_fail.json",
        "fail_diff_output.json",
        expected_code=3,
        extra_args=["--diff"],
    )
    diff_iam = _assert_matches(
        "tfplan_iam_drift.json",
        "iam_drift_diff_output.json",
        expected_code=0,
        extra_args=["--diff"],
    )
    assert diff_iam["plan_diff"]["summary"]["adds"] >= 0
