import contextlib
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from tests import test_json_output as json_helpers

REPO_ROOT = json_helpers.REPO_ROOT
CLI = json_helpers.CLI
FIX = json_helpers.FIX
GOLD = json_helpers.GOLD
ENV = json_helpers.ENV.copy()
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

LEDGER_ENV = ENV.copy()
LEDGER_ENV.update(
    {
        "VSCAN_CLOCK_EPOCH": "1700000000",
        "VSCAN_CLOCK_ISO": "2024-01-02T00:00:00Z",
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
)


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _run_human(plan: Path, extra_args: list[str] | None = None):
    plan = Path(plan)
    if plan.is_absolute():
        try:
            plan = plan.relative_to(REPO_ROOT)
        except ValueError:
            pass
    cmd = ["python3", str(CLI), plan.as_posix()]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=ENV,
        check=False,
    )


def _assert_json_matches(
    plan_name: str, golden_name: str, expected_code: int, extra_args: list[str] | None = None
) -> dict:
    result = json_helpers.run_json(FIX / plan_name, extra_args=extra_args)
    assert result.returncode == expected_code, result.stderr
    payload = json_helpers._normalize(json.loads(result.stdout))
    expected = json_helpers._normalize(json_helpers._load(GOLD / golden_name))
    assert payload == expected
    return payload


def test_scenario_a_pass_end_to_end():
    human = _run_human(FIX / "tfplan_pass.json")
    clean = _strip_ansi(human.stdout)

    assert human.returncode == 0, human.stderr
    assert "PASS - tfplan.json - VectorScan checks" in clean

    _assert_json_matches("tfplan_pass.json", "pass_output.json", expected_code=0)


def test_scenario_b_fail_end_to_end():
    human = _run_human(FIX / "tfplan_fail.json")
    clean = _strip_ansi(human.stdout)

    assert human.returncode == 3, human.stdout + human.stderr
    assert "FAIL - tfplan.json - VectorScan checks" in clean
    assert "P-SEC-001" in clean and "P-FIN-001" in clean

    _assert_json_matches("tfplan_fail.json", "fail_output.json", expected_code=3)


def test_scenario_c_drift_penalty_flag():
    baseline = json_helpers.run_json(FIX / "tfplan_iam_drift.json")
    penalized = json_helpers.run_json(
        FIX / "tfplan_iam_drift.json",
        extra_args=["--iam-drift-penalty", "40"],
    )

    assert baseline.returncode == 0, baseline.stderr
    assert penalized.returncode == 0, penalized.stderr

    base_payload = json.loads(baseline.stdout)
    penalized_payload = json.loads(penalized.stdout)

    assert base_payload["iam_drift_report"]["status"] == "FAIL"
    base_score = base_payload["metrics"]["compliance_score"]
    penalized_score = penalized_payload["metrics"]["compliance_score"]

    assert base_score == 80  # default penalty already applied
    assert penalized_score == 60


def test_scenario_d_audit_ledger_matches_golden():
    output_rel = Path("audit_logs") / "scenario-ledgers" / f"ledger_{uuid.uuid4().hex}.yaml"
    result = subprocess.run(
        [
            str(REPO_ROOT / "run_scan.sh"),
            "-i",
            str((FIX / "tfplan_iam_drift.json").as_posix()),
            "-e",
            "tests",
            "-o",
            output_rel.as_posix(),
        ],
        cwd=REPO_ROOT,
        env=LEDGER_ENV,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    output_path = REPO_ROOT / output_rel
    try:
        generated = output_path.read_text(encoding="utf-8").strip()
    finally:
        with contextlib.suppress(FileNotFoundError):
            output_path.unlink()
        with contextlib.suppress(OSError):
            output_path.parent.rmdir()

    expected = (GOLD / "audit_ledger.yaml").read_text(encoding="utf-8").strip()
    assert generated == expected
