import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "tools" / "vectorscan" / "vectorscan.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures"


def run_cli(plan_path: Path):
    return subprocess.run(["python3", str(CLI), str(plan_path), "--json"], capture_output=True, text=True)


def test_cli_exit_codes_pass_fail():
    # PASS plan -> exit code 0
    res_pass = run_cli(FIXTURES / "tfplan_pass.json")
    assert res_pass.returncode == 0, res_pass.stderr
    assert json.loads(res_pass.stdout)["status"] == "PASS"

    # FAIL plan -> exit code 3
    res_fail = run_cli(FIXTURES / "tfplan_fail.json")
    assert res_fail.returncode == 3, res_fail.stdout + "\n" + res_fail.stderr
    payload = json.loads(res_fail.stdout)
    assert payload["status"] == "FAIL"
    assert isinstance(payload.get("violations"), list)


def test_cli_invalid_json_exit_code():
    res_bad = run_cli(FIXTURES / "tfplan_invalid.json")
    assert res_bad.returncode == 2, res_bad.stdout + "\n" + res_bad.stderr
