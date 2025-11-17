import json
import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "tools" / "vectorscan" / "vectorscan.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures"


def _run_cli(args: list[str], *, env: dict[str, str] | None = None):
    base_env = os.environ.copy()
    existing = base_env.get("PYTHONPATH")
    parts = [str(REPO_ROOT)]
    if existing:
        parts.append(existing)
    base_env["PYTHONPATH"] = os.pathsep.join(parts)
    if env:
        base_env.update(env)
    cmd = ["python3", str(CLI), *args]
    return subprocess.run(cmd, capture_output=True, text=True, env=base_env)


def run_cli(plan_path: Path):
    return _run_cli([str(plan_path), "--json"])


def test_cli_exit_codes_pass_fail():
    # PASS plan -> exit code 0
    res_pass = run_cli(FIXTURES / "tfplan_pass.json")
    assert res_pass.returncode == 0, res_pass.stderr
    pass_payload = json.loads(res_pass.stdout)
    assert pass_payload["status"] == "PASS"
    summary = pass_payload.get("violation_severity_summary")
    assert summary == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert isinstance(pass_payload["metrics"].get("scan_duration_ms"), int)
    assert pass_payload["metrics"]["scan_duration_ms"] >= 0

    # FAIL plan -> exit code 3
    res_fail = run_cli(FIXTURES / "tfplan_fail.json")
    assert res_fail.returncode == 3, res_fail.stdout + "\n" + res_fail.stderr
    payload = json.loads(res_fail.stdout)
    assert payload["status"] == "FAIL"
    assert isinstance(payload.get("violations"), list)
    fail_summary = payload.get("violation_severity_summary")
    assert fail_summary == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert isinstance(payload["metrics"].get("scan_duration_ms"), int)
    assert payload["metrics"]["scan_duration_ms"] >= 0


def test_cli_invalid_json_exit_code():
    res_bad = run_cli(FIXTURES / "tfplan_invalid.json")
    assert res_bad.returncode == 2, res_bad.stdout + "\n" + res_bad.stderr


def test_cli_color_output_forced_and_disabled():
    plan = FIXTURES / "tfplan_pass.json"
    env = {"VSCAN_FORCE_COLOR": "1"}

    colored = _run_cli([str(plan)], env=env)
    assert colored.returncode == 0, colored.stderr
    assert "\x1b[" in colored.stdout

    no_color = _run_cli([str(plan), "--no-color"], env=env)
    assert no_color.returncode == 0, no_color.stderr
    assert "\x1b[" not in no_color.stdout


def test_cli_includes_policy_pack_hash():
    res = run_cli(FIXTURES / "tfplan_pass.json")
    assert res.returncode == 0, res.stderr
    payload = json.loads(res.stdout)
    hash_value = payload.get("policy_pack_hash")
    assert isinstance(hash_value, str)
    assert len(hash_value) == 64
