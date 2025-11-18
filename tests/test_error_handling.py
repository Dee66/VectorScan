import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "tools" / "vectorscan" / "vectorscan.py"


def test_missing_file_exit_code():
    res = subprocess.run(
        ["python3", str(CLI), "tests/fixtures/not_exists.json", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 2
    assert "file not found" in res.stderr.lower()


def test_invalid_json_exit_code():
    res = subprocess.run(
        ["python3", str(CLI), "tests/fixtures/tfplan_invalid.json", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 2
    assert "invalid json" in res.stderr.lower()


def test_policy_pack_missing_exit_code(tmp_path):
    missing = tmp_path / "ghost.rego"
    env = os.environ.copy()
    env.pop("VSCAN_POLICY_PACK_HASH", None)
    env["VSCAN_POLICY_PACK_FILES"] = str(missing)
    existing_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(REPO_ROOT), existing_path]))

    res = subprocess.run(
        ["python3", str(CLI), "tests/fixtures/tfplan_fail.json", "--json"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert res.returncode == 4
    assert "policy pack load error" in res.stderr.lower()
