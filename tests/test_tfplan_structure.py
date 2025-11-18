import json
import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "tools" / "vectorscan" / "vectorscan.py"


def _run_plan(tmp_path, payload):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(payload))
    env = os.environ.copy()
    existing_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [existing_path, str(REPO_ROOT)]))
    return subprocess.run(
        ["python3", str(CLI), str(plan), "--json"],
        capture_output=True,
        text=True,
        env=env,
    )


def test_cli_handles_missing_planned_values(tmp_path):
    res = _run_plan(tmp_path, {"format_version": "1.0"})
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["counts"]["violations"] == 0


def test_cli_handles_missing_root_module(tmp_path):
    payload = {"planned_values": {"root_module": {}}}
    res = _run_plan(tmp_path, payload)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["status"] == "PASS"


def test_cli_handles_empty_child_modules(tmp_path):
    payload = {
        "planned_values": {
            "root_module": {
                "resources": [{"type": "aws_db_instance", "values": {"storage_encrypted": True}}],
                "child_modules": None,
            }
        }
    }
    res = _run_plan(tmp_path, payload)
    assert res.returncode == 3
    data = json.loads(res.stdout)
    assert data["status"] == "FAIL"
