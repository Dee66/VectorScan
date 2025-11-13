import json
import sys
import subprocess
from pathlib import Path

import pytest


def make_plan(tmp_path: Path, resources) -> Path:
    plan = {"planned_values": {"root_module": {"resources": resources}}}
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(plan))
    return p


def run_cli(plan_path: Path, extra_args=None):
    args = [sys.executable, "tools/vectorscan/vectorscan.py", str(plan_path)]
    if extra_args:
        args.extend(extra_args)
    return subprocess.run(args, capture_output=True)


def test_cli_with_security_policy(tmp_path):
    # Unencrypted DB instance should FAIL with P-SEC-001
    resources = [
        {"type": "aws_db_instance", "name": "db1", "values": {"storage_encrypted": False, "kms_key_id": None}},
    ]
    plan_path = make_plan(tmp_path, resources)
    result = run_cli(plan_path)
    assert result.returncode == 3
    assert b"P-SEC-001" in result.stdout


def test_cli_with_finops_policy(tmp_path):
    # Missing mandatory tags should trigger P-FIN-001
    resources = [
        {"type": "aws_db_instance", "name": "db2", "values": {"storage_encrypted": True, "tags": {}}},
    ]
    plan_path = make_plan(tmp_path, resources)
    result = run_cli(plan_path)
    assert result.returncode == 3
    assert b"P-FIN-001" in result.stdout


def test_cli_with_audit_policy(tmp_path):
    # No resources should PASS
    plan_path = make_plan(tmp_path, [])
    result = run_cli(plan_path)
    assert result.returncode == 0
    assert b"PASS" in result.stdout


def test_cli_with_multiple_policies(tmp_path):
    # Both encryption and tags violations should be aggregated
    resources = [
        {"type": "aws_db_instance", "name": "db1", "values": {"storage_encrypted": False, "kms_key_id": None, "tags": {}}},
    ]
    plan_path = make_plan(tmp_path, resources)
    result = run_cli(plan_path)
    assert result.returncode == 3
    out = result.stdout
    assert b"P-SEC-001" in out
    assert b"P-FIN-001" in out
