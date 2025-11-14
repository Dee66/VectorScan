import json
import time
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools" / "vectorscan" / "vectorscan.py"
PASS_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
FAIL_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-fail.json"


def run(cmd):
    start = time.perf_counter()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    elapsed = time.perf_counter() - start
    return p.returncode, p.stdout.strip(), p.stderr.strip(), elapsed


@pytest.mark.performance
def test_vectorscan_runtime_pass_fixture():
    code, out, err, elapsed = run([sys.executable, str(CLI), str(PASS_PLAN), "--json"])
    assert code == 0, f"unexpected exit code: {code}\nstderr={err}"
    data = json.loads(out)
    assert data["status"] == "PASS"
    # Soft budget: small fixture should complete quickly
    assert elapsed < 1.5, f"PASS fixture runtime too slow: {elapsed:.3f}s"


@pytest.mark.performance
def test_vectorscan_runtime_fail_fixture():
    code, out, err, elapsed = run([sys.executable, str(CLI), str(FAIL_PLAN), "--json"])
    assert code == 3, f"unexpected exit code: {code}\nstderr={err}"
    data = json.loads(out)
    assert data["status"] == "FAIL"
    # Soft budget: small fixture should complete quickly
    assert elapsed < 1.5, f"FAIL fixture runtime too slow: {elapsed:.3f}s"


@pytest.mark.performance
def test_vectorscan_scaling_large_plan(tmp_path):
    # Create a plan with many taggable resources (avoid encryption checks)
    resources = [
        {
            "type": "aws_s3_bucket",
            "name": f"b{i}",
            "values": {"tags": {"CostCenter": "C", "Project": "P"}},
        }
        for i in range(1000)
    ]
    plan = {"planned_values": {"root_module": {"resources": resources}}}
    p = tmp_path / "large-plan.json"
    p.write_text(json.dumps(plan))

    code, out, err, elapsed = run([sys.executable, str(CLI), str(p), "--json"])
    assert code == 0, f"unexpected exit code: {code}\nstderr={err}"
    data = json.loads(out)
    assert data["status"] == "PASS"
    # Soft budget for 1000 resources
    assert elapsed < 3.0, f"Large plan runtime too slow: {elapsed:.3f}s"
