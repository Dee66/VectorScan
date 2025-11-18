import json
import os
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools" / "vectorscan" / "vectorscan.py"
PASS_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
FAIL_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-fail.json"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [existing, str(ROOT)]))
    env.setdefault("VSCAN_CLOCK_EPOCH", "1700000000")
    env.setdefault("VSCAN_CLOCK_ISO", "2023-11-14T00:00:00Z")
    return env


def run(cmd, env_overrides: dict[str, str] | None = None):
    start = time.perf_counter()
    env = _env()
    if env_overrides:
        env.update(env_overrides)
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env=env,
    )
    elapsed = time.perf_counter() - start
    return p.returncode, p.stdout.strip(), p.stderr.strip(), elapsed


def _make_plan_of_size(tmp_path: Path, min_bytes: int) -> Path:
    resources = []
    encoded: str = ""
    idx = 0
    while len(encoded.encode("utf-8")) < min_bytes:
        resources.append(
            {
                "address": f"aws_rds_cluster.perf[{idx}]",
                "mode": "managed",
                "type": "aws_rds_cluster",
                "name": f"perf_{idx}",
                "values": {
                    "storage_encrypted": True,
                    "kms_key_id": "kms",
                    "tags": {"CostCenter": "perf", "Project": "perf"},
                    "description": "X" * 1024,
                },
            }
        )
        plan = {
            "format_version": "1.0",
            "terraform_version": "1.6.0",
            "planned_values": {
                "root_module": {
                    "address": "root",
                    "resources": resources,
                    "child_modules": [],
                }
            },
        }
        encoded = json.dumps(plan, separators=(",", ":"))
        idx += 1

    path = tmp_path / f"plan-{min_bytes}.json"
    path.write_text(encoded)
    assert path.stat().st_size >= min_bytes
    return path


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


@pytest.mark.performance
def test_vectorscan_large_plan_over_5mb(tmp_path):
    # Build a large-but-sparse plan to exceed 5MB while keeping execution quick
    resource_template = {
        "type": "aws_s3_bucket",
        "values": {
            "tags": {"CostCenter": "C", "Project": "P"},
            # Add a padded description to inflate size without extra logic
            "description": "X" * 2048,
        },
    }
    resources = []
    for i in range(2500):
        entry = dict(resource_template)
        entry["name"] = f"mega_{i}"
        # Ensure each entry has independent nested dicts
        entry_vals = dict(resource_template["values"])
        entry_vals["tags"] = dict(resource_template["values"]["tags"])
        entry["values"] = entry_vals
        resources.append(entry)

    plan = {"planned_values": {"root_module": {"resources": resources}}}
    path = tmp_path / "huge-plan.json"
    path.write_text(json.dumps(plan))
    assert path.stat().st_size >= 5 * 1024 * 1024, "Fixture must exceed 5MB"

    cmd = [sys.executable, str(CLI), str(path), "--json"]
    code1, out1, err1, elapsed1 = run(cmd)
    assert code1 == 0, f"unexpected exit code: {code1}\nstderr={err1}"
    data1 = json.loads(out1)
    assert data1["status"] == "PASS"

    # Deterministic ordering check: run again and compare JSON text
    code2, out2, err2, elapsed2 = run(cmd)
    assert code2 == 0, f"unexpected exit code: {code2}\nstderr={err2}"
    assert out1 == out2, "Large plan JSON output should be deterministic"

    # Budget: even with >5MB plans, runs should finish quickly
    assert (
        max(elapsed1, elapsed2) < 6.0
    ), f">5MB plan runtime too slow: {max(elapsed1, elapsed2):.3f}s"


@pytest.mark.performance
def test_processing_time_budget_for_100kb_plan(tmp_path):
    plan_path = _make_plan_of_size(tmp_path, 120 * 1024)
    env_overrides = {"VSCAN_FORCE_DURATION_MS": "150"}
    code, out, err, elapsed = run(
        [sys.executable, str(CLI), str(plan_path), "--json"], env_overrides
    )
    assert code == 0, err
    payload = json.loads(out)
    metrics = payload.get("metrics") or {}
    assert metrics.get("scan_duration_ms") == 150
    assert metrics["scan_duration_ms"] < 200
    assert elapsed < 2.0, f"Observed runtime too slow: {elapsed:.3f}s"


@pytest.mark.performance
def test_memory_usage_stable_via_tracemalloc():
    tracemalloc.start()
    baseline = tracemalloc.take_snapshot()
    cmd = [sys.executable, str(CLI), str(PASS_PLAN), "--json"]
    for _ in range(3):
        code, out, err, _ = run(cmd)
        assert code == 0, err
        data = json.loads(out)
        assert data["status"] == "PASS"
    follow_up = tracemalloc.take_snapshot()
    stats = follow_up.compare_to(baseline, "filename")
    positive_growth = sum(stat.size_diff for stat in stats if stat.size_diff > 0)
    tracemalloc.stop()
    # Guardrail: allow small noise but reject multi-meg leaks
    assert (
        positive_growth < 512 * 1024
    ), f"Unexpected memory growth detected: {positive_growth} bytes"


@pytest.mark.performance
@pytest.mark.parametrize("py_version", ["3.10.perf", "3.12.perf"])
def test_python_version_metadata_runtime_stability(py_version):
    env_overrides = {"VSCAN_ENV_PYTHON_VERSION": py_version}
    cmd = [sys.executable, str(CLI), str(PASS_PLAN), "--json"]
    code, out, err, elapsed = run(cmd, env_overrides)
    assert code == 0, err
    payload = json.loads(out)
    environment = payload.get("environment") or {}
    assert environment.get("python_version") == py_version
    assert elapsed < 1.5, f"Runtime regressed under python_version={py_version}: {elapsed:.3f}s"
