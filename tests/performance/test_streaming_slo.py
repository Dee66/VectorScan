import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools/vectorscan/vectorscan.py"


def _make_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH")
    segments = [str(ROOT)]
    if pythonpath:
        segments.append(pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(segments)
    env.setdefault("VSCAN_CLOCK_EPOCH", "1700000000")
    env.setdefault("VSCAN_CLOCK_ISO", "2024-01-02T00:00:00Z")
    env.setdefault("VSCAN_ENV_PLATFORM", "linux")
    env.setdefault("VSCAN_ENV_PLATFORM_RELEASE", "perf-kernel")
    env.setdefault("VSCAN_ENV_PYTHON_VERSION", "3.11.perf")
    env.setdefault("VSCAN_ENV_PYTHON_IMPL", "CPython")
    env.setdefault("VSCAN_ENV_TERRAFORM_VERSION", "not-run")
    env.setdefault("VSCAN_ENV_TERRAFORM_SOURCE", "not-run")
    env.setdefault("VSCAN_FORCE_DURATION_MS", "123")
    if overrides:
        env.update(overrides)
    return env


def _run_cli(
    plan_path: Path, *, env_overrides: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    cmd = ["python3", str(CLI), str(plan_path), "--json"]
    env = _make_env(env_overrides)
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, check=False)


def _generate_plan(tmp_path: Path, resource_count: int) -> Path:
    resources = [
        {
            "address": f"aws_db_instance.perf[{idx}]",
            "mode": "managed",
            "type": "aws_db_instance",
            "name": f"perf_{idx}",
            "values": {
                "storage_encrypted": True,
                "kms_key_id": "kms",
                "tags": {"CostCenter": "perf", "Project": "perf"},
            },
        }
        for idx in range(resource_count)
    ]
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
    path = tmp_path / f"plan-{resource_count}.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(plan, fh, separators=(",", ":"))
    return path


@pytest.mark.performance
@pytest.mark.parametrize(
    "resource_count,forced_duration,expected_window,expect_exceeds,expected_reason",
    [
        (800, 150, "fast_path", False, None),
        (5000, 2500, "large_plan", True, "parse_duration"),
        (11000, 1500, "oversized", True, "resource_count"),
    ],
)
def test_streaming_plan_slo_windows(
    tmp_path, resource_count, forced_duration, expected_window, expect_exceeds, expected_reason
):
    plan_path = _generate_plan(tmp_path, resource_count)
    env_overrides = {
        "VSCAN_FORCE_PLAN_PARSE_MS": str(forced_duration),
    }
    result = _run_cli(plan_path, env_overrides=env_overrides)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    metadata = payload.get("plan_metadata") or {}

    assert metadata.get("resource_count") == resource_count
    assert metadata.get("parse_duration_ms") == forced_duration
    assert metadata.get("exceeds_threshold") is expect_exceeds

    plan_slo = metadata.get("plan_slo") or {}
    assert plan_slo.get("active_window") == expected_window
    assert plan_slo.get("breach_reason") == expected_reason
    observed = plan_slo.get("observed") or {}
    assert observed.get("resource_count") == resource_count
    assert observed.get("parse_duration_ms") == forced_duration
