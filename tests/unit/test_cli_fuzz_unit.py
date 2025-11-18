"""Lightweight CLI fuzz tests to ensure no unhandled exceptions surface."""

from __future__ import annotations

import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools" / "vectorscan" / "vectorscan.py"
PASS_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
FAIL_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-fail.json"


def _random_plan() -> Path:
    return random.choice([PASS_PLAN, FAIL_PLAN])


def _random_flag_set(tmp_path: Path) -> list[str]:
    flags: list[str] = []
    if random.choice([True, False]):
        flags.append("--json")
    if random.choice([True, False]):
        flags.append("--explain")
    if random.choice([True, False]):
        flags.append("--diff")
    if random.choice([True, False]):
        flags.append("--gha")
    if random.choice([True, False]):
        flags.extend(["--lead-capture", "--email", "fuzz@example.com"])
    if random.choice([True, False]):
        flags.append("--allow-network")
    if random.choice([True, False]):
        flags.extend(["--iam-drift-penalty", str(random.randint(0, 100))])
    if random.choice([True, False]):
        flags.extend(["--resource", "aws_db_instance.db1"])
    if random.choice([True, False]):
        flags.append("--terraform-tests")
        if random.choice([True, False]):
            flags.append("--no-terraform-download")
    if random.choice([True, False]):
        tmp_plan = tmp_path / "invalid.json"
        tmp_plan.write_text("not json")
        return [str(tmp_plan)] + flags
    return [str(_random_plan())] + flags


@pytest.mark.parametrize("seed", range(25))
def test_cli_fuzz_no_crash(tmp_path, seed):
    random.seed(seed)
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(ROOT))
    env.setdefault("VSCAN_ALLOW_NETWORK", "0")
    env.setdefault("VSCAN_ALLOW_TERRAFORM_DOWNLOAD", "0")

    args = [sys.executable, str(CLI)] + _random_flag_set(tmp_path)
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert proc.returncode in {0, 2, 3, 4, 5, 6, 10}
    assert "Traceback" not in proc.stderr