"""Shared helpers for VectorScan tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
import json


TESTDATA_ROOT = Path(__file__).resolve().parents[3] / "guardsuite-testdata" / "plans"


def load_sample_plan(name: str) -> Dict[str, Any]:
    plan_path = TESTDATA_ROOT / f"{name}.json"
    if not plan_path.exists():
        raise FileNotFoundError(f"Sample plan not found: {plan_path}")
    return json.loads(plan_path.read_text())
