"""Shared helpers for pillar tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
import json


def load_sample_plan(name: str) -> Dict[str, Any]:
    """Load sample plans from guardsuite-testdata when available."""
    root = Path(__file__).resolve().parents[3] / "guardsuite-testdata" / "plans"
    plan_path = root / f"{name}.json"
    if not plan_path.exists():
        raise FileNotFoundError(f"Sample plan not found: {plan_path}")
    return json.loads(plan_path.read_text())
