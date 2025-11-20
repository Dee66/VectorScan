"""Rule registry smoke tests for the VectorScan evaluator."""

from __future__ import annotations

import json
from pathlib import Path

from vectorscan.evaluator import run_scan  # pyright: ignore[reportMissingImports]
from vectorscan.rules import get_all_rules  # pyright: ignore[reportMissingImports]

FIXTURE_PATH = Path("tests/fixtures/minimal_plan.json")
ENCODING = "utf-8"


def _load_plan() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding=ENCODING))


def test_placeholder_rule_is_registered() -> None:
    rules = get_all_rules()
    assert any(rule.id == "P-VEC-000" for rule in rules)


def test_evaluator_runs_rules_without_issues() -> None:
    plan = _load_plan()
    result = run_scan(plan=plan)
    assert result["issues"] == []
