"""Tests for the first production rule (P-VEC-001)."""

from src.vectorscan.evaluator import evaluate_plan


def test_public_access_rule_detects_issue():
    plan = {
        "resources": [
            {"type": "vector_index", "public_access": True, "address": "idx.main"}
        ],
        "resource_count": 1,
        "providers": ["aws"],
    }

    output = evaluate_plan(plan)
    issues = output["issues"]

    assert len(issues) == 1
    assert issues[0]["id"] == "P-VEC-001"
    assert issues[0]["severity"] == "critical"
    assert issues[0]["remediation_hint"] == "fixpack:P-VEC-001"
