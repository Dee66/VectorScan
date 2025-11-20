"""Phase 9 regression covering multiple rule firings."""

from src.vectorscan.evaluator import evaluate_plan


def test_multiple_rules_fire():
    plan = {
        "resources": [
            {
                "type": "vector_index",
                "public_access": True,
                "encryption_enabled": False,
                "allowed_cidrs": ["0.0.0.0/0"],
                "dimension": 8,
                "address": "idx.main",
            }
        ],
        "resource_count": 1,
        "providers": ["aws"],
    }

    output = evaluate_plan(plan)
    issues = {issue["id"] for issue in output["issues"]}

    assert issues == {
        "P-VEC-001",
        "P-VEC-002",
        "P-VEC-003",
        "P-VEC-004",
    }
