"""Phase 8 scoring sanity tests."""

from src.vectorscan.evaluator import evaluate_plan


def test_scoring_totals():
    plan = {
        "resources": [
            {
                "type": "vector_index",
                "public_access": True,
                "encryption_enabled": True,
                "allowed_cidrs": ["10.0.0.0/8"],
                "dimension": 64,
                "address": "idx1",
            },
            {
                "type": "vector_index",
                "public_access": True,
                "encryption_enabled": True,
                "allowed_cidrs": ["10.0.0.0/8"],
                "dimension": 64,
                "address": "idx2",
            },
        ],
        "resource_count": 2,
        "providers": ["aws"],
    }

    output = evaluate_plan(plan)
    scores = output["pillar_score_inputs"]

    assert scores["critical"] == 2
    assert scores["high"] == 0
    assert scores["medium"] == 0
    assert scores["low"] == 0
