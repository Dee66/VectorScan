"""Phase 8 scoring sanity tests."""

from src.vectorscan.evaluator import evaluate_plan


def test_scoring_totals():
    plan = {
        "resources": [
            {"type": "vector_index", "public_access": True, "address": "idx1"},
            {"type": "vector_index", "public_access": True, "address": "idx2"},
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
