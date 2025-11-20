from vectorscan.engine.evaluator import PillarEvaluator
from vectorscan.engine.loader import PlanLoader


def test_evaluator_returns_canonical_structure():
    loader = PlanLoader()
    evaluator = PillarEvaluator(loader)
    result = evaluator.evaluate(path=None, stdin_payload={})
    assert result["pillar"] == "vectorscan"
    assert "issues" in result
    assert isinstance(result["issues"], list)
