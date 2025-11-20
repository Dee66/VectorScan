from pillar.engine.evaluator import PillarEvaluator
from pillar.engine.loader import PlanLoader


def test_evaluator_returns_canonical_structure():
    loader = PlanLoader()
    evaluator = PillarEvaluator(loader)
    result = evaluator.evaluate(path=None, stdin_payload={})
    assert result["pillar"] == "PILLAR_NAME_REPLACE_ME"
    assert "issues" in result
    assert isinstance(result["issues"], list)
