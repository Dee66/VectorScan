import json
from pathlib import Path

from pillar.engine.evaluator import PillarEvaluator
from pillar.engine.loader import PlanLoader

SCHEMA_PATH = Path("schemas/guardsuite_pillar_schema.json")


def test_schema_keys_exist():
    loader = PlanLoader()
    evaluator = PillarEvaluator(loader)
    result = evaluator.evaluate(path=None, stdin_payload={})
    schema = json.loads(SCHEMA_PATH.read_text())
    for key in schema.keys():
        assert key in result
