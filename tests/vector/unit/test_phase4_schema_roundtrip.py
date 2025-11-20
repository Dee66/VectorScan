"""Schema validation smoke test for the canonical evaluator output."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema  # pyright: ignore[reportMissingImports]

from vectorscan.evaluator import run_scan  # pyright: ignore[reportMissingImports]

FIXTURE_PATH = Path("tests/fixtures/minimal_plan.json")
SCHEMA_PATH = Path("schemas/guardsuite_pillar_schema.json")
ENCODING = "utf-8"


def _load_json(path: Path) -> dict:
	return json.loads(path.read_text(encoding=ENCODING))


def test_phase4_schema_roundtrip() -> None:
	plan = _load_json(FIXTURE_PATH)
	result = run_scan(plan=plan)

	schema_doc = _load_json(SCHEMA_PATH)
	dynamic_schema = {
		"type": "object",
		"required": schema_doc.get("required", []),
		"properties": {key: {} for key in schema_doc.get("required", [])},
	}

	jsonschema.validate(result, dynamic_schema)
	assert "schema_validation_error" in result
	assert result["schema_validation_error"] is None
