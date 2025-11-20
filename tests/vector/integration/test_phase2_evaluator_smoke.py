"""Integration smoke test for the phase-2 evaluator wiring."""

from __future__ import annotations

import json
import sys
from importlib import import_module, util
from pathlib import Path
from typing import Any, Callable, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

legacy_module = sys.modules.get("vectorscan")
if legacy_module and getattr(legacy_module, "__file__", "").endswith("vectorscan.py"):
    sys.modules.pop("vectorscan", None)
    sys.modules.pop("vectorscan.constants", None)
    sys.modules.pop("vectorscan.evaluator", None)

package_init = SRC_PATH / "vectorscan" / "__init__.py"
if package_init.exists():
    spec = util.spec_from_file_location(
        "vectorscan",
        package_init,
        submodule_search_locations=[str(package_init.parent)],
    )
    if spec and spec.loader:
        module = util.module_from_spec(spec)
        sys.modules["vectorscan"] = module
        spec.loader.exec_module(module)

_constants = import_module("vectorscan.constants")
_evaluator = import_module("vectorscan.evaluator")
PILLAR_NAME: str = getattr(_constants, "PILLAR_NAME")
run_scan: Callable[..., Dict[str, Any]] = getattr(_evaluator, "run_scan")

FIXTURE_PATH = Path("tests/fixtures/minimal_plan.json")
SCHEMA_PATH = Path("schemas/guardsuite_pillar_schema.json")
ENCODING = "utf-8"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding=ENCODING))


def _validate_against_schema(payload: dict) -> None:
    schema = _load_json(SCHEMA_PATH)
    for key in schema.get("required", []):
        assert key in payload, f"Missing required field: {key}"

    severity_keys = schema.get("severity_keys", [])
    for key in severity_keys:
        assert key in payload["severity_totals"], f"Missing severity: {key}"
        assert key in payload["pillar_score_inputs"], f"Missing pillar score key: {key}"

    issue_fields = schema.get("issue_required_fields", [])
    for issue in payload.get("issues", []):
        for field in issue_fields:
            assert field in issue, f"Missing issue field: {field}"


def test_phase2_evaluator_smoke() -> None:
    plan_text = FIXTURE_PATH.read_text(encoding=ENCODING)
    plan = json.loads(plan_text)
    result = run_scan(
        plan=plan,
        source_path=FIXTURE_PATH,
        raw_size=len(plan_text.encode(ENCODING)),
    )

    _validate_against_schema(result)

    assert result["pillar"] == PILLAR_NAME
    assert result["issues"] == []
    assert result["environment"]["resource_count"] == plan["resource_count"]
    assert result["quick_score_mode"] is False
    assert all(value == 0 for value in result["pillar_score_inputs"].values())
