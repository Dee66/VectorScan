import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from tools.vectorscan.plan_stream import (
    FAST_PATH_RESOURCES,
    LARGE_PLAN_RESOURCES,
    PlanSchemaError,
    build_slo_metadata,
    stream_plan,
)


def _write_plan(tmp_path, payload):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload))
    return path


def test_stream_plan_collects_resources_and_stats(tmp_path):
    plan = {
        "format_version": "1.0",
        "terraform_version": "1.6.0",
        "planned_values": {
            "root_module": {
                "address": "root",
                "resources": [
                    {"type": "aws_db_instance", "name": "db", "values": {"storage_encrypted": True}}
                ],
                "child_modules": [
                    {
                        "address": "module.child",
                        "resources": [
                            {"type": "aws_s3_bucket", "name": "bucket", "values": {"tags": {}}}
                        ],
                        "child_modules": [],
                    }
                ],
            }
        },
        "resource_changes": [
            {
                "address": "aws_db_instance.db",
                "type": "aws_db_instance",
                "change": {"actions": ["update"]},
            }
        ],
    }
    path = _write_plan(tmp_path, plan)

    result = stream_plan(path)

    assert len(result.resources) == 2
    assert result.resources[0]["module_address"] == "root"
    assert result.resources[1]["module_address"] == "module.child"
    assert result.module_stats.module_count == 2
    assert result.module_stats.modules_with_resources == 2
    assert result.module_stats.child_module_count == 1
    assert result.resource_changes == plan["resource_changes"]
    assert result.top_level["planned_values"]["root_module"]["address"] == "root"


def test_stream_plan_schema_errors(tmp_path):
    bad_plan = {"planned_values": {"root_module": {"resources": {"not": "a list"}}}}
    path = _write_plan(tmp_path, bad_plan)
    with pytest.raises(PlanSchemaError):
        stream_plan(path)


def test_build_slo_metadata_windows():
    exceeds, slo = build_slo_metadata(FAST_PATH_RESOURCES // 2, 50, 100)
    assert exceeds is False
    assert slo["active_window"] == "fast_path"

    exceeds_large, slo_large = build_slo_metadata(LARGE_PLAN_RESOURCES + 1, 10, 100)
    assert exceeds_large is True
    assert slo_large["active_window"] == "oversized"
    assert slo_large["breach_reason"] == "resource_count"


def test_stream_plan_honors_forced_parse_duration(monkeypatch: pytest.MonkeyPatch, tmp_path):
    plan = {
        "format_version": "1.0",
        "terraform_version": "1.6.0",
        "planned_values": {
            "root_module": {
                "address": "root",
                "resources": [],
                "child_modules": [],
            }
        },
    }
    path = _write_plan(tmp_path, plan)

    monkeypatch.setenv("VSCAN_FORCE_PARSE_MS", "42")
    result = stream_plan(path)

    assert result.parse_duration_ms == 42
