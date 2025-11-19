"""Unit tests for the Copilot scaffolding helper."""

from __future__ import annotations

import json
from pathlib import Path

from tools.vectorscan import copilot_scaffolder as scaffolder


def test_scaffolder_creates_missing_artifacts(tmp_path: Path) -> None:
    report = scaffolder.ensure_structure(tmp_path, apply_changes=True)

    assert not report.missing_directories
    assert not report.missing_files

    for item in scaffolder.REQUIRED_ITEMS:
        assert (tmp_path / item.relative_path).exists()

    second_report = scaffolder.ensure_structure(tmp_path, apply_changes=True)
    assert not second_report.created_directories
    assert not second_report.created_files


def test_scaffolder_reports_missing_assets_when_dry_run(tmp_path: Path) -> None:
    target_root = tmp_path / "dry"
    report = scaffolder.ensure_structure(target_root, apply_changes=False)

    assert not report.created_directories
    assert not report.created_files
    assert report.missing_directories
    assert report.missing_files
    assert not target_root.exists()


def test_fixture_templates_embed_semantic_content(tmp_path: Path) -> None:
    scaffolder.ensure_structure(tmp_path, apply_changes=True)
    pass_plan = json.loads((tmp_path / "tests/fixtures/tfplan_pass.json").read_text())
    fail_plan = json.loads((tmp_path / "tests/fixtures/tfplan_fail.json").read_text())
    iam_drift_plan = json.loads((tmp_path / "tests/fixtures/tfplan_iam_drift.json").read_text())

    assert pass_plan["resource_changes"][0]["change"]["after"]["storage_encrypted"] is True
    assert fail_plan["resource_changes"][0]["change"]["after"]["storage_encrypted"] is False
    assert iam_drift_plan["resource_changes"][0]["change"]["after"]["policy"]["Statement"]

    invalid_contents = (tmp_path / "tests/fixtures/tfplan_invalid.json").read_text()
    assert "invalid_json_placeholder" in invalid_contents


def test_golden_templates_embed_expected_blocks(tmp_path: Path) -> None:
    scaffolder.ensure_structure(tmp_path, apply_changes=True)

    pass_golden = json.loads((tmp_path / "tests/golden/pass_output.json").read_text())
    fail_golden = json.loads((tmp_path / "tests/golden/fail_output.json").read_text())
    iam_drift_golden = json.loads((tmp_path / "tests/golden/iam_drift_output.json").read_text())
    plan_compare_golden = json.loads(
        (tmp_path / "tests/golden/plan_compare_output.json").read_text()
    )
    ledger_yaml = (tmp_path / "tests/golden/audit_ledger.yaml").read_text()

    assert pass_golden["status"] == "PASS"
    assert fail_golden["violations"][0]["policy_id"] == "P-SEC-001"
    assert "iam_drift_report" in iam_drift_golden
    assert plan_compare_golden["plan_evolution"]["downgraded_encryption"]
    assert "scan_timestamp" in ledger_yaml
