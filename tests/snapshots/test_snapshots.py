from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests import canonicalize_snapshot

SNAPSHOT_DIR = Path(__file__).resolve().parent
GOLDEN_DIR = SNAPSHOT_DIR.parent / "golden"
SNAPSHOT_FILES = [
    "pass_output.json",
    "fail_output.json",
    "iam_drift_output.json",
    "pass_explain_output.json",
    "fail_explain_output.json",
    "iam_drift_explain_output.json",
    "pass_diff_output.json",
    "fail_diff_output.json",
    "iam_drift_diff_output.json",
    "fail_resource_output.json",
    "module_resource_output.json",
    "fail_preview_output.json",
    "plan_compare_output.json",
]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_schema_fields(payload: dict) -> None:
    if payload.get("mode") == "compare":
        # Compare output omits canonical scan schema fields by design.
        return
    required = ["pillar", "guardscore_rules_version", "badge_eligible", "quick_score_mode", "latency_ms"]
    for field in required:
        assert field in payload, f"Missing required schema field: {field}"
    assert isinstance(payload["badge_eligible"], bool)
    assert isinstance(payload["quick_score_mode"], bool)
    assert isinstance(payload["latency_ms"], int)


def _assert_metadata_order(payload: dict) -> None:
    metadata = payload.get("metadata")
    if metadata is None:
        # Compare payloads omit metadata entirely.
        assert payload.get("mode") == "compare", "metadata block missing"
        return
    assert isinstance(metadata, dict), "metadata block missing"
    keys = list(metadata.keys())
    assert keys == sorted(keys), f"metadata keys must be sorted alphabetically: {keys}"


def _assert_issues_order(payload: dict) -> None:
    issues = payload.get("issues") or []
    expected = sorted(
        issues,
        key=lambda issue: (SEVERITY_ORDER.get(issue.get("severity"), 99), issue.get("id", "")),
    )
    assert issues == expected, "issues must be ordered by severity then id"


def _assert_ledger_order(payload: dict) -> None:
    ledger = payload.get("remediation_ledger") or {}
    paths = ledger.get("paths") or []
    expected = sorted(
        paths,
        key=lambda entry: (SEVERITY_ORDER.get(entry.get("severity"), 99), entry.get("id", "")),
    )
    assert paths == expected, "remediation ledger paths must be ordered by severity then id"
    rule_ids = ledger.get("rule_ids") or []
    assert [entry.get("id") for entry in paths] == rule_ids, "rule_ids must align with ledger paths"


@pytest.mark.parametrize("filename", SNAPSHOT_FILES)
def test_snapshot_matches_golden(filename: str) -> None:
    snapshot_path = SNAPSHOT_DIR / filename
    golden_path = GOLDEN_DIR / filename

    assert snapshot_path.exists(), f"Snapshot missing: {snapshot_path}"
    assert golden_path.exists(), f"Golden missing: {golden_path}"

    snapshot_payload = _load_json(snapshot_path)
    golden_payload = _load_json(golden_path)
    allow_compare = filename == "plan_compare_output.json"
    canonical_snapshot = canonicalize_snapshot(snapshot_payload, allow_compare_mode=allow_compare)
    canonical_golden = canonicalize_snapshot(golden_payload, allow_compare_mode=allow_compare)

    assert canonical_snapshot == canonical_golden, f"Snapshot diverged from golden: {filename}"

    _assert_schema_fields(snapshot_payload)
    _assert_metadata_order(snapshot_payload)
    _assert_issues_order(snapshot_payload)
    _assert_ledger_order(snapshot_payload)
