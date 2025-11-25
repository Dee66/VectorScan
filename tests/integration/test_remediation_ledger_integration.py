import json
from pathlib import Path

from src.pillar.compat.normalization import ScanOptions
from src.pillar.evaluator import evaluate_scan

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _load_plan(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _issue_sort_key(issue: dict) -> tuple[int, str, str]:
    severity = str(issue.get("severity", "")).lower()
    return (
        _SEVERITY_RANK.get(severity, len(_SEVERITY_RANK)),
        str(issue.get("id") or ""),
        str(issue.get("resource_address") or ""),
    )


def test_remediation_ledger_alignment_across_evaluation_and_payload():
    plan_payload = _load_plan("tfplan_fail.json")
    result = evaluate_scan(plan_payload, options=ScanOptions())

    payload = result.payload
    evaluation = result.evaluation
    assert isinstance(evaluation, dict), "evaluation block must exist"
    payload_issues = payload.get("issues")
    assert isinstance(payload_issues, list) and payload_issues, "payload issues missing"
    assert evaluation.get("issues") is payload_issues, "evaluation issues must reuse payload list"
    assert payload_issues == sorted(payload_issues, key=_issue_sort_key)

    ledger = payload.get("remediation_ledger")
    assert isinstance(ledger, dict), "remediation ledger must exist"
    aggregate = ledger.get("remediation_metadata_aggregate")
    assert isinstance(aggregate, dict) and aggregate, "ledger aggregate missing"

    for issue in payload_issues:
        metadata = issue.get("remediation_metadata")
        assert isinstance(metadata, dict)
        ledger_metadata = aggregate.get(issue["id"])
        assert isinstance(ledger_metadata, dict)
        assert ledger_metadata == metadata

    environment = payload.get("environment")
    assert isinstance(environment, dict)
    assert list(environment.keys()) == sorted(environment.keys())

    metadata_block = payload.get("metadata") or {}
    control_block = metadata_block.get("control") or {}
    assert isinstance(control_block, dict) and control_block
    assert list(control_block.keys()) == sorted(control_block.keys())

    evaluation_metadata = (evaluation.get("metadata") or {}).get("control") or {}
    if evaluation_metadata:
        assert list(evaluation_metadata.keys()) == sorted(evaluation_metadata.keys())

    ledger_paths = ledger.get("paths")
    assert isinstance(ledger_paths, list) and ledger_paths
    for entry in ledger_paths:
        rem_meta = entry.get("remediation_metadata")
        assert isinstance(rem_meta, dict)
        assert rem_meta == {}

    control_env = ledger.get("remediation_rule_index")
    assert isinstance(control_env, list) and control_env == ledger.get("rule_ids")