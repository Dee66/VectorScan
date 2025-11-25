"""Test package helpers shared across VectorScan suites."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

CANONICAL_REQUIRED_FIELDS: tuple[str, ...] = (
    "pillar",
    "scan_version",
    "guardscore_rules_version",
    "canonical_schema_version",
    "issues",
    "severity_totals",
    "metadata",
    "environment",
    "badge_eligible",
    "quick_score_mode",
    "latency_ms",
    "schema_validation_error",
)

LEGACY_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "status",
    "violations",
    "violations_struct",
    "counts",
    "plan_metadata",
    "remediation_payload",
)

ISSUE_REQUIRED_FIELDS: tuple[str, ...] = (
    "id",
    "severity",
    "title",
    "description",
    "resource_address",
    "attributes",
    "remediation_hint",
    "remediation_difficulty",
    "remediation_metadata",
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def canonicalize_snapshot(payload: Dict[str, Any], *, allow_compare_mode: bool = False) -> Dict[str, Any]:
    """Normalize evaluator output for deterministic golden snapshots."""

    clone: Dict[str, Any] = json.loads(json.dumps(payload))
    mode = clone.get("mode")
    compare_mode = mode == "compare"
    if not allow_compare_mode and not compare_mode:
        _assert_required_fields(clone, CANONICAL_REQUIRED_FIELDS)

    for field in LEGACY_TOP_LEVEL_FIELDS:
        clone.pop(field, None)

    _normalize_metadata_sections(clone)
    _normalize_issue_collection(clone)
    _normalize_severity_totals(clone)

    return _sort_structure(clone)


def _assert_required_fields(payload: Dict[str, Any], fields: Iterable[str]) -> None:
    missing = [field for field in fields if field not in payload]
    if missing:
        raise AssertionError(f"Missing canonical fields: {', '.join(sorted(missing))}")


def _normalize_metadata_sections(payload: Dict[str, Any]) -> None:
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        payload["metadata"] = _sort_structure(metadata)
    environment = payload.get("environment")
    if isinstance(environment, dict):
        payload["environment"] = _sort_structure(environment)


def _normalize_issue_collection(payload: Dict[str, Any]) -> None:
    issues = payload.get("issues")
    if not isinstance(issues, list):
        payload["issues"] = []
        return
    normalized: List[Dict[str, Any]] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        candidate = {key: issue.get(key) for key in ISSUE_REQUIRED_FIELDS}
        _assert_required_fields(candidate, ISSUE_REQUIRED_FIELDS)
        attributes = candidate.get("attributes")
        if isinstance(attributes, dict):
            normalized_attrs = _sort_structure(attributes)
            normalized_attrs.setdefault("rule_id", candidate["id"])
            candidate["attributes"] = normalized_attrs
        else:
            candidate["attributes"] = {"rule_id": candidate["id"]}
        metadata = candidate.get("remediation_metadata")
        candidate["remediation_metadata"] = metadata if isinstance(metadata, dict) else {}
        candidate["remediation_hint"] = candidate.get("remediation_hint") or ""
        candidate["remediation_difficulty"] = candidate.get("remediation_difficulty") or "low"
        normalized.append(candidate)
    normalized.sort(
        key=lambda entry: (
            SEVERITY_ORDER.get(str(entry.get("severity", "")).lower(), len(SEVERITY_ORDER)),
            entry.get("id"),
        )
    )
    payload["issues"] = normalized


def _normalize_severity_totals(payload: Dict[str, Any]) -> None:
    totals = payload.get("severity_totals")
    severity_levels = ("critical", "high", "medium", "low")
    normalized: Dict[str, int] = {}
    for level in severity_levels:
        value = totals.get(level) if isinstance(totals, dict) else 0
        try:
            normalized[level] = max(int(value), 0)
        except (TypeError, ValueError):
            normalized[level] = 0
    payload["severity_totals"] = normalized


def _sort_structure(value: Any):
    if isinstance(value, dict):
        return {key: _sort_structure(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_sort_structure(item) for item in value]
    return value


__all__ = ["canonicalize_snapshot"]
