"""Canonical evaluator wiring for VectorScan phase 2."""

from __future__ import annotations

from copy import copy
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, List, Optional

from .constants import (
    PILLAR_NAME,
    SCAN_VERSION,
    GUARDSCORE_RULES_VERSION,
    CANONICAL_SCHEMA_VERSION,
)
from src.vectorscan.metadata import build_environment
from src.vectorscan.rules import get_all_rules
from src.vectorscan.fixpack import loader as fixpack_loader

REQUIRED_OUTPUT_KEYS = [
    "pillar",
    "scan_version",
    "guardscore_rules_version",
    "canonical_schema_version",
    "issues",
    "severity_totals",
    "pillar_score_inputs",
    "metadata",
    "environment",
    "badge_eligible",
    "quick_score_mode",
    "latency_ms",
    "schema_validation_error",
]

ISSUE_REQUIRED_FIELDS = [
    "id",
    "severity",
    "title",
    "description",
    "resource_address",
    "attributes",
    "remediation_hint",
    "remediation_difficulty",
]

SEVERITY_KEYS = ["critical", "high", "medium", "low"]


def evaluate_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience wrapper for compatibility with legacy call sites."""

    return run_scan(plan=plan)


def run_scan(
    plan: Dict[str, Any],
    *,
    source_path: Optional[Path] = None,
    raw_size: Optional[int] = None,
) -> Dict[str, Any]:
    """Produce a canonical payload derived from the supplied plan."""

    start = perf_counter()
    plan_snapshot = copy(plan) if isinstance(plan, dict) else {}
    resource_count = _extract_resource_count(plan_snapshot)
    providers = _extract_providers(plan_snapshot)
    metadata_environment = build_environment(plan_snapshot)
    quick_score_mode = _should_enable_quick_score(resource_count, raw_size, source_path)
    issues: List[Dict[str, Any]] = []

    for rule_cls in get_all_rules():
        try:
            results = rule_cls.evaluate(plan_snapshot)
        except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-except
            issues.append(
                {
                    "id": "P-VEC-EVAL-ERR",
                    "severity": "high",
                    "title": "Rule execution error",
                    "description": str(exc),
                    "resource_address": "",
                    "attributes": {},
                    "remediation_hint": "",
                    "remediation_difficulty": "medium",
                }
            )
            continue

        if results:
            issues.extend(results)

    # optional fixpack mapping
    for issue in issues:
        rule_id = issue.get("id", "")
        hint = fixpack_loader.get_fixpack_hint(rule_id)
        if hint:
            issue["remediation_hint"] = hint
        metadata = fixpack_loader.get_fixpack_metadata(rule_id)
        if metadata:
            issue["remediation_metadata"] = metadata

    pillar_score_inputs = {
        "critical": sum(1 for issue in issues if issue.get("severity") == "critical"),
        "high": sum(1 for issue in issues if issue.get("severity") == "high"),
        "medium": sum(1 for issue in issues if issue.get("severity") == "medium"),
        "low": sum(1 for issue in issues if issue.get("severity") == "low"),
    }
    severity_totals = dict(pillar_score_inputs)

    payload = _build_base_payload(
        severity_totals=severity_totals,
        metadata_environment=metadata_environment,
        plan_metadata={
            "resource_count": resource_count,
            "providers": providers,
        },
        quick_score_mode=quick_score_mode,
        schema_error=None,
        issues=issues,
        pillar_score_inputs=pillar_score_inputs,
    )
    payload["latency_ms"] = _measure_latency_ms(start)
    return _sort_payload(payload)


def build_fatal_error_output(message: str) -> Dict[str, Any]:
    metadata_environment = {
        "inferred_stage": "dev",
        "resource_count": 0,
        "providers": [],
    }
    payload = _build_base_payload(
        severity_totals=_zero_severity_totals(),
        metadata_environment=metadata_environment,
        plan_metadata={"resource_count": 0, "providers": []},
        quick_score_mode=False,
        schema_error=message,
        pillar_score_inputs=_zero_severity_totals(),
    )
    payload["percentile_placeholder"] = True
    payload["guardscore_badge"] = {
        "eligible": False,
        "score_placeholder": True,
    }
    payload["playground_summary"] = ""
    payload["upgrade_hint"] = ""
    payload["schema_validation_error"] = message
    payload["latency_ms"] = 0
    return _sort_payload(payload)


def _build_base_payload(
    *,
    severity_totals: Dict[str, int],
    metadata_environment: Dict[str, Any],
    plan_metadata: Dict[str, Any],
    quick_score_mode: bool,
    schema_error: Optional[str],
    issues: Optional[List[Dict[str, Any]]] = None,
    pillar_score_inputs: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "pillar": PILLAR_NAME,
        "scan_version": SCAN_VERSION,
        "guardscore_rules_version": GUARDSCORE_RULES_VERSION,
        "canonical_schema_version": CANONICAL_SCHEMA_VERSION,
        "issues": list(issues or []),
        "severity_totals": severity_totals,
        "pillar_score_inputs": dict(pillar_score_inputs or severity_totals),
        "metadata": {
            "environment": metadata_environment,
            "plan": plan_metadata,
        },
        "environment": metadata_environment,
        "badge_eligible": False,
        "guardscore_badge": {
            "eligible": False,
            "score_placeholder": False,
        },
        "percentile_placeholder": False,
        "quick_score_mode": quick_score_mode,
        "latency_ms": 0,
        "schema_validation_error": schema_error,
        "required": list(REQUIRED_OUTPUT_KEYS),
        "issue_required_fields": list(ISSUE_REQUIRED_FIELDS),
        "severity_keys": list(SEVERITY_KEYS),
        "playground_summary": "",
        "upgrade_hint": "",
    }
    return payload


def _extract_resource_count(plan: Dict[str, Any]) -> int:
    candidate = plan.get("resource_count")
    try:
        count = int(candidate)
    except (TypeError, ValueError):
        count = None
    if count is not None and count >= 0:
        return count
    resource_changes = plan.get("resource_changes")
    if isinstance(resource_changes, list):
        return len(resource_changes)
    return 0


def _extract_providers(plan: Dict[str, Any]) -> list[str]:
    providers = plan.get("providers")
    if isinstance(providers, list):
        normalized = [str(provider) for provider in providers]
        return sorted(normalized)
    provider_schemas = plan.get("provider_schemas")
    if isinstance(provider_schemas, dict):
        return sorted(str(key) for key in provider_schemas.keys())
    return []


def _zero_severity_totals() -> Dict[str, int]:
    return {key: 0 for key in SEVERITY_KEYS}


def _should_enable_quick_score(
    resource_count: int,
    raw_size: Optional[int],
    source_path: Optional[Path],
) -> bool:
    if resource_count > 1000:
        return True
    size_bytes = raw_size
    if size_bytes is None and source_path and source_path.exists():
        size_bytes = source_path.stat().st_size
    if size_bytes is None:
        return False
    return size_bytes > 40 * 1024 * 1024


def _measure_latency_ms(start: float) -> int:
    elapsed = perf_counter() - start
    return max(int(elapsed * 1000), 0)


def _sort_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {key: payload[key] for key in sorted(payload.keys())}
