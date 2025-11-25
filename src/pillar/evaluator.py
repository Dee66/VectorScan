from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.pillar import constants as pillar_constants
from src.pillar.compat.normalization import (
    NormalizationResult,
    ScanOptions,
    audit_ledger_synthesize,
    canonical_issue_collect,
    flatten_plan,
    iam_drift_normalize,
    metadata_inject,
    severity_aggregate,
    build_control_flags,
    resolve_offline_mode,
    run_normalized_scan,
)
from src.pillar.rules import registry as rule_registry
from src.pillar.rules.rule_engine import evaluate_rules
from src.pillar.metadata import build_metadata, snapshot_control_flags
from tools.vectorscan.constants import (
    EXIT_PREVIEW_MODE,
    EXIT_TERRAFORM_ERROR,
    EXIT_TERRAFORM_FAIL,
)

_SEVERITY_RANK = {level: idx for idx, level in enumerate(("critical", "high", "medium", "low"))}


def evaluate_scan(
    plan: Dict[str, Any],
    *,
    source_path: Optional[Path] = None,
    raw_size: Optional[int] = None,
    options: Optional[ScanOptions] = None,
) -> NormalizationResult:
    """Execute the legacy-parity normalization pipeline."""

    resolved_options = options or ScanOptions()
    flattened = flatten_plan(plan)
    enriched = metadata_inject(flattened)
    enriched = iam_drift_normalize(enriched)
    enriched = canonical_issue_collect(enriched)
    _evaluate_stub_rules(enriched)
    _normalize_issue_remediation_fields(enriched.get("issues"))
    enriched = severity_aggregate(enriched)
    enriched = audit_ledger_synthesize(enriched)
    offline_mode = resolve_offline_mode(enriched, resolved_options)
    environment_block = dict(enriched.get("environment") or {})
    control_flags = snapshot_control_flags(
        build_control_flags(enriched, resolved_options, offline_mode)
    )
    environment_block.update(control_flags)
    environment_block = dict(sorted(environment_block.items()))
    enriched["environment"] = environment_block
    enriched["_control_flags"] = dict(control_flags)
    enriched["_canonical_metadata"] = build_metadata(enriched)
    evaluation_value = enriched.get("evaluation")
    evaluation_block = evaluation_value if isinstance(evaluation_value, dict) else None
    if evaluation_block is not None:
        flags_block = evaluation_block.setdefault("flags", {})
        flags_block.update(control_flags)
        evaluation_block["scan_version"] = pillar_constants.SCAN_VERSION
        metadata_block = evaluation_block.setdefault("metadata", {})
        control_meta = metadata_block.setdefault("control", {})
        control_meta.update(control_flags)
        metadata_block["control"] = dict(sorted(control_meta.items()))
        metadata_block["_control_flags"] = dict(control_flags)
        enriched["evaluation"] = evaluation_block
    raw_result = run_normalized_scan(
        enriched["plan"],
        source_path=source_path,
        raw_size=raw_size,
        options=resolved_options,
        flattened=enriched,
    )
    payload_view = raw_result.payload if isinstance(raw_result.payload, dict) else {}
    payload_issues = payload_view.get("issues") if isinstance(payload_view.get("issues"), list) else []
    updated_evaluation = raw_result.evaluation if isinstance(raw_result.evaluation, dict) else None
    if updated_evaluation is not None:
        updated_evaluation["issues"] = payload_issues
        _attach_canonical_sections(updated_evaluation, payload_view)
    severity_summary = raw_result.severity_summary if isinstance(raw_result.severity_summary, dict) else {}
    exit_code = finalize_exit_code(severity_summary, updated_evaluation)
    if raw_result.exit_code in (EXIT_TERRAFORM_FAIL, EXIT_TERRAFORM_ERROR):
        exit_code = raw_result.exit_code
        if updated_evaluation is not None:
            updated_evaluation["exit_code"] = exit_code
    if raw_result.exit_code == EXIT_PREVIEW_MODE:
        exit_code = EXIT_PREVIEW_MODE
        if updated_evaluation is not None:
            updated_evaluation["exit_code"] = exit_code
    return replace(
        raw_result,
        exit_code=exit_code,
        evaluation=updated_evaluation,
    )


def _evaluate_stub_rules(enriched_context: Dict[str, Any]) -> None:
    """Invoke deterministic rule stubs and append canonical issues."""

    canonical_issues = enriched_context.get("issues")
    if not isinstance(canonical_issues, list):
        canonical_issues = []
        enriched_context["issues"] = canonical_issues
        evaluation_block = dict(enriched_context.get("evaluation") or {})
        evaluation_block["issues"] = canonical_issues
        enriched_context["evaluation"] = evaluation_block

    rule_context = {
        "plan": enriched_context.get("plan"),
        "plan_metadata": enriched_context.get("plan_metadata"),
        "environment": enriched_context.get("environment"),
        "environment_label": enriched_context.get("environment_label", "vectorscan"),
        "resources": enriched_context.get("resources"),
        "evaluation": enriched_context.get("evaluation"),
    }
    rules = rule_registry.get_rules()
    canonical_issues.extend(evaluate_rules(rules, context=rule_context))


def _normalize_issue_remediation_fields(issues: Any) -> None:
    """Ensure remediation fields remain schema-compliant without local fixpacks."""

    if not isinstance(issues, list):
        return

    for issue in issues:
        if not isinstance(issue, dict):
            continue
        issue.setdefault("remediation_hint", "")
        issue.setdefault("remediation_difficulty", "medium")
        if "remediation_metadata" in issue:
            issue.pop("remediation_metadata")

    issues.sort(
        key=lambda entry: (
            _SEVERITY_RANK.get(str(entry.get("severity", "")).lower(), len(_SEVERITY_RANK)),
            str(entry.get("id") or ""),
            str(entry.get("resource_address") or ""),
        )
        if isinstance(entry, dict)
        else (len(_SEVERITY_RANK), "", "")
    )


def fatal_error_payload(message: str) -> Dict[str, Any]:
    """Return a minimal failure payload used for unexpected errors."""

    return {
        "status": "FAIL",
        "error": message,
    }


def is_valid_plan_payload(plan: object) -> bool:
    """Simple schema guard used by the validate command."""

    return isinstance(plan, dict)


def finalize_exit_code(
    severity_summary: Optional[Dict[str, Any]],
    evaluation: Optional[Dict[str, Any]] = None,
) -> int:
    """Compute and store the canonical exit code from severity summary data."""

    if not isinstance(severity_summary, dict):
        severity_summary = {}

    def _count(level: str) -> int:
        value = severity_summary.get(level)
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    exit_code = _exit_code_from_counts(
        critical=_count("critical"),
        high=_count("high"),
        medium=_count("medium"),
    )
    if isinstance(evaluation, dict):
        evaluation["exit_code"] = exit_code
        normalized_summary = {
            level: _count(level)
            for level in ("critical", "high", "medium", "low")
        }
        evaluation["severity_summary"] = normalized_summary
    return exit_code


def _exit_code_from_counts(*, critical: int, high: int, medium: int) -> int:
    if critical > 0:
        return 3
    if high > 0:
        return 2
    if medium > 0:
        return 1
    return 0


def _attach_canonical_sections(evaluation_block: Dict[str, Any], payload_view: Dict[str, Any]) -> None:
    evaluation_block.setdefault("pillar", pillar_constants.PILLAR_NAME)
    evaluation_block.setdefault(
        "guardscore_rules_version",
        payload_view.get("guardscore_rules_version", pillar_constants.GUARDSCORE_RULES_VERSION),
    )
    evaluation_block.setdefault(
        "badge_eligible",
        bool(payload_view.get("badge_eligible", False)),
    )
    evaluation_block.setdefault(
        "quick_score_mode",
        bool(payload_view.get("quick_score_mode", False)),
    )
    latency_candidate = payload_view.get("latency_ms", 0)
    try:
        latency_value = int(latency_candidate)
    except (TypeError, ValueError):
        latency_value = 0
    evaluation_block.setdefault("latency_ms", max(latency_value, 0))
    evaluation_block.setdefault(
        "schema_validation_error",
        payload_view.get("schema_validation_error"),
    )
    metadata_block = payload_view.get("metadata")
    if isinstance(metadata_block, dict):
        control_block = metadata_block.get("control")
        if isinstance(control_block, dict):
            evaluation_metadata = evaluation_block.setdefault("metadata", {})
            metadata_control = evaluation_metadata.setdefault("control", {})
            metadata_control.update(control_block)
            evaluation_metadata["control"] = dict(sorted(metadata_control.items()))
