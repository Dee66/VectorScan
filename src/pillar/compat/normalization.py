from __future__ import annotations

import os
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from src.pillar import constants as pillar_constants
from src.pillar import terraform_shim
from src.pillar.rules import registry
from tools.vectorscan import plan_utils
from tools.vectorscan import vectorscan as legacy
from tools.vectorscan.constants import (
    EXIT_CONFIG_ERROR,
    EXIT_INVALID_INPUT,
    EXIT_POLICY_FAIL,
    EXIT_POLICY_LOAD_ERROR,
    EXIT_PREVIEW_MODE,
    EXIT_SUCCESS,
    EXIT_TERRAFORM_ERROR,
    EXIT_TERRAFORM_FAIL,
)
from tools.vectorscan.env_flags import env_falsey, env_truthy
from tools.vectorscan.time_utils import deterministic_isoformat


@dataclass(frozen=True)
class ScanOptions:
    """Normalized configuration derived from CLI or shim inputs."""

    as_json: bool = True
    gha_mode: bool = False
    quiet: bool = False
    no_color: bool = False
    resource: Optional[str] = None
    diff: bool = False
    explain: bool = False
    preview_vectorguard: bool = False
    policy_ids: Optional[Sequence[str]] = None
    policy_presets: Optional[Sequence[str]] = None
    policy_manifest_path: Optional[str] = None
    lead_capture: bool = False
    email: Optional[str] = None
    endpoint: Optional[str] = None
    allow_network: bool = False
    force_no_network: bool = False
    terraform_tests: bool = False
    terraform_bin: Optional[str] = None
    no_terraform_download: bool = False
    iam_drift_penalty: Optional[int] = None
    strict_mode_override: Optional[bool] = None


_EVAL_FLAG_SEVERITY = "severity"
_EVAL_FLAG_LEDGER = "audit_ledger"

ISSUE_REQUIRED_FIELDS: Tuple[str, ...] = (
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

_ISSUE_DICT_FIELDS: Set[str] = {"attributes", "remediation_metadata"}
_SEVERITY_RANK = {level: idx for idx, level in enumerate(legacy.SEVERITY_LEVELS)}


@dataclass(frozen=True)
class NormalizationResult:
    """Outcome of the normalization pipeline."""

    payload: Dict[str, Any]
    exit_code: int
    severity_summary: Dict[str, int]
    policy_errors: List[Dict[str, str]]
    violations: List[str]
    terraform_report: Optional[Dict[str, Any]]
    resource_scope: Optional[Dict[str, Any]]
    explanation_block: Optional[Dict[str, Any]]
    plan_diff_block: Optional[Dict[str, Any]]
    preview_manifest_data: Optional[Dict[str, Any]]
    use_color: bool
    evaluation: Optional[Dict[str, Any]] = None


class NormalizationError(RuntimeError):
    """Raised when parity normalization cannot proceed."""

    def __init__(self, message: str, exit_code: int = EXIT_INVALID_INPUT) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def flatten_plan(plan_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce tfplan JSON into a deterministic structure for downstream stages."""

    if not isinstance(plan_payload, dict):
        raise NormalizationError(
            "Terraform plan payload must be a JSON object.", EXIT_INVALID_INPUT
        )

    plan_copy = deepcopy(plan_payload)
    planned_values = plan_copy.setdefault("planned_values", {})
    if not isinstance(planned_values, dict):
        planned_values = {}
        plan_copy["planned_values"] = planned_values
    root_module = planned_values.setdefault("root_module", {})
    if not isinstance(root_module, dict):
        root_module = {}
        planned_values["root_module"] = root_module
    resources = root_module.setdefault("resources", [])
    if not isinstance(resources, list):
        root_module["resources"] = []
    try:
        plan_utils._validate_plan_schema(plan_copy)
    except plan_utils.PlanLoadError as exc:
        raise NormalizationError(f"Invalid Terraform plan schema: {exc}", EXIT_INVALID_INPUT)

    flattened_resources = plan_utils.iter_resources(plan_copy)
    flattened_resources = sorted(flattened_resources, key=_resource_sort_key)

    raw_changes = plan_copy.get("resource_changes") or []
    plan_copy["resource_changes"] = _normalize_resource_changes(raw_changes)

    return {
        "plan": plan_copy,
        "resources": flattened_resources,
    }


def metadata_inject(flat_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Attach legacy metadata fields to a flattened plan context."""

    if not isinstance(flat_ctx, dict):
        raise NormalizationError("Metadata stage requires a flattened context map.")
    source_plan = flat_ctx.get("plan")
    source_resources = flat_ctx.get("resources")
    if not isinstance(source_plan, dict) or not isinstance(source_resources, list):
        raise NormalizationError("Flattened context is missing plan/resources data.")

    plan_copy = deepcopy(source_plan)
    planned_values = plan_copy.setdefault("planned_values", {})
    if not isinstance(planned_values, dict):
        planned_values = {}
        plan_copy["planned_values"] = planned_values
    root_module = planned_values.setdefault("root_module", {})
    if not isinstance(root_module, dict):
        root_module = {}
        planned_values["root_module"] = root_module

    collected: List[Dict[str, Any]] = []
    _normalize_module_tree(root_module, "root", collected)
    enriched_resources = sorted(collected, key=_resource_sort_tuple)

    plan_metadata = plan_utils.compute_plan_metadata(
        plan_copy,
        enriched_resources,
        module_stats=None,
        plan_limits=None,
        resource_filter=None,
    )

    resource_index = {
        res["address"]: res
        for res in enriched_resources
        if isinstance(res.get("address"), str) and res["address"]
    }

    enriched_context: Dict[str, Any] = {
        "plan": plan_copy,
        "resources": enriched_resources,
        "plan_metadata": plan_metadata,
        "resource_index": resource_index,
    }

    for key, value in flat_ctx.items():
        if key in enriched_context:
            continue
        enriched_context[key] = deepcopy(value)

    return enriched_context


def canonical_issue_collect(meta_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Seed a deterministic issue list for downstream canonical consumers."""

    if not isinstance(meta_ctx, dict):
        raise NormalizationError("Canonical issue staging requires a metadata context map.")

    enriched_context = deepcopy(meta_ctx)
    canonical_issues: List[Dict[str, Any]] = []
    enriched_context["issues"] = canonical_issues

    evaluation_block = dict(enriched_context.get("evaluation") or {})
    evaluation_block["issues"] = canonical_issues
    evaluation_block["issue_required_fields"] = list(ISSUE_REQUIRED_FIELDS)
    flags_block = dict(evaluation_block.get("flags") or {})
    flags_block.setdefault("offline_mode", False)
    evaluation_block["flags"] = flags_block

    rule_catalog = registry.issue_catalog()
    evaluation_block["rule_catalog"] = rule_catalog
    enriched_context["evaluation"] = evaluation_block
    enriched_context["_issue_required_fields"] = ISSUE_REQUIRED_FIELDS
    enriched_context["rule_catalog"] = rule_catalog
    return enriched_context


def severity_aggregate(meta_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate per-severity counts from normalized issues if present."""

    if not isinstance(meta_ctx, dict):
        raise NormalizationError("Severity aggregation requires a metadata context map.")

    enriched_context = deepcopy(meta_ctx)
    issues = enriched_context.get("issues")
    totals: Dict[str, int] = {level: 0 for level in legacy.SEVERITY_LEVELS}
    if isinstance(issues, list):
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            level = _safe_str(issue.get("severity")).lower()
            if level in totals:
                totals[level] += 1
    evaluation_block = dict(enriched_context.get("evaluation") or {})
    evaluation_block["severity_summary"] = totals
    enriched_context["evaluation"] = evaluation_block
    return enriched_context


def audit_ledger_synthesize(meta_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Attach a deterministic audit ledger skeleton to the evaluation context."""

    if not isinstance(meta_ctx, dict):
        raise NormalizationError("Audit ledger synthesis requires a metadata context map.")

    enriched_context = deepcopy(meta_ctx)
    evaluation_block = dict(enriched_context.get("evaluation") or {})
    ledger_entry = _build_audit_ledger_entry(enriched_context)
    evaluation_block["audit_ledger"] = ledger_entry
    enriched_context["evaluation"] = evaluation_block
    return enriched_context


def iam_drift_normalize(meta_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Attach a deterministic IAM drift summary derived from the plan payload."""

    if not isinstance(meta_ctx, dict):
        raise NormalizationError("IAM drift stage requires a metadata context map.")
    plan = meta_ctx.get("plan")
    if not isinstance(plan, dict):
        raise NormalizationError("IAM drift stage requires a canonical plan object.")

    drift_report = legacy.build_iam_drift_report(plan)
    normalized_report = _normalize_iam_drift_report(drift_report)

    enriched_context = deepcopy(meta_ctx)
    enriched_context["iam_drift"] = normalized_report
    return enriched_context


def resolve_offline_mode(flat_or_meta_ctx: Dict[str, Any], flags: ScanOptions) -> bool:
    """Replicate legacy offline-mode semantics with a default of False."""

    if getattr(flags, "force_no_network", False):
        return True
    if flags.allow_network:
        return False

    offline_value = os.getenv("VSCAN_OFFLINE")
    if offline_value is not None:
        if env_truthy(offline_value):
            return True
        if env_falsey(offline_value):
            return False

    allow_value = os.getenv("VSCAN_ALLOW_NETWORK")
    if allow_value is not None:
        if env_truthy(allow_value):
            return False
        if env_falsey(allow_value):
            return True

    ctx_environment = flat_or_meta_ctx.get("environment")
    if isinstance(ctx_environment, dict):
        stored = ctx_environment.get("offline_mode")
        if isinstance(stored, bool):
            return stored

    return False


def resolve_allow_network_capture(
    flat_or_meta_ctx: Dict[str, Any], flags: ScanOptions, offline_mode: bool
) -> bool:
    """Determine whether network side-effects (lead capture, downloads) are allowed."""

    if getattr(flags, "force_no_network", False):
        return False

    allow_value = os.getenv("VSCAN_ALLOW_NETWORK")
    if allow_value is not None:
        if env_truthy(allow_value):
            return True
        if env_falsey(allow_value):
            return False

    offline_value = os.getenv("VSCAN_OFFLINE")
    if offline_value is not None:
        if env_truthy(offline_value):
            return False
        if env_falsey(offline_value):
            return True

    ctx_environment = flat_or_meta_ctx.get("environment")
    if isinstance(ctx_environment, dict):
        stored = ctx_environment.get("allow_network_capture")
        if isinstance(stored, bool):
            return stored

    if offline_mode:
        return False
    return bool(flags.allow_network)


def resolve_auto_download(
    flags: ScanOptions,
    *,
    offline_mode: bool,
) -> bool:
    """Determine whether Terraform auto-download should be attempted."""

    if offline_mode:
        return False
    if env_truthy(os.getenv("VSCAN_TERRAFORM_STUB")):
        return False
    if getattr(flags, "no_terraform_download", False):
        return False

    allow_env = os.getenv("VSCAN_ALLOW_TERRAFORM_DOWNLOAD")
    if allow_env is not None:
        if env_truthy(allow_env):
            return True
        if env_falsey(allow_env):
            return False

    legacy_env = os.getenv("VSCAN_TERRAFORM_AUTO_DOWNLOAD")
    if legacy_env is not None:
        if env_truthy(legacy_env):
            return True
        if env_falsey(legacy_env):
            return False

    return False


def _resolve_allow_network_flag(
    flat_or_meta_ctx: Dict[str, Any],
    flags: ScanOptions,
    offline_mode: bool,
) -> bool:
    if getattr(flags, "force_no_network", False):
        return False

    allow_env = os.getenv("VSCAN_ALLOW_NETWORK")
    if allow_env is not None:
        if env_truthy(allow_env):
            return True
        if env_falsey(allow_env):
            return False

    ctx_environment = flat_or_meta_ctx.get("environment")
    if isinstance(ctx_environment, dict):
        stored = ctx_environment.get("allow_network")
        if isinstance(stored, bool):
            return stored

    if offline_mode:
        return False

    return bool(getattr(flags, "allow_network", False))


def build_control_flags(
    flat_or_meta_ctx: Dict[str, Any],
    flags: ScanOptions,
    offline_mode: bool,
) -> Dict[str, bool]:
    """Construct deterministic control flags for downstream metadata."""

    allow_network_capture = resolve_allow_network_capture(flat_or_meta_ctx, flags, offline_mode)
    allow_network_flag = _resolve_allow_network_flag(flat_or_meta_ctx, flags, offline_mode)
    auto_download = resolve_auto_download(
        flags,
        offline_mode=offline_mode,
    )
    return {
        "offline_mode": bool(offline_mode),
        "allow_network_capture": bool(allow_network_capture),
        "auto_download": bool(auto_download),
        "allow_network": bool(allow_network_flag),
    }


def run_normalized_scan(
    plan_payload: Dict[str, Any],
    *,
    source_path: Optional[Path],
    raw_size: Optional[int],
    options: ScanOptions,
    flattened: Optional[Dict[str, Any]] = None,
) -> NormalizationResult:
    """Mirror the legacy VectorScan pipeline and return a deterministic payload."""

    start_time = time.perf_counter()
    strict_mode = (
        options.strict_mode_override
        if options.strict_mode_override is not None
        else legacy.is_strict_mode()
    )
    legacy._ensure_strict_clock(strict_mode)
    use_color = legacy._should_use_color(options.no_color)
    terraform_report: Optional[Dict[str, Any]] = None
    terraform_outcome = "SKIP"

    flattened_ctx = flattened or flatten_plan(plan_payload)
    if "plan_metadata" not in flattened_ctx:
        flattened_ctx = metadata_inject(flattened_ctx)
    normalized_plan = flattened_ctx["plan"]
    flattened_resources = flattened_ctx["resources"]

    env_block = flattened_ctx.get("environment")
    offline_mode = env_block.get("offline_mode") if isinstance(env_block, dict) else None
    if not isinstance(offline_mode, bool):
        offline_mode = resolve_offline_mode(flattened_ctx, options)
    control_flags = dict(flattened_ctx.get("_control_flags") or {})
    if not control_flags:
        control_flags = build_control_flags(flattened_ctx, options, offline_mode)
    else:
        control_flags.setdefault("offline_mode", bool(offline_mode))
        control_flags.setdefault(
            "allow_network_capture",
            resolve_allow_network_capture(flattened_ctx, options, offline_mode),
        )
        control_flags.setdefault(
            "allow_network",
            _resolve_allow_network_flag(flattened_ctx, options, offline_mode),
        )
        control_flags.setdefault(
            "auto_download",
            resolve_auto_download(
                options,
                offline_mode=offline_mode,
            ),
        )
    flattened_ctx["_control_flags"] = control_flags
    if isinstance(env_block, dict):
        env_block.update(control_flags)
    else:
        env_block = dict(control_flags)
    flattened_ctx["environment"] = env_block

    if terraform_shim.tests_requested(options):
        terraform_report, terraform_outcome = terraform_shim.execute(
            options,
            auto_download=bool(control_flags.get("auto_download")),
        )
        control_flags["terraform_outcome"] = terraform_outcome
    else:
        control_flags.setdefault("terraform_outcome", terraform_outcome)

    plan, resources, plan_limits, module_stats = _load_plan_context(
        normalized_plan,
        flattened_resources,
        source_path,
    )

    resource_scope = None
    resource_filter_set: Optional[Set[str]] = None
    scoped_resources = resources
    scope_details = None
    if options.resource:
        try:
            scope_details = legacy._resolve_resource_scope(options.resource, resources)
        except legacy._ResourceScopeError as exc:  # type: ignore[attr-defined]
            raise NormalizationError(_format_scope_error(exc))
        scoped_resources = [scope_details["resource"]]
        resource_filter_set = {scope_details["address"]}
        resource_scope = {
            "address": scope_details["address"],
            "resource": scope_details["resource"],
            "match_type": scope_details["match_type"],
            "input": options.resource,
        }

    policy_pack_hash_value = legacy.POLICY_PACK_HASH
    if policy_pack_hash_value is None:
        message = getattr(legacy, "_POLICY_PACK_ERROR", "Unknown policy pack error")
        raise NormalizationError(f"Policy pack load error: {message}", EXIT_POLICY_LOAD_ERROR)

    manifest_override_path = options.policy_manifest_path

    all_policies = legacy.get_policies()
    available_policy_ids = [p.metadata.policy_id for p in all_policies]
    try:
        selected_policy_ids = legacy._resolve_policy_selection(  # type: ignore[attr-defined]
            options.policy_ids,
            options.policy_presets,
            available_policy_ids,
        )
    except legacy._PolicySelectionError as exc:  # type: ignore[attr-defined]
        message = exc.message if hasattr(exc, "message") else str(exc)
        if getattr(exc, "choices", None):
            choices = ", ".join(getattr(exc, "choices"))
            message = f"{message}\nAvailable options: {choices}"
        raise NormalizationError(message)
    if not selected_policy_ids:
        raise NormalizationError("No policies selected for evaluation.")

    policy_lookup = {p.metadata.policy_id: p for p in all_policies}
    policies = [policy_lookup[pid] for pid in selected_policy_ids]

    policy_eval = legacy._evaluate_registered_policies(scoped_resources, policies)  # type: ignore[attr-defined]
    violations = legacy._sort_violations(policy_eval.violations, policy_eval.severity_lookup)  # type: ignore[attr-defined]
    policy_errors = list(policy_eval.policy_errors)

    def _policy_sort_key(policy_id: str) -> tuple[int, str]:
        severity = policy_eval.severity_lookup.get(policy_id, "low")
        return (legacy._SEVERITY_RANK.get(severity, len(legacy.SEVERITY_LEVELS)), policy_id)

    ordered_policy_ids = sorted(policy_eval.policy_ids, key=_policy_sort_key)

    if manifest_override_path:
        try:
            manifest_data = legacy._load_manifest_override(  # type: ignore[attr-defined]
                manifest_override_path,
                policy_pack_hash_value=policy_pack_hash_value,
                selected_policy_ids=policy_eval.policy_ids,
            )
        except legacy.PolicyManifestError as exc:
            raise NormalizationError(f"Policy manifest error: {exc}", EXIT_CONFIG_ERROR)
    else:
        manifest_data = legacy.build_policy_manifest(
            [policy.metadata for policy in policies],
            policy_pack_hash_value=policy_pack_hash_value,
        )

    legacy._strict_require(
        strict_mode,
        not policy_errors,
        "Strict mode prohibits policy_errors; ensure all policies execute cleanly.",
    )

    severity_summary = legacy.compute_violation_severity_summary(
        violations,
        policy_eval.severity_lookup,
    )
    status = "FAIL" if (violations or policy_errors) else "PASS"
    exit_code = EXIT_POLICY_FAIL if status == "FAIL" else EXIT_SUCCESS

    violation_structs = legacy.build_violation_structs(
        violations=violations,
        resources=scoped_resources,
        severity_lookup=policy_eval.severity_lookup,
        policy_metadata=policy_eval.policy_metadata,
    )

    payload: Dict[str, Any] = {
        "status": status,
        "file": str(source_path) if source_path else "-",
        "violations": violations,
        "violations_struct": violation_structs,
        "counts": {"violations": len(violations)},
        "checks": ordered_policy_ids,
        "vectorscan_version": legacy.VECTORSCAN_VERSION,
        "policy_version": legacy.POLICY_VERSION,
        "schema_version": legacy.OUTPUT_SCHEMA_VERSION,
        "policy_pack_hash": policy_pack_hash_value,
        "policy_errors": policy_errors,
        "violation_severity_summary": severity_summary,
        "scan_version": pillar_constants.SCAN_VERSION,
        "policy_source_url": manifest_data.get("policy_source_url"),
        "policy_manifest": manifest_data,
        "violation_count_by_severity": dict(severity_summary),
    }

    if scope_details:
        payload["resource_filter"] = {
            "input": options.resource,
            "address": scope_details["address"],
            "type": scope_details["resource"].get("type"),
            "name": scope_details["resource"].get("name"),
            "module_path": legacy._module_path_from_address(scope_details["address"]),
            "match": scope_details["match_type"],
        }

    if terraform_report is not None:
        payload["terraform_tests"] = {
            **{
                key: terraform_report.get(key)
                for key in (
                    "status",
                    "version",
                    "binary",
                    "source",
                    "strategy",
                    "message",
                    "returncode",
                )
            },
            "stdout": legacy._truncate_output(terraform_report.get("stdout"), strict=strict_mode),
            "stderr": legacy._truncate_output(terraform_report.get("stderr"), strict=strict_mode),
        }
        tf_status = str(terraform_report.get("status", "SKIP")).upper()
        if status == "PASS":
            if tf_status == "FAIL":
                status = "FAIL"
                exit_code = EXIT_TERRAFORM_FAIL
            elif tf_status == "ERROR":
                status = "FAIL"
                exit_code = EXIT_TERRAFORM_ERROR
        payload["status"] = status

    plan_metadata = legacy.compute_plan_metadata(
        plan,
        scoped_resources,
        module_stats=module_stats,
        plan_limits=plan_limits,
        resource_filter=resource_filter_set,
    )
    payload["plan_metadata"] = plan_metadata
    quick_score_mode = _should_enable_quick_score(
        plan_metadata.get("resource_count"),
        raw_size,
        source_path,
    )

    suspicious_defaults = legacy.detect_suspicious_defaults(plan, resources)
    payload["suspicious_defaults"] = suspicious_defaults

    suspicious_reasons: List[str] = []
    for entry in suspicious_defaults:
        if isinstance(entry, dict):
            reason = entry.get("reason")
            if isinstance(reason, str) and reason:
                suspicious_reasons.append(reason)

    smell_report = legacy.compute_smell_report(
        plan_metadata=plan_metadata,
        resources=scoped_resources,
        resource_changes=plan.get("resource_changes") or [],
        resource_filter=resource_filter_set,
    )
    payload["smell_report"] = smell_report

    plan_diff_block = None
    if options.diff:
        plan_diff_block = legacy.build_plan_diff(plan, resource_filter=resource_filter_set)
        payload["plan_diff"] = plan_diff_block

    metrics = legacy.compute_metrics(scoped_resources, violations)
    iam_drift_report = flattened_ctx.get("iam_drift")
    if not isinstance(iam_drift_report, dict):
        iam_drift_report = _normalize_iam_drift_report(legacy.build_iam_drift_report(plan))
        flattened_ctx["iam_drift"] = iam_drift_report
    payload["iam_drift_report"] = iam_drift_report
    iam_status = _safe_str(iam_drift_report.get("status")) or "PASS"
    iam_counts = iam_drift_report.get("counts", {}) if isinstance(iam_drift_report, dict) else {}
    risky_count = _safe_int(iam_counts.get("risky_changes"))
    metrics["iam_drift"] = {
        "status": iam_status,
        "risky_change_count": risky_count,
    }

    score = _safe_int(metrics.get("compliance_score"))
    penalty = _resolve_drift_penalty(options.iam_drift_penalty)
    if metrics["iam_drift"]["status"] == "FAIL" and penalty:
        score = max(0, score - penalty)
    metrics["compliance_score"] = score
    latency_ms = legacy._compute_scan_duration_ms(start_time)
    metrics["scan_duration_ms"] = latency_ms
    parser_mode_value = plan_metadata.get("parser_mode") or (
        "streaming" if module_stats else "legacy"
    )
    metrics["parser_mode"] = parser_mode_value
    resource_count_value = plan_metadata.get("resource_count")
    if resource_count_value is not None:
        metrics["resource_count"] = resource_count_value
    payload["metrics"] = metrics

    risk_result = legacy.compute_plan_risk_profile(
        severity_summary=severity_summary,
        metrics=metrics,
        suspicious_defaults=suspicious_reasons,
    )
    payload["plan_risk_profile"] = risk_result["profile"]
    if risk_result["factors"]:
        payload["plan_risk_factors"] = risk_result["factors"]

    payload["security_grade"] = legacy.compute_security_grade(score, severity_summary)

    explanation_block = None
    if options.explain:
        explanation_block = legacy.build_explanation(
            status=status,
            plan_metadata=plan_metadata,
            smell_report=smell_report,
            metrics=metrics,
            severity_summary=severity_summary,
            violations=violations,
            policies=policies,
            iam_drift=iam_drift_report,
        )
        payload["explanation"] = explanation_block

    preview_manifest_data = None
    if options.preview_vectorguard:
        try:
            preview_manifest_data = legacy._inject_preview_metadata(payload)
        except legacy.PreviewManifestError as exc:
            raise NormalizationError(f"Preview manifest error: {exc}", EXIT_CONFIG_ERROR)
        exit_code = EXIT_PREVIEW_MODE

    environment_snapshot = legacy._build_environment_metadata(
        strict_mode=strict_mode,
        offline_mode=offline_mode,
        terraform_report=terraform_report,
        vectorscan_version_value=str(payload.get("vectorscan_version", legacy.VECTORSCAN_VERSION)),
    )
    environment_snapshot["allow_network_capture"] = bool(control_flags.get("allow_network_capture"))
    environment_snapshot["allow_network"] = bool(
        control_flags.get("allow_network")
        if "allow_network" in control_flags
        else control_flags.get("allow_network_capture")
    )
    environment_snapshot = dict(sorted(environment_snapshot.items()))
    payload["environment"] = environment_snapshot
    canonical_issues = _canonical_issues_for_payload(flattened_ctx.get("issues"))
    payload["issues"] = canonical_issues
    remediation_ledger = _build_remediation_ledger(canonical_issues)
    payload["remediation_ledger"] = remediation_ledger
    evaluation_block_snapshot = flattened_ctx.get("evaluation")
    if isinstance(evaluation_block_snapshot, dict):
        audit_block = evaluation_block_snapshot.get("audit_ledger")
        if isinstance(audit_block, dict):
            audit_block["remediation_summary"] = deepcopy(remediation_ledger["remediation_summary"])
            audit_block["remediation_rule_index"] = list(remediation_ledger["remediation_rule_index"])
            audit_block["remediation_metadata_aggregate"] = deepcopy(
                remediation_ledger["remediation_metadata_aggregate"]
            )

    _attach_canonical_schema_fields(
        payload,
        plan_metadata=plan_metadata,
        environment=payload.get("environment"),
        severity_summary=severity_summary,
        quick_score_mode=quick_score_mode,
        latency_ms=latency_ms,
        control_flags=control_flags,
    )

    return NormalizationResult(
        payload=payload,
        exit_code=exit_code,
        severity_summary=severity_summary,
        policy_errors=policy_errors,
        violations=violations,
        terraform_report=terraform_report,
        resource_scope=resource_scope,
        explanation_block=explanation_block,
        plan_diff_block=plan_diff_block,
        preview_manifest_data=preview_manifest_data,
        use_color=use_color,
        evaluation=flattened_ctx.get("evaluation"),
    )


def _load_plan_context(
    flattened_plan: Dict[str, Any],
    flattened_resources: List[Dict[str, Any]],
    source_path: Optional[Path],
) -> tuple[Dict[str, Any], List[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Any]]:
    plan_limits: Optional[Dict[str, Any]] = None
    module_stats: Optional[Any] = None
    if source_path and source_path.exists():
        try:
            _, _, plan_limits, module_stats = legacy.load_plan_context(source_path)
        except legacy._PlanLoadError:  # type: ignore[attr-defined]
            raise NormalizationError("Failed to load plan context.", EXIT_INVALID_INPUT)
    return flattened_plan, flattened_resources, plan_limits, module_stats


def _normalize_resource_changes(raw_changes: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_changes, list):
        return []
    filtered: List[Dict[str, Any]] = [entry for entry in raw_changes if isinstance(entry, dict)]
    filtered.sort(key=_resource_change_sort_key)
    return filtered


def _normalize_module_tree(
    module: Dict[str, Any],
    fallback_address: str,
    collected: List[Dict[str, Any]],
) -> Dict[str, Any]:
    module_address = _normalize_module_address(module.get("address"), fallback_address)
    module["address"] = module_address

    resources = module.get("resources")
    normalized_resources: List[Dict[str, Any]] = []
    if isinstance(resources, list):
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            _assign_resource_metadata(resource, module_address)
            normalized_resources.append(resource)
            collected.append(resource)
    normalized_resources.sort(key=_resource_local_sort_key)
    module["resources"] = normalized_resources

    child_modules = module.get("child_modules")
    normalized_children: List[Dict[str, Any]] = []
    if isinstance(child_modules, list):
        for idx, child in enumerate(child_modules):
            if not isinstance(child, dict):
                continue
            normalized_children.append(
                _normalize_module_tree(child, _child_module_address(module_address, idx), collected)
            )
    normalized_children.sort(key=lambda data: _safe_str(data.get("address")))
    module["child_modules"] = normalized_children
    return module


def _should_enable_quick_score(
    resource_count: Any,
    raw_size: Optional[int],
    source_path: Optional[Path],
) -> bool:
    try:
        count_value = int(resource_count)
    except (TypeError, ValueError):
        count_value = 0
    if count_value > 1000:
        return True

    size_bytes = raw_size
    if size_bytes is None and source_path and source_path.exists():
        try:
            size_bytes = source_path.stat().st_size
        except OSError:
            size_bytes = None
    if size_bytes is None:
        return False
    return size_bytes > 40 * 1024 * 1024


def _normalize_iam_drift_report(report: Dict[str, Any]) -> Dict[str, Any]:
    status_value = _safe_str(report.get("status")) or "PASS"
    counts_raw = report.get("counts") or {}
    risky_changes_value = _safe_int(counts_raw.get("risky_changes"))
    counts_block = {"risky_changes": max(0, risky_changes_value)}

    raw_items = report.get("items") or []
    normalized_items: List[Dict[str, Any]] = []
    for entry in raw_items:
        if not isinstance(entry, dict):
            continue
        normalized_items.append(
            {
                "resource_type": _safe_str(entry.get("resource_type")) or "unknown",
                "resource_name": _safe_str(entry.get("resource_name")) or "<unnamed>",
                "change": _normalize_string_list(entry.get("change")),
                "risky_additions": _normalize_string_list(entry.get("risky_additions"), dedupe=True),
                "severity_by_action": _normalize_string_map(entry.get("severity_by_action")),
                "notaction_broad_allow": bool(entry.get("notaction_broad_allow", False)),
            }
        )
    normalized_items.sort(key=_iam_drift_item_sort_key)

    notes_block: Dict[str, Any] = {"limitations": []}
    notes = report.get("notes")
    if isinstance(notes, dict):
        limitations = notes.get("limitations")
        normalized_limits = _normalize_string_list(limitations, dedupe=True)
        normalized_limits.sort()
        notes_block["limitations"] = normalized_limits

    return {
        "status": status_value,
        "counts": counts_block,
        "items": normalized_items,
        "notes": notes_block,
    }


def _assign_resource_metadata(resource: Dict[str, Any], module_address: str) -> None:
    module_label = module_address or "root"
    r_type = _safe_str(resource.get("type")) or "unknown"
    r_name = _safe_str(resource.get("name")) or "unnamed"
    resource["module_address"] = module_label
    resource["resource_type"] = r_type
    resource["resource_name"] = r_name
    address_value = resource.get("address")
    if not isinstance(address_value, str) or not address_value.strip():
        resource["address"] = _build_resource_address(module_label, r_type, r_name)
    provider_token = _normalize_provider_token(resource.get("provider_name") or resource.get("provider"))
    if not provider_token:
        provider_token = _normalize_provider_token(resource.get("provider_config_key"))
    if provider_token:
        resource["provider_type"] = provider_token


def _normalize_provider_token(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    token = value.strip().strip('"')
    if not token:
        return None
    if token.startswith("provider["):
        token = token[len("provider[") :]
        if token.endswith("]"):
            token = token[:-1]
        token = token.strip('"')
    if token.startswith("registry.terraform.io/"):
        token = token.split("/")[-1]
    if "/" in token:
        token = token.split("/")[-1]
    token = token.strip()
    if not token:
        return None
    return token.lower()


def _normalize_module_address(candidate: Any, fallback: str) -> str:
    if isinstance(candidate, str):
        trimmed = candidate.strip()
        if trimmed:
            return trimmed
    return fallback


def _child_module_address(parent_address: str, index: int) -> str:
    base = parent_address or "root"
    if base == "root":
        return f"root.child[{index}]"
    return f"{base}.child[{index}]"


def _build_resource_address(module_address: str, r_type: str, r_name: str) -> str:
    leaf = f"{r_type}.{r_name}" if r_type else r_name or "resource"
    if module_address and module_address != "root":
        return f"{module_address}.{leaf}"
    return leaf


def _resource_local_sort_key(resource: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        _safe_str(resource.get("module_address")),
        _safe_str(resource.get("resource_type")),
        _safe_str(resource.get("resource_name")),
    )


def _resource_sort_tuple(resource: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        _safe_str(resource.get("module_address")),
        _safe_str(resource.get("resource_type")),
        _safe_str(resource.get("resource_name")),
        _safe_str(resource.get("address")),
    )


def _resource_sort_key(resource: Dict[str, Any]) -> Tuple[str, str, str]:
    address = resource.get("address")
    if not isinstance(address, str):
        address = ""
    r_type = resource.get("type")
    if not isinstance(r_type, str):
        r_type = ""
    name = resource.get("name")
    if not isinstance(name, str):
        name = ""
    return (address.lower(), r_type.lower(), name.lower())


def _resource_change_sort_key(change: Dict[str, Any]) -> Tuple[str, str, str]:
    address = change.get("address")
    if not isinstance(address, str):
        address = ""
    r_type = change.get("type")
    if not isinstance(r_type, str):
        r_type = ""
    name = change.get("name")
    if not isinstance(name, str):
        name = ""
    return (address.lower(), r_type.lower(), name.lower())


def _safe_str(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if value is None:
        return ""
    return str(value).strip()


def _normalize_string_list(value: Any, *, dedupe: bool = False) -> List[str]:
    entries: List[str] = []
    if isinstance(value, (list, tuple, set)):
        iterable = value
    elif isinstance(value, str):
        iterable = [value]
    else:
        return []
    seen: Set[str] = set()
    for item in iterable:
        token = _safe_str(item)
        if not token:
            continue
        if dedupe:
            if token in seen:
                continue
            seen.add(token)
        entries.append(token)
    entries.sort()
    return entries


def _normalize_string_map(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    normalized: Dict[str, str] = {}
    for key in sorted(value.keys(), key=lambda k: _safe_str(k)):
        normalized_key = _safe_str(key)
        if not normalized_key:
            continue
        normalized[normalized_key] = _safe_str(value[key]) or ""
    return normalized


def _canonical_issues_for_payload(raw_issues: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_issues, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for issue in raw_issues:
        normalized_issue = _normalize_issue_dict(issue)
        if normalized_issue is not None:
            normalized.append(normalized_issue)
    normalized.sort(key=_issue_sort_key)
    return normalized


def _normalize_issue_dict(issue: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(issue, dict):
        return None
    normalized: Dict[str, Any] = {}
    issue_id = _safe_str(issue.get("id")) or "PILLAR-UNKNOWN"
    severity_value = _safe_str(issue.get("severity")).lower() or "low"
    if severity_value not in _SEVERITY_RANK:
        severity_value = "low"
    normalized["id"] = issue_id
    normalized["severity"] = severity_value
    normalized["title"] = _safe_str(issue.get("title")) or ""
    normalized["description"] = _safe_str(issue.get("description")) or ""
    normalized["resource_address"] = _safe_str(issue.get("resource_address"))

    for field in ISSUE_REQUIRED_FIELDS:
        if field in normalized:
            continue
        value = issue.get(field)
        if field in _ISSUE_DICT_FIELDS:
            normalized[field] = deepcopy(value) if isinstance(value, dict) else {}
        else:
            normalized[field] = _safe_str(value)

    normalized["attributes"] = _normalize_issue_attributes(issue_id, issue.get("attributes"))
    normalized["remediation_hint"] = _safe_str(issue.get("remediation_hint")) or ""
    normalized["remediation_difficulty"] = _safe_str(issue.get("remediation_difficulty")) or "low"
    normalized["remediation_metadata"] = {}
    return normalized


def _normalize_issue_attributes(issue_id: str, attributes: Any) -> Dict[str, Any]:
    if isinstance(attributes, dict):
        normalized = deepcopy(attributes)
    else:
        normalized = {}
    normalized.setdefault("rule_id", issue_id)
    return normalized


def _issue_sort_key(issue: Dict[str, Any]) -> Tuple[int, str, str]:
    severity_rank = _SEVERITY_RANK.get(str(issue.get("severity", "")).lower(), len(_SEVERITY_RANK))
    issue_id = _safe_str(issue.get("id"))
    resource_address = _safe_str(issue.get("resource_address"))
    return (severity_rank, issue_id, resource_address)


def _attach_canonical_schema_fields(
    payload: Dict[str, Any],
    *,
    plan_metadata: Any,
    environment: Any,
    severity_summary: Any,
    quick_score_mode: bool,
    latency_ms: int,
    control_flags: Optional[Dict[str, Any]] = None,
) -> None:
    metadata_block = _build_metadata_block(plan_metadata, environment, control_flags)
    severity_totals = _coerce_severity_totals(severity_summary)

    payload["pillar"] = pillar_constants.PILLAR_NAME
    payload["guardscore_rules_version"] = pillar_constants.GUARDSCORE_RULES_VERSION
    payload["canonical_schema_version"] = pillar_constants.CANONICAL_SCHEMA_VERSION
    payload["badge_eligible"] = _compute_badge_eligibility(payload.get("status"), severity_totals)
    payload["quick_score_mode"] = bool(quick_score_mode)
    payload["latency_ms"] = max(int(latency_ms), 0)
    payload["metadata"] = metadata_block
    payload["severity_totals"] = severity_totals
    if "schema_validation_error" not in payload:
        payload["schema_validation_error"] = None


def _build_metadata_block(
    plan_metadata: Any,
    environment: Any,
    control_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    plan_block = deepcopy(plan_metadata) if isinstance(plan_metadata, dict) else {}
    environment_block = deepcopy(environment) if isinstance(environment, dict) else {}
    control_block: Dict[str, Any] = {}
    if isinstance(control_flags, dict):
        control_block = {
            "auto_download": bool(control_flags.get("auto_download")),
            "allow_network_capture": bool(control_flags.get("allow_network_capture")),
            "offline_mode": bool(control_flags.get("offline_mode")),
            "allow_network": bool(
                control_flags.get("allow_network")
                if "allow_network" in control_flags
                else control_flags.get("allow_network_capture")
            ),
        }
        if "terraform_outcome" in control_flags:
            control_block["terraform_outcome"] = control_flags["terraform_outcome"]

    if environment_block:
        environment_block = dict(sorted(environment_block.items()))
    if control_block:
        control_block = dict(sorted(control_block.items()))

    metadata_items = [
        ("environment", environment_block),
        ("plan", plan_block),
    ]
    if control_block:
        metadata_items.append(("control", control_block))

    ordered_metadata: Dict[str, Any] = {}
    for key, value in sorted(metadata_items, key=lambda item: item[0]):
        ordered_metadata[key] = value
    return ordered_metadata


def _coerce_severity_totals(summary: Any) -> Dict[str, int]:
    totals: Dict[str, int] = {}
    for level in legacy.SEVERITY_LEVELS:
        value = 0
        if isinstance(summary, dict) and level in summary:
            try:
                value = int(summary[level])
            except (TypeError, ValueError):
                value = 0
        totals[level] = max(value, 0)
    return totals


def _compute_badge_eligibility(status_value: Any, severity_totals: Dict[str, int]) -> bool:
    status_label = _safe_str(status_value).upper()
    if status_label != "PASS":
        return False
    for level in legacy.SEVERITY_LEVELS:
        if severity_totals.get(level, 0) > 0:
            return False
    return True


def _iam_drift_item_sort_key(entry: Dict[str, Any]) -> Tuple[str, str]:
    return (
        _safe_str(entry.get("resource_type")),
        _safe_str(entry.get("resource_name")),
    )


def _build_audit_ledger_entry(context: Dict[str, Any]) -> Dict[str, Any]:
    evaluation_value = context.get("evaluation")
    evaluation: Dict[str, Any] = evaluation_value if isinstance(evaluation_value, dict) else {}
    summary_candidate = evaluation.get("severity_summary") if evaluation else None
    severity_summary = summary_candidate if isinstance(summary_candidate, dict) else None
    if severity_summary is None:
        severity_summary = {level: 0 for level in legacy.SEVERITY_LEVELS}
    plan_metadata = context.get("plan_metadata") if isinstance(context.get("plan_metadata"), dict) else {}
    environment_meta = context.get("environment") if isinstance(context.get("environment"), dict) else {}
    iam_drift = context.get("iam_drift") if isinstance(context.get("iam_drift"), dict) else {}
    raw_issues = context.get("issues")
    issues: List[Any] = raw_issues if isinstance(raw_issues, list) else []
    canonical_issues = _canonical_issues_for_payload(issues)
    normalized_violations = _normalize_ledger_violations(canonical_issues)
    remediation_summary = _build_remediation_ledger(canonical_issues)
    total_violations = sum(int(value) for value in severity_summary.values())

    return {
        "timestamp": deterministic_isoformat(),
        "environment": context.get("environment_label", "vectorscan"),
        "input_file": context.get("source_path", "-"),
        "environment_metadata": _ledger_environment(environment_meta),
        "plan_metadata": deepcopy(plan_metadata),
        "policy_errors": [],
        "violations": normalized_violations,
        "violation_severity_summary": deepcopy(severity_summary),
        "remediation_summary": remediation_summary["remediation_summary"],
        "remediation_rule_index": remediation_summary["remediation_rule_index"],
        "remediation_metadata_aggregate": remediation_summary["remediation_metadata_aggregate"],
        "smell_report": {},
        "audit_status": "NON_COMPLIANT" if total_violations else "PASS",
        "overall_score": None,
        "evidence": {"iam_drift": _ledger_evidence(iam_drift)},
        "terraform_test_results": {"status": "not_run"},
    }


def _ledger_environment(environment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(environment, dict):
        return {}
    allowed = {
        "platform",
        "platform_release",
        "python_version",
        "python_implementation",
        "terraform_version",
        "terraform_source",
        "strict_mode",
        "offline_mode",
    }
    return {key: environment.get(key) for key in allowed if key in environment}


def _ledger_evidence(iam_drift_report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(iam_drift_report, dict):
        return []
    items = iam_drift_report.get("items")
    if not isinstance(items, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for record in items:
        if not isinstance(record, dict):
            continue
        normalized.append(  # brief evidence suitable for audit YAML
            {
                "resource_type": _safe_str(record.get("resource_type")) or "unknown",
                "resource_name": _safe_str(record.get("resource_name")) or "resource",
                "risky_additions": _normalize_string_list(record.get("risky_additions")),
            }
        )
    normalized.sort(key=lambda entry: (entry["resource_type"], entry["resource_name"]))
    return normalized


def _normalize_ledger_violations(issues: List[Any]) -> List[str]:
    normalized: List[str] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        identifier = _safe_str(issue.get("id"))
        if not identifier:
            continue
        normalized.append(identifier)
    normalized.sort()
    return normalized


def _build_remediation_ledger(issues: List[Any]) -> Dict[str, Any]:
    per_severity: Dict[str, int] = {level: 0 for level in legacy.SEVERITY_LEVELS}
    rule_records: Dict[str, Dict[str, Any]] = {}

    for issue in issues:
        if not isinstance(issue, dict):
            continue
        severity = _safe_str(issue.get("severity")).lower() or "low"
        if severity not in per_severity:
            severity = "low"
        per_severity[severity] += 1

        issue_id = _safe_str(issue.get("id"))
        if not issue_id or issue_id in rule_records:
            continue
        rule_records[issue_id] = {
            "severity": severity,
            "remediation_metadata": {},
        }

    ordered_rules = sorted(
        rule_records.items(),
        key=lambda item: (_SEVERITY_RANK.get(item[1]["severity"], len(_SEVERITY_RANK)), item[0]),
    )

    per_severity_ordered = {level: per_severity[level] for level in legacy.SEVERITY_LEVELS}
    rule_ids = [rule_id for rule_id, _ in ordered_rules]
    paths = [
        {
            "id": rule_id,
            "severity": data["severity"],
            "remediation_metadata": data["remediation_metadata"],
        }
        for rule_id, data in ordered_rules
    ]

    metadata_aggregate = {rule_id: data["remediation_metadata"] for rule_id, data in ordered_rules}

    return {
        "per_severity": per_severity_ordered,
        "rule_ids": rule_ids,
        "paths": paths,
        "remediation_summary": dict(per_severity_ordered),
        "remediation_rule_index": list(rule_ids),
        "remediation_metadata_aggregate": metadata_aggregate,
    }


def _format_scope_error(exc: Exception) -> str:
    message = getattr(exc, "message", str(exc))
    suggestions = getattr(exc, "suggestions", None)
    if suggestions:
        joined = ", ".join(suggestions)
        return f"{message}\nDid you mean: {joined}?"
    return message


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _resolve_drift_penalty(flag_value: Optional[int]) -> int:
    if flag_value is not None:
        return int(max(0, min(100, flag_value)))
    try:
        env_value = int(os.getenv("VSCAN_IAM_DRIFT_PENALTY", "20"))
    except (TypeError, ValueError):
        env_value = 20
    return int(max(0, min(100, env_value)))
