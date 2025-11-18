"""Reporting and explanation helpers for the VectorScan CLI."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from tools.vectorscan.constants import REMEDIATION_DOCS, SEVERITY_LEVELS
from tools.vectorscan.plan_utils import _format_diff_display
from tools.vectorscan.policies.common import REQUIRED_TAGS, is_nonempty_string


_VIOLATION_RESOURCE_PATTERN = re.compile(r"(?P<rtype>[A-Za-z0-9_\.]+)\s+'(?P<name>[^']+)'")


def _parse_violation_record(violation: str) -> Dict[str, Optional[str]]:
    policy_id = "unknown"
    remainder = violation
    if ":" in violation:
        policy_id, remainder = violation.split(":", 1)
        policy_id = policy_id.strip() or "unknown"
        remainder = remainder.strip()
    match = _VIOLATION_RESOURCE_PATTERN.search(remainder)
    resource = None
    detail = remainder
    resource_type = None
    resource_name = None
    if match:
        resource_type = match.group("rtype")
        resource_name = match.group("name")
        resource = f"{resource_type}.{resource_name}"
        tail = remainder[match.end():].strip()
        if tail:
            detail = tail
    return {
        "policy_id": policy_id,
        "resource": resource,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "detail": detail,
    }


def _looks_like_variable_reference(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    token = value.strip()
    if not token:
        return False
    if token.startswith("${") and token.endswith("}"):
        token = token[2:-1]
    token = token.strip()
    return token.startswith("var.") or token.startswith("module.") or token.startswith("local.") or token.startswith("data.")


def _module_path_from_address(address: Optional[str]) -> str:
    if not isinstance(address, str) or not address:
        return "root"
    modules = [part for part in address.split(".") if part.startswith("module")]
    if not modules:
        return "root"
    return ".".join(modules)


def _compute_encryption_completeness(values: Dict[str, Any]) -> float:
    completeness = 0.6
    if isinstance(values, dict):
        if "storage_encrypted" in values:
            completeness += 0.2
        kms_value = values.get("kms_key_id")
        if is_nonempty_string(kms_value):
            completeness += 0.25 if not _looks_like_variable_reference(kms_value) else 0.15
        else:
            completeness -= 0.05
    return round(min(1.0, max(0.3, completeness)), 2)


def _compute_tagging_completeness(tags: Any) -> float:
    completeness = 0.4
    if isinstance(tags, dict):
        completeness = 1.0
        for tag in REQUIRED_TAGS:
            if not is_nonempty_string(tags.get(tag)):
                completeness -= 0.25
    return round(min(1.0, max(0.25, completeness)), 2)


def _build_encryption_example(resource: Optional[Dict[str, Any]]) -> str:
    r_type = (resource or {}).get("type") or "aws_rds_cluster"
    r_name = (resource or {}).get("name") or "example"
    return (
        f'resource "{r_type}" "{r_name}" {{\n'
        "  storage_encrypted = true\n"
        "  kms_key_id       = \"<kms-key-arn>\"\n"
        "}}"
    )


def _build_tagging_example(resource: Optional[Dict[str, Any]]) -> str:
    r_type = (resource or {}).get("type") or "aws_db_instance"
    r_name = (resource or {}).get("name") or "example"
    return (
        f'resource "{r_type}" "{r_name}" {{\n'
        "  tags = merge(var.default_tags, {\n"
        '    CostCenter = "finops-1234"\n'
        '    Project    = "vectorguard"\n'
        "  })\n"
        "}}"
    )


def _infer_data_taint(policy_id: str, resource: Optional[Dict[str, Any]], parsed: Dict[str, Optional[str]]) -> Tuple[str, str]:
    address = (resource or {}).get("address") or parsed.get("resource") or "resource"
    module_path = _module_path_from_address((resource or {}).get("address"))
    values = (resource or {}).get("values", {}) or {}
    if policy_id == "P-SEC-001":
        kms_value = values.get("kms_key_id")
        if _looks_like_variable_reference(kms_value):
            return "variable_source", f"kms_key_id for {address} references {kms_value}; update the variable or module wiring."
        if not is_nonempty_string(kms_value):
            if module_path != "root":
                return "module_source", f"kms_key_id missing inside {module_path}; extend module outputs/variables."
            return "resource_body", f"Set kms_key_id directly on {address}."
        if values.get("storage_encrypted") is False:
            return "resource_body", f"storage_encrypted is false on {address}."
    elif policy_id == "P-FIN-001":
        tags = values.get("tags") or {}
        missing = [tag for tag in REQUIRED_TAGS if not is_nonempty_string(tags.get(tag))]
        if missing:
            missing_list = ", ".join(missing)
            if module_path != "root":
                return "module_source", f"Tags {missing_list} missing within {module_path}; update module locals or variables."
            return "resource_body", f"Tags {missing_list} missing on {address}."
        if tags:
            return "resource_body", f"Verify tag inheritance for {address}."
    return "unknown", f"No taint inference available for {address}."


def _build_remediation_block(policy_id: str, resource: Optional[Dict[str, Any]], parsed: Dict[str, Optional[str]]) -> Dict[str, Any]:
    address = (resource or {}).get("address") or parsed.get("resource") or "resource"
    values = (resource or {}).get("values") or {}
    docs = list(
        REMEDIATION_DOCS.get(
            policy_id,
            [
                "https://docs.aws.amazon.com/config/latest/developerguide/",
                "https://vectorguard.dev/docs/vectorscan",
            ],
        )
    )
    if policy_id == "P-SEC-001":
        summary = f"Enable encryption and configure kms_key_id for {address}."
        hcl_examples = [_build_encryption_example(resource)]
        completeness = _compute_encryption_completeness(values)
    elif policy_id == "P-FIN-001":
        summary = f"Populate CostCenter and Project tags for {address}."
        tags = values.get("tags") if isinstance(values, dict) else {}
        hcl_examples = [_build_tagging_example(resource)]
        completeness = _compute_tagging_completeness(tags)
    else:
        summary = f"Resolve {policy_id} findings on {address}."
        hcl_examples = [f"# Update {address} to satisfy {policy_id}"]
        completeness = 0.5
    return {
        "summary": summary,
        "hcl_examples": hcl_examples,
        "docs": docs,
        "hcl_completeness": completeness,
    }


def _build_resource_details(resource: Optional[Dict[str, Any]], parsed: Dict[str, Optional[str]]) -> Dict[str, Any]:
    address = (resource or {}).get("address") or parsed.get("resource")
    details = {
        "address": address,
        "type": (resource or {}).get("type") or parsed.get("resource_type"),
        "name": (resource or {}).get("name") or parsed.get("resource_name"),
        "module_path": _module_path_from_address((resource or {}).get("address")),
    }
    taint, explanation = _infer_data_taint(parsed.get("policy_id") or "unknown", resource, parsed)
    details["data_taint"] = taint
    details["taint_explanation"] = explanation
    return details


def _build_resource_lookup(resources: Sequence[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    lookup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for res in resources:
        r_type = res.get("type")
        r_name = res.get("name")
        if isinstance(r_type, str) and isinstance(r_name, str):
            lookup[(r_type, r_name)] = res
    return lookup


def build_violation_structs(
    *,
    violations: Sequence[str],
    resources: Sequence[Dict[str, Any]],
    severity_lookup: Dict[str, str],
    policy_metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    lookup = _build_resource_lookup(resources)
    structured: List[Dict[str, Any]] = []
    for violation in violations:
        if not isinstance(violation, str):
            continue
        parsed = _parse_violation_record(violation)
        resource = None
        r_type = parsed.get("resource_type")
        r_name = parsed.get("resource_name")
        if isinstance(r_type, str) and isinstance(r_name, str):
            resource = lookup.get((r_type, r_name))
        policy_id = parsed.get("policy_id", "") or "unknown"
        metadata = policy_metadata.get(policy_id)
        details = _build_resource_details(resource, parsed)
        structured.append(
            {
                "policy_id": policy_id,
                "policy_name": getattr(metadata, "name", None) if metadata else None,
                "message": violation,
                "severity": severity_lookup.get(policy_id, "medium"),
                "resource": details.get("address"),
                "resource_details": details,
                "remediation": _build_remediation_block(policy_id, resource, parsed),
            }
        )
    return structured


def build_explanation(
    *,
    status: str,
    plan_metadata: Dict[str, Any],
    smell_report: Optional[Dict[str, Any]],
    metrics: Dict[str, Any],
    severity_summary: Dict[str, int],
    violations: List[str],
    policies: List[Any],
    iam_drift: Dict[str, Any],
) -> Dict[str, Any]:
    smell_report = smell_report or {}
    providers = plan_metadata.get("providers") or []
    resource_count = plan_metadata.get("resource_count", 0)
    module_count = plan_metadata.get("module_count", 0)
    modules_info = plan_metadata.get("modules", {}) or {}
    modules_with_resources = modules_info.get("with_resources", 0)
    child_module_count = modules_info.get("child_module_count", 0)
    provider_label = ", ".join(sorted(providers)) if providers else "unspecified"
    resource_word = "resource" if resource_count == 1 else "resources"
    module_word = "module" if module_count == 1 else "modules"
    child_phrase = "no child modules" if child_module_count == 0 else f"{child_module_count} child {'module' if child_module_count == 1 else 'modules'}"
    plan_narrative = (
        f"Plan defines {resource_count} {resource_word} across {module_count} {module_word} "
        f"(providers: {provider_label}; modules with resources: {modules_with_resources}; {child_phrase})."
    )
    smell_summary = smell_report.get("summary") if smell_report else None
    smell_level = smell_report.get("level") if smell_report else None

    compliance_score = metrics.get("compliance_score")
    network_score = metrics.get("network_exposure_score")
    iam_risky_actions = metrics.get("iam_risky_actions")
    eligible_checks = metrics.get("eligible_checks")
    passed_checks = metrics.get("passed_checks")

    scores_block = {
        "compliance_score": compliance_score,
        "network_exposure_score": network_score,
        "iam_risky_actions": iam_risky_actions,
        "eligible_checks": eligible_checks,
        "passed_checks": passed_checks,
    }

    severity_line = ", ".join(f"{level}={severity_summary.get(level, 0)}" for level in SEVERITY_LEVELS)

    drift_status = (iam_drift.get("status") or "PASS").upper()
    risky_changes = iam_drift.get("counts", {}).get("risky_changes", 0)
    drift_summary = f"IAM drift {drift_status} ({risky_changes} risky change{'s' if risky_changes != 1 else ''})."

    summary = (
        f"{status} scan – compliance score {compliance_score if compliance_score is not None else 'unknown'}/100, "
        f"severity counts [{severity_line}], {drift_summary.rstrip('.')}"
    )

    policy_context = []
    for policy in sorted(policies, key=lambda p: p.metadata.policy_id):
        meta = policy.metadata
        policy_context.append(
            {
                "policy_id": meta.policy_id,
                "name": meta.name,
                "severity": meta.severity,
                "description": meta.description,
            }
        )
    policy_meta_lookup = {entry["policy_id"]: entry for entry in policy_context}

    risk_highlights: List[Dict[str, Any]] = []
    for violation in violations:
        parsed = _parse_violation_record(violation)
        meta = policy_meta_lookup.get(parsed["policy_id"], {})
        risk_highlights.append(
            {
                "policy_id": parsed.get("policy_id"),
                "policy_name": meta.get("name"),
                "resource": parsed.get("resource"),
                "severity": meta.get("severity", "unknown"),
                "summary": parsed.get("detail"),
            }
        )

    recommendations: List[str] = []
    if risk_highlights:
        seen: Set[tuple[str, str]] = set()
        for item in risk_highlights:
            resource_label = item.get("resource") or "plan"
            policy_id = item.get("policy_id") or "unknown"
            key = (policy_id, resource_label)
            if key in seen:
                continue
            seen.add(key)
            meta = policy_meta_lookup.get(policy_id, {})
            description = meta.get("description") or (item.get("summary") or "Resolve guardrail finding")
            policy_name = meta.get("name") or "Unknown policy"
            recommendations.append(
                f"Remediate {resource_label} to satisfy {policy_id} ({policy_name}): {description}"
            )
    else:
        guardrail_titles = ", ".join(f"{entry['policy_id']} {entry['name']}" for entry in policy_context)
        if guardrail_titles:
            recommendations.append(
                f"Plan currently satisfies {guardrail_titles}; maintain encryption and tagging coverage as modules evolve."
            )

    explanation = {
        "summary": summary,
        "plan_overview": {
            "narrative": plan_narrative,
            "resource_count": resource_count,
            "module_count": module_count,
            "providers": sorted(providers),
            "modules_with_resources": modules_with_resources,
            "child_module_count": child_module_count,
            "has_child_modules": modules_info.get("has_child_modules", False),
            "smell_summary": smell_summary,
            "smell_level": smell_level,
        },
        "scores": scores_block,
        "risk_highlights": risk_highlights,
        "iam_drift": {
            "summary": drift_summary,
            "status": drift_status,
            "risky_change_count": risky_changes,
        },
        "recommendations": recommendations,
        "policy_context": policy_context,
    }
    if smell_report:
        explanation["plan_smells"] = smell_report
    return explanation


def render_explanation_text(explanation: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("VectorScan Explain Report")
    lines.append("-------------------------")
    lines.append(explanation.get("summary", ""))
    lines.append("")

    overview = explanation.get("plan_overview", {})
    if overview:
        lines.append(f"Plan overview: {overview.get('narrative', '')}")

    smell_report = explanation.get("plan_smells") or {}
    if smell_report:
        lines.append(
            f"Plan smells ({smell_report.get('level', 'low')}): {smell_report.get('summary', 'n/a')}"
        )
        smell_items = smell_report.get("smells") or []
        for smell in smell_items[:3]:
            lines.append(
                f"  - [{smell.get('level', 'low')}] {smell.get('message', 'Structural smell detected.')}"
            )
    scores = explanation.get("scores", {})
    compliance = scores.get("compliance_score")
    network = scores.get("network_exposure_score")
    iam_actions = scores.get("iam_risky_actions")
    eligible = scores.get("eligible_checks")
    passed = scores.get("passed_checks")
    compliance_display = f"{compliance}/100" if isinstance(compliance, (int, float)) else "unknown"
    network_display = f"{network}/100" if isinstance(network, (int, float)) else "unknown"
    iam_display = str(iam_actions) if iam_actions is not None else "unknown"
    lines.append(
        f"Scores: compliance {compliance_display} (eligible {eligible}/{passed}), network exposure {network_display}, IAM risky actions {iam_display}."
    )

    iam_drift_block = explanation.get("iam_drift", {})
    if iam_drift_block:
        lines.append(f"IAM drift: {iam_drift_block.get('summary', '')}")

    risk_highlights = explanation.get("risk_highlights") or []
    if risk_highlights:
        lines.append("High-risk resources:")
        for item in risk_highlights:
            resource = item.get("resource") or "plan"
            policy_id = item.get("policy_id") or "unknown"
            severity = item.get("severity") or "unknown"
            summary_text = item.get("summary") or "Guardrail triggered"
            lines.append(f"  - {resource} [{policy_id}/{severity}]: {summary_text}")
    else:
        lines.append("High-risk resources: none detected.")

    recommendations = explanation.get("recommendations") or []
    if recommendations:
        lines.append("Recommendations:")
        for rec in recommendations:
            lines.append(f"  - {rec}")

    policy_context = explanation.get("policy_context") or []
    if policy_context:
        lines.append("Guardrails:")
        for policy in policy_context:
            lines.append(
                f"  - {policy.get('policy_id')} ({policy.get('severity')}): {policy.get('description')}"
            )

    return "\n".join(line.rstrip() for line in lines if line is not None)


def render_plan_diff_text(plan_diff: Dict[str, Any]) -> str:
    lines: List[str] = []
    summary = plan_diff.get("summary") or {}
    lines.append("Plan diff (changed attributes)")
    lines.append(
        "Summary: adds={adds}, changes={changes}, destroys={destroys}".format(
            adds=summary.get("adds", 0),
            changes=summary.get("changes", 0),
            destroys=summary.get("destroys", 0),
        )
    )
    resources = plan_diff.get("resources") or []
    if not resources:
        lines.append("No attribute-level changes detected in tfplan.")
        return "\n".join(lines)
    for entry in resources:
        address = entry.get("address") or (entry.get("type") or "resource")
        change_type = entry.get("change_type") or "changes"
        lines.append(f"- {address} ({change_type})")
        attributes = entry.get("changed_attributes") or []
        if not attributes:
            lines.append("    (no attribute deltas recorded)")
            continue
        for attr in attributes:
            path = attr.get("path") or "."
            before = _format_diff_display(attr.get("before"))
            after = _format_diff_display(attr.get("after"))
            lines.append(f"    {path}: {before} -> {after}")
    return "\n".join(lines)


def render_plan_evolution_text(plan_evolution: Dict[str, Any]) -> str:
    lines: List[str] = []
    old_file = (plan_evolution.get("old_plan") or {}).get("file")
    new_file = (plan_evolution.get("new_plan") or {}).get("file")
    header = "Plan Evolution Summary"
    lines.append(header)
    lines.append("-" * len(header))
    if old_file and new_file:
        lines.append(f"Comparing: {old_file} → {new_file}")
    summary_lines = (plan_evolution.get("summary") or {}).get("lines") or []
    for entry in summary_lines:
        lines.append(f"  {entry}")

    downgraded = plan_evolution.get("downgraded_encryption") or {}
    downgraded_resources = downgraded.get("resources") or []
    if downgraded_resources:
        lines.append("")
        lines.append("Downgraded encryption details:")
        for item in downgraded_resources:
            address = item.get("address") or "resource"
            reasons = ", ".join(item.get("reasons") or ["degraded encryption"])
            before = item.get("previous") or {}
            after = item.get("current") or {}
            lines.append(f"  - {address}: {reasons}")
            lines.append(
                f"      storage_encrypted {before.get('storage_encrypted')} → {after.get('storage_encrypted')}"
            )
            lines.append(f"      kms_key_id {before.get('kms_key_id')} → {after.get('kms_key_id')}")
    else:
        lines.append("")
        lines.append("Downgraded encryption: none detected.")
    return "\n".join(line.rstrip() for line in lines if line is not None)


__all__ = [
    "build_violation_structs",
    "build_explanation",
    "render_explanation_text",
    "render_plan_diff_text",
    "render_plan_evolution_text",
]
