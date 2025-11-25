from __future__ import annotations

"""Deterministic rule-engine stubs for ATU-07."""

import json
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Sequence

_ALLOWED_SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_RANK = {level: idx for idx, level in enumerate(_ALLOWED_SEVERITIES)}
_ISSUE_FIELDS = (
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
_DICT_DEFAULT_FIELDS = {"attributes", "remediation_metadata"}


def evaluate_rule(rule_meta: Dict[str, Any], *, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate canonical issues for a single rule based on resource matches."""

    resources = _resolved_resources(context)
    matches = _match_resources(resources, rule_meta.get("match"))
    issues: List[Dict[str, Any]] = []
    for resource in matches:
        issues.append(_build_issue(rule_meta, resource, context))
    return issues


def evaluate_rules(rules: Iterable[Dict[str, Any]], *, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate a collection of rules using the deterministic stub pipeline."""

    issues: List[Dict[str, Any]] = []
    ordered_rules = sorted(rules, key=lambda rule: str(rule.get("id", "")))
    for rule in ordered_rules:
        issues.extend(evaluate_rule(rule, context=context))
    issues.sort(
        key=lambda issue: (
            _SEVERITY_RANK.get(str(issue.get("severity", "")).lower(), len(_SEVERITY_RANK)),
            str(issue.get("id", "")),
            str(issue.get("resource_address", "")),
        )
    )
    return issues


def _build_issue(rule_meta: Dict[str, Any], resource: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    meta = deepcopy(rule_meta)
    issue: Dict[str, Any] = {}
    issue_id = str(meta.get("id") or "PILLAR-STUB-UNSET")
    issue["id"] = issue_id
    severity = str(meta.get("severity") or "medium").lower()
    if severity not in _ALLOWED_SEVERITIES:
        severity = "medium"
    issue["severity"] = severity
    issue["title"] = str(meta.get("title") or "Placeholder issue")
    issue["description"] = str(meta.get("description") or "Pending rule implementation.")
    issue["resource_address"] = _resource_address(resource, fallback=str(meta.get("resource_address") or "vectorscan.placeholder"))

    raw_attributes = meta.get("attributes")
    issue_attributes: Dict[str, Any]
    if isinstance(raw_attributes, dict):
        issue_attributes = dict(raw_attributes)
    else:
        issue_attributes = {}
    issue_attributes.setdefault("rule_id", issue_id)
    issue_attributes.setdefault("stub", True)
    issue_attributes.setdefault("resource_type", resource.get("resource_type"))
    issue_attributes.setdefault("resource_name", resource.get("resource_name"))
    issue_attributes.setdefault("module_address", resource.get("module_address"))
    plan_meta_value = context.get("plan_metadata")
    plan_meta = plan_meta_value if isinstance(plan_meta_value, dict) else {}
    resource_count = plan_meta.get("resource_count")
    if isinstance(resource_count, int):
        issue_attributes.setdefault("resource_count", resource_count)
    issue["attributes"] = issue_attributes

    issue["remediation_hint"] = str(meta.get("remediation_hint") or "")
    difficulty = str(meta.get("remediation_difficulty") or "medium")
    issue["remediation_difficulty"] = difficulty
    metadata_value = meta.get("remediation_metadata")
    issue["remediation_metadata"] = dict(metadata_value) if isinstance(metadata_value, dict) else {}

    for field in _ISSUE_FIELDS:
        if field not in issue:
            issue[field] = {} if field in _DICT_DEFAULT_FIELDS else ""
    return issue


def _resolved_resources(context: Dict[str, Any]) -> Sequence[Dict[str, Any]]:
    resources = context.get("resources")
    if isinstance(resources, list):
        normalized = [res for res in resources if isinstance(res, dict)]
        normalized.sort(key=lambda res: str(res.get("address", "")))
        return normalized
    return []


def _match_resources(resources: Sequence[Dict[str, Any]], match_meta: Any) -> List[Dict[str, Any]]:
    if not isinstance(match_meta, dict):
        match_meta = {}
    resource_type = str(match_meta.get("resource_type") or "").strip()
    required_attribute = match_meta.get("required_attribute")
    attr_requirements = match_meta.get("attributes") if isinstance(match_meta.get("attributes"), dict) else {}
    flag_requirements = match_meta.get("flags") if isinstance(match_meta.get("flags"), dict) else {}
    matches: List[Dict[str, Any]] = []
    for resource in resources:
        if resource_type and resource.get("resource_type") != resource_type:
            continue
        if required_attribute and not _has_attribute(resource, required_attribute):
            continue
        if attr_requirements and not _match_attributes(resource, attr_requirements):
            continue
        if flag_requirements and not _match_flags(resource, flag_requirements):
            continue
        matches.append(resource)
    return matches


def _match_attributes(resource: Dict[str, Any], required: Dict[str, Any]) -> bool:
    for key, expected in required.items():
        actual = resource.get(key)
        if actual is None:
            values_block = resource.get("values")
            if isinstance(values_block, dict):
                actual = values_block.get(key)
        if str(actual) != str(expected):
            return False
    return True


def _match_flags(resource: Dict[str, Any], required: Dict[str, Any]) -> bool:
    for name, expected in required.items():
        actual = _resource_flag_value(resource, name)
        if bool(actual) != bool(expected):
            return False
    return True


def _resource_flag_value(resource: Dict[str, Any], flag_name: str) -> bool:
    flags_block = resource.get("flags")
    if isinstance(flags_block, dict) and flag_name in flags_block:
        return bool(flags_block.get(flag_name))
    computed = _compute_flags(resource)
    return bool(computed.get(flag_name))


def _compute_flags(resource: Dict[str, Any]) -> Dict[str, Any]:
    values_raw = resource.get("values")
    values = values_raw if isinstance(values_raw, dict) else {}
    tags_raw = values.get("tags")
    tags = tags_raw if isinstance(tags_raw, dict) else {}
    ingress_raw = values.get("ingress")
    ingress = ingress_raw if isinstance(ingress_raw, list) else []
    resource_type = str(resource.get("resource_type") or resource.get("type") or "")
    policy_value = values.get("policy") or values.get("document")
    versioning_value = values.get("versioning")
    encryption_block = values.get("server_side_encryption_configuration")
    return {
        "is_managed": resource.get("mode") == "managed",
        "has_missing_tags": not (tags.get("CostCenter") and tags.get("Project")),
        "allows_0_0_0_0": _ingress_allows_any(ingress),
        "iam_policy_wildcard": _policy_has_wildcards(policy_value),
        "s3_encryption_disabled": _s3_encryption_disabled(resource_type, values, encryption_block),
        "s3_versioning_disabled": _s3_versioning_disabled(versioning_value),
    }


def _ingress_allows_any(ingress_rules: Sequence[Any]) -> bool:
    for rule in ingress_rules:
        if not isinstance(rule, dict):
            continue
        cidr_blocks = rule.get("cidr_blocks")
        if isinstance(cidr_blocks, list) and any(cidr == "0.0.0.0/0" for cidr in cidr_blocks):
            return True
    return False


def _policy_has_wildcards(policy_value: Any) -> bool:
    if policy_value is None:
        return False
    if isinstance(policy_value, str):
        text = policy_value
    else:
        try:
            text = json.dumps(policy_value)
        except (TypeError, ValueError):
            return False
    lowered = text.lower()
    return "\"*\"" in lowered or "action\":\"*" in lowered or "action\":['*']" in lowered


def _s3_encryption_disabled(resource_type: str, values: Dict[str, Any], encryption_block: Any) -> bool:
    if resource_type != "aws_s3_bucket":
        return False
    if encryption_block:
        return False
    if values.get("bucket_encryption"):
        return False
    if values.get("kms_master_key_id") or values.get("kms_key_id"):
        return False
    return True


def _s3_versioning_disabled(versioning_value: Any) -> bool:
    if isinstance(versioning_value, list):
        versioning_value = versioning_value[0] if versioning_value else {}
    if isinstance(versioning_value, dict):
        status = versioning_value.get("status")
        if isinstance(status, str):
            return status.strip().lower() not in {"enabled", "enabling", "on"}
        enabled_flag = versioning_value.get("enabled")
        if enabled_flag is None:
            return True
        return not bool(enabled_flag)
    if versioning_value is None:
        return True
    return not bool(versioning_value)


def _has_attribute(resource: Dict[str, Any], attribute_name: str) -> bool:
    value = resource.get(attribute_name)
    if value:
        return True
    values_block = resource.get("values")
    if isinstance(values_block, dict) and values_block.get(attribute_name):
        return True
    return False


def _resource_address(resource: Dict[str, Any], *, fallback: str) -> str:
    candidate = resource.get("address")
    if isinstance(candidate, str) and candidate:
        return candidate
    return fallback
