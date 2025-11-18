from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from tools.vectorscan.constants import SEVERITY_LEVELS
from tools.vectorscan.policies import get_policies
from tools.vectorscan.policies.common import REQUIRED_TAGS, TAGGABLE_TYPES, is_nonempty_string


__all__ = [
    "compute_metrics",
    "compute_violation_severity_summary",
    "check_network_exposure",
    "check_iam_risky_actions",
    "compute_security_grade",
]


def compute_violation_severity_summary(
    violations: List[str], severity_lookup: Dict[str, str] | None = None
) -> Dict[str, int]:
    if severity_lookup is None:
        severity_lookup = {p.metadata.policy_id: p.metadata.severity for p in get_policies()}
    summary: Dict[str, int] = {level: 0 for level in SEVERITY_LEVELS}
    for violation in violations:
        if not isinstance(violation, str):
            continue
        policy_id = violation.split(":", 1)[0].strip()
        severity = severity_lookup.get(policy_id, "medium")
        if severity not in summary:
            summary[severity] = 0
        summary[severity] += 1
    return summary


def check_network_exposure(resources: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """Counts security groups with 0.0.0.0/0 or ::/0 ingress."""
    open_count = 0
    details: List[str] = []
    for r in resources:
        if r.get("type") != "aws_security_group":
            continue
        vals = r.get("values", {}) or {}
        ingress = vals.get("ingress") or []
        name = r.get("name", "<unnamed>")
        try:
            for rule in ingress:
                cidrs = (rule or {}).get("cidr_blocks") or []
                ipv6s = (rule or {}).get("ipv6_cidr_blocks") or []
                if ("0.0.0.0/0" in cidrs) or ("::/0" in ipv6s):
                    open_count += 1
                    details.append(
                        f"aws_security_group '{name}' has open ingress (0.0.0.0/0 or ::/0)"
                    )
                    break
        except (TypeError, AttributeError):
            pass
    return open_count, details


def check_iam_risky_actions(resources: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    risky = 0
    details: List[str] = []
    policy_types = {"aws_iam_policy", "aws_iam_role", "aws_iam_role_policy", "aws_iam_user_policy"}
    risky_terms = (":*", "*", "s3:DeleteObject", "s3:PutObject", "rds:*", "iam:PassRole")
    for r in resources:
        if r.get("type") not in policy_types:
            continue
        vals = r.get("values", {}) or {}
        pol = vals.get("policy")
        if not isinstance(pol, str) or not pol.strip():
            continue
        try:
            pj = json.loads(pol)
        except (json.JSONDecodeError, TypeError):
            if any(t in pol for t in risky_terms):
                risky += 1
                details.append(
                    f"{r.get('type')} '{r.get('name','<unnamed>')}' contains broad or risky actions (string match)"
                )
            continue
        stmts = pj.get("Statement")
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list):
            continue
        found = False
        for s in stmts:
            acts = s.get("Action")
            if isinstance(acts, str):
                acts = [acts]
            if not isinstance(acts, list):
                continue
            for a in acts:
                if isinstance(a, str) and any(t in a for t in risky_terms):
                    found = True
                    break
            if found:
                break
        if found:
            risky += 1
            details.append(
                f"{r.get('type')} '{r.get('name','<unnamed>')}' contains wildcard or high-risk actions"
            )
    return risky, details


def compute_metrics(resources: List[Dict[str, Any]], violations: List[str]) -> Dict[str, Any]:
    violation_count = len(violations)
    enc_targets = [r for r in resources if r.get("type") in {"aws_db_instance", "aws_rds_cluster"}]
    tag_targets = [r for r in resources if r.get("type") in TAGGABLE_TYPES]

    enc_pass = 0
    for r in enc_targets:
        vals = r.get("values", {}) or {}
        if vals.get("storage_encrypted") is True and vals.get("kms_key_id"):
            enc_pass += 1

    tag_pass = 0
    for r in tag_targets:
        tags = (r.get("values", {}) or {}).get("tags") or {}
        if isinstance(tags, dict) and all(is_nonempty_string(tags.get(k)) for k in REQUIRED_TAGS):
            tag_pass += 1

    total_checks = len(enc_targets) + len(tag_targets)
    passed_checks = enc_pass + tag_pass
    compliance_score = 100 if total_checks == 0 else int(round(100 * (passed_checks / total_checks)))

    open_sg_count, open_sg_details = check_network_exposure(resources)
    network_exposure_score = max(0, 100 - min(100, open_sg_count * 25))

    risky_count, risky_details = check_iam_risky_actions(resources)

    return {
        "eligible_checks": total_checks,
        "passed_checks": passed_checks,
        "compliance_score": compliance_score,
        "network_exposure_score": network_exposure_score,
        "open_sg_count": open_sg_count,
        "iam_risky_actions": risky_count,
        "notes": {
            "open_security_groups": open_sg_details,
            "iam_risky_details": risky_details,
            "violation_count": violation_count,
        },
    }


def compute_security_grade(score: Any, severity_summary: Dict[str, int] | None) -> str:
    try:
        numeric_score = int(score)
    except (TypeError, ValueError):
        numeric_score = 0

    if numeric_score >= 90:
        grade = "A"
    elif numeric_score >= 80:
        grade = "B"
    elif numeric_score >= 70:
        grade = "C"
    elif numeric_score >= 60:
        grade = "D"
    else:
        grade = "F"

    summary = severity_summary or {}
    if summary.get("critical"):
        return "F"
    if summary.get("high") and grade in {"A", "B"}:
        return "C"
    return grade
