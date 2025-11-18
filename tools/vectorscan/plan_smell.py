"""Plan smell analyzer heuristics for VectorScan outputs."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

_SMELL_LEVEL_RANK = {"low": 0, "moderate": 1, "high": 2}
_KMS_REQUIRED_TYPES = {
    "aws_rds_cluster",
    "aws_db_instance",
    "aws_redshift_cluster",
    "aws_docdb_cluster",
    "aws_efs_file_system",
    "aws_opensearch_domain",
    "aws_neptune_cluster",
}
_IAM_POLICY_TYPES = {
    "aws_iam_policy",
    "aws_iam_role",
    "aws_iam_role_policy",
    "aws_iam_group_policy",
    "aws_iam_user_policy",
    "aws_iam_policy_attachment",
}


def _module_depth(address: Optional[str]) -> int:
    if not isinstance(address, str) or not address:
        return 0
    return sum(1 for part in address.split(".") if part.startswith("module"))


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _count_for_each_instances(resources: Sequence[Dict[str, Any]]) -> int:
    count = 0
    for resource in resources:
        address = resource.get("address")
        if isinstance(address, str) and "[" in address:
            count += 1
            continue
        if resource.get("index") is not None or resource.get("index_key") is not None:
            count += 1
    return count


def _collect_kms_gaps(resources: Sequence[Dict[str, Any]]) -> List[str]:
    missing: List[str] = []
    for resource in resources:
        r_type = str(resource.get("type") or "").lower()
        if r_type not in _KMS_REQUIRED_TYPES:
            continue
        values = resource.get("values") or {}
        kms_value = values.get("kms_key_id") or values.get("kms_key_arn")
        if _is_nonempty_string(kms_value):
            continue
        address = resource.get("address") or f"{r_type}.{resource.get('name') or 'resource'}"
        missing.append(str(address))
    return missing


def _summarize_policy_document(doc: Any) -> Optional[Dict[str, int]]:
    if doc is None:
        return None
    parsed = None
    raw_length = 0
    if isinstance(doc, str):
        raw_length = len(doc)
        try:
            parsed = json.loads(doc)
        except json.JSONDecodeError:
            parsed = None
    elif isinstance(doc, dict):
        parsed = doc
        raw_length = len(json.dumps(doc, sort_keys=True))
    if parsed is None:
        return {"statements": 0, "actions": 0, "length": raw_length}
    statements = parsed.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        statements = []
    statement_count = len(statements)
    action_count = 0
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        actions = stmt.get("Action") or stmt.get("NotAction")
        if isinstance(actions, str):
            action_count += 1
        elif isinstance(actions, list):
            action_count += sum(1 for value in actions if _is_nonempty_string(value))
    return {
        "statements": statement_count,
        "actions": action_count,
        "length": raw_length,
    }


def _filter_resource_changes(
    resource_changes: Sequence[Dict[str, Any]],
    resource_filter: Optional[Set[str]],
) -> List[Dict[str, Any]]:
    if not resource_filter:
        return list(resource_changes)
    scoped: List[Dict[str, Any]] = []
    for change in resource_changes:
        address = change.get("address")
        if isinstance(address, str) and address in resource_filter:
            scoped.append(change)
    return scoped


def _analyze_iam_documents(
    resource_changes: Sequence[Dict[str, Any]],
    resource_filter: Optional[Set[str]],
) -> Tuple[int, int, int]:
    scoped_changes = _filter_resource_changes(resource_changes, resource_filter)
    max_statements = 0
    max_actions = 0
    max_length = 0
    for rc in scoped_changes:
        r_type = str(rc.get("type") or "").lower()
        if r_type not in _IAM_POLICY_TYPES:
            continue
        change = rc.get("change") or {}
        after = change.get("after") or {}
        policy_doc = after.get("policy")
        summary = _summarize_policy_document(policy_doc)
        if not summary:
            continue
        max_statements = max(max_statements, summary.get("statements", 0))
        max_actions = max(max_actions, summary.get("actions", 0))
        max_length = max(max_length, summary.get("length", 0))
    return max_statements, max_actions, max_length


def _aggregate_level(smells: Sequence[Dict[str, Any]]) -> str:
    highest = "low"
    for smell in smells:
        level = smell.get("level")
        if level not in _SMELL_LEVEL_RANK:
            continue
        if _SMELL_LEVEL_RANK[level] > _SMELL_LEVEL_RANK[highest]:
            highest = level
    if smells and highest == "low":
        return "moderate"
    return highest


def _build_summary(smells: Sequence[Dict[str, Any]]) -> str:
    if not smells:
        return "No structural smells detected."
    labels = ", ".join(sorted({smell.get("id", "smell") for smell in smells}))
    count = len(smells)
    plural = "s" if count != 1 else ""
    return f"{count} structural smell{plural} detected ({labels})"


def compute_smell_report(
    *,
    plan_metadata: Optional[Dict[str, Any]],
    resources: Optional[Sequence[Dict[str, Any]]],
    resource_changes: Optional[Sequence[Dict[str, Any]]] = None,
    resource_filter: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    plan_metadata = plan_metadata or {}
    resources = list(resources or [])
    resource_changes = list(resource_changes or [])

    max_depth = 0
    for resource in resources:
        max_depth = max(max_depth, _module_depth(resource.get("address")))
    for_each_instances = _count_for_each_instances(resources)
    kms_missing = _collect_kms_gaps(resources)
    iam_statements, iam_actions, iam_length = _analyze_iam_documents(
        resource_changes, resource_filter
    )

    change_summary = plan_metadata.get("change_summary") or {}
    change_total = 0
    for key in ("adds", "changes", "destroys"):
        try:
            change_total += int(change_summary.get(key, 0) or 0)
        except (TypeError, ValueError):
            continue

    smells: List[Dict[str, Any]] = []

    if max_depth >= 4:
        smells.append(
            {
                "id": "module_depth",
                "level": "high",
                "message": f"Module tree depth is {max_depth} levels (threshold 3).",
                "evidence": {"max_depth": max_depth, "threshold": 3},
            }
        )
    elif max_depth >= 2:
        smells.append(
            {
                "id": "module_depth",
                "level": "moderate",
                "message": f"Module tree depth is {max_depth} levels; consider flattening nested modules.",
                "evidence": {"max_depth": max_depth, "threshold": 2},
            }
        )

    if for_each_instances >= 25:
        smells.append(
            {
                "id": "for_each_bloat",
                "level": "high",
                "message": f"Plan expands {for_each_instances} for_each/loop instances (threshold 25).",
                "evidence": {"for_each_instances": for_each_instances, "threshold": 25},
            }
        )
    elif for_each_instances >= 10:
        smells.append(
            {
                "id": "for_each_bloat",
                "level": "moderate",
                "message": f"Plan expands {for_each_instances} for_each or count instances; consider module consolidation.",
                "evidence": {"for_each_instances": for_each_instances, "threshold": 10},
            }
        )

    if kms_missing:
        level = "high" if len(kms_missing) >= 3 else "moderate"
        smells.append(
            {
                "id": "missing_kms_key",
                "level": level,
                "message": f"{len(kms_missing)} data store resource(s) missing kms_key_id encryption wiring.",
                "evidence": {"missing_count": len(kms_missing), "sample": kms_missing[:5]},
            }
        )

    if iam_statements >= 10 or iam_actions >= 50 or iam_length >= 4000:
        smells.append(
            {
                "id": "iam_policy_bulk",
                "level": "high",
                "message": "IAM policy document is extremely large (≥10 statements or ≥50 actions).",
                "evidence": {
                    "statements": iam_statements,
                    "actions": iam_actions,
                    "length": iam_length,
                },
            }
        )
    elif iam_statements >= 5 or iam_actions >= 25 or iam_length >= 2000:
        smells.append(
            {
                "id": "iam_policy_bulk",
                "level": "moderate",
                "message": "IAM policy document is unusually large; consider modularizing permissions.",
                "evidence": {
                    "statements": iam_statements,
                    "actions": iam_actions,
                    "length": iam_length,
                },
            }
        )

    if change_total >= 50:
        smells.append(
            {
                "id": "change_volume",
                "level": "high",
                "message": f"Plan contains {change_total} resource changes; review blast radius before apply.",
                "evidence": {"change_total": change_total, "threshold": 50},
            }
        )
    elif change_total >= 15:
        smells.append(
            {
                "id": "change_volume",
                "level": "moderate",
                "message": f"Plan contains {change_total} resource changes (adds+updates+destroys).",
                "evidence": {"change_total": change_total, "threshold": 15},
            }
        )

    def _sort_key(item: Dict[str, Any]) -> Tuple[int, str]:
        level = str(item.get("level") or "low")
        rank = _SMELL_LEVEL_RANK.get(level, 0)
        identifier = str(item.get("id") or "")
        return (-rank, identifier)

    smells.sort(key=_sort_key)
    level = _aggregate_level(smells)
    summary = _build_summary(smells)
    stats = {
        "resource_count": plan_metadata.get("resource_count", len(resources)),
        "max_module_depth": max_depth,
        "for_each_instances": for_each_instances,
        "kms_missing": len(kms_missing),
        "iam_policy_statements": iam_statements,
        "iam_policy_actions": iam_actions,
        "iam_policy_length": iam_length,
        "change_total": change_total,
    }
    return {
        "level": level,
        "summary": summary,
        "stats": stats,
        "smells": smells,
    }


__all__ = ["compute_smell_report"]
