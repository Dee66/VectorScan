"""Heuristics for flagging suspicious Terraform defaults before policy evaluation."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Sequence

Address = str


def _normalize_address(resource: Dict[str, Any]) -> Address:
    address = resource.get("address")
    if isinstance(address, str) and address:
        return address
    name = resource.get("name")
    r_type = resource.get("type")
    if isinstance(r_type, str) and isinstance(name, str):
        return f"{r_type}.{name}"
    if isinstance(r_type, str):
        return r_type
    return "unknown"


def _iter_ingress_blocks(values: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    ingress = values.get("ingress")
    if isinstance(ingress, list):
        for block in ingress:
            if isinstance(block, dict):
                yield block


def _is_open_cidr(block: Dict[str, Any]) -> bool:
    for field in ("cidr_blocks", "ipv6_cidr_blocks"):
        cidrs = block.get(field)
        if isinstance(cidrs, list):
            for item in cidrs:
                if isinstance(item, str) and item in {"0.0.0.0/0", "::/0"}:
                    return True
    return False


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return bool(value)


def _encrypt_at_rest_disabled(values: Dict[str, Any]) -> bool:
    encrypt = values.get("encrypt_at_rest")
    if isinstance(encrypt, dict):
        enabled = encrypt.get("enabled")
        return not _to_bool(enabled)
    if isinstance(encrypt, bool):
        return not encrypt
    return False


def _storage_encrypted_disabled(values: Dict[str, Any]) -> bool:
    return not _to_bool(values.get("storage_encrypted"))


def _node_to_node_disabled(values: Dict[str, Any]) -> bool:
    enabled = values.get("node_to_node_encryption")
    if isinstance(enabled, dict):
        enabled = enabled.get("enabled")
    return not _to_bool(enabled)


def _s3_bucket_overexposed(values: Dict[str, Any]) -> Sequence[str]:
    findings: List[str] = []
    acl = values.get("acl")
    if isinstance(acl, str) and acl.lower() in {"public-read", "public-read-write"}:
        findings.append("ACL allows public reads")
    pab = values.get("public_access_block_configuration")
    if not isinstance(pab, dict):
        findings.append("Public access block configuration missing")
    return findings


def _subnet_public(values: Dict[str, Any]) -> Sequence[str]:
    if _to_bool(values.get("map_public_ip_on_launch")):
        return ["subnet maps public IPs on launch"]
    return []


def _iam_wildcard_actions(values: Dict[str, Any]) -> Sequence[str]:
    policy_blob = values.get("policy")
    if not isinstance(policy_blob, str) or not policy_blob.strip():
        return []
    try:
        document = json.loads(policy_blob)
    except json.JSONDecodeError:
        if "*" in policy_blob:
            return ["IAM inline policy contains wildcard action"]
        return []

    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    for statement in statements:
        actions = statement.get("Action")
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue
        for action in actions:
            if isinstance(action, str) and (
                action == "*" or action.endswith(":*") or "*" in action
            ):
                return ["IAM inline policy contains wildcard action"]
    return []


def _evaluate_resource(resource: Dict[str, Any]) -> List[str]:
    values = resource.get("values")
    if not isinstance(values, dict):
        return []
    r_type = resource.get("type")
    if not isinstance(r_type, str):
        return []

    findings: List[str] = []
    if r_type in {"aws_rds_cluster", "aws_db_instance", "aws_rds_instance"}:
        if _storage_encrypted_disabled(values):
            findings.append("storage_encrypted defaults to false")

    if r_type in {"aws_elasticsearch_domain", "aws_opensearch_domain"}:
        if _encrypt_at_rest_disabled(values):
            findings.append("encrypt_at_rest disabled (defaults to false)")
        if _node_to_node_disabled(values):
            findings.append("node-to-node encryption disabled")

    if r_type == "aws_security_group":
        for ingress in _iter_ingress_blocks(values):
            if _is_open_cidr(ingress):
                findings.append("ingress allows 0.0.0.0/0 or ::/0")
                break

    if r_type == "aws_s3_bucket":
        findings.extend(_s3_bucket_overexposed(values))

    if r_type == "aws_subnet":
        findings.extend(_subnet_public(values))

    if r_type in {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }:
        findings.extend(_iam_wildcard_actions(values))

    return findings


def detect_suspicious_defaults(
    plan: Dict[str, Any], resources: Sequence[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Return advisory findings that highlight insecure defaults."""

    detections: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _register(address: str, resource_type: str, reason: str) -> None:
        key = (address, reason)
        if key in seen:
            return
        seen.add(key)
        detections.append(
            {
                "address": address,
                "resource_type": resource_type,
                "reason": reason,
            }
        )

    for resource in resources:
        r_type = resource.get("type")
        if not isinstance(r_type, str):
            continue
        address = _normalize_address(resource)
        for reason in _evaluate_resource(resource):
            _register(address, r_type, reason)

    # resource_changes may include entries not present in planned_values
    for change in plan.get("resource_changes", []) or []:
        if not isinstance(change, dict):
            continue
        after = (change.get("change") or {}).get("after")
        if not isinstance(after, dict):
            continue
        r_type = change.get("type")
        if not isinstance(r_type, str):
            continue
        address = change.get("address")
        if not isinstance(address, str) or not address:
            name = change.get("name")
            if isinstance(name, str):
                address = f"{r_type}.{name}"
            else:
                address = r_type
        resource_stub = {"type": r_type, "values": after, "address": address}
        for reason in _evaluate_resource(resource_stub):
            _register(address, r_type, reason)

    detections.sort(key=lambda item: (item.get("address", ""), item.get("reason", "")))
    return detections


__all__ = ["detect_suspicious_defaults"]
