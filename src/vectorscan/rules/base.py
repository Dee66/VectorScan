"""Rule base class for VectorScan."""

from __future__ import annotations

from typing import Any, Dict, List


class Rule:
    """Minimal rule abstraction loaded by the evaluator."""

    id = "UNSET"
    severity = "low"

    @classmethod
    def evaluate(cls, plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []


def build_issue(
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    resource_address: str,
    attributes: Dict[str, Any] | None,
    remediation_hint: str = "",
    remediation_difficulty: str = "medium",
) -> Dict[str, Any]:
    """Create a schema-compliant issue dictionary."""
    return {
        "id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "resource_address": resource_address,
        "attributes": attributes or {},
        "remediation_hint": remediation_hint,
        "remediation_difficulty": remediation_difficulty,
    }
