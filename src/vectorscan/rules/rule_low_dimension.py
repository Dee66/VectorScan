"""Rule P-VEC-004: detect suspiciously low vector dimensions."""

from __future__ import annotations

from . import register
from .base import Rule, build_issue


@register
class LowDimensionRule(Rule):
    id = "P-VEC-004"
    severity = "low"

    @classmethod
    def evaluate(cls, plan: dict):
        resources = plan.get("resources", [])
        issues = []

        for resource in resources:
            if resource.get("type") != "vector_index":
                continue
            dimension = resource.get("dimension")
            try:
                dimension_value = int(dimension)
            except (TypeError, ValueError):
                continue
            if dimension_value >= 16:
                continue
            issues.append(
                build_issue(
                    rule_id=cls.id,
                    severity=cls.severity,
                    title="Suspiciously low vector dimension",
                    description=f"Vector dimension={dimension_value} may indicate misconfiguration.",
                    resource_address=resource.get("address", ""),
                    attributes={"dimension": dimension_value},
                    remediation_difficulty="medium",
                )
            )

        return issues
