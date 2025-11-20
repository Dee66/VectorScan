"""Public access detection rule for VectorScan."""

from __future__ import annotations

from . import register
from .base import Rule, build_issue


@register
class PublicAccessRule(Rule):
    id = "P-VEC-001"
    severity = "critical"

    @classmethod
    def evaluate(cls, plan: dict):
        resources = plan.get("resources", [])
        issues = []

        for resource in resources:
            if resource.get("type") != "vector_index":
                continue
            if resource.get("public_access") is True:
                issues.append(
                    build_issue(
                        rule_id=cls.id,
                        severity=cls.severity,
                        title="Publicly accessible vector DB",
                        description="Vector index allows public queries.",
                        resource_address=resource.get("address", ""),
                        attributes={"public_access": True},
                        remediation_hint="",
                        remediation_difficulty="high",
                    )
                )
        return issues
