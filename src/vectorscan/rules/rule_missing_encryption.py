"""Rule P-VEC-002: ensure vector indexes have encryption enabled."""

from __future__ import annotations

from . import register
from .base import Rule, build_issue


@register
class MissingEncryptionRule(Rule):
    id = "P-VEC-002"
    severity = "high"

    @classmethod
    def evaluate(cls, plan: dict):
        resources = plan.get("resources", [])
        issues = []

        for resource in resources:
            if resource.get("type") != "vector_index":
                continue
            encryption_enabled = resource.get("encryption_enabled")
            if encryption_enabled is True:
                continue
            issues.append(
                build_issue(
                    rule_id=cls.id,
                    severity=cls.severity,
                    title="Encryption disabled",
                    description="Vector index has encryption set to false.",
                    resource_address=resource.get("address", ""),
                    attributes={"encryption_enabled": bool(encryption_enabled)},
                    remediation_difficulty="medium",
                )
            )

        return issues
