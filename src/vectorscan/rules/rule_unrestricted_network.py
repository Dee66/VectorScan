"""Rule P-VEC-003: flag unrestricted network access for vector indexes."""

from __future__ import annotations

from typing import Any, Iterable

from . import register
from .base import Rule, build_issue


def _iter_cidrs(value: Any) -> Iterable[str]:
    if isinstance(value, list):
        for item in value:
            yield str(item)


@register
class UnrestrictedNetworkRule(Rule):
    id = "P-VEC-003"
    severity = "medium"

    @classmethod
    def evaluate(cls, plan: dict):
        resources = plan.get("resources", [])
        issues = []

        for resource in resources:
            if resource.get("type") != "vector_index":
                continue
            allowed_cidrs = list(_iter_cidrs(resource.get("allowed_cidrs")))
            if "0.0.0.0/0" not in allowed_cidrs:
                continue
            issues.append(
                build_issue(
                    rule_id=cls.id,
                    severity=cls.severity,
                    title="Unrestricted network access",
                    description="Vector index allows traffic from 0.0.0.0/0.",
                    resource_address=resource.get("address", ""),
                    attributes={"allowed_cidrs": allowed_cidrs},
                    remediation_hint="fixpack:P-VEC-003",
                    remediation_difficulty="medium",
                )
            )

        return issues
