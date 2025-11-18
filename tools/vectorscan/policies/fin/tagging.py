"""FinOps tagging policy plugin."""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from ..base_policy import BasePolicy, PolicyMetadata, register_policy
from ..common import REQUIRED_TAGS, TAGGABLE_TYPES, is_nonempty_string


@register_policy
class TaggingPolicy(BasePolicy):
    metadata = PolicyMetadata(
        policy_id="P-FIN-001",
        name="Mandatory Tagging",
        severity="high",
        category="finops",
        description="Taggable AWS resources must include CostCenter and Project tags.",
    )

    def evaluate(self, resources: Sequence[Dict[str, Any]]) -> List[str]:
        violations: List[str] = []
        for resource in resources:
            if resource.get("type") not in TAGGABLE_TYPES:
                continue
            values = resource.get("values", {}) or {}
            tags = values.get("tags") or {}
            name = resource.get("name", "<unnamed>")
            rtype = resource.get("type")
            if not isinstance(tags, dict) or not tags:
                violations.append(f"{self.metadata.policy_id}: {rtype} '{name}' has no tags")
                continue
            for key in REQUIRED_TAGS:
                if key not in tags or not is_nonempty_string(tags.get(key)):
                    violations.append(
                        f"{self.metadata.policy_id}: {rtype} '{name}' missing/empty tag '{key}'"
                    )
        return violations
