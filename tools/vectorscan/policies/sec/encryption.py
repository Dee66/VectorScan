"""Security policy plugin enforcing RDS encryption guardrail."""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from ..base_policy import BasePolicy, PolicyMetadata, register_policy


@register_policy
class EncryptionPolicy(BasePolicy):
    metadata = PolicyMetadata(
        policy_id="P-SEC-001",
        name="Encryption Mandate",
        severity="critical",
        category="security",
        description="RDS resources must enable storage encryption and reference a kms_key_id.",
    )

    _TARGET_TYPES = {"aws_db_instance", "aws_rds_cluster"}

    def evaluate(self, resources: Sequence[Dict[str, Any]]) -> List[str]:
        violations: List[str] = []
        for resource in resources:
            if resource.get("type") not in self._TARGET_TYPES:
                continue
            values = resource.get("values", {}) or {}
            encrypted = values.get("storage_encrypted")
            kms_key = values.get("kms_key_id")
            name = resource.get("name", "<unnamed>")
            rtype = resource.get("type")
            if encrypted is not True:
                violations.append(
                    f"{self.metadata.policy_id}: {rtype} '{name}' has storage_encrypted != true"
                )
                continue
            if not kms_key:
                violations.append(
                    f"{self.metadata.policy_id}: {rtype} '{name}' encryption enabled but no kms_key_id specified"
                )
        return violations
