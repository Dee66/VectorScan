# VectorScan Output Schema Reference

## scan_version

- **Type:** string
- **Location:** Top-level field in every VectorScan scan payload (JSON) and echoed in the human-readable CLI header/footer.
- **Format:** Semantic identifier `vMAJOR.MINOR.PATCH`.
- **Current value:** `v2.0.0`.
- **Purpose:** Indicates the deterministic GuardSuite pillar version responsible for producing the scan. Downstream automation can use this value to reason about feature availability and to gate schema migrations.
- **Determinism:** The value is constant for a given release train and does not change within a single execution, ensuring reproducible outputs across runs with identical inputs.

## remediation fields

- **`remediation_hint`:** Present but intentionally blank (`""`) in free_scanner builds. Paid tiers may replace the placeholder with detailed instructions, but the public VectorScan release stays neutral.
- **`remediation_difficulty`:** One of `low`, `medium`, or `high`. The value mirrors the rule registry entry and is never omitted or null.
- **`remediation_metadata`:** Canonical payloads now emit an empty object (`{}`) for every issue to satisfy schema requirements without bundling proprietary fixpack content.

The remediation trio is required on every canonical IssueDict; VectorScan simply supplies empty placeholders where proprietary artifacts used to live.

## remediation ledger

- **`remediation_ledger`:** Top-level object summarizing remediation coverage for the scan payload. The structure is:

	```json
	{
		"per_severity": {
			"critical": <int>,
			"high": <int>,
			"medium": <int>,
			"low": <int>
		},
		"rule_ids": ["PILLAR-AWS-001", ...],
		"paths": [
			{
				"id": "PILLAR-AWS-001",
				"severity": "critical",
				"remediation_metadata": {"fixpack_id": "PILLAR-AWS-001", ...}
			}
		]
	}
	```

	- `per_severity` mirrors the canonical severity ordering and always includes all four buckets, even when zero.
	- `rule_ids` is a deduplicated, severity-ordered list of IssueDict identifiers.
	- `paths` preserves the same ordering as `rule_ids`. Each entry includes the issue id, severity, and an empty `remediation_metadata` block (matching the issue payloads) so downstream automation can maintain shape compatibility without exposing patch data.

- **Audit ledger:** The evaluator continues to expose `evaluation.audit_ledger`. That structure now includes a nested `remediation_summary` block that mirrors `remediation_ledger`, ensuring audit exports and JSON payloads stay in sync.
