# VectorScan Output Schema

## Top-Level Required Keys

| Key | Description |
| --- | --- |
| `pillar` | Name of the pillar emitting the scan (always 'vector'). |
| `scan_version` | VectorScan semantic version for traceability. |
| `guardscore_rules_version` | Ruleset version consumed by GuardScore. |
| `canonical_schema_version` | Version of the shared GuardSuite schema. |
| `issues` | List of structured findings emitted by the evaluator. |
| `severity_totals` | Aggregated counts per severity used for reporting. |
| `pillar_score_inputs` | Per-severity counts GuardScore ingests for scoring. |
| `metadata` | Additional evaluator metadata (plan info, renderer hints). |
| `environment` | Detected environment context (stage, providers, counts). |
| `badge_eligible` | Boolean flag used by GuardScore badge pipeline. |
| `quick_score_mode` | Indicates reduced evaluation path for huge plans. |
| `latency_ms` | End-to-end evaluation latency in milliseconds. |
| `schema_validation_error` | Null or populated when canonicalization fails. |

## Issue Object Requirements

| Key | Description |
| --- | --- |
| `id` | Stable issue identifier (e.g., P-VEC-001). |
| `severity` | critical / high / medium / low severity classification. |
| `title` | One-line summary of the finding. |
| `description` | Detailed description of the detected risk. |
| `resource_address` | Terraform address pointing to the offending resource. |
| `attributes` | Structured context for remediation (resource metadata). |
| `remediation_hint` | Fixpack reference such as fixpack:P-VEC-001. |
| `remediation_difficulty` | low / medium / high remediation effort guidance. |

The `issues` array must contain dictionaries with the fields listed above. Each field is required across the GuardSuite pillars so downstream tooling can present remediation guidance consistently.

## Severity Totals

| Key | Description |
| --- | --- |
| `critical` | Blocks deployment or introduces severe exposure. |
| `high` | Major governance failure that must be addressed soon. |
| `medium` | Operational or quality issue with moderate impact. |
| `low` | Informational signal that does not block rollout. |

Severity keys are used by both `severity_totals` and `pillar_score_inputs`. Missing keys are treated as zero counts, but VectorScan should always emit all buckets for determinism.

## Nested Structures

- `environment` captures inferred stage, provider list, and resource counts.
- `metadata` holds evaluator diagnostics, renderer hints, and provenance identifiers.
- `badge_eligible` indicates GuardScore badge readiness and mirrors `guardscore_badge` in prior specs.
- `schema_validation_error` is null for valid output and stringified when schema enforcement fails.

Refer to `schemas/guardsuite_pillar_schema.json` for machine-readable enforcement while this document captures the human-readable contract.
