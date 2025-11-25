# VectorScan Output Schema

## Top-Level Required Keys (Alphabetical)

| Key | Description |
| --- | --- |
| `badge_eligible` | Boolean flag surfaced to the CLI badge pipeline (evaluator emits a placeholder, CLI decides the final user-visible value). |
| `canonical_schema_version` | Version of the shared GuardSuite schema. |
| `environment` | Detected environment context (stage, providers, counts). |
| `guardscore_rules_version` | Ruleset version consumed by GuardScore. |
| `issues` | List of structured findings emitted by the evaluator. |
| `latency_ms` | End-to-end evaluation latency in milliseconds. |
| `metadata` | Additional evaluator metadata (plan info, renderer hints). |
| `pillar` | Name of the pillar emitting the scan (always "vector"). |
| `pillar_score_inputs` | Per-severity counts the evaluator computes for GuardScore ingestion (scaffolding, not part of CLI presentation). |
| `quick_score_mode` | Indicates reduced evaluation path for huge plans. |
| `scan_version` | VectorScan semantic version for traceability. |
| `schema_validation_error` | Null or populated when canonicalization fails. |
| `severity_totals` | Aggregated counts per severity used for reporting. |

## Issue Object Requirements

| Key | Description |
| --- | --- |
| `id` | Stable issue identifier (e.g., P-VEC-001). |
| `severity` | critical / high / medium / low severity classification. |
| `title` | One-line summary of the finding. |
| `description` | Detailed description of the detected risk. |
| `resource_address` | Terraform address pointing to the offending resource. |
| `attributes` | Structured context for remediation (resource metadata). |
| `remediation_hint` | Placeholder guidance string (upgrade to VectorGuard for full remediation). |
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

- `environment` captures inferred stage, provider list, resource counts, and (within the CLI) richer control flags collected from the legacy shim.
- `metadata` holds evaluator diagnostics, renderer hints, control flags, and provenance identifiers. The canonical evaluator emits `metadata.environment` + `metadata.plan`, while the CLI extends the block with `policy_blocks.*` and `reporting.*` mirrors.
- `badge_eligible` indicates GuardScore badge readiness. The evaluator sets a deterministic placeholder; the CLI owns the final badge gating exposed to users.
- `schema_validation_error` is null for valid output and stringified when schema enforcement fails.

## Shared Canonical Fields

The evaluator and CLI agree on the structural contract for the following keys: `badge_eligible`, `canonical_schema_version`, `environment`, `guardscore_rules_version`, `issues`, `latency_ms`, `metadata`, `pillar`, `quick_score_mode`, `scan_version`, `schema_validation_error`, and `severity_totals`. INIT-012 confirmed these fields stay deterministic across multi-run sweeps even when latency jitter is ±1 ms.

## Evaluator-Exclusive Fields

| Field | Description | Rationale |
| --- | --- | --- |
| `guardscore_badge` | Internal summary of badge eligibility fed into GuardScore. | GuardScore consumes this scaffolding directly; the CLI does not re-emit it. |
| `issue_required_fields` | Canonical list of required IssueDict keys. | Ensures downstream schema validators can assert evaluator completeness without leaking to users. |
| `percentile_placeholder` | GuardScore percentile shim. | Placeholder until badge percentile launches. |
| `pillar_score_inputs` | Per-severity counts before CLI formatting. | Marked as scaffolding in INIT-013 (see spec annotations). |
| `playground_summary` | Placeholder string for future UI surfaces. | Not rendered in CLI JSON. |
| `required` | Canonical list of required top-level keys. | Evaluator exposes it for schema consumers; CLI omits it. |
| `severity_keys` | Ordered severity list used for deterministic sorting. | Shared internally but not displayed. |
| `upgrade_hint` | Future-proofed upgrade guidance text. | Reserved for GuardSuite experiences beyond the CLI. |

## CLI-Exclusive Fields

| Field/Group | Description | Notes |
| --- | --- | --- |
| `badge_eligible` (CLI source-of-truth) | CLI re-evaluates eligibility against policy-pack state before presenting to users. | Evaluator placeholder stays `False`; CLI finalizes the boolean. |
| `checks`, `counts`, `status` | Human-friendly reporting summary for violations. | Lives under the broader `reporting.*` grouping referenced in the spec. |
| `iam_drift_report`, `metrics`, `smell_report`, `suspicious_defaults` | Presentation-oriented diagnostics derived from the legacy engine. | Retained for backward compatibility; evaluator does not emit them. |
| `plan_metadata`, `plan_risk_profile` | Detailed plan stats used in CLI tips. | Canonical evaluator only stores minimal `metadata.plan`. |
| `policy_blocks.*` (`policy_manifest`, `policy_pack_hash`, `policy_version`, `policy_source_url`, `policy_errors`) | Policy manifest provenance surfaced to CLI users. | Required for transparency; not part of evaluator-only payload. |
| `remediation_ledger` | Aggregated remediation context for the CLI report footer. | Evaluator tracks audit ledger separately. |
| `schema_version`, `security_grade`, `vectorscan_version` | Legacy presentation metadata. | Not part of canonical evaluator output.
| `violation_count_by_severity`, `violation_severity_summary`, `violations`, `violations_struct` | Rich violation structures for CLI rendering. | Evaluator emits normalized `issues` instead. |

## Field Parity Matrix

The matrix below consolidates the INIT-012 findings and documents intentional divergences so future regressions can be detected quickly.

| Field | Evaluator Behavior | CLI Behavior | Notes |
| --- | --- | --- | --- |
| `badge_eligible` | Always deterministic (currently `False`) placeholder emitted for GuardScore. | Source of truth for badge gating; may flip to `True` when CLI policy thresholds are satisfied. | CLI result overrides evaluator placeholder before presentation. |
| `environment` | Minimal inferred stage + provider/resource counts. | Rich snapshot including control flags (`allow_network`, `auto_download`, Terraform info). | CLI extends the dictionary but preserves canonical keys. |
| `latency_ms` | Computed via `_measure_latency_ms`; may be `0` on extremely fast runs. | Captures CLI runtime including Terraform shim; typically ≥1 ms. | Documented during INIT-012 multi-run determinism sweep. |
| `metadata._control_flags` | Present with control defaults only when CLI executes. | CLI adds `_control_flags`, `control`, and policy/reporting mirrors. | Evaluator keeps metadata minimal. |
| `pillar_score_inputs` | Emitted for GuardScore scaffolding only. | Not present. | Marked as evaluator-only. |
| `policy_manifest` | Not present. | Detailed manifest payload. | Part of policy_blocks.* grouping. |
| `remediation_ledger` | Not present; evaluator uses audit ledger. | CLI summarises remediation exposure for users. | Ensures CLI parity with legacy outputs. |
| `required` | Evaluator lists canonical required keys. | Not present. | Marked as scaffolding. |
| `status` | Not present. | CLI exposes PASS/FAIL for UX parity. | Derived from violation counts. |

Refer to `schemas/guardsuite_pillar_schema.json` for machine-readable enforcement while this document captures the human-readable contract and the INIT-013 parity annotations.
