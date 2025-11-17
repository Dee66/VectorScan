# VectorScan Output Schema

_Generated on 2025-11-17 09:24:45 UTC via `scripts/generate_schema_docs.py`. Run the script again after schema changes to keep this document accurate._

## Sample Coverage

This schema is derived from the union of these fixture runs:
- `examples/aws-pgvector-rag/tfplan-pass.json`
- `examples/aws-pgvector-rag/tfplan-fail.json`

## Top-Level Fields

| Field | Type | Description |
| --- | --- | --- |
| `status` | `string` | Overall scan outcome. PASS when no violations/policy errors remain. |
| `file` | `string` | Input Terraform plan path (as provided to the CLI). |
| `checks` | `array<string>` | Ordered list of policy identifiers executed during the scan. |
| `counts` | `object` | Summary counters (currently just violation totals). |
| `violations` | `array<string>` | Human-readable violation messages for each failed policy. |
| `violations_struct` | `array<object>` | Structured violation objects with remediation guidance and taint metadata. |
| `policy_errors` | `array` | Structured errors raised while evaluating a policy (rare). |
| `violation_severity_summary` | `object` | Map of severity → violation counts. |
| `metrics` | `object` | Machine-readable scoring + exposure metrics for dashboards. |
| `iam_drift_report` | `object` | IAM drift analysis output with risky additions and severities. |
| `terraform_tests` | `object` | Optional Terraform test run metadata (present when --terraform-tests is used). |
| `environment` | `object` | Runtime metadata (platform, Python, Terraform, VectorScan, strict/offline flags). |
| `plan_metadata` | `object` | Terraform plan inventory summary (resource/module counts, providers, types). |
| `plan_diff` | `object` | Change-only diff summary emitted when --diff is provided. |
| `explanation` | `object` | Narrative explain block emitted when --explain is provided. |
| `vectorscan_version` | `string` | Semantic version of the CLI binary producing the output. |
| `policy_version` | `string` | Policy pack SemVer string for auditors. |
| `schema_version` | `string` | Version tag for this JSON schema contract. |
| `policy_pack_hash` | `string` | SHA-256 hash of the shipped policy bundle. |

## Counts

| Field | Type | Description |
| --- | --- | --- |
| `counts.violations` | `integer` | Number of violation strings emitted in the top-level array. |

<details><summary>Example</summary>


```json
{
  "violations": 0
}
```

</details>

## Structured Violations

| Field | Type | Description |
| --- | --- | --- |
| `violations_struct[].policy_id` | `string` | Policy identifier (e.g., P-SEC-001). |
| `violations_struct[].policy_name` | `string` | Human-readable policy title. |
| `violations_struct[].message` | `string` | Original violation message for backwards compatibility. |
| `violations_struct[].severity` | `string` | Severity level derived from policy metadata. |
| `violations_struct[].resource` | `string` | Resource address shorthand (type.name / module path). |
| `violations_struct[].resource_details` | `object` | Resource metadata including module path and taint analysis. |
| `violations_struct[].remediation` | `object` | Structured remediation summary with docs and HCL completeness. |

## Violation Resource Details

| Field | Type | Description |
| --- | --- | --- |
| `resource_details.address` | `string` | Full Terraform address when available. |
| `resource_details.type` | `string` | Terraform resource type. |
| `resource_details.name` | `string` | Resource name component. |
| `resource_details.module_path` | `string` | Module path derived from the address (root/module.child). |
| `resource_details.data_taint` | `string` | Where the fix must occur (resource_body/module_source/variable_source). |
| `resource_details.taint_explanation` | `string` | Reasoning for the taint classification. |

## Violation Remediation

| Field | Type | Description |
| --- | --- | --- |
| `remediation.summary` | `string` | One-line remediation guidance. |
| `remediation.hcl_examples` | `array<string>` | List of HCL snippets that resolve the violation. |
| `remediation.docs` | `array<string>` | Reference documentation links. |
| `remediation.hcl_completeness` | `number` | 0–1 score indicating how complete the suggested HCL fix is. |

## Violation Severity Summary

| Field | Type | Description |
| --- | --- | --- |
| `violation_severity_summary.critical` | `integer` | Critical-level violation count. |
| `violation_severity_summary.high` | `integer` | High-level violation count. |
| `violation_severity_summary.medium` | `integer` | Medium-level violation count. |
| `violation_severity_summary.low` | `integer` | Low-level violation count. |

## Policy Errors

| Field | Type | Description |
| --- | --- | --- |
| `policy_errors[].policy` | `string` | Policy identifier that raised an exception. |
| `policy_errors[].error` | `string` | Exception class + message captured from the policy runtime. |

## Metrics

| Field | Type | Description |
| --- | --- | --- |
| `metrics.eligible_checks` | `integer` | Total number of encryption + tagging resources evaluated. |
| `metrics.passed_checks` | `integer` | Resources that satisfied the enforced guardrails. |
| `metrics.compliance_score` | `integer` | 0–100 normalized pass percentage after IAM penalties. |
| `metrics.network_exposure_score` | `integer` | 100 minus penalties for open security groups. |
| `metrics.open_sg_count` | `integer` | Security groups with 0.0.0.0/0 style ingress. |
| `metrics.iam_risky_actions` | `integer` | Count of IAM actions flagged as risky. |
| `metrics.iam_drift.status` | `string` | IAM drift status mirrored into metrics for quick filters. |
| `metrics.iam_drift.risky_change_count` | `integer` | Number of IAM drift findings mirrored into metrics. |
| `metrics.notes` | `object` | Additional context for open security groups and IAM risk analysis. |
| `metrics.scan_duration_ms` | `integer` | CLI runtime duration in milliseconds. |

<details><summary>Example</summary>


```json
{
  "eligible_checks": 2,
  "passed_checks": 2,
  "compliance_score": 100,
  "network_exposure_score": 100,
  "open_sg_count": 0,
  "iam_risky_actions": 0,
  "notes": {
    "open_security_groups": [],
    "iam_risky_details": []
  },
  "iam_drift": {
    "status": "PASS",
    "ri…
```

</details>

## Metric Notes

| Field | Type | Description |
| --- | --- | --- |
| `metrics.notes.open_security_groups` | `array` | Details for each open security group detected. |
| `metrics.notes.iam_risky_details` | `array` | Detailed descriptions of IAM risky actions. |

## Environment Metadata

| Field | Type | Description |
| --- | --- | --- |
| `environment.platform` | `string` | Lowercase platform identifier (platform.system) or VSCAN_ENV_PLATFORM override. |
| `environment.platform_release` | `string` | Kernel/platform release string or VSCAN_ENV_PLATFORM_RELEASE override. |
| `environment.python_version` | `string` | Detected Python version or VSCAN_ENV_PYTHON_VERSION override. |
| `environment.python_implementation` | `string` | Python implementation name or VSCAN_ENV_PYTHON_IMPL override. |
| `environment.terraform_version` | `string` | Terraform CLI version used (or not-run/unknown when absent). |
| `environment.terraform_source` | `string` | Source of Terraform binary (system/download/override/not-run). |
| `environment.vectorscan_version` | `string` | VectorScan version reported inside the metadata block (overridable via VSCAN_ENV_VECTORSCAN_VERSION). |
| `environment.strict_mode` | `boolean` | Boolean indicating VSCAN_STRICT enforcement. |
| `environment.offline_mode` | `boolean` | Boolean indicating offline/air-gapped execution. |

## Plan Metadata

| Field | Type | Description |
| --- | --- | --- |
| `plan_metadata.resource_count` | `integer` | Total number of resources discovered across the plan. |
| `plan_metadata.module_count` | `integer` | Total number of modules (root + nested) present in the plan. |
| `plan_metadata.resource_types` | `object` | Map of Terraform resource type → count. |
| `plan_metadata.providers` | `array<string>` | Sorted list of inferred providers present in the plan. |
| `plan_metadata.modules.root` | `string` | Root module address (defaults to 'root'). |
| `plan_metadata.modules.with_resources` | `integer` | Number of modules that contain at least one resource. |
| `plan_metadata.modules.child_module_count` | `integer` | Count of nested/child modules encountered. |
| `plan_metadata.modules.has_child_modules` | `boolean` | Boolean indicating whether any child modules exist. |
| `plan_metadata.change_summary` | `object` | Map of adds/changes/destroys counters derived from Terraform resource_changes. |
| `plan_metadata.resources_by_type` | `object` | Per-type map of `{planned, adds, changes, destroys}` counts. |
| `plan_metadata.file_size_mb` | `number` | Plan file size converted to MB (rounded). |
| `plan_metadata.file_size_bytes` | `integer` | Raw plan file size in bytes. |
| `plan_metadata.parse_duration_ms` | `integer` | Plan parsing duration captured by the streaming parser. |
| `plan_metadata.plan_slo.active_window` | `string` | SLO tier label (fast_path/large_plan/oversized). |
| `plan_metadata.plan_slo.observed` | `object` | Observed metrics (resource_count, parse_duration_ms, file_size_bytes). |
| `plan_metadata.plan_slo.thresholds` | `object` | Threshold metadata for each SLO tier. |
| `plan_metadata.plan_slo.breach_reason` | `null` | Reason provided when the plan breaches the active SLO. |
| `plan_metadata.exceeds_threshold` | `boolean` | Boolean recording whether the plan exceeded the SLO thresholds. |

## Plan Diff (--diff)

| Field | Type | Description |
| --- | --- | --- |
| `plan_diff.summary.adds` | `integer` | Number of resources slated for creation in the diff scope. |
| `plan_diff.summary.changes` | `integer` | Number of resources being modified. |
| `plan_diff.summary.destroys` | `integer` | Number of resources being destroyed. |

## Plan Diff Resources

| Field | Type | Description |
| --- | --- | --- |
| `plan_diff.resources[].address` | `string` | Full Terraform address for the changed resource. |
| `plan_diff.resources[].type` | `string` | Terraform resource type for the diff entry. |
| `plan_diff.resources[].name` | `string` | Resource name component derived from the address. |
| `plan_diff.resources[].change_type` | `string` | Canonical change bucket (adds/changes/destroys). |
| `plan_diff.resources[].actions` | `array` | Underlying Terraform actions reported for the change. |
| `plan_diff.resources[].changed_attributes` | `array` | Array of changed attribute objects scoped to this resource. |

## Plan Diff Attributes

| Field | Type | Description |
| --- | --- | --- |
| `plan_diff.resources[].changed_attributes[].path` | `string` | Dot-delimited attribute path that changed. |
| `plan_diff.resources[].changed_attributes[].before` | `string` | Value before the change (can be null when resource is new). |
| `plan_diff.resources[].changed_attributes[].after` | `string` | Value after the change (can be null when resource is destroyed). |

## Explanation Block (--explain)

| Field | Type | Description |
| --- | --- | --- |
| `explanation.summary` | `string` | Human-readable summary of status, compliance score, severity counts, and IAM drift. |
| `explanation.plan_overview.narrative` | `string` | Narrative describing resource/module/provider mix. |
| `explanation.scores.compliance_score` | `integer` | Compliance score echoed for explain consumers. |
| `explanation.scores.network_exposure_score` | `integer` | Network exposure score copy. |
| `explanation.risk_highlights` | `array<object>` | List of high-risk resources derived from violations. |
| `explanation.iam_drift.summary` | `string` | Plain-language IAM drift summary mirroring iam_drift_report. |
| `explanation.recommendations` | `array<string>` | Ordered list of guardrail recommendations. |
| `explanation.policy_context` | `array<object>` | Metadata for each guardrail referenced in the explanation block. |

## IAM Drift Report

| Field | Type | Description |
| --- | --- | --- |
| `iam_drift_report.status` | `string` | PASS/FAIL summary of IAM drift analysis. |
| `iam_drift_report.counts.risky_changes` | `integer` | Number of IAM resources with newly risky actions. |
| `iam_drift_report.items` | `array` | List of per-resource IAM drift findings. |

<details><summary>Example</summary>


```json
{
  "status": "PASS",
  "counts": {
    "risky_changes": 0
  },
  "items": [],
  "notes": {
    "limitations": [
      "NotAction not evaluated",
      "Resource scoping not evaluated for drift risk"
    ]
  }
}
```

</details>

## IAM Drift Items

| Field | Type | Description |
| --- | --- | --- |
| `iam_drift_report.items[].resource_type` | `string` | Terraform resource type for the IAM policy under review. |
| `iam_drift_report.items[].resource_name` | `string` | Resource name/address in the plan. |
| `iam_drift_report.items[].risky_additions` | `array<string>` | IAM actions newly introduced by the change. |
| `iam_drift_report.items[].severity_by_action` | `object` | Per-action severity map (high/medium). |
| `iam_drift_report.items[].notaction_broad_allow` | `boolean` | Boolean indicating NotAction + Resource '*' pattern. |

## Terraform Tests

| Field | Type | Description |
| --- | --- | --- |
| `terraform_tests.status` | `string` | PASS/FAIL/SKIP from 'terraform test'. |
| `terraform_tests.version` | `string` | Terraform CLI version used for tests. |
| `terraform_tests.source` | `string` | Where the CLI was resolved (system/download/override). |
| `terraform_tests.strategy` | `string` | Named test harness that executed (modern, legacy, etc.). |
| `terraform_tests.stdout` | `string` | Truncated stdout from Terraform tests. |
| `terraform_tests.stderr` | `string` | Truncated stderr from Terraform tests. |
