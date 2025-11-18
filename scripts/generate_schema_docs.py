#!/usr/bin/env python3
"""Generate Markdown documentation for the VectorScan JSON output schema."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "output_schema.md"
DEFAULT_PASS_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
DEFAULT_FAIL_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-fail.json"
DEFAULT_COMPARE_PAIR = (
    ROOT / "tests" / "fixtures" / "tfplan_compare_old.json",
    ROOT / "tests" / "fixtures" / "tfplan_compare_new.json",
)
CLI_PATH = ROOT / "tools" / "vectorscan" / "vectorscan.py"
PREVIEW_EXIT_CODE = 10


@dataclass(frozen=True)
class FieldSpec:
    path: Tuple[str, ...]
    label: str
    description: str
    expected_type: str | None = None


TOP_LEVEL_FIELDS: List[FieldSpec] = [
    FieldSpec(("status",), "status", "Overall scan outcome. PASS when no violations/policy errors remain."),
    FieldSpec(("file",), "file", "Input Terraform plan path (as provided to the CLI)."),
    FieldSpec(("checks",), "checks", "Ordered list of policy identifiers executed during the scan."),
    FieldSpec(("counts",), "counts", "Summary counters (currently just violation totals)."),
    FieldSpec(("violations",), "violations", "Human-readable violation messages for each failed policy."),
    FieldSpec(("violations_struct",), "violations_struct", "Structured violation objects with remediation guidance and taint metadata."),
    FieldSpec(("policy_errors",), "policy_errors", "Structured errors raised while evaluating a policy (rare)."),
    FieldSpec(("violation_severity_summary",), "violation_severity_summary", "Map of severity → violation counts."),
    FieldSpec(("metrics",), "metrics", "Machine-readable scoring + exposure metrics for dashboards."),
    FieldSpec(("security_grade",), "security_grade", "Letter-grade security rating derived from compliance score and severity mix."),
    FieldSpec(("iam_drift_report",), "iam_drift_report", "IAM drift analysis output with risky additions and severities."),
    FieldSpec(("terraform_tests",), "terraform_tests", "Optional Terraform test run metadata (present when --terraform-tests is used).", expected_type="object"),
    FieldSpec(("environment",), "environment", "Runtime metadata (platform, Python, Terraform, VectorScan, strict/offline flags).", expected_type="object"),
    FieldSpec(("plan_metadata",), "plan_metadata", "Terraform plan inventory summary (resource/module counts, providers, types).", expected_type="object"),
    FieldSpec(("plan_diff",), "plan_diff", "Change-only diff summary emitted when --diff is provided.", expected_type="object"),
    FieldSpec(("explanation",), "explanation", "Narrative explain block emitted when --explain is provided.", expected_type="object"),
    FieldSpec(("violation_count_by_severity",), "violation_count_by_severity", "Legacy severity count map kept for backwards compatibility.", expected_type="object"),
    FieldSpec(("vectorscan_version",), "vectorscan_version", "Semantic version of the CLI binary producing the output."),
    FieldSpec(("policy_version",), "policy_version", "Policy pack SemVer string for auditors."),
    FieldSpec(("schema_version",), "schema_version", "Version tag for this JSON schema contract."),
    FieldSpec(("policy_pack_hash",), "policy_pack_hash", "SHA-256 hash of the shipped policy bundle."),
    FieldSpec(("policy_source_url",), "policy_source_url", "Canonical repository or URL describing the policy source."),
    FieldSpec(("policy_manifest",), "policy_manifest", "Signed manifest metadata describing the active policy pack.", expected_type="object"),
    FieldSpec(("preview_generated",), "preview_generated", "Boolean indicating VectorGuard preview metadata was emitted.", expected_type="boolean"),
    FieldSpec(("preview_policies",), "preview_policies", "Array of teaser policies surfaced by preview mode.", expected_type="array"),
    FieldSpec(("preview_manifest",), "preview_manifest", "Signed manifest metadata describing the preview payload.", expected_type="object"),
    FieldSpec(("resource_filter",), "resource_filter", "Resource scope metadata emitted when --resource is provided.", expected_type="object"),
    FieldSpec(("smell_report",), "smell_report", "Plan smell heuristics summarizing structural risk indicators.", expected_type="object"),
    FieldSpec(("plan_evolution",), "plan_evolution", "Plan comparison summary emitted when --compare is used.", expected_type="object"),
]
SMELL_REPORT_FIELDS = [
    FieldSpec(("smell_report", "level"), "smell_report.level", "Aggregated smell severity level (low/moderate/high)."),
    FieldSpec(("smell_report", "summary"), "smell_report.summary", "One-line summary of detected plan smells."),
    FieldSpec(("smell_report", "stats", "resource_count"), "smell_report.stats.resource_count", "Resource count snapshot used during smell analysis."),
    FieldSpec(("smell_report", "stats", "max_module_depth"), "smell_report.stats.max_module_depth", "Deepest module nesting level observed."),
    FieldSpec(("smell_report", "stats", "for_each_instances"), "smell_report.stats.for_each_instances", "Number of expanded for_each/count instances."),
    FieldSpec(("smell_report", "stats", "kms_missing"), "smell_report.stats.kms_missing", "Count of KMS-required resources lacking kms_key_id."),
    FieldSpec(("smell_report", "stats", "iam_policy_statements"), "smell_report.stats.iam_policy_statements", "Max IAM statements observed in plan changes."),
    FieldSpec(("smell_report", "stats", "iam_policy_actions"), "smell_report.stats.iam_policy_actions", "Max IAM actions observed in plan changes."),
    FieldSpec(("smell_report", "stats", "iam_policy_length"), "smell_report.stats.iam_policy_length", "Largest IAM policy document size (bytes)."),
    FieldSpec(("smell_report", "stats", "change_total"), "smell_report.stats.change_total", "Adds+changes+destroys aggregated across the plan."),
    FieldSpec(("smell_report", "smells"), "smell_report.smells", "Array of detected smell findings with evidence.", expected_type="array"),
]

SMELL_ITEM_FIELDS = [
    FieldSpec(("smell_report", "smells", "[]", "id"), "smell_report.smells[].id", "Smell identifier (e.g., module_depth)."),
    FieldSpec(("smell_report", "smells", "[]", "level"), "smell_report.smells[].level", "Severity level for the smell finding."),
    FieldSpec(("smell_report", "smells", "[]", "message"), "smell_report.smells[].message", "Human-readable explanation of the smell."),
    FieldSpec(("smell_report", "smells", "[]", "evidence"), "smell_report.smells[].evidence", "Structured evidence backing the smell detection.", expected_type="object"),
]

PLAN_EVOLUTION_PLAN_FIELDS = [
    FieldSpec(("plan_evolution", "old_plan", "file"), "plan_evolution.old_plan.file", "Filesystem path to the previous plan used in --compare.", expected_type="string"),
    FieldSpec(("plan_evolution", "old_plan", "resource_count"), "plan_evolution.old_plan.resource_count", "Resource count for the previous plan."),
    FieldSpec(("plan_evolution", "old_plan", "change_summary"), "plan_evolution.old_plan.change_summary", "Adds/changes/destroys summary for the previous plan.", expected_type="object"),
    FieldSpec(("plan_evolution", "new_plan", "file"), "plan_evolution.new_plan.file", "Filesystem path to the newer plan used in --compare.", expected_type="string"),
    FieldSpec(("plan_evolution", "new_plan", "resource_count"), "plan_evolution.new_plan.resource_count", "Resource count for the newer plan."),
    FieldSpec(("plan_evolution", "new_plan", "change_summary"), "plan_evolution.new_plan.change_summary", "Adds/changes/destroys summary for the newer plan.", expected_type="object"),
]

PLAN_EVOLUTION_DELTA_FIELDS = [
    FieldSpec(("plan_evolution", "delta", "resource_count"), "plan_evolution.delta.resource_count", "Difference in total resources between the compared plans."),
    FieldSpec(("plan_evolution", "delta", "adds"), "plan_evolution.delta.adds", "Difference in adds between the plans."),
    FieldSpec(("plan_evolution", "delta", "changes"), "plan_evolution.delta.changes", "Difference in changes between the plans."),
    FieldSpec(("plan_evolution", "delta", "destroys"), "plan_evolution.delta.destroys", "Difference in destroy counts between the plans."),
]

PLAN_EVOLUTION_SUMMARY_FIELDS = [
    FieldSpec(("plan_evolution", "summary", "lines"), "plan_evolution.summary.lines", "Human-readable +/-/~/! summary lines describing the comparison.", expected_type="array"),
]

PLAN_EVOLUTION_DOWNGRADED_FIELDS = [
    FieldSpec(("plan_evolution", "downgraded_encryption", "count"), "plan_evolution.downgraded_encryption.count", "Number of resources where encryption was downgraded."),
    FieldSpec(("plan_evolution", "downgraded_encryption", "resources"), "plan_evolution.downgraded_encryption.resources", "Details for each downgraded resource.", expected_type="array"),
]

PLAN_EVOLUTION_DOWNGRADED_ENTRY_FIELDS = [
    FieldSpec(("plan_evolution", "downgraded_encryption", "resources", "[]", "address"), "plan_evolution.downgraded_encryption.resources[].address", "Resource address that experienced a downgrade.", expected_type="string"),
    FieldSpec(("plan_evolution", "downgraded_encryption", "resources", "[]", "reasons"), "plan_evolution.downgraded_encryption.resources[].reasons", "List of downgrade reasons (storage_encrypted flip, kms removal).", expected_type="array"),
    FieldSpec(("plan_evolution", "downgraded_encryption", "resources", "[]", "previous"), "plan_evolution.downgraded_encryption.resources[].previous", "Previous encryption state snapshot.", expected_type="object"),
    FieldSpec(("plan_evolution", "downgraded_encryption", "resources", "[]", "current"), "plan_evolution.downgraded_encryption.resources[].current", "Current encryption state snapshot.", expected_type="object"),
]

COUNTS_FIELDS = [
    FieldSpec(("counts", "violations"), "counts.violations", "Number of violation strings emitted in the top-level array."),
]

VIOLATION_STRUCT_FIELDS = [
    FieldSpec(("violations_struct", "[]", "policy_id"), "violations_struct[].policy_id", "Policy identifier (e.g., P-SEC-001).", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "policy_name"), "violations_struct[].policy_name", "Human-readable policy title.", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "message"), "violations_struct[].message", "Original violation message for backwards compatibility.", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "severity"), "violations_struct[].severity", "Severity level derived from policy metadata.", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "resource"), "violations_struct[].resource", "Resource address shorthand (type.name / module path).", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "resource_details"), "violations_struct[].resource_details", "Resource metadata including module path and taint analysis.", expected_type="object"),
    FieldSpec(("violations_struct", "[]", "remediation"), "violations_struct[].remediation", "Structured remediation summary with docs and HCL completeness.", expected_type="object"),
]

VIOLATION_RESOURCE_FIELDS = [
    FieldSpec(("violations_struct", "[]", "resource_details", "address"), "resource_details.address", "Full Terraform address when available.", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "resource_details", "type"), "resource_details.type", "Terraform resource type.", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "resource_details", "name"), "resource_details.name", "Resource name component.", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "resource_details", "module_path"), "resource_details.module_path", "Module path derived from the address (root/module.child).", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "resource_details", "data_taint"), "resource_details.data_taint", "Where the fix must occur (resource_body/module_source/variable_source).", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "resource_details", "taint_explanation"), "resource_details.taint_explanation", "Reasoning for the taint classification.", expected_type="string"),
]

VIOLATION_REMEDIATION_FIELDS = [
    FieldSpec(("violations_struct", "[]", "remediation", "summary"), "remediation.summary", "One-line remediation guidance.", expected_type="string"),
    FieldSpec(("violations_struct", "[]", "remediation", "hcl_examples"), "remediation.hcl_examples", "List of HCL snippets that resolve the violation.", expected_type="array"),
    FieldSpec(("violations_struct", "[]", "remediation", "docs"), "remediation.docs", "Reference documentation links.", expected_type="array"),
    FieldSpec(("violations_struct", "[]", "remediation", "hcl_completeness"), "remediation.hcl_completeness", "0–1 score indicating how complete the suggested HCL fix is.", expected_type="number"),
]

POLICY_ERROR_FIELDS = [
    FieldSpec(("policy_errors", "[]", "policy"), "policy_errors[].policy", "Policy identifier that raised an exception.", expected_type="string"),
    FieldSpec(("policy_errors", "[]", "error"), "policy_errors[].error", "Exception class + message captured from the policy runtime.", expected_type="string"),
]

SEVERITY_FIELDS = [
    FieldSpec(("violation_severity_summary", "critical"), "violation_severity_summary.critical", "Critical-level violation count."),
    FieldSpec(("violation_severity_summary", "high"), "violation_severity_summary.high", "High-level violation count."),
    FieldSpec(("violation_severity_summary", "medium"), "violation_severity_summary.medium", "Medium-level violation count."),
    FieldSpec(("violation_severity_summary", "low"), "violation_severity_summary.low", "Low-level violation count."),
]

VIOLATION_COUNT_FIELDS = [
    FieldSpec(("violation_count_by_severity", "critical"), "violation_count_by_severity.critical", "Critical-level violation count mirrored for backwards compatibility."),
    FieldSpec(("violation_count_by_severity", "high"), "violation_count_by_severity.high", "High-level violation count mirrored for backwards compatibility."),
    FieldSpec(("violation_count_by_severity", "medium"), "violation_count_by_severity.medium", "Medium-level violation count mirrored for backwards compatibility."),
    FieldSpec(("violation_count_by_severity", "low"), "violation_count_by_severity.low", "Low-level violation count mirrored for backwards compatibility."),
]

METRICS_FIELDS = [
    FieldSpec(("metrics", "eligible_checks"), "metrics.eligible_checks", "Total number of encryption + tagging resources evaluated."),
    FieldSpec(("metrics", "passed_checks"), "metrics.passed_checks", "Resources that satisfied the enforced guardrails."),
    FieldSpec(("metrics", "compliance_score"), "metrics.compliance_score", "0–100 normalized pass percentage after IAM penalties."),
    FieldSpec(("metrics", "network_exposure_score"), "metrics.network_exposure_score", "100 minus penalties for open security groups."),
    FieldSpec(("metrics", "open_sg_count"), "metrics.open_sg_count", "Security groups with 0.0.0.0/0 style ingress."),
    FieldSpec(("metrics", "iam_risky_actions"), "metrics.iam_risky_actions", "Count of IAM actions flagged as risky."),
    FieldSpec(("metrics", "iam_drift", "status"), "metrics.iam_drift.status", "IAM drift status mirrored into metrics for quick filters."),
    FieldSpec(("metrics", "iam_drift", "risky_change_count"), "metrics.iam_drift.risky_change_count", "Number of IAM drift findings mirrored into metrics."),
    FieldSpec(("metrics", "notes"), "metrics.notes", "Additional context for open security groups and IAM risk analysis."),
    FieldSpec(("metrics", "scan_duration_ms"), "metrics.scan_duration_ms", "CLI runtime duration in milliseconds."),
    FieldSpec(("metrics", "parser_mode"), "metrics.parser_mode", "Parser implementation used for the scan (streaming vs legacy)."),
    FieldSpec(("metrics", "resource_count"), "metrics.resource_count", "Resource count echoed into metrics for quick filters."),
]

METRIC_NOTES_FIELDS = [
    FieldSpec(("metrics", "notes", "open_security_groups"), "metrics.notes.open_security_groups", "Details for each open security group detected."),
    FieldSpec(("metrics", "notes", "iam_risky_details"), "metrics.notes.iam_risky_details", "Detailed descriptions of IAM risky actions."),
]

ENVIRONMENT_FIELDS = [
    FieldSpec(("environment", "platform"), "environment.platform", "Lowercase platform identifier (platform.system) or VSCAN_ENV_PLATFORM override."),
    FieldSpec(("environment", "platform_release"), "environment.platform_release", "Kernel/platform release string or VSCAN_ENV_PLATFORM_RELEASE override."),
    FieldSpec(("environment", "python_version"), "environment.python_version", "Detected Python version or VSCAN_ENV_PYTHON_VERSION override."),
    FieldSpec(("environment", "python_implementation"), "environment.python_implementation", "Python implementation name or VSCAN_ENV_PYTHON_IMPL override."),
    FieldSpec(("environment", "terraform_version"), "environment.terraform_version", "Terraform CLI version used (or not-run/unknown when absent)."),
    FieldSpec(("environment", "terraform_source"), "environment.terraform_source", "Source of Terraform binary (system/download/override/not-run)."),
    FieldSpec(("environment", "vectorscan_version"), "environment.vectorscan_version", "VectorScan version reported inside the metadata block (overridable via VSCAN_ENV_VECTORSCAN_VERSION)."),
    FieldSpec(("environment", "strict_mode"), "environment.strict_mode", "Boolean indicating VSCAN_STRICT enforcement.", expected_type="boolean"),
    FieldSpec(("environment", "offline_mode"), "environment.offline_mode", "Boolean indicating offline/air-gapped execution.", expected_type="boolean"),
]

RESOURCE_FILTER_FIELDS = [
    FieldSpec(("resource_filter", "input"), "resource_filter.input", "Original --resource input string.", expected_type="string"),
    FieldSpec(("resource_filter", "address"), "resource_filter.address", "Fully-qualified Terraform resource address that matched the selector.", expected_type="string"),
    FieldSpec(("resource_filter", "type"), "resource_filter.type", "Terraform resource type for the scoped result.", expected_type="string"),
    FieldSpec(("resource_filter", "name"), "resource_filter.name", "Resource name component from the scoped address.", expected_type="string"),
    FieldSpec(("resource_filter", "module_path"), "resource_filter.module_path", "Module path derived from the scoped address.", expected_type="string"),
    FieldSpec(("resource_filter", "match"), "resource_filter.match", "Indicates whether the selector resolved via exact or suffix match.", expected_type="string"),
]

PLAN_METADATA_FIELDS = [
    FieldSpec(("plan_metadata", "resource_count"), "plan_metadata.resource_count", "Total number of resources discovered across the plan."),
    FieldSpec(("plan_metadata", "module_count"), "plan_metadata.module_count", "Total number of modules (root + nested) present in the plan."),
    FieldSpec(("plan_metadata", "resource_types"), "plan_metadata.resource_types", "Map of Terraform resource type → count."),
    FieldSpec(("plan_metadata", "providers"), "plan_metadata.providers", "Sorted list of inferred providers present in the plan."),
    FieldSpec(("plan_metadata", "modules", "root"), "plan_metadata.modules.root", "Root module address (defaults to 'root')."),
    FieldSpec(("plan_metadata", "modules", "with_resources"), "plan_metadata.modules.with_resources", "Number of modules that contain at least one resource."),
    FieldSpec(("plan_metadata", "modules", "child_module_count"), "plan_metadata.modules.child_module_count", "Count of nested/child modules encountered."),
    FieldSpec(("plan_metadata", "modules", "has_child_modules"), "plan_metadata.modules.has_child_modules", "Boolean indicating whether any child modules exist.", expected_type="boolean"),
    FieldSpec(("plan_metadata", "change_summary"), "plan_metadata.change_summary", "Map of adds/changes/destroys counters derived from Terraform resource_changes.", expected_type="object"),
    FieldSpec(("plan_metadata", "resources_by_type"), "plan_metadata.resources_by_type", "Per-type map of `{planned, adds, changes, destroys}` counts.", expected_type="object"),
    FieldSpec(("plan_metadata", "file_size_mb"), "plan_metadata.file_size_mb", "Plan file size converted to MB (rounded).", expected_type="number"),
    FieldSpec(("plan_metadata", "file_size_bytes"), "plan_metadata.file_size_bytes", "Raw plan file size in bytes.", expected_type="integer"),
    FieldSpec(("plan_metadata", "parse_duration_ms"), "plan_metadata.parse_duration_ms", "Plan parsing duration captured by the streaming parser.", expected_type="integer"),
    FieldSpec(("plan_metadata", "plan_slo", "active_window"), "plan_metadata.plan_slo.active_window", "SLO tier label (fast_path/large_plan/oversized).", expected_type="string"),
    FieldSpec(("plan_metadata", "plan_slo", "observed"), "plan_metadata.plan_slo.observed", "Observed metrics (resource_count, parse_duration_ms, file_size_bytes).", expected_type="object"),
    FieldSpec(("plan_metadata", "plan_slo", "thresholds"), "plan_metadata.plan_slo.thresholds", "Threshold metadata for each SLO tier.", expected_type="object"),
    FieldSpec(("plan_metadata", "plan_slo", "breach_reason"), "plan_metadata.plan_slo.breach_reason", "Reason provided when the plan breaches the active SLO.", expected_type="string"),
    FieldSpec(("plan_metadata", "exceeds_threshold"), "plan_metadata.exceeds_threshold", "Boolean recording whether the plan exceeded the SLO thresholds.", expected_type="boolean"),
]

PLAN_DIFF_FIELDS = [
    FieldSpec(("plan_diff", "summary", "adds"), "plan_diff.summary.adds", "Number of resources slated for creation in the diff scope.", expected_type="integer"),
    FieldSpec(("plan_diff", "summary", "changes"), "plan_diff.summary.changes", "Number of resources being modified.", expected_type="integer"),
    FieldSpec(("plan_diff", "summary", "destroys"), "plan_diff.summary.destroys", "Number of resources being destroyed.", expected_type="integer"),
]

PLAN_DIFF_RESOURCE_FIELDS = [
    FieldSpec(("plan_diff", "resources", "[]", "address"), "plan_diff.resources[].address", "Full Terraform address for the changed resource.", expected_type="string"),
    FieldSpec(("plan_diff", "resources", "[]", "type"), "plan_diff.resources[].type", "Terraform resource type for the diff entry.", expected_type="string"),
    FieldSpec(("plan_diff", "resources", "[]", "name"), "plan_diff.resources[].name", "Resource name component derived from the address.", expected_type="string"),
    FieldSpec(("plan_diff", "resources", "[]", "change_type"), "plan_diff.resources[].change_type", "Canonical change bucket (adds/changes/destroys).", expected_type="string"),
    FieldSpec(("plan_diff", "resources", "[]", "actions"), "plan_diff.resources[].actions", "Underlying Terraform actions reported for the change.", expected_type="array"),
    FieldSpec(("plan_diff", "resources", "[]", "changed_attributes"), "plan_diff.resources[].changed_attributes", "Array of changed attribute objects scoped to this resource.", expected_type="array"),
]

PLAN_DIFF_ATTRIBUTE_FIELDS = [
    FieldSpec(("plan_diff", "resources", "[]", "changed_attributes", "[]", "path"), "plan_diff.resources[].changed_attributes[].path", "Dot-delimited attribute path that changed.", expected_type="string"),
    FieldSpec(("plan_diff", "resources", "[]", "changed_attributes", "[]", "before"), "plan_diff.resources[].changed_attributes[].before", "Value before the change (can be null when resource is new).", expected_type="string"),
    FieldSpec(("plan_diff", "resources", "[]", "changed_attributes", "[]", "after"), "plan_diff.resources[].changed_attributes[].after", "Value after the change (can be null when resource is destroyed).", expected_type="string"),
]

EXPLANATION_FIELDS = [
    FieldSpec(("explanation", "summary"), "explanation.summary", "Human-readable summary of status, compliance score, severity counts, and IAM drift.", expected_type="string"),
    FieldSpec(("explanation", "plan_overview", "narrative"), "explanation.plan_overview.narrative", "Narrative describing resource/module/provider mix.", expected_type="string"),
    FieldSpec(("explanation", "scores", "compliance_score"), "explanation.scores.compliance_score", "Compliance score echoed for explain consumers.", expected_type="integer"),
    FieldSpec(("explanation", "scores", "network_exposure_score"), "explanation.scores.network_exposure_score", "Network exposure score copy.", expected_type="integer"),
    FieldSpec(("explanation", "risk_highlights"), "explanation.risk_highlights", "List of high-risk resources derived from violations.", expected_type="array"),
    FieldSpec(("explanation", "iam_drift", "summary"), "explanation.iam_drift.summary", "Plain-language IAM drift summary mirroring iam_drift_report.", expected_type="string"),
    FieldSpec(("explanation", "recommendations"), "explanation.recommendations", "Ordered list of guardrail recommendations.", expected_type="array"),
    FieldSpec(("explanation", "policy_context"), "explanation.policy_context", "Metadata for each guardrail referenced in the explanation block.", expected_type="array"),
]

IAM_DRIFT_FIELDS = [
    FieldSpec(("iam_drift_report", "status"), "iam_drift_report.status", "PASS/FAIL summary of IAM drift analysis."),
    FieldSpec(("iam_drift_report", "counts", "risky_changes"), "iam_drift_report.counts.risky_changes", "Number of IAM resources with newly risky actions."),
    FieldSpec(("iam_drift_report", "items"), "iam_drift_report.items", "List of per-resource IAM drift findings."),
]

IAM_DRIFT_ITEM_FIELDS = [
    FieldSpec(("iam_drift_report", "items", "[]", "resource_type"), "iam_drift_report.items[].resource_type", "Terraform resource type for the IAM policy under review.", expected_type="string"),
    FieldSpec(("iam_drift_report", "items", "[]", "resource_name"), "iam_drift_report.items[].resource_name", "Resource name/address in the plan.", expected_type="string"),
    FieldSpec(("iam_drift_report", "items", "[]", "risky_additions"), "iam_drift_report.items[].risky_additions", "IAM actions newly introduced by the change.", expected_type="array<string>"),
    FieldSpec(("iam_drift_report", "items", "[]", "severity_by_action"), "iam_drift_report.items[].severity_by_action", "Per-action severity map (high/medium).", expected_type="object"),
    FieldSpec(("iam_drift_report", "items", "[]", "notaction_broad_allow"), "iam_drift_report.items[].notaction_broad_allow", "Boolean indicating NotAction + Resource '*' pattern.", expected_type="boolean"),
]

TERRAFORM_FIELDS = [
    FieldSpec(("terraform_tests", "status"), "terraform_tests.status", "PASS/FAIL/SKIP from 'terraform test'.", expected_type="string"),
    FieldSpec(("terraform_tests", "version"), "terraform_tests.version", "Terraform CLI version used for tests.", expected_type="string"),
    FieldSpec(("terraform_tests", "binary"), "terraform_tests.binary", "Path to the Terraform binary used for tests.", expected_type="string"),
    FieldSpec(("terraform_tests", "source"), "terraform_tests.source", "Where the CLI was resolved (system/download/override).", expected_type="string"),
    FieldSpec(("terraform_tests", "strategy"), "terraform_tests.strategy", "Named test harness that executed (modern, legacy, etc.).", expected_type="string"),
    FieldSpec(("terraform_tests", "message"), "terraform_tests.message", "Contextual status or error message from Terraform test orchestration.", expected_type="string"),
    FieldSpec(("terraform_tests", "stdout"), "terraform_tests.stdout", "Truncated stdout from Terraform tests.", expected_type="string"),
    FieldSpec(("terraform_tests", "stderr"), "terraform_tests.stderr", "Truncated stderr from Terraform tests.", expected_type="string"),
    FieldSpec(("terraform_tests", "returncode"), "terraform_tests.returncode", "Return code emitted by the executed Terraform command (null when skipped).", expected_type="integer"),
]

PREVIEW_FIELDS = [
    FieldSpec(("preview_generated",), "preview_generated", "Boolean flag indicating preview mode is active.", expected_type="boolean"),
    FieldSpec(("preview_policies", "[]", "id"), "preview_policies[].id", "Preview policy identifier surfaced from the manifest.", expected_type="string"),
    FieldSpec(("preview_policies", "[]", "summary"), "preview_policies[].summary", "One-line description of the teaser policy.", expected_type="string"),
    FieldSpec(("preview_manifest", "version"), "preview_manifest.version", "Preview manifest version tag.", expected_type="string"),
    FieldSpec(("preview_manifest", "generated_at"), "preview_manifest.generated_at", "ISO8601 timestamp describing when the manifest was produced.", expected_type="string"),
    FieldSpec(("preview_manifest", "signature"), "preview_manifest.signature", "sha256-prefixed signature verifying the preview manifest contents.", expected_type="string"),
    FieldSpec(("preview_manifest", "verified"), "preview_manifest.verified", "Boolean indicating whether the manifest signature verification succeeded or was skipped via env overrides.", expected_type="boolean"),
]

POLICY_MANIFEST_FIELDS = [
    FieldSpec(("policy_manifest", "policy_version"), "policy_manifest.policy_version", "Policy version captured inside the manifest.", expected_type="string"),
    FieldSpec(("policy_manifest", "policy_pack_hash"), "policy_manifest.policy_pack_hash", "Hash of the bundled policy files asserted by the manifest.", expected_type="string"),
    FieldSpec(("policy_manifest", "policy_source_url"), "policy_manifest.policy_source_url", "Reference URL for the policy pack source.", expected_type="string"),
    FieldSpec(("policy_manifest", "policy_count"), "policy_manifest.policy_count", "Number of policies described by the manifest.", expected_type="integer"),
    FieldSpec(("policy_manifest", "policies"), "policy_manifest.policies", "List of policy metadata entries covered by the manifest.", expected_type="array"),
    FieldSpec(("policy_manifest", "policies", "[]", "id"), "policy_manifest.policies[].id", "Policy identifier in the manifest entry.", expected_type="string"),
    FieldSpec(("policy_manifest", "policies", "[]", "name"), "policy_manifest.policies[].name", "Human-readable policy name.", expected_type="string"),
    FieldSpec(("policy_manifest", "policies", "[]", "category"), "policy_manifest.policies[].category", "Policy category such as security or finops.", expected_type="string"),
    FieldSpec(("policy_manifest", "policies", "[]", "severity"), "policy_manifest.policies[].severity", "Policy severity rating.", expected_type="string"),
    FieldSpec(("policy_manifest", "policies", "[]", "description"), "policy_manifest.policies[].description", "Human-readable description for the policy.", expected_type="string"),
    FieldSpec(("policy_manifest", "signature"), "policy_manifest.signature", "sha256-prefixed signature over the manifest payload.", expected_type="string"),
    FieldSpec(("policy_manifest", "signed"), "policy_manifest.signed", "Boolean indicating a signature is attached.", expected_type="boolean"),
    FieldSpec(("policy_manifest", "verified"), "policy_manifest.verified", "Boolean indicating signature verification succeeded.", expected_type="boolean"),
    FieldSpec(("policy_manifest", "path"), "policy_manifest.path", "Filesystem path for the manifest file (embedded or overridden).", expected_type="string"),
]

ALL_SECTIONS = [
    ("Top-Level Fields", TOP_LEVEL_FIELDS),
    ("Counts", COUNTS_FIELDS),
    ("Structured Violations", VIOLATION_STRUCT_FIELDS),
    ("Violation Resource Details", VIOLATION_RESOURCE_FIELDS),
    ("Violation Remediation", VIOLATION_REMEDIATION_FIELDS),
    ("Violation Severity Summary", SEVERITY_FIELDS),
    ("Violation Count by Severity", VIOLATION_COUNT_FIELDS),
    ("Policy Errors", POLICY_ERROR_FIELDS),
    ("Metrics", METRICS_FIELDS),
    ("Metric Notes", METRIC_NOTES_FIELDS),
    ("Environment Metadata", ENVIRONMENT_FIELDS),
    ("Resource Filter (--resource)", RESOURCE_FILTER_FIELDS),
    ("Plan Metadata", PLAN_METADATA_FIELDS),
    ("Plan Smell Report", SMELL_REPORT_FIELDS),
    ("Plan Smell Entries", SMELL_ITEM_FIELDS),
    ("Plan Evolution (Compare Mode)", PLAN_EVOLUTION_PLAN_FIELDS),
    ("Plan Evolution Delta", PLAN_EVOLUTION_DELTA_FIELDS),
    ("Plan Evolution Summary", PLAN_EVOLUTION_SUMMARY_FIELDS),
    ("Plan Evolution Downgraded Encryption", PLAN_EVOLUTION_DOWNGRADED_FIELDS),
    ("Plan Evolution Downgraded Entries", PLAN_EVOLUTION_DOWNGRADED_ENTRY_FIELDS),
    ("Plan Diff (--diff)", PLAN_DIFF_FIELDS),
    ("Plan Diff Resources", PLAN_DIFF_RESOURCE_FIELDS),
    ("Plan Diff Attributes", PLAN_DIFF_ATTRIBUTE_FIELDS),
    ("Explanation Block (--explain)", EXPLANATION_FIELDS),
    ("IAM Drift Report", IAM_DRIFT_FIELDS),
    ("IAM Drift Items", IAM_DRIFT_ITEM_FIELDS),
    ("Terraform Tests", TERRAFORM_FIELDS),
    ("VectorGuard Preview", PREVIEW_FIELDS),
    ("Policy Manifest", POLICY_MANIFEST_FIELDS),
]


class SchemaDocError(RuntimeError):
    pass


def _describe_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if value is None:
        return "null"
    if isinstance(value, list):
        if not value:
            return "array"
        return f"array<{_describe_type(value[0])}>"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _lookup(data: Dict[str, Any], path: Tuple[str, ...]) -> Any:
    cursor: Any = data
    for part in path:
        if part == "[]":
            if not isinstance(cursor, list) or not cursor:
                raise SchemaDocError(f"Cannot descend into empty list for path {'/'.join(path)}")
            cursor = cursor[0]
            continue
        if not isinstance(cursor, dict):
            raise SchemaDocError(f"Expected dict when traversing {path}, got {type(cursor).__name__}")
        if part not in cursor:
            raise SchemaDocError(f"Key '{part}' missing when traversing {path}")
        cursor = cursor[part]
    return cursor


def _value_from_samples(samples: Sequence[Dict[str, Any]], path: Tuple[str, ...]) -> Any:
    last_error: SchemaDocError | None = None
    fallback: Any = None
    for sample in samples:
        try:
            value = _lookup(sample, path)
        except SchemaDocError as exc:
            last_error = exc
            continue
        if isinstance(value, list) and not value:
            fallback = value
            continue
        return value
    if fallback is not None:
        return fallback
    if last_error:
        raise last_error
    raise SchemaDocError(f"None of the samples expose path {'/'.join(path)}")


def _render_table(specs: Iterable[FieldSpec], samples: Sequence[Dict[str, Any]]) -> str:
    rows = ["| Field | Type | Description |", "| --- | --- | --- |"]
    for spec in specs:
        value = None
        dtype = spec.expected_type or "unknown"
        try:
            value = _value_from_samples(samples, spec.path)
        except SchemaDocError as exc:
            if spec.expected_type is None:
                raise SchemaDocError(str(exc))
        else:
            dtype = _describe_type(value)
        rows.append(f"| `{spec.label}` | `{dtype}` | {spec.description} |")
    return "\n".join(rows)


def _format_excerpt(value: Any, *, limit: int = 280) -> str:
    snippet = json.dumps(value, indent=2, ensure_ascii=False)
    if len(snippet) > limit:
        snippet = snippet[:limit].rstrip() + "…"
    return snippet


def _build_samples(
    plan_paths: Sequence[Path],
    cli_path: Path,
    *,
    env: Dict[str, str],
    compare_pairs: Sequence[Tuple[Path, Path]] | None = None,
) -> List[Dict[str, Any]]:
    samples: List[Dict[str, Any]] = []
    for plan in plan_paths:
        cmd = [sys.executable, str(cli_path), str(plan), "--json"]
        cmd.append("--explain")
        cmd.append("--diff")
        cmd.append("--preview-vectorguard")
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode not in {0, 3, PREVIEW_EXIT_CODE}:
            raise SchemaDocError(
                f"VectorScan exited with code {result.returncode} for {plan}. stderr={result.stderr.strip()}"
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SchemaDocError(f"Failed to parse JSON output for {plan}: {exc}") from exc
        samples.append(payload)
    for old_path, new_path in compare_pairs or []:
        cmd = [
            sys.executable,
            str(cli_path),
            "--json",
            "--compare",
            str(old_path),
            str(new_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            raise SchemaDocError(
                f"VectorScan compare mode exited with code {result.returncode} for {old_path} vs {new_path}. stderr={result.stderr.strip()}"
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SchemaDocError(
                f"Failed to parse JSON output for compare pair {old_path} vs {new_path}: {exc}"
            ) from exc
        samples.append(payload)
    return samples


def generate_schema_markdown(
    *,
    plan_paths: Sequence[Path] | None = None,
    compare_pairs: Sequence[Tuple[Path, Path]] | None = None,
    cli_path: Path = CLI_PATH,
    output_path: Path = DEFAULT_OUTPUT,
) -> str:
    plan_paths = list(plan_paths or (DEFAULT_PASS_PLAN, DEFAULT_FAIL_PLAN))
    compare_pairs = list(compare_pairs or (DEFAULT_COMPARE_PAIR,))
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(ROOT))
    env.setdefault("VSCAN_OFFLINE", "1")
    env.setdefault("VSCAN_CLOCK_EPOCH", "1730000000")
    env.setdefault("VSCAN_CLOCK_ISO", "2024-11-16T00:00:00Z")
    env.setdefault("VSCAN_FORCE_DURATION_MS", "250")
    env.setdefault("VSCAN_FORCE_PLAN_PARSE_MS", "250")
    samples = _build_samples(plan_paths, cli_path, env=env, compare_pairs=compare_pairs)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    header = textwrap.dedent(
        f"""
        # VectorScan Output Schema

        _Generated on {timestamp} via `scripts/generate_schema_docs.py`. Run the script again after schema changes to keep this document accurate._
        """
    ).strip()

    summary_lines = [
        "## Sample Coverage",
        "",
        "This schema is derived from the union of these fixture runs:",
    ]
    for plan in plan_paths:
        try:
            display = plan.relative_to(ROOT)
        except ValueError:
            display = plan
        summary_lines.append(f"- `{display}`")
    if compare_pairs:
        summary_lines.append("")
        summary_lines.append("Compare samples:")
        for old_path, new_path in compare_pairs:
            try:
                old_display = old_path.relative_to(ROOT)
            except ValueError:
                old_display = old_path
            try:
                new_display = new_path.relative_to(ROOT)
            except ValueError:
                new_display = new_path
            summary_lines.append(f"- `{old_display}` → `{new_display}`")

    body_sections = [header, "", *summary_lines, ""]

    def _section_example_path(field: FieldSpec) -> Tuple[str, ...]:
        path = field.path[:-1]
        while path and path[-1] == "[]":
            path = path[:-1]
        return path

    for title, fields in ALL_SECTIONS:
        body_sections.append(f"## {title}")
        body_sections.append("")
        body_sections.append(_render_table(fields, samples))
        body_sections.append("")

        # Attach example excerpts for complex structures
        if any(spec.path[-1] in {"violations", "policy_errors", "items", "notes", "iam_drift"} for spec in fields):
            example_path = _section_example_path(fields[0])
            example_value = None
            if example_path:
                try:
                    example_value = _value_from_samples(samples, example_path)
                except SchemaDocError:
                    example_value = None
            if example_value is not None and isinstance(example_value, (dict, list)):
                body_sections.append("<details><summary>Example</summary>\n\n")
                body_sections.append("```json")
                body_sections.append(_format_excerpt(example_value))
                body_sections.append("```")
                body_sections.append("\n</details>")
                body_sections.append("")

    markdown = "\n".join(body_sections).rstrip() + "\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    return markdown


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/output_schema.md from live CLI output.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Destination markdown path (default docs/output_schema.md)")
    parser.add_argument(
        "--plan",
        action="append",
        type=Path,
        help="Optional tfplan fixture path. Defaults to bundled pass/fail fixtures (repeat flag for multiples).",
    )
    parser.add_argument(
        "--compare",
        action="append",
        nargs=2,
        metavar=("OLD_PLAN", "NEW_PLAN"),
        help="Optional pair of tfplan fixtures to run via --compare for documenting plan_evolution.",
    )
    parser.add_argument("--cli", type=Path, default=CLI_PATH, help="Path to vectorscan.py (default tools/vectorscan/vectorscan.py)")
    args = parser.parse_args(argv)

    plan_paths = args.plan or None
    compare_pairs = None
    if args.compare:
        compare_pairs = [(Path(old), Path(new)) for old, new in args.compare]
    try:
        generate_schema_markdown(
            plan_paths=plan_paths,
            compare_pairs=compare_pairs,
            cli_path=args.cli,
            output_path=args.output,
        )
    except SchemaDocError as exc:
        print(f"Schema doc generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
