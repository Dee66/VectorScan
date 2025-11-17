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
CLI_PATH = ROOT / "tools" / "vectorscan" / "vectorscan.py"


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
    FieldSpec(("iam_drift_report",), "iam_drift_report", "IAM drift analysis output with risky additions and severities."),
    FieldSpec(("terraform_tests",), "terraform_tests", "Optional Terraform test run metadata (present when --terraform-tests is used).", expected_type="object"),
    FieldSpec(("environment",), "environment", "Runtime metadata (platform, Python, Terraform, VectorScan, strict/offline flags).", expected_type="object"),
    FieldSpec(("plan_metadata",), "plan_metadata", "Terraform plan inventory summary (resource/module counts, providers, types).", expected_type="object"),
    FieldSpec(("plan_diff",), "plan_diff", "Change-only diff summary emitted when --diff is provided.", expected_type="object"),
    FieldSpec(("explanation",), "explanation", "Narrative explain block emitted when --explain is provided.", expected_type="object"),
    FieldSpec(("vectorscan_version",), "vectorscan_version", "Semantic version of the CLI binary producing the output."),
    FieldSpec(("policy_version",), "policy_version", "Policy pack SemVer string for auditors."),
    FieldSpec(("schema_version",), "schema_version", "Version tag for this JSON schema contract."),
    FieldSpec(("policy_pack_hash",), "policy_pack_hash", "SHA-256 hash of the shipped policy bundle."),
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
    FieldSpec(("terraform_tests", "source"), "terraform_tests.source", "Where the CLI was resolved (system/download/override).", expected_type="string"),
    FieldSpec(("terraform_tests", "strategy"), "terraform_tests.strategy", "Named test harness that executed (modern, legacy, etc.).", expected_type="string"),
    FieldSpec(("terraform_tests", "stdout"), "terraform_tests.stdout", "Truncated stdout from Terraform tests.", expected_type="string"),
    FieldSpec(("terraform_tests", "stderr"), "terraform_tests.stderr", "Truncated stderr from Terraform tests.", expected_type="string"),
]

ALL_SECTIONS = [
    ("Top-Level Fields", TOP_LEVEL_FIELDS),
    ("Counts", COUNTS_FIELDS),
    ("Structured Violations", VIOLATION_STRUCT_FIELDS),
    ("Violation Resource Details", VIOLATION_RESOURCE_FIELDS),
    ("Violation Remediation", VIOLATION_REMEDIATION_FIELDS),
    ("Violation Severity Summary", SEVERITY_FIELDS),
    ("Policy Errors", POLICY_ERROR_FIELDS),
    ("Metrics", METRICS_FIELDS),
    ("Metric Notes", METRIC_NOTES_FIELDS),
    ("Environment Metadata", ENVIRONMENT_FIELDS),
    ("Plan Metadata", PLAN_METADATA_FIELDS),
    ("Plan Diff (--diff)", PLAN_DIFF_FIELDS),
    ("Plan Diff Resources", PLAN_DIFF_RESOURCE_FIELDS),
    ("Plan Diff Attributes", PLAN_DIFF_ATTRIBUTE_FIELDS),
    ("Explanation Block (--explain)", EXPLANATION_FIELDS),
    ("IAM Drift Report", IAM_DRIFT_FIELDS),
    ("IAM Drift Items", IAM_DRIFT_ITEM_FIELDS),
    ("Terraform Tests", TERRAFORM_FIELDS),
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


def _build_samples(plan_paths: Sequence[Path], cli_path: Path, *, env: Dict[str, str]) -> List[Dict[str, Any]]:
    samples: List[Dict[str, Any]] = []
    for plan in plan_paths:
        cmd = [sys.executable, str(cli_path), str(plan), "--json"]
        cmd.append("--explain")
        cmd.append("--diff")
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode not in {0, 3}:
            raise SchemaDocError(
                f"VectorScan exited with code {result.returncode} for {plan}. stderr={result.stderr.strip()}"
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SchemaDocError(f"Failed to parse JSON output for {plan}: {exc}") from exc
        samples.append(payload)
    return samples


def generate_schema_markdown(
    *,
    plan_paths: Sequence[Path] | None = None,
    cli_path: Path = CLI_PATH,
    output_path: Path = DEFAULT_OUTPUT,
) -> str:
    plan_paths = list(plan_paths or (DEFAULT_PASS_PLAN, DEFAULT_FAIL_PLAN))
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(ROOT))
    env.setdefault("VSCAN_OFFLINE", "1")
    env.setdefault("VSCAN_CLOCK_EPOCH", "1730000000")
    env.setdefault("VSCAN_CLOCK_ISO", "2024-11-16T00:00:00Z")
    samples = _build_samples(plan_paths, cli_path, env=env)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    header = textwrap.dedent(
        f"""
        # VectorScan Output Schema

        _Generated on {timestamp} via `scripts/generate_schema_docs.py`. Run the script again after schema changes to keep this document accurate._
        """
    ).strip()

    summary_lines = [
        "## Sample Coverage",
        "", "This schema is derived from the union of these fixture runs:",
    ]
    for plan in plan_paths:
        try:
            display = plan.relative_to(ROOT)
        except ValueError:
            display = plan
        summary_lines.append(f"- `{display}`")

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
    parser.add_argument("--cli", type=Path, default=CLI_PATH, help="Path to vectorscan.py (default tools/vectorscan/vectorscan.py)")
    args = parser.parse_args(argv)

    plan_paths = args.plan or None
    try:
        generate_schema_markdown(plan_paths=plan_paths, cli_path=args.cli, output_path=args.output)
    except SchemaDocError as exc:
        print(f"Schema doc generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
