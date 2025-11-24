# VS-017 — Reconciliation Diff Report

## src/pillar/cli.py
```diff
@@ -150,10 +150,11 @@ def main(argv: Optional[Sequence[str]] = None) -> int:
 
 
 def _handle_scan(plan: Optional[Path], stdin: bool, options: ScanOptions) -> int:
+	strict_mode_active = legacy.strict_mode_enabled()
 	try:
 		plan_payload, source_path, raw_size = _load_plan_payload(plan, stdin)
 	except PlanLoadError as exc:
-		_return_plan_error(str(exc))
+		_return_plan_error(str(exc), strict_mode_active=strict_mode_active)
 	return _execute_scan(plan_payload, source_path, raw_size, options)
 
 
@@ -305,10 +306,11 @@ def _handle_lead_capture(
 		or options.endpoint
 		or os.getenv("VSCAN_LEAD_ENDPOINT")
 	)
-	if not wants_capture or offline_mode:
+	if not wants_capture:
 		return
 	output_stream = sys.stderr if options.as_json else sys.stdout
-	if options.force_no_network or not allow_network_capture:
+	no_network_active = offline_mode or options.force_no_network or not allow_network_capture
+	if no_network_active:
 		_SAFE_PRINT(error_text.NO_NETWORK_MESSAGE, stream=output_stream)
 		return
 	lead = {
@@ -361,9 +363,12 @@ def _load_plan_payload(
 	return payload, plan, len(text.encode("utf-8"))
 
 
-def _return_plan_error(message: str) -> None:
-	_SAFE_PRINT(message, stream=sys.stderr)
-	_SAFE_PRINT("", stream=sys.stderr)
+def _return_plan_error(message: str, *, strict_mode_active: bool = False) -> None:
+	if strict_mode_active:
+		emit_strict_mode_banner(message)
+	else:
+		_SAFE_PRINT(message, stream=sys.stderr)
+		_SAFE_PRINT("", stream=sys.stderr)
 	raise SystemExit(EXIT_INVALID_INPUT)
 
 
```

## src/pillar/constants.py
```diff
@@ -1,2 +1,13 @@
-# Pillar constants placeholder for deterministic metadata (pillar name, schema versions, etc.).
-# TODO: define canonical constant values once migration wiring is ready.
+"""Deterministic pillar constants consumed across the GuardSuite pipeline."""
+
+PILLAR_NAME = "VectorScan"
+SCAN_VERSION = "v2.0.0"
+GUARDSCORE_RULES_VERSION = "2025.1"
+CANONICAL_SCHEMA_VERSION = "1.0.0"
+
+__all__ = [
+	"PILLAR_NAME",
+	"SCAN_VERSION",
+	"GUARDSCORE_RULES_VERSION",
+	"CANONICAL_SCHEMA_VERSION",
+]
```

## src/pillar/evaluator.py
```diff
@@ -1,2 +1,204 @@
-# Evaluator placeholder for canonical pillar pipeline.
-# TODO: implement plan evaluation bridge to rule registry and fixpack metadata.
+from __future__ import annotations
+
+from dataclasses import replace
+from pathlib import Path
+from typing import Any, Dict, Optional
+
+from src.pillar import constants as pillar_constants
+from src.pillar.compat.normalization import (
+    NormalizationResult,
+    ScanOptions,
+    audit_ledger_synthesize,
+    canonical_issue_collect,
+    flatten_plan,
+    iam_drift_normalize,
+    metadata_inject,
+    severity_aggregate,
+    build_control_flags,
+    resolve_offline_mode,
+    run_normalized_scan,
+)
+from src.pillar.rules import registry as rule_registry
+from src.pillar.rules.rule_engine import evaluate_rules
+from src.pillar.metadata import build_metadata
+from tools.vectorscan.constants import (
+    EXIT_PREVIEW_MODE,
+    EXIT_TERRAFORM_ERROR,
+    EXIT_TERRAFORM_FAIL,
+)
+
+
+def evaluate_scan(
+    plan: Dict[str, Any],
+    *,
+    source_path: Optional[Path] = None,
+    raw_size: Optional[int] = None,
+    options: Optional[ScanOptions] = None,
+) -> NormalizationResult:
+    """Execute the legacy-parity normalization pipeline."""
+
+    resolved_options = options or ScanOptions()
+    flattened = flatten_plan(plan)
+    enriched = metadata_inject(flattened)
+    enriched = iam_drift_normalize(enriched)
+    enriched = canonical_issue_collect(enriched)
+    _evaluate_stub_rules(enriched)
+    enriched = severity_aggregate(enriched)
+    enriched = audit_ledger_synthesize(enriched)
+    offline_mode = resolve_offline_mode(enriched, resolved_options)
+    environment_block = dict(enriched.get("environment") or {})
+    control_flags = build_control_flags(enriched, resolved_options, offline_mode)
+    environment_block.update(control_flags)
+    enriched["environment"] = environment_block
+    enriched["_control_flags"] = control_flags
+    enriched["_canonical_metadata"] = build_metadata(enriched)
+    evaluation_value = enriched.get("evaluation")
+    evaluation_block = evaluation_value if isinstance(evaluation_value, dict) else None
+    if evaluation_block is not None:
+        flags_block = evaluation_block.setdefault("flags", {})
+        flags_block.update(control_flags)
+        evaluation_block["scan_version"] = pillar_constants.SCAN_VERSION
+        metadata_block = evaluation_block.setdefault("metadata", {})
+        control_meta = metadata_block.setdefault("control", {})
+        control_meta.update(control_flags)
+        enriched["evaluation"] = evaluation_block
+    raw_result = run_normalized_scan(
+        enriched["plan"],
+        source_path=source_path,
+        raw_size=raw_size,
+        options=resolved_options,
+        flattened=enriched,
+    )
+    payload_view = raw_result.payload if isinstance(raw_result.payload, dict) else {}
+    payload_issues = payload_view.get("issues") if isinstance(payload_view.get("issues"), list) else []
+    updated_evaluation = raw_result.evaluation if isinstance(raw_result.evaluation, dict) else None
+    if updated_evaluation is not None:
+        updated_evaluation["issues"] = payload_issues
+        _attach_canonical_sections(updated_evaluation, payload_view)
+    severity_summary = raw_result.severity_summary if isinstance(raw_result.severity_summary, dict) else {}
+    exit_code = finalize_exit_code(severity_summary, updated_evaluation)
+    if raw_result.exit_code in (EXIT_TERRAFORM_FAIL, EXIT_TERRAFORM_ERROR):
+        exit_code = raw_result.exit_code
+        if updated_evaluation is not None:
+            updated_evaluation["exit_code"] = exit_code
+    if raw_result.exit_code == EXIT_PREVIEW_MODE:
+        exit_code = EXIT_PREVIEW_MODE
+        if updated_evaluation is not None:
+            updated_evaluation["exit_code"] = exit_code
+    return replace(
+        raw_result,
+        exit_code=exit_code,
+        evaluation=updated_evaluation,
+    )
+
+
+def _evaluate_stub_rules(enriched_context: Dict[str, Any]) -> None:
+    """Invoke deterministic rule stubs and append canonical issues."""
+
+    canonical_issues = enriched_context.get("issues")
+    if not isinstance(canonical_issues, list):
+        canonical_issues = []
+        enriched_context["issues"] = canonical_issues
+        evaluation_block = dict(enriched_context.get("evaluation") or {})
+        evaluation_block["issues"] = canonical_issues
+        enriched_context["evaluation"] = evaluation_block
+
+    rule_context = {
+        "plan": enriched_context.get("plan"),
+        "plan_metadata": enriched_context.get("plan_metadata"),
+        "environment": enriched_context.get("environment"),
+        "environment_label": enriched_context.get("environment_label", "vectorscan"),
+        "resources": enriched_context.get("resources"),
+        "evaluation": enriched_context.get("evaluation"),
+    }
+    rules = rule_registry.get_rules()
+    canonical_issues.extend(evaluate_rules(rules, context=rule_context))
+
+
+def fatal_error_payload(message: str) -> Dict[str, Any]:
+    """Return a minimal failure payload used for unexpected errors."""
+
+    return {
+        "status": "FAIL",
+        "error": message,
+    }
+
+
+def is_valid_plan_payload(plan: object) -> bool:
+    """Simple schema guard used by the validate command."""
+
+    return isinstance(plan, dict)
+
+
+def finalize_exit_code(
+    severity_summary: Optional[Dict[str, Any]],
+    evaluation: Optional[Dict[str, Any]] = None,
+) -> int:
+    """Compute and store the canonical exit code from severity summary data."""
+
+    if not isinstance(severity_summary, dict):
+        severity_summary = {}
+
+    def _count(level: str) -> int:
+        value = severity_summary.get(level)
+        try:
+            return int(value)
+        except (TypeError, ValueError):
+            return 0
+
+    exit_code = _exit_code_from_counts(
+        critical=_count("critical"),
+        high=_count("high"),
+        medium=_count("medium"),
+    )
+    if isinstance(evaluation, dict):
+        evaluation["exit_code"] = exit_code
+        normalized_summary = {
+            level: _count(level)
+            for level in ("critical", "high", "medium", "low")
+        }
+        evaluation["severity_summary"] = normalized_summary
+    return exit_code
+
+
+def _exit_code_from_counts(*, critical: int, high: int, medium: int) -> int:
+    if critical > 0:
+        return 3
+    if high > 0:
+        return 2
+    if medium > 0:
+        return 1
+    return 0
+
+
+def _attach_canonical_sections(evaluation_block: Dict[str, Any], payload_view: Dict[str, Any]) -> None:
+    evaluation_block.setdefault("pillar", pillar_constants.PILLAR_NAME)
+    evaluation_block.setdefault(
+        "guardscore_rules_version",
+        payload_view.get("guardscore_rules_version", pillar_constants.GUARDSCORE_RULES_VERSION),
+    )
+    evaluation_block.setdefault(
+        "badge_eligible",
+        bool(payload_view.get("badge_eligible", False)),
+    )
+    evaluation_block.setdefault(
+        "quick_score_mode",
+        bool(payload_view.get("quick_score_mode", False)),
+    )
+    latency_candidate = payload_view.get("latency_ms", 0)
+    try:
+        latency_value = int(latency_candidate)
+    except (TypeError, ValueError):
+        latency_value = 0
+    evaluation_block.setdefault("latency_ms", max(latency_value, 0))
+    evaluation_block.setdefault(
+        "schema_validation_error",
+        payload_view.get("schema_validation_error"),
+    )
+    metadata_block = payload_view.get("metadata")
+    if isinstance(metadata_block, dict):
+        control_block = metadata_block.get("control")
+        if isinstance(control_block, dict):
+            evaluation_metadata = evaluation_block.setdefault("metadata", {})
+            metadata_control = evaluation_metadata.setdefault("control", {})
+            metadata_control.update(control_block)
```

## src/pillar/metadata.py
```diff
@@ -1,2 +1,64 @@
-# Pillar metadata builder placeholder for environment and plan context.
-# TODO: implement metadata assembly helpers referencing canonical schema.
+from __future__ import annotations
+
+from copy import deepcopy
+from typing import Any, Dict
+
+from src.pillar import constants as pillar_constants
+
+
+def build_metadata(context: Dict[str, Any]) -> Dict[str, Any]:
+    """Return a deterministic metadata block derived from the evaluation context."""
+
+    metadata: Dict[str, Any] = {
+        "pillar": pillar_constants.PILLAR_NAME,
+        "scan_version": pillar_constants.SCAN_VERSION,
+        "canonical_schema_version": pillar_constants.CANONICAL_SCHEMA_VERSION,
+    }
+    plan_block = _copy_dict(context.get("plan_metadata"))
+    if plan_block:
+        metadata["plan"] = plan_block
+    environment_block = _build_environment_metadata(context)
+    if environment_block:
+        metadata["environment"] = environment_block
+    return metadata
+
+
+def _build_environment_metadata(context: Dict[str, Any]) -> Dict[str, Any]:
+    base_environment = _copy_dict(context.get("environment"))
+    flags = _extract_control_flags(context)
+    ordered: Dict[str, Any] = {}
+    for key in sorted(base_environment.keys()):
+        ordered[key] = base_environment[key]
+    ordered.update(_ordered_flag_snapshot(flags))
+    return ordered
+
+
+def _extract_control_flags(context: Dict[str, Any]) -> Dict[str, Any]:
+    raw_flags = context.get("_control_flags")
+    flags = dict(raw_flags) if isinstance(raw_flags, dict) else {}
+    environment_block = context.get("environment")
+    if isinstance(environment_block, dict):
+        for key in ("offline_mode", "allow_network_capture", "auto_download", "terraform_outcome"):
+            if key not in flags and key in environment_block:
+                flags[key] = environment_block[key]
+    return flags
+
+
+def _ordered_flag_snapshot(flags: Dict[str, Any]) -> Dict[str, Any]:
+    offline_mode = bool(flags.get("offline_mode"))
+    allow_network_capture = bool(flags.get("allow_network_capture"))
+    allow_network = bool(flags.get("allow_network", allow_network_capture))
+    auto_download = bool(flags.get("auto_download"))
+    terraform_outcome_value = flags.get("terraform_outcome")
+    terraform_outcome = str(terraform_outcome_value or "SKIP")
+    return {
+        "offline_mode": offline_mode,
+        "allow_network_capture": allow_network_capture,
+        "allow_network": allow_network,
+        "auto_download": auto_download,
+        "terraform_outcome": terraform_outcome,
+    }
+
+
+def _copy_dict(value: Any) -> Dict[str, Any]:
+    return deepcopy(value) if isinstance(value, dict) else {}
```

## src/pillar/rules/registry.py
```diff
@@ -1,2 +1,825 @@
-# Pillar rule registry placeholder describing deterministic ordering and signatures.
-# TODO: implement register(rule) helpers and all_rules iterator shared with evaluator.
+from __future__ import annotations
+
+from typing import Any, Dict, List, Sequence
+
+
+def _remediation_metadata(rule_id: str, summary: str, terraform_patch: str) -> Dict[str, str]:
+    return {
+        "fixpack_id": rule_id,
+        "summary": summary,
+        "terraform_patch": terraform_patch.strip(),
+    }
+
+_BASE_RULE_CATALOG: Sequence[Dict[str, Any]] = (
+    {
+        "id": "PILLAR-AWS-001",
+        "severity": "critical",
+        "title": "RDS clusters must enable storage encryption",
+        "description": "Tier-1 data stores require storage_encrypted=true with a customer-managed KMS key.",
+        "resource_type": "aws_rds_cluster",
+        "attributes": {
+            "category": "database",
+            "service": "rds",
+            "resource_selector": "aws_rds_cluster.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-001",
+        "remediation_difficulty": "high",
+        "match": {
+            "resource_type": "aws_rds_cluster",
+            "required_attribute": "storage_encrypted",
+            "attributes": {
+                "storage_encrypted": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-002",
+        "severity": "high",
+        "title": "RDS clusters require CostCenter + Project tags",
+        "description": "FinOps policy mandates CostCenter and Project tags on production Aurora clusters.",
+        "resource_type": "aws_rds_cluster",
+        "attributes": {
+            "category": "finops",
+            "service": "rds",
+            "resource_selector": "aws_rds_cluster.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-002",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_rds_cluster",
+            "required_attribute": "tags",
+            "attributes": {},
+            "flags": {
+                "has_missing_tags": True,
+            },
+        },
+    },
+    {
+        "id": "PILLAR-AWS-003",
+        "severity": "high",
+        "title": "Security groups must block 0.0.0.0/0 ingress",
+        "description": "Open ingress creates unmanaged exposure; restrict to CIDRs owned by the workload.",
+        "resource_type": "aws_security_group",
+        "attributes": {
+            "category": "network",
+            "service": "ec2",
+            "resource_selector": "aws_security_group.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-003",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_security_group",
+            "required_attribute": "ingress",
+            "attributes": {},
+            "flags": {
+                "allows_0_0_0_0": True,
+            },
+        },
+    },
+    {
+        "id": "PILLAR-AWS-004",
+        "severity": "critical",
+        "title": "IAM policies may not grant wildcard admin",
+        "description": "Production roles must avoid Action='*' grants across all resources.",
+        "resource_type": "aws_iam_policy",
+        "attributes": {
+            "category": "identity",
+            "service": "iam",
+            "resource_selector": "aws_iam_*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-004",
+        "remediation_difficulty": "high",
+        "match": {
+            "resource_type": "aws_iam_policy",
+            "required_attribute": "policy",
+            "attributes": {},
+            "flags": {
+                "iam_policy_wildcard": True,
+            },
+        },
+    },
+    {
+        "id": "PILLAR-AWS-005",
+        "severity": "high",
+        "title": "S3 buckets must enforce encryption at rest",
+        "description": "Buckets containing build outputs or models must define SSE or KMS defaults.",
+        "resource_type": "aws_s3_bucket",
+        "attributes": {
+            "category": "storage",
+            "service": "s3",
+            "resource_selector": "aws_s3_bucket.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-005",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_s3_bucket",
+            "required_attribute": None,
+            "attributes": {},
+            "flags": {
+                "s3_encryption_disabled": True,
+            },
+        },
+    },
+    {
+        "id": "PILLAR-AWS-006",
+        "severity": "medium",
+        "title": "S3 buckets must enable versioning",
+        "description": "Versioning preserves recovery points for drifted objects and vector manifests.",
+        "resource_type": "aws_s3_bucket",
+        "attributes": {
+            "category": "resilience",
+            "service": "s3",
+            "resource_selector": "aws_s3_bucket.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-006",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_s3_bucket",
+            "required_attribute": None,
+            "attributes": {},
+            "flags": {
+                "s3_versioning_disabled": True,
+            },
+        },
+    },
+    {
+        "id": "PILLAR-AWS-007",
+        "severity": "high",
+        "title": "EBS volumes require encryption",
+        "description": "Store embeddings and checkpoints on encrypted block devices.",
+        "resource_type": "aws_ebs_volume",
+        "attributes": {
+            "category": "storage",
+            "service": "ebs",
+            "resource_selector": "aws_ebs_volume.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-007",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_ebs_volume",
+            "required_attribute": "encrypted",
+            "attributes": {
+                "encrypted": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-008",
+        "severity": "medium",
+        "title": "CloudTrail must be multi-region",
+        "description": "Audit trails must capture events from every region that VectorScan resources use.",
+        "resource_type": "aws_cloudtrail",
+        "attributes": {
+            "category": "audit",
+            "service": "cloudtrail",
+            "resource_selector": "aws_cloudtrail.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-008",
+        "remediation_difficulty": "low",
+        "match": {
+            "resource_type": "aws_cloudtrail",
+            "required_attribute": "is_multi_region_trail",
+            "attributes": {
+                "is_multi_region_trail": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-009",
+        "severity": "medium",
+        "title": "CloudTrail log file validation required",
+        "description": "Log file validation prevents tampering across compliance reviews.",
+        "resource_type": "aws_cloudtrail",
+        "attributes": {
+            "category": "audit",
+            "service": "cloudtrail",
+            "resource_selector": "aws_cloudtrail.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-009",
+        "remediation_difficulty": "low",
+        "match": {
+            "resource_type": "aws_cloudtrail",
+            "required_attribute": "enable_log_file_validation",
+            "attributes": {
+                "enable_log_file_validation": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-010",
+        "severity": "medium",
+        "title": "DynamoDB tables must enable PITR",
+        "description": "Point-in-time recovery keeps catalog state restorable for guardrails metadata.",
+        "resource_type": "aws_dynamodb_table",
+        "attributes": {
+            "category": "resilience",
+            "service": "dynamodb",
+            "resource_selector": "aws_dynamodb_table.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-010",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_dynamodb_table",
+            "required_attribute": "point_in_time_recovery",
+            "attributes": {
+                "point_in_time_recovery": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-011",
+        "severity": "medium",
+        "title": "Lambda functions need KMS-backed environment vars",
+        "description": "Secrets injected via environment variables must be encrypted with KMS.",
+        "resource_type": "aws_lambda_function",
+        "attributes": {
+            "category": "serverless",
+            "service": "lambda",
+            "resource_selector": "aws_lambda_function.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-011",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_lambda_function",
+            "required_attribute": "kms_key_arn",
+            "attributes": {
+                "kms_key_arn": None,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-012",
+        "severity": "high",
+        "title": "EKS control plane logging required",
+        "description": "Enable api, audit, authenticator, controllerManager, and scheduler logs for GuardDuty feeds.",
+        "resource_type": "aws_eks_cluster",
+        "attributes": {
+            "category": "kubernetes",
+            "service": "eks",
+            "resource_selector": "aws_eks_cluster.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-012",
+        "remediation_difficulty": "high",
+        "match": {
+            "resource_type": "aws_eks_cluster",
+            "required_attribute": "enabled_cluster_log_types",
+            "attributes": {
+                "enabled_cluster_log_types": [],
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-013",
+        "severity": "critical",
+        "title": "GuardDuty must stay enabled",
+        "description": "Managed accounts must enable GuardDuty detectors across every region.",
+        "resource_type": "aws_guardduty_detector",
+        "attributes": {
+            "category": "threat-detection",
+            "service": "guardduty",
+            "resource_selector": "aws_guardduty_detector.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-013",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_guardduty_detector",
+            "required_attribute": "enable",
+            "attributes": {
+                "enable": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-014",
+        "severity": "high",
+        "title": "AWS Config recorder must be active",
+        "description": "Configuration history is mandatory before running VectorScan remediation packs.",
+        "resource_type": "aws_config_configuration_recorder",
+        "attributes": {
+            "category": "audit",
+            "service": "config",
+            "resource_selector": "aws_config_configuration_recorder.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-014",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_config_configuration_recorder",
+            "required_attribute": "recording_group",
+            "attributes": {
+                "recording_group": {},
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-015",
+        "severity": "medium",
+        "title": "VPCs should emit flow logs",
+        "description": "Flow logs feed the anomaly detectors that back GuardSuite recommendations.",
+        "resource_type": "aws_flow_log",
+        "attributes": {
+            "category": "network",
+            "service": "vpc",
+            "resource_selector": "aws_flow_log.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-015",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_flow_log",
+            "required_attribute": "log_destination",
+            "attributes": {
+                "log_destination": None,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-016",
+        "severity": "high",
+        "title": "Redshift clusters must encrypt data",
+        "description": "Analytics warehouses contain PII and require encryption + KMS wiring.",
+        "resource_type": "aws_redshift_cluster",
+        "attributes": {
+            "category": "database",
+            "service": "redshift",
+            "resource_selector": "aws_redshift_cluster.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-016",
+        "remediation_difficulty": "high",
+        "match": {
+            "resource_type": "aws_redshift_cluster",
+            "required_attribute": "encrypted",
+            "attributes": {
+                "encrypted": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-017",
+        "severity": "high",
+        "title": "ElastiCache clusters must enable encryption",
+        "description": "Cache tiers store tokens that must remain encrypted in transit and at rest.",
+        "resource_type": "aws_elasticache_replication_group",
+        "attributes": {
+            "category": "cache",
+            "service": "elasticache",
+            "resource_selector": "aws_elasticache_replication_group.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-017",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_elasticache_replication_group",
+            "required_attribute": "at_rest_encryption_enabled",
+            "attributes": {
+                "at_rest_encryption_enabled": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-018",
+        "severity": "critical",
+        "title": "Root accounts must not retain access keys",
+        "description": "Delete root access keys to reduce blast radius.",
+        "resource_type": "aws_iam_account_password_policy",
+        "attributes": {
+            "category": "identity",
+            "service": "iam",
+            "resource_selector": "aws_iam_account_password_policy",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-018",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_iam_account_password_policy",
+            "required_attribute": "require_uppercase_characters",
+            "attributes": {
+                "require_uppercase_characters": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-019",
+        "severity": "medium",
+        "title": "Backup vaults must specify KMS keys",
+        "description": "Use customer-managed KMS keys for cross-account restore workflows.",
+        "resource_type": "aws_backup_vault",
+        "attributes": {
+            "category": "resilience",
+            "service": "backup",
+            "resource_selector": "aws_backup_vault.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-019",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_backup_vault",
+            "required_attribute": "kms_key_arn",
+            "attributes": {
+                "kms_key_arn": None,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-020",
+        "severity": "medium",
+        "title": "SNS topics must enforce encryption",
+        "description": "Notifications often forward secrets; require KMS-backed encryption.",
+        "resource_type": "aws_sns_topic",
+        "attributes": {
+            "category": "messaging",
+            "service": "sns",
+            "resource_selector": "aws_sns_topic.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-020",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_sns_topic",
+            "required_attribute": "kms_master_key_id",
+            "attributes": {
+                "kms_master_key_id": None,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-021",
+        "severity": "medium",
+        "title": "SQS queues must encrypt payloads",
+        "description": "Message queues contain request context and must reference a CMK.",
+        "resource_type": "aws_sqs_queue",
+        "attributes": {
+            "category": "messaging",
+            "service": "sqs",
+            "resource_selector": "aws_sqs_queue.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-021",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_sqs_queue",
+            "required_attribute": "kms_master_key_id",
+            "attributes": {
+                "kms_master_key_id": None,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-022",
+        "severity": "medium",
+        "title": "KMS keys must rotate annually",
+        "description": "Managed cryptographic material requires automatic rotation.",
+        "resource_type": "aws_kms_key",
+        "attributes": {
+            "category": "security",
+            "service": "kms",
+            "resource_selector": "aws_kms_key.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-022",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_kms_key",
+            "required_attribute": "enable_key_rotation",
+            "attributes": {
+                "enable_key_rotation": False,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-023",
+        "severity": "medium",
+        "title": "RDS clusters should not be publicly accessible",
+        "description": "Private data stores must launch inside isolated subnets.",
+        "resource_type": "aws_rds_cluster",
+        "attributes": {
+            "category": "network",
+            "service": "rds",
+            "resource_selector": "aws_rds_cluster.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-023",
+        "remediation_difficulty": "high",
+        "match": {
+            "resource_type": "aws_rds_cluster",
+            "required_attribute": "publicly_accessible",
+            "attributes": {
+                "publicly_accessible": True,
+            },
+            "flags": {},
+        },
+    },
+    {
+        "id": "PILLAR-AWS-024",
+        "severity": "medium",
+        "title": "ECS services should avoid public IP assignment",
+        "description": "Service tasks behind ALBs must use private subnets and NAT egress.",
+        "resource_type": "aws_ecs_service",
+        "attributes": {
+            "category": "containers",
+            "service": "ecs",
+            "resource_selector": "aws_ecs_service.*",
+        },
+        "remediation_hint": "fixpack:PILLAR-AWS-024",
+        "remediation_difficulty": "medium",
+        "match": {
+            "resource_type": "aws_ecs_service",
+            "required_attribute": "assign_public_ip",
+            "attributes": {
+                "assign_public_ip": True,
+            },
+            "flags": {},
+        },
+    },
+)
+
+_RULE_REMEDIATIONS: Dict[str, Dict[str, str]] = {
+        "PILLAR-AWS-001": _remediation_metadata(
+                "PILLAR-AWS-001",
+                "Enable storage encryption on the RDS cluster and supply a customer-managed KMS key.",
+                """
+resource "aws_rds_cluster" "example" {
+    storage_encrypted = true
+    kms_key_id       = "arn:aws:kms:region:account:key/id"
+}
+""",
+        ),
+        "PILLAR-AWS-002": _remediation_metadata(
+                "PILLAR-AWS-002",
+                "Add CostCenter and Project tags to production Aurora clusters.",
+                """
+resource "aws_rds_cluster" "example" {
+    tags = merge(var.default_tags, {
+        CostCenter = "finops-1234"
+        Project    = "vector-scan"
+    })
+}
+""",
+        ),
+        "PILLAR-AWS-003": _remediation_metadata(
+                "PILLAR-AWS-003",
+                "Restrict ingress rules to owned CIDRs instead of 0.0.0.0/0.",
+                """
+resource "aws_security_group" "example" {
+    ingress {
+        cidr_blocks = ["10.0.0.0/16"]
+        from_port   = 443
+        to_port     = 443
+        protocol    = "tcp"
+    }
+}
+""",
+        ),
+        "PILLAR-AWS-004": _remediation_metadata(
+                "PILLAR-AWS-004",
+                "Replace wildcard IAM statements with explicit actions and resources.",
+                """
+data "aws_iam_policy_document" "example" {
+    statement {
+        actions   = ["rds:DescribeDBClusters"]
+        resources = [aws_rds_cluster.vector_db.arn]
+    }
+}
+""",
+        ),
+        "PILLAR-AWS-005": _remediation_metadata(
+                "PILLAR-AWS-005",
+                "Enable default encryption on S3 buckets storing build artifacts.",
+                """
+resource "aws_s3_bucket" "example" {
+    server_side_encryption_configuration {
+        rule {
+            apply_server_side_encryption_by_default {
+                sse_algorithm = "aws:kms"
+            }
+        }
+    }
+}
+""",
+        ),
+        "PILLAR-AWS-006": _remediation_metadata(
+                "PILLAR-AWS-006",
+                "Turn on S3 versioning so drifted objects remain recoverable.",
+                """
+resource "aws_s3_bucket_versioning" "example" {
+    bucket = aws_s3_bucket.example.id
+    versioning_configuration {
+        status = "Enabled"
+    }
+}
+""",
+        ),
+        "PILLAR-AWS-007": _remediation_metadata(
+                "PILLAR-AWS-007",
+                "Set `encrypted = true` on EBS volumes and wire a KMS key when required.",
+                """
+resource "aws_ebs_volume" "example" {
+    encrypted = true
+    kms_key_id = aws_kms_key.ebs.arn
+}
+""",
+        ),
+        "PILLAR-AWS-008": _remediation_metadata(
+                "PILLAR-AWS-008",
+                "Enable multi-region CloudTrail coverage for full audit visibility.",
+                """
+resource "aws_cloudtrail" "example" {
+    is_multi_region_trail = true
+}
+""",
+        ),
+        "PILLAR-AWS-009": _remediation_metadata(
+                "PILLAR-AWS-009",
+                "Turn on CloudTrail log file validation to detect tampering.",
+                """
+resource "aws_cloudtrail" "example" {
+    enable_log_file_validation = true
+}
+""",
+        ),
+        "PILLAR-AWS-010": _remediation_metadata(
+                "PILLAR-AWS-010",
+                "Enable DynamoDB point-in-time recovery on business-critical tables.",
+                """
+resource "aws_dynamodb_table" "example" {
+    point_in_time_recovery {
+        enabled = true
+    }
+}
+""",
+        ),
+        "PILLAR-AWS-011": _remediation_metadata(
+                "PILLAR-AWS-011",
+                "Attach a kms_key_arn so Lambda environment variables stay encrypted.",
+                """
+resource "aws_lambda_function" "example" {
+    kms_key_arn = aws_kms_key.lambda.arn
+}
+""",
+        ),
+        "PILLAR-AWS-012": _remediation_metadata(
+                "PILLAR-AWS-012",
+                "Enable control plane log types (api, audit, authenticator, controllerManager, scheduler).",
+                """
+resource "aws_eks_cluster" "example" {
+    enabled_cluster_log_types = [
+        "api",
+        "audit",
+        "authenticator",
+        "controllerManager",
+        "scheduler",
+    ]
+}
+""",
+        ),
+        "PILLAR-AWS-013": _remediation_metadata(
+                "PILLAR-AWS-013",
+                "Keep GuardDuty detectors enabled across every region in scope.",
+                """
+resource "aws_guardduty_detector" "example" {
+    enable = true
+}
+""",
+        ),
+        "PILLAR-AWS-014": _remediation_metadata(
+                "PILLAR-AWS-014",
+                "Ensure the AWS Config recorder tracks all supported resources.",
+                """
+resource "aws_config_configuration_recorder" "example" {
+    recording_group {
+        all_supported = true
+    }
+}
+""",
+        ),
+        "PILLAR-AWS-015": _remediation_metadata(
+                "PILLAR-AWS-015",
+                "Capture VPC flow logs for ingestion by anomaly detectors.",
+                """
+resource "aws_flow_log" "example" {
+    traffic_type = "ALL"
+    log_destination = aws_cloudwatch_log_group.flow.arn
+}
+""",
+        ),
+        "PILLAR-AWS-016": _remediation_metadata(
+                "PILLAR-AWS-016",
+                "Encrypt Redshift clusters and reference the mandated KMS key.",
+                """
+resource "aws_redshift_cluster" "example" {
+    encrypted  = true
+    kms_key_id = aws_kms_key.redshift.arn
+}
+""",
+        ),
+        "PILLAR-AWS-017": _remediation_metadata(
+                "PILLAR-AWS-017",
+                "Enable at-rest and in-transit encryption on ElastiCache replication groups.",
+                """
+resource "aws_elasticache_replication_group" "example" {
+    at_rest_encryption_enabled    = true
+    transit_encryption_enabled    = true
+}
+""",
+        ),
+        "PILLAR-AWS-018": _remediation_metadata(
+                "PILLAR-AWS-018",
+                "Update the IAM account password policy to require uppercase characters and guardrails.",
+                """
+resource "aws_iam_account_password_policy" "example" {
+    require_uppercase_characters = true
+}
+""",
+        ),
+        "PILLAR-AWS-019": _remediation_metadata(
+                "PILLAR-AWS-019",
+                "Assign a kms_key_arn so backup vaults use customer-managed encryption.",
+                """
+resource "aws_backup_vault" "example" {
+    kms_key_arn = aws_kms_key.backup.arn
+}
+""",
+        ),
+        "PILLAR-AWS-020": _remediation_metadata(
+                "PILLAR-AWS-020",
+                "Require SNS topics to use a CMK via kms_master_key_id.",
+                """
+resource "aws_sns_topic" "example" {
+    kms_master_key_id = aws_kms_key.notifications.arn
+}
+""",
+        ),
+        "PILLAR-AWS-021": _remediation_metadata(
+                "PILLAR-AWS-021",
+                "Ensure SQS queues encrypt payloads using a customer-managed key.",
+                """
+resource "aws_sqs_queue" "example" {
+    kms_master_key_id = aws_kms_key.queue.arn
+}
+""",
+        ),
+        "PILLAR-AWS-022": _remediation_metadata(
+                "PILLAR-AWS-022",
+                "Enable automatic rotation on KMS keys that protect critical workloads.",
+                """
+resource "aws_kms_key" "example" {
+    enable_key_rotation = true
+}
+""",
+        ),
+        "PILLAR-AWS-023": _remediation_metadata(
+                "PILLAR-AWS-023",
+                "Keep RDS clusters private by disabling public access.",
+                """
+resource "aws_rds_cluster" "example" {
+    publicly_accessible = false
+}
+""",
+        ),
+        "PILLAR-AWS-024": _remediation_metadata(
+                "PILLAR-AWS-024",
+                "Deploy ECS services without assigning public IPs to tasks.",
+                """
+resource "aws_ecs_service" "example" {
+    network_configuration {
+        assign_public_ip = false
+    }
+}
+""",
+        ),
+}
+
+
+def _attach_remediation(entry: Dict[str, Any]) -> Dict[str, Any]:
+        enriched = dict(entry)
+        rule_id = str(enriched.get("id") or "")
+        metadata = _RULE_REMEDIATIONS.get(rule_id)
+        if metadata is None:
+                metadata = _remediation_metadata(
+                        rule_id or "PILLAR-UNKNOWN",
+                        "Apply the matching fixpack to remediate this issue.",
+                        f"fixpack:{rule_id or 'PILLAR-UNKNOWN'}",
+                )
+        enriched["remediation_metadata"] = dict(metadata)
+        return enriched
+
+
+_RULE_CATALOG: Sequence[Dict[str, Any]] = tuple(
+        _attach_remediation(entry) for entry in _BASE_RULE_CATALOG
+)
+
+
+def issue_catalog() -> List[Dict[str, Any]]:
+    return [dict(entry) for entry in _RULE_CATALOG]
+
+
+def get_rules() -> List[Dict[str, Any]]:
+    return issue_catalog()
```
