from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import click

from tools.vectorscan import vectorscan as legacy
from tools.vectorscan.env_flags import env_truthy
from tools.vectorscan.constants import (
	EXIT_CONFIG_ERROR,
	EXIT_INVALID_INPUT,
	EXIT_POLICY_FAIL,
	EXIT_SUCCESS,
)
from tools.vectorscan.environment import _status_badge
from tools.vectorscan.reports import render_explanation_text, render_plan_diff_text

from src.pillar import constants as pillar_constants
from src.pillar.compat import error_text
from src.pillar.compat.normalization import NormalizationError, NormalizationResult, ScanOptions
from src.pillar.evaluator import evaluate_scan, is_valid_plan_payload
from src.pillar.entrypoint_shim import emit_strict_mode_banner

EXIT_VALIDATION_ERROR = 2
_SAFE_PRINT = legacy._safe_print


class PlanLoadError(RuntimeError):
	"""Raised when a scan or validate command cannot load a plan payload."""


@click.group()
def cli() -> None:
	"""GuardSuite pillar CLI."""


@cli.command()
@click.argument("plan", required=False, type=click.Path(path_type=Path))
@click.option(
	"--json-output/--no-json-output",
	"json_output",
	default=False,
	help="Emit JSON output",
)
@click.option("--stdin", is_flag=True, help="Read plan JSON from stdin")
@click.option("--quiet", is_flag=True, help="Suppress human-readable output")
@click.option("--allow-network", is_flag=True, help="Allow network actions like lead capture or downloads")
@click.option("--no-network", is_flag=True, help="Force offline mode and disable network side-effects")
@click.option("--lead-capture", is_flag=True, help="Persist scan payload to the local capture directory")
@click.option("--email", type=str, help="Override the email stored in lead captures")
@click.option("--endpoint", type=str, help="HTTP endpoint for lead capture POST requests")
@click.option("--terraform-tests", is_flag=True, help="Run Terraform module tests before policy evaluation")
@click.option(
	"--terraform-bin",
	 type=click.Path(path_type=Path),
	 help="Path to a Terraform binary to use for module tests",
)
@click.option("--no-terraform-download", is_flag=True, help="Disable Terraform auto-download even when allowed")
@click.option(
	"--iam-drift-penalty",
	 type=int,
	 help="Override the IAM drift penalty percentage applied to compliance scores",
)
def scan(
	plan: Optional[Path],
	json_output: bool,
	stdin: bool,
	quiet: bool,
	allow_network: bool,
	no_network: bool,
	lead_capture: bool,
	email: Optional[str],
	endpoint: Optional[str],
	terraform_tests: bool,
	terraform_bin: Optional[Path],
	no_terraform_download: bool,
	iam_drift_penalty: Optional[int],
) -> int:
	"""Evaluate a Terraform plan and emit VectorScan results."""

	options = ScanOptions(
		as_json=json_output,
		quiet=quiet,
		allow_network=allow_network,
		force_no_network=no_network,
		lead_capture=lead_capture,
		email=email,
		endpoint=endpoint,
		terraform_tests=terraform_tests,
		terraform_bin=str(terraform_bin) if terraform_bin else None,
		no_terraform_download=no_terraform_download,
		iam_drift_penalty=iam_drift_penalty,
	)
	return _handle_scan(plan, stdin, options)


@cli.command()
@click.option("--manifest", is_flag=True, help="Print the policy manifest")
@click.argument("manifest_path", required=False, type=click.Path(path_type=Path))
def rules(manifest: bool, manifest_path: Optional[Path]) -> int:
	"""Emit metadata describing the rule registry."""

	if not manifest:
		_SAFE_PRINT("Usage: pillar rules --manifest", stream=sys.stderr)
		return EXIT_INVALID_INPUT
	path_value = str(manifest_path) if manifest_path else None
	return legacy._print_policy_manifest(path_value)


@cli.command()
@click.argument("plan", required=False, type=click.Path(path_type=Path))
@click.option("--stdin", is_flag=True, help="Read plan JSON from stdin")
def validate(plan: Optional[Path], stdin: bool) -> int:
	"""Perform a minimal schema sanity check on the supplied plan."""

	try:
		payload, _, _ = _load_plan_payload(plan, stdin)
	except PlanLoadError as exc:
		_SAFE_PRINT(str(exc), stream=sys.stderr)
		return EXIT_INVALID_INPUT

	if not is_valid_plan_payload(payload):
		_SAFE_PRINT("Plan payload must be a JSON object.", stream=sys.stderr)
		return EXIT_VALIDATION_ERROR
	return EXIT_SUCCESS


def main(argv: Optional[Sequence[str]] = None) -> int:
	args = list(argv if argv is not None else sys.argv[1:])
	ctx = None
	try:
		ctx = cli.make_context("pillar", args, resilient_parsing=False)
		result = cli.invoke(ctx)
		if isinstance(result, int):
			return result
		return EXIT_SUCCESS
	except click.ClickException as exc:
		exc.show()
		return exc.exit_code
	except SystemExit as exc:
		code = exc.code
		return int(code) if isinstance(code, int) else EXIT_SUCCESS
	finally:
		if ctx is not None:
			ctx.close()


def _handle_scan(plan: Optional[Path], stdin: bool, options: ScanOptions) -> int:
	strict_mode_active = legacy.strict_mode_enabled()
	try:
		plan_payload, source_path, raw_size = _load_plan_payload(plan, stdin)
	except PlanLoadError as exc:
		_return_plan_error(str(exc), strict_mode_active=strict_mode_active)
	return _execute_scan(plan_payload, source_path, raw_size, options)


def _execute_scan(
	plan_payload: Dict[str, Any],
	source_path: Optional[Path],
	raw_size: Optional[int],
	options: ScanOptions,
) -> int:
	strict_mode_active = legacy.strict_mode_enabled()
	try:
		result = evaluate_scan(
			plan_payload,
			source_path=source_path,
			raw_size=raw_size,
			options=options,
		)
	except NormalizationError as exc:
		message = str(exc)
		if message.startswith("Invalid Terraform plan schema:"):
			detail = message.split(":", 1)[1].strip()
			_SAFE_PRINT(f"Schema error: {detail}", stream=sys.stderr)
		_SAFE_PRINT(message, stream=sys.stderr)
		return exc.exit_code
	except legacy.StrictModeViolation as exc:  # type: ignore[attr-defined]
		emit_strict_mode_banner(str(exc))
		return EXIT_CONFIG_ERROR
	except Exception as exc:  # pragma: no cover - defensive guard
		if strict_mode_active:
			emit_strict_mode_banner(str(exc), include_unexpected=True)
			return EXIT_CONFIG_ERROR
		_SAFE_PRINT("Unexpected scan failure: {exc}".format(exc=exc), stream=sys.stderr)
		return EXIT_CONFIG_ERROR

	_emit_scan_output(result, options)
	return result.exit_code


def _emit_scan_output(result: NormalizationResult, options: ScanOptions) -> None:
	payload = result.payload
	safe_payload = legacy._sanitize_for_json(payload)
	_ensure_cli_metadata_alignment(payload, safe_payload)
	if options.as_json:
		_SAFE_PRINT(
			json.dumps(
				safe_payload,
				indent=2,
				ensure_ascii=False,
				sort_keys=options.gha_mode,
			)
		)
	elif not options.quiet:
		_emit_human_output(result, options)
	_handle_lead_capture(result, safe_payload, options)


def _emit_human_output(result: NormalizationResult, options: ScanOptions) -> None:
	terraform_report = result.terraform_report
	use_color = result.use_color and not options.gha_mode
	plan_label = "tfplan.json"

	_SAFE_PRINT(f"[VectorScan] scan_version={pillar_constants.SCAN_VERSION}")

	if terraform_report is not None:
		tf_status = str(terraform_report.get("status", "SKIP")).upper()
		badge = _status_badge(tf_status, use_color)
		if tf_status == "PASS":
			_SAFE_PRINT(f"Terraform tests: {badge}")
		elif tf_status == "SKIP":
			message = terraform_report.get(
				"message",
				"Terraform CLI unavailable; skipping tests",
			)
			_SAFE_PRINT(f"Terraform tests: {badge} - {message}")
		else:
			_SAFE_PRINT(f"Terraform tests: {badge} (see details above)")

	if result.resource_scope and not options.as_json:
		scope_addr = result.resource_scope["address"]
		match_type = result.resource_scope["match_type"]
		resource_input = options.resource
		if match_type == "suffix" and resource_input and resource_input != scope_addr:
			_SAFE_PRINT(f"Resource scope: {scope_addr} (matched from '{resource_input}')")
		else:
			_SAFE_PRINT(f"Resource scope: {scope_addr}")

	if result.policy_errors or result.violations:
		_SAFE_PRINT(f"{_status_badge('FAIL', use_color)} - {plan_label} - VectorScan checks")
		for violation in result.violations:
			_SAFE_PRINT(f"  {violation}")
		if result.violations:
			summary_line = ", ".join(
				f"{level}={result.severity_summary.get(level, 0)}"
				for level in legacy.SEVERITY_LEVELS
			)
			_SAFE_PRINT(f"  Violation severity summary: {summary_line}")
		if result.policy_errors:
			_SAFE_PRINT("  Policy engine errors detected (partial coverage):")
			for err in result.policy_errors:
				_SAFE_PRINT(f"    - {err['policy']}: {err['error']}")
		_SAFE_PRINT("\n🚀 Want full, automated Zero-Trust & FinOps coverage?")
		_SAFE_PRINT(
			"Get the complete 8-point compliance kit (Blueprint) for $79/year → https://gumroad.com/l/vectorguard-blueprint\n"
		)
	else:
		_SAFE_PRINT(
			f"{_status_badge('PASS', use_color)} - {plan_label} - VectorScan checks (encryption + mandatory tags)"
		)

	if result.explanation_block and not options.as_json:
		_SAFE_PRINT("")
		_SAFE_PRINT(render_explanation_text(result.explanation_block))
		_SAFE_PRINT("")

	if result.plan_diff_block and not options.as_json:
		_SAFE_PRINT("")
		_SAFE_PRINT(
			render_plan_diff_text(result.plan_diff_block or {"summary": {}, "resources": []})
		)
		_SAFE_PRINT("")

	if result.preview_manifest_data and not options.as_json:
		_SAFE_PRINT("VectorGuard preview policies (no paid policy execution):")
		for entry in result.preview_manifest_data.get("policies", []):
			policy_id = entry.get("id")
			summary = entry.get("summary", "")
			_SAFE_PRINT(f"  - {policy_id}: {summary}")
		preview_path = result.preview_manifest_data.get("path")
		if preview_path:
			verified = result.preview_manifest_data.get("verified", False)
			_SAFE_PRINT(f"  Manifest: {preview_path} (verified={verified})")
		_SAFE_PRINT("Preview mode exit code: 10 (PREVIEW_MODE_ONLY)")

	_SAFE_PRINT(f"[VectorScan] completed scan_version={pillar_constants.SCAN_VERSION}")


def _ensure_cli_metadata_alignment(raw_payload: Any, safe_payload: Any) -> None:
	if not isinstance(raw_payload, dict) or not isinstance(safe_payload, dict):
		return
	raw_issues = raw_payload.get("issues")
	safe_issues = safe_payload.get("issues")
	if not isinstance(raw_issues, list) or not isinstance(safe_issues, list):
		return
	limit = min(len(raw_issues), len(safe_issues))
	for idx in range(limit):
		raw_issue = raw_issues[idx]
		safe_issue = safe_issues[idx]
		template = _ordered_metadata_from_issue(safe_issue) or _ordered_metadata_from_issue(raw_issue)
		_apply_metadata_template(raw_issue, template)
		_apply_metadata_template(safe_issue, template)
	for idx in range(limit, len(raw_issues)):
		_apply_metadata_template(raw_issues[idx], None)
	for idx in range(limit, len(safe_issues)):
		_apply_metadata_template(safe_issues[idx], None)


def _ordered_metadata_from_issue(issue: Any) -> Optional[Dict[str, Any]]:
	if not isinstance(issue, dict):
		return None
	metadata = issue.get("remediation_metadata")
	if not isinstance(metadata, dict):
		return None
	ordered: Dict[str, Any] = {}
	for key in sorted(metadata.keys()):
		ordered[key] = metadata[key]
	return ordered or None


def _apply_metadata_template(issue: Any, template: Optional[Dict[str, Any]]) -> None:
	if not isinstance(issue, dict):
		return
	canonical_issue = _ordered_metadata_from_issue(issue)
	if template is None:
		template = canonical_issue
	if template is None:
		return
	if canonical_issue != template:
		issue["remediation_metadata"] = dict(template)


def _handle_lead_capture(
	result: NormalizationResult,
	safe_payload: Dict[str, Any],
	options: ScanOptions,
) -> None:
	environment = result.payload.get("environment") or {}
	metadata_block = result.payload.get("metadata") or {}
	control_block = metadata_block.get("control") if isinstance(metadata_block, dict) else {}
	offline_mode = bool(environment.get("offline_mode"))
	allow_network_capture = bool(control_block.get("allow_network_capture", False))
	wants_capture = (
		options.lead_capture
		or options.email
		or options.endpoint
		or os.getenv("VSCAN_LEAD_ENDPOINT")
	)
	if not wants_capture:
		return
	output_stream = sys.stderr if options.as_json else sys.stdout
	no_network_active = offline_mode or options.force_no_network or not allow_network_capture
	if no_network_active:
		_SAFE_PRINT(error_text.NO_NETWORK_MESSAGE, stream=output_stream)
		return
	lead = {
		"email": options.email or "",
		"result": safe_payload,
		"timestamp": legacy._now(),
		"source": "vectorscan-cli",
	}
	path_out = legacy._write_local_capture(lead)
	_SAFE_PRINT(f"Lead payload saved: {path_out}", stream=output_stream)

	endpoint = options.endpoint or os.getenv("VSCAN_LEAD_ENDPOINT", "")
	if endpoint and allow_network_capture:
		ok, info = legacy._maybe_post(endpoint, lead)
		_SAFE_PRINT(f"Lead POST => {info} ({'OK' if ok else 'SKIP/FAIL'})", stream=output_stream)


def _load_plan_payload(
	plan: Optional[Path],
	stdin: bool,
) -> Tuple[Dict[str, Any], Optional[Path], Optional[int]]:
	if stdin and plan is not None:
		raise PlanLoadError("Provide a plan path or --stdin, not both.")

	if stdin:
		text = click.get_text_stream("stdin").read()
		if not text.strip():
			raise PlanLoadError(error_text.stdin_json_error())
		try:
			payload = json.loads(text)
		except json.JSONDecodeError as exc:
			raise PlanLoadError(error_text.stdin_json_error()) from exc
		return payload, None, len(text.encode("utf-8"))

	if plan is None:
		raise PlanLoadError("Plan path is required unless --stdin is provided.")
	if not plan.exists():
		raise PlanLoadError(error_text.file_not_found(plan))

	try:
		text = plan.read_text()
	except PermissionError:
		raise PlanLoadError(error_text.permission_denied(plan)) from None
	except OSError:
		raise PlanLoadError(error_text.permission_denied(plan)) from None
	try:
		payload = json.loads(text)
	except json.JSONDecodeError as exc:
		raise PlanLoadError(error_text.invalid_json(plan)) from exc
	return payload, plan, len(text.encode("utf-8"))


def _return_plan_error(message: str, *, strict_mode_active: bool = False) -> None:
	if strict_mode_active:
		emit_strict_mode_banner(message)
	else:
		_SAFE_PRINT(message, stream=sys.stderr)
		_SAFE_PRINT("", stream=sys.stderr)
	raise SystemExit(EXIT_INVALID_INPUT)


def run_scan_from_namespace(namespace: Any) -> int:
	options = _options_from_namespace(namespace)
	plan_value = getattr(namespace, "plan", None)
	plan_path = Path(plan_value) if plan_value else None
	stdin = bool(getattr(namespace, "stdin", False))
	return _handle_scan(plan_path, stdin, options)


def run_rules_manifest(manifest_path: Optional[str]) -> int:
	return legacy._print_policy_manifest(manifest_path)


def _options_from_namespace(namespace: Any) -> ScanOptions:
	policy_ids = _normalize_flag_sequence(getattr(namespace, "policy_ids", None))
	policy_presets = _normalize_flag_sequence(getattr(namespace, "policies", None))
	manifest_flag = getattr(namespace, "policy_manifest", None)
	manifest_path = None
	sentinel = getattr(legacy, "_POLICY_MANIFEST_SENTINEL", object())
	if manifest_flag not in (None, sentinel):
		manifest_path = str(manifest_flag)
	gha_mode = bool(getattr(namespace, "gha", False))
	as_json = bool(getattr(namespace, "as_json", False) or gha_mode)
	quiet = bool(getattr(namespace, "quiet", False) or gha_mode)
	no_color = bool(getattr(namespace, "no_color", False) or gha_mode)
	allow_network_flag = bool(getattr(namespace, "allow_network", False))
	no_network_flag = bool(getattr(namespace, "no_network", False))
	terraform_tests_flag = bool(getattr(namespace, "terraform_tests", False))
	if not terraform_tests_flag and env_truthy(os.getenv("VSCAN_TERRAFORM_TESTS")):
		terraform_tests_flag = True
	return ScanOptions(
		as_json=as_json,
		gha_mode=gha_mode,
		quiet=quiet,
		no_color=no_color,
		resource=getattr(namespace, "resource", None),
		diff=bool(getattr(namespace, "diff", False)),
		explain=bool(getattr(namespace, "explain", False)),
		preview_vectorguard=bool(getattr(namespace, "preview_vectorguard", False)),
		policy_ids=policy_ids,
		policy_presets=policy_presets,
		policy_manifest_path=manifest_path,
		lead_capture=bool(getattr(namespace, "lead_capture", False)),
		email=getattr(namespace, "email", None),
		endpoint=getattr(namespace, "endpoint", None),
		allow_network=allow_network_flag,
		force_no_network=no_network_flag,
		terraform_tests=terraform_tests_flag,
		terraform_bin=getattr(namespace, "terraform_bin", None),
		no_terraform_download=bool(getattr(namespace, "no_terraform_download", False)),
		iam_drift_penalty=getattr(namespace, "iam_drift_penalty", None),
	)


def _normalize_flag_sequence(value: Any) -> Optional[List[str]]:
	if value is None:
		return None
	if isinstance(value, (list, tuple)):
		return [str(item) for item in value if str(item).strip()]
	text = str(value).strip()
	if not text:
		return None
	return [text]


if __name__ == "__main__":  # pragma: no cover - manual execution helper
	raise SystemExit(main())
