#!/usr/bin/env python3
"""VectorScan CLI entry point for Terraform plan guardrails."""

from __future__ import annotations

import argparse
import json
import os
import platform as _platform_module
import subprocess as _subprocess_module
import sys
import tempfile as _tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, cast
from urllib import request as _urllib_request

# ruff: noqa: E402


_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.vectorscan.constants import (
    EXIT_CONFIG_ERROR,
    EXIT_INVALID_INPUT,
    EXIT_POLICY_FAIL,
    EXIT_POLICY_LOAD_ERROR,
    EXIT_PREVIEW_MODE,
    EXIT_SUCCESS,
    EXIT_TERRAFORM_ERROR,
    EXIT_TERRAFORM_FAIL,
)
from tools.vectorscan.constants import ROOT_DIR as _ROOT_DIR
from tools.vectorscan.constants import (
    SEVERITY_LEVELS,
)
from tools.vectorscan.env_flags import env_falsey, env_truthy, is_offline, is_strict_mode
from tools.vectorscan.environment import (
    StrictModeViolation,
    _build_environment_metadata,
    _compute_scan_duration_ms,
    _ensure_strict_clock,
    _now,
    _should_use_color,
    _status_badge,
    _strict_require,
)
from tools.vectorscan.iam_drift import build_iam_drift_report
from tools.vectorscan.lead_capture import maybe_post, write_local_capture
from tools.vectorscan.metrics import (
    compute_metrics,
    compute_security_grade,
    compute_violation_severity_summary,
)
from tools.vectorscan.plan_evolution import compute_plan_evolution
from tools.vectorscan.plan_risk import compute_plan_risk_profile
from tools.vectorscan.plan_smell import compute_smell_report
from tools.vectorscan.plan_utils import PlanLoadError as _PlanLoadError
from tools.vectorscan.plan_utils import (
    build_plan_diff,
    compute_plan_metadata,
)
from tools.vectorscan.plan_utils import iter_resources as _iter_resources
from tools.vectorscan.plan_utils import load_json as _plan_load_json
from tools.vectorscan.plan_utils import (
    load_plan_context,
)
from tools.vectorscan.policies import get_policies, get_policy
from tools.vectorscan.policies.common import TAGGABLE_TYPES as _POLICY_TAGGABLE_TYPES
from tools.vectorscan.policies.common import is_nonempty_string
from tools.vectorscan.policy_manifest import (
    PolicyManifestError,
    build_policy_manifest,
    load_policy_manifest,
)
from tools.vectorscan.policy_pack import PolicyPackError, policy_pack_hash
from tools.vectorscan.python_compat import ensure_supported_python, UnsupportedPythonVersion
from tools.vectorscan.preview import PreviewManifestError, load_preview_manifest
from tools.vectorscan.reports import (
    build_explanation,
    build_violation_structs,
    render_explanation_text,
    render_plan_diff_text,
    render_plan_evolution_text,
)
from tools.vectorscan.suspicious_defaults import detect_suspicious_defaults
from tools.vectorscan.terraform import LegacyTerraformTestStrategy as _LegacyTerraformTestStrategy
from tools.vectorscan.terraform import ModernTerraformTestStrategy as _ModernTerraformTestStrategy
from tools.vectorscan.terraform import TerraformDownloadError as _TerraformDownloadError
from tools.vectorscan.terraform import TerraformManager as _TerraformManager
from tools.vectorscan.terraform import TerraformManagerError as _TerraformManagerError
from tools.vectorscan.terraform import TerraformNotFoundError as _TerraformNotFoundError
from tools.vectorscan.terraform import TerraformResolution as _TerraformResolution
from tools.vectorscan.terraform import TerraformTestStrategy as _TerraformTestStrategy
from tools.vectorscan.terraform import _safe_chdir_flag as _terraform_safe_chdir_flag
from tools.vectorscan.terraform import _select_strategy as _terraform_select_strategy
from tools.vectorscan.terraform import (
    _truncate_output,
)
from tools.vectorscan.terraform import register_vectorscan_module as _register_vectorscan_module
from tools.vectorscan.terraform import (
    run_terraform_tests,
)
from tools.vectorscan.terraform import set_strategy_resolver as _set_strategy_resolver
from tools.vectorscan.versioning import OUTPUT_SCHEMA_VERSION, POLICY_VERSION, VECTORSCAN_VERSION

# Backwards-compatible shims for legacy tests and monkeypatching
_write_local_capture = write_local_capture
_maybe_post = maybe_post
tempfile = _tempfile
platform = _platform_module
request = _urllib_request
subprocess = _subprocess_module

# Re-export select utilities for downstream tests and integrations without adding new public modules.
TAGGABLE_TYPES = _POLICY_TAGGABLE_TYPES
iter_resources = _iter_resources


def load_json(path: Path) -> Dict[str, Any]:
    try:
        return _plan_load_json(path)
    except _PlanLoadError:
        sys.exit(EXIT_INVALID_INPUT)


ROOT_DIR = _ROOT_DIR
ModernTerraformTestStrategy = _ModernTerraformTestStrategy
LegacyTerraformTestStrategy = _LegacyTerraformTestStrategy
TerraformTestStrategy = _TerraformTestStrategy
TerraformManager = _TerraformManager
TerraformManagerError = _TerraformManagerError
TerraformNotFoundError = _TerraformNotFoundError
TerraformDownloadError = _TerraformDownloadError
TerraformResolution = _TerraformResolution
_safe_chdir_flag = _terraform_safe_chdir_flag
_select_strategy = _terraform_select_strategy
_set_strategy_resolver(lambda version: _select_strategy(version))

__all__ = [
    "TAGGABLE_TYPES",
    "iter_resources",
    "load_json",
    "ROOT_DIR",
    "ModernTerraformTestStrategy",
    "LegacyTerraformTestStrategy",
    "TerraformTestStrategy",
    "TerraformManager",
    "TerraformManagerError",
    "TerraformNotFoundError",
    "TerraformDownloadError",
    "TerraformResolution",
    "_safe_chdir_flag",
    "_select_strategy",
    "platform",
    "request",
    "tempfile",
    "subprocess",
]

_current_module = sys.modules[__name__]
sys.modules["vectorscan"] = _current_module
_register_vectorscan_module(_current_module)

try:
    ensure_supported_python()
except UnsupportedPythonVersion as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(EXIT_CONFIG_ERROR)


POLICY_PACK_HASH: Optional[str]
_POLICY_PACK_ERROR: Optional[str]

try:
    POLICY_PACK_HASH = policy_pack_hash()
    _POLICY_PACK_ERROR = None
except PolicyPackError as exc:  # pragma: no cover - exercised in integration tests
    POLICY_PACK_HASH = None
    _POLICY_PACK_ERROR = str(exc)


def check_encryption(resources: List[Dict[str, Any]]) -> List[str]:
    """Compatibility wrapper delegating to the pluggable encryption policy."""

    return get_policy("P-SEC-001").evaluate(resources)


def _is_nonempty_string(s: Any) -> bool:
    """Backwards-compatible shim to utilities used in tests."""

    return is_nonempty_string(s)


def check_tags(resources: List[Dict[str, Any]]) -> List[str]:
    """Compatibility wrapper delegating to the pluggable tagging policy."""

    return get_policy("P-FIN-001").evaluate(resources)


def _sanitize_for_json(value: Any) -> Any:
    if isinstance(value, str):
        return value.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    if isinstance(value, list):
        return [_sanitize_for_json(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_for_json(item) for item in value)
    if isinstance(value, dict):
        return {key: _sanitize_for_json(item) for key, item in value.items()}
    return value


_POLICY_MANIFEST_SENTINEL = "__PRINT_POLICY_MANIFEST__"
_POLICY_PRESET_ALL = "__POLICY_PRESET_ALL__"
_FREE_POLICY_IDS = frozenset({"P-SEC-001", "P-FIN-001"})
_POLICY_PRESETS = {
    "all": _POLICY_PRESET_ALL,
    "free": _FREE_POLICY_IDS,
    "baseline": _FREE_POLICY_IDS,
    "security": frozenset({"P-SEC-001"}),
    "sec": frozenset({"P-SEC-001"}),
    "encryption": frozenset({"P-SEC-001"}),
    "finops": frozenset({"P-FIN-001"}),
    "tags": frozenset({"P-FIN-001"}),
}


class _ResourceScopeError(Exception):
    def __init__(self, message: str, suggestions: Optional[List[str]] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.suggestions = suggestions or []


class _PolicySelectionError(Exception):
    def __init__(self, message: str, choices: Optional[Sequence[str]] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.choices = list(choices or [])


def _normalize_resource_address(address: Any) -> Optional[str]:
    if not isinstance(address, str):
        return None
    token = address.strip()
    return token or None


def _module_path_from_address(address: Optional[str]) -> str:
    if not isinstance(address, str) or not address:
        return "root"
    modules = [segment for segment in address.split(".") if segment.startswith("module")]
    if not modules:
        return "root"
    return ".".join(modules)


def _suggest_addresses(target: str, available: Sequence[str], limit: int = 5) -> List[str]:
    subset = [addr for addr in available if target in addr]
    if not subset:
        subset = list(available)
    return subset[:limit]


def _resolve_resource_scope(target: str, resources: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    normalized = (target or "").strip()
    if not normalized:
        raise _ResourceScopeError("Resource address must be non-empty.")
    address_pairs = [
        (addr, res)
        for res in resources
        for addr in [_normalize_resource_address(res.get("address"))]
        if addr
    ]
    if not address_pairs:
        raise _ResourceScopeError("Plan has no addressable resources.")
    for addr, res in address_pairs:
        if addr == normalized:
            return {"address": addr, "resource": res, "match_type": "exact"}
    suffix_matches = [(addr, res) for addr, res in address_pairs if addr.endswith(normalized)]
    if len(suffix_matches) == 1:
        addr, res = suffix_matches[0]
        return {"address": addr, "resource": res, "match_type": "suffix"}
    if len(suffix_matches) > 1:
        suggestions = [addr for addr, _ in suffix_matches][:5]
        raise _ResourceScopeError(
            f"Resource selector '{normalized}' is ambiguous; matches {len(suffix_matches)} addresses.",
            suggestions=suggestions,
        )
    suggestions = _suggest_addresses(normalized, [addr for addr, _ in address_pairs])
    raise _ResourceScopeError(
        f"Resource address '{normalized}' not found in plan.",
        suggestions=suggestions,
    )


def _tokenize_multi_value(values: Optional[Sequence[Any]]) -> List[str]:
    tokens: List[str] = []
    for value in values or []:
        if not isinstance(value, str):
            continue
        parts = value.split(",")
        for part in parts:
            normalized = part.strip()
            if normalized:
                tokens.append(normalized)
    return tokens


def _resolve_policy_selection(
    explicit_ids: Optional[Sequence[str]],
    preset_values: Optional[Sequence[str]],
    available_ids: Sequence[str],
) -> List[str]:
    available_set = set(available_ids)
    requested: List[str] = []

    for token in _tokenize_multi_value(explicit_ids):
        policy_id = token.upper()
        if policy_id not in available_set:
            raise _PolicySelectionError(
                f"Unknown policy id '{token}'.",
                choices=sorted(available_set),
            )
        requested.append(policy_id)

    preset_tokens = _tokenize_multi_value(preset_values)
    for token in preset_tokens:
        lower = token.lower()
        if lower in _POLICY_PRESETS:
            preset = _POLICY_PRESETS[lower]
            if preset == _POLICY_PRESET_ALL:
                requested.extend(available_ids)
            else:
                missing = sorted(pid for pid in preset if pid not in available_set)
                if missing:
                    raise _PolicySelectionError(
                        f"Preset '{token}' references unavailable policies: {', '.join(missing)}",
                        choices=sorted(available_set),
                    )
                for pid in available_ids:
                    if pid in preset:
                        requested.append(pid)
            continue
        upper = token.upper()
        if upper in available_set:
            requested.append(upper)
            continue
        preset_choices = sorted(set(list(_POLICY_PRESETS.keys()) + list(available_set)))
        raise _PolicySelectionError(
            f"Unknown policy preset or id '{token}'.",
            choices=preset_choices,
        )

    if not requested:
        return list(available_ids)

    result: List[str] = []
    seen: Set[str] = set()
    for policy_id in requested:
        if policy_id in seen:
            continue
        seen.add(policy_id)
        result.append(policy_id)
    return result


class _PolicyEvaluationGuard:
    def __init__(self, policy: Any, sink: List[Dict[str, str]]) -> None:
        self._policy = policy
        self._sink = sink

    def __enter__(self) -> "_PolicyEvaluationGuard":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        _tb: Optional[Any],
    ) -> bool:
        if exc_type is None or exc is None:
            return False
        if not issubclass(exc_type, Exception):
            return False
        policy_id = getattr(getattr(self._policy, "metadata", None), "policy_id", "unknown")
        self._sink.append(
            {
                "policy": policy_id,
                "error": f"{exc.__class__.__name__}: {exc}",
            }
        )
        return True


def _print_policy_manifest(manifest_path: Optional[str]) -> int:
    if POLICY_PACK_HASH is None:
        message = _POLICY_PACK_ERROR or "Unknown policy pack error"
        print(f"Policy pack load error: {message}", file=sys.stderr)
        return EXIT_POLICY_LOAD_ERROR
    if manifest_path:
        try:
            manifest = load_policy_manifest(manifest_path)
        except PolicyManifestError as exc:
            print(f"Policy manifest error: {exc}", file=sys.stderr)
            return EXIT_CONFIG_ERROR
    else:
        policies = get_policies()
        manifest = build_policy_manifest(
            [policy.metadata for policy in policies],
            policy_pack_hash_value=POLICY_PACK_HASH,
        )
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return EXIT_SUCCESS


def _run_compare_mode(
    *,
    old_path: Path,
    new_path: Path,
    as_json: bool,
    gha_mode: bool,
) -> int:
    try:
        old_plan, old_resources, *_ = load_plan_context(old_path)
        new_plan, new_resources, *_ = load_plan_context(new_path)
    except _PlanLoadError:
        return EXIT_INVALID_INPUT

    plan_evolution = compute_plan_evolution(
        old_plan=old_plan,
        new_plan=new_plan,
        old_file=old_path,
        new_file=new_path,
        old_resources=old_resources,
        new_resources=new_resources,
    )
    status = "ALERT" if plan_evolution.get("downgraded_encryption", {}).get("count") else "OK"
    payload: Dict[str, Any] = {
        "mode": "compare",
        "status": status,
        "plan_evolution": plan_evolution,
        "vectorscan_version": VECTORSCAN_VERSION,
        "schema_version": OUTPUT_SCHEMA_VERSION,
    }
    payload = cast(Dict[str, Any], _sanitize_for_json(payload))
    if as_json:
        print(
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
                sort_keys=gha_mode,
            )
        )
    else:
        print(render_plan_evolution_text(plan_evolution))
    return EXIT_SUCCESS


def _load_manifest_override(
    manifest_path: str,
    *,
    policy_pack_hash_value: str,
    selected_policy_ids: Sequence[str],
) -> Dict[str, Any]:
    manifest = load_policy_manifest(manifest_path)
    manifest_hash = manifest.get("policy_pack_hash")
    if manifest_hash and manifest_hash != policy_pack_hash_value:
        raise PolicyManifestError(
            "Policy manifest hash does not match the active policy pack.",
        )
    manifest_ids = {
        entry.get("id") for entry in manifest.get("policies", []) if isinstance(entry, dict)
    }
    if manifest_ids and not set(selected_policy_ids).issubset(manifest_ids):
        missing = sorted(set(selected_policy_ids) - manifest_ids)
        raise PolicyManifestError(
            f"Policy manifest missing selected policy ids: {', '.join(missing)}",
        )
    return manifest


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VectorScan: minimal tfplan checks (encryption + mandatory tags)"
    )
    parser.add_argument("plan", type=str, nargs="?", help="Path to tfplan.json")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON result")
    parser.add_argument("--email", type=str, help="Optional email for lead capture payload")
    parser.add_argument(
        "--lead-capture",
        action="store_true",
        help="Enable local lead capture (writes JSON under tools/vectorscan/captures)",
    )
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Opt-in to lead capture POSTs, telemetry uploads, and Terraform downloads (default: network disabled)",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        help="Optional HTTP endpoint to POST lead payload (default from env VSCAN_LEAD_ENDPOINT)",
    )
    parser.add_argument(
        "--iam-drift-penalty",
        type=int,
        default=None,
        help="Penalty to subtract from compliance_score when IAM drift fails (overrides env VSCAN_IAM_DRIFT_PENALTY; default 20)",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("OLD_PLAN", "NEW_PLAN"),
        help="Compare two tfplan.json files and emit a plan_evolution summary (skips policy evaluation).",
    )
    parser.add_argument(
        "--terraform-tests",
        action="store_true",
        help="Ensure a supported Terraform CLI is available and run 'terraform test' before scanning",
    )
    parser.add_argument(
        "--terraform-bin",
        type=str,
        help="Optional path to a Terraform binary to use when running tests (overrides VSCAN_TERRAFORM_BIN)",
    )
    parser.add_argument(
        "--no-terraform-download",
        action="store_true",
        help="Skip automatic Terraform downloads when running tests",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color in human-readable output"
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Include a narrative explain block (also adds 'explanation' to JSON output)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Show only changed attributes via a structured plan diff block",
    )
    parser.add_argument(
        "--preview-vectorguard",
        action="store_true",
        help="Emit VectorGuard preview metadata (no paid policies) and exit with code 10",
    )
    parser.add_argument(
        "--resource",
        type=str,
        help="Terraform address (e.g., module.db.aws_db_instance.example) to scope checks",
    )
    parser.add_argument(
        "--policy-manifest",
        nargs="?",
        const=_POLICY_MANIFEST_SENTINEL,
        metavar="PATH",
        help="Print or override the policy manifest metadata. Run without PATH (and without a plan) to print the embedded manifest; provide PATH during scans to use a custom manifest file.",
    )
    parser.add_argument(
        "--policies",
        action="append",
        metavar="PRESET",
        help="Comma-separated policy presets or IDs to enable (e.g., 'free', 'finops', 'P-SEC-001').",
    )
    parser.add_argument(
        "--policy",
        dest="policy_ids",
        action="append",
        metavar="POLICY_ID",
        help="Explicit policy ID to enable (repeatable).",
    )
    parser.add_argument(
        "--gha",
        action="store_true",
        help="GitHub Action mode: force JSON output, disable color, and suppress human-readable banners.",
    )
    return parser


def _normalize_email_args(argv: Sequence[str] | None) -> List[str]:
    raw_argv = list(argv or sys.argv[1:])
    try:
        idx = raw_argv.index("--email")
        if idx + 1 < len(raw_argv):
            next_value = raw_argv[idx + 1]
            if isinstance(next_value, str) and next_value.startswith("-"):
                raw_argv.pop(idx + 1)
                raw_argv[idx] = f"--email={next_value}"
    except ValueError:
        pass
    return raw_argv


def _should_run_terraform_tests(ns: argparse.Namespace) -> bool:
    return ns.terraform_tests or os.getenv("VSCAN_TERRAFORM_TESTS", "0") == "1"


def _should_auto_download_terraform(ns: argparse.Namespace, offline_mode: bool) -> bool:
    if offline_mode:
        return False
    if getattr(ns, "no_terraform_download", False):
        return False

    allow_env = os.getenv("VSCAN_ALLOW_TERRAFORM_DOWNLOAD")
    if allow_env is not None:
        if env_truthy(allow_env):
            return True
        if env_falsey(allow_env):
            return False

    legacy_env = os.getenv("VSCAN_TERRAFORM_AUTO_DOWNLOAD")
    if legacy_env is not None:
        if env_truthy(legacy_env):
            return True
        if env_falsey(legacy_env):
            return False

    return False


def _execute_terraform_tests(
    ns: argparse.Namespace, *, offline_mode: bool
) -> Dict[str, Any] | None:
    if not _should_run_terraform_tests(ns):
        return None
    auto_download = _should_auto_download_terraform(ns, offline_mode)
    print("[VectorScan] Ensuring Terraform CLI for module tests...", file=sys.stderr)
    terraform_report = run_terraform_tests(ns.terraform_bin, auto_download)
    status = terraform_report.get("status") if terraform_report else "SKIP"
    version = terraform_report.get("version", "?") if terraform_report else "?"
    source = terraform_report.get("source", "?") if terraform_report else "?"
    print(
        f"[VectorScan] Terraform test status: {status} (CLI {version}, source={source})",
        file=sys.stderr,
    )
    if terraform_report:
        stdout_full = terraform_report.get("stdout", "")
        stderr_full = terraform_report.get("stderr", "")
        if stdout_full:
            print(stdout_full, end="" if stdout_full.endswith("\n") else "\n")
        if stderr_full:
            print(stderr_full, end="" if stderr_full.endswith("\n") else "\n", file=sys.stderr)
    return terraform_report


@dataclass
class PolicyEvaluationResult:
    policies: List[Any]
    policy_ids: List[str]
    severity_lookup: Dict[str, str]
    policy_metadata: Dict[str, Any]
    violations: List[str]
    policy_errors: List[Dict[str, str]]


def _evaluate_registered_policies(
    resources: Sequence[Dict[str, Any]],
    policies: Sequence[Any],
) -> PolicyEvaluationResult:
    policies_list = list(policies)
    policy_ids = [p.metadata.policy_id for p in policies_list]
    severity_lookup = {p.metadata.policy_id: p.metadata.severity for p in policies_list}
    policy_metadata_lookup = {p.metadata.policy_id: p.metadata for p in policies_list}
    violations: List[str] = []
    policy_errors: List[Dict[str, str]] = []
    for policy in policies_list:
        with _PolicyEvaluationGuard(policy, policy_errors):
            violations.extend(policy.evaluate(resources))
    return PolicyEvaluationResult(
        policies=policies_list,
        policy_ids=policy_ids,
        severity_lookup=severity_lookup,
        policy_metadata=policy_metadata_lookup,
        violations=violations,
        policy_errors=policy_errors,
    )


def _inject_preview_metadata(payload: Dict[str, Any]) -> Dict[str, Any]:
    manifest = load_preview_manifest()
    payload["preview_generated"] = True
    payload["preview_policies"] = manifest["policies"]
    payload["preview_manifest"] = {
        "version": manifest.get("version"),
        "generated_at": manifest.get("generated_at"),
        "signature": manifest.get("signature"),
        "verified": manifest.get("verified", False),
    }
    return manifest


def _run_cli(argv: list[str] | None = None) -> int:
    start_time = time.perf_counter()
    parser = _build_arg_parser()
    raw_argv = _normalize_email_args(argv)
    ns = parser.parse_args(raw_argv)
    gha_mode = bool(getattr(ns, "gha", False))
    if gha_mode:
        ns.as_json = True
        ns.no_color = True
    compare_args = list(getattr(ns, "compare") or [])
    offline_mode = is_offline()
    if getattr(ns, "allow_network", False):
        offline_mode = False
    strict_mode = is_strict_mode()
    _ensure_strict_clock(strict_mode)
    use_color = _should_use_color(ns.no_color)

    manifest_flag_value = getattr(ns, "policy_manifest", None)
    if compare_args:
        if ns.plan is not None:
            parser.error("--compare cannot be combined with a plan input.")
        if manifest_flag_value is not None:
            parser.error("--policy-manifest cannot be combined with --compare.")
        old_path, new_path = (Path(compare_args[0]), Path(compare_args[1]))
        return _run_compare_mode(
            old_path=old_path,
            new_path=new_path,
            as_json=bool(ns.as_json),
            gha_mode=gha_mode,
        )
    if ns.plan is None:
        if manifest_flag_value is None:
            parser.error("Path to tfplan.json is required unless --policy-manifest is used.")
        manifest_path = (
            None if manifest_flag_value == _POLICY_MANIFEST_SENTINEL else manifest_flag_value
        )
        return _print_policy_manifest(manifest_path)
    if manifest_flag_value == _POLICY_MANIFEST_SENTINEL:
        parser.error(
            "--policy-manifest requires a PATH when scanning. Run without a plan to print the embedded manifest."
        )
    manifest_override_path: Optional[str] = None
    if manifest_flag_value not in (None, _POLICY_MANIFEST_SENTINEL):
        manifest_override_path = manifest_flag_value

    if POLICY_PACK_HASH is None:
        message = _POLICY_PACK_ERROR or "Unknown policy pack error"
        print(f"Policy pack load error: {message}", file=sys.stderr)
        return EXIT_POLICY_LOAD_ERROR
    policy_pack_hash_value = POLICY_PACK_HASH

    path = Path(ns.plan)
    try:
        plan, all_resources, plan_limits, module_stats = load_plan_context(path)
    except _PlanLoadError:
        return EXIT_INVALID_INPUT

    resource_scope = None
    resource_filter_set: Optional[Set[str]] = None
    resources = all_resources
    if ns.resource:
        try:
            resource_scope = _resolve_resource_scope(ns.resource, all_resources)
        except _ResourceScopeError as exc:
            print(exc.message, file=sys.stderr)
            if exc.suggestions:
                joined = ", ".join(exc.suggestions)
                print(f"Did you mean: {joined}?", file=sys.stderr)
            return EXIT_INVALID_INPUT
        resources = [resource_scope["resource"]]
        resource_filter_set = {resource_scope["address"]}

    terraform_report = _execute_terraform_tests(ns, offline_mode=offline_mode)

    all_policies = get_policies()
    available_policy_ids = [p.metadata.policy_id for p in all_policies]
    try:
        selected_policy_ids = _resolve_policy_selection(
            ns.policy_ids, ns.policies, available_policy_ids
        )
    except _PolicySelectionError as exc:
        print(exc.message, file=sys.stderr)
        if exc.choices:
            print("Available options: " + ", ".join(exc.choices), file=sys.stderr)
        return EXIT_INVALID_INPUT
    if not selected_policy_ids:
        print("No policies selected for evaluation.", file=sys.stderr)
        return EXIT_INVALID_INPUT
    policy_lookup = {p.metadata.policy_id: p for p in all_policies}
    policies = [policy_lookup[pid] for pid in selected_policy_ids]

    policy_eval = _evaluate_registered_policies(resources, policies)
    policy_ids = policy_eval.policy_ids
    severity_lookup = policy_eval.severity_lookup
    policy_metadata_lookup = policy_eval.policy_metadata
    violations = policy_eval.violations
    policy_errors = policy_eval.policy_errors

    if manifest_override_path:
        try:
            manifest_data = _load_manifest_override(
                manifest_override_path,
                policy_pack_hash_value=policy_pack_hash_value,
                selected_policy_ids=policy_ids,
            )
        except PolicyManifestError as exc:
            print(f"Policy manifest error: {exc}", file=sys.stderr)
            return EXIT_CONFIG_ERROR
    else:
        manifest_data = build_policy_manifest(
            [policy.metadata for policy in policies],
            policy_pack_hash_value=policy_pack_hash_value,
        )

    _strict_require(
        strict_mode,
        not policy_errors,
        "Strict mode prohibits policy_errors; ensure all policies execute cleanly.",
    )

    severity_summary = compute_violation_severity_summary(violations, severity_lookup)
    status = "FAIL" if (violations or policy_errors) else "PASS"
    code = EXIT_POLICY_FAIL if status == "FAIL" else EXIT_SUCCESS

    violation_structs = build_violation_structs(
        violations=violations,
        resources=resources,
        severity_lookup=severity_lookup,
        policy_metadata=policy_metadata_lookup,
    )

    payload = {
        "status": status,
        "file": str(path),
        "violations": violations,
        "violations_struct": violation_structs,
        "counts": {"violations": len(violations)},
        "checks": policy_ids,
        "vectorscan_version": VECTORSCAN_VERSION,
        "policy_version": POLICY_VERSION,
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "policy_pack_hash": policy_pack_hash_value,
        "policy_errors": policy_errors,
        "violation_severity_summary": severity_summary,
    }

    payload["policy_source_url"] = manifest_data.get("policy_source_url")
    payload["policy_manifest"] = manifest_data

    payload["violation_count_by_severity"] = dict(severity_summary)

    if resource_scope:
        payload["resource_filter"] = {
            "input": ns.resource,
            "address": resource_scope["address"],
            "type": resource_scope["resource"].get("type"),
            "name": resource_scope["resource"].get("name"),
            "module_path": _module_path_from_address(resource_scope["address"]),
            "match": resource_scope["match_type"],
        }

    if terraform_report is not None:
        payload["terraform_tests"] = {
            **{
                k: terraform_report.get(k)
                for k in (
                    "status",
                    "version",
                    "binary",
                    "source",
                    "strategy",
                    "message",
                    "returncode",
                )
            },
            "stdout": _truncate_output(terraform_report.get("stdout"), strict=strict_mode),
            "stderr": _truncate_output(terraform_report.get("stderr"), strict=strict_mode),
        }
        if status == "PASS":
            if terraform_report.get("status") == "FAIL":
                status = "FAIL"
                code = EXIT_TERRAFORM_FAIL
            elif terraform_report.get("status") == "ERROR":
                status = "FAIL"
                code = EXIT_TERRAFORM_ERROR
        payload["status"] = status

    payload["environment"] = _build_environment_metadata(
        strict_mode=strict_mode,
        offline_mode=offline_mode,
        terraform_report=terraform_report,
        vectorscan_version_value=str(
            payload.get("vectorscan_version", VECTORSCAN_VERSION)
        ),
    )
    plan_metadata = compute_plan_metadata(
        plan,
        resources,
        module_stats=module_stats,
        plan_limits=plan_limits,
        resource_filter=resource_filter_set,
    )
    payload["plan_metadata"] = plan_metadata
    parser_mode_value = plan_metadata.get("parser_mode") or (
        "streaming" if module_stats else "legacy"
    )
    resource_count_value = plan_metadata.get("resource_count")

    suspicious_defaults = detect_suspicious_defaults(plan, all_resources)
    payload["suspicious_defaults"] = suspicious_defaults
    suspicious_default_reasons: List[str] = []
    for entry in suspicious_defaults:
        reason = entry.get("reason") if isinstance(entry, dict) else None
        if isinstance(reason, str) and reason:
            suspicious_default_reasons.append(reason)

    smell_report = compute_smell_report(
        plan_metadata=plan_metadata,
        resources=resources,
        resource_changes=plan.get("resource_changes") or [],
        resource_filter=resource_filter_set,
    )
    payload["smell_report"] = smell_report

    plan_diff_block: Optional[Dict[str, Any]] = None
    if ns.diff:
        plan_diff_block = build_plan_diff(plan, resource_filter=resource_filter_set)
        payload["plan_diff"] = plan_diff_block

    # Metrics
    metrics = compute_metrics(resources, violations)
    # IAM drift report
    drift = build_iam_drift_report(plan)
    payload["iam_drift_report"] = drift
    metrics["iam_drift"] = {
        "status": drift.get("status", "PASS"),
        "risky_change_count": drift.get("counts", {}).get("risky_changes", 0),
    }
    # Apply penalty to compliance_score if IAM drift failed (configurable)
    try:
        score = int(metrics.get("compliance_score", 0))
    except (TypeError, ValueError):
        score = 0
    # Determine penalty weight: CLI flag > env var > default 20
    if ns.iam_drift_penalty is not None:
        penalty = ns.iam_drift_penalty
    else:
        try:
            penalty = int(os.getenv("VSCAN_IAM_DRIFT_PENALTY", "20"))
        except (TypeError, ValueError):
            penalty = 20
    # Clamp penalty to sensible range
    if penalty < 0:
        penalty = 0
    if penalty > 100:
        penalty = 100
    if metrics["iam_drift"]["status"] == "FAIL" and penalty:
        score = max(0, score - penalty)
    metrics["compliance_score"] = score
    metrics["scan_duration_ms"] = _compute_scan_duration_ms(start_time)
    metrics["parser_mode"] = parser_mode_value
    if resource_count_value is not None:
        metrics["resource_count"] = resource_count_value
    payload["metrics"] = metrics

    risk_result = compute_plan_risk_profile(
        severity_summary=severity_summary,
        metrics=metrics,
        suspicious_defaults=suspicious_default_reasons,
    )
    payload["plan_risk_profile"] = risk_result["profile"]
    if risk_result["factors"]:
        payload["plan_risk_factors"] = risk_result["factors"]

    try:
        compliance_for_grade = int(metrics.get("compliance_score", 0))
    except (TypeError, ValueError):
        compliance_for_grade = 0
    payload["security_grade"] = compute_security_grade(compliance_for_grade, severity_summary)

    explanation_block: Dict[str, Any] | None = None
    if ns.explain:
        explanation_block = build_explanation(
            status=status,
            plan_metadata=plan_metadata,
            smell_report=smell_report,
            metrics=metrics,
            severity_summary=severity_summary,
            violations=violations,
            policies=policies,
            iam_drift=drift,
        )
        payload["explanation"] = explanation_block

    preview_manifest_data: Dict[str, Any] | None = None
    if ns.preview_vectorguard:
        try:
            preview_manifest_data = _inject_preview_metadata(payload)
        except PreviewManifestError as exc:
            print(f"Preview manifest error: {exc}", file=sys.stderr)
            return EXIT_CONFIG_ERROR
        code = EXIT_PREVIEW_MODE

    safe_payload = cast(Dict[str, Any], _sanitize_for_json(payload))

    if ns.as_json:
        print(
            json.dumps(
                safe_payload,
                indent=2,
                ensure_ascii=False,
                sort_keys=gha_mode,
            )
        )
        return code

    has_policy_failures = bool(policy_errors)
    has_policy_violations = bool(violations)

    # default human-readable output
    if terraform_report is not None:
        tf_status = str(terraform_report.get("status", "SKIP")).upper()
        badge = _status_badge(tf_status, use_color)
        if tf_status == "PASS":
            print(f"Terraform tests: {badge}")
        elif tf_status == "SKIP":
            message = terraform_report.get("message", "Terraform CLI unavailable; skipping tests")
            print(f"Terraform tests: {badge} - {message}")
        else:
            print(f"Terraform tests: {badge} (see details above)")

    if resource_scope and not ns.as_json:
        scope_addr = resource_scope["address"]
        if resource_scope["match_type"] == "suffix" and ns.resource != scope_addr:
            print(f"Resource scope: {scope_addr} (matched from '{ns.resource}')")
        else:
            print(f"Resource scope: {scope_addr}")

    if has_policy_failures or has_policy_violations:
        print(f"{_status_badge('FAIL', use_color)} - tfplan.json - VectorScan checks")
        for v in violations:
            print("  ", v)
        if violations:
            summary_line = ", ".join(
                f"{level}={severity_summary.get(level, 0)}" for level in SEVERITY_LEVELS
            )
            print(f"  Violation severity summary: {summary_line}")
        if policy_errors:
            print("  Policy engine errors detected (partial coverage):")
            for err in policy_errors:
                print(f"    - {err['policy']}: {err['error']}")
        print("\n🚀 Want full, automated Zero-Trust & FinOps coverage?")
        print(
            "Get the complete 8-point compliance kit (Blueprint) for $79/year → https://gumroad.com/l/vectorguard-blueprint\n"
        )
    else:
        print(
            f"{_status_badge('PASS', use_color)} - tfplan.json - VectorScan checks (encryption + mandatory tags)"
        )

    if ns.explain and not ns.as_json and explanation_block:
        print("")
        print(render_explanation_text(explanation_block))
        print("")

    if ns.diff and not ns.as_json:
        print("")
        print(render_plan_diff_text(plan_diff_block or {"summary": {}, "resources": []}))
        print("")

    if preview_manifest_data and not ns.as_json:
        print("VectorGuard preview policies (no paid policy execution):")
        for entry in preview_manifest_data["policies"]:
            print(f"  - {entry['id']}: {entry['summary']}")
        preview_path = preview_manifest_data.get("path")
        if preview_path:
            print(
                f"  Manifest: {preview_path} (verified={preview_manifest_data.get('verified', False)})"
            )
        print("Preview mode exit code: 10 (PREVIEW_MODE_ONLY)")

    # Optional lead capture (local, and optional HTTP POST if configured)
    if (not offline_mode) and (
        ns.lead_capture or ns.email or ns.endpoint or os.getenv("VSCAN_LEAD_ENDPOINT")
    ):
        lead = {
            "email": (ns.email or ""),
            "result": safe_payload,
            "timestamp": _now(),
            "source": "vectorscan-cli",
        }
        path_out = _write_local_capture(lead)
        print(f"Lead payload saved: {path_out}")

        endpoint = ns.endpoint or os.getenv("VSCAN_LEAD_ENDPOINT", "")
        if endpoint:
            ok, info = _maybe_post(endpoint, lead)
            print(f"Lead POST => {info} ({'OK' if ok else 'SKIP/FAIL'})")
    return code


def main(argv: list[str] | None = None) -> int:
    try:
        ensure_supported_python()
        return _run_cli(argv)
    except UnsupportedPythonVersion as exc:
        print(f"[Python Compatibility] {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except StrictModeViolation as exc:
        print(f"[Strict Mode] {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
