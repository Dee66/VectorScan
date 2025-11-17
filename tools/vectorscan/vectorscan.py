#!/usr/bin/env python3
"""
VectorScan: Minimal CLI to check two critical guardrails in a Terraform plan JSON.
    root_module = planned_values.get("root_module")
    if root_module is None:
        _schema_error("root_module must be present under planned_values")
    - P-FIN-001 (Mandatory Tagging): Resources should have CostCenter and Project tags (non-empty)

Usage:
    python3 tools/vectorscan/vectorscan.py path/to/tfplan.json [--json] [--email you@example.com] [--lead-capture] [--endpoint URL]

Exit codes:
    0 - PASS (no violations)
    2 - Input not found or invalid JSON
    3 - FAIL (violations found)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
import os
import time
import hashlib
from urllib import request
import argparse
import subprocess
import platform
import zipfile
import io
import shutil
import tempfile
import stat
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Set, Optional, Sequence, cast

ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_BOLD = "\033[1m"

from tools.vectorscan.time_utils import deterministic_epoch
from tools.vectorscan.tempfiles import secure_temp_file
from tools.vectorscan.policy_pack import PolicyPackError, policy_pack_hash
from tools.vectorscan.env_flags import env_truthy, env_falsey, is_offline, is_strict_mode
from tools.vectorscan.plan_stream import (
    ModuleStats,
    PlanSchemaError,
    PlanStreamError,
    build_slo_metadata as _build_slo_metadata,
    stream_plan,
)
from tools.vectorscan.versioning import (
    VECTORSCAN_VERSION,
    POLICY_VERSION,
    OUTPUT_SCHEMA_VERSION,
)
from tools.vectorscan.policies import get_policies, get_policy
from tools.vectorscan.policies.common import TAGGABLE_TYPES, REQUIRED_TAGS, is_nonempty_string

SEVERITY_LEVELS = ("critical", "high", "medium", "low")
RISKY_ACTION_TERMS = (
    # Wildcards
    "*",
    ":*",
    # S3 destructive or policy changes
    "s3:DeleteObject",
    "s3:PutObject",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    # RDS broad
    "rds:*",
    # IAM escalation
    "iam:*",
    "iam:PassRole",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    # KMS risky
    "kms:ScheduleKeyDeletion",
    "kms:DisableKey",
    "kms:DisableKeyRotation",
    "kms:PutKeyPolicy",
    # EC2 network exposure
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:CreateSecurityGroup",
    # CloudTrail disabling
    "cloudtrail:StopLogging",
    # CloudWatch Logs destructive
    "logs:DeleteLogGroup",
)

REMEDIATION_DOCS = {
    "P-SEC-001": [
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
        "https://vectorguard.dev/docs/policies/p-sec-001",
    ],
    "P-FIN-001": [
        "https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html",
        "https://vectorguard.dev/docs/policies/p-fin-001",
    ],
}

REQUIRED_TERRAFORM_VERSION = os.getenv("VSCAN_TERRAFORM_REQUIRED_VERSION", "1.13.5")
MIN_TERRAFORM_TESTS_VERSION = (1, 8, 0)
_ENV_TERRAFORM_CACHE = os.getenv("VSCAN_TERRAFORM_CACHE")
DEFAULT_TERRAFORM_CACHE = Path(_ENV_TERRAFORM_CACHE).expanduser() if _ENV_TERRAFORM_CACHE else Path(__file__).resolve().parent / ".terraform-bin"
ROOT_DIR = Path(__file__).resolve().parents[2]


EXIT_SUCCESS = 0
EXIT_INVALID_INPUT = 2
EXIT_POLICY_FAIL = 3
EXIT_POLICY_LOAD_ERROR = 4
EXIT_TERRAFORM_FAIL = 5
EXIT_CONFIG_ERROR = 6
EXIT_TERRAFORM_ERROR = EXIT_CONFIG_ERROR

try:
    POLICY_PACK_HASH: str | None = policy_pack_hash()
    _POLICY_PACK_ERROR: str | None = None
except PolicyPackError as exc:  # pragma: no cover - exercised via CLI tests
    POLICY_PACK_HASH = None
    _POLICY_PACK_ERROR = str(exc)


class StrictModeViolation(RuntimeError):
    """Raised when VSCAN_STRICT invariants are not satisfied."""


def _now() -> int:
    return deterministic_epoch()


def _compute_scan_duration_ms(start: float) -> int:
    forced = os.getenv("VSCAN_FORCE_DURATION_MS")
    if forced is not None:
        try:
            value = int(forced)
            return max(0, value)
        except ValueError:
            pass
    elapsed = (time.perf_counter() - start) * 1000.0
    if elapsed < 0:
        elapsed = 0
    return int(round(elapsed))


def _should_use_color(disable_flag: bool) -> bool:
    if disable_flag:
        return False
    # Respect standard NO_COLOR contract: presence disables color outright
    if os.getenv("NO_COLOR") is not None:
        return False
    vscan_no_color = os.getenv("VSCAN_NO_COLOR")
    if vscan_no_color is not None and not env_falsey(vscan_no_color):
        return False
    if env_truthy(os.getenv("VSCAN_FORCE_COLOR")):
        return True
    return sys.stdout.isatty()


def _colorize(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{code}{text}{ANSI_RESET}"


def _status_badge(status: str, use_color: bool) -> str:
    palette = {
        "PASS": ANSI_GREEN,
        "FAIL": ANSI_RED,
        "ERROR": ANSI_RED,
        "SKIP": ANSI_YELLOW,
    }
    color = palette.get(status.upper(), ANSI_BOLD)
    return _colorize(status, color, use_color)

def _parse_semver(value: str) -> Tuple[int, int, int]:
    parts: List[int] = []
    for token in value.split('.'):
        digits = ''.join(ch for ch in token if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])  # type: ignore[return-value]


def _safe_chdir_flag(path: Path, *, root: Optional[Path] = None) -> str:
    base = (root or ROOT_DIR).resolve()
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"Unsafe Terraform directory: {path} does not exist") from exc
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(
            f"Unsafe Terraform directory: {resolved} escapes repository root {base}"
        ) from exc
    return f"-chdir={resolved}"


def _truncate_output(text: Optional[str], limit: int = 4000, *, strict: bool = False) -> str:
    if not text:
        return ""
    text = text.strip()
    if strict:
        return text
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... (truncated)"


def _ensure_strict_clock(strict_mode: bool) -> None:
    if not strict_mode:
        return
    for key in ("VSCAN_CLOCK_ISO", "VSCAN_CLOCK_EPOCH", "SOURCE_DATE_EPOCH"):
        if os.getenv(key):
            return
    raise StrictModeViolation(
        "VSCAN_STRICT requires deterministic clock overrides via VSCAN_CLOCK_EPOCH, VSCAN_CLOCK_ISO, or SOURCE_DATE_EPOCH."
    )


def _strict_require(strict_mode: bool, condition: bool, message: str) -> None:
    if strict_mode and not condition:
        raise StrictModeViolation(message)


def _env_override(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _build_environment_metadata(
    *,
    strict_mode: bool,
    offline_mode: bool,
    terraform_report: Optional[Dict[str, Any]],
    vectorscan_version_value: str,
) -> Dict[str, Any]:
    platform_name = (_env_override("VSCAN_ENV_PLATFORM") or platform.system() or "unknown").lower()
    platform_release = _env_override("VSCAN_ENV_PLATFORM_RELEASE") or platform.release()
    python_version = _env_override("VSCAN_ENV_PYTHON_VERSION") or platform.python_version()
    python_impl = _env_override("VSCAN_ENV_PYTHON_IMPL") or platform.python_implementation()

    terraform_version = _env_override("VSCAN_ENV_TERRAFORM_VERSION")
    terraform_source = _env_override("VSCAN_ENV_TERRAFORM_SOURCE")
    if terraform_report:
        terraform_version = terraform_report.get("version") or terraform_version
        terraform_source = terraform_report.get("source") or terraform_source
    if terraform_version is None:
        terraform_version = "not-run" if terraform_report is None else "unknown"
    if terraform_source is None:
        terraform_source = "not-run" if terraform_report is None else "unknown"

    vectorscan_override = _env_override("VSCAN_ENV_VECTORSCAN_VERSION")

    return {
        "platform": platform_name,
        "platform_release": platform_release,
        "python_version": python_version,
        "python_implementation": python_impl,
        "terraform_version": terraform_version,
        "terraform_source": terraform_source,
        "vectorscan_version": vectorscan_override or vectorscan_version_value,
        "strict_mode": strict_mode,
        "offline_mode": offline_mode,
    }


class TerraformManagerError(RuntimeError):
    pass


class TerraformDownloadError(TerraformManagerError):
    pass


class TerraformNotFoundError(TerraformManagerError):
    pass


@dataclass
class TerraformResolution:
    path: Path
    version: str
    source: str  # "system", "override", or "download"


class TerraformManager:
    def __init__(self, required_version: str = REQUIRED_TERRAFORM_VERSION, download_dir: Optional[Path] = None, auto_download: bool = True):
        self.required_version = required_version
        self.required_tuple = _parse_semver(required_version)
        self.download_dir = download_dir or DEFAULT_TERRAFORM_CACHE
        self.auto_download = auto_download

    def ensure(self, override_path: Optional[str] = None) -> TerraformResolution:
        override = override_path or os.getenv("VSCAN_TERRAFORM_BIN")
        if override:
            override_path = override_path or override
            return self._resolve_override(Path(override_path))

        system_path = shutil.which("terraform")
        candidates: List[TerraformResolution] = []
        if system_path:
            res = self._resolution_for(Path(system_path), source="system")
            if res:
                if _parse_semver(res.version) >= self.required_tuple:
                    return res
                candidates.append(res)

        if not self.auto_download:
            if candidates:
                return candidates[0]
            raise TerraformNotFoundError("Terraform CLI not found and auto-download disabled. Set VSCAN_TERRAFORM_BIN or enable downloads.")

        try:
            downloaded = self._download()
        except TerraformDownloadError as exc:
            if candidates:
                print(f"VectorScan: Terraform download failed ({exc}); falling back to installed Terraform {candidates[0].version}.", file=sys.stderr)
                return candidates[0]
            raise

        res = self._resolution_for(downloaded, source="download")
        if not res:
            raise TerraformManagerError("Failed to determine version of downloaded Terraform binary.")
        return res

    def _resolve_override(self, path: Path) -> TerraformResolution:
        res = self._resolution_for(path, source="override")
        if not res:
            raise TerraformManagerError(f"Could not determine Terraform version for override path: {path}")
        return res

    def _resolution_for(self, path: Path, source: str) -> Optional[TerraformResolution]:
        version = self._binary_version(path)
        if not version:
            return None
        return TerraformResolution(path=path, version=version, source=source)

    def _binary_version(self, binary: Path) -> Optional[str]:
        try:
            result = subprocess.run([str(binary), "version", "-json"], capture_output=True, text=True)
        except FileNotFoundError:
            return None
        if result.returncode == 0:
            try:
                parsed = json.loads(result.stdout or "{}")
                version = parsed.get("terraform_version")
                if version:
                    return version
            except json.JSONDecodeError:
                pass
        # Fallback to plain string parsing
        try:
            result = subprocess.run([str(binary), "version"], capture_output=True, text=True)
        except FileNotFoundError:
            return None
        output = (result.stdout or "") + (result.stderr or "")
        for line in output.splitlines():
            line = line.strip()
            if line.lower().startswith("terraform v"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1].lstrip("v")
        return None

    def _download(self) -> Path:
        os_tag = platform.system().lower()
        arch_tag = platform.machine().lower()
        os_map = {
            "linux": "linux",
            "darwin": "darwin",
            "windows": "windows",
        }
        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "arm64": "arm64",
            "aarch64": "arm64",
        }
        if os_tag not in os_map or arch_tag not in arch_map:
            raise TerraformDownloadError(f"Unsupported platform for auto-download: {platform.system()} {platform.machine()}")

        dest_dir = self.download_dir / self.required_version
        dest_dir.mkdir(parents=True, exist_ok=True)
        binary_name = "terraform.exe" if os_map[os_tag] == "windows" else "terraform"
        dest_binary = dest_dir / binary_name
        if dest_binary.exists():
            return dest_binary

        filename = f"terraform_{self.required_version}_{os_map[os_tag]}_{arch_map[arch_tag]}.zip"
        url = f"https://releases.hashicorp.com/terraform/{self.required_version}/{filename}"
        try:
            with request.urlopen(url, timeout=30) as resp:
                data = resp.read()
        except Exception as exc:
            raise TerraformDownloadError(str(exc)) from exc

        expected_checksum = self._expected_checksum(filename)
        actual_checksum = hashlib.sha256(data).hexdigest()
        if expected_checksum and actual_checksum != expected_checksum:
            raise TerraformDownloadError(
                f"Checksum mismatch for {filename}: expected {expected_checksum}, got {actual_checksum}"
            )

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            try:
                member = zf.getinfo(binary_name)
            except KeyError as exc:
                raise TerraformDownloadError(f"Binary {binary_name} not found in Terraform archive") from exc
            try:
                tmp_dir = Path(tempfile.mkdtemp(prefix="terraform-download-"))
            except OSError as exc:
                raise TerraformDownloadError(f"Failed to create temp dir for Terraform download: {exc}") from exc
            try:
                zf.extract(member, path=tmp_dir)
                extracted = tmp_dir / binary_name
                shutil.move(str(extracted), dest_binary)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        dest_binary.chmod(dest_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return dest_binary

    def _expected_checksum(self, filename: str) -> str:
        sums_name = f"terraform_{self.required_version}_SHA256SUMS"
        sums_url = f"https://releases.hashicorp.com/terraform/{self.required_version}/{sums_name}"
        try:
            with request.urlopen(sums_url, timeout=30) as resp:
                text = resp.read().decode("utf-8")
        except Exception as exc:
            raise TerraformDownloadError(f"Failed to fetch Terraform checksum file: {exc}") from exc

        for line in text.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            parts = clean.split()
            if len(parts) < 2:
                continue
            hash_value, file_name = parts[0], parts[-1]
            if file_name == filename:
                return hash_value
        raise TerraformDownloadError(f"Checksum entry for {filename} not found at {sums_url}")


class TerraformTestStrategy:
    name = "base"

    def run(self, terraform_bin: Path, version: str) -> Dict[str, Any]:
        raise NotImplementedError


class ModernTerraformTestStrategy(TerraformTestStrategy):
    name = "modern"

    def run(self, terraform_bin: Path, version: str) -> Dict[str, Any]:
        test_dir = ROOT_DIR / "tests" / "tf-tests"
        if not test_dir.exists():
            return {
                "status": "SKIP",
                "message": f"Terraform tests directory not found: {test_dir}",
            }
        try:
            chdir_flag = _safe_chdir_flag(test_dir)
        except ValueError as exc:
            return {
                "status": "ERROR",
                "message": str(exc),
            }

        cmd_init = [str(terraform_bin), chdir_flag, "init", "-input=false"]
        init_result = subprocess.run(cmd_init, capture_output=True, text=True)
        stdout_parts: List[str] = []
        stderr_parts: List[str] = []
        if init_result.stdout:
            stdout_parts.append(init_result.stdout)
        if init_result.stderr:
            stderr_parts.append(init_result.stderr)

        if init_result.returncode != 0:
            return {
                "status": "FAIL",
                "returncode": init_result.returncode,
                "stdout": "".join(stdout_parts),
                "stderr": "".join(stderr_parts),
                "command": cmd_init,
            }

        cmd_test = [str(terraform_bin), chdir_flag, "test"]
        test_result = subprocess.run(cmd_test, capture_output=True, text=True)
        if test_result.stdout:
            stdout_parts.append(test_result.stdout)
        if test_result.stderr:
            stderr_parts.append(test_result.stderr)
        status = "PASS" if test_result.returncode == 0 else "FAIL"
        return {
            "status": status,
            "returncode": test_result.returncode,
            "stdout": "".join(stdout_parts),
            "stderr": "".join(stderr_parts),
            "command": cmd_test,
            "init_command": cmd_init,
            "init_returncode": init_result.returncode,
        }


class LegacyTerraformTestStrategy(TerraformTestStrategy):
    name = "legacy-skip"

    def run(self, terraform_bin: Path, version: str) -> Dict[str, Any]:
        message = (
            f"Terraform v{version} does not support 'terraform test'. "
            "Upgrade the CLI or allow VectorScan to download a newer version."
        )
        return {
            "status": "SKIP",
            "message": message,
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }


def _select_strategy(version: str) -> TerraformTestStrategy:
    if _parse_semver(version) >= MIN_TERRAFORM_TESTS_VERSION:
        return ModernTerraformTestStrategy()
    return LegacyTerraformTestStrategy()


def _strategy_error_report(
    resolution: TerraformResolution,
    strategy: TerraformTestStrategy,
    message: str,
    *,
    stderr: str = "",
) -> Dict[str, Any]:
    return {
        "status": "ERROR",
        "message": message,
        "version": resolution.version,
        "binary": str(resolution.path),
        "source": resolution.source,
        "strategy": getattr(strategy, "name", "unknown"),
        "stdout": "",
        "stderr": stderr,
    }


def run_terraform_tests(override_bin: Optional[str], auto_download: bool) -> Dict[str, Any]:
    manager = TerraformManager(required_version=REQUIRED_TERRAFORM_VERSION, download_dir=DEFAULT_TERRAFORM_CACHE, auto_download=auto_download)
    try:
        resolution = manager.ensure(override_bin)
    except TerraformNotFoundError as exc:
        return {
            "status": "SKIP",
            "message": str(exc),
        }
    except TerraformManagerError as exc:
        return {
            "status": "ERROR",
            "message": str(exc),
        }

    strategy = _select_strategy(resolution.version)
    try:
        report = strategy.run(resolution.path, resolution.version)
    except OSError as exc:
        return _strategy_error_report(
            resolution,
            strategy,
            f"Terraform execution failed: {exc}",
            stderr=str(exc),
        )
    except Exception as exc:
        return _strategy_error_report(
            resolution,
            strategy,
            f"Terraform tests crashed unexpectedly: {exc}",
            stderr=str(exc),
        )
    report["version"] = resolution.version
    report["binary"] = str(resolution.path)
    report["source"] = resolution.source
    report["strategy"] = strategy.name
    return report


def _schema_error(message: str) -> None:
    print(f"Schema error: {message}", file=sys.stderr)
    sys.exit(EXIT_INVALID_INPUT)


def _validate_plan_schema(plan: Dict[str, Any]) -> None:
    planned_values = plan.get("planned_values")
    if not isinstance(planned_values, dict):
        planned_values = {}
        plan["planned_values"] = planned_values

    root_module_obj = planned_values.get("root_module")
    if root_module_obj is None:
        _schema_error("planned_values.root_module must be present")
    if not isinstance(root_module_obj, dict):
        _schema_error("planned_values.root_module must be an object")
    root_module = cast(Dict[str, Any], root_module_obj)

    resources = root_module.get("resources")
    if resources is None:
        root_module["resources"] = []
    elif not isinstance(resources, list):
        _schema_error("resources must be a list under planned_values/root_module")

    child_modules = root_module.get("child_modules")
    if child_modules is None:
        root_module["child_modules"] = []
    elif not isinstance(child_modules, list):
        _schema_error("child_modules must be a list when present")


def load_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(EXIT_INVALID_INPUT)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {path}: {e}", file=sys.stderr)
        sys.exit(EXIT_INVALID_INPUT)
    if not isinstance(data, dict):
        _schema_error("Top-level plan JSON must be an object")
    _validate_plan_schema(data)
    return data


def load_plan_context(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], Optional[ModuleStats]]:
    """Load a tfplan with streaming parser when enabled.

    Returns a tuple of (plan_dict, resources, plan_limits, module_stats).
    plan_limits carries parse duration/file size metadata and exceeds_threshold flag.
    """

    disable_flag = os.getenv("VSCAN_STREAMING_DISABLE")
    streaming_enabled = not (disable_flag and not env_falsey(disable_flag))

    if streaming_enabled:
        try:
            return _load_plan_streaming_context(path)
        except SystemExit:
            raise
        except Exception as exc:
            print(
                f"[VectorScan] Streaming parser unavailable ({exc}); falling back to legacy parser.",
                file=sys.stderr,
            )

    return _load_plan_eager_context(path)


def _load_plan_streaming_context(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], ModuleStats]:
    try:
        result = stream_plan(path)
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(EXIT_INVALID_INPUT)
    except PlanSchemaError as exc:
        _schema_error(str(exc))
    except PlanStreamError as exc:
        print(f"Error: invalid JSON: {path}: {exc}", file=sys.stderr)
        sys.exit(EXIT_INVALID_INPUT)

    plan = result.top_level
    plan_limits = _build_plan_limit_block(
        resource_count=len(result.resources),
        parse_duration_ms=result.parse_duration_ms,
        file_size_bytes=result.file_size_bytes,
    )
    return plan, result.resources, plan_limits, result.module_stats


def _load_plan_eager_context(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], Optional[ModuleStats]]:
    start = time.perf_counter()
    plan = load_json(path)
    duration_ms = int(round((time.perf_counter() - start) * 1000))
    try:
        file_size_bytes = path.stat().st_size
    except FileNotFoundError:
        file_size_bytes = 0
    resources = iter_resources(plan)
    plan_limits = _build_plan_limit_block(
        resource_count=len(resources),
        parse_duration_ms=duration_ms,
        file_size_bytes=file_size_bytes,
    )
    return plan, resources, plan_limits, None


def _build_plan_limit_block(*, resource_count: int, parse_duration_ms: int, file_size_bytes: int) -> Dict[str, Any]:
    forced = os.getenv("VSCAN_FORCE_PLAN_PARSE_MS")
    if forced is None:
        forced = os.getenv("VSCAN_FORCE_DURATION_MS")
    if forced is not None:
        try:
            parse_duration_ms = max(0, int(forced))
        except ValueError:
            pass

    exceeds, slo_block = _build_slo_metadata(resource_count, parse_duration_ms, file_size_bytes)
    return {
        "file_size_bytes": file_size_bytes,
        "parse_duration_ms": parse_duration_ms,
        "plan_slo": slo_block,
        "exceeds_threshold": exceeds,
    }


def iter_resources(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    def collect(mod):
        res = list(mod.get("resources", []) or [])
        for child in mod.get("child_modules", []) or []:
            res.extend(collect(child))
        return res
    root = plan.get("planned_values", {}).get("root_module", {})
    return collect(root)


def _bytes_to_mb(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    try:
        return round(float(value) / 1_000_000, 6)
    except Exception:
        return None


def _classify_change_actions(actions: Sequence[Any]) -> Optional[str]:
    normalized = [str(action).lower() for action in actions if isinstance(action, str) and action]
    if not normalized:
        return None
    if "update" in normalized:
        return "changes"
    if "create" in normalized and "delete" in normalized:
        return "changes"
    if "create" in normalized:
        return "adds"
    if "delete" in normalized:
        return "destroys"
    return None


def _compute_security_grade(compliance_score: int, severity_summary: Dict[str, int]) -> str:
    score = max(0, min(100, compliance_score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    critical = severity_summary.get("critical", 0)
    high = severity_summary.get("high", 0)

    if critical:
        return "F"
    if high:
        if grade == "A":
            return "B"
        if grade in {"B", "C"}:
            return "C"
    return grade


def _normalize_provider_label(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    token = value.strip().strip('"')
    if not token:
        return None
    if token.startswith("provider["):
        token = token[len("provider[") :]
        if token.endswith("]"):
            token = token[:-1]
        token = token.strip('"')
    if "/" in token:
        token = token.split("/")[-1]
    token = token.strip()
    if not token:
        return None
    return token.lower()


def compute_plan_metadata(
    plan: Dict[str, Any],
    resources: Optional[List[Dict[str, Any]]] = None,
    *,
    module_stats: Optional[ModuleStats] = None,
    plan_limits: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resource_list = resources if resources is not None else iter_resources(plan)
    resource_types: Dict[str, int] = {}
    providers: Set[str] = set()

    for resource in resource_list:
        r_type = resource.get("type")
        if isinstance(r_type, str) and r_type:
            resource_types[r_type] = resource_types.get(r_type, 0) + 1
            provider_guess = r_type.split("_", 1)[0]
            if provider_guess:
                providers.add(provider_guess.lower())
        provider_name = resource.get("provider_name") or resource.get("provider")
        provider_label = _normalize_provider_label(provider_name)
        if provider_label:
            providers.add(provider_label)

    resources_by_type: Dict[str, Dict[str, int]] = {}
    for r_type, count in resource_types.items():
        resources_by_type[r_type] = {
            "planned": count,
            "adds": 0,
            "changes": 0,
            "destroys": 0,
        }

    planned_values = plan.get("planned_values", {}) or {}
    root_module = planned_values.get("root_module")
    if not isinstance(root_module, dict):
        root_module = {}

    def normalize_address(module: Dict[str, Any], fallback: str) -> str:
        addr = module.get("address")
        if isinstance(addr, str) and addr.strip():
            return addr
        return fallback

    if module_stats:
        module_count = module_stats.module_count
        modules_with_resources = module_stats.modules_with_resources
        child_module_count = module_stats.child_module_count
        root_address = module_stats.root_address or "root"
    else:
        root_address = normalize_address(root_module, "root")
        module_stack: List[Tuple[Dict[str, Any], str]] = [(root_module, root_address)]
        module_count = 0
        modules_with_resources = 0
        child_module_count = 0

        while module_stack:
            module, addr = module_stack.pop()
            module_count += 1
            module_resources = module.get("resources")
            if isinstance(module_resources, list) and module_resources:
                modules_with_resources += 1
            children = module.get("child_modules")
            if not isinstance(children, list):
                continue
            for idx, child in enumerate(children):
                if not isinstance(child, dict):
                    continue
                child_addr = normalize_address(child, f"{addr}.child[{idx}]")
                child_module_count += 1
                module_stack.append((child, child_addr))

    change_summary = {"adds": 0, "changes": 0, "destroys": 0}
    for rc in plan.get("resource_changes") or []:
        r_type = rc.get("type")
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        bucket = _classify_change_actions(actions)
        if not bucket:
            continue
        change_summary[bucket] += 1
        entry = resources_by_type.setdefault(
            r_type or "unknown",
            {"planned": 0, "adds": 0, "changes": 0, "destroys": 0},
        )
        entry[bucket] += 1

    metadata = {
        "resource_count": len(resource_list),
        "resource_types": dict(sorted(resource_types.items())),
        "providers": sorted(providers),
        "module_count": module_count,
        "modules": {
            "root": root_address,
            "with_resources": modules_with_resources,
            "child_module_count": child_module_count,
            "has_child_modules": child_module_count > 0,
        },
        "exceeds_threshold": False,
        "change_summary": change_summary,
        "resources_by_type": resources_by_type,
        "file_size_mb": None,
    }

    if plan_limits:
        file_size_bytes = plan_limits.get("file_size_bytes")
        metadata["file_size_bytes"] = file_size_bytes
        metadata["parse_duration_ms"] = plan_limits.get("parse_duration_ms")
        metadata["plan_slo"] = plan_limits.get("plan_slo")
        metadata["exceeds_threshold"] = bool(plan_limits.get("exceeds_threshold"))
        metadata["file_size_mb"] = _bytes_to_mb(file_size_bytes)

    return metadata


def _safe_diff_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    try:
        normalized = json.dumps(value, sort_keys=True)
    except Exception:
        normalized = str(value)
    if len(normalized) > 200:
        return normalized[:197] + "..."
    return normalized


def _format_diff_display(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def _collect_changed_attributes(before: Any, after: Any) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    def walk(b: Any, a: Any, path: str) -> None:
        if b == a:
            return
        if isinstance(b, dict) and isinstance(a, dict):
            keys = sorted(set(b.keys()) | set(a.keys()))
            for key in keys:
                next_path = f"{path}.{key}" if path else key
                walk(b.get(key), a.get(key), next_path)
            return
        if b is None and isinstance(a, dict):
            for key in sorted(a.keys()):
                next_path = f"{path}.{key}" if path else key
                walk(None, a.get(key), next_path)
            return
        if a is None and isinstance(b, dict):
            for key in sorted(b.keys()):
                next_path = f"{path}.{key}" if path else key
                walk(b.get(key), None, next_path)
            return
        if isinstance(b, list) and isinstance(a, list) and b == a:
            return
        entries.append({
            "path": path or ".",
            "before": _safe_diff_value(b),
            "after": _safe_diff_value(a),
        })

    walk(before, after, "")
    entries.sort(key=lambda item: item.get("path") or "")
    return entries


def build_plan_diff(plan: Dict[str, Any]) -> Dict[str, Any]:
    summary = {"adds": 0, "changes": 0, "destroys": 0}
    resources: List[Dict[str, Any]] = []
    for rc in plan.get("resource_changes") or []:
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        change_type = _classify_change_actions(actions) or "changes"
        if change_type in summary:
            summary[change_type] += 1
        else:
            summary["changes"] += 1
        before = change.get("before")
        after = change.get("after")
        attrs = _collect_changed_attributes(before, after)
        if not attrs and change_type not in {"adds", "destroys"}:
            continue
        address = rc.get("address")
        if not isinstance(address, str) or not address:
            r_type = rc.get("type") or "resource"
            r_name = rc.get("name") or "unnamed"
            address = f"{r_type}.{r_name}"
        resources.append({
            "address": address,
            "type": rc.get("type"),
            "name": rc.get("name"),
            "change_type": change_type,
            "actions": actions,
            "changed_attributes": attrs,
        })
    resources.sort(key=lambda entry: entry.get("address") or "")
    return {
        "summary": summary,
        "resources": resources,
    }


_VIOLATION_RESOURCE_PATTERN = re.compile(r"(?P<rtype>[A-Za-z0-9_\.]+)\s+'(?P<name>[^']+)'")


def _parse_violation_record(violation: str) -> Dict[str, Optional[str]]:
    policy_id = "unknown"
    remainder = violation
    if ":" in violation:
        policy_id, remainder = violation.split(":", 1)
        policy_id = policy_id.strip() or "unknown"
        remainder = remainder.strip()
    match = _VIOLATION_RESOURCE_PATTERN.search(remainder)
    resource = None
    detail = remainder
    resource_type = None
    resource_name = None
    if match:
        resource_type = match.group("rtype")
        resource_name = match.group("name")
        resource = f"{resource_type}.{resource_name}"
        tail = remainder[match.end():].strip()
        if tail:
            detail = tail
    return {
        "policy_id": policy_id,
        "resource": resource,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "detail": detail,
    }


def _looks_like_variable_reference(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    token = value.strip()
    if not token:
        return False
    if token.startswith("${") and token.endswith("}"):
        token = token[2:-1]
    token = token.strip()
    return token.startswith("var.") or token.startswith("module.") or token.startswith("local.") or token.startswith("data.")


def _module_path_from_address(address: Optional[str]) -> str:
    if not isinstance(address, str) or not address:
        return "root"
    modules = [part for part in address.split(".") if part.startswith("module")]
    if not modules:
        return "root"
    return ".".join(modules)


def _compute_encryption_completeness(values: Dict[str, Any]) -> float:
    completeness = 0.6
    if isinstance(values, dict):
        if "storage_encrypted" in values:
            completeness += 0.2
        kms_value = values.get("kms_key_id")
        if _is_nonempty_string(kms_value):
            completeness += 0.25 if not _looks_like_variable_reference(kms_value) else 0.15
        else:
            completeness -= 0.05
    return round(min(1.0, max(0.3, completeness)), 2)


def _compute_tagging_completeness(tags: Any) -> float:
    completeness = 0.4
    if isinstance(tags, dict):
        completeness = 1.0
        for tag in REQUIRED_TAGS:
            if not _is_nonempty_string(tags.get(tag)):
                completeness -= 0.25
    return round(min(1.0, max(0.25, completeness)), 2)


def _build_encryption_example(resource: Optional[Dict[str, Any]]) -> str:
    r_type = (resource or {}).get("type") or "aws_rds_cluster"
    r_name = (resource or {}).get("name") or "example"
    return (
        f'resource "{r_type}" "{r_name}" {{\n'
        "  storage_encrypted = true\n"
        "  kms_key_id       = \"<kms-key-arn>\"\n"
        "}}"
    )


def _build_tagging_example(resource: Optional[Dict[str, Any]]) -> str:
    r_type = (resource or {}).get("type") or "aws_db_instance"
    r_name = (resource or {}).get("name") or "example"
    return (
        f'resource "{r_type}" "{r_name}" {{\n'
        "  tags = merge(var.default_tags, {\n"
        '    CostCenter = "finops-1234"\n'
        '    Project    = "vectorguard"\n'
        "  })\n"
        "}}"
    )


def _infer_data_taint(policy_id: str, resource: Optional[Dict[str, Any]], parsed: Dict[str, Optional[str]]) -> Tuple[str, str]:
    address = (resource or {}).get("address") or parsed.get("resource") or "resource"
    module_path = _module_path_from_address((resource or {}).get("address"))
    values = (resource or {}).get("values", {}) or {}
    if policy_id == "P-SEC-001":
        kms_value = values.get("kms_key_id")
        if _looks_like_variable_reference(kms_value):
            return "variable_source", f"kms_key_id for {address} references {kms_value}; update the variable or module wiring."
        if not _is_nonempty_string(kms_value):
            if module_path != "root":
                return "module_source", f"kms_key_id missing inside {module_path}; extend module outputs/variables."
            return "resource_body", f"Set kms_key_id directly on {address}."
        if values.get("storage_encrypted") is False:
            return "resource_body", f"storage_encrypted is false on {address}."
    elif policy_id == "P-FIN-001":
        tags = values.get("tags") or {}
        missing = [tag for tag in REQUIRED_TAGS if not _is_nonempty_string(tags.get(tag))]
        if missing:
            missing_list = ", ".join(missing)
            if module_path != "root":
                return "module_source", f"Tags {missing_list} missing within {module_path}; update module locals or variables."
            return "resource_body", f"Tags {missing_list} missing on {address}."
        if tags:
            return "resource_body", f"Verify tag inheritance for {address}."
    return "unknown", f"No taint inference available for {address}."


def _build_remediation_block(policy_id: str, resource: Optional[Dict[str, Any]], parsed: Dict[str, Optional[str]]) -> Dict[str, Any]:
    address = (resource or {}).get("address") or parsed.get("resource") or "resource"
    values = (resource or {}).get("values") or {}
    docs = list(REMEDIATION_DOCS.get(policy_id, [
        "https://docs.aws.amazon.com/config/latest/developerguide/",
        "https://vectorguard.dev/docs/vectorscan",
    ]))
    if policy_id == "P-SEC-001":
        summary = f"Enable encryption and configure kms_key_id for {address}."
        hcl_examples = [_build_encryption_example(resource)]
        completeness = _compute_encryption_completeness(values)
    elif policy_id == "P-FIN-001":
        summary = f"Populate CostCenter and Project tags for {address}."
        tags = values.get("tags") if isinstance(values, dict) else {}
        hcl_examples = [_build_tagging_example(resource)]
        completeness = _compute_tagging_completeness(tags)
    else:
        summary = f"Resolve {policy_id} findings on {address}."
        hcl_examples = [f"# Update {address} to satisfy {policy_id}"]
        completeness = 0.5
    return {
        "summary": summary,
        "hcl_examples": hcl_examples,
        "docs": docs,
        "hcl_completeness": completeness,
    }


def _build_resource_details(resource: Optional[Dict[str, Any]], parsed: Dict[str, Optional[str]]) -> Dict[str, Any]:
    address = (resource or {}).get("address") or parsed.get("resource")
    details = {
        "address": address,
        "type": (resource or {}).get("type") or parsed.get("resource_type"),
        "name": (resource or {}).get("name") or parsed.get("resource_name"),
        "module_path": _module_path_from_address((resource or {}).get("address")),
    }
    taint, explanation = _infer_data_taint(parsed.get("policy_id") or "unknown", resource, parsed)
    details["data_taint"] = taint
    details["taint_explanation"] = explanation
    return details


def _build_resource_lookup(resources: Sequence[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    lookup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for res in resources:
        r_type = res.get("type")
        r_name = res.get("name")
        if isinstance(r_type, str) and isinstance(r_name, str):
            lookup[(r_type, r_name)] = res
    return lookup


def build_violation_structs(
    *,
    violations: Sequence[str],
    resources: Sequence[Dict[str, Any]],
    severity_lookup: Dict[str, str],
    policy_metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    lookup = _build_resource_lookup(resources)
    structured: List[Dict[str, Any]] = []
    for violation in violations:
        if not isinstance(violation, str):
            continue
        parsed = _parse_violation_record(violation)
        resource = None
        r_type = parsed.get("resource_type")
        r_name = parsed.get("resource_name")
        if isinstance(r_type, str) and isinstance(r_name, str):
            resource = lookup.get((r_type, r_name))
        policy_id = parsed.get("policy_id", "") or "unknown"
        metadata = policy_metadata.get(policy_id)
        details = _build_resource_details(resource, parsed)
        structured.append(
            {
                "policy_id": policy_id,
                "policy_name": getattr(metadata, "name", None) if metadata else None,
                "message": violation,
                "severity": severity_lookup.get(policy_id, "medium"),
                "resource": details.get("address"),
                "resource_details": details,
                "remediation": _build_remediation_block(policy_id, resource, parsed),
            }
        )
    return structured


def build_explanation(
    *,
    status: str,
    plan_metadata: Dict[str, Any],
    metrics: Dict[str, Any],
    severity_summary: Dict[str, int],
    violations: List[str],
    policies: List[Any],
    iam_drift: Dict[str, Any],
) -> Dict[str, Any]:
    providers = plan_metadata.get("providers") or []
    resource_count = plan_metadata.get("resource_count", 0)
    module_count = plan_metadata.get("module_count", 0)
    modules_info = plan_metadata.get("modules", {}) or {}
    modules_with_resources = modules_info.get("with_resources", 0)
    child_module_count = modules_info.get("child_module_count", 0)
    provider_label = ", ".join(sorted(providers)) if providers else "unspecified"
    resource_word = "resource" if resource_count == 1 else "resources"
    module_word = "module" if module_count == 1 else "modules"
    child_phrase = "no child modules" if child_module_count == 0 else f"{child_module_count} child {'module' if child_module_count == 1 else 'modules'}"
    plan_narrative = (
        f"Plan defines {resource_count} {resource_word} across {module_count} {module_word} "
        f"(providers: {provider_label}; modules with resources: {modules_with_resources}; {child_phrase})."
    )

    compliance_score = metrics.get("compliance_score")
    network_score = metrics.get("network_exposure_score")
    iam_risky_actions = metrics.get("iam_risky_actions")
    eligible_checks = metrics.get("eligible_checks")
    passed_checks = metrics.get("passed_checks")

    scores_block = {
        "compliance_score": compliance_score,
        "network_exposure_score": network_score,
        "iam_risky_actions": iam_risky_actions,
        "eligible_checks": eligible_checks,
        "passed_checks": passed_checks,
    }

    severity_line = ", ".join(f"{level}={severity_summary.get(level, 0)}" for level in SEVERITY_LEVELS)

    drift_status = (iam_drift.get("status") or "PASS").upper()
    risky_changes = iam_drift.get("counts", {}).get("risky_changes", 0)
    drift_summary = f"IAM drift {drift_status} ({risky_changes} risky change{'s' if risky_changes != 1 else ''})."

    summary = (
        f"{status} scan – compliance score {compliance_score if compliance_score is not None else 'unknown'}/100, "
        f"severity counts [{severity_line}], {drift_summary.rstrip('.')}"
    )

    policy_context = []
    for policy in sorted(policies, key=lambda p: p.metadata.policy_id):
        meta = policy.metadata
        policy_context.append(
            {
                "policy_id": meta.policy_id,
                "name": meta.name,
                "severity": meta.severity,
                "description": meta.description,
            }
        )
    policy_meta_lookup = {entry["policy_id"]: entry for entry in policy_context}

    risk_highlights: List[Dict[str, Any]] = []
    for violation in violations:
        parsed = _parse_violation_record(violation)
        meta = policy_meta_lookup.get(parsed["policy_id"], {})
        risk_highlights.append(
            {
                "policy_id": parsed.get("policy_id"),
                "policy_name": meta.get("name"),
                "resource": parsed.get("resource"),
                "severity": meta.get("severity", "unknown"),
                "summary": parsed.get("detail"),
            }
        )

    recommendations: List[str] = []
    if risk_highlights:
        seen: Set[tuple[str, str]] = set()
        for item in risk_highlights:
            resource_label = item.get("resource") or "plan"
            policy_id = item.get("policy_id") or "unknown"
            key = (policy_id, resource_label)
            if key in seen:
                continue
            seen.add(key)
            meta = policy_meta_lookup.get(policy_id, {})
            description = meta.get("description") or (item.get("summary") or "Resolve guardrail finding")
            policy_name = meta.get("name") or "Unknown policy"
            recommendations.append(
                f"Remediate {resource_label} to satisfy {policy_id} ({policy_name}): {description}"
            )
    else:
        guardrail_titles = ", ".join(f"{entry['policy_id']} {entry['name']}" for entry in policy_context)
        if guardrail_titles:
            recommendations.append(
                f"Plan currently satisfies {guardrail_titles}; maintain encryption and tagging coverage as modules evolve."
            )

    explanation = {
        "summary": summary,
        "plan_overview": {
            "narrative": plan_narrative,
            "resource_count": resource_count,
            "module_count": module_count,
            "providers": sorted(providers),
            "modules_with_resources": modules_with_resources,
            "child_module_count": child_module_count,
            "has_child_modules": modules_info.get("has_child_modules", False),
        },
        "scores": scores_block,
        "risk_highlights": risk_highlights,
        "iam_drift": {
            "summary": drift_summary,
            "status": drift_status,
            "risky_change_count": risky_changes,
        },
        "recommendations": recommendations,
        "policy_context": policy_context,
    }
    return explanation


def _render_explanation_text(explanation: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("VectorScan Explain Report")
    lines.append("-------------------------")
    lines.append(explanation.get("summary", ""))
    lines.append("")

    overview = explanation.get("plan_overview", {})
    if overview:
        lines.append(f"Plan overview: {overview.get('narrative', '')}")

    scores = explanation.get("scores", {})
    compliance = scores.get("compliance_score")
    network = scores.get("network_exposure_score")
    iam_actions = scores.get("iam_risky_actions")
    eligible = scores.get("eligible_checks")
    passed = scores.get("passed_checks")
    compliance_display = f"{compliance}/100" if isinstance(compliance, (int, float)) else "unknown"
    network_display = f"{network}/100" if isinstance(network, (int, float)) else "unknown"
    iam_display = str(iam_actions) if iam_actions is not None else "unknown"
    lines.append(
        f"Scores: compliance {compliance_display} (eligible {eligible}/{passed}), network exposure {network_display}, IAM risky actions {iam_display}."
    )

    iam_drift_block = explanation.get("iam_drift", {})
    if iam_drift_block:
        lines.append(f"IAM drift: {iam_drift_block.get('summary', '')}")

    risk_highlights = explanation.get("risk_highlights") or []
    if risk_highlights:
        lines.append("High-risk resources:")
        for item in risk_highlights:
            resource = item.get("resource") or "plan"
            policy_id = item.get("policy_id") or "unknown"
            severity = item.get("severity") or "unknown"
            summary_text = item.get("summary") or "Guardrail triggered"
            lines.append(f"  - {resource} [{policy_id}/{severity}]: {summary_text}")
    else:
        lines.append("High-risk resources: none detected.")

    recommendations = explanation.get("recommendations") or []
    if recommendations:
        lines.append("Recommendations:")
        for rec in recommendations:
            lines.append(f"  - {rec}")

    policy_context = explanation.get("policy_context") or []
    if policy_context:
        lines.append("Guardrails:")
        for policy in policy_context:
            lines.append(
                f"  - {policy.get('policy_id')} ({policy.get('severity')}): {policy.get('description')}"
            )

    return "\n".join(line.rstrip() for line in lines if line is not None)


def _render_plan_diff_text(plan_diff: Dict[str, Any]) -> str:
    lines: List[str] = []
    summary = plan_diff.get("summary") or {}
    lines.append("Plan diff (changed attributes)")
    lines.append(
        "Summary: adds={adds}, changes={changes}, destroys={destroys}".format(
            adds=summary.get("adds", 0),
            changes=summary.get("changes", 0),
            destroys=summary.get("destroys", 0),
        )
    )
    resources = plan_diff.get("resources") or []
    if not resources:
        lines.append("No attribute-level changes detected in tfplan.")
        return "\n".join(lines)
    for entry in resources:
        address = entry.get("address") or (entry.get("type") or "resource")
        change_type = entry.get("change_type") or "changes"
        lines.append(f"- {address} ({change_type})")
        attributes = entry.get("changed_attributes") or []
        if not attributes:
            lines.append("    (no attribute deltas recorded)")
            continue
        for attr in attributes:
            path = attr.get("path") or "."
            before = _format_diff_display(attr.get("before"))
            after = _format_diff_display(attr.get("after"))
            lines.append(f"    {path}: {before} -> {after}")
    return "\n".join(lines)


def check_encryption(resources: List[Dict[str, Any]]) -> List[str]:
    """Compatibility wrapper delegating to the pluggable encryption policy."""

    return get_policy("P-SEC-001").evaluate(resources)


def _is_nonempty_string(s: Any) -> bool:
    """Backwards-compatible shim to utilities used in tests."""

    return is_nonempty_string(s)


def check_tags(resources: List[Dict[str, Any]]) -> List[str]:
    """Compatibility wrapper delegating to the pluggable tagging policy."""

    return get_policy("P-FIN-001").evaluate(resources)


def compute_violation_severity_summary(
    violations: List[str], severity_lookup: Optional[Dict[str, str]] = None
) -> Dict[str, int]:
    if severity_lookup is None:
        severity_lookup = {p.metadata.policy_id: p.metadata.severity for p in get_policies()}
    summary: Dict[str, int] = {level: 0 for level in SEVERITY_LEVELS}
    for violation in violations:
        if not isinstance(violation, str):
            continue
        policy_id = violation.split(":", 1)[0].strip()
        severity = severity_lookup.get(policy_id, "medium")
        if severity not in summary:
            summary[severity] = 0
        summary[severity] += 1
    return summary


def check_network_exposure(resources: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """Very lightweight network exposure indicator.
    Counts security groups with 0.0.0.0/0 or ::/0 ingress.
    Returns (open_sg_count, details)
    """
    open_count = 0
    details: List[str] = []
    for r in resources:
        if r.get("type") != "aws_security_group":
            continue
        vals = r.get("values", {}) or {}
        ingress = vals.get("ingress") or []
        name = r.get("name", "<unnamed>")
        try:
            for rule in ingress:
                cidrs = (rule or {}).get("cidr_blocks") or []
                ipv6s = (rule or {}).get("ipv6_cidr_blocks") or []
                if ("0.0.0.0/0" in cidrs) or ("::/0" in ipv6s):
                    open_count += 1
                    details.append(f"aws_security_group '{name}' has open ingress (0.0.0.0/0 or ::/0)")
                    break
        except Exception:
            # If ingress shape is unexpected, ignore
            pass
    return open_count, details


def check_iam_risky_actions(resources: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """Heuristic: flag wildcard or high-risk actions in inline policy JSON strings.
    Returns (risky_count, details)
    """
    import json as _json
    risky = 0
    details: List[str] = []
    policy_types = {"aws_iam_policy", "aws_iam_role", "aws_iam_role_policy", "aws_iam_user_policy"}
    risky_terms = (":*", "*", "s3:DeleteObject", "s3:PutObject", "rds:*", "iam:PassRole")
    for r in resources:
        if r.get("type") not in policy_types:
            continue
        vals = r.get("values", {}) or {}
        pol = vals.get("policy")
        if not isinstance(pol, str) or not pol.strip():
            continue
        try:
            pj = _json.loads(pol)
        except Exception:
            # Non-JSON or templated; perform string heuristic
            if any(t in pol for t in risky_terms):
                risky += 1
                details.append(f"{r.get('type')} '{r.get('name','<unnamed>')}' contains broad or risky actions (string match)")
            continue
        # Inspect statements
        stmts = pj.get("Statement")
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list):
            continue
        found = False
        for s in stmts:
            acts = s.get("Action")
            if isinstance(acts, str):
                acts = [acts]
            if not isinstance(acts, list):
                continue
            for a in acts:
                if isinstance(a, str) and any(t in a for t in risky_terms):
                    found = True
                    break
            if found:
                break
        if found:
            risky += 1
            details.append(f"{r.get('type')} '{r.get('name','<unnamed>')}' contains wildcard or high-risk actions")
    return risky, details


def compute_metrics(resources: List[Dict[str, Any]], violations: List[str]) -> Dict[str, Any]:
    # Eligible checks
    enc_targets = [r for r in resources if r.get("type") in {"aws_db_instance", "aws_rds_cluster"}]
    tag_targets = [r for r in resources if r.get("type") in TAGGABLE_TYPES]

    # Passed checks (independent of violation list length)
    enc_pass = 0
    for r in enc_targets:
        vals = r.get("values", {}) or {}
        if vals.get("storage_encrypted") is True and vals.get("kms_key_id"):
            enc_pass += 1

    tag_pass = 0
    for r in tag_targets:
        tags = (r.get("values", {}) or {}).get("tags") or {}
        if isinstance(tags, dict) and all(_is_nonempty_string(tags.get(k)) for k in REQUIRED_TAGS):
            tag_pass += 1

    total_checks = len(enc_targets) + len(tag_targets)
    passed_checks = enc_pass + tag_pass
    compliance_score = 100 if total_checks == 0 else int(round(100 * (passed_checks / total_checks)))

    # Network exposure
    open_sg_count, open_sg_details = check_network_exposure(resources)
    network_exposure_score = max(0, 100 - min(100, open_sg_count * 25))

    # IAM risky actions
    risky_count, risky_details = check_iam_risky_actions(resources)

    return {
        "eligible_checks": total_checks,
        "passed_checks": passed_checks,
        "compliance_score": compliance_score,
        "network_exposure_score": network_exposure_score,
        "open_sg_count": open_sg_count,
        "iam_risky_actions": risky_count,
        "notes": {
            "open_security_groups": open_sg_details,
            "iam_risky_details": risky_details,
        },
    }


def _policy_actions_from_json_string(s: str) -> Set[str]:
    import json as _json
    acts: Set[str] = set()
    try:
        j = _json.loads(s)
    except Exception:
        # Heuristic fallback: look for risky terms in raw string
        for term in RISKY_ACTION_TERMS:
            if term in s:
                acts.add(term)
        return acts
    stmts = j.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return acts
    for st in stmts:
        a = st.get("Action")
        if isinstance(a, str):
            acts.add(a)
        elif isinstance(a, list):
            for it in a:
                if isinstance(it, str):
                    acts.add(it)
    return acts


def _is_risky_action(a: str) -> bool:
    # Consider wildcards or listed risky terms
    if a == "*" or a.endswith(":*"):
        return True
    for term in RISKY_ACTION_TERMS:
        if term == "*":
            continue
        if term in a:
            return True
    return False


def _extract_policy_strings(before: Any, after: Any) -> Tuple[Optional[str], Optional[str]]:
    # before/after may be dicts with 'policy' or direct strings
    b = None
    a = None
    if isinstance(before, dict):
        pb = before.get("policy")
        if isinstance(pb, str):
            b = pb
    elif isinstance(before, str):
        b = before
    if isinstance(after, dict):
        pa = after.get("policy")
        if isinstance(pa, str):
            a = pa
    elif isinstance(after, str):
        a = after
    return b, a


def _parse_policy(s: str) -> List[Dict[str, Any]]:
    """Parse IAM policy JSON string, returning list of normalized statements.
    Each statement has keys: Effect, Actions (list[str]), NotActions (list[str]), Resources (list[str]), NotResources (list[str]).
    """
    import json as _json
    out: List[Dict[str, Any]] = []
    try:
        j = _json.loads(s)
    except Exception:
        return out
    stmts = j.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return out
    for st in stmts:
        eff = st.get("Effect", "Allow")
        act = st.get("Action")
        not_act = st.get("NotAction")
        res = st.get("Resource")
        not_res = st.get("NotResource")
        def norm_list(x):
            if x is None:
                return []
            if isinstance(x, str):
                return [x]
            if isinstance(x, list):
                return [y for y in x if isinstance(y, str)]
            return []
        out.append({
            "Effect": eff,
            "Actions": norm_list(act),
            "NotActions": norm_list(not_act),
            "Resources": norm_list(res),
            "NotResources": norm_list(not_res),
        })
    return out


def _resource_scope(resources: List[str], not_resources: List[str]) -> str:
    """Classify resource scope: 'global' if '*' present in Resources and not restricted by NotResources, else 'scoped'."""
    has_star = any(r == "*" or r.endswith(":*") for r in resources) if resources else True
    has_not = bool(not_resources)
    return "global" if has_star and not has_not else "scoped"


def build_iam_drift_report(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze resource_changes for risky IAM action additions (drift risk).
    Returns a report dict with items, counts, and status.
    """
    items: List[Dict[str, Any]] = []
    rc_list = plan.get("resource_changes") or []
    iam_types = {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
    risky_count = 0
    for rc in rc_list:
        rtype = rc.get("type")
        if rtype not in iam_types:
            continue
        name = rc.get("name", "<unnamed>")
        change = rc.get("change", {}) or {}
        before = change.get("before")
        after = change.get("after")
        b_policy, a_policy = _extract_policy_strings(before, after)
        if not a_policy:
            continue
        # Parse full statements for scoping assessment
        after_stmts = _parse_policy(a_policy)
        before_stmts = _parse_policy(b_policy) if b_policy else []
        after_actions = _policy_actions_from_json_string(a_policy)
        before_actions = _policy_actions_from_json_string(b_policy) if b_policy else set()
        additions = {a for a in after_actions if a not in before_actions}
        risky_additions = []
        severity_by_action: Dict[str, str] = {}
        # Evaluate added actions for risk and scope
        for a in sorted(additions):
            if not _is_risky_action(a):
                continue
            # Find a matching statement to infer scope
            scope = "global"
            for st in after_stmts:
                if a in st.get("Actions", []):
                    scope = _resource_scope(st.get("Resources", []), st.get("NotResources", []))
                    break
            sev = "high" if scope == "global" else "medium"
            severity_by_action[a] = sev
            risky_additions.append(a)
        # Handle NotAction broad allows (e.g., Allow with Resource '*')
        notaction_flag = False
        for st in after_stmts:
            if st.get("NotActions") and st.get("Effect", "Allow") == "Allow":
                scope = _resource_scope(st.get("Resources", []), st.get("NotResources", []))
                if scope == "global":
                    notaction_flag = True
                    break
        # If we couldn't parse structured actions, but risky terms present in raw policy string
        if not additions and not before_actions:
            # Fallback: if any risky term appears in after policy and not in before
            for term in RISKY_ACTION_TERMS:
                if a_policy and term in a_policy and (not b_policy or term not in b_policy):
                    risky_additions.append(term)
                    severity_by_action[term] = "high"
        if risky_additions:
            risky_count += 1
            items.append({
                "resource_type": rtype,
                "resource_name": name,
                "change": change.get("actions", []),
                "risky_additions": risky_additions,
                "severity_by_action": severity_by_action,
                "notaction_broad_allow": notaction_flag,
            })
    status = "PASS" if risky_count == 0 else "FAIL"
    return {
        "status": status,
        "counts": {"risky_changes": risky_count},
        "items": items,
        "notes": {
            "limitations": [
                "NotAction not evaluated",
                "Resource scoping not evaluated for drift risk",
            ]
        },
    }


def _write_local_capture(payload: dict) -> Path:
    stamp = _now()
    payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:10]
    prefix = f"lead_{stamp}_{payload_hash}_"
    primary = Path(__file__).parent / "captures"
    fallback = Path(tempfile.gettempdir()) / "vectorscan-captures"
    errors: List[str] = []

    for directory in (primary, fallback):
        try:
            target = secure_temp_file(prefix=prefix, suffix=".json", directory=directory)
            target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return target
        except OSError as exc:
            errors.append(f"{directory}: {exc}")
            continue

    raise OSError("Failed to write lead capture: " + "; ".join(errors))


def _maybe_post(endpoint: str, payload: dict, timeout: int = 5) -> tuple[bool, str]:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(endpoint, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, 'status', 200)
            return (200 <= code < 300), f"HTTP {code}"
    except Exception as e:
        return False, str(e)


def _run_cli(argv: list[str] | None = None) -> int:
    start_time = time.perf_counter()
    parser = argparse.ArgumentParser(description="VectorScan: minimal tfplan checks (encryption + mandatory tags)")
    parser.add_argument("plan", type=str, help="Path to tfplan.json")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON result")
    parser.add_argument("--email", type=str, help="Optional email for lead capture payload")
    parser.add_argument("--lead-capture", action="store_true", help="Enable local lead capture (writes JSON under tools/vectorscan/captures)")
    parser.add_argument("--endpoint", type=str, help="Optional HTTP endpoint to POST lead payload (default from env VSCAN_LEAD_ENDPOINT)")
    parser.add_argument(
        "--iam-drift-penalty",
        type=int,
        default=None,
        help="Penalty to subtract from compliance_score when IAM drift fails (overrides env VSCAN_IAM_DRIFT_PENALTY; default 20)",
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
        "--no-color",
        action="store_true",
        help="Disable ANSI color in human-readable output",
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
    # Preprocess argv to be resilient to values that start with '-' for options like --email
    raw_argv = list(argv or sys.argv[1:])
    try:
        idx = raw_argv.index("--email")
        # If the next token looks like an option (starts with '-') but is intended as the email value,
        # convert to '--email=<value>' form so argparse treats it as the value.
        if idx + 1 < len(raw_argv) and isinstance(raw_argv[idx + 1], str) and raw_argv[idx + 1].startswith("-"):
            val = raw_argv.pop(idx + 1)
            raw_argv[idx] = f"--email={val}"
    except ValueError:
        pass

    ns = parser.parse_args(raw_argv)
    offline_mode = is_offline()
    strict_mode = is_strict_mode()
    _ensure_strict_clock(strict_mode)
    use_color = _should_use_color(ns.no_color)

    if POLICY_PACK_HASH is None:
        message = _POLICY_PACK_ERROR or "Unknown policy pack error"
        print(f"Policy pack load error: {message}", file=sys.stderr)
        return EXIT_POLICY_LOAD_ERROR
    policy_pack_hash_value = POLICY_PACK_HASH

    path = Path(ns.plan)
    plan, resources, plan_limits, module_stats = load_plan_context(path)

    terraform_report: Dict[str, Any] | None = None
    run_tests_flag = ns.terraform_tests or os.getenv("VSCAN_TERRAFORM_TESTS", "0") == "1"
    if run_tests_flag:
        auto_download = not ns.no_terraform_download and os.getenv("VSCAN_TERRAFORM_AUTO_DOWNLOAD", "1") != "0"
        if offline_mode:
            auto_download = False
        print("[VectorScan] Ensuring Terraform CLI for module tests...", file=sys.stderr)
        terraform_report = run_terraform_tests(ns.terraform_bin, auto_download)
        status = terraform_report.get("status") if terraform_report else "SKIP"
        version = terraform_report.get("version", "?") if terraform_report else "?"
        source = terraform_report.get("source", "?") if terraform_report else "?"
        print(f"[VectorScan] Terraform test status: {status} (CLI {version}, source={source})", file=sys.stderr)
        if terraform_report:
            stdout_full = terraform_report.get("stdout", "")
            stderr_full = terraform_report.get("stderr", "")
            if stdout_full:
                print(stdout_full, end="" if stdout_full.endswith("\n") else "\n")
            if stderr_full:
                print(stderr_full, end="" if stderr_full.endswith("\n") else "\n", file=sys.stderr)

    policies = get_policies()
    policy_ids = [p.metadata.policy_id for p in policies]
    severity_lookup = {p.metadata.policy_id: p.metadata.severity for p in policies}
    policy_metadata_lookup = {p.metadata.policy_id: p.metadata for p in policies}

    violations: List[str] = []
    policy_errors: List[Dict[str, str]] = []
    for policy in policies:
        try:
            violations.extend(policy.evaluate(resources))
        except Exception as exc:
            policy_errors.append({
                "policy": policy.metadata.policy_id,
                "error": f"{exc.__class__.__name__}: {exc}",
            })

    _strict_require(strict_mode, not policy_errors, "Strict mode prohibits policy_errors; ensure all policies execute cleanly.")

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

    payload["violation_count_by_severity"] = dict(severity_summary)

    if terraform_report is not None:
        payload["terraform_tests"] = {
            **{k: terraform_report.get(k) for k in ("status", "version", "binary", "source", "strategy", "message", "returncode")},
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
        vectorscan_version_value=payload["vectorscan_version"],
    )
    plan_metadata = compute_plan_metadata(
        plan,
        resources,
        module_stats=module_stats,
        plan_limits=plan_limits,
    )
    payload["plan_metadata"] = plan_metadata

    plan_diff_block: Optional[Dict[str, Any]] = None
    if ns.diff:
        plan_diff_block = build_plan_diff(plan)
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
    except Exception:
        score = 0
    # Determine penalty weight: CLI flag > env var > default 20
    if ns.iam_drift_penalty is not None:
        penalty = ns.iam_drift_penalty
    else:
        try:
            penalty = int(os.getenv("VSCAN_IAM_DRIFT_PENALTY", "20"))
        except Exception:
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
    payload["metrics"] = metrics

    try:
        compliance_for_grade = int(metrics.get("compliance_score", 0))
    except Exception:
        compliance_for_grade = 0
    payload["security_grade"] = _compute_security_grade(compliance_for_grade, severity_summary)

    explanation_block: Dict[str, Any] | None = None
    if ns.explain:
        explanation_block = build_explanation(
            status=status,
            plan_metadata=plan_metadata,
            metrics=metrics,
            severity_summary=severity_summary,
            violations=violations,
            policies=policies,
            iam_drift=drift,
        )
        payload["explanation"] = explanation_block

    if ns.as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
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

    if has_policy_failures or has_policy_violations:
        print(f"{_status_badge('FAIL', use_color)} - tfplan.json - VectorScan checks")
        for v in violations:
            print("  ", v)
        if violations:
            summary_line = ", ".join(f"{level}={severity_summary.get(level, 0)}" for level in SEVERITY_LEVELS)
            print(f"  Violation severity summary: {summary_line}")
        if policy_errors:
            print("  Policy engine errors detected (partial coverage):")
            for err in policy_errors:
                print(f"    - {err['policy']}: {err['error']}")
        print("\n🚀 Want full, automated Zero-Trust & FinOps coverage?")
        print("Get the complete 8-point compliance kit (Blueprint) for $79/year → https://gumroad.com/l/vectorguard-blueprint\n")
    else:
        print(f"{_status_badge('PASS', use_color)} - tfplan.json - VectorScan checks (encryption + mandatory tags)")

    if ns.explain and not ns.as_json and explanation_block:
        print("")
        print(_render_explanation_text(explanation_block))
        print("")

    if ns.diff and not ns.as_json:
        print("")
        print(_render_plan_diff_text(plan_diff_block or {"summary": {}, "resources": []}))
        print("")

    # Optional lead capture (local, and optional HTTP POST if configured)
    if (not offline_mode) and (ns.lead_capture or ns.email or ns.endpoint or os.getenv("VSCAN_LEAD_ENDPOINT")):
        lead = {
            "email": (ns.email or ""),
            "result": payload,
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
        return _run_cli(argv)
    except StrictModeViolation as exc:
        print(f"[Strict Mode] {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
