#!/usr/bin/env python3
"""
VectorScan: Minimal CLI to check two critical guardrails in a Terraform plan JSON.

Checks:
    - P-SEC-001 (Encryption Mandate): RDS instance/cluster must have storage_encrypted=true and kms_key_id set
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
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Set

TAGGABLE_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_eks_cluster",
    "aws_autoscaling_group",
    "aws_instance",
    "aws_s3_bucket",
    "aws_kms_key",
    "aws_security_group",
    "aws_vpc",
    "aws_subnet",
}
REQUIRED_TAGS = ("CostCenter", "Project")
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

REQUIRED_TERRAFORM_VERSION = os.getenv("VSCAN_TERRAFORM_REQUIRED_VERSION", "1.13.5")
MIN_TERRAFORM_TESTS_VERSION = (1, 8, 0)
_ENV_TERRAFORM_CACHE = os.getenv("VSCAN_TERRAFORM_CACHE")
DEFAULT_TERRAFORM_CACHE = Path(_ENV_TERRAFORM_CACHE).expanduser() if _ENV_TERRAFORM_CACHE else Path(__file__).resolve().parent / ".terraform-bin"
ROOT_DIR = Path(__file__).resolve().parents[2]


def _parse_semver(value: str) -> Tuple[int, int, int]:
    parts: List[int] = []
    for token in value.split('.'):
        digits = ''.join(ch for ch in token if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])  # type: ignore[return-value]


def _truncate_output(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... (truncated)"


class TerraformManagerError(RuntimeError):
    pass


class TerraformDownloadError(TerraformManagerError):
    pass


@dataclass
class TerraformResolution:
    path: Path
    version: str
    source: str  # "system", "override", or "download"


class TerraformManager:
    def __init__(self, required_version: str = REQUIRED_TERRAFORM_VERSION, download_dir: Path | None = None, auto_download: bool = True):
        self.required_version = required_version
        self.required_tuple = _parse_semver(required_version)
        self.download_dir = download_dir or DEFAULT_TERRAFORM_CACHE
        self.auto_download = auto_download

    def ensure(self, override_path: str | None = None) -> TerraformResolution:
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
            raise TerraformManagerError("Terraform CLI not found and auto-download disabled. Set VSCAN_TERRAFORM_BIN or enable downloads.")

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

    def _resolution_for(self, path: Path, source: str) -> TerraformResolution | None:
        version = self._binary_version(path)
        if not version:
            return None
        return TerraformResolution(path=path, version=version, source=source)

    def _binary_version(self, binary: Path) -> str | None:
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

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            try:
                member = zf.getinfo(binary_name)
            except KeyError as exc:
                raise TerraformDownloadError(f"Binary {binary_name} not found in Terraform archive") from exc
            tmp_dir = Path(tempfile.mkdtemp(prefix="terraform-download-"))
            try:
                zf.extract(member, path=tmp_dir)
                extracted = tmp_dir / binary_name
                shutil.move(str(extracted), dest_binary)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        dest_binary.chmod(dest_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return dest_binary


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
        cmd_init = [str(terraform_bin), f"-chdir={test_dir}", "init", "-input=false"]
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

        cmd_test = [str(terraform_bin), f"-chdir={test_dir}", "test"]
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


def run_terraform_tests(override_bin: str | None, auto_download: bool) -> Dict[str, Any]:
    manager = TerraformManager(required_version=REQUIRED_TERRAFORM_VERSION, download_dir=DEFAULT_TERRAFORM_CACHE, auto_download=auto_download)
    try:
        resolution = manager.ensure(override_bin)
    except TerraformManagerError as exc:
        return {
            "status": "ERROR",
            "message": str(exc),
        }

    strategy = _select_strategy(resolution.version)
    report = strategy.run(resolution.path, resolution.version)
    report["version"] = resolution.version
    report["binary"] = str(resolution.path)
    report["source"] = resolution.source
    report["strategy"] = strategy.name
    return report


def load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {path}: {e}", file=sys.stderr)
        sys.exit(2)


def iter_resources(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    def collect(mod):
        res = list(mod.get("resources", []) or [])
        for child in mod.get("child_modules", []) or []:
            res.extend(collect(child))
        return res
    root = plan.get("planned_values", {}).get("root_module", {})
    return collect(root)


def check_encryption(resources: List[Dict[str, Any]]) -> List[str]:
    violations: List[str] = []
    for r in resources:
        if r.get("type") not in {"aws_db_instance", "aws_rds_cluster"}:
            continue
        vals = r.get("values", {}) or {}
        enc = vals.get("storage_encrypted")
        kms = vals.get("kms_key_id")
        name = r.get("name", "<unnamed>")
        if enc is not True:
            violations.append(
                f"P-SEC-001: {r.get('type')} '{name}' has storage_encrypted != true"
            )
            continue
        if not kms:
            violations.append(
                f"P-SEC-001: {r.get('type')} '{name}' encryption enabled but no kms_key_id specified"
            )
    return violations


def _is_nonempty_string(s: Any) -> bool:
    return isinstance(s, str) and s.strip() != ""


def check_tags(resources: List[Dict[str, Any]]) -> List[str]:
    violations: List[str] = []
    for r in resources:
        if r.get("type") not in TAGGABLE_TYPES:
            continue
        name = r.get("name", "<unnamed>")
        tags = (r.get("values", {}) or {}).get("tags") or {}
        if not isinstance(tags, dict) or not tags:
            violations.append(f"P-FIN-001: {r.get('type')} '{name}' has no tags")
            continue
        for key in REQUIRED_TAGS:
            if key not in tags or not _is_nonempty_string(tags.get(key)):
                violations.append(
                    f"P-FIN-001: {r.get('type')} '{name}' missing/empty tag '{key}'"
                )
    return violations


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


def _extract_policy_strings(before: Any, after: Any) -> Tuple[str | None, str | None]:
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
    out_dir = Path(__file__).parent / "captures"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:10]
    out = out_dir / f"lead_{stamp}_{h}.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def _maybe_post(endpoint: str, payload: dict, timeout: int = 5) -> tuple[bool, str]:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(endpoint, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, 'status', 200)
            return (200 <= code < 300), f"HTTP {code}"
    except Exception as e:
        return False, str(e)


def main(argv: list[str] | None = None) -> int:
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
    ns = parser.parse_args(argv or sys.argv[1:])

    path = Path(ns.plan)
    plan = load_json(path)
    resources = iter_resources(plan)

    terraform_report: Dict[str, Any] | None = None
    run_tests_flag = ns.terraform_tests or os.getenv("VSCAN_TERRAFORM_TESTS", "0") == "1"
    if run_tests_flag:
        auto_download = not ns.no_terraform_download and os.getenv("VSCAN_TERRAFORM_AUTO_DOWNLOAD", "1") != "0"
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

    violations: List[str] = []
    violations += check_encryption(resources)
    violations += check_tags(resources)

    status = "FAIL" if violations else "PASS"
    code = 3 if violations else 0

    payload = {
        "status": status,
        "file": str(path),
        "violations": violations,
        "counts": {"violations": len(violations)},
        "checks": ["P-SEC-001", "P-FIN-001"],
        "vectorscan_version": "0.1.0",
    }

    if terraform_report is not None:
        payload["terraform_tests"] = {
            **{k: terraform_report.get(k) for k in ("status", "version", "binary", "source", "strategy", "message", "returncode")},
            "stdout": _truncate_output(terraform_report.get("stdout")),
            "stderr": _truncate_output(terraform_report.get("stderr")),
        }
        if status == "PASS":
            if terraform_report.get("status") == "FAIL":
                status = "FAIL"
                code = 4
            elif terraform_report.get("status") == "ERROR":
                status = "FAIL"
                code = 5
        payload["status"] = status

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
    payload["metrics"] = metrics

    if ns.as_json:
        print(json.dumps(payload, indent=2))
        return code

    # default human-readable output
    if terraform_report is not None and terraform_report.get("status") not in {"PASS", "SKIP"}:
        print("Terraform tests: FAIL (see details above)")
    elif terraform_report is not None and terraform_report.get("status") == "PASS":
        print("Terraform tests: PASS")
    elif terraform_report is not None and terraform_report.get("status") == "SKIP":
        print(f"Terraform tests: SKIP - {terraform_report.get('message', 'unsupported Terraform CLI')}")

    if violations:
        print("FAIL - tfplan.json - VectorScan checks")
        for v in violations:
            print("  ", v)
        print("\n🚀 Want full, automated Zero-Trust & FinOps coverage?")
        print("Get the complete 8-point compliance kit (Blueprint) for $79/year → https://gumroad.com/l/vectorguard-blueprint\n")
    else:
        print("PASS - tfplan.json - VectorScan checks (encryption + mandatory tags)")

    # Optional lead capture (local, and optional HTTP POST if configured)
    if ns.lead_capture or ns.email or ns.endpoint or os.getenv("VSCAN_LEAD_ENDPOINT"):
        lead = {
            "email": (ns.email or ""),
            "result": payload,
            "timestamp": int(time.time()),
            "source": "vectorscan-cli",
        }
        path_out = _write_local_capture(lead)
        print(f"Lead payload saved: {path_out}")

        endpoint = ns.endpoint or os.getenv("VSCAN_LEAD_ENDPOINT", "")
        if endpoint:
            ok, info = _maybe_post(endpoint, lead)
            print(f"Lead POST => {info} ({'OK' if ok else 'SKIP/FAIL'})")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
