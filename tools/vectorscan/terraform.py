"""Terraform management and test helpers for VectorScan."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple, cast
from urllib import request

from tools.vectorscan.constants import (
    DEFAULT_TERRAFORM_CACHE,
    MIN_TERRAFORM_TESTS_VERSION,
    REQUIRED_TERRAFORM_VERSION,
)
from tools.vectorscan.constants import ROOT_DIR as _ROOT_DIR
from tools.vectorscan.env_flags import env_truthy
_STUB_VERSION = os.getenv("VSCAN_TERRAFORM_STUB_VERSION", "1.6.0")
_STUB_BINARY = "terraform-stub"


def _stub_mode_enabled() -> bool:
    return env_truthy(os.getenv("VSCAN_TERRAFORM_STUB"))


def _offline_stub_report(status: str, *, message: str) -> Dict[str, Any]:
    normalized = status.upper()
    if normalized not in {"PASS", "FAIL", "SKIP", "ERROR"}:
        normalized = "SKIP"
    default_return = 0
    if normalized == "FAIL":
        default_return = 1
    elif normalized == "ERROR":
        default_return = 2
    return {
        "status": normalized,
        "returncode": default_return,
        "stdout": "[terraform-stub] offline execution",
        "stderr": "",
        "message": message,
        "version": _STUB_VERSION,
        "binary": _STUB_BINARY,
        "source": "stub",
        "strategy": "stub",
        "plan_output": "mock-plan-output",
    }


def _parse_semver(value: str) -> Tuple[int, int, int]:
    parts: List[int] = []
    for token in value.split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])  # type: ignore[return-value]


def _safe_chdir_flag(path: Path, *, root: Optional[Path] = None) -> str:
    base = (root or _ROOT_DIR).resolve()
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


_REGISTERED_VECTORSCAN_MODULES: List[ModuleType] = []
_strategy_resolver_override: Optional[Callable[[str], TerraformTestStrategy]] = None


def register_vectorscan_module(module: ModuleType) -> None:
    if module not in _REGISTERED_VECTORSCAN_MODULES:
        _REGISTERED_VECTORSCAN_MODULES.append(module)


def set_strategy_resolver(resolver: Callable[[str], TerraformTestStrategy]) -> None:
    """Allow external modules to override the Terraform strategy selector."""

    global _strategy_resolver_override
    _strategy_resolver_override = resolver


def _vectorscan_modules():
    seen = set()
    for name in ("vectorscan", "tools.vectorscan.vectorscan"):
        module = sys.modules.get(name)
        if module and module not in seen:
            seen.add(module)
            yield module
    for module in _REGISTERED_VECTORSCAN_MODULES:
        if module and module not in seen:
            seen.add(module)
            yield module
    target_suffix = f"{os.sep}tools{os.sep}vectorscan{os.sep}vectorscan.py"
    alt_suffix = target_suffix.replace(os.sep, "/")
    for module in sys.modules.values():
        if not module or module in seen:
            continue
        path = getattr(module, "__file__", "")
        if not path:
            continue
        normalized = path.replace("\\", "/")
        if normalized.endswith(alt_suffix):
            seen.add(module)
            yield module


def _current_root_dir() -> Path:
    for module in _vectorscan_modules():
        candidate = getattr(module, "ROOT_DIR", None)
        if isinstance(candidate, Path):
            return candidate
    return _ROOT_DIR


def _shared_safe_chdir_flag() -> Callable[..., str]:
    for module in _vectorscan_modules():
        candidate = getattr(module, "_safe_chdir_flag", None)
        if callable(candidate):
            return cast(Callable[..., str], candidate)
    return _safe_chdir_flag


def _truncate_output(text: Optional[str], limit: int = 4000, *, strict: bool = False) -> str:
    if not text:
        return ""
    text = text.strip()
    if strict:
        return text
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... (truncated)"


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
    def __init__(
        self,
        required_version: str = REQUIRED_TERRAFORM_VERSION,
        download_dir: Optional[Path] = None,
        auto_download: bool = True,
    ):
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
            raise TerraformNotFoundError(
                "Terraform CLI not found and auto-download disabled. Set VSCAN_TERRAFORM_BIN or enable downloads."
            )

        try:
            downloaded = self._download()
        except TerraformDownloadError as exc:
            if candidates:
                print(
                    f"VectorScan: Terraform download failed ({exc}); falling back to installed Terraform {candidates[0].version}.",
                    file=sys.stderr,
                )
                return candidates[0]
            raise

        res = self._resolution_for(downloaded, source="download")
        if not res:
            raise TerraformManagerError(
                "Failed to determine version of downloaded Terraform binary."
            )
        return res

    def _resolve_override(self, path: Path) -> TerraformResolution:
        res = self._resolution_for(path, source="override")
        if not res:
            raise TerraformManagerError(
                f"Could not determine Terraform version for override path: {path}"
            )
        return res

    def _resolution_for(self, path: Path, source: str) -> Optional[TerraformResolution]:
        version = self._binary_version(path)
        if not version:
            return None
        return TerraformResolution(path=path, version=version, source=source)

    def _binary_version(self, binary: Path) -> Optional[str]:
        try:
            result = subprocess.run(
                [str(binary), "version", "-json"], capture_output=True, text=True
            )
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
        import platform  # local import to avoid module-level dependency cycle

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
            raise TerraformDownloadError(
                f"Unsupported platform for auto-download: {platform.system()} {platform.machine()}"
            )

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
                raise TerraformDownloadError(
                    f"Binary {binary_name} not found in Terraform archive"
                ) from exc
            try:
                tmp_dir = Path(tempfile.mkdtemp(prefix="terraform-download-"))
            except OSError as exc:
                raise TerraformDownloadError(
                    f"Failed to create temp dir for Terraform download: {exc}"
                ) from exc
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
        root_dir = _current_root_dir()
        test_dir = root_dir / "tests" / "tf-tests"
        if not test_dir.exists():
            return {
                "status": "SKIP",
                "message": f"Terraform tests directory not found: {test_dir}",
            }
        try:
            safe_flag = _shared_safe_chdir_flag()
            chdir_flag = safe_flag(test_dir, root=root_dir)
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


def _shared_select_strategy() -> Callable[[str], TerraformTestStrategy]:
    if _strategy_resolver_override is not None:
        return _strategy_resolver_override
    for module in _vectorscan_modules():
        candidate = getattr(module, "_select_strategy", None)
        if callable(candidate):
            return cast(Callable[[str], TerraformTestStrategy], candidate)
    return _select_strategy


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
    manager = TerraformManager(
        required_version=REQUIRED_TERRAFORM_VERSION,
        download_dir=DEFAULT_TERRAFORM_CACHE,
        auto_download=auto_download,
    )
    try:
        resolution = manager.ensure(override_bin)
    except TerraformNotFoundError as exc:
        if _stub_mode_enabled():
            return _offline_stub_report("SKIP", message=str(exc))
        return {
            "status": "SKIP",
            "message": str(exc),
        }
    except TerraformManagerError as exc:
        if _stub_mode_enabled():
            return _offline_stub_report("ERROR", message=str(exc))
        return {
            "status": "ERROR",
            "message": str(exc),
        }

    strategy = _shared_select_strategy()(resolution.version)
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
    report["strategy"] = getattr(strategy, "name", "unknown")
    return report


__all__ = [
    "TerraformManager",
    "TerraformManagerError",
    "TerraformDownloadError",
    "TerraformNotFoundError",
    "TerraformResolution",
    "TerraformTestStrategy",
    "ModernTerraformTestStrategy",
    "LegacyTerraformTestStrategy",
    "run_terraform_tests",
    "set_strategy_resolver",
    "_safe_chdir_flag",
    "_truncate_output",
]
