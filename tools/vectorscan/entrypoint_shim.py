from __future__ import annotations

import importlib
import platform as _platform_module
import subprocess as _subprocess_module
import sys
import tempfile as _tempfile
from typing import List, Optional, Sequence, Tuple
from urllib import request as _urllib_request


from tools.vectorscan.constants import EXIT_CONFIG_ERROR as _EXIT_CONFIG_ERROR
from tools.vectorscan.python_compat import (
	ensure_supported_python as _ensure_supported_python,
	UnsupportedPythonVersion as _UnsupportedPythonVersion,
)
from tools.vectorscan.terraform import (
	LegacyTerraformTestStrategy as _LegacyTerraformTestStrategy,
	ModernTerraformTestStrategy as _ModernTerraformTestStrategy,
	TerraformDownloadError as _TerraformDownloadError,
	TerraformManager as _TerraformManager,
	TerraformManagerError as _TerraformManagerError,
	TerraformNotFoundError as _TerraformNotFoundError,
	TerraformResolution as _TerraformResolution,
	TerraformTestStrategy as _TerraformTestStrategy,
	register_vectorscan_module as _register_vectorscan_module,
	_safe_chdir_flag as _terraform_safe_chdir_flag,
	_select_strategy as _terraform_select_strategy,
	run_terraform_tests as _terraform_run_terraform_tests,
	set_strategy_resolver as _set_strategy_resolver,
	_truncate_output as _terraform_truncate_output,
)

try:  # pragma: no cover - executed in canonical environments
	from pillar.entrypoint_shim import emit_strict_mode_banner as _pillar_emit_strict_mode_banner
except ModuleNotFoundError:  # pragma: no cover - legacy fallback
	def _pillar_emit_strict_mode_banner(detail: str, include_unexpected: bool = False) -> None:
		_sys_stderr = sys.stderr
		_sys_stderr.write(f"[Strict Mode] {detail}\n")
		if include_unexpected:
			_sys_stderr.write("Unexpected scan failure\n")
		_sys_stderr.write("\n")


CANONICAL_COMMANDS = {"scan", "rules", "validate"}

# Legacy parity exports for terraform helpers and shared modules.
run_terraform_tests = _terraform_run_terraform_tests
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
_truncate_output = _terraform_truncate_output
platform = _platform_module
subprocess = _subprocess_module
tempfile = _tempfile
request = _urllib_request

_set_strategy_resolver(lambda version: _select_strategy(version))
_register_vectorscan_module(sys.modules[__name__])


def _guard_python_version() -> None:
	try:
		_ensure_supported_python()
	except _UnsupportedPythonVersion as exc:
		sys.stderr.write(f"[Python Compatibility] {exc}\n")
		raise SystemExit(_EXIT_CONFIG_ERROR) from exc


_guard_python_version()


def main(argv: Optional[Sequence[str]] = None) -> int:
	legacy = _legacy_module()
	raw_args = list(argv) if argv is not None else list(sys.argv[1:])
	try:
		return _dispatch(raw_args, legacy)
	except legacy.StrictModeViolation as exc:  # type: ignore[attr-defined]
		_pillar_emit_strict_mode_banner(str(exc))
		return legacy.EXIT_CONFIG_ERROR


def _dispatch(raw_args: List[str], legacy) -> int:
	command, remainder = _extract_canonical_command(raw_args)
	if command:
		return _handle_canonical_command(command, remainder, legacy)

	normalized = legacy._normalize_email_args(raw_args)
	parser = legacy._build_arg_parser()
	namespace = parser.parse_args(normalized)
	compare_args = list(getattr(namespace, "compare", []) or [])
	if compare_args:
		return _call_legacy(raw_args, legacy)

	manifest_value = getattr(namespace, "policy_manifest", None)
	sentinel = getattr(legacy, "_POLICY_MANIFEST_SENTINEL", object())
	if namespace.plan is None and manifest_value is not None:
		return _invoke_rules_manifest(manifest_value, sentinel, raw_args, legacy)

	if namespace.plan is None:
		parser.error("Path to tfplan.json is required unless --policy-manifest is used.")
	if manifest_value == sentinel:
		parser.error(
			"--policy-manifest requires a PATH when scanning. Run without a plan to print the embedded manifest."
		)

	if _requires_legacy_scan(namespace):
		return _call_legacy(raw_args, legacy)

	result = _call_pillar_scan(namespace)
	if result is None:
		return _call_legacy(raw_args, legacy)
	return result


def _extract_canonical_command(raw_args: Sequence[str]) -> Tuple[Optional[str], List[str]]:
	if raw_args and raw_args[0] in CANONICAL_COMMANDS:
		return raw_args[0], list(raw_args[1:])
	return None, list(raw_args)


def _handle_canonical_command(command: str, args: List[str], legacy) -> int:
	pillar_args = [command, *args]
	result = _call_pillar_cli(pillar_args)
	if result is None:
		message = "Canonical CLI is unavailable; legacy entrypoint cannot execute '{command}'."
		return _emit_config_error(message.format(command=command), legacy)
	return result


def _invoke_rules_manifest(manifest_value: Optional[str], sentinel, raw_args: List[str], legacy) -> int:
	path_arg = None if manifest_value in (None, sentinel) else manifest_value
	try:
		module = importlib.import_module("pillar.cli")
	except ModuleNotFoundError:
		return _call_legacy(raw_args, legacy)
	entry = getattr(module, "run_rules_manifest", None)
	if entry is None:
		return _call_legacy(raw_args, legacy)
	return entry(path_arg)


def _requires_legacy_scan(namespace) -> bool:
	return False


def _call_pillar_cli(argv: Sequence[str]) -> Optional[int]:
	try:
		module = importlib.import_module("pillar.cli")
	except ModuleNotFoundError:
		return None
	cli_main = getattr(module, "main", None)
	if cli_main is None:
		return None
	try:
		result = cli_main(list(argv))
	except SystemExit as exc:  # pragma: no cover - future pillar CLI behavior
		code = exc.code
		if isinstance(code, int):
			return code
		return 0
	return int(result) if isinstance(result, int) else 0


def _call_legacy(raw_args: Sequence[str], legacy) -> int:
	_sync_legacy_exports(legacy)
	return legacy._run_cli(list(raw_args))


def _emit_config_error(message: str, legacy) -> int:
	legacy._safe_print(message, stream=sys.stderr)
	return legacy.EXIT_CONFIG_ERROR


def _legacy_module():
	return importlib.import_module("tools.vectorscan.vectorscan")


def _sync_legacy_exports(legacy) -> None:
	legacy.run_terraform_tests = run_terraform_tests
	legacy.ModernTerraformTestStrategy = ModernTerraformTestStrategy
	legacy.LegacyTerraformTestStrategy = LegacyTerraformTestStrategy
	legacy.TerraformTestStrategy = TerraformTestStrategy
	legacy.TerraformManager = TerraformManager
	legacy.TerraformManagerError = TerraformManagerError
	legacy.TerraformNotFoundError = TerraformNotFoundError
	legacy.TerraformDownloadError = TerraformDownloadError
	legacy.TerraformResolution = TerraformResolution
	legacy._safe_chdir_flag = _safe_chdir_flag
	legacy._select_strategy = _select_strategy
	legacy._truncate_output = _truncate_output
	legacy.platform = platform
	legacy.subprocess = subprocess
	legacy.tempfile = tempfile
	legacy.request = request


def _call_pillar_scan(namespace) -> Optional[int]:
	try:
		module = importlib.import_module("pillar.cli")
	except ModuleNotFoundError:
		return None
	entry = getattr(module, "run_scan_from_namespace", None)
	if entry is None:
		return None
	return entry(namespace)


if __name__ == "__main__":  # pragma: no cover - script entrypoint
	raise SystemExit(main())
