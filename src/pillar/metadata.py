from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

from src.pillar import constants as pillar_constants

__all__ = ["build_metadata", "snapshot_control_flags"]


def build_metadata(context: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deterministic metadata block derived from the evaluation context."""

    metadata: Dict[str, Any] = {
        "pillar": pillar_constants.PILLAR_NAME,
        "scan_version": pillar_constants.SCAN_VERSION,
        "canonical_schema_version": pillar_constants.CANONICAL_SCHEMA_VERSION,
    }
    plan_block = _copy_dict(context.get("plan_metadata"))
    if plan_block:
        metadata["plan"] = plan_block
    environment_block = _build_environment_metadata(context)
    if environment_block:
        metadata["environment"] = environment_block
    control_flags = snapshot_control_flags(_extract_control_flags(context))
    if control_flags:
        metadata["_control_flags"] = control_flags
        metadata["control"] = dict(control_flags)
    return metadata


def _build_environment_metadata(context: Dict[str, Any]) -> Dict[str, Any]:
    base_environment = _copy_dict(context.get("environment"))
    flags = snapshot_control_flags(_extract_control_flags(context))
    ordered: Dict[str, Any] = {}
    for key in sorted(base_environment.keys()):
        ordered[key] = base_environment[key]
    ordered.update(flags)
    return ordered


def _extract_control_flags(context: Dict[str, Any]) -> Dict[str, Any]:
    raw_flags = context.get("_control_flags")
    flags = dict(raw_flags) if isinstance(raw_flags, dict) else {}
    environment_block = context.get("environment")
    if isinstance(environment_block, dict):
        for key in ("offline_mode", "allow_network_capture", "auto_download", "terraform_outcome"):
            if key not in flags and key in environment_block:
                flags[key] = environment_block[key]
    return flags


def snapshot_control_flags(flags: Dict[str, Any]) -> Dict[str, Any]:
    offline_mode = bool(flags.get("offline_mode"))
    allow_network_capture = bool(flags.get("allow_network_capture"))
    allow_network = bool(flags.get("allow_network", allow_network_capture))
    auto_download = bool(flags.get("auto_download"))
    terraform_outcome_value = flags.get("terraform_outcome")
    terraform_outcome = str(terraform_outcome_value or "SKIP")
    return {
        "offline_mode": offline_mode,
        "allow_network_capture": allow_network_capture,
        "allow_network": allow_network,
        "auto_download": auto_download,
        "terraform_outcome": terraform_outcome,
    }


def _copy_dict(value: Any) -> Dict[str, Any]:
    return deepcopy(value) if isinstance(value, dict) else {}
