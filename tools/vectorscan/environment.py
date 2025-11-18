"""Utilities for strict mode, environment metadata, and CLI color helpers."""

from __future__ import annotations

import os
import platform
import sys
import time
from typing import Any, Dict, Optional

from tools.vectorscan.constants import (
    ANSI_BOLD,
    ANSI_GREEN,
    ANSI_RED,
    ANSI_RESET,
    ANSI_YELLOW,
)
from tools.vectorscan.env_flags import env_falsey, env_truthy
from tools.vectorscan.time_utils import deterministic_epoch


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


__all__ = [
    "StrictModeViolation",
    "_now",
    "_compute_scan_duration_ms",
    "_should_use_color",
    "_colorize",
    "_status_badge",
    "_build_environment_metadata",
    "_ensure_strict_clock",
    "_strict_require",
]
