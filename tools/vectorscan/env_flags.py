from __future__ import annotations

import os
from typing import Optional


_TRUTHY = {"1", "true", "yes", "on"}
_FALSEY = {"0", "false", "no", "off"}


def env_truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in _TRUTHY


def env_falsey(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in _FALSEY


def is_offline() -> bool:
    return env_truthy(os.getenv("VSCAN_OFFLINE"))


def is_strict_mode() -> bool:
    return env_truthy(os.getenv("VSCAN_STRICT"))


def is_statsd_disabled() -> bool:
    """Return True when telemetry scripts should skip StatsD emission."""

    if env_truthy(os.getenv("VSCAN_DISABLE_STATSD")):
        return True
    # Optional override: explicitly allow statsd when enable flag is set
    enable_flag = os.getenv("VSCAN_ENABLE_STATSD")
    if enable_flag is not None:
        # If enable flag is provided, honor falsey interpretation as disabled
        return env_falsey(enable_flag)
    return False
