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


def _env_override(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    return value.strip()


def is_offline() -> bool:
    """Return True when VectorScan should avoid any network activity."""

    allow_value = _env_override("VSCAN_ALLOW_NETWORK")
    offline_value = _env_override("VSCAN_OFFLINE")

    if offline_value is not None:
        if env_truthy(offline_value):
            return True
        if env_falsey(offline_value):
            return False

    if allow_value is not None:
        if env_truthy(allow_value):
            return False
        if env_falsey(allow_value):
            return True

    # Default: run in offline mode until explicitly overridden.
    return True


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
