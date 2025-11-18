"""Deterministic clock helpers shared across VectorScan tooling."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Optional


def _int_from_env(name: str) -> Optional[int]:
    value = os.getenv(name)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def deterministic_epoch() -> int:
    """Return a reproducible epoch seconds value.

    Preference order:
    1. VSCAN_CLOCK_EPOCH – purpose-built override used by CI/tests.
    2. SOURCE_DATE_EPOCH – industry-standard reproducible builds variable.
    3. Current system time.
    """

    for key in ("VSCAN_CLOCK_EPOCH", "SOURCE_DATE_EPOCH"):
        value = _int_from_env(key)
        if value is not None:
            return value
    return int(time.time())


def deterministic_isoformat() -> str:
    """Return an ISO-8601 UTC timestamp honoring deterministic overrides."""

    override = os.getenv("VSCAN_CLOCK_ISO")
    if override:
        return override
    epoch = deterministic_epoch()
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def deterministic_timestamp(prefix: str = "") -> str:
    """Return a timestamp string safe for filenames.

    Args:
        prefix: Optional prefix to prepend to the timestamp output.
    """

    stamp = deterministic_isoformat().replace(":", "").replace("-", "")
    stamp = stamp.replace("T", "_")
    return f"{prefix}{stamp}"
