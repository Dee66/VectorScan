"""Telemetry helpers."""

from __future__ import annotations

from typing import Dict, Any


def emit(event: Dict[str, Any]) -> None:
    del event
