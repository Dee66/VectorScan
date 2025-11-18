"""Telemetry schema metadata for VectorScan monitoring artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class SchemaInfo:
    kind: str
    version: str


_BASE_VERSION = "2025-11-14.4"
_SCHEMA_MAP: Dict[str, SchemaInfo] = {
    "log_entry": SchemaInfo(kind="vectorscan.telemetry.log_entry", version=_BASE_VERSION),
    "summary": SchemaInfo(kind="vectorscan.telemetry.summary", version=_BASE_VERSION),
    "csv": SchemaInfo(kind="vectorscan.telemetry.csv", version=_BASE_VERSION),
}


def schema_version(target: str) -> str:
    """Return the version string for the requested telemetry artifact."""
    if target not in _SCHEMA_MAP:
        raise KeyError(f"Unknown telemetry schema target: {target}")
    return _SCHEMA_MAP[target].version


def schema_kind(target: str) -> str:
    if target not in _SCHEMA_MAP:
        raise KeyError(f"Unknown telemetry schema target: {target}")
    return _SCHEMA_MAP[target].kind


def schema_header(target: str) -> dict[str, str]:
    """Return a reusable schema header with version + kind metadata."""
    return {
        "schema_version": schema_version(target),
        "schema_kind": schema_kind(target),
    }
