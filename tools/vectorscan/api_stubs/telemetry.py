"""Stub telemetry client for Copilot-generated flows."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


@dataclass
class TelemetryClient:
    """Collects emitted metrics in-memory for deterministic testing."""

    metrics: List[Tuple[str, float, dict[str, Any]]] = field(default_factory=list)

    def emit(self, metric: str, value: float, tags: dict[str, Any] | None = None) -> None:
        self.metrics.append((metric, value, tags or {}))

    def clear(self) -> None:
        self.metrics.clear()
