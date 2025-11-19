"""Stub lead capture client for Copilot-generated flows."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List


@dataclass
class LeadCaptureClient:
    """Stores all capture payloads locally for later inspection."""

    captures: List[dict[str, Any]] = field(default_factory=list)

    def capture(self, email: str, payload: dict[str, Any]) -> None:
        record: dict[str, Any] = {"email": email, "payload": payload}
        self.captures.append(record)

    def last_capture(self) -> dict[str, Any] | None:
        return self.captures[-1] if self.captures else None
